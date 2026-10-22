//! Asynchronous ownership transfer (`metabibasis` request/accept).
//!
//! The old two-sided mutation required both vaults on the same machine: the
//! cedente and the cessionário signed while holding each other's private
//! keys. That is not a transfer between people, it is a rename. This module
//! implements the handshake described in §11:
//!
//! 1. the cedente creates a signed *request* (manifest included);
//! 2. the cessionário sees it in the inbox and signs an *acceptance*;
//! 3. the source pyle locks the ceded paths and copies the bytes to the
//!    destination pyle (or locally), and both sides keep an immutable record.
//!
//! Nothing here trusts a client-supplied path or hash: every copied byte is
//! checked against the signed manifest before it is stored.

use std::collections::BTreeMap;

use base64::Engine;
use ed25519_dalek::SigningKey;
use hdap_core::crypto::{aead_open, aead_seal, ed25519_sign, ed25519_verify};
use hdap_core::doc::{parse as parse_doc, Doc, Signature};
use hdap_core::protocol::{
    TransferAcceptDoc, TransferRequestDoc, TransferTarget, TRANSFER_TARGET_DIR,
    TRANSFER_TARGET_FILE, TRANSFER_TARGET_IDENTITY,
};
use rand_core::RngCore;

use crate::config::Config;
use crate::fed_client::FedHttpClient;
use crate::http::{Request, Response};
use crate::node::{content_hash, json_err, require_json, sig_from_b64};
use crate::store::{Blob, Cession, State, TransferAsset, TransferRecord};

pub struct TransferModule {
    cfg: Config,
}

impl TransferModule {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    /// `POST /transfer/request` — build a draft (`{"draft":{...}}`) or accept a
    /// signed request (`{"request":"<doc>"}`) and store it.
    pub fn handle_request(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(old_owner) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if let Some(draft) = body.get("draft") {
            return self.request_draft(node, &old_owner, draft);
        }
        let text = match body.get("request").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return Response::json(400, json_err("request or draft required")),
        };
        self.request_finalize(node, &old_owner, text)
    }

    fn request_draft(
        &self,
        node: &crate::node::Node,
        old_owner: &str,
        draft: &serde_json::Value,
    ) -> Response {
        let new_owner = draft
            .get("new_owner")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let new_pyle = draft
            .get("new_pyle")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let target_kind = draft
            .get("target_kind")
            .and_then(|v| v.as_str())
            .unwrap_or(TRANSFER_TARGET_FILE)
            .trim()
            .to_string();
        if new_owner.is_empty() || new_pyle.is_empty() {
            return Response::json(400, json_err("new_owner and new_pyle required"));
        }
        if new_owner == old_owner {
            return Response::json(400, json_err("cannot transfer to yourself"));
        }
        if !matches!(
            target_kind.as_str(),
            TRANSFER_TARGET_FILE | TRANSFER_TARGET_DIR | TRANSFER_TARGET_IDENTITY
        ) {
            return Response::json(400, json_err("target_kind must be file, dir or identity"));
        }
        let targets: Vec<String> = draft
            .get("targets")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .map(|s| s.trim().trim_start_matches('/').to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if target_kind != TRANSFER_TARGET_IDENTITY && targets.is_empty() {
            return Response::json(400, json_err("at least one target required"));
        }
        if target_kind == TRANSFER_TARGET_FILE && targets.len() != 1 {
            return Response::json(400, json_err("file transfer takes exactly one target"));
        }

        let (old_nickname, old_pub) = {
            let st = node.state.lock().unwrap();
            let Some(user) = st.users.get(old_owner) else {
                return Response::json(404, json_err("old owner not registered"));
            };
            let Some(pubkey) = user.sign_pub_bytes() else {
                return Response::json(500, json_err("old owner has no signing key"));
            };
            (user.nickname.clone(), hex::encode(pubkey))
        };
        let mut new_pubkey = draft
            .get("new_owner_pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let new_nickname = draft
            .get("new_nickname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let new_uri = draft
            .get("new_uri")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let mut new_pyle_pubkey = draft
            .get("new_pyle_pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let mut new_pyle_tls_pin = draft
            .get("new_pyle_tls_pin")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if new_pyle == self.cfg.server_id {
            if new_pubkey.is_empty() {
                let st = node.state.lock().unwrap();
                new_pubkey = st
                    .users
                    .get(&new_owner)
                    .and_then(|u| u.sign_pub_bytes())
                    .map(hex::encode)
                    .unwrap_or_default();
            }
            if new_pyle_pubkey.is_empty() {
                new_pyle_pubkey = node_node_sign_pub(node);
            }
            if new_pyle_tls_pin.is_empty() {
                new_pyle_tls_pin = node.tls_pin.clone().unwrap_or_default();
            }
        } else if new_pubkey.is_empty() || new_pyle_pubkey.is_empty() {
            let want_user = if new_pubkey.is_empty() {
                Some(new_owner.as_str())
            } else {
                None
            };
            match self.discover_pyle(&new_pyle, &new_pyle_tls_pin, want_user) {
                Ok((node_pub, pin, user_pub)) => {
                    if new_pyle_pubkey.is_empty() {
                        new_pyle_pubkey = node_pub;
                    }
                    if new_pyle_tls_pin.is_empty() {
                        new_pyle_tls_pin = pin;
                    }
                    if new_pubkey.is_empty() {
                        new_pubkey = user_pub.unwrap_or_default();
                    }
                }
                Err(e) => {
                    return Response::json(
                        502,
                        json_err(&format!("cannot discover destination pyle: {e}")),
                    )
                }
            }
        }
        if new_pubkey.is_empty() {
            return Response::json(
                400,
                json_err("new_owner_pubkey required for a remote recipient"),
            );
        }
        if new_pyle_pubkey.is_empty() {
            return Response::json(400, json_err("new_pyle_pubkey required"));
        }

        let assets =
            match self.manifest(node, old_owner, &old_pyle_id(node), &target_kind, &targets) {
                Ok(a) => a,
                Err(resp) => return resp,
            };
        let request_id = random_id();
        let mut id_bytes = [0u8; 8];
        rand_core::OsRng.fill_bytes(&mut id_bytes);
        let old_uri = format!(
            "HDAP!{}@{}/{}",
            node.cfg.server_id,
            old_owner,
            targets.first().cloned().unwrap_or_default()
        );
        let new_uri = if new_uri.is_empty() {
            format!("HDAP!{}@{}/", new_pyle, new_owner)
        } else {
            new_uri
        };
        let scopes = if target_kind == TRANSFER_TARGET_IDENTITY {
            vec![String::new()]
        } else {
            targets.clone()
        };
        let doc = TransferRequestDoc {
            request_id,
            old_owner: old_owner.to_string(),
            new_owner,
            old_nickname,
            new_nickname,
            old_uri,
            new_uri,
            old_pyle: node.cfg.server_id.clone(),
            new_pyle,
            old_owner_pubkey: old_pub,
            new_owner_pubkey: new_pubkey,
            old_pyle_pubkey: node_node_sign_pub(node),
            new_pyle_pubkey,
            old_pyle_tls_pin: node.tls_pin.clone().unwrap_or_default(),
            new_pyle_tls_pin,
            target_kind,
            scopes,
            targets: assets
                .iter()
                .map(|a| TransferTarget {
                    source: a.source.clone(),
                    dest: a.dest.clone(),
                    hash: a.hash.clone(),
                    size: a.size,
                })
                .collect(),
            created_at: node_now(node),
        };
        Response::json(
            200,
            serde_json::json!({
                "request": doc.to_doc().render(),
                "request_id": doc.request_id,
            })
            .to_string(),
        )
    }

    fn request_finalize(&self, node: &crate::node::Node, old_owner: &str, text: &str) -> Response {
        let doc = match parse_doc(text) {
            Ok(d) => d,
            Err(e) => return Response::json(400, json_err(&format!("invalid request: {e}"))),
        };
        let request = match TransferRequestDoc::from_doc(&doc) {
            Some(r) => r,
            None => return Response::json(400, json_err("not a transfer request")),
        };
        if request.old_owner != old_owner {
            return Response::json(403, json_err("request belongs to another identity"));
        }
        if request.old_pyle != self.cfg.server_id {
            return Response::json(403, json_err("request names another source pyle"));
        }
        if doc.sigs.len() != 1 && doc.sigs.len() != 2 {
            return Response::json(
                400,
                json_err("request must carry one signature, or two on an idempotent retry"),
            );
        }
        if !verify_slot(&doc, 0, &request.old_owner, &request.old_owner_pubkey) {
            return Response::json(401, json_err("request signature invalid"));
        }
        let old_user_pub = {
            let st = node.state.lock().unwrap();
            st.users
                .get(old_owner)
                .and_then(|u| u.sign_pub_bytes())
                .map(hex::encode)
        };
        if old_user_pub.as_deref() != Some(request.old_owner_pubkey.as_str()) {
            return Response::json(
                401,
                json_err("request signing key is not the registered key"),
            );
        }
        if doc.sigs.len() == 2 {
            // A retry may post the already-countersigned document. Accept it
            // only if it is byte-for-byte the request this pyle stored.
            if !verify_slot(&doc, 1, &request.old_pyle, &request.old_pyle_pubkey) {
                return Response::json(401, json_err("request countersignature invalid"));
            }
            let provided_hash = content_hash(text.as_bytes());
            let existing = {
                let st = node.state.lock().unwrap();
                st.transfers.get(&request.request_id).cloned()
            };
            let Some(existing) = existing else {
                return Response::json(409, json_err("request is not known to this pyle"));
            };
            if existing.request_hash != provided_hash {
                return Response::json(409, json_err("request id collision"));
            }
            if request.new_pyle != self.cfg.server_id {
                if let Err(e) = self.send_request_to_destination(&request, &existing.request_doc) {
                    return Response::json(
                        502,
                        serde_json::json!({
                            "error": format!("could not deliver to destination pyle: {e}"),
                            "request_id": request.request_id,
                            "request": existing.request_doc,
                            "request_hash": existing.request_hash,
                        })
                        .to_string(),
                    );
                }
            }
            return Response::json(
                200,
                serde_json::json!({
                    "request_id": request.request_id,
                    "request": existing.request_doc,
                    "request_hash": existing.request_hash,
                    "old_pyle": request.old_pyle,
                    "new_pyle": request.new_pyle,
                })
                .to_string(),
            );
        }
        if !verify_manifest(node, old_owner, &request) {
            return Response::json(409, json_err("manifest no longer matches stored content"));
        }

        // Countersign the request as the source pyle (second slot). This is
        // the "documento de provas" for the inter-pyle path: a peer can verify
        // that the pyle hosting the bytes saw the cedente's own signature.
        let mut final_doc = doc;
        if !append_node_signature(node, &mut final_doc) {
            return Response::json(500, json_err("could not sign request"));
        }
        let final_text = final_doc.render();
        let request_hash = content_hash(final_text.as_bytes());
        let record = record_from_request(&request, final_text.clone(), request_hash.clone());

        let duplicate = {
            let st = node.state.lock().unwrap();
            st.transfers.get(&request.request_id).cloned()
        };
        if let Some(existing) = duplicate {
            if existing.request_hash != request_hash {
                return Response::json(409, json_err("request id collision"));
            }
            // Idempotent retry: the first attempt may have stored the record
            // and then failed to reach the destination. Deliver again instead
            // of making the only copy of the request unrecoverable.
            if request.new_pyle != self.cfg.server_id {
                if let Err(e) = self.send_request_to_destination(&request, &existing.request_doc) {
                    return Response::json(
                        502,
                        serde_json::json!({
                            "error": format!("could not deliver to destination pyle: {e}"),
                            "request_id": request.request_id,
                            "request": existing.request_doc,
                            "request_hash": existing.request_hash,
                        })
                        .to_string(),
                    );
                }
            }
            return Response::json(
                200,
                serde_json::json!({
                    "request_id": request.request_id,
                    "request": existing.request_doc,
                    "request_hash": existing.request_hash,
                    "old_pyle": request.old_pyle,
                    "new_pyle": request.new_pyle,
                })
                .to_string(),
            );
        }
        {
            let mut st = node.state.lock().unwrap();
            st.transfers.insert(request.request_id.clone(), record);
            if request.new_pyle == self.cfg.server_id {
                // Same pyle: the recipient is local, so the inbox is right here.
                if let Err(resp) = write_pending_doc(&mut st, &request, &final_text) {
                    st.transfers.remove(&request.request_id);
                    return resp;
                }
            }
        }
        if request.new_pyle != self.cfg.server_id {
            if let Err(e) = self.send_request_to_destination(&request, &final_text) {
                return Response::json(
                    502,
                    serde_json::json!({
                        "error": format!("could not deliver to destination pyle: {e}"),
                        "request_id": request.request_id,
                        "request": final_text,
                        "request_hash": request_hash,
                    })
                    .to_string(),
                );
            }
        }
        Response::json(
            200,
            serde_json::json!({
                "request_id": request.request_id,
                "request": final_text,
                "request_hash": request_hash,
                "old_pyle": request.old_pyle,
                "new_pyle": request.new_pyle,
            })
            .to_string(),
        )
    }

    /// `POST /transfer/inbox` — deliver a signed request to its destination
    /// pyle. Unauthenticated on purpose: the document is self-verifying, and a
    /// stranger can only offer a transfer, never complete one.
    pub fn handle_inbox_post(&self, node: &crate::node::Node, req: &Request) -> Response {
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let text = match body.get("request").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return Response::json(400, json_err("request required")),
        };
        let doc = match parse_doc(text) {
            Ok(d) => d,
            Err(e) => return Response::json(400, json_err(&format!("invalid request: {e}"))),
        };
        let request = match TransferRequestDoc::from_doc(&doc) {
            Some(r) => r,
            None => return Response::json(400, json_err("not a transfer request")),
        };
        if request.new_pyle != self.cfg.server_id {
            return Response::json(403, json_err("request names another destination pyle"));
        }
        if doc.sigs.len() < 2
            || !verify_slot(&doc, 0, &request.old_owner, &request.old_owner_pubkey)
            || !verify_slot(&doc, 1, &request.old_pyle, &request.old_pyle_pubkey)
        {
            return Response::json(401, json_err("request signatures invalid"));
        }
        let registered_pub = {
            let st = node.state.lock().unwrap();
            st.users
                .get(&request.new_owner)
                .and_then(|u| u.sign_pub_bytes())
                .map(hex::encode)
        };
        let Some(registered_pub) = registered_pub else {
            return Response::json(404, json_err("recipient not registered here"));
        };
        if registered_pub != request.new_owner_pubkey {
            return Response::json(409, json_err("request names a different recipient key"));
        }
        let hash = content_hash(text.as_bytes());
        let mut st = node.state.lock().unwrap();
        if let Some(existing) = st.transfers.get(&request.request_id) {
            if existing.request_hash == hash {
                return Response::json(200, json_err("already delivered"));
            }
            return Response::json(409, json_err("request id collision"));
        }
        let record = record_from_request(&request, text.to_string(), hash.clone());
        st.transfers.insert(request.request_id.clone(), record);
        if let Err(resp) = write_pending_doc(&mut st, &request, text) {
            st.transfers.remove(&request.request_id);
            return resp;
        }
        Response::json(
            200,
            serde_json::json!({
                "request_id": request.request_id,
                "request_hash": hash,
            })
            .to_string(),
        )
    }

    /// `GET /transfer/inbox` — pending offers for the authenticated user.
    pub fn handle_inbox_get(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let st = node.state.lock().unwrap();
        let items: Vec<serde_json::Value> = st
            .transfers
            .values()
            .filter(|r| r.new_owner == user && r.new_pyle == self.cfg.server_id && r.is_pending())
            .map(|r| {
                serde_json::json!({
                    "request_id": r.request_id,
                    "old_owner": r.old_owner,
                    "old_nickname": r.old_nickname,
                    "new_owner": r.new_owner,
                    "old_uri": r.old_uri,
                    "new_uri": r.new_uri,
                    "target_kind": r.target_kind,
                    "assets": r.assets.len(),
                    "created_at": r.created_at,
                    "request": r.request_doc,
                })
            })
            .collect();
        Response::json(200, serde_json::json!({ "inbox": items }).to_string())
    }

    /// `POST /transfer/accept` — draft (`{"draft":"<request_id>"}`) or store
    /// the recipient-signed acceptance (`{"accept":"<doc>"}`).
    pub fn handle_accept(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if let Some(id) = body.get("draft").and_then(|v| v.as_str()) {
            return self.accept_draft(node, &user, id);
        }
        let text = match body.get("accept").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return Response::json(400, json_err("accept or draft required")),
        };
        self.accept_finalize(node, &user, text)
    }

    fn accept_draft(&self, node: &crate::node::Node, user: &str, request_id: &str) -> Response {
        let st = node.state.lock().unwrap();
        let Some(record) = st.transfers.get(request_id) else {
            return Response::json(404, json_err("request not found"));
        };
        if record.new_owner != user || record.new_pyle != self.cfg.server_id {
            return Response::json(403, json_err("request is not addressed to you"));
        }
        if !record.is_pending() && record.status != "accepted" {
            return Response::json(409, json_err("request already handled"));
        }
        let doc = TransferAcceptDoc {
            request_id: record.request_id.clone(),
            request_hash: record.request_hash.clone(),
            request_doc: record.request_doc.clone(),
            old_owner: record.old_owner.clone(),
            new_owner: record.new_owner.clone(),
            old_nickname: record.old_nickname.clone(),
            new_nickname: record.new_nickname.clone(),
            old_uri: record.old_uri.clone(),
            new_uri: record.new_uri.clone(),
            old_pyle: record.old_pyle.clone(),
            new_pyle: record.new_pyle.clone(),
            target_kind: record.target_kind.clone(),
            targets: record
                .assets
                .iter()
                .map(|a| TransferTarget {
                    source: a.source.clone(),
                    dest: a.dest.clone(),
                    hash: a.hash.clone(),
                    size: a.size,
                })
                .collect(),
            created_at: node_now(node),
        };
        Response::json(
            200,
            serde_json::json!({ "accept": doc.to_doc().render() }).to_string(),
        )
    }

    fn accept_finalize(&self, node: &crate::node::Node, user: &str, text: &str) -> Response {
        let doc = match parse_doc(text) {
            Ok(d) => d,
            Err(e) => return Response::json(400, json_err(&format!("invalid accept: {e}"))),
        };
        let accept = match TransferAcceptDoc::from_doc(&doc) {
            Some(a) => a,
            None => return Response::json(400, json_err("not a transfer acceptance")),
        };
        if accept.new_owner != user {
            return Response::json(403, json_err("acceptance belongs to another identity"));
        }
        if accept.new_pyle != self.cfg.server_id {
            return Response::json(403, json_err("acceptance names another destination pyle"));
        }
        if accept.request_hash != content_hash(accept.request_doc.as_bytes()) {
            return Response::json(400, json_err("embedded request hash does not match"));
        }
        let parsed_request = match parse_doc(&accept.request_doc) {
            Ok(d) => d,
            Err(_) => return Response::json(400, json_err("embedded request is malformed")),
        };
        let request = match TransferRequestDoc::from_doc(&parsed_request) {
            Some(r) => r,
            None => return Response::json(400, json_err("embedded request is not a request")),
        };
        let record = {
            let st = node.state.lock().unwrap();
            st.transfers.get(&request.request_id).cloned()
        };
        let Some(mut record) = record else {
            return Response::json(404, json_err("request not found"));
        };
        if record.new_owner != user
            || record.request_hash != accept.request_hash
            || record.request_doc != accept.request_doc
        {
            return Response::json(
                409,
                json_err("acceptance does not match the stored request"),
            );
        }
        if record.status == "completed" {
            return Response::json(
                200,
                serde_json::json!({
                    "status": "completed",
                    "accept": record.accept_doc.unwrap_or_else(|| text.to_string()),
                    "record_path": record.record_path,
                })
                .to_string(),
            );
        }
        // Slot 0 is the cessionário; slot 1 is *this* pyle.
        if doc.sigs.len() != 1
            || !verify_slot(&doc, 0, &accept.new_owner, &request.new_owner_pubkey)
        {
            return Response::json(401, json_err("acceptance signature invalid"));
        }
        if node_node_sign_pub(node) != request.new_pyle_pubkey {
            return Response::json(403, json_err("request names another destination pyle key"));
        }
        let mut final_doc = doc;
        if !append_node_signature(node, &mut final_doc) {
            return Response::json(500, json_err("could not countersign acceptance"));
        }
        let final_text = final_doc.render();
        let accept_hash = content_hash(final_text.as_bytes());
        {
            let mut st = node.state.lock().unwrap();
            if let Some(r) = st.transfers.get_mut(&request.request_id) {
                r.status = "accepted".into();
                r.accept_doc = Some(final_text.clone());
                r.accept_hash = Some(accept_hash.clone());
            }
            record.status = "accepted".into();
            record.accept_doc = Some(final_text.clone());
            record.accept_hash = Some(accept_hash);
        }

        if request.old_pyle == self.cfg.server_id {
            lock_cessions(node, &record);
            let (status, record_path) = match self.complete_local(node, &record) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            return Response::json(
                200,
                serde_json::json!({
                    "status": status,
                    "accept": final_text,
                    "record_path": record_path,
                })
                .to_string(),
            );
        }

        match self.forward_to_source(node, &record, &final_text) {
            Ok((status, record_path)) => {
                let mut st = node.state.lock().unwrap();
                if let Some(r) = st.transfers.get_mut(&request.request_id) {
                    r.status = status.clone();
                    r.record_path = Some(record_path.clone());
                }
                if let Some(r) = st.transfers.get(&request.request_id).cloned() {
                    if let Err(resp) = write_final_doc(&mut st, &r, &final_text) {
                        return resp;
                    }
                }
                Response::json(
                    200,
                    serde_json::json!({
                        "status": status,
                        "accept": final_text,
                        "record_path": record_path,
                    })
                    .to_string(),
                )
            }
            Err(e) => Response::json(
                502,
                serde_json::json!({
                    "error": format!("source pyle unreachable: {e}"),
                    "status": "accepted",
                    "accept": final_text,
                })
                .to_string(),
            ),
        }
    }

    /// `POST /transfer/complete` — source pyle receives the accepted request
    /// from the destination pyle, locks the ceded paths and pushes the bytes.
    pub fn handle_complete(&self, node: &crate::node::Node, req: &Request) -> Response {
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let request_text = body.get("request").and_then(|v| v.as_str()).unwrap_or("");
        let accept_text = body.get("accept").and_then(|v| v.as_str()).unwrap_or("");
        let request = match parse_doc(request_text)
            .ok()
            .and_then(|d| TransferRequestDoc::from_doc(&d))
        {
            Some(r) => r,
            None => return Response::json(400, json_err("invalid request")),
        };
        let accept_doc = match parse_doc(accept_text) {
            Ok(d) => d,
            Err(e) => return Response::json(400, json_err(&format!("invalid accept: {e}"))),
        };
        let accept = match TransferAcceptDoc::from_doc(&accept_doc) {
            Some(a) => a,
            None => return Response::json(400, json_err("not a transfer acceptance")),
        };
        if request.old_pyle != self.cfg.server_id {
            return Response::json(403, json_err("this pyle is not the source"));
        }
        if accept.request_hash != content_hash(request_text.as_bytes())
            || accept.request_doc != request_text
            || accept.request_id != request.request_id
        {
            return Response::json(409, json_err("acceptance does not match the request"));
        }
        if accept_doc.sigs.len() != 2
            || !verify_slot(&accept_doc, 0, &accept.new_owner, &request.new_owner_pubkey)
            || !verify_slot(&accept_doc, 1, &request.new_pyle, &request.new_pyle_pubkey)
        {
            return Response::json(401, json_err("acceptance signatures invalid"));
        }
        let existing = {
            let st = node.state.lock().unwrap();
            st.transfers.get(&request.request_id).cloned()
        };
        let Some(mut record) = existing else {
            return Response::json(404, json_err("request not found"));
        };
        if record.request_hash != content_hash(request_text.as_bytes()) {
            return Response::json(409, json_err("request hash mismatch"));
        }
        if record.status == "completed" {
            return Response::json(
                200,
                serde_json::json!({
                    "status": "completed",
                    "record_path": record.record_path,
                })
                .to_string(),
            );
        }
        if !verify_manifest(node, &record.old_owner, &request) {
            return Response::json(409, json_err("source content changed after the request"));
        }
        // Lock first, copy second. A failed copy must never leave the cedente
        // able to rewrite something the cessionário has already accepted.
        lock_cessions(node, &record);
        {
            let mut st = node.state.lock().unwrap();
            if let Some(r) = st.transfers.get_mut(&request.request_id) {
                r.status = "accepted".into();
                r.accept_doc = Some(accept_text.to_string());
                r.accept_hash = Some(content_hash(accept_text.as_bytes()));
            }
            record.status = "accepted".into();
            record.accept_doc = Some(accept_text.to_string());
            record.accept_hash = Some(content_hash(accept_text.as_bytes()));
        }
        let (status, record_path) = if request.new_pyle == self.cfg.server_id {
            match self.complete_local(node, &record) {
                Ok(v) => v,
                Err(resp) => return resp,
            }
        } else {
            match self.push_to_destination(node, &record, accept_text) {
                Ok(path) => ("completed".to_string(), path),
                Err(e) => {
                    return Response::json(
                        502,
                        serde_json::json!({
                            "error": format!("destination pyle unreachable: {e}"),
                            "status": "accepted",
                        })
                        .to_string(),
                    )
                }
            }
        };
        let mut st = node.state.lock().unwrap();
        if let Some(r) = st.transfers.get_mut(&request.request_id) {
            r.status = status.clone();
            r.record_path = Some(record_path.clone());
        }
        if let Some(r) = st.transfers.get(&request.request_id).cloned() {
            let _ = write_final_doc(&mut st, &r, accept_text);
        }
        Response::json(
            200,
            serde_json::json!({
                "status": status,
                "record_path": record_path,
            })
            .to_string(),
        )
    }

    /// `POST /transfer/deliver` — destination pyle receives the bytes. The
    /// request/accept documents travel with them; each byte is re-hashed
    /// against the signed manifest before it is stored.
    pub fn handle_deliver(&self, node: &crate::node::Node, req: &Request) -> Response {
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let request_text = body.get("request").and_then(|v| v.as_str()).unwrap_or("");
        let accept_text = body.get("accept").and_then(|v| v.as_str()).unwrap_or("");
        let request = match parse_doc(request_text)
            .ok()
            .and_then(|d| TransferRequestDoc::from_doc(&d))
        {
            Some(r) => r,
            None => return Response::json(400, json_err("invalid request")),
        };
        let accept_doc = match parse_doc(accept_text) {
            Ok(d) => d,
            Err(e) => return Response::json(400, json_err(&format!("invalid accept: {e}"))),
        };
        let accept = match TransferAcceptDoc::from_doc(&accept_doc) {
            Some(a) => a,
            None => return Response::json(400, json_err("not a transfer acceptance")),
        };
        if request.new_pyle != self.cfg.server_id {
            return Response::json(403, json_err("this pyle is not the destination"));
        }
        if accept.request_hash != content_hash(request_text.as_bytes())
            || accept.request_doc != request_text
        {
            return Response::json(409, json_err("acceptance does not match the request"));
        }
        let request_signed =
            parse_doc(request_text).unwrap_or_else(|_| unreachable!("parsed above"));
        if request_signed.sigs.len() < 2
            || !verify_slot(
                &request_signed,
                0,
                &request.old_owner,
                &request.old_owner_pubkey,
            )
            || !verify_slot(
                &request_signed,
                1,
                &request.old_pyle,
                &request.old_pyle_pubkey,
            )
        {
            return Response::json(401, json_err("request signatures invalid"));
        }
        if accept_doc.sigs.len() != 2
            || !verify_slot(&accept_doc, 0, &accept.new_owner, &request.new_owner_pubkey)
            || !verify_slot(&accept_doc, 1, &accept.new_pyle, &request.new_pyle_pubkey)
        {
            return Response::json(401, json_err("acceptance signatures invalid"));
        }
        let Some(record) = ({
            let st = node.state.lock().unwrap();
            st.transfers.get(&request.request_id).cloned()
        }) else {
            return Response::json(404, json_err("transfer request not in this inbox"));
        };
        if record.new_owner != request.new_owner || record.request_hash != accept.request_hash {
            return Response::json(409, json_err("transfer record mismatch"));
        }
        let blobs = body
            .get("blobs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if blobs.len() != record.assets.len() {
            return Response::json(400, json_err("blob count does not match the manifest"));
        }
        let mut plain_by_dest: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (asset, item) in record.assets.iter().zip(blobs.iter()) {
            let dest = item.get("dest").and_then(|v| v.as_str()).unwrap_or("");
            let hash = item.get("hash").and_then(|v| v.as_str()).unwrap_or("");
            let data_b64 = item.get("data").and_then(|v| v.as_str()).unwrap_or("");
            if dest != asset.dest || hash != asset.hash {
                return Response::json(409, json_err("blob does not match the manifest"));
            }
            let Ok(data) = base64::engine::general_purpose::STANDARD.decode(data_b64) else {
                return Response::json(400, json_err("blob is not base64"));
            };
            if data.len() as u64 != asset.size || content_hash(&data) != asset.hash {
                return Response::json(409, json_err("blob hash or size mismatch"));
            }
            plain_by_dest.insert(asset.dest.clone(), data);
        }
        let mut st = node.state.lock().unwrap();
        let total: u64 = plain_by_dest.values().map(|v| v.len() as u64).sum();
        let used = st.stored.get(&record.new_owner).copied().unwrap_or(0);
        if self.cfg.moira_bytes > 0 && used + total > self.cfg.moira_bytes {
            return Response::json(413, json_err("recipient moira quota exceeded"));
        }
        for (dest, data) in &plain_by_dest {
            let key = State::key(&record.new_owner, dest);
            if let Some(existing) = st.objects.get(&key) {
                if existing.hash != content_hash(data) {
                    return Response::json(409, json_err("destination path already occupied"));
                }
            }
        }
        let mut added = 0u64;
        for (dest, data) in &plain_by_dest {
            let key = State::key(&record.new_owner, dest);
            if st.objects.contains_key(&key) {
                continue;
            }
            let master = st.master_key;
            added += data.len() as u64;
            st.objects.insert(
                key,
                Blob {
                    owner: record.new_owner.clone(),
                    path: dest.clone(),
                    hash: content_hash(data),
                    bytes: aead_seal(&master, data),
                },
            );
        }
        *st.stored.entry(record.new_owner.clone()).or_insert(0) += added;
        let record_path =
            write_final_doc_locked(&mut st, &record, accept_text).unwrap_or_else(|_| String::new());
        if let Some(r) = st.transfers.get_mut(&request.request_id) {
            r.status = "completed".into();
            r.record_path = Some(record_path.clone());
        }
        Response::json(
            200,
            serde_json::json!({
                "status": "completed",
                "stored": plain_by_dest.len(),
                "record_path": record_path,
            })
            .to_string(),
        )
    }

    fn complete_local(
        &self,
        node: &crate::node::Node,
        record: &TransferRecord,
    ) -> Result<(String, String), Response> {
        let mut st = node.state.lock().unwrap();
        let total: u64 = record.assets.iter().map(|a| a.size).sum();
        let used = st.stored.get(&record.new_owner).copied().unwrap_or(0);
        if self.cfg.moira_bytes > 0 && used + total > self.cfg.moira_bytes {
            return Err(Response::json(
                413,
                json_err("recipient moira quota exceeded"),
            ));
        }
        // Validate every source and every destination before writing anything:
        // a collision on the last asset must not leave the earlier assets
        // half-copied.
        let mut prepared: Vec<(&str, &str, &str, Vec<u8>)> = Vec::new();
        for asset in &record.assets {
            let src_key = State::key(&record.old_owner, &asset.source);
            let Some(src) = st.objects.get(&src_key) else {
                return Err(Response::json(
                    409,
                    json_err(&format!("source {} disappeared", asset.source)),
                ));
            };
            let plain = match aead_open(&st.master_key, &src.bytes) {
                Ok(p) => p,
                Err(_) => return Err(Response::json(500, json_err("storage decryption failed"))),
            };
            if content_hash(&plain) != asset.hash || plain.len() as u64 != asset.size {
                return Err(Response::json(
                    409,
                    json_err("source content no longer matches the manifest"),
                ));
            }
            let dst_key = State::key(&record.new_owner, &asset.dest);
            if let Some(existing) = st.objects.get(&dst_key) {
                if existing.hash != asset.hash {
                    return Err(Response::json(
                        409,
                        json_err("destination path already occupied"),
                    ));
                }
            }
            prepared.push((&asset.dest, &asset.hash, &asset.source, plain));
        }
        let mut added = 0u64;
        for (dest, hash, _source, plain) in prepared {
            let dst_key = State::key(&record.new_owner, dest);
            if st.objects.contains_key(&dst_key) {
                continue;
            }
            let master = st.master_key;
            added += plain.len() as u64;
            st.objects.insert(
                dst_key,
                Blob {
                    owner: record.new_owner.clone(),
                    path: dest.to_string(),
                    hash: hash.to_string(),
                    bytes: aead_seal(&master, &plain),
                },
            );
        }
        *st.stored.entry(record.new_owner.clone()).or_insert(0) += added;
        let accept_text = record.accept_doc.clone().unwrap_or_default();
        let record_path = write_final_doc_locked(&mut st, record, &accept_text)?;
        if let Some(r) = st.transfers.get_mut(&record.request_id) {
            r.status = "completed".into();
            r.record_path = Some(record_path.clone());
        }
        Ok(("completed".into(), record_path))
    }

    fn forward_to_source(
        &self,
        node: &crate::node::Node,
        record: &TransferRecord,
        accept_text: &str,
    ) -> Result<(String, String), String> {
        let endpoint = crate::pyle::endpoint_from_id(&record.old_pyle)
            .ok_or_else(|| format!("pyle {} is not endpoint-addressed", record.old_pyle))?;
        let pin = if record.old_pyle_tls_pin.is_empty() {
            None
        } else {
            Some(record.old_pyle_tls_pin.clone())
        };
        let client = FedHttpClient::new(&endpoint, pin).map_err(|e| e.to_string())?;
        let body = serde_json::json!({
            "request": record.request_doc,
            "accept": accept_text,
        })
        .to_string();
        let resp = client
            .post_json("/transfer/complete", &body)
            .map_err(|e| e.to_string())?;
        if !(200..300).contains(&resp.status) {
            return Err(format!(
                "source pyle answered {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
        let status = v["status"].as_str().unwrap_or("completed").to_string();
        let record_path = v["record_path"].as_str().unwrap_or("").to_string();
        let _ = node;
        Ok((status, record_path))
    }

    fn push_to_destination(
        &self,
        node: &crate::node::Node,
        record: &TransferRecord,
        accept_text: &str,
    ) -> Result<String, String> {
        let endpoint = crate::pyle::endpoint_from_id(&record.new_pyle)
            .ok_or_else(|| format!("pyle {} is not endpoint-addressed", record.new_pyle))?;
        let pin = if record.new_pyle_tls_pin.is_empty() {
            None
        } else {
            Some(record.new_pyle_tls_pin.clone())
        };
        let client = FedHttpClient::new(&endpoint, pin).map_err(|e| e.to_string())?;
        let mut blobs = Vec::with_capacity(record.assets.len());
        {
            let st = node.state.lock().unwrap();
            for asset in &record.assets {
                let key = State::key(&record.old_owner, &asset.source);
                let Some(blob) = st.objects.get(&key) else {
                    return Err(format!("source {} disappeared", asset.source));
                };
                let plain = aead_open(&st.master_key, &blob.bytes).map_err(|e| format!("{e:?}"))?;
                if content_hash(&plain) != asset.hash || plain.len() as u64 != asset.size {
                    return Err(format!("source {} changed", asset.source));
                }
                blobs.push(serde_json::json!({
                    "dest": asset.dest,
                    "hash": asset.hash,
                    "data": base64::engine::general_purpose::STANDARD.encode(plain),
                }));
            }
        }
        let body = serde_json::json!({
            "request": record.request_doc,
            "accept": accept_text,
            "blobs": blobs,
        })
        .to_string();
        let resp = client
            .post_json("/transfer/deliver", &body)
            .map_err(|e| e.to_string())?;
        if !(200..300).contains(&resp.status) {
            return Err(format!(
                "destination pyle answered {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
        Ok(v["record_path"].as_str().unwrap_or("").to_string())
    }

    fn discover_pyle(
        &self,
        pyle_id: &str,
        supplied_pin: &str,
        user_id: Option<&str>,
    ) -> Result<(String, String, Option<String>), String> {
        let endpoint = crate::pyle::endpoint_from_id(pyle_id)
            .ok_or_else(|| format!("pyle {pyle_id} is not endpoint-addressed"))?;
        let pin_opt = if supplied_pin.is_empty() {
            None
        } else {
            Some(supplied_pin.to_string())
        };
        let client = FedHttpClient::new(&endpoint, pin_opt.clone()).map_err(|e| e.to_string())?;
        let resp = client.get_json("/health").map_err(|e| e.to_string())?;
        if !(200..300).contains(&resp.status) {
            return Err(format!("health answered {}", resp.status));
        }
        let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
        let node_pub = v["node_sign_pub"]
            .as_str()
            .ok_or_else(|| "health missing node_sign_pub".to_string())?
            .to_string();
        let pin = if supplied_pin.is_empty() {
            v["tls_pin"].as_str().unwrap_or_default().to_string()
        } else {
            supplied_pin.to_string()
        };
        let user_pub = if let Some(uid) = user_id {
            let client = FedHttpClient::new(
                &endpoint,
                if pin.is_empty() {
                    pin_opt
                } else {
                    Some(pin.clone())
                },
            )
            .map_err(|e| e.to_string())?;
            let resp = client
                .get_json(&format!("/registry?user_id={uid}"))
                .map_err(|e| e.to_string())?;
            if !(200..300).contains(&resp.status) {
                return Err(format!("registry answered {}", resp.status));
            }
            let v: serde_json::Value =
                serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
            Some(
                v["sign_pub"]
                    .as_str()
                    .ok_or_else(|| "registry missing sign_pub".to_string())?
                    .to_string(),
            )
        } else {
            None
        };
        Ok((node_pub, pin, user_pub))
    }

    fn send_request_to_destination(
        &self,
        request: &TransferRequestDoc,
        request_text: &str,
    ) -> Result<(), String> {
        let endpoint = crate::pyle::endpoint_from_id(&request.new_pyle)
            .ok_or_else(|| format!("pyle {} is not endpoint-addressed", request.new_pyle))?;
        let pin = if request.new_pyle_tls_pin.is_empty() {
            None
        } else {
            Some(request.new_pyle_tls_pin.clone())
        };
        let client = FedHttpClient::new(&endpoint, pin).map_err(|e| e.to_string())?;
        let body = serde_json::json!({ "request": request_text }).to_string();
        let resp = client
            .post_json("/transfer/inbox", &body)
            .map_err(|e| e.to_string())?;
        if !(200..300).contains(&resp.status) {
            return Err(format!(
                "destination pyle answered {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        Ok(())
    }

    fn manifest(
        &self,
        node: &crate::node::Node,
        old_owner: &str,
        old_pyle: &str,
        target_kind: &str,
        targets: &[String],
    ) -> Result<Vec<TransferAsset>, Response> {
        let st = node.state.lock().unwrap();
        if st.ceessions.get(old_owner).is_some_and(|c| !c.is_empty())
            && target_kind == TRANSFER_TARGET_IDENTITY
        {
            return Err(Response::json(
                409,
                json_err("identity already has a ceded path"),
            ));
        }
        let mut out = Vec::new();
        for (path, blob) in &st.objects {
            let Some((owner, blob_path)) = path.split_once('/') else {
                continue;
            };
            if owner != old_owner
                || blob_path.starts_with("metabibasis/")
                || blob_path.starts_with("pow/")
            {
                continue;
            }
            let selected = match target_kind {
                TRANSFER_TARGET_IDENTITY => true,
                TRANSFER_TARGET_FILE => targets.iter().any(|t| t == blob_path),
                TRANSFER_TARGET_DIR => targets.iter().any(|t| in_scope(blob_path, t)),
                _ => false,
            };
            if !selected {
                continue;
            }
            if target_kind != TRANSFER_TARGET_IDENTITY
                && st
                    .ceessions
                    .get(old_owner)
                    .is_some_and(|cs| cs.iter().any(|c| in_scope(blob_path, &c.path)))
            {
                return Err(Response::json(
                    409,
                    json_err("a target is already read-only (ceded)"),
                ));
            }
            let dest = if target_kind == TRANSFER_TARGET_IDENTITY {
                format!("{old_owner}@{old_pyle}/{blob_path}")
            } else {
                blob_path.to_string()
            };
            out.push(TransferAsset {
                source: blob_path.to_string(),
                dest,
                hash: blob.hash.clone(),
                size: (blob.bytes.len().saturating_sub(crate::node::SEAL_OVERHEAD)) as u64,
            });
        }
        out.sort_by(|a, b| a.source.cmp(&b.source));
        Ok(out)
    }

    /// `POST /transfer/release` — destination pyle asks the source to drop the
    /// old owner's copy after the cessionário deleted it. The node signature is
    /// checked against the `new_pyle_pubkey` recorded in the transfer, so no
    /// federation allowlist is needed for this cleanup.
    pub fn handle_release(&self, node: &crate::node::Node, req: &Request) -> Response {
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let request_id = body
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pyle = body.get("pyle").and_then(|v| v.as_str()).unwrap_or("");
        let signature = body.get("signature").and_then(|v| v.as_str()).unwrap_or("");
        let dests: Vec<String> = body
            .get("dests")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if request_id.is_empty() || pyle.is_empty() || signature.is_empty() || dests.is_empty() {
            return Response::json(
                400,
                json_err("request_id, dests, pyle and signature required"),
            );
        }
        let record = {
            let st = node.state.lock().unwrap();
            st.transfers.get(request_id).cloned()
        };
        let Some(record) = record else {
            return Response::json(404, json_err("transfer not found"));
        };
        if record.old_pyle != self.cfg.server_id {
            return Response::json(403, json_err("this pyle is not the source"));
        }
        if record.status != "completed" {
            return Response::json(409, json_err("transfer is not completed"));
        }
        if pyle != record.new_pyle {
            return Response::json(403, json_err("only the destination pyle may release"));
        }
        let Some(tag) = sig_from_b64(signature) else {
            return Response::json(400, json_err("invalid release signature"));
        };
        let Ok(pub_bytes) = hex::decode(&record.new_pyle_pubkey) else {
            return Response::json(500, json_err("stored pyle key invalid"));
        };
        let Ok(pub_arr) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
            return Response::json(500, json_err("stored pyle key invalid"));
        };
        let payload = release_payload(request_id, &dests);
        if ed25519_verify(&pub_arr, payload.as_bytes(), &tag).is_err() {
            return Response::json(401, json_err("release signature invalid"));
        }
        let removed = release_local(node, &record, &dests, None);
        Response::json(
            200,
            serde_json::json!({ "released": true, "removed": removed }).to_string(),
        )
    }
}

fn node_now(node: &crate::node::Node) -> u64 {
    node.now()
}

fn node_node_sign_pub(node: &crate::node::Node) -> String {
    let seed = node.state.lock().unwrap().node_sign_seed;
    hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

fn old_pyle_id(node: &crate::node::Node) -> String {
    node.cfg.server_id.clone()
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn record_from_request(
    request: &TransferRequestDoc,
    request_doc: String,
    request_hash: String,
) -> TransferRecord {
    TransferRecord {
        request_id: request.request_id.clone(),
        request_doc,
        request_hash,
        old_owner: request.old_owner.clone(),
        new_owner: request.new_owner.clone(),
        old_nickname: request.old_nickname.clone(),
        new_nickname: request.new_nickname.clone(),
        old_uri: request.old_uri.clone(),
        new_uri: request.new_uri.clone(),
        old_pyle: request.old_pyle.clone(),
        new_pyle: request.new_pyle.clone(),
        old_owner_pubkey: request.old_owner_pubkey.clone(),
        new_owner_pubkey: request.new_owner_pubkey.clone(),
        old_pyle_pubkey: request.old_pyle_pubkey.clone(),
        new_pyle_pubkey: request.new_pyle_pubkey.clone(),
        old_pyle_tls_pin: request.old_pyle_tls_pin.clone(),
        new_pyle_tls_pin: request.new_pyle_tls_pin.clone(),
        target_kind: request.target_kind.clone(),
        scopes: if request.scopes.is_empty() {
            if request.target_kind == TRANSFER_TARGET_IDENTITY {
                vec![String::new()]
            } else {
                request.targets.iter().map(|t| t.source.clone()).collect()
            }
        } else {
            request.scopes.clone()
        },
        assets: request
            .targets
            .iter()
            .map(|t| TransferAsset {
                source: t.source.clone(),
                dest: t.dest.clone(),
                hash: t.hash.clone(),
                size: t.size,
            })
            .collect(),
        created_at: request.created_at,
        status: "pending".into(),
        accept_doc: None,
        accept_hash: None,
        record_path: None,
    }
}

fn verify_manifest(
    node: &crate::node::Node,
    old_owner: &str,
    request: &TransferRequestDoc,
) -> bool {
    let st = node.state.lock().unwrap();
    for asset in &request.targets {
        let Some(blob) = st.objects.get(&State::key(old_owner, &asset.source)) else {
            return false;
        };
        if blob.hash != asset.hash {
            return false;
        }
        let plain_len = blob.bytes.len().saturating_sub(crate::node::SEAL_OVERHEAD) as u64;
        if plain_len != asset.size {
            return false;
        }
    }
    true
}

fn in_scope(path: &str, scope: &str) -> bool {
    let scope = scope.trim_matches('/');
    if scope.is_empty() {
        return true;
    }
    path == scope || path.starts_with(&format!("{scope}/"))
}

fn append_node_signature(node: &crate::node::Node, doc: &mut Doc) -> bool {
    let seed = node.state.lock().unwrap().node_sign_seed;
    let key = SigningKey::from_bytes(&seed);
    let idx = doc.sigs.len();
    doc.sigs.push(Signature {
        signer: node.cfg.server_id.clone(),
        signer_pubkey: Some(hex::encode(key.verifying_key().to_bytes())),
        signature: String::new(),
    });
    let Ok(input) = doc.signature_input(idx) else {
        return false;
    };
    let sig = ed25519_sign(&key, input.as_bytes());
    doc.sigs[idx].signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    true
}

fn verify_slot(doc: &Doc, idx: usize, signer: &str, pubkey_hex: &str) -> bool {
    let Some(sig_field) = doc.sigs.get(idx) else {
        return false;
    };
    if sig_field.signer != signer {
        return false;
    }
    if let Some(pk) = &sig_field.signer_pubkey {
        if pk != pubkey_hex {
            return false;
        }
    }
    let Ok(pub_bytes) = hex::decode(pubkey_hex) else {
        return false;
    };
    let Ok(pub_arr) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
        return false;
    };
    let Some(tag) = sig_from_b64(&sig_field.signature) else {
        return false;
    };
    let Ok(input) = doc.signature_input(idx) else {
        return false;
    };
    ed25519_verify(&pub_arr, input.as_bytes(), &tag).is_ok()
}

fn lock_cessions(node: &crate::node::Node, record: &TransferRecord) {
    let scopes = if record.scopes.is_empty() {
        if record.target_kind == TRANSFER_TARGET_IDENTITY {
            vec![String::new()]
        } else {
            record.assets.iter().map(|a| a.source.clone()).collect()
        }
    } else {
        record.scopes.clone()
    };
    let mut st = node.state.lock().unwrap();
    for scope in scopes {
        let list = st.ceessions.entry(record.old_owner.clone()).or_default();
        if !list
            .iter()
            .any(|c| c.path == scope && c.to == record.new_owner)
        {
            list.push(Cession {
                to: record.new_owner.clone(),
                path: scope,
                at: node_now(node),
            });
        }
    }
}

fn record_path_for(old_uri: &str, new_uri: &str, request_id: &str, suffix: &str) -> String {
    let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes());
    format!(
        "metabibasis/{}-{}-{}{}",
        b64(old_uri),
        b64(new_uri),
        request_id,
        suffix
    )
}

fn pending_path(request: &TransferRequestDoc) -> String {
    record_path_for(
        &request.old_uri,
        &request.new_uri,
        &request.request_id,
        ".request.hdap",
    )
}

fn final_path(record: &TransferRecord) -> String {
    record_path_for(
        &record.old_uri,
        &record.new_uri,
        &record.request_id,
        ".hdap",
    )
}

fn put_object(st: &mut State, owner: &str, path: &str, data: &[u8]) -> Result<bool, Response> {
    let hash = content_hash(data);
    let key = State::key(owner, path);
    if let Some(existing) = st.objects.get(&key) {
        return Ok(existing.hash == hash);
    }
    let master = st.master_key;
    st.objects.insert(
        key,
        Blob {
            owner: owner.to_string(),
            path: path.to_string(),
            hash,
            bytes: aead_seal(&master, data),
        },
    );
    *st.stored.entry(owner.to_string()).or_insert(0) += data.len() as u64;
    Ok(true)
}

fn write_pending_doc(
    st: &mut State,
    request: &TransferRequestDoc,
    text: &str,
) -> Result<(), Response> {
    put_object(
        st,
        &request.new_owner,
        &pending_path(request),
        text.as_bytes(),
    )
    .map(|_| ())
    .map_err(|_| Response::json(500, json_err("could not store pending request")))
}

fn write_final_doc(
    st: &mut State,
    record: &TransferRecord,
    accept_text: &str,
) -> Result<(), Response> {
    let path = final_path(record);
    // The immutable acceptance record is the receipt. Write it to both the
    // cessionário (the main requirement) and the cedente when local.
    put_object(st, &record.new_owner, &path, accept_text.as_bytes())
        .map_err(|_| Response::json(500, json_err("could not store acceptance record")))?;
    if record.old_pyle == st.whoami {
        put_object(st, &record.old_owner, &path, accept_text.as_bytes())
            .map_err(|_| Response::json(500, json_err("could not store acceptance record")))?;
    }
    let _ = remove_pending(st, record);
    Ok(())
}

fn write_final_doc_locked(
    st: &mut State,
    record: &TransferRecord,
    accept_text: &str,
) -> Result<String, Response> {
    let path = final_path(record);
    put_object(st, &record.new_owner, &path, accept_text.as_bytes())
        .map_err(|_| Response::json(500, json_err("could not store acceptance record")))?;
    let _ = remove_pending(st, record);
    Ok(path)
}

/// After the cessionário deletes a path it received, the old copy is no
/// longer the counterpart of a live transfer. Ask the source pyle to remove
/// that copy and release the cession; otherwise the "read-only link" and every
/// mirror of it would outlive the content forever. Best-effort: the local
/// delete already succeeded, so an unreachable source is not rolled back.
pub(crate) fn release_after_delete(
    node: &crate::node::Node,
    new_owner: &str,
    dest: &str,
    hash: &str,
) -> usize {
    let record = {
        let st = node.state.lock().unwrap();
        st.transfers
            .values()
            .rev()
            .find(|r| {
                r.status == "completed"
                    && r.new_owner == new_owner
                    && r.assets.iter().any(|a| a.dest == dest && a.hash == hash)
            })
            .cloned()
    };
    let Some(record) = record else {
        return 0;
    };
    if record.old_pyle == node.cfg.server_id {
        release_local(node, &record, &[dest.to_string()], None)
    } else {
        let removed = send_release(node, &record, dest);
        // Even if the source is offline (or its pin rotated), this pyle must
        // stop serving its own mirror of the old namespace: the cessionário
        // deleted the content, so keeping the cached copy here would resurrect
        // a file the owner no longer wants. Other mirrors are retracted by the
        // source when it is reachable.
        for asset in record.assets.iter().filter(|a| a.dest == dest) {
            let _ = drop_local_replica(node, &record.old_owner, &asset.source, &asset.hash);
        }
        removed
    }
}

/// Evict a mirrored copy of `(owner, source)` if it still matches `hash`.
/// This is a local cache deletion, not an authoritative tombstone: the source
/// (or its notification) remains the authority for every other pyle.
fn drop_local_replica(node: &crate::node::Node, owner: &str, source: &str, hash: &str) -> bool {
    let key = State::key(owner, source);
    let mut st = node.state.lock().unwrap();
    let Some(blob) = st.objects.get(&key) else {
        return false;
    };
    if blob.hash != hash {
        return false;
    }
    let bytes = blob.bytes.len().saturating_sub(crate::node::SEAL_OVERHEAD) as u64;
    st.objects.remove(&key);
    if let Some(used) = st.stored.get_mut(owner) {
        *used = used.saturating_sub(bytes);
        if *used == 0 {
            st.stored.remove(owner);
        }
    }
    st.replica_acls.remove(&key);
    let replica = format!("{}:{}", node.cfg.server_id, key);
    for entry in st.prytaneion.values_mut() {
        entry.replicas.retain(|r| *r != replica);
    }
    true
}

fn send_release(node: &crate::node::Node, record: &TransferRecord, dest: &str) -> usize {
    let (endpoint, recorded_pin, node_id, sign_key) = {
        let st = node.state.lock().unwrap();
        // Prefer the live peer record: a handshake updates its pin, whereas
        // the pin captured in an older transfer record can be stale. Fall
        // back to the record/id when the peer is not in the bubble anymore.
        let peer = st.peers.get(&record.old_pyle);
        let endpoint = peer
            .map(|p| p.endpoint.clone())
            .filter(|e| !e.trim().is_empty())
            .or_else(|| crate::pyle::endpoint_from_id(&record.old_pyle));
        let pin = peer
            .and_then(|p| p.tls_pin.clone())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| record.old_pyle_tls_pin.clone());
        (
            endpoint,
            pin,
            node.cfg.server_id.clone(),
            SigningKey::from_bytes(&st.node_sign_seed),
        )
    };
    let Some(endpoint) = endpoint else {
        return 0;
    };
    let pin = if recorded_pin.is_empty() {
        None
    } else {
        Some(recorded_pin)
    };
    let Ok(client) = FedHttpClient::new(&endpoint, pin) else {
        return 0;
    };
    let dests = vec![dest.to_string()];
    let payload = release_payload(&record.request_id, &dests);
    let signature = base64::engine::general_purpose::STANDARD
        .encode(ed25519_sign(&sign_key, payload.as_bytes()).to_bytes());
    let body = serde_json::json!({
        "request_id": record.request_id,
        "dests": dests,
        "pyle": node_id,
        "signature": signature,
    })
    .to_string();
    match client.post_json("/transfer/release", &body) {
        Ok(resp) if (200..300).contains(&resp.status) => {
            serde_json::from_slice::<serde_json::Value>(&resp.body)
                .ok()
                .and_then(|v| v["removed"].as_u64())
                .unwrap_or(0) as usize
        }
        _ => 0,
    }
}

fn release_payload(request_id: &str, dests: &[String]) -> String {
    format!("hdap-transfer-release:{request_id}:{}", dests.join("\n"))
}

/// Remove the old owner's copy of `dests` on the source pyle and drop the
/// cession once no live object remains under its scope. `skip` is the peer that
/// just sent us the update (used when forwarding a deletion, so we do not echo
/// it back).
pub(crate) fn release_local(
    node: &crate::node::Node,
    record: &TransferRecord,
    dests: &[String],
    skip: Option<&str>,
) -> usize {
    let now = node.now();
    let mut removed: Vec<(String, String, String)> = Vec::new();
    {
        let mut st = node.state.lock().unwrap();
        for dest in dests {
            let Some(asset) = record.assets.iter().find(|a| a.dest == *dest) else {
                continue;
            };
            let key = State::key(&record.old_owner, &asset.source);
            let Some(blob) = st.objects.get(&key).cloned() else {
                continue;
            };
            if blob.hash != asset.hash {
                // The source was already rewritten (should be impossible while
                // the cession exists), so do not delete unrelated bytes.
                continue;
            }
            let plain = aead_open(&st.master_key, &blob.bytes).unwrap_or_default();
            let bytes = blob.bytes.len().saturating_sub(crate::node::SEAL_OVERHEAD) as u64;
            st.objects.remove(&key);
            if let Some(used) = st.stored.get_mut(&record.old_owner) {
                *used = used.saturating_sub(bytes);
                if *used == 0 {
                    st.stored.remove(&record.old_owner);
                }
            }
            if matches!(
                asset.source.as_str(),
                "adeia.hdap" | "kerux.hdap" | "timi.hdap" | "prytaneion.hdap" | "prosopeion.hdap"
            ) {
                node.storage.reindex_config_doc_removed(
                    &mut st,
                    &record.old_owner,
                    &asset.source,
                    &plain,
                );
            }
            let deletion = format!("DELETED:{}:{}", key, now);
            for entry in st.prytaneion.values_mut() {
                let replica = format!("{}:{}", node.cfg.server_id, key);
                if let Some(pos) = entry.replicas.iter().position(|r| *r == replica) {
                    entry.replicas.remove(pos);
                    entry.deletions.push(deletion.clone());
                }
            }
            removed.push((asset.source.clone(), asset.hash.clone(), deletion));
        }

        // A cession is only meaningful while the old owner still holds some
        // object under its scope. Once the cessionário deleted the last one,
        // keeping the lock would permanently bar the old owner from reusing
        // the path (and `POST /adeia` cannot undo it).
        let remaining: Vec<String> = st.objects.keys().cloned().collect();
        let mut empty = false;
        if let Some(list) = st.ceessions.get_mut(&record.old_owner) {
            list.retain(|c| {
                c.to != record.new_owner
                    || remaining.iter().any(|key| {
                        let Some((owner, path)) = key.split_once('/') else {
                            return false;
                        };
                        if owner != record.old_owner
                            || path.starts_with("metabibasis/")
                            || path.starts_with("pow/")
                        {
                            return false;
                        }
                        let scope = c.path.trim_matches('/');
                        scope.is_empty() || path == scope || path.starts_with(&format!("{scope}/"))
                    })
            });
            empty = list.is_empty();
        }
        if empty {
            st.ceessions.remove(&record.old_owner);
        }
    }
    for (path, hash, deletion) in &removed {
        let key = State::key(&record.old_owner, path);
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let operation_id = format!("del:{}:{}:{}", node.cfg.server_id, key, hex::encode(nonce));
        crate::node::notify_deletion(
            node,
            &record.old_owner,
            path,
            hash,
            deletion,
            &operation_id,
            skip,
        );
    }
    removed.len()
}

fn remove_pending(st: &mut State, record: &TransferRecord) -> bool {
    let path = record_path_for(
        &record.old_uri,
        &record.new_uri,
        &record.request_id,
        ".request.hdap",
    );
    let key = State::key(&record.new_owner, &path);
    if let Some(blob) = st.objects.remove(&key) {
        let len = blob.bytes.len().saturating_sub(crate::node::SEAL_OVERHEAD) as u64;
        if let Some(used) = st.stored.get_mut(&record.new_owner) {
            *used = used.saturating_sub(len);
        }
        true
    } else {
        false
    }
}

#[cfg(test)]
mod release_tests {
    use super::*;
    use crate::store::{Blob, TransferAsset, TransferRecord};
    use hdap_core::crypto::{aead_seal, sha256_hex};

    fn record(old: &str, new: &str, hash: &str) -> TransferRecord {
        TransferRecord {
            request_id: "req-1".into(),
            request_doc: String::new(),
            request_hash: String::new(),
            old_owner: old.into(),
            new_owner: new.into(),
            old_nickname: String::new(),
            new_nickname: String::new(),
            old_uri: String::new(),
            new_uri: String::new(),
            old_pyle: "pyle-a".into(),
            new_pyle: "pyle-b".into(),
            old_owner_pubkey: String::new(),
            new_owner_pubkey: String::new(),
            old_pyle_pubkey: String::new(),
            new_pyle_pubkey: String::new(),
            old_pyle_tls_pin: String::new(),
            new_pyle_tls_pin: String::new(),
            target_kind: TRANSFER_TARGET_FILE.into(),
            scopes: vec!["docs/r.txt".into()],
            assets: vec![TransferAsset {
                source: "docs/r.txt".into(),
                dest: "docs/r.txt".into(),
                hash: hash.into(),
                size: 4,
            }],
            created_at: 1,
            status: "completed".into(),
            accept_doc: None,
            accept_hash: None,
            record_path: None,
        }
    }

    #[test]
    fn deleting_a_transferred_file_evicts_the_local_mirror_even_if_the_source_is_gone() {
        let cfg = Config {
            server_id: "pyle-b".into(),
            ..Config::default()
        };
        let node = crate::node::Node::new(cfg);
        let old = "alice_0123456789abcdef";
        let new = "bob_0123456789abcdef";
        let data = b"blog";
        let hash = sha256_hex(data);
        {
            let mut st = node.state.lock().unwrap();
            st.transfers.insert("req-1".into(), record(old, new, &hash));
            let master = st.master_key;
            for (owner, path) in [(old, "docs/r.txt"), (new, "docs/r.txt")] {
                st.objects.insert(
                    State::key(owner, path),
                    Blob {
                        owner: owner.into(),
                        path: path.into(),
                        hash: hash.clone(),
                        bytes: aead_seal(&master, data),
                    },
                );
            }
        }
        let removed = release_after_delete(&node, new, "docs/r.txt", &hash);
        assert_eq!(
            removed, 0,
            "pyle-a is not endpoint-addressed: no remote ack"
        );
        assert!(
            !node
                .state
                .lock()
                .unwrap()
                .objects
                .contains_key(&State::key(old, "docs/r.txt")),
            "the local mirror of the old namespace must be evicted"
        );
        assert!(
            node.state
                .lock()
                .unwrap()
                .objects
                .contains_key(&State::key(new, "docs/r.txt")),
            "the destination copy is deleted by the caller, not by the release"
        );
    }
}
