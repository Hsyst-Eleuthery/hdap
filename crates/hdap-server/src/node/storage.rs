//! Storage module: ktema (upload, download, list, delete), encryption at rest.

use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use hdap_core::crypto::{aead_open, aead_seal};
use hdap_core::doc::{parse as parse_doc, DocType};
use rand_core::RngCore;
use serde_json::Value;

use crate::config::Config;
use crate::http::{Request, Response};
use crate::node::{content_hash, json_err, Access, SEAL_OVERHEAD};
use crate::store::{Blob, State};

pub struct StorageModule {
    cfg: Config,
}

impl StorageModule {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    /// `POST /ktema` — upload a blob (requires band credit + permissions).
    pub fn handle_ktema_upload(&self, node: &crate::node::Node, req: &Request) -> Response {
        let now = node.now();
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let owner = match req.query.get("owner").cloned() {
            Some(o) => o,
            None => return Response::json(400, json_err("owner query required")),
        };
        let path = match req.query.get("path").cloned() {
            Some(p) => p,
            None => return Response::json(400, json_err("path query required")),
        };
        if is_transfer_record_path(&path) {
            return Response::json(403, json_err("metabibasis records are immutable"));
        }
        if !node.authorize(&user_id, &owner, &path, Access::Write) {
            return Response::json(403, json_err("forbidden: insufficient permission"));
        }
        // Verify author signature (§4.2 rule 6): the author must sign the raw
        // content so the node can prove who wrote the content, not just that
        // the upload was authenticated. The client sends the signature in
        // `x-hdap-sphragis` header (base64 Ed25519 of the raw body).
        let sphragis_b64 = match req.headers.get("x-hdap-sphragis") {
            Some(h) => h,
            None => {
                return Response::json(400, json_err("missing author signature (x-hdap-sphragis)"))
            }
        };
        let sphragis_bytes = match base64::engine::general_purpose::STANDARD.decode(sphragis_b64) {
            Ok(b) => b,
            Err(_) => return Response::json(400, json_err("invalid sphragis encoding")),
        };
        if sphragis_bytes.len() != 64 {
            return Response::json(400, json_err("invalid sphragis signature length"));
        }
        let sphragis: [u8; 64] = sphragis_bytes.as_slice().try_into().unwrap();
        let sphragis = Ed25519Signature::from_bytes(&sphragis);
        let Some(owner_pub) = node
            .state
            .lock()
            .unwrap()
            .users
            .get(&user_id)
            .and_then(|u| u.sign_pub_bytes())
        else {
            return Response::json(403, json_err("session user has no signing key"));
        };
        let pub_key = match VerifyingKey::from_bytes(&owner_pub) {
            Ok(pk) => pk,
            Err(_) => return Response::json(500, json_err("invalid stored public key")),
        };
        if pub_key.verify(req.body.as_ref(), &sphragis).is_err() {
            return Response::json(401, json_err("author signature invalid"));
        }
        if req.body.len() as u64 + 12 + 16 > self.cfg.max_upload_bytes {
            return Response::json(413, json_err("payload too large"));
        }
        let key = State::key(&owner, &path);
        let hash = content_hash(&req.body);
        let master_key = node.state.lock().unwrap().master_key;
        let sealed = aead_seal(&master_key, &req.body);
        let mut st = node.state.lock().unwrap();

        // Per-user storage quota (`moira`, §16.4); 0 = unlimited. Checked
        // *before* payment so a refused upload never burns band credit or a
        // syngraphe/pow proof (charging for a rejected request is a bug).
        let used = st.stored.get(&owner).copied().unwrap_or(0);
        if self.cfg.moira_bytes > 0 && used + req.body.len() as u64 > self.cfg.moira_bytes {
            return Response::json(413, json_err("moira quota exceeded"));
        }

        // Payment (§9.4). A countersigned `.hdap.pow` is consumed by an
        // owner-signed `syngraphe`; the proof object is replaced by the
        // syngraphe in the same directory. Legacy/small uploads fall back to
        // the raw `choregia` integer.
        let mut paid_by_band = false;
        if let Some(header) = req.headers.get("x-hdap-syngraphe") {
            match self.consume_syngraphe(&mut st, &owner, &path, header, req.body.len() as u64, now)
            {
                Ok(()) => paid_by_band = true,
                Err(resp) => return resp,
            }
        }
        if !paid_by_band {
            let credit = st.choregia.get(&owner).copied().unwrap_or(0);
            if credit < req.body.len() as u64 {
                return Response::json(403, json_err("insufficient band credit"));
            }
            st.choregia
                .insert(owner.clone(), credit - req.body.len() as u64);
        }

        // Encrypt at rest; never store plaintext.
        st.objects.insert(
            key.clone(),
            Blob {
                owner: owner.clone(),
                path: path.clone(),
                hash: hash.clone(),
                bytes: sealed,
            },
        );
        *st.stored.entry(owner.clone()).or_insert(0) += req.body.len() as u64;

        // Config documents written by their owner drive the *structured* maps
        // too (§16): saving `adeia.hdap` in the GUI would otherwise update a
        // blob that authorization never reads, and aliases/prices published
        // through the fast paths would drift from the durable docs.
        if owner == user_id
            && matches!(
                path.as_str(),
                "adeia.hdap" | "kerux.hdap" | "timi.hdap" | "prytaneion.hdap" | "prosopeion.hdap"
            )
        {
            self.reindex_config_doc(&mut st, &owner, &path, &req.body);
        }

        // Register the origin in the `prytaneion` (especificacao §10.2).
        let replica = format!("{}:{}", self.cfg.server_id, key);
        let created_at = now;
        let pubkey_hex = hex::encode(owner_pub);
        let entry =
            st.prytaneion
                .entry(hash.clone())
                .or_insert_with(|| crate::store::PrytaneionEntry {
                    content_hash: hash.clone(),
                    origin_server: self.cfg.server_id.clone(),
                    origin_user: owner.clone(),
                    origin_user_pubkey: pubkey_hex.clone(),
                    origin_path: path.clone(),
                    sphragis: sphragis_b64.clone(),
                    replicas: vec![replica.clone()],
                    deletions: vec![],
                    created_at,
                });
        // The global ledger must be able to verify this content even if this
        // pyle is gone, so persist the author key, original path and signature
        // with the provenance entry (not only in the transient upload request).
        if entry.origin_user_pubkey.is_empty() {
            entry.origin_user_pubkey = pubkey_hex;
        }
        if entry.origin_path.is_empty() {
            entry.origin_path = path.clone();
        }
        if entry.sphragis.is_empty() {
            entry.sphragis = sphragis_b64.clone();
        }
        if !entry.replicas.contains(&replica) {
            entry.replicas.push(replica.clone());
        }

        Response::json(
            201,
            serde_json::json!({ "user": owner, "path": path, "hash": hash, "bytes": req.body.len() })
                .to_string(),
        )
    }

    /// Validate and consume a band object for this upload (§9.4).
    ///
    /// The header is a base64 `.hdap.syngraphe` signed by the *owner* of the
    /// band. On success the referenced `.hdap.pow` object is deleted, a
    /// `.hdap.syngraphe` is written in its place, and the band object's
    /// `remaining` is decremented (removed once exhausted).
    fn consume_syngraphe(
        &self,
        st: &mut State,
        owner: &str,
        path: &str,
        header: &str,
        spent: u64,
        now: u64,
    ) -> Result<(), Response> {
        let master_key = st.master_key;
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(header) else {
            return Err(Response::json(400, json_err("syngraphe header not base64")));
        };
        let Ok(mut syn_doc) = parse_doc(&String::from_utf8_lossy(&raw)) else {
            return Err(Response::json(400, json_err("syngraphe document corrupt")));
        };
        let Some(syn) = hdap_core::protocol::SyngrapheDoc::from_doc(&syn_doc) else {
            return Err(Response::json(
                400,
                json_err("syngraphe document malformed"),
            ));
        };
        if syn.owner != owner || syn.used_for != path || syn.bandwidth_used != spent {
            return Err(Response::json(
                403,
                json_err("syngraphe does not authorize this upload"),
            ));
        }
        if syn.issuer != self.cfg.server_id {
            return Err(Response::json(403, json_err("syngraphe issued elsewhere")));
        }
        let Some(band) = st.band_objects.get(&syn.pow_object_hash) else {
            return Err(Response::json(
                402,
                json_err("unknown or spent band object"),
            ));
        };
        if band.owner != owner || !band.countersigned {
            return Err(Response::json(402, json_err("band object not spendable")));
        }
        if band.remaining < spent {
            return Err(Response::json(402, json_err("insufficient band credit")));
        }
        if band.expires_at != 0 && now > band.expires_at {
            return Err(Response::json(402, json_err("band object expired")));
        }
        let pow_path = band.path.clone();
        let new_remaining = band.remaining - spent;
        // Verify the owner signed the syngraphe (slot 0).
        let Some(pub_bytes) = st.users.get(owner).and_then(|u| u.sign_pub_bytes()) else {
            return Err(Response::json(
                403,
                json_err("band owner has no signing key"),
            ));
        };
        let Some(tag) = syn_doc
            .sigs
            .first()
            .and_then(|s| crate::node::sig_from_b64(&s.signature))
        else {
            return Err(Response::json(401, json_err("syngraphe signature missing")));
        };
        let Ok(input) = syn_doc.signature_input(0) else {
            return Err(Response::json(
                400,
                json_err("syngraphe signatures malformed"),
            ));
        };
        if hdap_core::crypto::ed25519_verify(&pub_bytes, input.as_bytes(), &tag).is_err() {
            return Err(Response::json(401, json_err("syngraphe signature invalid")));
        }
        // Consume: the proof becomes a syngraphe in the same directory.
        st.objects.remove(&State::key(owner, &pow_path));
        let syn_path = pow_path
            .strip_suffix(".hdap.pow")
            .map(|base| format!("{base}.hdap.syngraphe"))
            .unwrap_or_else(|| format!("{pow_path}.syngraphe"));
        // The pyle countersigns the treaty it accepted (§9.4 "ack do nó"),
        // appending its own slot signed over `signature_input(1)`. The
        // advertised key is the node's persistent Ed25519 verifying key, so
        // third parties can actually verify the ack.
        {
            let sign_key = ed25519_dalek::SigningKey::from_bytes(&st.node_sign_seed);
            let node_sign_pub = hex::encode(sign_key.verifying_key().to_bytes());
            let idx = syn_doc.sigs.len();
            syn_doc.sigs.push(hdap_core::doc::Signature {
                signer: self.cfg.server_id.clone(),
                signer_pubkey: Some(node_sign_pub),
                signature: String::new(),
            });
            if let Ok(input) = syn_doc.signature_input(idx) {
                let ack = hdap_core::crypto::ed25519_sign(&sign_key, input.as_bytes());
                syn_doc.sigs[idx].signature =
                    base64::engine::general_purpose::STANDARD.encode(ack.to_bytes());
            }
        }
        let rendered = syn_doc.render();
        st.objects.insert(
            State::key(owner, &syn_path),
            Blob {
                owner: owner.to_string(),
                path: syn_path.clone(),
                hash: content_hash(rendered.as_bytes()),
                bytes: aead_seal(&master_key, rendered.as_bytes()),
            },
        );
        // Keep the legacy integer in sync so a band can never be spent twice.
        let credit = st.choregia.get(owner).copied().unwrap_or(0);
        st.choregia
            .insert(owner.to_string(), credit.saturating_sub(spent));
        if new_remaining == 0 {
            st.band_objects.remove(&syn.pow_object_hash);
        } else if let Some(b) = st.band_objects.get_mut(&syn.pow_object_hash) {
            b.remaining = new_remaining;
        }
        Ok(())
    }

    /// `GET /ktema` — download a blob (requires read permission).
    pub fn handle_ktema_get(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let owner = match req.query.get("owner").cloned() {
            Some(o) => o,
            None => return Response::json(400, json_err("owner query required")),
        };
        let path = match req.query.get("path").cloned() {
            Some(p) => p,
            None => return Response::json(400, json_err("path query required")),
        };
        if !node.authorize(&user_id, &owner, &path, Access::Read)
            && !node.authorize_replica(&user_id, &owner, &path)
        {
            return Response::json(403, json_err("forbidden: insufficient permission"));
        }
        let key = State::key(&owner, &path);
        let st = node.state.lock().unwrap();
        let Some(blob) = st.objects.get(&key).cloned() else {
            return Response::json(404, json_err("file not found"));
        };
        let plain = match aead_open(&st.master_key, &blob.bytes) {
            Ok(p) => p,
            Err(_) => return Response::json(500, json_err("storage decryption failed")),
        };
        if let Some(want) = req.query.get("hash") {
            if content_hash(&plain) != *want {
                return Response::json(409, json_err("integrity hash mismatch"));
            }
        }
        let mut resp = Response::bytes(200, "application/octet-stream", plain);
        resp.headers.insert("X-HDAP-Hash".to_string(), blob.hash);
        resp
    }

    /// `GET /ktema/list` — list directory contents (requires read on directory).
    pub fn handle_ktema_list(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let owner = match req.query.get("owner").cloned() {
            Some(o) => o,
            None => return Response::json(400, json_err("owner query required")),
        };
        let dir = req.query.get("path").cloned().unwrap_or_default();
        let prefix = if dir.is_empty() || dir == "/" {
            String::new()
        } else {
            format!("{}/", dir.trim_matches('/'))
        };
        // The dir itself must be readable to list its contents.
        if !node.authorize(&user_id, &owner, &dir, Access::Read)
            && !node.authorize_replica(&user_id, &owner, &dir)
        {
            return Response::json(403, json_err("forbidden: insufficient permission"));
        }
        let st = node.state.lock().unwrap();
        // Aggregate under each first segment: a subdirectory (more `/`
        // segments follow) or a direct file (the whole remainder is the name).
        let mut dirs: std::collections::BTreeSet<String> = Default::default();
        let mut files: Vec<Value> = Vec::new();
        for blob in st.objects.values() {
            if blob.owner != owner {
                continue;
            }
            let Some(rest) = blob.path.strip_prefix(&prefix) else {
                continue;
            };
            if rest.is_empty() || rest.starts_with('/') {
                continue;
            }
            match rest.split_once('/') {
                Some((sub, _)) => {
                    dirs.insert(sub.to_string());
                }
                None => {
                    let size = blob.bytes.len().saturating_sub(SEAL_OVERHEAD) as u64;
                    files.push(serde_json::json!({
                        "name": rest,
                        "dir": false,
                        "size": size,
                        "hash": blob.hash,
                        "path": blob.path,
                    }));
                }
            }
        }
        let mut entries: Vec<Value> = dirs
            .into_iter()
            .map(|name| {
                let full = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{}{}", prefix, name)
                };
                serde_json::json!({ "name": name, "dir": true, "path": full })
            })
            .collect();
        entries.append(&mut files);
        Response::json(
            200,
            serde_json::json!({ "owner": owner, "path": dir.trim_matches('/'), "entries": entries })
                .to_string(),
        )
    }

    /// `DELETE /ktema` — delete a blob (requires write permission).
    pub fn handle_ktema_delete(&self, node: &crate::node::Node, req: &Request) -> Response {
        let now = node.now();
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let owner = match req.query.get("owner").cloned() {
            Some(o) => o,
            None => return Response::json(400, json_err("owner query required")),
        };
        let path = match req.query.get("path").cloned() {
            Some(p) => p,
            None => return Response::json(400, json_err("path query required")),
        };
        if is_transfer_record_path(&path) {
            return Response::json(403, json_err("metabibasis records are immutable"));
        }
        if !node.authorize(&user_id, &owner, &path, Access::Write) {
            return Response::json(403, json_err("forbidden: insufficient permission"));
        }
        let key = State::key(&owner, &path);
        let (hash, deletion, operation_id) = {
            let mut st = node.state.lock().unwrap();
            // Capture the hash and plaintext before the blob is gone: the hash
            // identifies the replicas to retract, and config-doc deletions must
            // retract their structured side effects (permissions/aliases).
            let Some(blob) = st.objects.get(&key) else {
                return Response::json(404, json_err("file not found"));
            };
            let hash = blob.hash.clone();
            let old_plain = aead_open(&st.master_key, &blob.bytes).unwrap_or_default();
            let removed = blob.bytes.len().saturating_sub(SEAL_OVERHEAD) as u64;
            st.objects.remove(&key);
            if owner == user_id
                && matches!(
                    path.as_str(),
                    "adeia.hdap"
                        | "kerux.hdap"
                        | "timi.hdap"
                        | "prytaneion.hdap"
                        | "prosopeion.hdap"
                )
            {
                self.reindex_config_doc_removed(&mut st, &owner, &path, &old_plain);
            }
            // Decrement the per-user storage usage (moira quota).
            if let Some(used) = st.stored.get_mut(&owner) {
                *used = used.saturating_sub(removed);
                if *used == 0 {
                    st.stored.remove(&owner);
                }
            }
            // Tombstone (`prytaneion` keeps history; the blob itself is gone).
            let deletion = format!("DELETED:{}:{}", key, now);
            for entry in st.prytaneion.values_mut() {
                let replica = format!("{}:{}", self.cfg.server_id, key);
                if let Some(pos) = entry.replicas.iter().position(|r| *r == replica) {
                    entry.replicas.remove(pos);
                    entry.deletions.push(deletion.clone());
                }
            }
            let mut nonce = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut nonce);
            let operation_id = format!("del:{}:{}:{}", self.cfg.server_id, key, hex::encode(nonce));
            (hash, deletion, operation_id)
        };
        // If this path arrived through an ownership transfer, deleting the
        // cessionário's copy must also remove the old owner's read-only copy
        // and release the cession. Otherwise the "link" at the source (and
        // every mirror of it) outlives the content forever.
        let released = crate::node::transfer::release_after_delete(node, &owner, &path, &hash);
        // Tell every peer that pulled this namespace to drop its replica. The
        // book of watchers is filled when a peer requests `/homospondoi/
        // namespace`; without this push a deleted blob would live forever on
        // the mirrors. Failures are best-effort: the local delete stands.
        let notified = crate::node::notify_deletion(
            node,
            &owner,
            &path,
            &hash,
            &deletion,
            &operation_id,
            None,
        );
        Response::json(
            200,
            serde_json::json!({
                "deleted": true,
                "notified": notified,
                "released": released,
            })
            .to_string(),
        )
    }

    /// Keep the structured maps congruent with the root config docs.
    pub(crate) fn reindex_config_doc(&self, st: &mut State, owner: &str, path: &str, plain: &[u8]) {
        match path {
            "adeia.hdap" => {
                if let Ok(text) = std::str::from_utf8(plain) {
                    if matches!(parse_doc(text), Ok(d) if d.doc_type == DocType::Adeia) {
                        st.permissions.insert(owner.to_string(), text.to_string());
                    }
                }
            }
            "kerux.hdap" => {
                self.drop_owned_aliases(st, owner);
                if let Ok(d) = parse_doc(&String::from_utf8_lossy(plain)) {
                    let alias = d.body.get("ALIAS").cloned().unwrap_or_default();
                    let uri = d.body.get("TARGET_URI").cloned().unwrap_or_default();
                    if !alias.trim().is_empty() && !uri.trim().is_empty() {
                        st.kerux.insert(alias.clone(), uri);
                        st.kerux_owner.insert(alias, owner.to_string());
                    }
                }
            }
            "timi.hdap" => {
                if let Ok(d) = parse_doc(&String::from_utf8_lossy(plain)) {
                    if d.doc_type == DocType::Timi {
                        if let Some(pyle) = d.body.get("PYLE").filter(|p| !p.trim().is_empty()) {
                            st.timi
                                .insert(pyle.clone(), String::from_utf8_lossy(plain).into_owned());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Undo a config doc's side effects on the structured maps.
    pub(crate) fn reindex_config_doc_removed(
        &self,
        st: &mut State,
        owner: &str,
        path: &str,
        plain: &[u8],
    ) {
        match path {
            "adeia.hdap" => {
                st.permissions.remove(owner);
            }
            "kerux.hdap" => {
                self.drop_owned_aliases(st, owner);
            }
            "timi.hdap" => {
                if let Ok(d) = parse_doc(&String::from_utf8_lossy(plain)) {
                    if let Some(pyle) = d.body.get("PYLE").filter(|p| !p.trim().is_empty()) {
                        let removed = String::from_utf8_lossy(plain);
                        if st.timi.get(pyle).map(String::as_str) == Some(removed.as_ref()) {
                            st.timi.remove(pyle);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn drop_owned_aliases(&self, st: &mut State, owner: &str) {
        let owned: Vec<String> = st
            .kerux_owner
            .iter()
            .filter(|(_, o)| *o == owner)
            .map(|(a, _)| a.clone())
            .collect();
        for alias in owned {
            st.kerux.remove(&alias);
            st.kerux_owner.remove(&alias);
        }
    }
}

/// Transfer receipts are written by the node itself and are the durable proof
/// that an ownership change happened. A client must never overwrite or delete
/// them through the generic `ktema` routes.
fn is_transfer_record_path(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    path == "metabibasis" || path == "metabibasis.hdap" || path.starts_with("metabibasis/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;
    use crate::store::Session;
    use std::collections::BTreeMap;

    fn signed_upload_req(node: &Node, owner: &str, path: &str, size: usize) -> Request {
        let seed = node.state.lock().unwrap().node_sign_seed;
        let sign_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let data = vec![0u8; size];
        let sphragis = base64::engine::general_purpose::STANDARD
            .encode(ed25519_dalek::Signer::sign(&sign_key, &data).to_bytes());
        let mut query = BTreeMap::new();
        query.insert("owner".to_string(), owner.to_string());
        query.insert("path".to_string(), path.to_string());
        let mut headers = BTreeMap::new();
        headers.insert("authorization".to_string(), "Bearer tok".to_string());
        headers.insert("x-hdap-sphragis".to_string(), sphragis);
        Request {
            method: "POST".to_string(),
            path: "ktema".to_string(),
            query,
            headers,
            body: data,
        }
    }

    /// A refused upload must not charge the user: the moira quota is checked
    /// *before* the band debit, so a 413 leaves `choregia` untouched.
    #[test]
    fn a_refused_upload_does_not_burn_band_credit() {
        let owner = "jose_0123456789abcdef";
        let cfg = Config {
            moira_bytes: 100,
            ..Config::default()
        };
        let node = Node::new(cfg);
        {
            let mut st = node.state.lock().unwrap();
            // Extract node_sign_seed before mutable borrow
            let seed = st.node_sign_seed;
            // Create user with signing key
            st.users.insert(
                owner.to_string(),
                crate::store::UserRecord {
                    user_id: owner.to_string(),
                    nickname: "jose".to_string(),
                    suffix_hex: "0123456789abcdef".to_string(),
                    sign_pub_hex: hex::encode(
                        ed25519_dalek::SigningKey::from_bytes(&seed)
                            .verifying_key()
                            .to_bytes(),
                    ),
                    enc_pub_hex: "bb".repeat(32),
                    otp_anchor_hex: "cc".repeat(32),
                    otp_k: 1024,
                    created_at: 1_700_000_000,
                    home_pyle: "pyle-p".into(),
                },
            );
            st.sessions.insert(
                "tok".to_string(),
                Session {
                    user_id: owner.to_string(),
                    exp: u64::MAX,
                },
            );
            st.choregia.insert(owner.to_string(), 10_000);
        }

        let resp = node
            .storage
            .handle_ktema_upload(&node, &signed_upload_req(&node, owner, "big.bin", 200));
        assert_eq!(resp.status, 413, "{}", String::from_utf8_lossy(&resp.body));
        {
            let st = node.state.lock().unwrap();
            assert_eq!(
                st.choregia.get(owner).copied(),
                Some(10_000),
                "band credit must be intact after a quota refusal"
            );
            assert!(!st.objects.contains_key(&State::key(owner, "big.bin")));
        }

        // And a small upload within quota still works and is charged.
        let resp = node
            .storage
            .handle_ktema_upload(&node, &signed_upload_req(&node, owner, "small.bin", 50));
        assert_eq!(resp.status, 201, "{}", String::from_utf8_lossy(&resp.body));
        let st = node.state.lock().unwrap();
        assert_eq!(st.choregia.get(owner).copied(), Some(9_950));
        assert!(st.objects.contains_key(&State::key(owner, "small.bin")));
    }
}
