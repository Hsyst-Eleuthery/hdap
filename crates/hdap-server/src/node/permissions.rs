//! Permissions module: ACL (adeia), ownership transfer (metabibasis), authorization.

use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use hdap_core::crypto::ed25519_verify;
use hdap_core::doc::{parse as parse_doc, DocType};
use hdap_core::protocol::transfer_payload;

use crate::config::Config;
use crate::http::{Request, Response};
use crate::node::{content_hash, json_err, require_json, sig_from_b64, SEAL_OVERHEAD};
use crate::store::{Blob, State};

pub struct PermissionsModule {}

impl PermissionsModule {
    pub fn new(_cfg: Config) -> Self {
        Self {}
    }

    /// `POST /adeia` — update permissions document.
    pub fn handle_adeia(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let text = match std::str::from_utf8(&req.body) {
            Ok(t) => t,
            Err(_) => return Response::json(400, json_err("permissions doc must be utf-8")),
        };
        match parse_doc(text) {
            Ok(d) if d.doc_type == DocType::Adeia => {
                // Verify the adeia document signature if present (§16).
                // If the document has no signature, accept it for backward compatibility
                // but log a warning. New adeia documents should be signed.
                if let Some(sig_field) = d.sigs.first() {
                    let sig_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&sig_field.signature)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            return Response::json(400, json_err("invalid signature encoding"))
                        }
                    };
                    if sig_bytes.len() != 64 {
                        return Response::json(400, json_err("invalid signature length"));
                    }
                    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
                    let sig = Ed25519Signature::from_bytes(&sig_arr);
                    // Compute signature input before clearing signatures (the function
                    // requires the signature to be present at the given index).
                    let input = match d.signature_input(0) {
                        Ok(i) => i,
                        Err(_) => {
                            return Response::json(400, json_err("cannot compute signature input"))
                        }
                    };
                    let owner_pub = match node
                        .state
                        .lock()
                        .unwrap()
                        .users
                        .get(&user_id)
                        .and_then(|u| u.sign_pub_bytes())
                    {
                        Some(p) => p,
                        None => return Response::json(403, json_err("owner has no signing key")),
                    };
                    let verify_key = match VerifyingKey::from_bytes(&owner_pub) {
                        Ok(vk) => vk,
                        Err(_) => {
                            return Response::json(400, json_err("invalid stored public key"))
                        }
                    };
                    if verify_key.verify(input.as_ref(), &sig).is_err() {
                        return Response::json(401, json_err("adeia signature invalid"));
                    }
                } else {
                    eprintln!("WARNING: adeia document accepted without signature (backward compatibility)");
                }

                let mut st = node.state.lock().unwrap();
                // The `adeia.hdap` document is the source of truth: it is what
                // the directory shows and what federation ships to a mirroring
                // pyle. Store it as a blob *and* refresh the ACL cache, so the
                // two can never diverge (a bare map update would never federate).
                let bytes = text.as_bytes();
                let sealed = hdap_core::crypto::aead_seal(&st.master_key, bytes);
                let blob = Blob {
                    owner: user_id.clone(),
                    path: "adeia.hdap".to_string(),
                    hash: content_hash(bytes),
                    bytes: sealed,
                };
                st.objects.insert(State::key(&user_id, "adeia.hdap"), blob);
                st.permissions.insert(user_id, text.to_string());
                Response::json(
                    200,
                    serde_json::json!({ "permissions": "updated" }).to_string(),
                )
            }
            _ => Response::json(400, json_err("invalid permissions doc")),
        }
    }

    /// `POST /metabibasis` — transfer ownership (dual signature required).
    pub fn handle_metabibasis(&self, node: &crate::node::Node, req: &Request) -> Response {
        // Crítica 4: The transfer is not atomic - need to handle errors properly
        // We'll use a scoped approach to ensure atomicity
        let Some(old_owner) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let new_owner = body
            .get("new_owner")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_default();
        let targets: Vec<String> = body
            .get("targets")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let old_sig = body
            .get("old_signature")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let new_sig = body
            .get("new_signature")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if targets.is_empty() || new_owner.is_empty() {
            return Response::json(400, json_err("targets and new_owner required"));
        }
        if new_owner == old_owner {
            return Response::json(400, json_err("cannot transfer to yourself"));
        }
        let payload = transfer_payload(&old_owner, &new_owner, &targets);
        let mut st = node.state.lock().unwrap();
        let (Some(old_pub), Some(new_pub)) = (
            st.users.get(&old_owner).and_then(|u| u.sign_pub_bytes()),
            st.users.get(&new_owner).and_then(|u| u.sign_pub_bytes()),
        ) else {
            return Response::json(404, json_err("old or new owner not registered"));
        };
        let (Some(old_tag), Some(new_tag)) = (sig_from_b64(old_sig), sig_from_b64(new_sig)) else {
            return Response::json(401, json_err("dual signature invalid"));
        };
        if ed25519_verify(&old_pub, payload.as_bytes(), &old_tag).is_err()
            || ed25519_verify(&new_pub, payload.as_bytes(), &new_tag).is_err()
        {
            return Response::json(401, json_err("dual signature invalid"));
        }

        // The transfer is real: the target *blobs* move to the new owner's
        // space (§11.4 "a pasta vira um link simbólico no diretório do
        // cessionário"). `prytaneion` ORIGIN_* stays as history; the live
        // OWNER is derivable from `adeia`/`metabibasis` (§11.5).
        let old_blobs: Vec<(String, Blob)> = st
            .objects
            .iter()
            .filter(|(k, b)| b.owner == old_owner && targets.iter().any(|t| t == *k))
            .map(|(k, b)| (k.clone(), b.clone()))
            .collect();
        if old_blobs.len() != targets.len() {
            return Response::json(
                400,
                json_err(
                    "legacy /metabibasis accepts existing files only; use /transfer/request for folders or identities",
                ),
            );
        }
        for target in &targets {
            let path = target.trim_matches('/');
            if path == "metabibasis"
                || path == "metabibasis.hdap"
                || path.starts_with("metabibasis/")
                || path == "pow"
                || path.starts_with("pow/")
            {
                return Response::json(403, json_err("target is immutable"));
            }
            if st
                .ceessions
                .get(&old_owner)
                .is_some_and(|cs| cs.iter().any(|c| crate::node::path_in_scope(path, &c.path)))
            {
                return Response::json(409, json_err("target is already read-only (ceded)"));
            }
        }

        // Check for collisions with new_owner's existing files (Crítica 4)
        for (_key, blob) in &old_blobs {
            let new_key = State::key(&new_owner, &blob.path);
            if st.objects.contains_key(&new_key) {
                return Response::json(
                    409,
                    json_err(&format!(
                        "collision: {} already exists for new owner",
                        blob.path
                    )),
                );
            }
        }

        // Calculate moved_bytes before moving (exact paths only)
        let moved_bytes: u64 = old_blobs
            .iter()
            .map(|(_, b)| (b.bytes.len() - SEAL_OVERHEAD) as u64)
            .sum();

        // Move blobs atomically
        for (key, mut blob) in old_blobs {
            let new_key = State::key(&new_owner, &blob.path);
            blob.owner = new_owner.clone();
            st.objects.remove(&key);
            st.objects.insert(new_key, blob);
        }
        if let Some(used) = st.stored.get_mut(&old_owner) {
            *used = used.saturating_sub(moved_bytes);
            if *used == 0 {
                st.stored.remove(&old_owner);
            }
        }
        *st.stored.entry(new_owner.clone()).or_insert(0) += moved_bytes;

        // Record the transaction where the cessionário can see it: a
        // `metabibasis.hdap` under the new owner names the asset and both
        // parties, so the ownership trail is legible without the prytaneion.
        let metabibasis_text = {
            let mut d =
                hdap_core::doc::Doc::new(hdap_core::DocType::Metabibasis, 1, None, node.now());
            d.body.insert("OLD_OWNER".into(), old_owner.clone());
            d.body.insert("NEW_OWNER".into(), new_owner.clone());
            for (i, t) in targets.iter().enumerate() {
                d.body.insert(format!("TARGET{i:04}"), t.clone());
            }
            let t = d.render();
            let bytes = t.as_bytes();
            let master = st.master_key;
            let key = State::key(&new_owner, "metabibasis.hdap");
            st.objects.insert(
                key,
                Blob {
                    owner: new_owner.clone(),
                    path: "metabibasis.hdap".into(),
                    hash: content_hash(bytes),
                    bytes: hdap_core::crypto::aead_seal(&master, bytes),
                },
            );
            t
        };

        // Old owner keeps read-only (irrevocable, §11); the new one owns.
        let read_grant = format!(
            "PERM {} user:{} {} read",
            new_owner,
            old_owner,
            targets.join(",")
        );
        let perms_new = st.permissions.entry(new_owner.clone()).or_default();
        if !perms_new.contains(&read_grant) {
            perms_new.push_str(&read_grant);
        }

        Response::json(
            200,
            serde_json::json!({
                "transferred": targets,
                "new_owner": new_owner,
                "record": "metabibasis.hdap",
                "record_hash": content_hash(metabibasis_text.as_bytes()),
                "read_only": true
            })
            .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;
    use crate::store::Session;
    use hdap_core::doc::Signature;

    fn node_with_session(user_id: &str) -> Node {
        let node = Node::new(Config::default());
        {
            let mut st = node.state.lock().unwrap();
            let seed = st.node_sign_seed;
            st.users.insert(
                user_id.to_string(),
                crate::store::UserRecord {
                    user_id: user_id.to_string(),
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
                    user_id: user_id.to_string(),
                    exp: u64::MAX,
                },
            );
        }
        node
    }

    fn req(body: &str) -> Request {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("authorization".to_string(), "Bearer tok".to_string());
        Request {
            method: "POST".to_string(),
            path: "adeia".to_string(),
            query: std::collections::BTreeMap::new(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    fn sign_adeia(node: &Node, owner: &str, text: &str) -> String {
        let seed = node.state.lock().unwrap().node_sign_seed;
        let sign_key = hdap_core::crypto::SigningKey::from_bytes(&seed);
        let mut d = hdap_core::doc::parse(text).unwrap();
        let mut sig = Signature {
            signer: owner.to_string(),
            signer_pubkey: Some(hex::encode(sign_key.verifying_key().to_bytes())),
            signature: String::new(),
        };
        d.sigs.push(sig.clone());
        let input = d.signature_input(0).expect("signable");
        sig.signature = base64::engine::general_purpose::STANDARD
            .encode(hdap_core::crypto::ed25519_sign(&sign_key, input.as_bytes()).to_bytes());
        d.sigs[0].signature = sig.signature;
        d.render()
    }

    /// Publishing an ACL through the API must store the `adeia.hdap` document,
    /// not just the cache: federation ships the *document*, so a bare map update
    /// would silently never reach a mirroring pyle (and the file listing would
    /// disagree with the enforced ACL).
    #[test]
    fn publishing_an_adeia_writes_the_document_it_enforces() {
        let owner = "jose_0123456789abcdef";
        let node = node_with_session(owner);
        let text =
            hdap_core::protocol::adeia_doc(owner, 1, None, 1_700_000_000, &[], None).render();
        let signed_text = sign_adeia(&node, owner, &text);

        let resp = node.permissions.handle_adeia(&node, &req(&signed_text));
        assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));

        let st = node.state.lock().unwrap();
        assert_eq!(
            st.permissions.get(owner).map(String::as_str),
            Some(signed_text.as_str())
        );
        let blob = st
            .objects
            .get(&State::key(owner, "adeia.hdap"))
            .expect("the ACL document must be stored as a blob so it federates");
        let back = hdap_core::crypto::aead_open(&st.master_key, &blob.bytes).unwrap();
        assert_eq!(back, signed_text.as_bytes());
    }

    #[test]
    fn an_invalid_document_is_rejected_and_stores_nothing() {
        let owner = "jose_0123456789abcdef";
        let node = node_with_session(owner);
        let resp = node
            .permissions
            .handle_adeia(&node, &req("not a hdap document"));
        assert_eq!(resp.status, 400);
        let st = node.state.lock().unwrap();
        assert!(!st.permissions.contains_key(owner));
        assert!(!st.objects.contains_key(&State::key(owner, "adeia.hdap")));
    }
}
