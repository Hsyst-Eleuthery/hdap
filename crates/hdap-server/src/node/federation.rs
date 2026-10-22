//! Federation module: peer handshake, sync, TCD (pheme), prytaneion updates.

use hdap_core::crypto::{aead_open, ed25519_verify};

use crate::config::Config;
use crate::http::{Request, Response};
use crate::node::discovery::PeerAdvert;
use crate::node::ledger;
use crate::node::{json_err, require_json, Access, SEAL_OVERHEAD};
use crate::store::{PeerRecord, PrytaneionEntry};

/// Identity and ACL documents are public by design: a peer needs the owner's
/// `adeia.hdap` to re-enforce the rules locally, so it may always be listed.
fn is_public_doc(path: &str) -> bool {
    crate::node::is_public_identity_doc(path)
}

pub struct FederationModule {
    cfg: Config,
}

impl FederationModule {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    /// `POST/GET /homospondoi/...` — federation routes.
    pub fn handle_fed(&self, node: &crate::node::Node, req: &Request) -> Response {
        let sub = req
            .path
            .trim_start_matches('/')
            .split('/')
            .nth(1)
            .unwrap_or("");
        match sub {
            "handshake" => self.fed_handshake(node, req),
            "sync" => self.fed_sync(node, req),
            "fetch_blob" => self.fed_fetch_blob(node, req),
            "namespace" => self.fed_namespace(node, req),
            "ledger" => self.fed_ledger(node, req),
            "house_move" => node.identity.handle_fed_house_move(node, req),
            "pheme" => self.fed_tcd(node, req),
            "prytaneion_update" => self.fed_prytaneion_update(node, req),
            "directory" => {
                let Some(_peer) = self.fed_verify_peer(node, req) else {
                    return Response::json(401, json_err("fed signature invalid"));
                };
                node.discovery.handle_directory(node, req)
            }
            "announce" => {
                let Some(peer) = self.fed_verify_peer(node, req) else {
                    return Response::json(401, json_err("fed signature invalid"));
                };
                node.discovery.handle_announce(node, req, &peer.node_id)
            }
            _ => Response::json(404, json_err("unknown homospondoi route")),
        }
    }

    /// `POST /homospondoi/handshake` — register a peer (allowlist in config, no TOFU).
    fn fed_handshake(&self, node: &crate::node::Node, req: &Request) -> Response {
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let node_id = body.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
        let pubkey_hex = body.get("pubkey").and_then(|v| v.as_str()).unwrap_or("");
        if node_id.is_empty() || hex::decode(pubkey_hex).map(|v| v.len()) != Ok(32) {
            return Response::json(400, json_err("node_id + 32-byte hex pubkey required"));
        }
        // Allowlist is mandatory by default (Crítica 1); `open_federation`
        // opts into TOFU pinning of a first caller for dev/self-hosted meshes.
        let expected = self.cfg.federation_peers.get(node_id);
        if let Some(expected) = expected {
            // Crítica 2: verify the presented pubkey matches the configured one
            if expected.pubkey != pubkey_hex {
                return Response::json(403, json_err("pubkey does not match allowlist"));
            }
        } else if !self.cfg.open_federation {
            return Response::json(403, json_err("peer not in federation allowlist"));
        }
        let configured = self.cfg.federation_peers.get(node_id);
        // The configured endpoint wins (provisioned out of band); a peer may
        // only self-declare one when the operator left it empty.
        let endpoint = configured
            .map(|p| p.endpoint.clone())
            .filter(|e| !e.trim().is_empty())
            .unwrap_or_else(|| {
                body.get("endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            });
        let tls_pin = configured.and_then(|p| p.tls_pin.clone()).or_else(|| {
            body.get("tls_pin")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
        });
        // Announce our own signing key so the caller can record us and verify
        // later documents (the `.hdap.pow` ack, syngraphe countersignatures).
        let node_sign_pub = crate::node::discovery::own_sign_pub(node);
        let caller_digest = body
            .get("directory_digest")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let caller_ledger_digest = body
            .get("ledger_digest")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let (known, peers_len) = {
            let mut st = node.state.lock().unwrap();
            let known = st.peers.contains_key(node_id);
            if let Some(existing) = st.peers.get(node_id) {
                if existing.sign_pub_hex != pubkey_hex {
                    return Response::json(409, json_err("peer id already uses another key"));
                }
            }
            st.peers.insert(
                node_id.to_string(),
                PeerRecord {
                    node_id: node_id.to_string(),
                    sign_pub_hex: pubkey_hex.to_string(),
                    endpoint: endpoint.clone(),
                    tls_pin: tls_pin.clone(),
                },
            );
            (known, st.peers.len())
        };
        let now = node.now();
        node.discovery.record_seen(node_id, now);
        let advert = PeerAdvert {
            node_id: node_id.to_string(),
            endpoint: endpoint.clone(),
            sign_pub_hex: pubkey_hex.to_string(),
            tls_pin: tls_pin.clone(),
        };
        if !known {
            // The caller reached us, but that does not prove we can dial it
            // back. Verify the callback, then tell a bounded fanout.
            let event_id = crate::node::discovery::new_event_id(node, node_id);
            node.discovery.enqueue_verify(advert, event_id, 4, true);
        }
        let digest = crate::node::discovery::directory_digest(node);
        if caller_digest != digest {
            node.discovery.enqueue_exchange(node_id.to_string());
        }
        let ledger_digest = ledger::digest(&node.state.lock().unwrap().prytaneion);
        if caller_ledger_digest != ledger_digest {
            node.discovery.enqueue_ledger(node_id.to_string());
        }
        let directory = if caller_digest == digest {
            serde_json::Value::Null
        } else {
            serde_json::json!(crate::node::discovery::adverts(node)
                .iter()
                .map(|p| p.to_json())
                .collect::<Vec<_>>())
        };
        let mut reply = serde_json::json!({
            "node_id": node_id,
            "server_id": node.cfg.server_id,
            "node_sign_pub": node_sign_pub,
            "tls_pin": node.tls_pin,
            "peers": peers_len,
            "directory_digest": digest,
            "ledger_digest": ledger_digest,
        });
        if !directory.is_null() {
            reply["directory"] = directory;
        }
        Response::json(200, reply.to_string())
    }

    /// `GET /homospondoi/fetch_blob?hash=<content_hash>` — return the plaintext
    /// bytes of a blob this node holds, to an authenticated peer, **for a user
    /// that peer is pulling on behalf of**. Used by the pull-through
    /// (`node/mirror.rs`) and by automatic replication: the peer re-verifies
    /// the `X-HDAP-Hash` against the content it received, so a compromised peer
    /// cannot substitute bytes (spec §14.2).
    ///
    /// The owner's `adeia` is enforced here, at the source: the requester must
    /// be allowed to `read` at least one `(owner, path)` that maps to this hash
    /// (or the blob must be a public config doc). A grant that only exists on a
    /// mirror is worthless if the bytes already left the origin.
    fn fed_fetch_blob(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(peer) = self.fed_verify_peer(node, req) else {
            return Response::json(401, json_err("fed signature invalid"));
        };
        let Some(requester) = req.headers.get("x-hdap-requester").cloned() else {
            return Response::json(400, json_err("requester header required"));
        };
        let hash = req.query.get("hash").cloned().unwrap_or_default();
        if hash.is_empty() {
            return Response::json(400, json_err("hash query required"));
        }
        let candidates: Vec<crate::store::Blob> = {
            let st = node.state.lock().unwrap();
            st.objects
                .values()
                .filter(|b| b.hash == hash)
                .cloned()
                .collect()
        };
        if candidates.is_empty() {
            return Response::json(404, json_err("blob not found on this pyle"));
        }
        let Some(blob) = candidates.into_iter().find(|b| {
            node.diadosi_allows(&b.owner, &peer.node_id, &b.path)
                && (is_public_doc(&b.path)
                    || node.authorize(&requester, &b.owner, &b.path, Access::Read)
                    || node.authorize_replica(&requester, &b.owner, &b.path))
        }) else {
            return Response::json(403, json_err("requester is not allowed to read this blob"));
        };
        let plain = {
            let st = node.state.lock().unwrap();
            match hdap_core::crypto::aead_open(&st.master_key, &blob.bytes) {
                Ok(p) => p,
                Err(_) => return Response::json(500, json_err("storage decryption failed")),
            }
        };
        // Origin provenance travels with the bytes so the puller can register
        // the replica in its own `prytaneion` under the real origin.
        let entry = {
            let st = node.state.lock().unwrap();
            st.prytaneion.get(&hash).cloned()
        };
        let origin_server = entry
            .as_ref()
            .map(|e| e.origin_server.clone())
            .unwrap_or_else(|| peer.node_id.clone());
        let origin_user = entry
            .as_ref()
            .map(|e| e.origin_user.clone())
            .unwrap_or_else(|| blob.owner.clone());
        let origin_user_pubkey = entry
            .as_ref()
            .map(|e| e.origin_user_pubkey.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let st = node.state.lock().unwrap();
                st.users.get(&origin_user).map(|u| u.sign_pub_hex.clone())
            })
            .unwrap_or_default();
        let origin_path = entry
            .as_ref()
            .map(|e| e.origin_path.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| blob.path.clone());
        let sphragis = entry
            .as_ref()
            .map(|e| e.sphragis.clone())
            .unwrap_or_default();
        let mut resp = Response::bytes(200, "application/octet-stream", plain);
        resp.headers
            .insert("X-HDAP-Hash".to_string(), blob.hash.clone());
        resp.headers
            .insert("X-HDAP-Origin-Server".to_string(), origin_server);
        resp.headers
            .insert("X-HDAP-Origin-User".to_string(), origin_user);
        resp.headers
            .insert("X-HDAP-Origin-Path".to_string(), origin_path);
        if !origin_user_pubkey.is_empty() {
            resp.headers
                .insert("X-HDAP-Origin-Pubkey".to_string(), origin_user_pubkey);
        }
        if !sphragis.is_empty() {
            resp.headers.insert("X-HDAP-Sphragis".to_string(), sphragis);
        }
        resp
    }

    /// `GET /homospondoi/namespace?owner=<user_id>` — the index of one user's
    /// namespace as seen by `requester`: their `prosopeion.hdap`/`adeia.hdap`
    /// (public docs, decrypted) plus `{path, hash, size}` for every `ktema`
    /// the requester is allowed to read. The puller fetches the bytes
    /// separately via `fetch_blob`, so a large namespace is listed once and
    /// streamed blob by blob.
    fn fed_namespace(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(peer) = self.fed_verify_peer(node, req) else {
            return Response::json(401, json_err("fed signature invalid"));
        };
        let Some(requester) = req.headers.get("x-hdap-requester").cloned() else {
            return Response::json(400, json_err("requester header required"));
        };
        let owner = req.query.get("owner").cloned().unwrap_or_default();
        if owner.is_empty() {
            return Response::json(400, json_err("owner query required"));
        }
        // The boundary is enforced at the source, before any bytes move. The
        // public identity docs still travel so the receiver can verify the
        // adeia it is being denied by.
        if !node.diadosi_allows(&owner, &peer.node_id, "") {
            return Response::json(403, json_err("pyle is outside this owner's diadosi"));
        }
        // This peer now holds a replica of `owner`'s namespace: remember it so
        // a later delete can be pushed instead of leaving the copy orphaned.
        node.state
            .lock()
            .unwrap()
            .watchers
            .entry(owner.clone())
            .or_default()
            .insert(peer.node_id);
        let (user_json, prosopeion, adeia, raw) = {
            let st = node.state.lock().unwrap();
            let Some(user) = st.users.get(&owner) else {
                return Response::json(404, json_err("owner not registered here"));
            };
            let doc_text = |name: &str| -> Option<String> {
                st.objects
                    .get(&crate::store::State::key(&owner, name))
                    .and_then(|b| hdap_core::crypto::aead_open(&st.master_key, &b.bytes).ok())
                    .map(|p| String::from_utf8_lossy(&p).into_owned())
            };
            let user_json = serde_json::json!({
                "sign_pub_hex": user.sign_pub_hex,
                "enc_pub_hex": user.enc_pub_hex,
                "otp_anchor_hex": user.otp_anchor_hex,
                "otp_k": user.otp_k,
                "nickname": user.nickname,
                "suffix_hex": user.suffix_hex,
                "created_at": user.created_at,
                "home_pyle": user.home_pyle,
            });
            let raw: Vec<(String, String, u64)> = st
                .objects
                .values()
                .filter(|b| b.owner == owner)
                .map(|b| {
                    (
                        b.path.clone(),
                        b.hash.clone(),
                        b.bytes.len().saturating_sub(crate::node::SEAL_OVERHEAD) as u64,
                    )
                })
                .collect();
            // Ship the ACL the node *enforces* (`st.permissions`, the cache
            // `authorize` reads), not merely the `adeia.hdap` blob. The two can
            // legitimately diverge after a mirror pull, and advertising one
            // while enforcing the other let the puller copy content and then
            // apply an empty ACL — the file arrived but listing it was 403.
            let adeia = st
                .permissions
                .get(&owner)
                .cloned()
                .or_else(|| doc_text("adeia.hdap"));
            (user_json, doc_text("prosopeion.hdap"), adeia, raw)
        };
        let mut entries: Vec<serde_json::Value> = Vec::new();
        // Count the content withheld from this requester so the puller can tell
        // "the owner authorized nothing" apart from "the owner has no files":
        // an empty mirror where files exist but were not granted would
        // otherwise look identical to a genuinely empty folder.
        let mut denied = 0usize;
        for (path, hash, size) in raw {
            if is_public_doc(&path)
                || node.authorize(&requester, &owner, &path, Access::Read)
                || node.authorize_replica(&requester, &owner, &path)
            {
                entries.push(serde_json::json!({
                    "path": path,
                    "hash": hash,
                    "size": size,
                }));
            } else if !path.starts_with("pow/") {
                // `pow/*` are node-local band artefacts: never mirrored, so a
                // requester "losing" them is not lost content.
                denied += 1;
            }
        }
        Response::json(
            200,
            serde_json::json!({
                "owner": owner,
                "prosopeion": prosopeion,
                "adeia": adeia,
                "entries": entries,
                "denied": denied,
                "user": user_json,
            })
            .to_string(),
        )
    }

    /// Verify a federated request signature (nonce + timestamp + node_id).
    pub(crate) fn fed_verify_peer(
        &self,
        node: &crate::node::Node,
        req: &Request,
    ) -> Option<PeerRecord> {
        let now = node.now() as i64;
        let node_id = req.headers.get("x-hdap-node-id")?.clone();
        let nonce = req.headers.get("x-hdap-nonce")?.clone();
        let ts: i64 = req.headers.get("x-hdap-timestamp")?.parse().ok()?;
        let sig_b64 = req.headers.get("x-hdap-signature")?;
        if (ts - now).abs() > self.cfg.fed_window_secs {
            return None;
        }
        let sig = crate::node::sig_from_b64(sig_b64)?;
        let mut st = node.state.lock().unwrap();
        let key = format!("{}:{}", node_id, nonce);
        if st.fed_nonces.contains_key(&key) {
            return None; // replay
        }
        // Cleanup old nonces (Crítica 5): remove nonces older than the window
        let cutoff = now - self.cfg.fed_window_secs;
        st.fed_nonces.retain(|_, &mut v| v > cutoff as u64);
        let peer = st.peers.get(&node_id)?.clone();
        let pubkey: [u8; 32] = hex::decode(&peer.sign_pub_hex).ok()?.try_into().ok()?;
        let payload = match req.headers.get("x-hdap-requester") {
            Some(r) => format!("{node_id}:{nonce}:{ts}:{r}"),
            None => format!("{node_id}:{nonce}:{ts}"),
        };
        if ed25519_verify(&pubkey, payload.as_bytes(), &sig).is_err() {
            return None;
        }
        st.fed_nonces.insert(key, now as u64);
        drop(st);
        node.discovery.record_seen(&peer.node_id, now as u64);
        Some(peer)
    }

    /// `POST /homospondoi/sync` — federated sync with OTP consumption propagation.
    fn fed_sync(&self, node: &crate::node::Node, req: &Request) -> Response {
        let now = node.now();
        let Some(peer) = self.fed_verify_peer(node, req) else {
            return Response::json(401, json_err("fed signature invalid"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let hash = body
            .get("content_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if hash.is_empty() {
            return Response::json(400, json_err("content_hash required"));
        }
        // Crítica 3: validate that the peer actually has this content or is authorized to sync it
        let mut st = node.state.lock().unwrap();
        if !st
            .objects
            .values()
            .any(|b| b.hash == hash && !b.owner.is_empty())
        {
            // Hash not known locally - this is a sync request for unknown content
            // Still allow registration but mark origin as this peer
        }
        // §7.3: a peer may piggyback consumed OTP steps (user -> next step)
        // so replay state propagates across homospondoi; merge by max.
        if let Some(consumed) = body.get("otp_consumed").and_then(|v| v.as_object()) {
            for (user, step) in consumed {
                if let Some(s) = step.as_u64() {
                    let next = st.omphalos_step.get(user).copied().unwrap_or(1);
                    st.omphalos_step.insert(user.clone(), next.max(s as usize));
                }
            }
        }

        let created_at = now;
        st.prytaneion
            .entry(hash.to_string())
            .or_insert_with(|| PrytaneionEntry {
                content_hash: hash.to_string(),
                origin_server: peer.node_id.clone(), // Track which peer announced this
                origin_user: String::new(),
                origin_user_pubkey: String::new(),
                origin_path: String::new(),
                sphragis: String::new(),
                replicas: vec![],
                deletions: vec![],
                created_at,
            });
        Response::json(200, serde_json::json!({ "synced": hash }).to_string())
    }

    /// `POST /homospondoi/pheme` — federated reputation update.
    fn fed_tcd(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(_peer) = self.fed_verify_peer(node, req) else {
            return Response::json(401, json_err("fed signature invalid"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let candidate = body.get("candidate").and_then(|v| v.as_str()).unwrap_or("");
        let doc = match hdap_core::doc::parse(candidate) {
            Ok(d) if d.doc_type == hdap_core::DocType::PhemeCandidate => d,
            _ => return Response::json(400, json_err("invalid tcd_candidate doc")),
        };
        let target = doc.body.get("TARGET_ID").cloned().unwrap_or_default();
        let delta: i64 = doc
            .body
            .get("SCORE_DELTA")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        // Crítica 7: require operation ID to prevent duplicate application
        let op_id = body
            .get("operation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if op_id.is_empty() {
            return Response::json(400, json_err("operation_id required for pheme update"));
        }
        let mut st = node.state.lock().unwrap();
        let applied_key = format!("pheme_applied:{op_id}");
        if st.fed_applied.contains(&applied_key) {
            return Response::json(200, serde_json::json!({ "target": target, "score": st.pheme.get(&target).copied().unwrap_or(0), "duplicate": true }).to_string());
        }
        // Validate evidence exists and is verifiable
        let mut evidence = Vec::new();
        for i in 0..100 {
            if let Some(s) = doc.body.get(&format!("EVIDENCE{i:04}")) {
                evidence.push(s.clone());
            }
        }
        if evidence.is_empty() {
            return Response::json(400, json_err("pheme candidate must include evidence"));
        }
        let score = st.pheme.get(&target).copied().unwrap_or(0) + delta;
        st.pheme.insert(target.clone(), score);
        st.fed_applied.insert(applied_key);
        Response::json(
            200,
            serde_json::json!({ "target": target, "score": score }).to_string(),
        )
    }

    /// `GET/POST /homospondoi/ledger` — global provenance ledger exchange.
    ///
    /// GET is digest-first: `?digest=` equal returns only `{digest}`; a
    /// mismatch returns the entries. `?hash=` returns a single entry (used to
    /// resolve a hash whose origin is down). POST merges a peer's entries.
    fn fed_ledger(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(_peer) = self.fed_verify_peer(node, req) else {
            return Response::json(401, json_err("fed signature invalid"));
        };
        if req.method == "GET" {
            if let Some(hash) = req.query.get("hash") {
                let st = node.state.lock().unwrap();
                return match st.prytaneion.get(hash) {
                    Some(entry) => Response::json(
                        200,
                        serde_json::json!({ "entry": ledger::entry_to_json(entry) }).to_string(),
                    ),
                    None => Response::json(404, json_err("ledger entry not found")),
                };
            }
            let want = req.query.get("digest").map(String::as_str).unwrap_or("");
            let st = node.state.lock().unwrap();
            return Response::json(200, ledger::exchange_body(&st, want).to_string());
        }
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (merged, digest) = {
            let mut st = node.state.lock().unwrap();
            let merged = ledger::merge_body(&mut st, &body);
            (merged, ledger::digest(&st.prytaneion))
        };
        Response::json(
            200,
            serde_json::json!({ "digest": digest, "merged": merged }).to_string(),
        )
    }

    /// `POST /homospondoi/prytaneion_update` — federated deletion propagation.
    ///
    /// The origin of a mirrored namespace (or a mirror forwarding the same
    /// operation id) tells us a blob is gone. Only the namespace origin may
    /// start a deletion, and the hash must match the replica we hold, so a
    /// stale or malicious update cannot erase unrelated local content. Once
    /// applied, the deletion cascades to peers that mirrored from *us*.
    fn fed_prytaneion_update(&self, node: &crate::node::Node, req: &Request) -> Response {
        let now = node.now();
        let Some(peer) = self.fed_verify_peer(node, req) else {
            return Response::json(401, json_err("fed signature invalid"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or("");
        let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let hash = body
            .get("content_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let deletion = body.get("deletion").and_then(|v| v.as_str()).unwrap_or("");
        // Crítica 7: require operation ID for idempotency
        let op_id = body
            .get("operation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if op_id.is_empty() {
            return Response::json(400, json_err("operation_id required for prytaneion update"));
        }
        if owner.is_empty() || path.is_empty() || hash.is_empty() || deletion.is_empty() {
            return Response::json(
                400,
                json_err("owner, path, content_hash and deletion required"),
            );
        }
        let applied_key = format!("prytaneion_applied:{op_id}");
        let (removed, op_id) = {
            let mut st = node.state.lock().unwrap();
            if st.fed_applied.contains(&applied_key) {
                return Response::json(
                    200,
                    serde_json::json!({ "prytaneion": "updated", "duplicate": true }).to_string(),
                );
            }
            // A deletion is authoritative only from the pyle this namespace was
            // mirrored from. Without this, any peer that completed a handshake
            // could erase someone else's files.
            let is_origin = st
                .mirrors
                .get(owner)
                .is_some_and(|m| m.origin_pyle == peer.node_id);
            if !is_origin {
                return Response::json(
                    403,
                    json_err("deletion must come from the namespace origin"),
                );
            }
            let key = crate::store::State::key(owner, path);
            let mut removed = false;
            if let Some(blob) = st.objects.get(&key) {
                if blob.hash == hash {
                    let plain = aead_open(&st.master_key, &blob.bytes).unwrap_or_default();
                    let bytes = blob.bytes.len().saturating_sub(SEAL_OVERHEAD) as u64;
                    st.objects.remove(&key);
                    if let Some(used) = st.stored.get_mut(owner) {
                        *used = used.saturating_sub(bytes);
                        if *used == 0 {
                            st.stored.remove(owner);
                        }
                    }
                    if matches!(
                        path,
                        "adeia.hdap"
                            | "kerux.hdap"
                            | "timi.hdap"
                            | "prytaneion.hdap"
                            | "prosopeion.hdap"
                    ) {
                        node.storage
                            .reindex_config_doc_removed(&mut st, owner, path, &plain);
                    }
                    removed = true;
                }
            }
            let tomb = format!("FED:{deletion}:{}", now);
            let entry = st
                .prytaneion
                .entry(hash.to_string())
                .or_insert_with(|| PrytaneionEntry {
                    content_hash: hash.to_string(),
                    origin_server: peer.node_id.clone(),
                    origin_user: owner.to_string(),
                    origin_user_pubkey: body
                        .get("origin_user_pubkey")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    origin_path: body
                        .get("origin_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or(path)
                        .to_string(),
                    sphragis: body
                        .get("sphragis")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    replicas: vec![],
                    deletions: vec![],
                    created_at: now,
                });
            if !entry.deletions.contains(&tomb) {
                entry.deletions.push(tomb);
            }
            st.fed_applied.insert(applied_key);
            (removed, op_id.to_string())
        };
        // Multi-hop: a mirror may itself be the source for other mirrors.
        let notified = crate::node::notify_deletion(
            node,
            owner,
            path,
            hash,
            deletion,
            &op_id,
            Some(&peer.node_id),
        );
        Response::json(
            200,
            serde_json::json!({
                "prytaneion": "updated",
                "removed": removed,
                "notified": notified,
            })
            .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;
    use crate::store::{Blob, State, UserRecord};
    use base64::Engine;
    use hdap_core::crypto::{aead_seal, ed25519_sign, sha256_hex};
    use std::collections::BTreeMap;
    use std::sync::atomic::Ordering;

    fn signed_fed_get(
        node_id: &str,
        seed: &[u8; 32],
        nonce: &str,
        ts: u64,
        path: &str,
        query: &[(&str, &str)],
        requester: Option<&str>,
    ) -> Request {
        let key = ed25519_dalek::SigningKey::from_bytes(seed);
        let payload = match requester {
            Some(r) => format!("{node_id}:{nonce}:{ts}:{r}"),
            None => format!("{node_id}:{nonce}:{ts}"),
        };
        let sig = ed25519_sign(&key, payload.as_bytes());
        let mut headers = BTreeMap::new();
        headers.insert("x-hdap-node-id".to_string(), node_id.to_string());
        headers.insert("x-hdap-nonce".to_string(), nonce.to_string());
        headers.insert("x-hdap-timestamp".to_string(), ts.to_string());
        headers.insert(
            "x-hdap-signature".to_string(),
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        );
        if let Some(r) = requester {
            headers.insert("x-hdap-requester".to_string(), r.to_string());
        }
        Request {
            method: "GET".to_string(),
            path: path.to_string(),
            query: query
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            headers,
            body: Vec::new(),
        }
    }

    fn signed_fed_req(
        node_id: &str,
        seed: &[u8; 32],
        nonce: &str,
        ts: u64,
        path: &str,
        body: &str,
    ) -> Request {
        let key = ed25519_dalek::SigningKey::from_bytes(seed);
        let payload = format!("{node_id}:{nonce}:{ts}");
        let sig = ed25519_sign(&key, payload.as_bytes());
        let mut headers = BTreeMap::new();
        headers.insert("x-hdap-node-id".to_string(), node_id.to_string());
        headers.insert("x-hdap-nonce".to_string(), nonce.to_string());
        headers.insert("x-hdap-timestamp".to_string(), ts.to_string());
        headers.insert(
            "x-hdap-signature".to_string(),
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        );
        Request {
            method: "POST".to_string(),
            path: path.to_string(),
            query: BTreeMap::new(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    /// Idempotency must outlive the replay window: the `pheme`/`prytaneion`
    /// op-id guard is a separate, unpruned set, so a peer cannot re-apply the
    /// same reputation bump after `fed_window_secs` elapses.
    #[test]
    fn a_fed_pheme_update_is_not_reapplied_after_the_replay_window() {
        let cfg = Config {
            fed_window_secs: 5,
            ..Config::default()
        };
        let (node, _now) = Node::with_clock_and_now(cfg, 1000);
        let peer_id = "pyle-b";
        let seed = [3u8; 32];
        let pub_hex = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        );
        node.state.lock().unwrap().peers.insert(
            peer_id.to_string(),
            PeerRecord {
                node_id: peer_id.to_string(),
                sign_pub_hex: pub_hex,
                endpoint: String::new(),
                tls_pin: None,
            },
        );

        let target = "maria_0123456789abcdef";
        let mut d = hdap_core::doc::Doc::new(hdap_core::DocType::PhemeCandidate, 1, None, 1000);
        d.body.insert("TARGET_ID".into(), target.into());
        d.body.insert("SCORE_DELTA".into(), "5".into());
        d.body.insert("EVIDENCE0000".into(), "proof".into());
        let body =
            serde_json::json!({ "candidate": d.render(), "operation_id": "op-1" }).to_string();

        let r1 = node.federation.handle_fed(
            &node,
            &signed_fed_req(peer_id, &seed, "n1", 1000, "/homospondoi/pheme", &body),
        );
        assert_eq!(r1.status, 200, "{}", String::from_utf8_lossy(&r1.body));
        assert_eq!(
            node.state.lock().unwrap().pheme.get(target).copied(),
            Some(5)
        );

        // Time jumps well past the window: the next fed request prunes the
        // replay map, but must not forget that op-1 was already applied.
        node.clock.store(2000, Ordering::Relaxed);
        let r2 = node.federation.handle_fed(
            &node,
            &signed_fed_req(peer_id, &seed, "n2", 2000, "/homospondoi/pheme", &body),
        );
        assert_eq!(r2.status, 200);
        assert!(
            String::from_utf8_lossy(&r2.body).contains("duplicate"),
            "a replayed op-id must be reported as duplicate"
        );
        assert_eq!(
            node.state.lock().unwrap().pheme.get(target).copied(),
            Some(5),
            "the score must not be applied twice after the replay window"
        );
    }

    /// The owner's `adeia` is enforced at the *origin*: a peer pulling on
    /// behalf of a user the owner never granted may list only the public
    /// config docs and cannot fetch the private bytes at all. The identity of
    /// the requester is bound into the signed payload, so it cannot be widened
    /// by tampering, and `fetch_blob` is refused as a second line of defence.
    #[test]
    fn fed_routes_enforce_the_owners_adeia_at_the_source() {
        let (node, _now) = Node::with_clock_and_now(Config::default(), 1000);
        let peer_id = "pyle-b";
        let seed = [3u8; 32];
        let pub_hex = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        );
        node.state.lock().unwrap().peers.insert(
            peer_id.to_string(),
            PeerRecord {
                node_id: peer_id.to_string(),
                sign_pub_hex: pub_hex,
                endpoint: String::new(),
                tls_pin: None,
            },
        );

        let owner = "jose_0123456789abcdef";
        let stranger = "outro_eeeeeeeeeeeeeeee";
        let plain = b"conteudo privado";
        let private_hash = sha256_hex(plain);
        {
            let mut st = node.state.lock().unwrap();
            st.users.insert(
                owner.to_string(),
                UserRecord {
                    user_id: owner.to_string(),
                    nickname: "jose".to_string(),
                    suffix_hex: "0123456789abcdef".to_string(),
                    sign_pub_hex: "aa".repeat(32),
                    enc_pub_hex: "bb".repeat(32),
                    otp_anchor_hex: "cc".repeat(32),
                    otp_k: 1024,
                    created_at: 1000,
                    home_pyle: "node-a".into(),
                },
            );
            let master = st.master_key;
            for (path, bytes) in [
                ("prosopeion.hdap", b"prosopeion".to_vec()),
                ("adeia.hdap", b"adeia".to_vec()),
                ("docs/a.txt", plain.to_vec()),
            ] {
                st.objects.insert(
                    State::key(owner, path),
                    Blob {
                        owner: owner.to_string(),
                        path: path.to_string(),
                        hash: sha256_hex(&bytes),
                        bytes: aead_seal(&master, &bytes),
                    },
                );
            }
        }

        // The stranger sees the public docs (the mirror needs the adeia to
        // enforce it locally) but never the private entry.
        let r = node.handle(&signed_fed_get(
            peer_id,
            &seed,
            "n1",
            1000,
            "/homospondoi/namespace",
            &[("owner", owner)],
            Some(stranger),
        ));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert!(v["adeia"].is_string(), "the ACL itself is public");
        assert!(v["prosopeion"].is_string());
        let mut listed: Vec<String> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_string())
            .collect();
        listed.sort();
        assert_eq!(listed, vec!["adeia.hdap", "prosopeion.hdap"]);

        // Fetching the private blob directly is refused for the stranger...
        let r = node.handle(&signed_fed_get(
            peer_id,
            &seed,
            "n2",
            1000,
            "/homospondoi/fetch_blob",
            &[("hash", &private_hash)],
            Some(stranger),
        ));
        assert_eq!(
            r.status,
            403,
            "unauthorized bytes must never leave the source: {}",
            String::from_utf8_lossy(&r.body)
        );

        // ...while the owner themself pulls their own bytes intact.
        let r = node.handle(&signed_fed_get(
            peer_id,
            &seed,
            "n3",
            1000,
            "/homospondoi/fetch_blob",
            &[("hash", &private_hash)],
            Some(owner),
        ));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.body, plain);
    }

    /// The ledger exchange is digest-first: a converged peer gets only the
    /// digest, while a mismatch ships entries (with provenance pubkey/sig).
    #[test]
    fn the_ledger_exchange_is_digest_first() {
        let (node, _now) = Node::with_clock_and_now(Config::default(), 1000);
        let peer_id = "pyle-b";
        let seed = [7u8; 32];
        let pub_hex = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        );
        node.state.lock().unwrap().peers.insert(
            peer_id.to_string(),
            PeerRecord {
                node_id: peer_id.to_string(),
                sign_pub_hex: pub_hex,
                endpoint: String::new(),
                tls_pin: None,
            },
        );
        let hash = "b".repeat(64);
        {
            let mut st = node.state.lock().unwrap();
            st.prytaneion.insert(
                hash.clone(),
                crate::store::PrytaneionEntry {
                    content_hash: hash.clone(),
                    origin_server: peer_id.into(),
                    origin_user: "jose_0123456789abcdef".into(),
                    origin_user_pubkey: "aa".repeat(32),
                    origin_path: "blog/post.md".into(),
                    sphragis: "sig".into(),
                    replicas: vec![format!("{peer_id}:jose/blog/post.md")],
                    deletions: vec![],
                    created_at: 1000,
                },
            );
        }
        let digest = crate::node::ledger::digest(&node.state.lock().unwrap().prytaneion);
        let r = node.federation.handle_fed(
            &node,
            &signed_fed_get(
                peer_id,
                &seed,
                "n1",
                1000,
                "/homospondoi/ledger",
                &[("digest", &digest)],
                None,
            ),
        );
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["digest"], digest);
        assert!(v.get("entries").is_none(), "equal digest ships no list");

        let r = node.federation.handle_fed(
            &node,
            &signed_fed_get(peer_id, &seed, "n2", 1000, "/homospondoi/ledger", &[], None),
        );
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        let entries = v["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["origin_user_pubkey"], "aa".repeat(32));
        assert_eq!(entries[0]["sphragis"], "sig");
    }

    /// A deletion is authoritative only from the pyle the namespace was
    /// mirrored from. Even a peer with a valid handshake/signature must not be
    /// able to erase a replica whose origin is someone else (open federation
    /// accepts unknown peers, so this guard is what keeps them from deleting).
    #[test]
    fn a_deletion_from_a_non_origin_peer_is_refused() {
        let (node, _now) = Node::with_clock_and_now(Config::default(), 1000);
        let owner = "jose_0123456789abcdef";
        let path = "docs/a.txt";
        let plain = b"keep me";

        {
            let mut st = node.state.lock().unwrap();
            st.mirrors.insert(
                owner.to_string(),
                crate::store::MirrorOrigin {
                    origin_pyle: "pyle-legit".to_string(),
                    origin_server: "pyle-legit".to_string(),
                    pulled_at: 1000,
                },
            );
            let master = st.master_key;
            st.objects.insert(
                State::key(owner, path),
                Blob {
                    owner: owner.to_string(),
                    path: path.to_string(),
                    hash: sha256_hex(plain),
                    bytes: aead_seal(&master, plain),
                },
            );
        }

        // The attacker is a known peer, but it is not the namespace origin.
        let attacker = "pyle-attacker";
        let seed = [5u8; 32];
        let pub_hex = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        );
        node.state.lock().unwrap().peers.insert(
            attacker.to_string(),
            PeerRecord {
                node_id: attacker.to_string(),
                sign_pub_hex: pub_hex,
                endpoint: String::new(),
                tls_pin: None,
            },
        );
        let body = serde_json::json!({
            "owner": owner,
            "path": path,
            "content_hash": sha256_hex(plain),
            "deletion": format!("DELETED:{owner}/{path}:1000"),
            "operation_id": "op-attacker",
        })
        .to_string();
        let r = node.federation.handle_fed(
            &node,
            &signed_fed_req(
                attacker,
                &seed,
                "n1",
                1000,
                "/homospondoi/prytaneion_update",
                &body,
            ),
        );
        assert_eq!(
            r.status,
            403,
            "non-origin deletion must be refused: {}",
            String::from_utf8_lossy(&r.body)
        );
        assert!(
            node.state
                .lock()
                .unwrap()
                .objects
                .contains_key(&State::key(owner, path)),
            "the replica must survive a non-origin deletion"
        );
    }
}
