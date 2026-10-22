//! Identity module: registration, registry lookup, prosopeion sync.

use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use hdap_core::doc::{parse as parse_doc, DocType};
use hdap_core::identity::parse_global_id;

use crate::config::Config;
use crate::http::{Request, Response};
use crate::node::{content_hash, json_err, require_json};
use crate::store::{Blob, State, UserRecord};

pub struct IdentityModule {
    cfg: Config,
}

impl IdentityModule {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    /// `POST /register` — register a new identity (prosopeion.hdap).
    pub fn handle_register(&self, node: &crate::node::Node, req: &Request) -> Response {
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let properties_text = match body.get("properties").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return Response::json(400, json_err("properties required")),
        };
        let doc = match parse_doc(properties_text) {
            Ok(d) if d.doc_type == DocType::Prosopeion => d,
            _ => return Response::json(400, json_err("invalid or non-properties doc")),
        };
        let field = |k: &str| doc.body.get(k).cloned();
        let (Some(nickname), Some(suffix)) = (field("NICKNAME"), field("SUFFIX")) else {
            return Response::json(400, json_err("properties missing nickname/suffix"));
        };
        let user_id = format!("{nickname}_{suffix}");
        if parse_global_id(&user_id).is_none() {
            return Response::json(400, json_err("invalid global id"));
        }
        let (Some(sign_pub_hex), Some(enc_pub_hex), Some(otp_anchor_hex)) =
            (field("SIGN_PUBKEY"), field("ENC_PUBKEY"), field("OMPHALOS"))
        else {
            return Response::json(400, json_err("properties missing public key/otp fields"));
        };
        let otp_k: usize = field("SEED_ITER").and_then(|s| s.parse().ok()).unwrap_or(0);
        if otp_k == 0 {
            return Response::json(400, json_err("properties missing seed_iter"));
        }
        // Verify the prosopeion document is self-signed by the declared key
        // (§3.1): the SIGN_PUBKEY in the body must match the signature.
        let sign_pub_bytes = match hex::decode(&sign_pub_hex) {
            Ok(b) => b,
            Err(_) => return Response::json(400, json_err("invalid sign_pubkey hex")),
        };
        if sign_pub_bytes.len() != 32 {
            return Response::json(400, json_err("sign_pubkey must be 32 bytes"));
        }
        let sign_pub: [u8; 32] = sign_pub_bytes.as_slice().try_into().unwrap();
        // Find the signature in the document
        let sig_field = match doc.sigs.first() {
            Some(s) => s,
            None => return Response::json(400, json_err("prosopeion must be self-signed")),
        };
        let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&sig_field.signature)
        {
            Ok(b) => b,
            Err(_) => return Response::json(400, json_err("invalid signature encoding")),
        };
        if sig_bytes.len() != 64 {
            return Response::json(400, json_err("invalid signature format"));
        }
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = Ed25519Signature::from_bytes(&sig_arr);
        // Compute signature input (canonical document without our signature).
        // The signature must stay in the list: `signature_input` omits that
        // slot's line, and uses the remaining slots to derive the canonical
        // bytes, so clearing the list would make verification impossible.
        let input = match doc.signature_input(0) {
            Ok(i) => i,
            Err(_) => return Response::json(400, json_err("cannot compute signature input")),
        };
        let verify_key = match VerifyingKey::from_bytes(&sign_pub) {
            Ok(vk) => vk,
            Err(_) => return Response::json(400, json_err("invalid sign_pubkey")),
        };
        if verify_key.verify(input.as_ref(), &sig).is_err() {
            return Response::json(401, json_err("prosopeion self-signature invalid"));
        }

        let mut st = node.state.lock().unwrap();
        if st.users.contains_key(&user_id) {
            return Response::json(409, json_err("identity already registered"));
        }
        let user = UserRecord {
            user_id: user_id.clone(),
            nickname,
            suffix_hex: suffix,
            sign_pub_hex: sign_pub_hex.clone(),
            enc_pub_hex,
            otp_anchor_hex,
            otp_k,
            created_at: doc.created_at,
            home_pyle: self.cfg.server_id.clone(),
        };
        st.users.insert(user_id.clone(), user.clone());
        // Materialize the logical directory (especificacao §3.2) so the new
        // space is never an empty folder: the public identity document the
        // client just registered, plus an ACL that starts private (no grants
        // = nobody else can read or write).
        let auth_module = crate::node::AuthModule::new(self.cfg.clone());
        auth_module.ensure_hestia(&mut st, &user_id, properties_text, doc.created_at);
        // The node holds NO user secret: factor-3 key `k` is later derived
        // as X25519(node_enc_priv, user.enc_pub) at auth time (§7.4).
        Response::json(201, serde_json::json!({ "user_id": user_id }).to_string())
    }

    /// `POST /house_move` — the owner signs a move to a new home pyle and a
    /// new `adeia` edition. Old public replicas keep their frozen ACL snapshot;
    /// this only makes the new edition authoritative from now on.
    pub fn handle_house_move(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(session_user) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        match self.apply_house_move(node, &body, Some(&session_user), None) {
            Ok((user, pyle, edition)) => {
                self.propagate_house_move(node, &body, 3, None);
                Response::json(
                    200,
                    serde_json::json!({
                        "status": "moved",
                        "user_id": user,
                        "pyle": pyle,
                        "adeia_edition": edition,
                    })
                    .to_string(),
                )
            }
            Err(e) => e,
        }
    }

    /// `POST /homospondoi/house_move` — a peer relays a user-signed move. The
    /// user's signature (not the peer's) is the authority, so this still works
    /// when the old home is offline.
    pub(crate) fn handle_fed_house_move(
        &self,
        node: &crate::node::Node,
        req: &Request,
    ) -> Response {
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ttl = body.get("ttl").and_then(|v| v.as_u64()).unwrap_or(1).min(8) as u8;
        match self.apply_house_move(node, &body, None, Some(&body)) {
            Ok((user, pyle, edition)) => {
                if ttl > 0 {
                    self.propagate_house_move(node, &body, ttl.saturating_sub(1), None);
                }
                Response::json(
                    200,
                    serde_json::json!({
                        "status": "moved",
                        "user_id": user,
                        "pyle": pyle,
                        "adeia_edition": edition,
                    })
                    .to_string(),
                )
            }
            Err(e) => e,
        }
    }

    /// Validate and install one house-move. `session_user` (local route)
    /// restricts the caller to their own identity; the federated route has no
    /// session and relies on the user's Ed25519 signature instead.
    fn apply_house_move(
        &self,
        node: &crate::node::Node,
        body: &serde_json::Value,
        session_user: Option<&str>,
        _federated: Option<&serde_json::Value>,
    ) -> Result<(String, String, u64), Response> {
        use base64::Engine as _;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use hdap_core::doc::DocType;

        let properties = body
            .get("properties")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let adeia = body.get("adeia").and_then(|v| v.as_str()).unwrap_or("");
        let new_pyle = body
            .get("new_pyle")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&self.cfg.server_id)
            .to_string();
        if properties.is_empty() || adeia.is_empty() {
            return Err(Response::json(
                400,
                json_err("properties and adeia required"),
            ));
        }
        let props = match parse_doc(properties) {
            Ok(d) if d.doc_type == DocType::Prosopeion => d,
            _ => return Err(Response::json(400, json_err("invalid properties doc"))),
        };
        let field = |k: &str| props.body.get(k).cloned().unwrap_or_default();
        let nickname = field("NICKNAME");
        let suffix = field("SUFFIX");
        let user_id = format!("{nickname}_{suffix}");
        if parse_global_id(&user_id).is_none() {
            return Err(Response::json(400, json_err("invalid global id")));
        }
        if let Some(session) = session_user {
            if session != user_id {
                return Err(Response::json(
                    403,
                    json_err("cannot move another user's house"),
                ));
            }
        }
        let pubkey_hex = field("SIGN_PUBKEY");
        let pubkey: [u8; 32] = match hex::decode(&pubkey_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
        {
            Some(b) => b,
            None => return Err(Response::json(400, json_err("invalid sign_pubkey"))),
        };
        let sig_b64 = body.get("signature").and_then(|v| v.as_str()).unwrap_or("");
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|_| Response::json(400, json_err("invalid house_move signature encoding")))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| Response::json(400, json_err("invalid house_move signature")))?;
        let key = VerifyingKey::from_bytes(&pubkey)
            .map_err(|_| Response::json(400, json_err("invalid sign_pubkey")))?;
        let payload = hdap_core::house_move_payload(&user_id, &new_pyle, properties, adeia);
        if key.verify(payload.as_bytes(), &sig).is_err() {
            return Err(Response::json(
                401,
                json_err("house_move signature invalid"),
            ));
        }
        let adeia_doc = match parse_doc(adeia) {
            Ok(d) if d.doc_type == DocType::Adeia => d,
            _ => return Err(Response::json(400, json_err("invalid adeia doc"))),
        };
        let edition = adeia_doc.edition;
        let enc_pub_hex = field("ENC_PUBKEY");
        let otp_anchor_hex = field("OMPHALOS");
        let otp_k = field("SEED_ITER").parse::<usize>().unwrap_or(0);
        if enc_pub_hex.is_empty() || otp_anchor_hex.is_empty() || otp_k == 0 {
            return Err(Response::json(400, json_err("properties incomplete")));
        }

        let mut st = node.state.lock().unwrap();
        if let Some(existing) = st.users.get(&user_id) {
            if existing.sign_pub_hex != pubkey_hex {
                return Err(Response::json(
                    409,
                    json_err("identity already uses another signing key"),
                ));
            }
        }
        let current_edition = st
            .permissions
            .get(&user_id)
            .and_then(|text| parse_doc(text).ok())
            .map(|d| d.edition)
            .unwrap_or(0);
        if edition <= current_edition && current_edition != 0 {
            return Err(Response::json(
                409,
                json_err("house_move must carry a newer adeia edition"),
            ));
        }
        let is_new = !st.users.contains_key(&user_id);
        st.users.insert(
            user_id.clone(),
            UserRecord {
                user_id: user_id.clone(),
                nickname,
                suffix_hex: suffix,
                sign_pub_hex: pubkey_hex,
                enc_pub_hex,
                otp_anchor_hex,
                otp_k,
                created_at: props.created_at,
                home_pyle: new_pyle.clone(),
            },
        );
        let master = st.master_key;
        let now = node.now();
        for (path, text) in [("prosopeion.hdap", properties), ("adeia.hdap", adeia)] {
            let key = State::key(&user_id, path);
            let bytes = text.as_bytes();
            let sealed = hdap_core::crypto::aead_seal(&master, bytes);
            let old = st
                .objects
                .get(&key)
                .map(|b| b.bytes.len().saturating_sub(crate::node::SEAL_OVERHEAD) as u64)
                .unwrap_or(0);
            st.objects.insert(
                key.clone(),
                Blob {
                    owner: user_id.clone(),
                    path: path.to_string(),
                    hash: content_hash(bytes),
                    bytes: sealed,
                },
            );
            let used = st.stored.entry(user_id.clone()).or_insert(0);
            *used = used.saturating_sub(old) + bytes.len() as u64;
        }
        st.permissions.insert(user_id.clone(), adeia.to_string());
        if is_new {
            // Materialize the rest of the hestia (identity doc and ACL are
            // already written above; this fills the logical directory).
            let auth = crate::node::AuthModule::new(self.cfg.clone());
            auth.ensure_hestia(&mut st, &user_id, properties, props.created_at);
            st.permissions.insert(user_id.clone(), adeia.to_string());
        }
        let _ = now;
        Ok((user_id, new_pyle, edition))
    }

    /// `POST /diadosi` — install the owner's signed fallback proxy.
    ///
    /// The document names the current home and an ordered backup list, and
    /// pins the hashes of the exact `prosopeion.hdap`/`adeia.hdap` it covers.
    /// A fallback may promote itself only while those hashes still match, so
    /// a stale proxy cannot silently resurrect an older ACL.
    pub fn handle_diadosi(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let text = match std::str::from_utf8(&req.body) {
            Ok(t) => t,
            Err(_) => return Response::json(400, json_err("diadosi doc must be utf-8")),
        };
        let doc = match parse_doc(text) {
            Ok(d) if d.doc_type == DocType::Diadosi => d,
            _ => return Response::json(400, json_err("invalid diadosi doc")),
        };
        let Some(proxy) = hdap_core::protocol::DiadosiDoc::from_doc(&doc) else {
            return Response::json(400, json_err("incomplete diadosi doc"));
        };
        if proxy.owner != user_id {
            return Response::json(403, json_err("diadosi belongs to another user"));
        }
        if proxy.fallbacks.is_empty() || proxy.fallbacks.len() > 16 {
            return Response::json(400, json_err("diadosi needs 1..=16 fallbacks"));
        }
        if !proxy.verify_signature(&doc) {
            return Response::json(401, json_err("diadosi signature invalid"));
        }

        let (stored_pub, current_home, properties, adeia, old_text) = {
            let st = node.state.lock().unwrap();
            let Some(user) = st.users.get(&user_id) else {
                return Response::json(404, json_err("user not registered"));
            };
            let read = |name: &str| {
                st.objects
                    .get(&State::key(&user_id, name))
                    .and_then(|b| hdap_core::crypto::aead_open(&st.master_key, &b.bytes).ok())
            };
            let Some(properties) = read("prosopeion.hdap") else {
                return Response::json(409, json_err("prosopeion.hdap not installed"));
            };
            let Some(adeia) = read("adeia.hdap") else {
                return Response::json(409, json_err("adeia.hdap not installed"));
            };
            let old_text = read("diadosi.hdap");
            let home = if user.home_pyle.is_empty() {
                node.cfg.server_id.clone()
            } else {
                user.home_pyle.clone()
            };
            (user.sign_pub_hex.clone(), home, properties, adeia, old_text)
        };
        if proxy.owner_pubkey != stored_pub {
            return Response::json(403, json_err("diadosi pubkey does not match identity"));
        }
        if proxy.home_pyle != current_home {
            return Response::json(409, json_err("diadosi home_pyle is not the current home"));
        }
        if proxy.properties_hash != hdap_core::crypto::sha256_hex(&properties) {
            return Response::json(409, json_err("diadosi properties hash is stale"));
        }
        if proxy.adeia_hash != hdap_core::crypto::sha256_hex(&adeia) {
            return Response::json(409, json_err("diadosi adeia hash is stale"));
        }
        let current_edition = match parse_doc(&String::from_utf8_lossy(&adeia)) {
            Ok(d) if d.doc_type == DocType::Adeia => d.edition,
            _ => return Response::json(409, json_err("stored adeia is invalid")),
        };
        if proxy.adeia_edition != current_edition {
            return Response::json(409, json_err("diadosi adeia edition is stale"));
        }
        if let Some(old) = old_text {
            let old_edition = parse_doc(&String::from_utf8_lossy(&old))
                .ok()
                .filter(|d| d.doc_type == DocType::Diadosi)
                .map(|d| d.edition)
                .unwrap_or(0);
            if proxy.edition <= old_edition {
                return Response::json(409, json_err("diadosi must carry a newer edition"));
            }
        }

        let bytes = text.as_bytes();
        let mut st = node.state.lock().unwrap();
        let sealed = hdap_core::crypto::aead_seal(&st.master_key, bytes);
        st.objects.insert(
            State::key(&user_id, "diadosi.hdap"),
            Blob {
                owner: user_id,
                path: "diadosi.hdap".to_string(),
                hash: content_hash(bytes),
                bytes: sealed,
            },
        );
        Response::json(
            200,
            serde_json::json!({ "diadosi": "installed", "edition": proxy.edition }).to_string(),
        )
    }

    /// Promote this pyle if a valid signed `diadosi.hdap` names it and the
    /// current home is unreachable. The caller is normally `GET /sync` right
    /// after login, so the first snapshot already shows the backup as home.
    pub fn maybe_promote_fallback(&self, node: &crate::node::Node, user_id: &str) -> bool {
        let (home, peer) = {
            let st = node.state.lock().unwrap();
            let Some(user) = st.users.get(user_id) else {
                return false;
            };
            let home = if user.home_pyle.is_empty() {
                node.cfg.server_id.clone()
            } else {
                user.home_pyle.clone()
            };
            if home == node.cfg.server_id {
                return false;
            }
            let Some(blob) = st.objects.get(&State::key(user_id, "diadosi.hdap")) else {
                return false;
            };
            let Ok(text) = hdap_core::crypto::aead_open(&st.master_key, &blob.bytes) else {
                return false;
            };
            let Ok(text) = String::from_utf8(text) else {
                return false;
            };
            let Ok(doc) = parse_doc(&text) else {
                return false;
            };
            let Some(proxy) = hdap_core::protocol::DiadosiDoc::from_doc(&doc) else {
                return false;
            };
            if proxy.owner != user_id
                || proxy.owner_pubkey != user.sign_pub_hex
                || proxy.home_pyle != home
                || !proxy.fallbacks.iter().any(|p| p == &node.cfg.server_id)
                || !proxy.verify_signature(&doc)
            {
                return false;
            }
            let read = |name: &str| {
                st.objects
                    .get(&State::key(user_id, name))
                    .and_then(|b| hdap_core::crypto::aead_open(&st.master_key, &b.bytes).ok())
            };
            let (Some(properties), Some(adeia)) = (read("prosopeion.hdap"), read("adeia.hdap"))
            else {
                return false;
            };
            if proxy.properties_hash != hdap_core::crypto::sha256_hex(&properties)
                || proxy.adeia_hash != hdap_core::crypto::sha256_hex(&adeia)
            {
                return false;
            }
            let Some(peer) = st.peers.get(&home).cloned() else {
                return false;
            };
            (home, peer)
        };
        if peer.endpoint.trim().is_empty() {
            return false;
        }
        let Ok(client) =
            crate::fed_client::FedHttpClient::new(&peer.endpoint, peer.tls_pin.clone())
        else {
            return false;
        };
        // A live home always wins. Only a transport/5xx failure promotes the
        // backup; a 4xx health answer still proves the pyle is there.
        match client.get_json("/health") {
            Ok(resp) if (200..300).contains(&resp.status) => return false,
            _ => {}
        }
        let mut st = node.state.lock().unwrap();
        if let Some(user) = st.users.get_mut(user_id) {
            if user.home_pyle == home {
                user.home_pyle = node.cfg.server_id.clone();
                return true;
            }
        }
        false
    }

    /// Best-effort push of a signed house-move to a bounded fanout. Failure to
    /// reach a peer is fine: the next peer that sees the user will relay it.
    fn propagate_house_move(
        &self,
        node: &crate::node::Node,
        body: &serde_json::Value,
        ttl: u8,
        skip: Option<&str>,
    ) {
        if ttl == 0 {
            return;
        }
        let mut outgoing = body.clone();
        outgoing["ttl"] = serde_json::json!(ttl);
        let payload = outgoing.to_string();
        let peers: Vec<_> = {
            let st = node.state.lock().unwrap();
            st.peers
                .values()
                .filter(|p| !p.endpoint.trim().is_empty())
                .filter(|p| Some(p.node_id.as_str()) != skip)
                .cloned()
                .collect()
        };
        for peer in peers.into_iter().take(2) {
            let Ok(client) = crate::fed_client::FedHttpClient::new(&peer.endpoint, peer.tls_pin)
            else {
                continue;
            };
            let _ = client.post_json("/homospondoi/house_move", &payload);
        }
    }

    /// `GET /registry` — public nickname -> `user_id` lookup (§14).
    pub fn handle_registry(&self, node: &crate::node::Node, req: &Request) -> Response {
        let nickname = req.query.get("nickname").cloned().unwrap_or_default();
        let user_id = req
            .query
            .get("user_id")
            .or_else(|| req.query.get("user"))
            .cloned()
            .unwrap_or_default();
        if nickname.is_empty() && user_id.is_empty() {
            return Response::json(400, json_err("nickname or user_id query required"));
        }
        let st = node.state.lock().unwrap();
        let found = if !user_id.is_empty() {
            st.users.get(&user_id)
        } else {
            st.users
                .values()
                .find(|u| u.nickname.eq_ignore_ascii_case(&nickname))
        };
        match found {
            Some(u) => Response::json(
                200,
                serde_json::json!({
                    "user_id": u.user_id,
                    "nickname": u.nickname,
                    "sign_pub": u.sign_pub_hex,
                })
                .to_string(),
            ),
            None => Response::json(404, json_err("identity not found")),
        }
    }

    /// `POST /prosopeion` — client -> server identity sync (§3.1/§7).
    pub fn handle_prosopeion_sync(&self, node: &crate::node::Node, req: &Request) -> Response {
        let session_user = node.session_user(req);
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let properties_text = match body.get("properties").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return Response::json(400, json_err("properties required")),
        };
        match self.sync_prosopeion(node, properties_text, session_user.as_deref()) {
            Ok((user_id, state, edition)) => {
                let mut body = serde_json::json!({ "user_id": user_id, "state": state });
                if let Some(ed) = edition {
                    body["edition"] = serde_json::json!(ed);
                }
                let code = if state == "registered" { 201 } else { 200 };
                Response::json(code, body.to_string())
            }
            Err(e) => e,
        }
    }

    /// Client -> server identity sync (especificacao §3.1/§7). Idempotent:
    /// a node that never met this identity registers it (mirroring the local
    /// vault onto the node), one it knows accepts only a *strictly newer*
    /// edition (`SEED_ITER` monotonic — the omphalos rotation rule).
    ///
    /// Returns `(user_id, state, rotated_edition)`. Shared by `POST
    /// /prosopeion` and `POST /sync`.
    pub(crate) fn sync_prosopeion(
        &self,
        node: &crate::node::Node,
        properties_text: &str,
        session_user: Option<&str>,
    ) -> Result<(String, String, Option<u64>), Response> {
        let doc = match parse_doc(properties_text) {
            Ok(d) if d.doc_type == DocType::Prosopeion => d,
            _ => {
                return Err(Response::json(
                    400,
                    json_err("invalid or non-properties doc"),
                ))
            }
        };
        let field = |k: &str| doc.body.get(k).cloned();
        let (
            Some(nickname),
            Some(suffix),
            Some(sign_pub_hex),
            Some(enc_pub_hex),
            Some(otp_anchor_hex),
        ) = (
            field("NICKNAME"),
            field("SUFFIX"),
            field("SIGN_PUBKEY"),
            field("ENC_PUBKEY"),
            field("OMPHALOS"),
        )
        else {
            return Err(Response::json(400, json_err("properties incomplete")));
        };
        let otp_k: usize = field("SEED_ITER").and_then(|s| s.parse().ok()).unwrap_or(0);
        let user_id = format!("{nickname}_{suffix}");
        // Verify the prosopeion document signature (new registration or rotation)
        let sign_pub_bytes = match hex::decode(&sign_pub_hex) {
            Ok(b) => b,
            Err(_) => return Err(Response::json(400, json_err("invalid sign_pubkey hex"))),
        };
        if sign_pub_bytes.len() != 32 {
            return Err(Response::json(
                400,
                json_err("sign_pubkey must be 32 bytes"),
            ));
        }
        let sign_pub: [u8; 32] = sign_pub_bytes.as_slice().try_into().unwrap();
        let sig_field = match doc.sigs.first() {
            Some(s) => s,
            None => {
                return Err(Response::json(
                    400,
                    json_err("prosopeion must be self-signed"),
                ))
            }
        };
        let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&sig_field.signature)
        {
            Ok(b) => b,
            Err(_) => return Err(Response::json(400, json_err("invalid signature encoding"))),
        };
        if sig_bytes.len() != 64 {
            return Err(Response::json(400, json_err("invalid signature format")));
        }
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = Ed25519Signature::from_bytes(&sig_arr);
        let input = match doc.signature_input(0) {
            Ok(i) => i,
            Err(_) => {
                return Err(Response::json(
                    400,
                    json_err("cannot compute signature input"),
                ))
            }
        };
        let verify_key = match VerifyingKey::from_bytes(&sign_pub) {
            Ok(vk) => vk,
            Err(_) => return Err(Response::json(400, json_err("invalid sign_pubkey"))),
        };
        if verify_key.verify(input.as_ref(), &sig).is_err() {
            return Err(Response::json(
                401,
                json_err("prosopeion self-signature invalid"),
            ));
        }

        if parse_global_id(&user_id).is_none() {
            return Err(Response::json(400, json_err("invalid global id")));
        }
        // For existing identities, require session user to match (prevent account takeover)
        let mut st = node.state.lock().unwrap();
        let is_new = !st.users.contains_key(&user_id);
        if !is_new {
            let session_user = match session_user {
                Some(s) => s,
                None => {
                    return Err(Response::json(
                        401,
                        json_err("login required for identity update"),
                    ))
                }
            };
            if session_user != user_id {
                return Err(Response::json(
                    403,
                    json_err("cannot update another user's identity"),
                ));
            }
        }
        if is_new {
            let user = UserRecord {
                user_id: user_id.clone(),
                nickname: nickname.clone(),
                suffix_hex: suffix.clone(),
                sign_pub_hex: sign_pub_hex.clone(),
                enc_pub_hex: enc_pub_hex.clone(),
                otp_anchor_hex: otp_anchor_hex.clone(),
                otp_k,
                created_at: doc.created_at,
                home_pyle: self.cfg.server_id.clone(),
            };
            st.users.insert(user_id.clone(), user.clone());
            let auth_module = crate::node::AuthModule::new(self.cfg.clone());
            auth_module.ensure_hestia(&mut st, &user_id, properties_text, doc.created_at);
            return Ok((user_id, "registered".to_string(), None));
        }
        let Some(existing) = st.users.get(&user_id).cloned() else {
            unreachable!("just checked");
        };
        if otp_k <= existing.otp_k {
            return Ok((user_id, "fresh".to_string(), None));
        }
        let current = st
            .objects
            .get(&State::key(&user_id, "prosopeion.hdap"))
            .and_then(|b| hdap_core::crypto::aead_open(&st.master_key, &b.bytes).ok())
            .unwrap_or_default();
        let next_edition = doc.edition.max(2);
        let next_text = {
            let mut n = doc.clone();
            n.edition = next_edition;
            if next_edition > 1 {
                n.prev_hash = Some(content_hash(&current));
            }
            n.render()
        };
        let master = st.master_key;
        let key = State::key(&user_id, "prosopeion.hdap");
        st.objects.insert(
            key,
            Blob {
                owner: user_id.clone(),
                path: "prosopeion.hdap".into(),
                hash: content_hash(next_text.as_bytes()),
                bytes: hdap_core::crypto::aead_seal(&master, next_text.as_bytes()),
            },
        );
        st.users.insert(
            user_id.clone(),
            UserRecord {
                user_id: user_id.clone(),
                nickname,
                suffix_hex: suffix,
                sign_pub_hex,
                enc_pub_hex,
                otp_anchor_hex,
                otp_k,
                created_at: existing.created_at,
                home_pyle: existing.home_pyle.clone(),
            },
        );
        // Reset OTP floor for new chain
        st.omphalos_step.insert(user_id.clone(), 1);
        Ok((user_id, "rotated".to_string(), Some(next_edition)))
    }
}

#[cfg(test)]
mod house_move_tests {
    use super::*;
    use ed25519_dalek::Signer;
    use hdap_core::doc::{Doc, DocType};
    use serde_json::json;

    fn signed_move(
        user: &str,
        suffix: &str,
        key: &ed25519_dalek::SigningKey,
        edition: u64,
    ) -> serde_json::Value {
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        let mut props = Doc::new(DocType::Prosopeion, 1, None, 1000);
        props.body.insert("NICKNAME".into(), user.into());
        props.body.insert("SUFFIX".into(), suffix.into());
        props.body.insert("SIGN_PUBKEY".into(), pub_hex);
        props.body.insert("ENC_PUBKEY".into(), "bb".repeat(32));
        props.body.insert("OMPHALOS".into(), "cc".repeat(32));
        props.body.insert("SEED_ITER".into(), "4096".into());
        props.body.insert("CREATED".into(), "1000".into());
        let properties = props.render();
        let adeia = hdap_core::protocol::adeia_doc(
            &format!("{user}_{suffix}"),
            edition,
            Some("aa".repeat(32)),
            2000,
            &[],
            None,
        )
        .render();
        let payload = hdap_core::house_move_payload(
            &format!("{user}_{suffix}"),
            "pyle-new",
            &properties,
            &adeia,
        );
        let sig = base64::engine::general_purpose::STANDARD
            .encode(key.sign(payload.as_bytes()).to_bytes());
        json!({
            "properties": properties,
            "adeia": adeia,
            "new_pyle": "pyle-new",
            "signature": sig,
        })
    }

    #[test]
    fn a_signed_house_move_installs_a_newer_adeia_once() {
        let (node, _) = crate::node::Node::with_clock_and_now(Config::default(), 1000);
        let m = IdentityModule::new(node.cfg.clone());
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let user = "jose";
        let suffix = "0123456789abcdef";
        let uid = format!("{user}_{suffix}");

        let body = signed_move(user, suffix, &key, 2);
        let (id, pyle, edition) = m.apply_house_move(&node, &body, None, None).unwrap();
        assert_eq!(
            (id.as_str(), pyle.as_str(), edition),
            (uid.as_str(), "pyle-new", 2)
        );
        {
            let st = node.state.lock().unwrap();
            assert_eq!(
                st.users[&uid].sign_pub_hex,
                hex::encode(key.verifying_key().to_bytes())
            );
            assert_eq!(
                st.users[&uid].home_pyle, "pyle-new",
                "a relayed move must record where the namespace now lives"
            );
            assert_eq!(
                hdap_core::doc::parse(&st.permissions[&uid])
                    .unwrap()
                    .edition,
                2
            );
            assert!(st
                .objects
                .contains_key(&crate::store::State::key(&uid, "adeia.hdap")));
        }

        let replay = m.apply_house_move(&node, &body, None, None);
        assert_eq!(replay.unwrap_err().status, 409);
    }

    fn signed_diadosi(
        user: &str,
        key: &ed25519_dalek::SigningKey,
        edition: u64,
        home: &str,
        fallbacks: &[&str],
        properties: &str,
        adeia: &str,
    ) -> String {
        let uid = format!("{user}_0123456789abcdef");
        let proxy = hdap_core::protocol::DiadosiDoc {
            owner: uid,
            owner_pubkey: hex::encode(key.verifying_key().to_bytes()),
            home_pyle: home.into(),
            fallbacks: fallbacks.iter().map(|p| p.to_string()).collect(),
            adeia_edition: 1,
            adeia_hash: hdap_core::crypto::sha256_hex(adeia.as_bytes()),
            properties_hash: hdap_core::crypto::sha256_hex(properties.as_bytes()),
            edition,
            prev_hash: None,
            created_at: 1000,
        };
        let mut doc = proxy.to_doc();
        doc.sigs.push(hdap_core::doc::Signature {
            signer: proxy.owner.clone(),
            signer_pubkey: Some(proxy.owner_pubkey.clone()),
            signature: String::new(),
        });
        let input = doc.signature_input(0).unwrap();
        doc.sigs[0].signature =
            base64::engine::general_purpose::STANDARD.encode(key.sign(input.as_bytes()).to_bytes());
        doc.render()
    }

    #[test]
    fn a_signed_diadosi_promotes_a_listed_backup_when_the_home_is_dead() {
        let (node, _) = crate::node::Node::with_clock_and_now(
            Config {
                server_id: "pyle-b".into(),
                ..Config::default()
            },
            1000,
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let user = "jose";
        let uid = format!("{user}_0123456789abcdef");
        let pub_hex = hex::encode(key.verifying_key().to_bytes());

        let mut props = Doc::new(DocType::Prosopeion, 1, None, 1000);
        props.body.insert("NICKNAME".into(), user.into());
        props
            .body
            .insert("SUFFIX".into(), "0123456789abcdef".into());
        props.body.insert("SIGN_PUBKEY".into(), pub_hex.clone());
        props.body.insert("ENC_PUBKEY".into(), "bb".repeat(32));
        props.body.insert("OMPHALOS".into(), "cc".repeat(32));
        props.body.insert("SEED_ITER".into(), "4096".into());
        let properties = props.render();
        let adeia = hdap_core::protocol::adeia_doc(&uid, 1, None, 1000, &[], None).render();
        let proxy = signed_diadosi(user, &key, 1, "pyle-a", &["pyle-b"], &properties, &adeia);

        {
            let mut st = node.state.lock().unwrap();
            st.users.insert(
                uid.clone(),
                UserRecord {
                    user_id: uid.clone(),
                    nickname: user.into(),
                    suffix_hex: "0123456789abcdef".into(),
                    sign_pub_hex: pub_hex,
                    enc_pub_hex: "bb".repeat(32),
                    otp_anchor_hex: "cc".repeat(32),
                    otp_k: 4096,
                    created_at: 1000,
                    home_pyle: "pyle-a".into(),
                },
            );
            for (path, plain) in [
                ("prosopeion.hdap", properties.as_bytes()),
                ("adeia.hdap", adeia.as_bytes()),
                ("diadosi.hdap", proxy.as_bytes()),
            ] {
                let sealed = hdap_core::crypto::aead_seal(&st.master_key, plain);
                st.objects.insert(
                    crate::store::State::key(&uid, path),
                    Blob {
                        owner: uid.clone(),
                        path: path.into(),
                        hash: content_hash(plain),
                        bytes: sealed,
                    },
                );
            }
            st.peers.insert(
                "pyle-a".into(),
                crate::store::PeerRecord {
                    node_id: "pyle-a".into(),
                    sign_pub_hex: "dd".repeat(32),
                    endpoint: "127.0.0.1:1".into(),
                    tls_pin: None,
                },
            );
        }

        let m = IdentityModule::new(node.cfg.clone());
        assert!(
            m.maybe_promote_fallback(&node, &uid),
            "a listed backup must take over when the home does not answer"
        );
        assert_eq!(node.state.lock().unwrap().users[&uid].home_pyle, "pyle-b");
        assert!(
            !m.maybe_promote_fallback(&node, &uid),
            "once promoted, this pyle is the home and must stop probing"
        );
    }

    #[test]
    fn a_house_move_with_a_forged_signature_is_rejected() {
        let (node, _) = crate::node::Node::with_clock_and_now(Config::default(), 1000);
        let m = IdentityModule::new(node.cfg.clone());
        let key = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]);
        let mut body = signed_move("maria", "fedcba9876543210", &key, 2);
        body["signature"] = json!(base64::engine::general_purpose::STANDARD.encode([0u8; 64]));
        let err = m.apply_house_move(&node, &body, None, None).unwrap_err();
        assert_eq!(err.status, 401);
        assert!(node.state.lock().unwrap().users.is_empty());
    }
}
