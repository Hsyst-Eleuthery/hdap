//! Pull-through federation (`apographon` on demand).
//!
//! When a user opens a `HDAP!<pyle>@<user>/<path>` URI naming a *different*
//! node, the local pyle does not just refuse: it pulls that user's whole
//! namespace from the source pyle, stores a local replica under the same
//! `owner`, and serves it from here. Any later reference to the external URI
//! then resolves locally (it is already present), and if the owner themself
//! logs into this pyle their root is already populated.
//!
//! Every pull registers the source pyle in the known-pyles book (`State::peers`
//! is fed by the handshake; the mirror record `State::mirrors` records which
//! pyle the bytes came from) and each fetched blob is entered in the local
//! `prytaneion` with the real origin, so provenance survives the copy.
//!
//! Security: any pyle can be dialed by its address-derived id (federation is
//! open, AME-34), the outbound call is signed with the node's persistent key,
//! and every blob is re-hashed after transfer — a peer cannot substitute
//! content. The request also names the user it is pulling for, and the source
//! applies *that user's* view of the owner's `adeia` before listing or sending
//! bytes: a mirror never receives content the requester could not read at the
//! origin.

use base64::Engine as _;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use hdap_core::crypto::{aead_seal, sha256_hex};
use hdap_core::identity::parse_global_id;
use hdap_core::parse_access_uri;
use serde_json::Value;

use crate::config::Config;
use crate::fed_client::FedHttpClient;
use crate::http::{Request, Response};
use crate::node::{json_err, require_json, Access};
use crate::store::{Blob, MirrorOrigin, State, UserRecord};

pub struct MirrorModule {
    cfg: Config,
}

/// A remote namespace as announced by `GET /homospondoi/namespace`.
struct RemoteNamespace {
    owner: String,
    user: RemoteUser,
    prosopeion: Option<String>,
    adeia: Option<String>,
    entries: Vec<RemoteEntry>,
    /// Files the source withheld because the requester's `adeia` grants nothing
    /// (public config docs excluded). Surfaced to the client so a mirror that
    /// looks empty can say *why*.
    denied: usize,
}

struct RemoteUser {
    sign_pub_hex: String,
    enc_pub_hex: String,
    otp_anchor_hex: String,
    otp_k: usize,
    nickname: String,
    suffix_hex: String,
    created_at: u64,
    home_pyle: String,
}

struct RemoteEntry {
    path: String,
    hash: String,
}

impl MirrorModule {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    /// `POST /resolve` — resolve an access URI, pulling the namespace here when
    /// it lives on another pyle. Body: `{ "uri": "HDAP!<pyle>@<user>/<path>" }`.
    ///
    /// Reply: `{ "status": "local" | "mirrored", "pyle": <this>, "owner": ...,
    /// "path": ... }`, or an error status with `{ "error": ... }`.
    pub fn handle_resolve(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let uri = body.get("uri").and_then(|v| v.as_str()).unwrap_or("");
        let Some((pyle, owner, path)) = parse_access_uri(uri) else {
            return Response::json(400, json_err("uri must be HDAP!<pyle>@<user>/<path>"));
        };
        if parse_global_id(&owner).is_none() {
            return Response::json(400, json_err("invalid user id in uri"));
        }

        let (local_known, local_home) = {
            let st = node.state.lock().unwrap();
            match st.users.get(&owner) {
                Some(u) => (true, u.home_pyle.clone()),
                None => (false, String::new()),
            }
        };

        // A local record is only authoritative when this is actually the
        // owner's home. A relayed house move installs a stub (`users` +
        // prosopeion/adeia) on peers so signatures and listings work offline;
        // treating that stub as "local" hid every uploaded file from a third
        // pyle. Empty `home_pyle` is the legacy/never-moved case.
        let local_is_home = pyle == self.cfg.server_id
            && local_known
            && (local_home.is_empty() || local_home == self.cfg.server_id);

        if pyle == self.cfg.server_id && !local_known {
            return Response::json(404, json_err("owner not registered on this pyle"));
        }
        if local_is_home {
            return Response::json(
                200,
                serde_json::json!({ "status": "local", "pyle": self.cfg.server_id, "owner": owner, "path": path })
                    .to_string(),
            );
        }

        // The URI's pyle is the first guess, not the only one. If the home
        // pyle went down, a known mirror can still serve the namespace; if the
        // user moved, the current home is authoritative even when the old URI
        // still names the previous pyle. Tried in order, deduplicated:
        //   1. pyle named by the URI
        //   2. the owner's current `home_pyle`
        //   3. the pyle this namespace was last mirrored from
        //   4. every other known peer (bounded by the peer table)
        let mut candidates: Vec<String> = Vec::new();
        let mut add = |id: &str| {
            if !id.is_empty() && id != self.cfg.server_id && !candidates.iter().any(|c| c == id) {
                candidates.push(id.to_string());
            }
        };
        if pyle != self.cfg.server_id {
            add(&pyle);
        }
        add(&local_home);
        {
            let st = node.state.lock().unwrap();
            if let Some(m) = st.mirrors.get(&owner) {
                add(&m.origin_pyle);
            }
            for id in st.peers.keys() {
                add(id);
            }
        }

        let mut last_error = String::from("no candidate pyle answered");
        for source in candidates {
            let peer = match self.ensure_peer(node, &source) {
                Ok(p) => p,
                Err(_) => {
                    last_error = format!("{source}: unreachable or unknown");
                    continue;
                }
            };
            if peer.endpoint.trim().is_empty() {
                last_error = format!("{source}: no endpoint");
                continue;
            }
            // Dial the peer (network I/O) *before* taking the state lock. The
            // requester travels with the pull: the source applies *their* view
            // of the owner's `adeia`, so unauthorized bytes never leave.
            let remote = match self.pull_namespace(node, &peer, &owner, &user_id) {
                Ok(r) if r.owner == owner => r,
                Ok(_) => {
                    last_error = format!("{source}: answered for another owner");
                    continue;
                }
                Err(_) => {
                    last_error = format!("{source}: namespace unavailable");
                    continue;
                }
            };
            let (copied, denied) = match self.store_namespace(node, &peer, remote, &user_id) {
                Ok(n) => n,
                Err(e) => return e,
            };
            return Response::json(
                200,
                serde_json::json!({
                    "status": "mirrored",
                    "pyle": self.cfg.server_id,
                    "owner": owner,
                    "path": path,
                    "copied": copied,
                    "denied": denied,
                    "resolved_via": source,
                })
                .to_string(),
            );
        }

        Response::json(
            502,
            json_err(&format!("namespace unavailable ({last_error})")),
        )
    }

    /// `POST /resolve_hash` — fetch a file by content hash.
    ///
    /// Body: `{ "hash": "<sha256-hex>", "owner"?: "...", "path"?: "..." }`.
    /// Order: a local blob the requester may read, then the origin pyle, then
    /// known replicas. The bytes are hash-checked, their `sphragis` is checked
    /// against the author's public key (from the ledger or the origin), and
    /// only then cached under the requester's own namespace — never in a
    /// shared one, so another user cannot list or read it.
    ///
    /// If the origin is gone and no reachable pyle has the entry/signature,
    /// the file is refused: a private namespace does not become public just
    /// because its home pyle vanished.
    pub fn handle_resolve_hash(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let hash = body
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Response::json(400, json_err("hash must be 64 hex characters"));
        }

        // 1. Local first: an authorized copy under any namespace (including a
        // previous cache in the requester's own space).
        let local_matches: Vec<Blob> = {
            let st = node.state.lock().unwrap();
            st.objects
                .values()
                .filter(|b| b.hash == hash)
                .cloned()
                .collect()
        };
        if let Some((owner, path)) = local_matches
            .iter()
            .find(|b| {
                is_public_doc(&b.path)
                    || node.authorize(&user_id, &b.owner, &b.path, Access::Read)
                    || node.authorize_replica(&user_id, &b.owner, &b.path)
            })
            .map(|b| (b.owner.clone(), b.path.clone()))
        {
            return Response::json(
                200,
                serde_json::json!({
                    "status": "local",
                    "owner": owner,
                    "path": path,
                    "hash": hash,
                    "verified": true,
                    "holders": ["local"],
                })
                .to_string(),
            );
        }

        // 2. Find provenance. The local ledger is global, but a fresh bubble
        // may not have exchanged it yet; ask a bounded set of peers.
        let mut entry = node.state.lock().unwrap().prytaneion.get(&hash).cloned();
        if entry.is_none() {
            let peers: Vec<_> = {
                let st = node.state.lock().unwrap();
                st.peers.values().cloned().collect()
            };
            for peer in peers.iter().take(8) {
                if let Some(found) = crate::node::ledger::find_on_peer(node, peer, &hash) {
                    let mut st = node.state.lock().unwrap();
                    crate::node::ledger::merge(&mut st, &found);
                    entry = Some(found);
                    break;
                }
            }
        }

        // 3. Origin first, then replicas named by the ledger.
        let mut sources: Vec<String> = Vec::new();
        if let Some(e) = &entry {
            if !e.origin_server.is_empty() && e.origin_server != self.cfg.server_id {
                sources.push(e.origin_server.clone());
            }
            let known: Vec<String> = node.state.lock().unwrap().peers.keys().cloned().collect();
            for replica in &e.replicas {
                let server = replica_server(replica, &known);
                if !server.is_empty() && server != self.cfg.server_id && !sources.contains(&server)
                {
                    sources.push(server);
                }
            }
        }
        if sources.is_empty() {
            return Response::json(404, json_err("no known pyle holds this hash"));
        }

        let mut refusals = 0usize;
        let mut last_error = String::from("no reachable pyle returned the blob");
        for source in sources {
            let peer = match self.ensure_peer(node, &source) {
                Ok(p) => p,
                Err(_) => {
                    refusals += 1;
                    continue;
                }
            };
            if peer.endpoint.trim().is_empty() {
                refusals += 1;
                continue;
            }
            let (node_id, sign_key) = self.outbound_identity(node);
            let client = match FedHttpClient::new(&peer.endpoint, peer.tls_pin.clone()) {
                Ok(c) => c,
                Err(e) => {
                    last_error = format!("bad peer endpoint: {e}");
                    continue;
                }
            };
            let path = format!("/homospondoi/fetch_blob?hash={hash}");
            let resp = match client.get_with_fed_auth(&path, &node_id, &sign_key, Some(&user_id)) {
                Ok(r) => r,
                Err(e) => {
                    last_error = format!("peer unreachable: {e}");
                    continue;
                }
            };
            if resp.status == 401 || resp.status == 403 {
                refusals += 1;
                continue;
            }
            if !(200..300).contains(&resp.status) {
                last_error = format!("peer returned {}", resp.status);
                continue;
            }
            if sha256_hex(&resp.body) != hash {
                last_error = "source returned bytes with the wrong hash".to_string();
                continue;
            }
            let origin_user = header(&resp, "x-hdap-origin-user")
                .or_else(|| entry.as_ref().map(|e| e.origin_user.clone()))
                .unwrap_or_default();
            let origin_server = header(&resp, "x-hdap-origin-server")
                .or_else(|| entry.as_ref().map(|e| e.origin_server.clone()))
                .unwrap_or_else(|| source.clone());
            let origin_path = header(&resp, "x-hdap-origin-path")
                .or_else(|| entry.as_ref().map(|e| e.origin_path.clone()))
                .unwrap_or_default();
            let mut pubkey_hex = header(&resp, "x-hdap-origin-pubkey")
                .or_else(|| entry.as_ref().map(|e| e.origin_user_pubkey.clone()))
                .unwrap_or_default();
            let mut sphragis = header(&resp, "x-hdap-sphragis")
                .or_else(|| entry.as_ref().map(|e| e.sphragis.clone()))
                .unwrap_or_default();
            // If the source could not supply provenance, ask the origin (or
            // the mirror's public `/prytaneion`) before accepting the bytes.
            if pubkey_hex.is_empty() || sphragis.is_empty() {
                if let Some(p) = self.origin_provenance(node, &peer, &hash) {
                    if pubkey_hex.is_empty() {
                        pubkey_hex = p.0;
                    }
                    if sphragis.is_empty() {
                        sphragis = p.1;
                    }
                }
            }
            if pubkey_hex.is_empty() && !origin_user.is_empty() {
                let st = node.state.lock().unwrap();
                pubkey_hex = st
                    .users
                    .get(&origin_user)
                    .map(|u| u.sign_pub_hex.clone())
                    .unwrap_or_default();
            }
            let verified = verify_sphragis(&resp.body, &pubkey_hex, &sphragis);
            if verified.is_none() && !sphragis.is_empty() {
                last_error = "author signature invalid".to_string();
                continue;
            }
            let verified = verified.unwrap_or(false);

            let cached = match self.cache_blob(
                node,
                &user_id,
                &hash,
                &resp.body,
                &origin_server,
                &origin_user,
                &origin_path,
                &pubkey_hex,
                &sphragis,
            ) {
                Ok(path) => path,
                Err(e) => return e,
            };
            let mut holders: Vec<String> = Vec::new();
            if let Some(e) = &entry {
                if !e.origin_server.is_empty() {
                    holders.push(e.origin_server.clone());
                }
                let known: Vec<String> = node.state.lock().unwrap().peers.keys().cloned().collect();
                for replica in &e.replicas {
                    let server = replica_server(replica, &known);
                    if !server.is_empty() && !holders.contains(&server) {
                        holders.push(server);
                    }
                }
            }
            if holders.is_empty() {
                holders.push(source.clone());
            }
            return Response::json(
                200,
                serde_json::json!({
                    "status": "fetched",
                    "source": source,
                    "owner": user_id,
                    "path": cached,
                    "hash": hash,
                    "verified": verified,
                    "holders": holders,
                    "origin": {
                        "server": origin_server,
                        "user": origin_user,
                        "path": origin_path,
                    },
                })
                .to_string(),
            );
        }

        let msg = if refusals > 0 {
            format!("blob unavailable: {refusals} pyle(s) refused authorization ({last_error})")
        } else {
            last_error
        };
        Response::json(404, json_err(&msg))
    }

    /// Ask a specific pyle for the provenance document of a hash. This is the
    /// "ask the origin for the author's public key" step; mirrors answer too.
    fn origin_provenance(
        &self,
        _node: &crate::node::Node,
        peer: &crate::store::PeerRecord,
        hash: &str,
    ) -> Option<(String, String)> {
        let client = FedHttpClient::new(&peer.endpoint, peer.tls_pin.clone()).ok()?;
        let path = format!("/prytaneion?hash={hash}");
        let resp = client.get_json(&path).ok()?;
        if !(200..300).contains(&resp.status) {
            return None;
        }
        let text = String::from_utf8(resp.body).ok()?;
        let doc = hdap_core::doc::parse(&text).ok()?;
        let pubkey = doc.body.get("ORIGIN_PUBKEY").cloned().unwrap_or_default();
        let sig = doc.body.get("SPHRAGIS").cloned().unwrap_or_default();
        if pubkey.is_empty() && sig.is_empty() {
            None
        } else {
            Some((pubkey, sig))
        }
    }

    /// Store the fetched plaintext under the requester's own cache namespace,
    /// respecting their moira quota, and register the replica in the global
    /// ledger (with provenance) so the bubble can find this copy later.
    #[allow(clippy::too_many_arguments)]
    fn cache_blob(
        &self,
        node: &crate::node::Node,
        requester: &str,
        hash: &str,
        plain: &[u8],
        origin_server: &str,
        origin_user: &str,
        origin_path: &str,
        pubkey_hex: &str,
        sphragis: &str,
    ) -> Result<String, Response> {
        let name = origin_path
            .rsplit('/')
            .next()
            .filter(|n| !n.is_empty() && *n != "." && *n != "..")
            .unwrap_or(hash);
        let name = name.replace(['/', '\\'], "_");
        let path = format!("cache/{hash}/{name}");
        let key = State::key(requester, &path);
        let now = node.now();
        let mut st = node.state.lock().unwrap();
        if let Some(existing) = st.objects.get(&key) {
            if existing.hash == hash {
                return Ok(path);
            }
        }
        let used = st.stored.get(requester).copied().unwrap_or(0);
        if self.cfg.moira_bytes > 0 && used + plain.len() as u64 > self.cfg.moira_bytes {
            return Err(Response::json(413, json_err("moira quota exceeded")));
        }
        let master = st.master_key;
        st.objects.insert(
            key.clone(),
            Blob {
                owner: requester.to_string(),
                path: path.clone(),
                hash: hash.to_string(),
                bytes: aead_seal(&master, plain),
            },
        );
        *st.stored.entry(requester.to_string()).or_insert(0) += plain.len() as u64;
        let replica = format!("{}:{}", self.cfg.server_id, key);
        let entry = st.prytaneion.entry(hash.to_string()).or_insert_with(|| {
            crate::store::PrytaneionEntry {
                content_hash: hash.to_string(),
                origin_server: origin_server.to_string(),
                origin_user: origin_user.to_string(),
                origin_user_pubkey: pubkey_hex.to_string(),
                origin_path: origin_path.to_string(),
                sphragis: sphragis.to_string(),
                replicas: vec![replica.clone()],
                deletions: vec![],
                created_at: now,
            }
        });
        for (slot, value) in [
            (&mut entry.origin_server, origin_server),
            (&mut entry.origin_user, origin_user),
            (&mut entry.origin_user_pubkey, pubkey_hex),
            (&mut entry.origin_path, origin_path),
            (&mut entry.sphragis, sphragis),
        ] {
            if slot.is_empty() && !value.is_empty() {
                *slot = value.to_string();
            }
        }
        if !entry.replicas.contains(&replica) {
            entry.replicas.push(replica);
        }
        Ok(path)
    }

    /// `GET /mirrors` — list the local copies of remote namespaces.
    pub fn handle_mirrors(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(_user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let st = node.state.lock().unwrap();
        let list: Vec<Value> = st
            .mirrors
            .iter()
            .map(|(owner, m)| {
                serde_json::json!({
                    "owner": owner,
                    "origin_pyle": m.origin_pyle,
                    "origin_server": m.origin_server,
                    "pulled_at": m.pulled_at,
                })
            })
            .collect();
        Response::json(200, serde_json::json!({ "mirrors": list }).to_string())
    }

    /// Resolve a pyle id to a dialable peer record. Known peers come from the
    /// handshake; an endpoint-addressed id is dialed directly, since federation
    /// is always open. On that first contact we handshake so both sides pin
    /// each other's signing key.
    fn ensure_peer(
        &self,
        node: &crate::node::Node,
        pyle: &str,
    ) -> Result<crate::store::PeerRecord, Response> {
        if let Some(peer) = node.state.lock().unwrap().peers.get(pyle).cloned() {
            return Ok(peer);
        }
        let Some(endpoint) = crate::pyle::endpoint_from_id(pyle) else {
            return Err(Response::json(
                409,
                json_err("unknown pyle: id is not endpoint-addressed and has not handshaked"),
            ));
        };
        let (node_id, sign_key) = self.outbound_identity(node);
        let self_endpoint = crate::node::discovery::own_endpoint(node);
        let body = serde_json::json!({
            "node_id": node_id,
            "pubkey": hex::encode(sign_key.verifying_key().to_bytes()),
            "endpoint": self_endpoint,
            "tls_pin": node.tls_pin,
            "directory_digest": crate::node::discovery::directory_digest(node),
            "ledger_digest": crate::node::ledger::digest(
                &node.state.lock().unwrap().prytaneion
            ),
        })
        .to_string();
        let client = match FedHttpClient::new(&endpoint, None) {
            Ok(c) => c,
            Err(e) => {
                return Err(Response::json(
                    502,
                    json_err(&format!("bad pyle endpoint: {e}")),
                ))
            }
        };
        let resp = match client.post_json("/homospondoi/handshake", &body) {
            Ok(r) => r,
            Err(e) => {
                return Err(Response::json(
                    502,
                    json_err(&format!("peer unreachable: {e}")),
                ))
            }
        };
        if !(200..300).contains(&resp.status) {
            return Err(Response::json(
                502,
                json_err(&format!("peer refused handshake: {}", resp.status)),
            ));
        }
        let reply = serde_json::from_slice::<Value>(&resp.body).ok();
        if reply
            .as_ref()
            .and_then(|v| v.get("server_id"))
            .and_then(|s| s.as_str())
            .is_some_and(|id| id != pyle)
        {
            return Err(Response::json(
                502,
                json_err("peer answered with another server_id"),
            ));
        }
        let peer_pub = reply
            .as_ref()
            .and_then(|v| {
                v.get("node_sign_pub")
                    .and_then(|s| s.as_str())
                    .map(String::from)
            })
            .unwrap_or_default();
        let tls_pin = reply
            .as_ref()
            .and_then(|v| v.get("tls_pin"))
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        let peer = crate::store::PeerRecord {
            node_id: pyle.to_string(),
            sign_pub_hex: peer_pub,
            endpoint,
            tls_pin,
        };
        node.state
            .lock()
            .unwrap()
            .peers
            .insert(pyle.to_string(), peer.clone());
        if let Some(peers) = reply
            .as_ref()
            .and_then(|v| v.get("directory"))
            .and_then(|v| v.as_array())
        {
            let base = format!("mirror-handshake:{pyle}:{}", node.now());
            crate::node::discovery::ingest_directory(node, peers, pyle, &base, 3);
        }
        node.discovery.enqueue_ledger(pyle.to_string());
        Ok(peer)
    }

    /// Dial `GET /homospondoi/namespace` on `peer` and parse the reply.
    fn pull_namespace(
        &self,
        node: &crate::node::Node,
        peer: &crate::store::PeerRecord,
        owner: &str,
        requester: &str,
    ) -> Result<RemoteNamespace, Response> {
        let (node_id, sign_key) = self.outbound_identity(node);
        let client = match FedHttpClient::new(&peer.endpoint, peer.tls_pin.clone()) {
            Ok(c) => c,
            Err(e) => {
                return Err(Response::json(
                    502,
                    json_err(&format!("bad peer endpoint: {e}")),
                ))
            }
        };
        let path = format!("/homospondoi/namespace?owner={owner}");
        let resp = match client.get_with_fed_auth(&path, &node_id, &sign_key, Some(requester)) {
            Ok(r) => r,
            Err(e) => {
                return Err(Response::json(
                    502,
                    json_err(&format!("peer unreachable: {e}")),
                ))
            }
        };
        if resp.status == 401 {
            return Err(Response::json(
                403,
                json_err("peer refused federation auth"),
            ));
        }
        if resp.status == 404 {
            return Err(Response::json(
                404,
                json_err("owner not registered on the source pyle"),
            ));
        }
        if !(200..300).contains(&resp.status) {
            return Err(Response::json(
                502,
                json_err(&format!("peer namespace error {}", resp.status)),
            ));
        }
        let v: Value = match serde_json::from_slice(&resp.body) {
            Ok(v) => v,
            Err(_) => {
                return Err(Response::json(
                    502,
                    json_err("peer sent non-json namespace"),
                ))
            }
        };
        parse_namespace(&v).ok_or_else(|| Response::json(502, json_err("peer namespace malformed")))
    }

    /// Fetch each blob the namespace lists that this pyle does not already
    /// hold, verify the hash, and store it sealed under the owner's space.
    fn store_namespace(
        &self,
        node: &crate::node::Node,
        peer: &crate::store::PeerRecord,
        remote: RemoteNamespace,
        requester: &str,
    ) -> Result<(usize, usize), Response> {
        // A pyle outside the owner's `DIADOSI` boundary must not acquire a
        // copy even if an older/unpatched source did not enforce it.
        if !node.diadosi_allows(&remote.owner, &self.cfg.server_id, "") {
            return Err(Response::json(
                403,
                json_err("this pyle is outside the owner's diadosi"),
            ));
        }
        let (node_id, sign_key) = self.outbound_identity(node);
        let client = match FedHttpClient::new(&peer.endpoint, peer.tls_pin.clone()) {
            Ok(c) => c,
            Err(e) => {
                return Err(Response::json(
                    502,
                    json_err(&format!("bad peer endpoint: {e}")),
                ))
            }
        };
        let now = node.now();
        let mut copied = 0usize;
        for entry in &remote.entries {
            // Skip anything already present byte-for-byte (idempotent resolve).
            {
                let st = node.state.lock().unwrap();
                if st
                    .objects
                    .get(&State::key(&remote.owner, &entry.path))
                    .is_some_and(|b| b.hash == entry.hash)
                {
                    continue;
                }
            }
            let path = format!("/homospondoi/fetch_blob?hash={}", entry.hash);
            let resp = match client.get_with_fed_auth(&path, &node_id, &sign_key, Some(requester)) {
                Ok(r) => r,
                Err(e) => {
                    return Err(Response::json(
                        502,
                        json_err(&format!("peer blob fetch failed: {e}")),
                    ))
                }
            };
            if !(200..300).contains(&resp.status) {
                return Err(Response::json(
                    502,
                    json_err(&format!(
                        "peer refused blob {}: {}",
                        entry.hash, resp.status
                    )),
                ));
            }
            // The hash is the only thing that makes the bytes trustworthy; a
            // peer that lies is caught here, not trusted.
            if sha256_hex(&resp.body) != entry.hash {
                return Err(Response::json(
                    502,
                    json_err(&format!("blob {} failed hash verification", entry.hash)),
                ));
            }
            let origin_server = resp
                .headers
                .get("x-hdap-origin-server")
                .cloned()
                .unwrap_or_else(|| peer.node_id.clone());
            let origin_user = resp
                .headers
                .get("x-hdap-origin-user")
                .cloned()
                .unwrap_or_else(|| remote.owner.clone());
            let mut st = node.state.lock().unwrap();
            let key = State::key(&remote.owner, &entry.path);
            // Never clobber existing local content with a replica.
            if st.objects.contains_key(&key) {
                continue;
            }
            // Honor the source directory's own `adeia` (and the other root
            // config docs): copying `adeia.hdap` into `objects` is not enough,
            // the ACL map must be reindexed from it, or authorization on the
            // mirror would ignore the owner's rules. The original pyle's adeia
            // is authoritative — if it says "no", it is "no".
            node.storage
                .reindex_config_doc(&mut st, &remote.owner, &entry.path, &resp.body);
            let master = st.master_key;
            st.objects.insert(
                key.clone(),
                Blob {
                    owner: remote.owner.clone(),
                    path: entry.path.clone(),
                    hash: entry.hash.clone(),
                    bytes: aead_seal(&master, &resp.body),
                },
            );
            *st.stored.entry(remote.owner.clone()).or_insert(0) += resp.body.len() as u64;
            // Freeze the `adeia` that authorized this copy. A later edition
            // (or a house move) governs new content, but must not retroactively
            // take an already public post offline on every mirror.
            if let Some(adeia) = &remote.adeia {
                st.replica_acls
                    .entry(key.clone())
                    .or_insert_with(|| adeia.clone());
            }
            let replica = format!("{}:{}", self.cfg.server_id, key);
            st.prytaneion.entry(entry.hash.clone()).or_insert_with(|| {
                crate::store::PrytaneionEntry {
                    content_hash: entry.hash.clone(),
                    origin_server,
                    origin_user,
                    origin_user_pubkey: resp
                        .headers
                        .get("x-hdap-origin-pubkey")
                        .cloned()
                        .unwrap_or_default(),
                    origin_path: resp
                        .headers
                        .get("x-hdap-origin-path")
                        .cloned()
                        .unwrap_or_else(|| entry.path.clone()),
                    sphragis: resp
                        .headers
                        .get("x-hdap-sphragis")
                        .cloned()
                        .unwrap_or_default(),
                    replicas: vec![replica.clone()],
                    deletions: vec![],
                    created_at: now,
                }
            });
            if let Some(e) = st.prytaneion.get_mut(&entry.hash) {
                if !e.replicas.contains(&replica) {
                    e.replicas.push(replica);
                }
                if e.origin_user_pubkey.is_empty() {
                    e.origin_user_pubkey = resp
                        .headers
                        .get("x-hdap-origin-pubkey")
                        .cloned()
                        .unwrap_or_default();
                }
                if e.origin_path.is_empty() {
                    e.origin_path = resp
                        .headers
                        .get("x-hdap-origin-path")
                        .cloned()
                        .unwrap_or_else(|| entry.path.clone());
                }
                if e.sphragis.is_empty() {
                    e.sphragis = resp
                        .headers
                        .get("x-hdap-sphragis")
                        .cloned()
                        .unwrap_or_default();
                }
            }
            copied += 1;
        }

        // Register (or refresh) the mirror record and the owner's identity, so
        // authorization (`adeia`) and listing work exactly like local content.
        let mut st = node.state.lock().unwrap();
        let home_pyle = if remote.user.home_pyle.is_empty() {
            peer.node_id.clone()
        } else {
            remote.user.home_pyle.clone()
        };
        st.users
            .entry(remote.owner.clone())
            .or_insert_with(|| UserRecord {
                user_id: remote.owner.clone(),
                nickname: remote.user.nickname.clone(),
                suffix_hex: remote.user.suffix_hex.clone(),
                sign_pub_hex: remote.user.sign_pub_hex.clone(),
                enc_pub_hex: remote.user.enc_pub_hex.clone(),
                otp_anchor_hex: remote.user.otp_anchor_hex.clone(),
                otp_k: remote.user.otp_k,
                created_at: remote.user.created_at,
                home_pyle: home_pyle.clone(),
            });
        if let Some(user) = st.users.get_mut(&remote.owner) {
            if !home_pyle.is_empty() {
                user.home_pyle = home_pyle;
            }
        }
        if let Some(prosopeion) = &remote.prosopeion {
            if !st
                .objects
                .contains_key(&State::key(&remote.owner, "prosopeion.hdap"))
            {
                let created_at = remote.user.created_at;
                let auth = crate::node::AuthModule::new(self.cfg.clone());
                auth.ensure_hestia(&mut st, &remote.owner, prosopeion, created_at);
            }
        }
        // The source directory's `adeia` decides who may read this replica, and
        // it is re-applied on every resolve so a change at the source is picked
        // up even when the blobs were already present (idempotent resolve).
        // "Segue a adeia": if the original says "no", it stays "no".
        if let Some(adeia) = &remote.adeia {
            st.permissions.insert(remote.owner.clone(), adeia.clone());
            // Keep the stored `adeia.hdap` identical to the ACL we enforce (and
            // later advertise). The entries loop above deliberately does not
            // clobber an existing local config doc, so without this the node
            // would enforce the source's ACL while its own blob — and what it
            // re-federates — stayed stale or empty.
            let master = st.master_key;
            st.objects.insert(
                State::key(&remote.owner, "adeia.hdap"),
                Blob {
                    owner: remote.owner.clone(),
                    path: "adeia.hdap".to_string(),
                    hash: sha256_hex(adeia.as_bytes()),
                    bytes: aead_seal(&master, adeia.as_bytes()),
                },
            );
        }
        st.mirrors.insert(
            remote.owner.clone(),
            MirrorOrigin {
                origin_pyle: peer.node_id.clone(),
                origin_server: peer.node_id.clone(),
                pulled_at: now,
            },
        );
        Ok((copied, remote.denied))
    }

    /// The node identity used to sign outbound federation calls.
    fn outbound_identity(&self, node: &crate::node::Node) -> (String, ed25519_dalek::SigningKey) {
        let seed = node.state.lock().unwrap().node_sign_seed;
        (
            self.cfg.server_id.clone(),
            ed25519_dalek::SigningKey::from_bytes(&seed),
        )
    }
}

fn is_public_doc(path: &str) -> bool {
    crate::node::is_public_identity_doc(path)
}

fn header(resp: &crate::fed_client::HttpResponse, name: &str) -> Option<String> {
    resp.headers
        .get(name)
        .cloned()
        .or_else(|| resp.headers.get(&name.to_ascii_uppercase()).cloned())
}

/// Return the pyle id a `pyle:owner/path` replica string belongs to. Known
/// pyle ids are matched by longest prefix, because ids may contain `:`.
fn replica_server(replica: &str, known: &[String]) -> String {
    if let Some(id) = known
        .iter()
        .filter(|id| replica.starts_with(&format!("{id}:")))
        .max_by_key(|id| id.len())
    {
        return id.clone();
    }
    replica
        .split_once(':')
        .map(|(s, _)| s)
        .unwrap_or("")
        .to_string()
}

fn verify_sphragis(body: &[u8], pubkey_hex: &str, sphragis_b64: &str) -> Option<bool> {
    if pubkey_hex.is_empty() || sphragis_b64.is_empty() {
        return None;
    }
    let pubkey: [u8; 32] = hex::decode(pubkey_hex).ok()?.try_into().ok()?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sphragis_b64)
        .ok()?;
    let sig = Ed25519Signature::from_slice(&sig_bytes).ok()?;
    let key = VerifyingKey::from_bytes(&pubkey).ok()?;
    Some(key.verify(body, &sig).is_ok())
}

/// Parse `HDAP!<pyle>@<user>/<path>` into its three components. The path is
/// normalized (leading/trailing slashes trimmed); `HDAP!pyle@user` is the root.
fn parse_namespace(v: &Value) -> Option<RemoteNamespace> {
    let owner = v.get("owner")?.as_str()?.to_string();
    let user = v.get("user")?;
    let remote_user = RemoteUser {
        sign_pub_hex: user.get("sign_pub_hex")?.as_str()?.to_string(),
        enc_pub_hex: user.get("enc_pub_hex")?.as_str()?.to_string(),
        otp_anchor_hex: user.get("otp_anchor_hex")?.as_str()?.to_string(),
        otp_k: user.get("otp_k")?.as_u64()? as usize,
        nickname: user.get("nickname")?.as_str()?.to_string(),
        suffix_hex: user.get("suffix_hex")?.as_str()?.to_string(),
        created_at: user.get("created_at")?.as_u64()?,
        home_pyle: user
            .get("home_pyle")
            .and_then(|h| h.as_str())
            .unwrap_or_default()
            .to_string(),
    };
    let prosopeion = v
        .get("prosopeion")
        .and_then(|p| p.as_str())
        .map(String::from);
    // The source pyle sends its `adeia` alongside the listing; it is the
    // authority for who may read the mirrored namespace. Keep it only if it
    // actually parses as an adeia document.
    let adeia = v
        .get("adeia")
        .and_then(|a| a.as_str())
        .filter(|t| {
            matches!(
                hdap_core::doc::parse(t),
                Ok(d) if d.doc_type == hdap_core::doc::DocType::Adeia
            )
        })
        .map(String::from);
    let mut entries = Vec::new();
    for e in v.get("entries")?.as_array()? {
        let path = e.get("path")?.as_str()?.to_string();
        let hash = e.get("hash")?.as_str()?.to_string();
        // Belt and braces: the sealed size must fit what a blob can hold.
        if path.is_empty() || hash.len() != 64 {
            continue;
        }
        // `pow/*` documents are node-local band artefacts, never mirrored.
        if path.starts_with("pow/") {
            continue;
        }
        entries.push(RemoteEntry { path, hash });
    }
    let denied = v.get("denied").and_then(|d| d.as_u64()).unwrap_or(0) as usize;
    Some(RemoteNamespace {
        owner,
        user: remote_user,
        prosopeion,
        adeia,
        entries,
        denied,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    mod integration {
        use super::*;
        use crate::config::FederationPeer;
        use crate::node::Node;
        use crate::store::{PeerRecord, Session};
        use ed25519_dalek::SigningKey;
        use std::collections::BTreeMap;

        fn sign_pub_hex(seed: [u8; 32]) -> String {
            hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
        }

        fn req(method: &str, path: &str, token: Option<&str>, body: &str) -> Request {
            let mut headers = BTreeMap::new();
            if let Some(t) = token {
                headers.insert("x-hdap-token".to_string(), t.to_string());
            }
            Request {
                method: method.to_string(),
                path: path.to_string(),
                query: BTreeMap::new(),
                headers,
                body: body.as_bytes().to_vec(),
            }
        }

        /// Populate `node` with a registered owner holding one blob, the way a
        /// real node would after register + upload.
        fn seed_owner(node: &Node, owner: &str, path: &str, plain: &[u8]) {
            let master = node.state.lock().unwrap().master_key;
            let mut st = node.state.lock().unwrap();
            st.users.insert(
                owner.to_string(),
                UserRecord {
                    user_id: owner.to_string(),
                    nickname: owner.split('_').next().unwrap_or("u").to_string(),
                    suffix_hex: owner.rsplit_once('_').unwrap().1.to_string(),
                    sign_pub_hex: "aa".repeat(32),
                    enc_pub_hex: "bb".repeat(32),
                    otp_anchor_hex: "cc".repeat(32),
                    otp_k: 1024,
                    created_at: 1_700_000_000,
                    home_pyle: node.cfg.server_id.clone(),
                },
            );
            let prosopeion = {
                let mut d = hdap_core::doc::Doc::new(
                    hdap_core::DocType::Prosopeion,
                    1,
                    None,
                    1_700_000_000,
                );
                d.body.insert("NICKNAME".into(), "jose".into());
                d.body.insert("SUFFIX".into(), "0123456789abcdef".into());
                d.body.insert("SIGN_PUBKEY".into(), "aa".repeat(32));
                d.body.insert("ENC_PUBKEY".into(), "bb".repeat(32));
                d.body.insert("OMPHALOS".into(), "cc".repeat(32));
                d.body.insert("SEED_ITER".into(), "1024".into());
                d.render()
            };
            let auth = crate::node::AuthModule::new(node.cfg.clone());
            auth.ensure_hestia(&mut st, owner, &prosopeion, 1_700_000_000);
            let sealed = hdap_core::crypto::aead_seal(&master, plain);
            st.objects.insert(
                State::key(owner, path),
                Blob {
                    owner: owner.to_string(),
                    path: path.to_string(),
                    hash: sha256_hex(plain),
                    bytes: sealed,
                },
            );
        }

        #[test]
        fn cross_pyle_uri_pulls_the_namespace_and_serves_it_locally() {
            let owner = "jose_0123456789abcdef";
            let plain = b"conteudo remoto";

            // --- source pyle (pyle-b) ---
            let seed_b = [7u8; 32];
            let node_b = Node::new(Config {
                server_id: "pyle-b".into(),
                federation_peers: BTreeMap::new(),
                ..Config::default()
            });
            node_b.state.lock().unwrap().node_sign_seed = seed_b;
            seed_owner(&node_b, owner, "docs/a.txt", plain);

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap().to_string();
            let node_b = std::sync::Arc::new(node_b);
            let served = std::sync::Arc::clone(&node_b);
            std::thread::spawn(move || {
                let h = move |r: Request| served.handle(&r);
                let _ = crate::http::serve(listener, 8 * 1024 * 1024, h);
            });

            // --- requester pyle (pyle-a) ---
            let seed_a = [9u8; 32];
            let mut peers = BTreeMap::new();
            peers.insert(
                "pyle-b".to_string(),
                FederationPeer {
                    pubkey: sign_pub_hex(seed_b),
                    endpoint: String::new(),
                    tls_pin: None,
                },
            );
            let node_a = Node::new(Config {
                server_id: "pyle-a".into(),
                federation_peers: peers,
                ..Config::default()
            });
            node_a.state.lock().unwrap().node_sign_seed = seed_a;
            // pyle-b must trust pyle-a's outbound signature.
            node_b.state.lock().unwrap().peers.insert(
                "pyle-a".to_string(),
                PeerRecord {
                    node_id: "pyle-a".to_string(),
                    sign_pub_hex: sign_pub_hex(seed_a),
                    endpoint: String::new(),
                    tls_pin: None,
                },
            );

            // Handshake tells pyle-a where pyle-b lives.
            let hs = req(
                "POST",
                "/homospondoi/handshake",
                None,
                &serde_json::json!({
                    "node_id": "pyle-b",
                    "pubkey": sign_pub_hex(seed_b),
                    "endpoint": endpoint,
                })
                .to_string(),
            );
            assert_eq!(node_a.handle(&hs).status, 200);

            // A session on pyle-a (the user doing the browsing). It is the
            // owner themself, so the source lets us pull their whole space.
            node_a.state.lock().unwrap().sessions.insert(
                "tok".to_string(),
                Session {
                    user_id: owner.to_string(),
                    exp: u64::MAX,
                },
            );

            let resolve = serde_json::json!({
                "uri": format!("HDAP!pyle-b@{owner}/docs/a.txt")
            })
            .to_string();
            let resp = node_a.handle(&req("POST", "/resolve", Some("tok"), &resolve));
            assert_eq!(
                resp.status,
                200,
                "body: {}",
                String::from_utf8_lossy(&resp.body)
            );
            let v: Value = serde_json::from_slice(&resp.body).unwrap();
            assert_eq!(v["status"], "mirrored");
            assert_eq!(v["owner"], owner);
            assert_eq!(v["path"], "docs/a.txt");
            assert!(
                v["copied"].as_u64().unwrap() >= 1,
                "the namespace listing (content + hestia docs) must be copied"
            );

            // The blob now lives here, byte-identical and attributed to the owner.
            {
                let st = node_a.state.lock().unwrap();
                let blob = st.objects.get(&State::key(owner, "docs/a.txt")).unwrap();
                assert_eq!(blob.owner, owner);
                assert_eq!(blob.hash, sha256_hex(plain));
                let back = hdap_core::crypto::aead_open(&st.master_key, &blob.bytes).unwrap();
                assert_eq!(back, plain);
                assert_eq!(st.mirrors.get(owner).unwrap().origin_pyle, "pyle-b");
                assert_eq!(st.users.get(owner).unwrap().user_id, owner);
            }

            // A second resolve is idempotent: nothing re-copied.
            let resp = node_a.handle(&req("POST", "/resolve", Some("tok"), &resolve));
            assert_eq!(resp.status, 200);
            let v: Value = serde_json::from_slice(&resp.body).unwrap();
            assert_eq!(v["copied"], 0);

            // `GET /mirrors` lists what was pulled.
            let resp = node_a.handle(&req("GET", "/mirrors", Some("tok"), ""));
            let v: Value = serde_json::from_slice(&resp.body).unwrap();
            assert_eq!(v["mirrors"][0]["origin_pyle"], "pyle-b");
        }

        #[test]
        fn resolve_rejects_an_unprovisioned_pyle() {
            let node = Node::new(Config {
                server_id: "pyle-a".into(),
                ..Config::default()
            });
            node.state.lock().unwrap().sessions.insert(
                "tok".to_string(),
                Session {
                    user_id: "local_ffffffffffffffff".to_string(),
                    exp: u64::MAX,
                },
            );
            let body =
                serde_json::json!({ "uri": "HDAP!pyle-z@jose_0123456789abcdef/x" }).to_string();
            let resp = node.handle(&req("POST", "/resolve", Some("tok"), &body));
            assert_eq!(resp.status, 502);
            assert!(
                String::from_utf8_lossy(&resp.body).contains("namespace unavailable"),
                "body: {}",
                String::from_utf8_lossy(&resp.body)
            );
        }

        /// A third pyle that only saw a relayed house move has the owner as a
        /// stub (identity + config docs, no uploads). It must treat its local
        /// record as non-authoritative and pull the real namespace from the
        /// current home, even when the URI still names the dead old pyle.
        #[test]
        fn a_relayed_house_move_stub_pulls_the_current_home_on_resolve() {
            let owner = "jose_0123456789abcdef";
            let plain = b"arquivo que so existe na casa nova";

            // Current home: pyle-b, with the upload.
            let seed_b = [7u8; 32];
            let node_b = Node::new(Config {
                server_id: "pyle-b".into(),
                ..Config::default()
            });
            node_b.state.lock().unwrap().node_sign_seed = seed_b;
            seed_owner(&node_b, owner, "docs/upload.txt", plain);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint_b = listener.local_addr().unwrap().to_string();
            let node_b = std::sync::Arc::new(node_b);
            let served = std::sync::Arc::clone(&node_b);
            std::thread::spawn(move || {
                let h = move |r: Request| served.handle(&r);
                let _ = crate::http::serve(listener, 8 * 1024 * 1024, h);
            });

            // Third pyle: pyle-c. It knows pyle-b and has only the stub that a
            // relayed house_move would install (home_pyle = pyle-b).
            let seed_c = [9u8; 32];
            let node_c = Node::new(Config {
                server_id: "pyle-c".into(),
                ..Config::default()
            });
            node_c.state.lock().unwrap().node_sign_seed = seed_c;
            node_b.state.lock().unwrap().peers.insert(
                "pyle-c".to_string(),
                PeerRecord {
                    node_id: "pyle-c".to_string(),
                    sign_pub_hex: sign_pub_hex(seed_c),
                    endpoint: String::new(),
                    tls_pin: None,
                },
            );
            node_c.state.lock().unwrap().peers.insert(
                "pyle-b".to_string(),
                PeerRecord {
                    node_id: "pyle-b".to_string(),
                    sign_pub_hex: sign_pub_hex(seed_b),
                    endpoint: endpoint_b,
                    tls_pin: None,
                },
            );
            {
                let mut st = node_c.state.lock().unwrap();
                st.users.insert(
                    owner.to_string(),
                    UserRecord {
                        user_id: owner.to_string(),
                        nickname: "jose".into(),
                        suffix_hex: "0123456789abcdef".into(),
                        sign_pub_hex: "aa".repeat(32),
                        enc_pub_hex: "bb".repeat(32),
                        otp_anchor_hex: "cc".repeat(32),
                        otp_k: 1024,
                        created_at: 1_700_000_000,
                        home_pyle: "pyle-b".into(),
                    },
                );
                st.sessions.insert(
                    "tok".to_string(),
                    Session {
                        user_id: owner.to_string(),
                        exp: u64::MAX,
                    },
                );
            }

            // The URI names the *old* (dead) pyle; the stub's home_pyle is the
            // only clue to where the bytes actually are.
            let resolve = serde_json::json!({
                "uri": format!("HDAP!pyle-a@{owner}/docs/upload.txt")
            })
            .to_string();
            let resp = node_c.handle(&req("POST", "/resolve", Some("tok"), &resolve));
            assert_eq!(
                resp.status,
                200,
                "body: {}",
                String::from_utf8_lossy(&resp.body)
            );
            let v: Value = serde_json::from_slice(&resp.body).unwrap();
            assert_eq!(v["status"], "mirrored");
            assert_eq!(v["resolved_via"], "pyle-b");
            let st = node_c.state.lock().unwrap();
            let blob = st
                .objects
                .get(&State::key(owner, "docs/upload.txt"))
                .expect("the upload must be mirrored from the current home");
            let back = hdap_core::crypto::aead_open(&st.master_key, &blob.bytes).unwrap();
            assert_eq!(back, plain);
        }

        #[test]
        fn federation_dials_an_endpoint_addressed_pyle_without_provisioning() {
            let owner = "jose_0123456789abcdef";
            let plain = b"sem provisionamento";

            // Source pyle: names itself after the address it binds; federation is
            // always open, so it accepts a first handshake from an unknown node.
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap().to_string();
            let id_b = crate::pyle::id_from_endpoint(&endpoint);
            let node_b = Node::new(Config {
                server_id: id_b.clone(),
                ..Config::default()
            });
            node_b.state.lock().unwrap().node_sign_seed = [7u8; 32];
            seed_owner(&node_b, owner, "docs/a.txt", plain);
            let node_b = std::sync::Arc::new(node_b);
            let served = std::sync::Arc::clone(&node_b);
            std::thread::spawn(move || {
                let h = move |r: Request| served.handle(&r);
                let _ = crate::http::serve(listener, 8 * 1024 * 1024, h);
            });

            // Requester pyle: knows nothing about the source beyond the URI.
            let id_a = crate::pyle::id_from_endpoint("127.0.0.1:19999");
            let node_a = Node::new(Config {
                server_id: id_a.clone(),
                ..Config::default()
            });
            node_a.state.lock().unwrap().node_sign_seed = [9u8; 32];
            node_a.state.lock().unwrap().sessions.insert(
                "tok".to_string(),
                Session {
                    user_id: owner.to_string(),
                    exp: u64::MAX,
                },
            );

            let resolve =
                serde_json::json!({ "uri": format!("HDAP!{id_b}@{owner}/docs/a.txt") }).to_string();
            let resp = node_a.handle(&req("POST", "/resolve", Some("tok"), &resolve));
            assert_eq!(
                resp.status,
                200,
                "body: {}",
                String::from_utf8_lossy(&resp.body)
            );
            let v: Value = serde_json::from_slice(&resp.body).unwrap();
            assert_eq!(v["status"], "mirrored");
            // `pyle` is where the content is now served from: this node.
            assert_eq!(v["pyle"], id_a);

            let st = node_a.state.lock().unwrap();
            let blob = st.objects.get(&State::key(owner, "docs/a.txt")).unwrap();
            let back = hdap_core::crypto::aead_open(&st.master_key, &blob.bytes).unwrap();
            assert_eq!(back, plain);
            // First contact pinned the source's signing key in our peer book.
            assert_eq!(
                st.peers.get(&id_b).unwrap().sign_pub_hex,
                sign_pub_hex([7u8; 32])
            );
        }

        /// The real dev/prod case: the source pyle runs behind TLS, so an
        /// endpoint-addressed id with no pin must still reach it — the client
        /// probes plaintext and falls back to TLS-TOFU.
        #[test]
        fn federation_dials_a_tls_endpoint_addressed_pyle() {
            let owner = "jose_0123456789abcdef";
            let plain = b"tls pull-through";

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap().to_string();
            let id_b = crate::pyle::id_from_endpoint(&endpoint);
            let identity = hdap_tls::self_signed("pyle-b", &["127.0.0.1", "localhost"]).unwrap();
            let tls = identity.server_config().unwrap();

            let node_b = Node::new(Config {
                server_id: id_b.clone(),
                ..Config::default()
            });
            node_b.state.lock().unwrap().node_sign_seed = [7u8; 32];
            seed_owner(&node_b, owner, "docs/a.txt", plain);
            let node_b = std::sync::Arc::new(node_b);
            let served = std::sync::Arc::clone(&node_b);
            std::thread::spawn(move || {
                let h = move |r: Request| served.handle(&r);
                let _ = crate::http::serve_tls(listener, 8 * 1024 * 1024, tls, h);
            });

            let id_a = crate::pyle::id_from_endpoint("127.0.0.1:19998");
            let node_a = Node::new(Config {
                server_id: id_a,
                ..Config::default()
            });
            node_a.state.lock().unwrap().node_sign_seed = [9u8; 32];
            node_a.state.lock().unwrap().sessions.insert(
                "tok".to_string(),
                Session {
                    user_id: owner.to_string(),
                    exp: u64::MAX,
                },
            );

            let resolve =
                serde_json::json!({ "uri": format!("HDAP!{id_b}@{owner}/docs/a.txt") }).to_string();
            let resp = node_a.handle(&req("POST", "/resolve", Some("tok"), &resolve));
            assert_eq!(
                resp.status,
                200,
                "body: {}",
                String::from_utf8_lossy(&resp.body)
            );

            let st = node_a.state.lock().unwrap();
            let blob = st.objects.get(&State::key(owner, "docs/a.txt")).unwrap();
            let back = hdap_core::crypto::aead_open(&st.master_key, &blob.bytes).unwrap();
            assert_eq!(back, plain);
        }

        /// Replace the owner's root `adeia.hdap` with one carrying `perms`, so
        /// the source advertises the ACL the mirror must obey.
        fn set_adeia(node: &Node, owner: &str, perms: &[hdap_core::protocol::Permission]) {
            let master = node.state.lock().unwrap().master_key;
            let text =
                hdap_core::protocol::adeia_doc(owner, 1, None, 1_700_000_000, perms, None).render();
            let mut st = node.state.lock().unwrap();
            st.objects.insert(
                State::key(owner, "adeia.hdap"),
                Blob {
                    owner: owner.to_string(),
                    path: "adeia.hdap".to_string(),
                    hash: sha256_hex(text.as_bytes()),
                    bytes: hdap_core::crypto::aead_seal(&master, text.as_bytes()),
                },
            );
            // Mirror what `POST /adeia` does: the ACL cache is what the source
            // itself enforces, and federation now consults it too.
            st.permissions.insert(owner.to_string(), text);
        }

        fn get_ktema(owner: &str, path: &str, token: &str) -> Request {
            let mut query = BTreeMap::new();
            query.insert("owner".to_string(), owner.to_string());
            query.insert("path".to_string(), path.to_string());
            let mut headers = BTreeMap::new();
            headers.insert("x-hdap-token".to_string(), token.to_string());
            Request {
                method: "GET".to_string(),
                path: "ktema".to_string(),
                query,
                headers,
                body: Vec::new(),
            }
        }

        fn delete_ktema(owner: &str, path: &str, token: &str) -> Request {
            let mut req = get_ktema(owner, path, token);
            req.method = "DELETE".to_string();
            req
        }

        /// The mirror must obey the *source* directory's `adeia`: a guest the
        /// owner granted `read` can read the replica here, and a guest the
        /// owner did not grant stays forbidden. Copying `adeia.hdap` into the
        /// object store without reindexing the ACL would silently ignore the
        /// owner's rules.
        #[test]
        fn the_mirror_honors_the_source_adeia() {
            use hdap_core::protocol::{Permission, Right, Scope};

            let owner = "jose_0123456789abcdef";
            let guest = "thais2_ffffffffffffffff";
            let stranger = "outro_eeeeeeeeeeeeeeee";
            let plain = b"conteudo com adeia";

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap().to_string();
            let id_b = crate::pyle::id_from_endpoint(&endpoint);
            let node_b = Node::new(Config {
                server_id: id_b.clone(),
                ..Config::default()
            });
            node_b.state.lock().unwrap().node_sign_seed = [7u8; 32];
            seed_owner(&node_b, owner, "docs/a.txt", plain);
            set_adeia(
                &node_b,
                owner,
                &[Permission {
                    scope: Scope::User(guest.to_string()),
                    right: Right::Read,
                }],
            );
            let node_b = std::sync::Arc::new(node_b);
            let served = std::sync::Arc::clone(&node_b);
            std::thread::spawn(move || {
                let h = move |r: Request| served.handle(&r);
                let _ = crate::http::serve(listener, 8 * 1024 * 1024, h);
            });

            let id_a = crate::pyle::id_from_endpoint("127.0.0.1:19997");
            let node_a = Node::new(Config {
                server_id: id_a,
                ..Config::default()
            });
            node_a.state.lock().unwrap().node_sign_seed = [9u8; 32];
            {
                let mut st = node_a.state.lock().unwrap();
                st.sessions.insert(
                    "tokg".to_string(),
                    Session {
                        user_id: guest.to_string(),
                        exp: u64::MAX,
                    },
                );
                st.sessions.insert(
                    "toks".to_string(),
                    Session {
                        user_id: stranger.to_string(),
                        exp: u64::MAX,
                    },
                );
            }

            let resolve =
                serde_json::json!({ "uri": format!("HDAP!{id_b}@{owner}/docs/a.txt") }).to_string();
            let resp = node_a.handle(&req("POST", "/resolve", Some("tokg"), &resolve));
            assert_eq!(
                resp.status,
                200,
                "body: {}",
                String::from_utf8_lossy(&resp.body)
            );

            // The granted guest reads the replica byte-for-byte.
            let r = node_a.handle(&get_ktema(owner, "docs/a.txt", "tokg"));
            assert_eq!(
                r.status,
                200,
                "granted guest body: {}",
                String::from_utf8_lossy(&r.body)
            );
            assert_eq!(r.body, plain);

            // The stranger the owner never granted stays forbidden: the
            // original directory's `adeia` said "no".
            let r = node_a.handle(&get_ktema(owner, "docs/a.txt", "toks"));
            assert_eq!(r.status, 403, "the adeia must still deny the stranger");
        }

        /// Regression: the source's *enforced* ACL and its `adeia.hdap` blob can
        /// diverge (a mirror pull used to apply the cache without overwriting an
        /// existing empty blob). Federation must advertise the ACL it actually
        /// enforces — otherwise the puller copies the content and then applies
        /// an empty ACL, so the file arrives but listing/downloading it is 403.
        #[test]
        fn a_divergent_source_adeia_is_advertised_as_the_acl_it_enforces() {
            use hdap_core::protocol::{Permission, Right, Scope};

            let owner = "jose_0123456789abcdef";
            let guest = "thais2_ffffffffffffffff";
            let plain = b"conteudo divergente";

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap().to_string();
            let id_b = crate::pyle::id_from_endpoint(&endpoint);
            let node_b = Node::new(Config {
                server_id: id_b.clone(),
                ..Config::default()
            });
            node_b.state.lock().unwrap().node_sign_seed = [7u8; 32];
            seed_owner(&node_b, owner, "docs/f.png", plain);
            // Enforce `all read` in the cache while leaving the `adeia.hdap`
            // blob at the empty default created at registration.
            let acl = hdap_core::protocol::adeia_doc(
                owner,
                1,
                None,
                1_700_000_000,
                &[Permission {
                    scope: Scope::All,
                    right: Right::Read,
                }],
                None,
            )
            .render();
            node_b
                .state
                .lock()
                .unwrap()
                .permissions
                .insert(owner.to_string(), acl);
            let node_b = std::sync::Arc::new(node_b);
            let served = std::sync::Arc::clone(&node_b);
            std::thread::spawn(move || {
                let h = move |r: Request| served.handle(&r);
                let _ = crate::http::serve(listener, 8 * 1024 * 1024, h);
            });

            let id_a = crate::pyle::id_from_endpoint("127.0.0.1:19996");
            let node_a = Node::new(Config {
                server_id: id_a,
                ..Config::default()
            });
            node_a.state.lock().unwrap().node_sign_seed = [9u8; 32];
            node_a.state.lock().unwrap().sessions.insert(
                "tok".to_string(),
                Session {
                    user_id: guest.to_string(),
                    exp: u64::MAX,
                },
            );

            let resolve = serde_json::json!({ "uri": format!("HDAP!{id_b}@{owner}/") }).to_string();
            let resp = node_a.handle(&req("POST", "/resolve", Some("tok"), &resolve));
            assert_eq!(
                resp.status,
                200,
                "body: {}",
                String::from_utf8_lossy(&resp.body)
            );

            // The file came *and* the guest can read it: the advertised ACL
            // matched the one the source enforced.
            let get = node_a.handle(&get_ktema(owner, "docs/f.png", "tok"));
            assert_eq!(
                get.status,
                200,
                "get: {}",
                String::from_utf8_lossy(&get.body)
            );
            assert_eq!(get.body, plain);
        }

        /// A deletion at the origin must reach the replicas. The origin learns
        /// who holds a copy when a peer asks for `/homospondoi/namespace` (the
        /// watcher book); on delete it pushes a signed `prytaneion_update` to
        /// each of them. Without the push the "deleted" file lives forever on
        /// every mirror.
        #[test]
        fn deleting_at_the_origin_removes_the_replica() {
            use hdap_core::protocol::{Permission, Right, Scope};

            let owner = "jose_0123456789abcdef";
            let guest = "thais2_ffffffffffffffff";
            let plain = b"some day this is gone";

            // --- origin (B), dialable ---
            let listener_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint_b = listener_b.local_addr().unwrap().to_string();
            let id_b = crate::pyle::id_from_endpoint(&endpoint_b);
            let node_b = Node::new(Config {
                server_id: id_b.clone(),
                ..Config::default()
            });
            {
                let mut st = node_b.state.lock().unwrap();
                st.node_sign_seed = [7u8; 32];
                st.sessions.insert(
                    "tok_o".to_string(),
                    Session {
                        user_id: owner.to_string(),
                        exp: u64::MAX,
                    },
                );
            }
            seed_owner(&node_b, owner, "docs/a.txt", plain);
            set_adeia(
                &node_b,
                owner,
                &[Permission {
                    scope: Scope::User(guest.to_string()),
                    right: Right::Read,
                }],
            );
            let node_b = std::sync::Arc::new(node_b);
            let served_b = std::sync::Arc::clone(&node_b);
            std::thread::spawn(move || {
                let h = move |r: Request| served_b.handle(&r);
                let _ = crate::http::serve(listener_b, 8 * 1024 * 1024, h);
            });

            // --- mirror (A), also dialable so B can push the deletion back ---
            let listener_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint_a = listener_a.local_addr().unwrap().to_string();
            let id_a = crate::pyle::id_from_endpoint(&endpoint_a);
            let node_a = Node::new(Config {
                server_id: id_a,
                ..Config::default()
            });
            node_a.state.lock().unwrap().node_sign_seed = [9u8; 32];
            node_a.state.lock().unwrap().sessions.insert(
                "tokg".to_string(),
                Session {
                    user_id: guest.to_string(),
                    exp: u64::MAX,
                },
            );
            let node_a = std::sync::Arc::new(node_a);
            let served_a = std::sync::Arc::clone(&node_a);
            std::thread::spawn(move || {
                let h = move |r: Request| served_a.handle(&r);
                let _ = crate::http::serve(listener_a, 8 * 1024 * 1024, h);
            });

            // A mirrors the namespace, so B records A as a watcher.
            let resolve = serde_json::json!({ "uri": format!("HDAP!{id_b}@{owner}/") }).to_string();
            let resp = node_a.handle(&req("POST", "/resolve", Some("tokg"), &resolve));
            assert_eq!(
                resp.status,
                200,
                "body: {}",
                String::from_utf8_lossy(&resp.body)
            );
            assert_eq!(
                node_a.handle(&get_ktema(owner, "docs/a.txt", "tokg")).body,
                plain
            );

            // Delete at the origin; the push must be delivered synchronously.
            let resp = node_b.handle(&delete_ktema(owner, "docs/a.txt", "tok_o"));
            assert_eq!(
                resp.status,
                200,
                "body: {}",
                String::from_utf8_lossy(&resp.body)
            );
            let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
            assert_eq!(
                body["notified"].as_u64(),
                Some(1),
                "the watcher must be notified: {body}"
            );

            // The replica is gone, not just tombstoned.
            let r = node_a.handle(&get_ktema(owner, "docs/a.txt", "tokg"));
            assert_eq!(
                r.status,
                404,
                "replica must be gone: {}",
                String::from_utf8_lossy(&r.body)
            );
            assert!(
                !node_a
                    .state
                    .lock()
                    .unwrap()
                    .objects
                    .contains_key(&crate::store::State::key(owner, "docs/a.txt")),
                "the blob must be removed from the mirror"
            );
        }

        /// A grant published at the source *after* the first mirror must be
        /// re-applied by a later resolve, even though the content blob is
        /// already present and therefore not re-copied.
        #[test]
        fn a_later_source_adeia_is_reapplied_on_resolve() {
            use hdap_core::protocol::{Permission, Right, Scope};

            let owner = "jose_0123456789abcdef";
            let guest = "thais2_ffffffffffffffff";
            let plain = b"adeia publicada depois";

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap().to_string();
            let id_b = crate::pyle::id_from_endpoint(&endpoint);
            let node_b = Node::new(Config {
                server_id: id_b.clone(),
                ..Config::default()
            });
            node_b.state.lock().unwrap().node_sign_seed = [7u8; 32];
            seed_owner(&node_b, owner, "docs/a.txt", plain);
            let node_b = std::sync::Arc::new(node_b);
            let served = std::sync::Arc::clone(&node_b);
            std::thread::spawn(move || {
                let h = move |r: Request| served.handle(&r);
                let _ = crate::http::serve(listener, 8 * 1024 * 1024, h);
            });

            let id_a = crate::pyle::id_from_endpoint("127.0.0.1:19996");
            let node_a = Node::new(Config {
                server_id: id_a,
                ..Config::default()
            });
            node_a.state.lock().unwrap().node_sign_seed = [9u8; 32];
            node_a.state.lock().unwrap().sessions.insert(
                "tokg".to_string(),
                Session {
                    user_id: guest.to_string(),
                    exp: u64::MAX,
                },
            );

            let resolve =
                serde_json::json!({ "uri": format!("HDAP!{id_b}@{owner}/docs/a.txt") }).to_string();
            let r = node_a.handle(&req("POST", "/resolve", Some("tokg"), &resolve));
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            // With no grant yet the source only hands over the public config
            // docs: the private blob must never leave the origin, so the
            // mirror cannot even hold a copy it would then have to deny.
            let v: Value = serde_json::from_slice(&r.body).unwrap();
            assert_eq!(v["copied"], 2, "only the public docs may be pulled");
            assert!(
                !node_a
                    .state
                    .lock()
                    .unwrap()
                    .objects
                    .contains_key(&State::key(owner, "docs/a.txt")),
                "unauthorized bytes must not be replicated"
            );
            // The guest is denied on the replica.
            let r = node_a.handle(&get_ktema(owner, "docs/a.txt", "tokg"));
            assert_eq!(r.status, 403, "no grant yet");

            // The owner publishes a grant at the source.
            set_adeia(
                &node_b,
                owner,
                &[Permission {
                    scope: Scope::User(guest.to_string()),
                    right: Right::Read,
                }],
            );

            // A second resolve has nothing new to copy, but must re-apply the
            // source adeia.
            let r = node_a.handle(&req("POST", "/resolve", Some("tokg"), &resolve));
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            let r = node_a.handle(&get_ktema(owner, "docs/a.txt", "tokg"));
            assert_eq!(
                r.status,
                200,
                "the later grant must be honoured: {}",
                String::from_utf8_lossy(&r.body)
            );
            assert_eq!(r.body, plain);
        }

        /// Build a source pyle that serves TLS and trusts `node_a`'s outbound
        /// signature, returning `(id_b, endpoint, pin)`. The caller passes the
        /// pin to its peer record to exercise the pinned transport.
        fn tls_source(
            owner: &str,
            path: &str,
            plain: &[u8],
            seed_a: [u8; 32],
        ) -> (String, String, String) {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap().to_string();
            let id_b = crate::pyle::id_from_endpoint(&endpoint);
            let identity = hdap_tls::self_signed(&id_b, &["127.0.0.1", "localhost"]).unwrap();
            let pin = identity.pin();
            let tls = identity.server_config().unwrap();

            let node_b = Node::new(Config {
                server_id: id_b.clone(),
                ..Config::default()
            });
            node_b.state.lock().unwrap().node_sign_seed = [7u8; 32];
            seed_owner(&node_b, owner, path, plain);
            // The source must trust the requester's outbound federation signature.
            node_b.state.lock().unwrap().peers.insert(
                "pyle-a".to_string(),
                PeerRecord {
                    node_id: "pyle-a".to_string(),
                    sign_pub_hex: sign_pub_hex(seed_a),
                    endpoint: String::new(),
                    tls_pin: None,
                },
            );
            let node_b = std::sync::Arc::new(node_b);
            let served = std::sync::Arc::clone(&node_b);
            std::thread::spawn(move || {
                let h = move |r: Request| served.handle(&r);
                let _ = crate::http::serve_tls(listener, 8 * 1024 * 1024, tls, h);
            });
            (id_b, endpoint, pin)
        }

        fn requester_with_peer(
            owner: &str,
            peer_id: &str,
            endpoint: &str,
            tls_pin: Option<String>,
            seed_b: [u8; 32],
        ) -> Node {
            let node_a = Node::new(Config {
                server_id: "pyle-a".into(),
                ..Config::default()
            });
            node_a.state.lock().unwrap().node_sign_seed = [9u8; 32];
            node_a.state.lock().unwrap().peers.insert(
                peer_id.to_string(),
                PeerRecord {
                    node_id: peer_id.to_string(),
                    sign_pub_hex: sign_pub_hex(seed_b),
                    endpoint: endpoint.to_string(),
                    tls_pin,
                },
            );
            node_a.state.lock().unwrap().sessions.insert(
                "tok".to_string(),
                Session {
                    user_id: owner.to_string(),
                    exp: u64::MAX,
                },
            );
            node_a
        }

        /// A provisioned peer record carrying the *right* pin must be dialed
        /// over TLS with that pin enforced, and the namespace pulled.
        #[test]
        fn a_provisioned_peer_is_dialed_over_tls_with_its_pin() {
            let owner = "jose_0123456789abcdef";
            let plain = b"puxado por tls pinado";
            let (id_b, endpoint, pin) = tls_source(owner, "docs/a.txt", plain, [9u8; 32]);
            let node_a = requester_with_peer(owner, &id_b, &endpoint, Some(pin), [7u8; 32]);

            let resolve =
                serde_json::json!({ "uri": format!("HDAP!{id_b}@{owner}/docs/a.txt") }).to_string();
            let r = node_a.handle(&req("POST", "/resolve", Some("tok"), &resolve));
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            let st = node_a.state.lock().unwrap();
            let blob = st.objects.get(&State::key(owner, "docs/a.txt")).unwrap();
            let back = hdap_core::crypto::aead_open(&st.master_key, &blob.bytes).unwrap();
            assert_eq!(back, plain);
        }

        /// A *wrong* pin must refuse the pull: the pin is the trust anchor, so a
        /// changed certificate is never silently accepted (AME-09/37).
        #[test]
        fn a_wrong_pin_refuses_the_pull() {
            let owner = "jose_0123456789abcdef";
            let (id_b, endpoint, _pin) = tls_source(owner, "docs/a.txt", b"segredo", [9u8; 32]);
            let node_a =
                requester_with_peer(owner, &id_b, &endpoint, Some("00".repeat(32)), [7u8; 32]);

            let resolve =
                serde_json::json!({ "uri": format!("HDAP!{id_b}@{owner}/docs/a.txt") }).to_string();
            let r = node_a.handle(&req("POST", "/resolve", Some("tok"), &resolve));
            assert!(
                r.status >= 500,
                "a mismatched pin must fail loudly, got {}: {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            );
            assert!(
                !node_a
                    .state
                    .lock()
                    .unwrap()
                    .objects
                    .contains_key(&State::key(owner, "docs/a.txt")),
                "nothing may be stored when the pin does not match"
            );
        }
    }
}
