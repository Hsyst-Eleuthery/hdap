//! Node business logic split into focused modules.
//!
//! Each module handles a specific domain:
//! - `auth`: registration, 3FA authentication, sessions, OTP rotation
//! - `storage`: ktema (upload, download, list, delete), encryption at rest
//! - `permissions`: ACL (adeia), ownership transfer (metabibasis), authorization
//! - `bandwidth`: PoW challenges (mochthos), band credit (choregia), quotas (moira)
//! - `identity`: identity sync (prosopeion), registry lookup
//! - `federation`: peer handshake, sync, TCD (pheme), prytaneion updates
//! - `matrix`: prytaneion (provenance), pheme (reputation), kerux (aliases), timi (prices)
//! - `sync`: client bidirectional sync (GET/POST /sync)

pub mod auth;
pub mod bandwidth;
pub mod discovery;
pub mod federation;
pub mod identity;
pub mod ledger;
pub mod matrix;
pub mod mirror;
pub mod permissions;
pub mod storage;
pub mod sync;
pub mod transfer;

use crate::node::auth::AuthModule;
use bandwidth::BandwidthModule;
use discovery::DiscoveryModule;
use federation::FederationModule;
use identity::IdentityModule;
use matrix::MatrixModule;
use mirror::MirrorModule;
use permissions::PermissionsModule;
use storage::StorageModule;
use sync::SyncModule;
use transfer::TransferModule;

use crate::config::Config;
use crate::http::{Request, Response};
use crate::store::State as StoreState;
use rand_core::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hdap_core::doc::parse as parse_doc;
use hdap_core::protocol::{parse_perm_line, Scope};

/// Effective access level derived from `adeia.hdap` lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Own,
}

fn right_to_access(r: hdap_core::protocol::Right) -> Option<Access> {
    match r {
        hdap_core::protocol::Right::Deny => None,
        hdap_core::protocol::Right::Read => Some(Access::Read),
        hdap_core::protocol::Right::Write => Some(Access::Write),
        hdap_core::protocol::Right::Own => Some(Access::Own),
    }
}

fn json_err(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

fn require_json(body: &[u8]) -> Result<serde_json::Value, Response> {
    serde_json::from_slice(body).map_err(|_| Response::json(400, json_err("invalid json body")))
}

fn sig_from_b64(b64: &str) -> Option<ed25519_dalek::Signature> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    ed25519_dalek::Signature::from_slice(&bytes).ok()
}

/// Compute the hex digest used for `prytaneion` keys.
pub fn content_hash(data: &[u8]) -> String {
    hdap_core::crypto::sha256_hex(data)
}

/// The band-credit challenge a `pyle` issues. It is bound to the issuing
/// node (`server_id`); a challenge minted by a different node is **not**
/// honored here (mochthos are honored only by their issuer — the anti
/// double-spend rule for band credit).
pub fn mochthos_challenge(server_id: &str) -> String {
    format!("hdap-mochthos:{server_id}")
}

pub const SERVER_INTEGRITY_TAG: &str = "hdap-server/v1";
pub const SEAL_OVERHEAD: usize = 12 + 16;

/// A node: owns a `State`, a clock and config; demuxes HTTP requests.
pub struct Node {
    pub cfg: Config,
    pub state: Mutex<StoreState>,
    /// Node ENC keypair. The private half never leaves memory; the public
    /// half is published so users derive the factor-3 shared key `k` (§7.4).
    node_enc_priv: x25519_dalek::StaticSecret,
    /// TLS certificate pin (SHA-256 of the node's self-signed cert DER),
    /// exposed on `/health` so clients can pin it (TOFU, AME-09).
    pub tls_pin: Option<String>,
    /// Optional durable database for at-rest persistence.
    pub db: Option<Arc<crate::db::Db>>,
    /// Address other pyles should dial. Set from `--advertise`/`--listen`;
    /// falls back to the endpoint encoded in an endpoint-addressed node id.
    pub advertise_endpoint: Option<String>,
    /// Wall-clock for deterministic tests; uses system time when 0.
    clock: Arc<AtomicU64>,

    // Submodules
    auth: AuthModule,
    bandwidth: BandwidthModule,
    federation: FederationModule,
    discovery: DiscoveryModule,
    identity: IdentityModule,
    matrix: MatrixModule,
    mirror: MirrorModule,
    permissions: PermissionsModule,
    storage: StorageModule,
    sync: SyncModule,
    transfer: TransferModule,
}

impl Node {
    /// Create a node with a live system clock.
    pub fn new(cfg: Config) -> Node {
        Self::with_clock_and_now(cfg, 0).0
    }

    /// Create a node pinned to a fixed wall-clock value (used by tests so
    /// challenge/session TTL logic is deterministic).
    pub(crate) fn with_clock_and_now(
        cfg: Config,
        now: u64,
    ) -> (Node, Box<dyn Fn() -> u64 + Send + Sync>) {
        let mut master_key = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut master_key);
        let mut state = StoreState {
            master_key,
            whoami: cfg.server_id.clone(),
            ..StoreState::default()
        };
        state.whoami.clone_from(&cfg.server_id);
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(now));
        let read = clock.clone();
        let now_fn: Box<dyn Fn() -> u64 + Send + Sync> =
            Box::new(move || read.load(std::sync::atomic::Ordering::Relaxed));
        let node_enc_priv = hdap_core::crypto::x25519_keygen(&mut rand_core::OsRng);
        let node = Node {
            cfg: cfg.clone(),
            state: Mutex::new(state),
            clock,
            node_enc_priv,
            tls_pin: None,
            db: None,
            advertise_endpoint: None,
            auth: AuthModule::new(cfg.clone()),
            bandwidth: BandwidthModule::new(cfg.clone()),
            federation: FederationModule::new(cfg.clone()),
            discovery: DiscoveryModule::default(),
            identity: IdentityModule::new(cfg.clone()),
            matrix: MatrixModule::new(cfg.clone()),
            mirror: MirrorModule::new(cfg.clone()),
            permissions: PermissionsModule::new(cfg.clone()),
            storage: StorageModule::new(cfg.clone()),
            sync: SyncModule::new(cfg.clone()),
            transfer: TransferModule::new(cfg.clone()),
        };
        (node, now_fn)
    }

    /// Hex of the node's published ENC public key.
    fn node_enc_pub_hex(&self) -> String {
        hex::encode(hdap_core::crypto::x25519_public(&self.node_enc_priv))
    }

    fn now(&self) -> u64 {
        let fixed = self.clock.load(Ordering::Relaxed);
        if fixed != 0 {
            fixed
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }
    }

    /// Dispatch a request to the matching handler.
    pub fn handle(&self, req: &Request) -> Response {
        if self.rate_limited(req) {
            return Response::json(429, json_err("rate limit exceeded"));
        }
        let mutating = matches!(req.method.as_str(), "POST" | "DELETE" | "PUT");
        let resp = self.dispatch(req);
        // AME-35: a mutating request is answered only after its effect is on
        // disk. The fingerprint inside `flush` makes a no-op POST cheap, so
        // this stays correct even for read-only POSTs (proklesis, etc.).
        if mutating && self.db.is_some() && (200..300).contains(&resp.status) {
            if let Err(e) = self.persist() {
                return Response::json(500, json_err(&format!("persist failed: {e}")));
            }
        }
        resp
    }

    fn dispatch(&self, req: &Request) -> Response {
        let method = req.method.as_str();
        let mut parts = req.path.trim_start_matches('/').splitn(3, '/');
        let primary = parts.next().unwrap_or("");
        eprintln!(
            "DISPATCH: method={} path={} primary={}",
            method, req.path, primary
        );
        match (method, primary) {
            ("GET", "health") => self.handle_health(),
            ("GET", "bubble") => self.discovery.handle_bubble(self, req),
            ("GET", "pyle") => {
                if parts.next() == Some("integrity") {
                    self.handle_integrity()
                } else {
                    Response::json(404, json_err("unknown route"))
                }
            }
            ("POST", "register") => self.identity.handle_register(self, req),
            ("POST", "house_move") => self.identity.handle_house_move(self, req),
            ("POST", "diadosi") => self.identity.handle_diadosi(self, req),
            ("GET", "registry") => self.identity.handle_registry(self, req),
            ("POST", "omphalos") => self.auth.handle_omphalos_rotate(self, req),
            ("GET", "proklesis") => self.auth.handle_proklesis(self, req),
            ("POST", "auth") => self.auth.handle_auth(self, req),
            ("POST", "mochthos") => match parts.next() {
                Some("issue") => self.bandwidth.handle_mochthos(self, req),
                Some("countersign") => self.bandwidth.handle_countersign(self, req),
                Some("proklesis") => Response::json(
                    200,
                    serde_json::json!({
                        "challenge": mochthos_challenge(&self.cfg.server_id),
                        "issuer": self.cfg.server_id,
                        "target_secs": self.cfg.pow.target_secs,
                        "min_bits": self.cfg.pow.min_bits,
                        "max_bits": self.cfg.pow.max_bits,
                    })
                    .to_string(),
                ),
                _ => Response::json(404, json_err("unknown mochthos route")),
            },
            ("GET", "mochthos") => match parts.next() {
                Some("band") => self.bandwidth.handle_band_list(self, req),
                _ => Response::json(404, json_err("unknown mochthos route")),
            },
            ("GET", "ktema") => match parts.next() {
                Some("list") => self.storage.handle_ktema_list(self, req),
                _ => self.storage.handle_ktema_get(self, req),
            },
            ("POST", "ktema") => self.storage.handle_ktema_upload(self, req),
            ("DELETE", "ktema") => self.storage.handle_ktema_delete(self, req),
            ("POST", "adeia") => self.permissions.handle_adeia(self, req),
            ("POST", "metabibasis") => self.permissions.handle_metabibasis(self, req),
            ("POST", "transfer") => match parts.next() {
                Some("request") => self.transfer.handle_request(self, req),
                Some("inbox") => self.transfer.handle_inbox_post(self, req),
                Some("accept") => self.transfer.handle_accept(self, req),
                Some("complete") => self.transfer.handle_complete(self, req),
                Some("deliver") => self.transfer.handle_deliver(self, req),
                Some("release") => self.transfer.handle_release(self, req),
                _ => Response::json(404, json_err("unknown transfer route")),
            },
            ("GET", "transfer") => match parts.next() {
                Some("inbox") => self.transfer.handle_inbox_get(self, req),
                _ => Response::json(404, json_err("unknown transfer route")),
            },
            ("GET", "sync") => self.sync.handle_sync(self, req),
            ("POST", "sync") => self.sync.handle_sync_post(self, req),
            ("POST", "prosopeion") => self.identity.handle_prosopeion_sync(self, req),
            ("GET", "prytaneion") => self.matrix.handle_prytaneion_read(self, req),
            ("POST", "prytaneion") => self.matrix.handle_prytaneion_write(self, req),
            ("GET", "pheme") => self.matrix.handle_pheme_read(self, req),
            ("POST", "pheme") => self.matrix.handle_pheme_propose(self, req),
            ("GET", "kerux") => self.matrix.handle_kerux_read(self, req),
            ("POST", "kerux") => self.matrix.handle_kerux_write(self, req),
            ("GET", "timi") => self.matrix.handle_timi_read(self, req),
            ("POST", "timi") => self.matrix.handle_timi_write(self, req),
            ("POST", "homospondoi") | ("GET", "homospondoi") => {
                self.federation.handle_fed(self, req)
            }
            ("POST", "resolve") => self.mirror.handle_resolve(self, req),
            ("POST", "resolve_hash") => self.mirror.handle_resolve_hash(self, req),
            ("GET", "mirrors") => self.mirror.handle_mirrors(self, req),
            _ => Response::json(404, json_err("route not found")),
        }
    }

    fn rate_limited(&self, req: &Request) -> bool {
        if self.cfg.rate_limit_per_sec == 0 {
            return false;
        }
        let key = req
            .headers
            .get("x-hdap-peer")
            .cloned()
            .unwrap_or_else(|| "local".to_string());
        let now = self.now();
        let mut st = self.state.lock().unwrap();
        let bucket = st.rate.entry(key).or_default();
        while bucket.front().is_some_and(|t| now.saturating_sub(*t) >= 1) {
            bucket.pop_front();
        }
        if bucket.len() as u32 >= self.cfg.rate_limit_burst {
            return true;
        }
        bucket.push_back(now);
        false
    }

    fn handle_health(&self) -> Response {
        let node_sign_pub = {
            let seed = self.state.lock().unwrap().node_sign_seed;
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            hex::encode(key.verifying_key().to_bytes())
        };
        let mut body = serde_json::json!({
            "status": "ok",
            "server_id": self.cfg.server_id,
            "node_enc_pub": self.node_enc_pub_hex(),
            "node_sign_pub": node_sign_pub,
            "pylaia_required": self.cfg.require_entry_pow,
            "pylaia_target": self.cfg.pylaia_target,
        });
        if let Some(pin) = &self.tls_pin {
            body["tls_pin"] = serde_json::json!(pin);
        }
        Response::json(200, body.to_string())
    }

    fn handle_integrity(&self) -> Response {
        let hash =
            content_hash(format!("{}:{}", SERVER_INTEGRITY_TAG, self.cfg.server_id).as_bytes());
        Response::json(
            200,
            serde_json::json!({ "server_id": self.cfg.server_id, "integrity_sha256": hash })
                .to_string(),
        )
    }

    /// Extract the authenticated user_id from the request headers (session token).
    pub(crate) fn session_user(&self, req: &Request) -> Option<String> {
        let token = req.headers.get("x-hdap-token").cloned().or_else(|| {
            req.headers
                .get("authorization")
                .and_then(|v| v.strip_prefix("Bearer ").map(|s| s.to_string()))
        })?;
        let st = self.state.lock().unwrap();
        let sess = st.sessions.get(&token)?;
        if sess.exp < self.now() {
            return None;
        }
        Some(sess.user_id.clone())
    }

    /// Authorization helper: checks if `requester` has `need` access to `path` under `owner`.
    pub fn authorize(&self, requester: &str, owner: &str, path: &str, need: Access) -> bool {
        // Identity documents are public by design and are needed to verify
        // signatures even when the requester has no grant. Writes still go
        // through the normal ownership checks below.
        if matches!(need, Access::Read) && is_public_identity_doc(path) {
            return true;
        }
        let st = self.state.lock().unwrap();
        if requester == owner {
            // A completed transfer is an irrevocable read-only cession for the
            // cedente (§11.3). `adeia` edits cannot buy write access back.
            if matches!(need, Access::Write | Access::Own)
                && st
                    .ceessions
                    .get(owner)
                    .is_some_and(|cs| cs.iter().any(|c| path_in_scope(path, &c.path)))
            {
                return false;
            }
            return true;
        }
        let Some(perms) = st.permissions.get(owner) else {
            return false;
        };
        if !diadosi_allows(perms, &self.cfg.server_id) {
            return false;
        }
        acl_grants(perms, owner, requester, path, need)
    }

    /// Read authorization for a replica using the `adeia` snapshot captured
    /// when it was pulled. This is what keeps an old public blog post (or any
    /// other already-signed public content) available after the owner moves to
    /// a new pyle or publishes a newer `adeia`; it never grants write/own.
    pub fn authorize_replica(&self, requester: &str, owner: &str, path: &str) -> bool {
        if requester == owner {
            return false;
        }
        let key = StoreState::key(owner, path);
        let snapshot = {
            let st = self.state.lock().unwrap();
            st.replica_acls.get(&key).cloned()
        };
        let Some(acl) = snapshot else {
            return false;
        };
        if !diadosi_allows(&acl, &self.cfg.server_id) {
            return false;
        }
        acl_grants(&acl, owner, requester, path, Access::Read)
    }

    /// Whether `pyle` may receive or serve this owner's content under the
    /// currently enforced ACL. Public identity documents are exempt: a peer
    /// must be able to fetch the adeia that contains the boundary itself.
    pub fn diadosi_allows(&self, owner: &str, pyle: &str, path: &str) -> bool {
        if is_public_identity_doc(path) {
            return true;
        }
        let st = self.state.lock().unwrap();
        st.permissions
            .get(owner)
            .or_else(|| {
                st.replica_acls
                    .iter()
                    .find(|(k, _)| k.starts_with(&format!("{owner}/")))
                    .map(|(_, v)| v)
            })
            .map(|acl| diadosi_allows(acl, pyle))
            .unwrap_or(true)
    }
}

/// Identity documents any peer may read so it can verify signatures and
/// enforce the ACL locally.
pub(crate) fn is_public_identity_doc(path: &str) -> bool {
    path == "prosopeion.hdap" || path == "adeia.hdap" || path == "diadosi.hdap"
}

/// Apply the `DIADOSI` boundary (when present) to a pyle. A missing or
/// malformed boundary means "no restriction"; a malformed one must not lock
/// every reader out of a valid ACL.
fn diadosi_allows(acl: &str, pyle: &str) -> bool {
    use hdap_core::protocol::DiadosiPolicy;
    let Ok(doc) = parse_doc(acl) else {
        return true;
    };
    match DiadosiPolicy::from_doc(&doc) {
        Some(policy) => policy.allows(pyle),
        None => true,
    }
}

/// Evaluate an `adeia` document against one `(owner, path, need)` request.
fn acl_grants(acl: &str, owner: &str, requester: &str, path: &str, need: Access) -> bool {
    let Ok(doc) = parse_doc(acl) else {
        return false;
    };
    let mut granted = false;
    for line in doc.body.values() {
        let Some((line_owner, scope, right)) = parse_perm_line(line) else {
            continue;
        };
        if line_owner != owner {
            continue;
        }
        let matched = match scope {
            Ok(Scope::All) => true,
            Ok(Scope::User(u)) => u == requester,
            Ok(Scope::Path(p)) => path.starts_with(p.trim_end_matches('/')),
            Err(_) => false,
        };
        if matched {
            let Some(access) = right_to_access(right) else {
                continue;
            };
            let meets = match need {
                Access::Read => matches!(access, Access::Read | Access::Write | Access::Own),
                Access::Write | Access::Own => matches!(access, Access::Write | Access::Own),
            };
            if meets {
                granted = true;
            }
        }
    }
    granted
}

fn path_in_scope(path: &str, scope: &str) -> bool {
    let scope = scope.trim_matches('/');
    if scope.is_empty() {
        return true;
    }
    path == scope || path.starts_with(&format!("{scope}/"))
}

/// Attach a durable store and load whatever it already holds.
impl Node {
    pub fn with_db(&mut self, db: Arc<crate::db::Db>) -> crate::db::DbResult<()> {
        self.state.lock().unwrap().whoami = self.cfg.server_id.clone();
        let restored = db.load()?;
        let mut st = self.state.lock().unwrap();
        match restored {
            Some(loaded) => {
                let mut loaded = loaded;
                loaded.whoami = self.cfg.server_id.clone();
                *st = loaded;
            }
            None => {
                let mut master_key = [0u8; 32];
                rand_core::OsRng.fill_bytes(&mut master_key);
                st.master_key = master_key;
                // A brand-new node needs its own signing key too. Leaving the
                // seed at the `State::default()` all-zero value would make
                // every fresh node sign `.hdap.pow`/`syngraphe` with the same
                // guessable key — the federation would be trivially forgeable.
                let mut seed = [0u8; 32];
                rand_core::OsRng.fill_bytes(&mut seed);
                st.node_sign_seed = seed;
            }
        }
        self.db = Some(db);
        Ok(())
    }

    /// Persist the current state to the attached database.
    pub fn persist(&self) -> crate::db::DbResult<()> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| crate::db::DbError::Corrupt("no database attached".to_string()))?;
        let st = self.state.lock().unwrap();
        db.flush(&st)
    }
}

/// Push a deletion tombstone to every peer that pulled `owner`'s namespace from
/// this node (and, in a cascade, to every peer that pulled it from the
/// receiver). Best-effort: an unreachable replica is skipped, not an error —
/// the local delete already succeeded. `skip` avoids echoing back to the peer
/// that just sent us the update. Returns how many peers accepted it.
pub(crate) fn notify_deletion(
    node: &Node,
    owner: &str,
    path: &str,
    content_hash: &str,
    deletion: &str,
    operation_id: &str,
    skip: Option<&str>,
) -> usize {
    let (node_id, sign_key, peers) = {
        let st = node.state.lock().unwrap();
        let ids = st.watchers.get(owner).cloned().unwrap_or_default();
        let peers: Vec<_> = ids
            .iter()
            .filter(|id| id.as_str() != node.cfg.server_id && Some(id.as_str()) != skip)
            .filter_map(|id| st.peers.get(id).cloned())
            .collect();
        (
            node.cfg.server_id.clone(),
            ed25519_dalek::SigningKey::from_bytes(&st.node_sign_seed),
            peers,
        )
    };
    let provenance = {
        let st = node.state.lock().unwrap();
        st.prytaneion.get(content_hash).map(|e| {
            (
                e.origin_user_pubkey.clone(),
                e.origin_path.clone(),
                e.sphragis.clone(),
            )
        })
    };
    let body = serde_json::json!({
        "owner": owner,
        "path": path,
        "content_hash": content_hash,
        "deletion": deletion,
        "operation_id": operation_id,
        "origin_user_pubkey": provenance.as_ref().map(|p| p.0.as_str()).unwrap_or(""),
        "origin_path": provenance.as_ref().map(|p| p.1.as_str()).unwrap_or(path),
        "sphragis": provenance.as_ref().map(|p| p.2.as_str()).unwrap_or(""),
    })
    .to_string();
    let mut notified = 0;
    for peer in peers {
        let Ok(client) = crate::fed_client::FedHttpClient::new(&peer.endpoint, peer.tls_pin) else {
            continue;
        };
        if let Ok(resp) =
            client.post_with_fed_auth("/homospondoi/prytaneion_update", &body, &node_id, &sign_key)
        {
            if (200..300).contains(&resp.status) {
                notified += 1;
            }
        }
    }
    notified
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::UserRecord;
    use std::collections::BTreeMap;

    fn post(path: &str) -> Request {
        Request {
            method: "POST".to_string(),
            path: path.to_string(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    /// Scenario B: a new `adeia` edition (or a house move) must not take an
    /// already public replica offline. The frozen snapshot keeps serving old
    /// public content; the current ACL governs new content only.
    #[test]
    fn an_old_public_replica_survives_a_new_private_adeia() {
        use hdap_core::protocol::{adeia_doc, Permission, Right, Scope};
        let (node, _) = Node::with_clock_and_now(
            Config {
                server_id: "pyle-b".into(),
                ..Config::default()
            },
            1000,
        );
        let owner = "jose_0123456789abcdef";
        let reader = "maria_0123456789abcdef";
        let path = "blog/post.md";
        let old_public = adeia_doc(
            owner,
            1,
            None,
            900,
            &[Permission {
                scope: Scope::All,
                right: Right::Read,
            }],
            None,
        )
        .render();
        let new_private = adeia_doc(owner, 2, Some("prev".into()), 1000, &[], None).render();
        {
            let mut st = node.state.lock().unwrap();
            st.permissions.insert(owner.to_string(), new_private);
            st.replica_acls
                .insert(StoreState::key(owner, path), old_public);
        }
        assert!(
            !node.authorize(reader, owner, path, Access::Read),
            "the new private adeia denies new reads"
        );
        assert!(
            node.authorize_replica(reader, owner, path),
            "the old public snapshot must keep serving the already replicated post"
        );
    }

    #[test]
    fn diadosi_is_a_replication_and_read_boundary() {
        use hdap_core::protocol::{
            adeia_doc_with_diadosi, DiadosiMode, DiadosiPolicy, Permission, Right, Scope,
        };
        let (node, _) = Node::with_clock_and_now(
            Config {
                server_id: "pyle-b".into(),
                ..Config::default()
            },
            1000,
        );
        let owner = "jose_0123456789abcdef";
        let reader = "maria_0123456789abcdef";
        let path = "blog/post.md";
        let allow_reader = [Permission {
            scope: Scope::All,
            right: Right::Read,
        }];

        let white = DiadosiPolicy {
            mode: DiadosiMode::White,
            pyles: vec!["pyle-a".into()],
        };
        let white_acl =
            adeia_doc_with_diadosi(owner, 1, None, 900, &allow_reader, None, Some(&white)).render();
        {
            let mut st = node.state.lock().unwrap();
            st.permissions.insert(owner.into(), white_acl);
        }
        assert!(
            !node.authorize(reader, owner, path, Access::Read),
            "a pyle outside a white list may not serve the content"
        );

        let black = DiadosiPolicy {
            mode: DiadosiMode::Black,
            pyles: vec!["pyle-a".into()],
        };
        let black_acl =
            adeia_doc_with_diadosi(owner, 1, None, 900, &allow_reader, None, Some(&black)).render();
        {
            let mut st = node.state.lock().unwrap();
            st.permissions.insert(owner.into(), black_acl.clone());
            st.replica_acls
                .insert(StoreState::key(owner, path), black_acl);
        }
        assert!(
            node.authorize(reader, owner, path, Access::Read),
            "pyle-b is not denied by a black list naming pyle-a"
        );
        assert!(
            node.authorize_replica(reader, owner, path),
            "the frozen snapshot applies the same boundary"
        );
    }

    /// The dispatcher must persist a mutating request *before* answering it
    /// (AME-35). This guards the regression where the `node.rs` split into
    /// modules dropped every `persist()` call, so accounts and uploads
    /// vanished on restart even though each request answered `200`.
    #[test]
    fn a_mutating_request_is_flushed_before_the_answer() {
        let dir = std::env::temp_dir().join(format!("hdap-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("n.db");

        {
            let db = std::sync::Arc::new(crate::db::Db::open(&path).unwrap());
            let mut node = Node::new(Config {
                server_id: "pyle-p".into(),
                ..Config::default()
            });
            node.with_db(db).unwrap();
            node.state.lock().unwrap().users.insert(
                "jose_0123456789abcdef".into(),
                UserRecord {
                    user_id: "jose_0123456789abcdef".into(),
                    nickname: "jose".into(),
                    suffix_hex: "0123456789abcdef".into(),
                    sign_pub_hex: "aa".repeat(32),
                    enc_pub_hex: "bb".repeat(32),
                    otp_anchor_hex: "cc".repeat(32),
                    otp_k: 1024,
                    created_at: 1_700_000_000,
                    home_pyle: "pyle-p".into(),
                },
            );
            // A read-only POST still proves the wiring: the flush runs, and the
            // fingerprint makes it cheap.
            let resp = node.handle(&post("/mochthos/proklesis"));
            assert_eq!(resp.status, 200);
        }

        let back = crate::db::Db::open(&path)
            .unwrap()
            .load()
            .unwrap()
            .expect("state persisted");
        assert!(
            back.users.contains_key("jose_0123456789abcdef"),
            "a registered user must survive a restart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
