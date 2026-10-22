//! Global server discovery.
//!
//! Every server that completes a handshake is a known pyle. Known pyles
//! exchange a small directory digest first and only ship the full directory
//! when the digests differ, so converged nodes stop trading lists. A newly
//! verified pyle is announced to a small deterministic fanout; announcements
//! carry an event id and a TTL, so a node forwards each event at most once and
//! the gossip cannot loop back through the mesh.
//!
//! Discovery is gated by `open_federation`: a node with a strict allowlist
//! will not auto-admit a pyle just because a trusted peer vouched for it.
//! Even in open mode a vouched pyle is only written to `State::peers` after a
//! successful callback handshake whose `node_id`, signing key and TLS pin
//! match the advertisement. A lying peer can therefore slow discovery down,
//! but cannot inject an identity it does not control.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hdap_core::crypto::sha256_hex;
use rand_core::RngCore;
use serde_json::{json, Value};

use crate::fed_client::FedHttpClient;
use crate::http::{Request, Response};
use crate::node::{json_err, require_json, Node};
use crate::store::PeerRecord;

/// Upper bound on the known-pyle list, so a malicious peer cannot make this
/// node dial unbounded candidates.
const MAX_KNOWN_PEERS: usize = 256;
/// Queue bound: discovery work is best-effort and must never grow without
/// limit while a peer floods announcements.
const MAX_JOBS: usize = 256;
const MAX_SEEN_EVENTS: usize = 4096;
const SEEN_TTL_SECS: u64 = 600;
const MAX_TTL: u8 = 8;
/// Immediate pushes go to a fixed small fanout; anti-entropy covers the rest.
const GOSSIP_FANOUT: usize = 2;
const ANTI_ENTROPY_EVERY_SECS: u64 = 60;
const HEALTH_EVERY_SECS: u64 = 300;
const LEDGER_EVERY_SECS: u64 = 30;
const DISCOVERY_TICK: Duration = Duration::from_secs(2);

/// A compact, dialable description of a pyle. This is exactly the information
/// needed to verify it; health and failure counters stay local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAdvert {
    pub node_id: String,
    pub endpoint: String,
    pub sign_pub_hex: String,
    pub tls_pin: Option<String>,
}

impl PeerAdvert {
    fn from_record(p: &PeerRecord) -> Option<Self> {
        let valid = !p.node_id.is_empty()
            && !p.endpoint.trim().is_empty()
            && p.endpoint.len() <= 255
            && hex::decode(&p.sign_pub_hex).map(|v| v.len()) == Ok(32);
        valid.then(|| PeerAdvert {
            node_id: p.node_id.clone(),
            endpoint: p.endpoint.clone(),
            sign_pub_hex: p.sign_pub_hex.clone(),
            tls_pin: p.tls_pin.clone(),
        })
    }

    fn parse(v: &Value) -> Option<Self> {
        let node_id = v.get("node_id")?.as_str()?.to_string();
        let endpoint = v.get("endpoint")?.as_str()?.to_string();
        let sign_pub_hex = v.get("sign_pub_hex")?.as_str()?.to_string();
        let tls_pin = v
            .get("tls_pin")
            .and_then(|p| p.as_str())
            .filter(|p| !p.is_empty())
            .map(String::from);
        if node_id.is_empty()
            || node_id.len() > 128
            || endpoint.is_empty()
            || endpoint.len() > 255
            || hex::decode(&sign_pub_hex).map(|v| v.len()) != Ok(32)
        {
            return None;
        }
        Some(PeerAdvert {
            node_id,
            endpoint,
            sign_pub_hex,
            tls_pin,
        })
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({
            "node_id": self.node_id,
            "endpoint": self.endpoint,
            "sign_pub_hex": self.sign_pub_hex,
            "tls_pin": self.tls_pin,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeerHealth {
    pub last_seen: u64,
    pub last_checked: u64,
    pub failures: u32,
    pub verified: bool,
}

enum Job {
    /// Dial a candidate, confirm its identity, then (for a fresh join) gossip.
    Verify {
        advert: PeerAdvert,
        event_id: String,
        ttl: u8,
        announce: bool,
    },
    /// Pull a peer's directory digest/list.
    Exchange { peer_id: String },
    /// Cheap liveness/identity check for an already-known peer.
    Health { peer_id: String },
    /// Digest-first exchange of the global `prytaneion` ledger.
    Ledger { peer_id: String },
}

/// Volatile discovery state. The known list itself lives in `State::peers` and
/// is persisted; queues, dedup ids and health counters are recomputed after a
/// restart, so a crash cannot leave stale gossip work behind.
pub struct DiscoveryModule {
    jobs: Mutex<VecDeque<Job>>,
    health: Mutex<BTreeMap<String, PeerHealth>>,
    seen: Mutex<BTreeMap<String, u64>>,
    cursor: AtomicU64,
    last_anti_entropy: AtomicU64,
    last_health: AtomicU64,
    last_ledger: AtomicU64,
}

impl Default for DiscoveryModule {
    fn default() -> Self {
        Self {
            jobs: Mutex::new(VecDeque::new()),
            health: Mutex::new(BTreeMap::new()),
            seen: Mutex::new(BTreeMap::new()),
            cursor: AtomicU64::new(0),
            last_anti_entropy: AtomicU64::new(0),
            last_health: AtomicU64::new(0),
            last_ledger: AtomicU64::new(0),
        }
    }
}

impl DiscoveryModule {
    fn enqueue(&self, job: Job) {
        let mut jobs = self.jobs.lock().unwrap();
        if jobs.len() < MAX_JOBS {
            jobs.push_back(job);
        }
    }

    pub(crate) fn enqueue_verify(
        &self,
        advert: PeerAdvert,
        event_id: String,
        ttl: u8,
        announce: bool,
    ) {
        self.enqueue(Job::Verify {
            advert,
            event_id,
            ttl: ttl.min(MAX_TTL),
            announce,
        });
    }

    pub(crate) fn enqueue_exchange(&self, peer_id: String) {
        // Collapse duplicates: anti-entropy and a fresh handshake often point
        // at the same peer in the same tick.
        let mut jobs = self.jobs.lock().unwrap();
        let already = jobs
            .iter()
            .any(|j| matches!(j, Job::Exchange { peer_id: p } if p == &peer_id));
        if !already && jobs.len() < MAX_JOBS {
            jobs.push_back(Job::Exchange { peer_id });
        }
    }

    pub(crate) fn enqueue_ledger(&self, peer_id: String) {
        let mut jobs = self.jobs.lock().unwrap();
        let already = jobs
            .iter()
            .any(|j| matches!(j, Job::Ledger { peer_id: p } if p == &peer_id));
        if !already && jobs.len() < MAX_JOBS {
            jobs.push_back(Job::Ledger { peer_id });
        }
    }

    fn enqueue_health(&self, peer_id: String) {
        let mut jobs = self.jobs.lock().unwrap();
        let already = jobs
            .iter()
            .any(|j| matches!(j, Job::Health { peer_id: p } if p == &peer_id));
        if !already && jobs.len() < MAX_JOBS {
            jobs.push_back(Job::Health { peer_id });
        }
    }

    /// Record an inbound authenticated contact. It proves the peer's signing
    /// key is live, but **not** that its advertised endpoint is dialable: the
    /// callback `Verify` job is the only thing that may mark it verified or
    /// clear endpoint failures. An existing verified flag is preserved.
    pub(crate) fn record_seen(&self, node_id: &str, now: u64) {
        let mut health = self.health.lock().unwrap();
        health.entry(node_id.to_string()).or_default().last_seen = now;
    }

    fn record_check(&self, node_id: &str, now: u64, ok: bool) {
        let mut health = self.health.lock().unwrap();
        let h = health.entry(node_id.to_string()).or_default();
        h.last_checked = now;
        if ok {
            h.last_seen = now;
            h.verified = true;
            h.failures = 0;
        } else {
            h.verified = false;
            h.failures = h.failures.saturating_add(1);
        }
    }

    fn seen_before(&self, event_id: &str, now: u64) -> bool {
        let mut seen = self.seen.lock().unwrap();
        let cutoff = now.saturating_sub(SEEN_TTL_SECS);
        seen.retain(|_, ts| *ts >= cutoff);
        if seen.contains_key(event_id) {
            return true;
        }
        if seen.len() >= MAX_SEEN_EVENTS {
            if let Some(oldest) = seen
                .iter()
                .min_by_key(|(_, ts)| **ts)
                .map(|(k, _)| k.clone())
            {
                seen.remove(&oldest);
            }
        }
        seen.insert(event_id.to_string(), now);
        false
    }

    /// Local health snapshot, useful for diagnostics and tests.
    pub fn health_snapshot(&self) -> BTreeMap<String, PeerHealth> {
        self.health.lock().unwrap().clone()
    }

    /// Expose the seen-set size for diagnostics/tests.
    pub fn seen_len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// Queue an exchange with every known pyle. Used by tests and by an
    /// operator-triggered refresh; the background loop uses a rotating subset.
    pub fn refresh(&self, node: &Node) {
        for p in adverts(node) {
            self.enqueue_exchange(p.node_id);
        }
    }

    /// Process one bounded batch and, on the configured cadence, schedule
    /// anti-entropy and a liveness check. `now` is passed in so tests can use a
    /// fixed clock without spawning the background thread.
    pub(crate) fn run_tick(&self, node: &Node, now: u64) {
        let mut modified = false;
        for _ in 0..8 {
            let job = self.jobs.lock().unwrap().pop_front();
            let Some(job) = job else { break };
            match job {
                Job::Verify {
                    advert,
                    event_id,
                    ttl,
                    announce,
                } => {
                    if verify_candidate(node, &advert, now) {
                        self.record_check(&advert.node_id, now, true);
                        if announce {
                            gossip(node, &advert, &event_id, ttl, Some(&advert.node_id));
                        }
                        modified = true;
                    } else {
                        self.record_check(&advert.node_id, now, false);
                    }
                }
                Job::Exchange { peer_id } => {
                    if exchange_directory(node, &peer_id, now) {
                        self.record_check(&peer_id, now, true);
                    } else {
                        self.record_check(&peer_id, now, false);
                    }
                }
                Job::Health { peer_id } => {
                    let ok = health_check(node, &peer_id, now);
                    self.record_check(&peer_id, now, ok);
                }
                Job::Ledger { peer_id } => {
                    let peer = {
                        let st = node.state.lock().unwrap();
                        st.peers.get(&peer_id).cloned()
                    };
                    if let Some(peer) = peer {
                        if let Ok(n) = crate::node::ledger::pull_from_peer(node, &peer) {
                            if n > 0 {
                                modified = true;
                            }
                        }
                    }
                }
            }
        }

        let last_ae = self.last_anti_entropy.load(Ordering::Relaxed);
        if now.saturating_sub(last_ae) >= ANTI_ENTROPY_EVERY_SECS {
            self.last_anti_entropy.store(now, Ordering::Relaxed);
            self.schedule_anti_entropy(node);
        }
        let last_health = self.last_health.load(Ordering::Relaxed);
        if now.saturating_sub(last_health) >= HEALTH_EVERY_SECS {
            self.last_health.store(now, Ordering::Relaxed);
            if let Some(peer) = self.pick_peer(node) {
                self.enqueue_health(peer.node_id);
            }
        }
        let last_ledger = self.last_ledger.load(Ordering::Relaxed);
        if now.saturating_sub(last_ledger) >= LEDGER_EVERY_SECS {
            self.last_ledger.store(now, Ordering::Relaxed);
            self.schedule_ledger(node);
        }

        if modified && node.db.is_some() {
            let _ = node.persist();
        }
    }

    fn schedule_anti_entropy(&self, node: &Node) {
        let peers = adverts(node);
        if peers.is_empty() {
            return;
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) as usize % peers.len();
        let take = GOSSIP_FANOUT.min(peers.len());
        for i in 0..take {
            self.enqueue_exchange(peers[(start + i) % peers.len()].node_id.clone());
        }
    }

    fn schedule_ledger(&self, node: &Node) {
        let peers = adverts(node);
        if peers.is_empty() {
            return;
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) as usize % peers.len();
        let take = GOSSIP_FANOUT.min(peers.len());
        for i in 0..take {
            self.enqueue_ledger(peers[(start + i) % peers.len()].node_id.clone());
        }
    }

    fn pick_peer(&self, node: &Node) -> Option<PeerAdvert> {
        let peers = adverts(node);
        if peers.is_empty() {
            return None;
        }
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) as usize % peers.len();
        Some(peers[idx].clone())
    }

    /// `GET /homospondoi/directory?digest=<hex>`.
    ///
    /// Digest-first is the request-saving part: a converged peer gets one tiny
    /// response instead of the whole list, and no list at all if it already
    /// matches.
    pub(crate) fn handle_directory(&self, node: &Node, req: &Request) -> Response {
        let digest = directory_digest(node);
        let peers = adverts(node);
        let want = req.query.get("digest").map(String::as_str).unwrap_or("");
        let body = if !want.is_empty() && want == digest {
            json!({ "digest": digest })
        } else {
            json!({
                "digest": digest,
                "peers": peers.iter().map(PeerAdvert::to_json).collect::<Vec<_>>(),
            })
        };
        Response::json(200, body.to_string())
    }

    /// `GET /bubble` — client-facing view of the known-pyle bubble.
    ///
    /// Tiers are advisory, not an authority: `core` means a verified callback
    /// with no failures, `extended` means a dialable peer we have not fully
    /// confirmed yet, and `untrusted` means repeated failures or no endpoint.
    pub(crate) fn handle_bubble(&self, node: &Node, req: &Request) -> Response {
        if node.session_user(req).is_none() {
            return Response::json(401, json_err("unauthorized"));
        }
        let health = self.health_snapshot();
        let mut core = 0usize;
        let mut extended = 0usize;
        let mut untrusted = 0usize;
        let mut peers = Vec::new();
        {
            let st = node.state.lock().unwrap();
            for peer in st.peers.values() {
                if peer.node_id == node.cfg.server_id {
                    continue;
                }
                let h = health.get(&peer.node_id);
                let failures = h.map(|h| h.failures).unwrap_or(0);
                let verified = h.map(|h| h.verified).unwrap_or(false);
                let tier = if peer.endpoint.trim().is_empty() || failures >= 3 {
                    untrusted += 1;
                    "untrusted"
                } else if verified && failures == 0 {
                    core += 1;
                    "core"
                } else {
                    extended += 1;
                    "extended"
                };
                peers.push(json!({
                    "node_id": peer.node_id,
                    "endpoint": peer.endpoint,
                    "tier": tier,
                    "verified": verified,
                    "failures": failures,
                    "last_seen": h.map(|h| h.last_seen).unwrap_or(0),
                    "last_checked": h.map(|h| h.last_checked).unwrap_or(0),
                    "tls_pin": peer.tls_pin,
                }));
            }
        }
        peers.sort_by(|a, b| {
            let rank = |t: &str| match t {
                "core" => 0,
                "extended" => 1,
                _ => 2,
            };
            rank(a["tier"].as_str().unwrap_or(""))
                .cmp(&rank(b["tier"].as_str().unwrap_or("")))
                .then_with(|| a["node_id"].as_str().cmp(&b["node_id"].as_str()))
        });
        Response::json(
            200,
            json!({
                "counts": {
                    "total": core + extended + untrusted,
                    "core": core,
                    "extended": extended,
                    "untrusted": untrusted,
                },
                "peers": peers,
            })
            .to_string(),
        )
    }

    /// `POST /homospondoi/announce`.
    pub(crate) fn handle_announce(&self, node: &Node, req: &Request, from: &str) -> Response {
        if !node.cfg.open_federation {
            return Response::json(403, json_err("peer discovery is disabled"));
        }
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let event_id = body.get("event_id").and_then(|v| v.as_str()).unwrap_or("");
        let ttl = body
            .get("ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(3)
            .min(MAX_TTL as u64) as u8;
        let Some(advert) = body.get("peer").and_then(PeerAdvert::parse) else {
            return Response::json(400, json_err("invalid peer advert"));
        };
        if event_id.is_empty() || event_id.len() > 128 {
            return Response::json(400, json_err("event_id required"));
        }
        if advert.node_id == node.cfg.server_id {
            return Response::json(400, json_err("cannot announce this node"));
        }
        if advert.node_id == from {
            // The caller is already known; re-announcing yourself is a no-op.
            return Response::json(200, json!({ "queued": false, "known": true }).to_string());
        }
        {
            let st = node.state.lock().unwrap();
            if let Some(existing) = st.peers.get(&advert.node_id) {
                if existing.sign_pub_hex != advert.sign_pub_hex {
                    return Response::json(409, json_err("peer id already uses another key"));
                }
                return Response::json(200, json!({ "queued": false, "known": true }).to_string());
            }
            if st.peers.len() >= MAX_KNOWN_PEERS {
                return Response::json(429, json_err("known-peer limit reached"));
            }
        }
        let now = node.now();
        if self.seen_before(event_id, now) {
            return Response::json(
                200,
                json!({ "queued": false, "duplicate": true }).to_string(),
            );
        }
        self.enqueue_verify(advert.clone(), event_id.to_string(), ttl, true);
        Response::json(
            202,
            json!({ "queued": true, "peer": advert.node_id }).to_string(),
        )
    }
}

/// Spawn the periodic discovery worker. `Node` is shared behind an `Arc` in
/// `main`, so the worker can keep converging while the HTTP loop blocks.
pub fn run_forever(node: Arc<Node>) {
    loop {
        node.discovery.run_tick(&node, node.now());
        std::thread::sleep(DISCOVERY_TICK);
    }
}

/// Canonical digest over the dialable directory. Order is `BTreeMap` order, so
/// every node computes the same value for the same set.
pub fn directory_digest(node: &Node) -> String {
    let mut input = Vec::new();
    for p in adverts(node) {
        input.extend_from_slice(p.node_id.as_bytes());
        input.push(0);
        input.extend_from_slice(p.endpoint.as_bytes());
        input.push(0);
        input.extend_from_slice(p.sign_pub_hex.as_bytes());
        input.push(0);
        input.extend_from_slice(p.tls_pin.as_deref().unwrap_or("").as_bytes());
        input.push(b'\n');
    }
    sha256_hex(&input)
}

pub(crate) fn adverts(node: &Node) -> Vec<PeerAdvert> {
    let st = node.state.lock().unwrap();
    st.peers
        .values()
        .filter(|p| p.node_id != node.cfg.server_id)
        .filter_map(PeerAdvert::from_record)
        .collect()
}

/// Our own dialable address. A provisioned, non-endpoint-addressed id cannot
/// be reached by derivation, but `--advertise` (or the listen address in
/// `main`) fills this in.
pub(crate) fn own_endpoint(node: &Node) -> String {
    node.advertise_endpoint
        .clone()
        .filter(|e| !e.trim().is_empty())
        .or_else(|| crate::pyle::endpoint_from_id(&node.cfg.server_id))
        .unwrap_or_default()
}

pub(crate) fn own_sign_pub(node: &Node) -> String {
    let seed = node.state.lock().unwrap().node_sign_seed;
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    )
}

pub(crate) fn handshake_body(node: &Node) -> String {
    json!({
        "node_id": node.cfg.server_id,
        "pubkey": own_sign_pub(node),
        "endpoint": own_endpoint(node),
        "tls_pin": node.tls_pin,
        "directory_digest": directory_digest(node),
        "ledger_digest": crate::node::ledger::digest(
            &node.state.lock().unwrap().prytaneion
        ),
    })
    .to_string()
}

/// Ingest a directory learned from `origin`. Nothing is trusted here: each
/// candidate is queued for a callback handshake and only accepted if that
/// handshake matches its advertised identity.
pub(crate) fn ingest_directory(
    node: &Node,
    peers: &[Value],
    origin: &str,
    base_event: &str,
    ttl: u8,
) {
    if !node.cfg.open_federation {
        return;
    }
    let now = node.now();
    for value in peers {
        let Some(advert) = PeerAdvert::parse(value) else {
            continue;
        };
        if advert.node_id == node.cfg.server_id || advert.node_id == origin {
            continue;
        }
        let known = node
            .state
            .lock()
            .unwrap()
            .peers
            .get(&advert.node_id)
            .map(|p| p.sign_pub_hex == advert.sign_pub_hex)
            .unwrap_or(false);
        if known {
            continue;
        }
        let event_id = format!("{base_event}:{}", advert.node_id);
        if node.discovery.seen_before(&event_id, now) {
            continue;
        }
        node.discovery.enqueue_verify(advert, event_id, ttl, true);
    }
}

fn verify_candidate(node: &Node, advert: &PeerAdvert, now: u64) -> bool {
    if advert.node_id == node.cfg.server_id {
        return false;
    }
    let Ok(client) = FedHttpClient::new(&advert.endpoint, advert.tls_pin.clone()) else {
        return false;
    };
    let mut client = client;
    client.connect_timeout = Duration::from_secs(3);
    client.io_timeout = Duration::from_secs(6);
    let body = handshake_body(node);
    let Ok(resp) = client.post_json("/homospondoi/handshake", &body) else {
        return false;
    };
    if !(200..300).contains(&resp.status) {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&resp.body) else {
        return false;
    };
    if value
        .get("server_id")
        .and_then(|v| v.as_str())
        .is_some_and(|id| id != advert.node_id)
    {
        return false;
    }
    let Some(pubkey) = value.get("node_sign_pub").and_then(|v| v.as_str()) else {
        return false;
    };
    if pubkey != advert.sign_pub_hex {
        return false;
    }
    if let (Some(expected), Some(actual)) = (
        advert.tls_pin.as_deref(),
        value.get("tls_pin").and_then(|v| v.as_str()),
    ) {
        if expected != actual {
            return false;
        }
    }

    {
        let mut st = node.state.lock().unwrap();
        match st.peers.get(&advert.node_id) {
            Some(existing) if existing.sign_pub_hex != advert.sign_pub_hex => return false,
            Some(_) => {}
            None => {
                if st.peers.len() >= MAX_KNOWN_PEERS {
                    return false;
                }
                st.peers.insert(
                    advert.node_id.clone(),
                    PeerRecord {
                        node_id: advert.node_id.clone(),
                        sign_pub_hex: advert.sign_pub_hex.clone(),
                        endpoint: advert.endpoint.clone(),
                        tls_pin: advert.tls_pin.clone(),
                    },
                );
            }
        }
    }
    node.discovery.record_check(&advert.node_id, now, true);
    node.discovery.enqueue_ledger(advert.node_id.clone());
    if let Some(peers) = value.get("directory").and_then(|v| v.as_array()) {
        let base = format!("handshake:{}:{now}", advert.node_id);
        ingest_directory(node, peers, &advert.node_id, &base, 3);
    }
    true
}

fn exchange_directory(node: &Node, peer_id: &str, now: u64) -> bool {
    let peer = {
        let st = node.state.lock().unwrap();
        st.peers.get(peer_id).cloned()
    };
    let Some(peer) = peer else { return false };
    let Some(advert) = PeerAdvert::from_record(&peer) else {
        return false;
    };
    let Ok(client) = FedHttpClient::new(&advert.endpoint, advert.tls_pin.clone()) else {
        return false;
    };
    let mut client = client;
    client.connect_timeout = Duration::from_secs(3);
    client.io_timeout = Duration::from_secs(6);
    let digest = directory_digest(node);
    let path = format!("/homospondoi/directory?digest={digest}");
    let seed = node.state.lock().unwrap().node_sign_seed;
    let sign_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let Ok(resp) = client.get_with_fed_auth(&path, &node.cfg.server_id, &sign_key, None) else {
        return false;
    };
    if !(200..300).contains(&resp.status) {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&resp.body) else {
        return false;
    };
    if let Some(peers) = value.get("peers").and_then(|v| v.as_array()) {
        let their_digest = value
            .get("digest")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let base = format!("dir:{peer_id}:{their_digest}:{now}");
        ingest_directory(node, peers, peer_id, &base, 3);
    }
    true
}

fn health_check(node: &Node, peer_id: &str, _now: u64) -> bool {
    let peer = {
        let st = node.state.lock().unwrap();
        st.peers.get(peer_id).cloned()
    };
    let Some(peer) = peer else { return false };
    let Ok(client) = FedHttpClient::new(&peer.endpoint, peer.tls_pin.clone()) else {
        return false;
    };
    let mut client = client;
    client.connect_timeout = Duration::from_secs(3);
    client.io_timeout = Duration::from_secs(6);
    let Ok(resp) = client.get_json("/health") else {
        return false;
    };
    if !(200..300).contains(&resp.status) {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&resp.body) else {
        return false;
    };
    value.get("server_id").and_then(|v| v.as_str()) == Some(peer.node_id.as_str())
        && value.get("node_sign_pub").and_then(|v| v.as_str()) == Some(peer.sign_pub_hex.as_str())
}

/// Push one announcement to a deterministic fanout. Sorting by
/// `hash(event_id, peer_id)` spreads the same event over different neighbours
/// without a central coordinator; the event id dedup makes the overlap cheap.
fn gossip(node: &Node, advert: &PeerAdvert, event_id: &str, ttl: u8, skip: Option<&str>) {
    if ttl == 0 {
        return;
    }
    let mut peers: Vec<PeerAdvert> = adverts(node)
        .into_iter()
        .filter(|p| p.node_id != advert.node_id)
        .filter(|p| Some(p.node_id.as_str()) != skip)
        .collect();
    peers.sort_by_key(|p| sha256_hex(format!("{event_id}:{}", p.node_id).as_bytes()));
    let body = json!({
        "event_id": event_id,
        "ttl": ttl.saturating_sub(1),
        "peer": advert.to_json(),
    })
    .to_string();
    let seed = node.state.lock().unwrap().node_sign_seed;
    let sign_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    for peer in peers.into_iter().take(GOSSIP_FANOUT) {
        let Ok(client) = FedHttpClient::new(&peer.endpoint, peer.tls_pin.clone()) else {
            continue;
        };
        let mut client = client;
        client.connect_timeout = Duration::from_secs(3);
        client.io_timeout = Duration::from_secs(6);
        let _ = client.post_with_fed_auth(
            "/homospondoi/announce",
            &body,
            &node.cfg.server_id,
            &sign_key,
        );
    }
}

/// A fresh event id. Not a cryptographic nonce: it only has to be unique
/// enough that two joins do not collapse into one gossip event.
pub(crate) fn new_event_id(node: &Node, peer_id: &str) -> String {
    let mut raw = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut raw);
    format!(
        "join:{}:{}:{}",
        node.cfg.server_id,
        peer_id,
        hex::encode(raw)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::http;
    use std::collections::BTreeSet;
    use std::net::TcpListener;
    use std::thread;

    fn spawn(open: bool) -> (Arc<Node>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let endpoint = format!("127.0.0.1:{port}");
        let id = crate::pyle::id_from_endpoint(&endpoint);
        let cfg = Config {
            server_id: id.clone(),
            open_federation: open,
            rate_limit_per_sec: 0,
            require_entry_pow: false,
            require_content_signature: false,
            ..Config::default()
        };
        let node = Arc::new(Node::new(cfg));
        let handle = Arc::clone(&node);
        thread::spawn(move || {
            let _ = http::serve(listener, 4 * 1024 * 1024, move |req| handle.handle(&req));
        });
        (node, endpoint)
    }

    fn advert(node: &Node, endpoint: &str) -> PeerAdvert {
        PeerAdvert {
            node_id: node.cfg.server_id.clone(),
            endpoint: endpoint.to_string(),
            sign_pub_hex: own_sign_pub(node),
            tls_pin: None,
        }
    }

    fn add_known(node: &Node, peer: &PeerAdvert) {
        node.state.lock().unwrap().peers.insert(
            peer.node_id.clone(),
            PeerRecord {
                node_id: peer.node_id.clone(),
                sign_pub_hex: peer.sign_pub_hex.clone(),
                endpoint: peer.endpoint.clone(),
                tls_pin: peer.tls_pin.clone(),
            },
        );
    }

    fn drain(node: &Node) {
        for _ in 0..32 {
            node.discovery.run_tick(node, 1000);
            if node.discovery.jobs.lock().unwrap().is_empty() {
                break;
            }
        }
    }

    fn known(node: &Node) -> BTreeSet<String> {
        node.state.lock().unwrap().peers.keys().cloned().collect()
    }

    /// A knows B, B knows C. A must verify C through B's directory, and all
    /// three must end up with the same known set without any node polling the
    /// whole mesh.
    #[test]
    fn a_three_node_bubble_converges() {
        let (a, ap) = spawn(true);
        let (b, bp) = spawn(true);
        let (c, cp) = spawn(true);
        let (aa, ba, ca) = (advert(&a, &ap), advert(&b, &bp), advert(&c, &cp));
        add_known(&a, &ba);
        add_known(&b, &aa);
        add_known(&b, &ca);
        add_known(&c, &ba);

        // A pulls B's directory, learns C and verifies it; the handshake also
        // teaches C about A.
        a.discovery.enqueue_exchange(b.cfg.server_id.clone());
        drain(&a);
        drain(&b);
        drain(&c);
        drain(&a);

        let ab = BTreeSet::from([b.cfg.server_id.clone(), c.cfg.server_id.clone()]);
        let ba = BTreeSet::from([a.cfg.server_id.clone(), c.cfg.server_id.clone()]);
        let cb = BTreeSet::from([a.cfg.server_id.clone(), b.cfg.server_id.clone()]);
        assert_eq!(known(&a), ab);
        assert_eq!(known(&b), ba);
        assert_eq!(known(&c), cb);
        assert!(a
            .discovery
            .health_snapshot()
            .get(&c.cfg.server_id)
            .is_some_and(|h| h.verified));
    }

    #[test]
    fn inbound_contact_does_not_fake_a_verified_endpoint() {
        let (node, _endpoint) = spawn(true);
        node.discovery.record_seen("pyle-inbound", 100);
        {
            let health = node.discovery.health_snapshot();
            let h = &health["pyle-inbound"];
            assert_eq!(h.last_seen, 100);
            assert!(!h.verified, "only a callback may verify an endpoint");
            assert_eq!(h.last_checked, 0);
        }
        // A previously verified peer stays verified on later inbound contact.
        node.discovery.record_check("pyle-inbound", 200, true);
        node.discovery.record_seen("pyle-inbound", 300);
        let health = node.discovery.health_snapshot();
        assert!(health["pyle-inbound"].verified);
        assert_eq!(health["pyle-inbound"].last_checked, 200);
    }

    /// `/bubble` classifies known pyles into the three advisory tiers the GUI
    /// shows: core (verified, no failures), extended (dialable but unconfirmed)
    /// and untrusted (repeated failures or no endpoint).
    #[test]
    fn bubble_counts_core_extended_and_untrusted() {
        let (node, _endpoint) = spawn(true);
        let record = |id: &str, endpoint: &str| PeerRecord {
            node_id: id.to_string(),
            sign_pub_hex: "aa".repeat(32),
            endpoint: endpoint.to_string(),
            tls_pin: None,
        };
        {
            let mut st = node.state.lock().unwrap();
            st.peers
                .insert("pyle-core".into(), record("pyle-core", "127.0.0.1:9001"));
            st.peers
                .insert("pyle-ext".into(), record("pyle-ext", "127.0.0.1:9002"));
            st.peers.insert("pyle-bad".into(), record("pyle-bad", ""));
            st.sessions.insert(
                "tok".into(),
                crate::store::Session {
                    user_id: "jose_0123456789abcdef".into(),
                    exp: u64::MAX,
                },
            );
        }
        node.discovery.record_check("pyle-core", 1000, true);
        node.discovery.record_check("pyle-bad", 1000, false);
        node.discovery.record_check("pyle-bad", 1000, false);
        node.discovery.record_check("pyle-bad", 1000, false);
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("x-hdap-token".to_string(), "tok".to_string());
        let req = crate::http::Request {
            method: "GET".into(),
            path: "/bubble".into(),
            query: Default::default(),
            headers,
            body: Vec::new(),
        };
        let resp = node.discovery.handle_bubble(&node, &req);
        assert_eq!(resp.status, 200);
        let v: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["counts"]["total"], 3);
        assert_eq!(v["counts"]["core"], 1);
        assert_eq!(v["counts"]["extended"], 1);
        assert_eq!(v["counts"]["untrusted"], 1);
    }

    /// A vouched advert whose signing key does not match the real endpoint is
    /// rejected: the callback handshake is the vote, not the announcer's word.
    #[test]
    fn a_spoofed_advert_is_not_added() {
        let (a, _ap) = spawn(true);
        let (b, bp) = spawn(true);
        let mut fake = advert(&b, &bp);
        fake.node_id = "pyle-impostor".to_string();
        fake.sign_pub_hex = "00".repeat(32);
        add_known(&a, &advert(&b, &bp));

        a.discovery
            .enqueue_verify(fake.clone(), "evt-spoof".into(), 3, false);
        drain(&a);
        assert!(!known(&a).contains(&fake.node_id));
        assert!(a
            .discovery
            .health_snapshot()
            .get(&fake.node_id)
            .is_some_and(|h| h.failures > 0 && !h.verified));
    }

    #[test]
    fn directory_answers_digest_only_when_equal() {
        let (a, ap) = spawn(true);
        let (b, bp) = spawn(true);
        add_known(&a, &advert(&b, &bp));
        add_known(&b, &advert(&a, &ap));
        let digest = directory_digest(&a);
        let req = Request {
            method: "GET".into(),
            path: "/homospondoi/directory".into(),
            query: BTreeMap::from([("digest".to_string(), digest.clone())]),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        let resp = a.discovery.handle_directory(&a, &req);
        assert_eq!(resp.status, 200);
        let body: Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["digest"], digest);
        assert!(body.get("peers").is_none());
    }
}
