//! Federation-wide provenance ledger (`prytaneion`).
//!
//! Every pyle keeps a local `content_hash -> PrytaneionEntry` map. This module
//! makes that map *global*: peers exchange digests first and only ship entries
//! when the two sides differ. Merging is idempotent and commutative, so a
//! bubble converges no matter which peer each node happens to talk to.
//!
//! The entry itself carries everything needed to verify a replicated blob
//! after its origin disappears: the origin pyle/user, the author's signing
//! public key and the author's signature (`sphragis`) over the plaintext.

use std::collections::BTreeMap;

use hdap_core::crypto::sha256_hex;
use serde_json::Value;

use crate::fed_client::FedHttpClient;
use crate::store::{PrytaneionEntry, State};

/// Hard cap per peer exchange so a malicious peer cannot make us allocate an
/// unbounded body. Entries are small; 4096 covers a large bubble.
pub const MAX_LEDGER_ENTRIES: usize = 4096;
/// Replicas/deletions are history, not a set of unbounded length.
const MAX_HISTORY: usize = 4096;

/// Deterministic serialization of one entry. Replicas and deletions are sorted
/// because two nodes may learn them in different orders; the digest must not
/// depend on that order.
fn canonical(entry: &PrytaneionEntry) -> String {
    let mut replicas = entry.replicas.clone();
    replicas.sort();
    replicas.dedup();
    let mut deletions = entry.deletions.clone();
    deletions.sort();
    deletions.dedup();
    serde_json::json!({
        "content_hash": entry.content_hash,
        "origin_server": entry.origin_server,
        "origin_user": entry.origin_user,
        "origin_user_pubkey": entry.origin_user_pubkey,
        "origin_path": entry.origin_path,
        "sphragis": entry.sphragis,
        "replicas": replicas,
        "deletions": deletions,
        "created_at": entry.created_at,
    })
    .to_string()
}

/// SHA-256 over the canonical, hash-sorted ledger. O(entries) on both sides,
/// but the exchange itself is one request and usually returns no list at all.
pub fn digest(entries: &BTreeMap<String, PrytaneionEntry>) -> String {
    let mut input = Vec::new();
    for (hash, entry) in entries {
        input.extend_from_slice(hash.as_bytes());
        input.push(0);
        input.extend_from_slice(canonical(entry).as_bytes());
        input.push(b'\n');
    }
    sha256_hex(&input)
}

/// Snapshot in stable order, capped for the wire.
pub fn snapshot(entries: &BTreeMap<String, PrytaneionEntry>) -> Vec<PrytaneionEntry> {
    entries.values().take(MAX_LEDGER_ENTRIES).cloned().collect()
}

pub fn entry_to_json(entry: &PrytaneionEntry) -> Value {
    serde_json::json!({
        "content_hash": entry.content_hash,
        "origin_server": entry.origin_server,
        "origin_user": entry.origin_user,
        "origin_user_pubkey": entry.origin_user_pubkey,
        "origin_path": entry.origin_path,
        "sphragis": entry.sphragis,
        "replicas": entry.replicas,
        "deletions": entry.deletions,
        "created_at": entry.created_at,
    })
}

pub fn entry_from_json(value: &Value) -> Option<PrytaneionEntry> {
    let hash = value.get("content_hash")?.as_str()?.to_string();
    if hash.is_empty() || hash.len() > 128 {
        return None;
    }
    let strings = |key: &str| -> Vec<String> {
        value
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .take(MAX_HISTORY)
                    .collect()
            })
            .unwrap_or_default()
    };
    Some(PrytaneionEntry {
        content_hash: hash,
        origin_server: value
            .get("origin_server")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        origin_user: value
            .get("origin_user")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        origin_user_pubkey: value
            .get("origin_user_pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        origin_path: value
            .get("origin_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        sphragis: value
            .get("sphragis")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        replicas: strings("replicas"),
        deletions: strings("deletions"),
        created_at: value
            .get("created_at")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    })
}

/// Merge one remote entry into the local ledger. Returns `true` when anything
/// changed. Origin provenance is only filled when the local copy is missing it;
/// replicas and deletions are unioned. A conflicting non-empty origin is kept
/// (first writer wins) so a peer cannot silently re-attribute a hash.
pub fn merge(st: &mut State, incoming: &PrytaneionEntry) -> bool {
    if incoming.content_hash.is_empty() {
        return false;
    }
    let Some(entry) = st.prytaneion.get_mut(&incoming.content_hash) else {
        if st.prytaneion.len() >= MAX_LEDGER_ENTRIES {
            return false;
        }
        st.prytaneion
            .insert(incoming.content_hash.clone(), incoming.clone());
        return true;
    };
    let mut changed = false;
    if entry.origin_server.is_empty() && !incoming.origin_server.is_empty() {
        entry.origin_server = incoming.origin_server.clone();
        changed = true;
    }
    if entry.origin_user.is_empty() && !incoming.origin_user.is_empty() {
        entry.origin_user = incoming.origin_user.clone();
        changed = true;
    }
    if entry.origin_user_pubkey.is_empty() && !incoming.origin_user_pubkey.is_empty() {
        entry.origin_user_pubkey = incoming.origin_user_pubkey.clone();
        changed = true;
    }
    if entry.origin_path.is_empty() && !incoming.origin_path.is_empty() {
        entry.origin_path = incoming.origin_path.clone();
        changed = true;
    }
    if entry.sphragis.is_empty() && !incoming.sphragis.is_empty() {
        entry.sphragis = incoming.sphragis.clone();
        changed = true;
    }
    if incoming.created_at != 0 && (entry.created_at == 0 || incoming.created_at < entry.created_at)
    {
        entry.created_at = incoming.created_at;
        changed = true;
    }
    for replica in &incoming.replicas {
        if entry.replicas.len() >= MAX_HISTORY {
            break;
        }
        if !entry.replicas.contains(replica) {
            entry.replicas.push(replica.clone());
            changed = true;
        }
    }
    for deletion in &incoming.deletions {
        if entry.deletions.len() >= MAX_HISTORY {
            break;
        }
        if !entry.deletions.contains(deletion) {
            entry.deletions.push(deletion.clone());
            changed = true;
        }
    }
    changed
}

/// Merge every entry in a `{ "entries": [...] }` body.
pub fn merge_body(st: &mut State, body: &Value) -> usize {
    let Some(entries) = body.get("entries").and_then(|v| v.as_array()) else {
        return 0;
    };
    let mut merged = 0;
    for value in entries.iter().take(MAX_LEDGER_ENTRIES) {
        if let Some(entry) = entry_from_json(value) {
            if merge(st, &entry) {
                merged += 1;
            }
        }
    }
    merged
}

/// Digest + entries for a peer that asked with `?digest=`. When the digest
/// matches, `entries` is omitted entirely (the common converged case).
pub fn exchange_body(st: &State, want_digest: &str) -> Value {
    let digest = digest(&st.prytaneion);
    if !want_digest.is_empty() && want_digest == digest {
        return serde_json::json!({ "digest": digest });
    }
    serde_json::json!({
        "digest": digest,
        "entries": snapshot(&st.prytaneion)
            .iter()
            .map(entry_to_json)
            .collect::<Vec<_>>(),
    })
}

/// Pull one peer's ledger (digest-first) and merge it. Returns how many entries
/// changed. Network I/O; callers must not hold the state lock.
pub fn pull_from_peer(
    node: &crate::node::Node,
    peer: &crate::store::PeerRecord,
) -> Result<usize, String> {
    if peer.endpoint.trim().is_empty() {
        return Err("peer has no endpoint".to_string());
    }
    let client = FedHttpClient::new(&peer.endpoint, peer.tls_pin.clone())
        .map_err(|e| format!("bad peer endpoint: {e}"))?;
    let local_digest = {
        let st = node.state.lock().unwrap();
        digest(&st.prytaneion)
    };
    let path = format!("/homospondoi/ledger?digest={local_digest}");
    let seed = node.state.lock().unwrap().node_sign_seed;
    let sign_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let resp = client
        .get_with_fed_auth(&path, &node.cfg.server_id, &sign_key, None)
        .map_err(|e| format!("ledger fetch failed: {e}"))?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("peer ledger error {}", resp.status));
    }
    let value: Value =
        serde_json::from_slice(&resp.body).map_err(|_| "peer sent non-json ledger")?;
    let merged = {
        let mut st = node.state.lock().unwrap();
        merge_body(&mut st, &value)
    };
    Ok(merged)
}

/// Push our current ledger to one peer. Used after a local change so the
/// bubble learns about a new replica without waiting for anti-entropy.
pub fn push_to_peer(
    node: &crate::node::Node,
    peer: &crate::store::PeerRecord,
) -> Result<usize, String> {
    if peer.endpoint.trim().is_empty() {
        return Err("peer has no endpoint".to_string());
    }
    let client = FedHttpClient::new(&peer.endpoint, peer.tls_pin.clone())
        .map_err(|e| format!("bad peer endpoint: {e}"))?;
    let body = {
        let st = node.state.lock().unwrap();
        serde_json::json!({ "entries": snapshot(&st.prytaneion) }).to_string()
    };
    let seed = node.state.lock().unwrap().node_sign_seed;
    let sign_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let resp = client
        .post_with_fed_auth("/homospondoi/ledger", &body, &node.cfg.server_id, &sign_key)
        .map_err(|e| format!("ledger push failed: {e}"))?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("peer ledger error {}", resp.status));
    }
    let value: Value =
        serde_json::from_slice(&resp.body).map_err(|_| "peer sent non-json ledger")?;
    Ok(value.get("merged").and_then(|v| v.as_u64()).unwrap_or(0) as usize)
}

/// Find one hash in a peer's ledger. Used when the local ledger has no entry.
pub fn find_on_peer(
    node: &crate::node::Node,
    peer: &crate::store::PeerRecord,
    hash: &str,
) -> Option<PrytaneionEntry> {
    if peer.endpoint.trim().is_empty() {
        return None;
    }
    let client = FedHttpClient::new(&peer.endpoint, peer.tls_pin.clone()).ok()?;
    let path = format!("/homospondoi/ledger?hash={hash}");
    let seed = node.state.lock().unwrap().node_sign_seed;
    let sign_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let resp = client
        .get_with_fed_auth(&path, &node.cfg.server_id, &sign_key, None)
        .ok()?;
    if !(200..300).contains(&resp.status) {
        return None;
    }
    let value: Value = serde_json::from_slice(&resp.body).ok()?;
    entry_from_json(value.get("entry")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(hash: &str) -> PrytaneionEntry {
        PrytaneionEntry {
            content_hash: hash.to_string(),
            origin_server: "pyle-a".to_string(),
            origin_user: "jose_0123456789abcdef".to_string(),
            origin_user_pubkey: "aa".repeat(32),
            origin_path: "docs/a.txt".to_string(),
            sphragis: "sig".to_string(),
            replicas: vec!["pyle-b:jose/docs/a.txt".to_string()],
            deletions: vec![],
            created_at: 10,
        }
    }

    #[test]
    fn merge_is_idempotent_and_unions_replicas() {
        let mut st = State::default();
        let mut a = entry(&"a".repeat(64));
        assert!(merge(&mut st, &a));
        assert!(!merge(&mut st, &a), "a repeated entry is a no-op");
        a.replicas.push("pyle-c:jose/docs/a.txt".to_string());
        assert!(merge(&mut st, &a));
        assert_eq!(
            st.prytaneion[&a.content_hash].replicas,
            vec![
                "pyle-b:jose/docs/a.txt".to_string(),
                "pyle-c:jose/docs/a.txt".to_string()
            ]
        );
        assert_eq!(
            st.prytaneion[&a.content_hash].origin_user_pubkey,
            "aa".repeat(32)
        );
    }

    #[test]
    fn digest_does_not_depend_on_replica_order() {
        let mut a = State::default();
        let mut b = State::default();
        let mut e1 = entry(&"a".repeat(64));
        e1.replicas = vec!["pyle-b:x".into(), "pyle-c:y".into()];
        let mut e2 = e1.clone();
        e2.replicas.reverse();
        a.prytaneion.insert(e1.content_hash.clone(), e1);
        b.prytaneion.insert(e2.content_hash.clone(), e2);
        assert_eq!(digest(&a.prytaneion), digest(&b.prytaneion));
    }
}
