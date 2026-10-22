//! Sync module: client bidirectional sync (GET/POST /sync).

use hdap_core::crypto::aead_open;
use hdap_core::doc::parse as parse_doc;
use serde_json::Value;

use crate::config::Config;
use crate::http::{Request, Response};
use crate::node::{json_err, require_json};
use crate::store::State;

pub struct SyncModule {
    cfg: Config,
}

impl SyncModule {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    /// `GET /sync` — full login snapshot for a session user.
    pub fn handle_sync(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        // A configured backup takes over only when its signed `diadosi.hdap`
        // names it and the current home no longer answers. Doing this before
        // the snapshot means the user's first login after the fall sees their
        // local identity as authoritative, not a dead pyle's stub.
        node.identity.maybe_promote_fallback(node, &user_id);
        let st = node.state.lock().unwrap();
        Response::json(
            200,
            self.sync_snapshot_json(node, &st, &user_id).to_string(),
        )
    }

    /// `POST /sync` — one-shot *bidirectional* login sync (§7). The client
    /// pushes everything it is authoritative for: its identity (registered or
    /// rotated exactly like `POST /prosopeion`) and the config documents it
    /// has seen (reconciled forward-only: a strictly newer edition wins, a
    /// stale or identical one is ignored). The reply is the full `GET /sync`
    /// snapshot, so the interface and the server both end up holding the same
    /// truthful state after a single round-trip.
    pub fn handle_sync_post(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if let Some(properties_text) = body.get("properties").and_then(|v| v.as_str()) {
            match node
                .identity
                .sync_prosopeion(node, properties_text, Some(&user_id))
            {
                Ok(_) => {}
                Err(e) => return e,
            }
        }
        if let Some(docs) = body.get("docs").and_then(|v| v.as_object()) {
            for (name, text) in docs {
                let name = name.as_str();
                if !matches!(
                    name,
                    "adeia.hdap"
                        | "diadosi.hdap"
                        | "kerux.hdap"
                        | "timi.hdap"
                        | "prytaneion.hdap"
                        | "prosopeion.hdap"
                ) {
                    continue;
                }
                let Some(text) = text.as_str() else { continue };
                let mut st = node.state.lock().unwrap();
                node.storage
                    .reindex_config_doc(&mut st, &user_id, name, text.as_bytes());
            }
        }
        let st = node.state.lock().unwrap();
        Response::json(
            200,
            self.sync_snapshot_json(node, &st, &user_id).to_string(),
        )
    }

    fn sync_snapshot_json(
        &self,
        node: &crate::node::Node,
        st: &State,
        user_id: &str,
    ) -> serde_json::Value {
        let mut ktema: Vec<Value> = Vec::new();
        let mut dirs: std::collections::BTreeSet<String> = Default::default();
        for blob in st.objects.values() {
            if blob.owner != user_id {
                continue;
            }
            let rest = blob.path.trim_start_matches('/');
            if rest.is_empty() {
                continue;
            }
            let name = rest.rsplit('/').next().unwrap_or(rest);
            let size = blob.bytes.len().saturating_sub(crate::node::SEAL_OVERHEAD) as u64;
            ktema.push(serde_json::json!({
                "name": name, "dir": false, "size": size,
                "hash": blob.hash, "path": blob.path
            }));
            // Every ancestor of a nested path is an implicit directory; only
            // the file's own path counts as a file entry.
            let mut acc = String::new();
            for seg in rest.split('/') {
                if acc.is_empty() {
                    acc.push_str(seg);
                } else {
                    acc.push('/');
                    acc.push_str(seg);
                }
                if acc != rest {
                    dirs.insert(acc.clone());
                }
            }
        }
        for d in dirs {
            let name = d.rsplit('/').next().unwrap_or(&d);
            ktema.push(serde_json::json!({ "name": name, "dir": true, "path": d }));
        }
        // Config documents the spec files in a `ktema` root — the panel reads
        // these directly, so it always shows the node's truth.
        let mut docs: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for name in [
            "adeia.hdap",
            "diadosi.hdap",
            "kerux.hdap",
            "timi.hdap",
            "prytaneion.hdap",
            "prosopeion.hdap",
        ] {
            if let Some(blob) = st.objects.get(&State::key(user_id, name)) {
                if let Ok(p) = aead_open(&st.master_key, &blob.bytes) {
                    docs.insert(name.to_string(), String::from_utf8_lossy(&p).into_owned());
                }
            }
        }
        let matrix: Vec<Value> = st
            .prytaneion
            .values()
            .map(|e| {
                serde_json::json!({
                    "content_hash": e.content_hash,
                    "origin_server": e.origin_server,
                    "origin_user": e.origin_user,
                    "replicas": e.replicas,
                    "deletions": e.deletions,
                })
            })
            .collect();
        let kerux: Vec<Value> = st
            .kerux
            .iter()
            .map(|(a, u)| serde_json::json!({ "alias": a, "uri": u }))
            .collect();
        let timi: Vec<Value> = st
            .timi
            .iter()
            .map(|(pyle, text)| {
                let doc = parse_doc(text).ok();
                let (price, max_dur, valid) = doc.map_or((0, 0, 0), |d| {
                    (
                        d.body
                            .get("PRICE_PER_GIB_DAY")
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0),
                        d.body
                            .get("MAX_DURATION_DAYS")
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0),
                        d.body
                            .get("VALID_KAIROS")
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0),
                    )
                });
                serde_json::json!({
                    "pyle": pyle,
                    "price_per_gib_day": price,
                    "max_duration_days": max_dur,
                    "valid_kairos": valid,
                })
            })
            .collect();
        let pheme: Vec<Value> = st
            .pheme
            .iter()
            .map(|(target, score)| serde_json::json!({ "target": target, "score": score }))
            .collect();
        serde_json::json!({
            "server_id": st.whoami,
            "node_enc_pub": node.node_enc_pub_hex(),
            "user_id": user_id,
            "band": st.choregia.get(user_id).copied().unwrap_or(0),
            "stored": st.stored.get(user_id).copied().unwrap_or(0),
            "moira_bytes": self.cfg.moira_bytes,
            "otp_step": st.omphalos_step.get(user_id).copied().unwrap_or(0),
            "ktema": ktema,
            "docs": docs,
            "prytaneion": matrix,
            "kerux": kerux,
            "timi": timi,
            "pheme": pheme,
        })
    }
}
