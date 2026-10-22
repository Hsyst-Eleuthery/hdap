//! Matrix module: prytaneion (provenance), pheme (reputation), kerux (aliases), timi (prices).

use hdap_core::doc::{parse as parse_doc, Doc, DocType};
use serde_json::Value;

use crate::config::Config;
use crate::http::{Request, Response};
use crate::node::{json_err, require_json};
use crate::store::PrytaneionEntry;

pub struct MatrixModule {
    cfg: Config,
}

impl MatrixModule {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    /// `GET /prytaneion` — read provenance entry by content hash.
    pub fn handle_prytaneion_read(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(hash) = req.query.get("hash") else {
            return Response::json(400, json_err("hash query required"));
        };
        let st = node.state.lock().unwrap();
        match st.prytaneion.get(hash) {
            Some(e) => Response::bytes(
                200,
                "text/plain; charset=utf-8",
                prytaneion_doc_text(e).into_bytes(),
            ),
            None => Response::json(404, json_err("prytaneion entry not found")),
        }
    }

    /// `POST /prytaneion` — add replica or deletion marker.
    pub fn handle_prytaneion_write(&self, node: &crate::node::Node, req: &Request) -> Response {
        let now = node.now();
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let hash = body
            .get("content_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let replica = body.get("replica").and_then(|v| v.as_str());
        let deletion = body.get("deletion").and_then(|v| v.as_str());
        if (replica.is_none() && deletion.is_none()) || hash.is_empty() {
            return Response::json(400, json_err("content_hash + replica or deletion required"));
        }
        let mut st = node.state.lock().unwrap();
        let created_at = now;
        let pubkey = st
            .users
            .get(&user_id)
            .map(|u| u.sign_pub_hex.clone())
            .unwrap_or_default();
        let entry = st
            .prytaneion
            .entry(hash.to_string())
            .or_insert_with(|| PrytaneionEntry {
                content_hash: hash.to_string(),
                origin_server: self.cfg.server_id.clone(),
                origin_user: user_id.clone(),
                origin_user_pubkey: pubkey,
                origin_path: String::new(),
                sphragis: String::new(),
                replicas: vec![],
                deletions: vec![],
                created_at,
            });
        if let Some(r) = replica {
            if !entry.replicas.contains(&r.to_string()) {
                entry.replicas.push(r.to_string());
            }
        }
        if let Some(d) = deletion {
            let tomb = format!("DELETED:{d}:{}", now);
            if !entry.deletions.contains(&tomb) {
                entry.deletions.push(tomb);
            }
        }
        Response::json(
            200,
            serde_json::json!({ "prytaneion": "updated" }).to_string(),
        )
    }

    /// `GET /pheme` — read reputation scores.
    pub fn handle_pheme_read(&self, node: &crate::node::Node, _req: &Request) -> Response {
        let st = node.state.lock().unwrap();
        let for_json: Vec<Value> = st
            .pheme
            .iter()
            .map(|(k, v)| serde_json::json!({ "target": k, "score": v }))
            .collect();
        Response::json(200, serde_json::json!({ "entries": for_json }).to_string())
    }

    /// `POST /pheme` — propose a reputation change (local).
    pub fn handle_pheme_propose(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(_user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let candidate = body.get("candidate").and_then(|v| v.as_str()).unwrap_or("");
        let doc = match parse_doc(candidate) {
            Ok(d) if d.doc_type == DocType::PhemeCandidate => d,
            _ => return Response::json(400, json_err("invalid tcd_candidate doc")),
        };
        let target = doc.body.get("TARGET_ID").cloned().unwrap_or_default();
        let delta: i64 = doc
            .body
            .get("SCORE_DELTA")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let mut st = node.state.lock().unwrap();
        let score = st.pheme.get(&target).copied().unwrap_or(0) + delta;
        st.pheme.insert(target.clone(), score);
        Response::json(
            200,
            serde_json::json!({ "target": target, "score": score }).to_string(),
        )
    }

    /// `GET /kerux/:alias` — resolve alias.
    pub fn handle_kerux_read(&self, node: &crate::node::Node, req: &Request) -> Response {
        let alias = req
            .path
            .trim_start_matches('/')
            .split('/')
            .nth(1)
            .unwrap_or("")
            .to_string();
        if alias.is_empty() {
            return Response::json(400, json_err("alias required"));
        }
        let st = node.state.lock().unwrap();
        match st.kerux.get(&alias) {
            Some(uri) => Response::json(
                200,
                serde_json::json!({ "alias": alias, "uri": uri }).to_string(),
            ),
            None => Response::json(404, json_err("alias not found")),
        }
    }

    /// `POST /kerux` — create/update alias (authenticated).
    pub fn handle_kerux_write(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let alias = body.get("alias").and_then(|v| v.as_str()).unwrap_or("");
        let uri = body.get("uri").and_then(|v| v.as_str()).unwrap_or("");
        if alias.is_empty() || uri.is_empty() {
            return Response::json(400, json_err("alias and uri required"));
        }
        let mut st = node.state.lock().unwrap();
        st.kerux.insert(alias.to_string(), uri.to_string());
        st.kerux_owner
            .insert(alias.to_string(), user_id.to_string());
        Response::json(200, serde_json::json!({ "kerux": "updated" }).to_string())
    }

    /// `GET /timi` — list price announcements.
    pub fn handle_timi_read(&self, node: &crate::node::Node, _req: &Request) -> Response {
        let st = node.state.lock().unwrap();
        let for_json: Vec<Value> = st
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
        Response::json(200, serde_json::json!({ "entries": for_json }).to_string())
    }

    /// `POST /timi` — publish a `timi.hdap` announcement from a federated pyle.
    pub fn handle_timi_write(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(_peer) = node.federation.fed_verify_peer(node, req) else {
            return Response::json(401, json_err("fed signature invalid"));
        };
        let text = match std::str::from_utf8(&req.body) {
            Ok(t) => t,
            Err(_) => return Response::json(400, json_err("timi doc must be utf-8")),
        };
        let doc = match parse_doc(text) {
            Ok(d) if d.doc_type == DocType::Timi => d,
            _ => return Response::json(400, json_err("invalid timi doc")),
        };
        let pyle = doc.body.get("PYLE").cloned().unwrap_or_default();
        if pyle != _peer.node_id {
            return Response::json(400, json_err("PYLE must match announcing node"));
        }
        if doc
            .body
            .get("PRICE_PER_GIB_DAY")
            .and_then(|s| s.parse::<u64>().ok())
            .is_none()
            || doc
                .body
                .get("MAX_DURATION_DAYS")
                .and_then(|s| s.parse::<u64>().ok())
                .is_none()
        {
            return Response::json(400, json_err("timi doc missing numeric fields"));
        }
        let mut st = node.state.lock().unwrap();
        st.timi.insert(pyle, text.to_string());
        Response::json(200, serde_json::json!({ "timi": "updated" }).to_string())
    }
}

fn prytaneion_doc_text(e: &PrytaneionEntry) -> String {
    let mut d = Doc::new(DocType::Prytaneion, 1, None, e.created_at);
    d.body
        .insert("CONTENT_HASH".to_string(), e.content_hash.clone());
    d.body
        .insert("ORIGIN_SERVER".to_string(), e.origin_server.clone());
    d.body
        .insert("ORIGIN_USER".to_string(), e.origin_user.clone());
    if !e.origin_user_pubkey.is_empty() {
        d.body
            .insert("ORIGIN_PUBKEY".to_string(), e.origin_user_pubkey.clone());
    }
    if !e.origin_path.is_empty() {
        d.body
            .insert("ORIGIN_PATH".to_string(), e.origin_path.clone());
    }
    if !e.sphragis.is_empty() {
        d.body.insert("SPHRAGIS".to_string(), e.sphragis.clone());
    }
    for (i, r) in e.replicas.iter().enumerate() {
        d.body.insert(format!("REPLICA{i:04}"), r.clone());
    }
    for (i, del) in e.deletions.iter().enumerate() {
        d.body.insert(format!("DELETION{i:04}"), del.clone());
    }
    d.render()
}
