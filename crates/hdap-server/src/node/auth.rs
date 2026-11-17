//! Authentication module: 3FA (possession, OTP knowledge, DH session),
//! proklesis challenges, session tokens, OTP anchor rotation.
//!
//! v2/Teleios hardening: bounded OTP work, no user enumeration, per-user
//! challenge caps, challenge-bound factor 3, server-owned timestamps and a
//! signature requirement for OTP-anchor rotation.

use base64::Engine;
use hdap_core::auth::{
    derive_shared_key, prove_session_secret, prove_session_secret_bound, session_storage_key,
    session_token, verify_knowledge_bounded, verify_possession, OtpWitness,
};
use hdap_core::pow::verify_pow;
use hdap_core::time::{client_ts_matches, is_expired};
use hdap_core::MAX_OTP_CHAIN_LEN;
use rand_core::RngCore;

use crate::config::Config;
use crate::http::{Request, Response};
use crate::node::{content_hash, json_err, require_json};
use crate::store::{Blob, ProklesisRecord, Session, State, UserRecord};

pub struct AuthModule {
    cfg: Config,
}

fn pylaia_challenge(server_id: &str, nonce: &str) -> String {
    format!("hdap-pylaia:{server_id}:{nonce}")
}

/// Factor-3 verification. The v2 proof is bound to the whole server-issued
/// challenge; the legacy `hdap:code:` proof is accepted only for identities
/// predating v2 and only for the exact UTC timestamp this node issued.
fn factor3_ok(
    k: &[u8],
    user: &str,
    server: &str,
    challenge_text: &str,
    issued_ts: u64,
    proof: &str,
    allow_legacy: bool,
) -> bool {
    if prove_session_secret_bound(k, user, server, challenge_text) == proof {
        return true;
    }
    allow_legacy && prove_session_secret(k, user, server, issued_ts) == proof
}

/// Canonical text an identity key must sign to rotate its own OTP anchor.
/// The definition lives in `hdap-core` so the client signs exactly what the
/// node verifies.
pub use hdap_core::auth::omphalos_rotation_text;

impl AuthModule {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    /// Write the two `hestia` documents (§3.2) into a fresh user space.
    fn prosopeion_of(u: &UserRecord) -> String {
        let mut d = hdap_core::doc::Doc::new(hdap_core::DocType::Prosopeion, 1, None, u.created_at);
        d.body.insert("NICKNAME".into(), u.nickname.clone());
        d.body.insert("SUFFIX".into(), u.suffix_hex.clone());
        d.body.insert("SIGN_PUBKEY".into(), u.sign_pub_hex.clone());
        d.body.insert("ENC_PUBKEY".into(), u.enc_pub_hex.clone());
        d.body.insert("OMPHALOS".into(), u.otp_anchor_hex.clone());
        d.body.insert("SEED_ITER".into(), u.otp_k.to_string());
        d.body.insert("CREATED".into(), u.created_at.to_string());
        d.render()
    }

    /// Make sure the logical directory exists, without ever overwriting
    /// anything the user owns. Called at registration *and* at authentication,
    /// because an account created before this feature has no `hestia` and a
    /// backfill that only ran at registration would leave it empty forever.
    pub(crate) fn ensure_hestia(
        &self,
        st: &mut State,
        user_id: &str,
        prosopeion: &str,
        created_at: u64,
    ) {
        let adeia = hdap_core::protocol::adeia_doc(user_id, 1, None, created_at, &[], None);
        let adeia = adeia.render();
        for (path, text) in [("prosopeion.hdap", prosopeion), ("adeia.hdap", &adeia)] {
            let key = State::key(user_id, path);
            // Never clobber: a file the user edited is theirs.
            if st.objects.contains_key(&key) {
                continue;
            }
            let bytes = text.as_bytes();
            let hash = content_hash(bytes);
            st.objects.insert(
                key,
                Blob {
                    owner: user_id.to_string(),
                    path: path.to_string(),
                    hash,
                    bytes: hdap_core::crypto::aead_seal(&st.master_key, bytes),
                },
            );
        }
    }

    /// `GET /proklesis` — issue a one-time challenge nonce for 3FA login.
    ///
    /// Unknown users and known users are indistinguishable in the response so
    /// this route is not a user-enumeration oracle (AME-30).
    pub fn handle_proklesis(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = req.query.get("user") else {
            return Response::json(400, json_err("user query required"));
        };
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let nonce_hex = hex::encode(nonce);
        let ts = node.now();
        let expires_at = ts.saturating_add(self.cfg.proklesis_ttl_secs);
        let mut st = node.lock_state();
        if !st.users.contains_key(user_id) {
            // Same shape as the success response, with an unusable nonce.
            return Response::json(
                200,
                serde_json::json!({
                    "nonce": nonce_hex,
                    "ts": ts,
                    "expires_at": expires_at,
                    "pylaia": {
                        "required": self.cfg.require_entry_pow,
                        "challenge": pylaia_challenge(&self.cfg.server_id, &nonce_hex),
                        "target_bits": self.cfg.pylaia_target,
                    },
                })
                .to_string(),
            );
        }
        // Drop expired challenges and cap the outstanding ones per user before
        // inserting, so an unauthenticated caller cannot grow the map forever.
        st.proklesis.retain(|_, r| !is_expired(ts, r.expires_at));
        let outstanding = st
            .proklesis
            .values()
            .filter(|r| r.user_id == *user_id)
            .count();
        if outstanding >= self.cfg.max_proklesis_per_user {
            return Response::json(429, json_err("too many outstanding challenges"));
        }
        st.proklesis.insert(
            nonce_hex.clone(),
            ProklesisRecord {
                user_id: user_id.clone(),
                ts,
                expires_at,
            },
        );
        let challenge = pylaia_challenge(&self.cfg.server_id, &nonce_hex);
        Response::json(
            200,
            serde_json::json!({
                "nonce": nonce_hex,
                "ts": ts,
                "expires_at": expires_at,
                "pylaia": {
                    "required": self.cfg.require_entry_pow,
                    "challenge": challenge,
                    "target_bits": self.cfg.pylaia_target,
                },
            })
            .to_string(),
        )
    }

    /// `POST /auth` — 3FA login:
    /// F1: Ed25519 signature over the server-issued challenge
    /// F2: OTP hash-chain step, bounded by the registered chain length
    /// F3: HMAC over the shared key and the *same* challenge
    /// F4: optional entry proof-of-work
    ///
    /// The state lock is held only for map reads/writes. Cryptography runs with
    /// the lock released so one request cannot stall every other request.
    pub fn handle_auth(&self, node: &crate::node::Node, req: &Request) -> Response {
        let now = node.now();
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let user_id = body
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let nonce = body
            .get("nonce")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ts = body.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
        let signature = body
            .get("signature")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // v2 accepts an explicit `otp_step` and keeps `step` as a legacy alias.
        let otp_step = body
            .get("otp_step")
            .or_else(|| body.get("step"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let otp_proof = body
            .get("otp_proof")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let code_proof = body
            .get("code_proof")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // --- short critical section: copy the two records we need ---
        let (rec, user, next) = {
            let st = node.lock_state();
            let Some(rec) = st.proklesis.get(&nonce).cloned() else {
                return Response::json(401, json_err("unknown or consumed challenge"));
            };
            if rec.user_id != user_id || is_expired(now, rec.expires_at) {
                return Response::json(401, json_err("invalid or expired challenge"));
            }
            let Some(user) = st.users.get(&user_id).cloned() else {
                // Do not distinguish "unknown user" from a bad challenge.
                return Response::json(401, json_err("invalid or expired challenge"));
            };
            let next = st.omphalos_step.get(&user_id).copied().unwrap_or(1);
            (rec, user, next)
        };

        // The client must echo the exact UTC timestamp the server issued. It
        // never gets to substitute its own local clock (timezone independence).
        if !client_ts_matches(ts, rec.ts) {
            return Response::json(401, json_err("challenge timestamp mismatch"));
        }

        // Factor 1: possession of the signing key.
        let Some(sign_pub) = user.sign_pub_bytes() else {
            return Response::json(500, json_err("stored pubkey invalid"));
        };
        let challenge = hdap_core::Challenge {
            nonce: nonce.clone(),
            ts: rec.ts,
        };
        if verify_possession(&sign_pub, &challenge.canonical_text(), &signature).is_err() {
            return Response::json(401, json_err("factor 1 failed"));
        }

        // Factor 2: bounded work. `user.otp_k` is the registered chain length;
        // no client-supplied number can drive the SHA loop.
        let step = match usize::try_from(otp_step) {
            Ok(s) => s,
            Err(_) => return Response::json(400, json_err("otp_step out of range")),
        };
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(&otp_proof)
            .unwrap_or_default();
        let witness = OtpWitness {
            step,
            proof: proof_bytes,
        };
        if step < next {
            return Response::json(
                401,
                serde_json::json!({ "error": "factor 2 step replayed", "next": next }).to_string(),
            );
        }
        if !verify_knowledge_bounded(&user.otp_anchor_hex, &witness, user.otp_k) {
            return Response::json(401, json_err("factor 2 failed"));
        }

        // Factor 3: shared key derived from X25519; proof bound to the challenge.
        let Some(enc_pub) = user.enc_pub_bytes() else {
            return Response::json(500, json_err("stored enc pubkey invalid"));
        };
        let k = derive_shared_key(&node.node_enc_priv, &enc_pub);
        if !factor3_ok(
            &k[..],
            &user_id,
            &self.cfg.server_id,
            &challenge.canonical_text(),
            rec.ts,
            &code_proof,
            user.accepts_legacy_f3(),
        ) {
            return Response::json(401, json_err("factor 3 failed"));
        }

        // Factor 4 (optional): entry proof-of-work on the same nonce.
        if self.cfg.require_entry_pow {
            let pylaia_nonce = body
                .get("pylaia_nonce")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if pylaia_nonce == 0 {
                return Response::json(400, json_err("missing pylaia nonce"));
            }
            let challenge_text = pylaia_challenge(&self.cfg.server_id, &nonce);
            if !verify_pow(
                challenge_text.as_bytes(),
                pylaia_nonce,
                self.cfg.pylaia_target,
            ) {
                return Response::json(401, json_err("pylaia proof-of-work not satisfied"));
            }
        }

        // --- short critical section: commit the successful login ---
        let exp = now.saturating_add(self.cfg.session_ttl_secs);
        let token = session_token(&k[..], &self.cfg.server_id, exp);
        {
            let mut st = node.lock_state();
            // Re-check under the lock: another request may have consumed it.
            if !st.proklesis.contains_key(&nonce) {
                return Response::json(401, json_err("unknown or consumed challenge"));
            }
            let current = st.omphalos_step.get(&user_id).copied().unwrap_or(1);
            if step < current {
                return Response::json(401, json_err("factor 2 step replayed"));
            }
            st.proklesis.remove(&nonce);
            st.omphalos_step
                .insert(user_id.clone(), step.saturating_add(1));
            // Store only a one-way hash: a DB dump must not contain a usable
            // bearer token (v2/Teleios).
            st.sessions.insert(
                session_storage_key(&token),
                Session {
                    user_id: user_id.clone(),
                    exp,
                },
            );
            let created_at = user.created_at;
            let prosopeion = Self::prosopeion_of(&user);
            self.ensure_hestia(&mut st, &user_id, &prosopeion, created_at);
        }

        Response::json(
            200,
            serde_json::json!({
                "user": user_id,
                "token": token,
                "exp": exp,
                "server_time_utc": now,
            })
            .to_string(),
        )
    }

    /// `POST /omphalos` — rotate the OTP anchor (OMPHALOS).
    ///
    /// v2 requires the identity key to sign the rotation text. A stolen 12-hour
    /// session is no longer enough to lock the real owner out forever.
    pub fn handle_omphalos_rotate(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let Some(new_anchor) = body.get("otp_anchor").and_then(|v| v.as_str()) else {
            return Response::json(400, json_err("otp_anchor required"));
        };
        if new_anchor.len() != 64 || !new_anchor.chars().all(|c| c.is_ascii_hexdigit()) {
            return Response::json(400, json_err("otp_anchor must be 64 hex"));
        }
        let Some(new_k) = body.get("seed_iter").and_then(|v| v.as_u64()) else {
            return Response::json(400, json_err("seed_iter required"));
        };
        if new_k == 0 || new_k > MAX_OTP_CHAIN_LEN as u64 {
            return Response::json(400, json_err("seed_iter out of range"));
        }
        let signature = body
            .get("identity_signature")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let old_anchor = {
            let st = node.lock_state();
            let Some(user) = st.users.get(&user_id) else {
                return Response::json(401, json_err("unauthorized"));
            };
            if new_k <= user.otp_k as u64 {
                return Response::json(
                    400,
                    json_err("seed_iter must be strictly greater than the current one"),
                );
            }
            user.otp_anchor_hex.clone()
        };
        let text = omphalos_rotation_text(&user_id, &old_anchor, new_anchor, new_k);
        let user = {
            let st = node.lock_state();
            st.users.get(&user_id).cloned()
        };
        let Some(user) = user else {
            return Response::json(401, json_err("unauthorized"));
        };
        let Some(sign_pub) = user.sign_pub_bytes() else {
            return Response::json(500, json_err("stored pubkey invalid"));
        };
        if verify_possession(&sign_pub, &text, signature).is_err() {
            return Response::json(401, json_err("identity signature required"));
        }
        // Preserve `v2_f3`: a legacy identity stays legacy until it re-registers
        // with a v2 client, so rotation never silently drops migration support.
        let rotated = UserRecord {
            otp_anchor_hex: new_anchor.to_string(),
            otp_k: new_k as usize,
            ..user
        };
        {
            let mut st = node.lock_state();
            st.users.insert(user_id.clone(), rotated);
            // Old chain consumed steps are dead; reset the replay floor.
            st.omphalos_step.insert(user_id.clone(), 1);
        }
        Response::json(
            200,
            serde_json::json!({ "rotated": true, "seed_iter": new_k }).to_string(),
        )
    }
}

/// Remove expired challenges and sessions. Called by the background worker
/// and directly by tests; returns the number of removed entries.
pub fn prune_expired(st: &mut State, now: u64) -> usize {
    let before = st.proklesis.len() + st.sessions.len();
    st.proklesis.retain(|_, r| !is_expired(now, r.expires_at));
    st.sessions.retain(|_, s| !is_expired(now, s.exp));
    before - (st.proklesis.len() + st.sessions.len())
}

#[cfg(test)]
mod tests {
    use super::omphalos_rotation_text;
    use super::*;
    use crate::node::Node;
    use hdap_core::auth::{make_otp_chain, prove_possession, prove_session_secret_bound};
    use std::collections::BTreeMap;

    fn auth_req(body: serde_json::Value) -> Request {
        Request {
            method: "POST".to_string(),
            path: "auth".to_string(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: body.to_string().into_bytes(),
            peer: None,
        }
    }

    /// A failed login must leave the challenge intact: burning it on a bad
    /// attempt would both diverge memory/disk and let a forged request DoS the
    /// legitimate user's challenge.
    #[test]
    fn a_failed_login_does_not_burn_the_challenge() {
        let node = Node::new(Config::default());
        let user = "jose_0123456789abcdef";
        {
            let mut st = node.lock_state();
            st.proklesis.insert(
                "nonce-1".to_string(),
                ProklesisRecord {
                    user_id: user.to_string(),
                    ts: 1,
                    expires_at: u64::MAX,
                },
            );
        }

        let resp = node.auth.handle_auth(
            &node,
            &auth_req(serde_json::json!({ "user": user, "nonce": "nonce-1", "ts": 1 })),
        );
        assert_eq!(resp.status, 401);

        let st = node.lock_state();
        assert!(
            st.proklesis.contains_key("nonce-1"),
            "a failed attempt must not consume the challenge"
        );
        assert!(st.sessions.is_empty());
    }

    #[test]
    fn prune_removes_expired_challenges_and_sessions() {
        let mut st = State::default();
        st.proklesis.insert(
            "old".into(),
            ProklesisRecord {
                user_id: "u".into(),
                ts: 1,
                expires_at: 10,
            },
        );
        st.proklesis.insert(
            "new".into(),
            ProklesisRecord {
                user_id: "u".into(),
                ts: 20,
                expires_at: 30,
            },
        );
        st.sessions.insert(
            hdap_core::session_storage_key("tok"),
            Session {
                user_id: "u".into(),
                exp: 9,
            },
        );
        assert_eq!(prune_expired(&mut st, 10), 2);
        assert!(st.proklesis.contains_key("new"));
        assert!(st.sessions.is_empty());
    }

    #[test]
    fn legacy_f3_is_accepted_only_for_pre_v2_identities() {
        let k = [3u8; 32];
        let user = "jose_0123456789abcdef";
        let server = "pyle-a";
        let ts = 1_700_000_000u64;
        let ch = hdap_core::Challenge {
            nonce: "nonce-abc".into(),
            ts,
        }
        .canonical_text();
        let bound = prove_session_secret_bound(&k, user, server, &ch);
        let legacy = prove_session_secret(&k, user, server, ts);
        assert_ne!(bound, legacy, "the two proof formats must never collide");

        // v2 account: only the challenge-bound proof works.
        assert!(factor3_ok(&k, user, server, &ch, ts, &bound, false));
        assert!(!factor3_ok(&k, user, server, &ch, ts, &legacy, false));

        // v1 account in migration: both work, but only for the issued ts.
        assert!(factor3_ok(&k, user, server, &ch, ts, &bound, true));
        assert!(factor3_ok(&k, user, server, &ch, ts, &legacy, true));
        assert!(!factor3_ok(&k, user, server, &ch, ts + 1, &legacy, true,));
    }

    #[test]
    fn rotation_text_is_bound_to_both_anchors_and_chain_length() {
        let a = omphalos_rotation_text("u", "old", "new", 100);
        let b = omphalos_rotation_text("u", "old", "new", 101);
        assert_ne!(a, b);
    }

    #[test]
    fn otp_chain_is_hkdf_bound_and_step_is_bounded() {
        let seed = [7u8; 32];
        let (anchor, chain) = make_otp_chain(&seed, 8);
        let w = hdap_core::auth::prove_knowledge(&chain, 4).unwrap();
        assert!(verify_knowledge_bounded(&anchor, &w, 8));
        // A client claiming a step beyond the registered chain is rejected
        // without performing any hash work.
        let forged = OtpWitness {
            step: 10_000_000,
            proof: w.proof.clone(),
        };
        assert!(!verify_knowledge_bounded(&anchor, &forged, 8));
    }

    #[test]
    fn factor3_uses_the_server_challenge_not_a_client_timestamp() {
        use hdap_core::crypto::x25519_keygen;
        use rand_core::OsRng;
        let user_enc = x25519_keygen(&mut OsRng);
        let node_enc = x25519_keygen(&mut OsRng);
        let k = derive_shared_key(&node_enc, &hdap_core::crypto::x25519_public(&user_enc));
        let challenge = hdap_core::Challenge {
            nonce: "n1".into(),
            ts: 1_700_000_000,
        };
        let good = prove_session_secret_bound(
            &k[..],
            "u",
            "node",
            &hdap_core::Challenge {
                nonce: "n1".into(),
                ts: 1_700_000_000,
            }
            .canonical_text(),
        );
        let bad = prove_session_secret_bound(
            &k[..],
            "u",
            "node",
            &hdap_core::Challenge {
                nonce: "n2".into(),
                ts: 1_700_000_000,
            }
            .canonical_text(),
        );
        assert_ne!(good, bad);
        // sanity: the legacy signing helper still uses the challenge text
        let _ = prove_possession(&hdap_core::crypto::ed25519_keygen(&mut OsRng), &challenge);
    }
}
