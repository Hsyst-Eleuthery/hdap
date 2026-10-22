//! Authentication module: 3FA (possession, OTP knowledge, DH session),
//! proklesis challenges, session tokens, OTP anchor rotation.

use base64::Engine;
use hdap_core::auth::{
    derive_shared_key, prove_session_secret, session_token, verify_knowledge, verify_possession,
    OtpWitness,
};
use hdap_core::pow::verify_pow;
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
    pub fn handle_proklesis(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = req.query.get("user") else {
            return Response::json(400, json_err("user query required"));
        };
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let nonce_hex = hex::encode(nonce);
        let ts = node.now();
        let expires_at = ts + self.cfg.proklesis_ttl_secs;
        let mut st = node.state.lock().unwrap();
        if !st.users.contains_key(user_id) {
            return Response::json(404, json_err("unknown user"));
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
    /// F1: Ed25519 signature over challenge
    /// F2: OTP chain step (hash ladder)
    /// F3: DH-derived session secret (X25519)
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
        let otp_step = body.get("otp_step").and_then(|v| v.as_u64()).unwrap_or(0);
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

        let mut st = node.state.lock().unwrap();
        let Some(rec) = st.proklesis.get(&nonce).cloned() else {
            return Response::json(401, json_err("unknown or consumed challenge"));
        };
        if rec.user_id != user_id || rec.expires_at < now {
            return Response::json(401, json_err("invalid or expired challenge"));
        }
        let Some(user) = st.users.get(&user_id).cloned() else {
            return Response::json(401, json_err("unknown user"));
        };

        // Factor 1: possession of the signing key.
        let Some(sign_pub) = user.sign_pub_bytes() else {
            return Response::json(500, json_err("stored pubkey invalid"));
        };
        let canonical = format!("hdap:challenge:{}:{}", nonce, rec.ts);
        if verify_possession(&sign_pub, &canonical, &signature).is_err() {
            return Response::json(401, json_err("factor 1 failed"));
        }

        // Factor 2: OTP knowledge against public anchor, step strictly increasing.
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(&otp_proof)
            .unwrap_or_default();
        let witness = OtpWitness {
            step: otp_step as usize,
            proof: proof_bytes,
        };
        if !verify_knowledge(&user.otp_anchor_hex, &witness) {
            return Response::json(401, json_err("factor 2 failed"));
        }
        let next = st.omphalos_step.get(&user_id).copied().unwrap_or(1);
        if (otp_step as usize) < next {
            return Response::json(
                401,
                serde_json::json!({ "error": "factor 2 step replayed", "next": next }).to_string(),
            );
        }

        // Factor 3: the shared key `k` is DERIVED from the node's ENC private
        // key and the user's published ENC public key. The server holds no
        // stored secret; an attacker who steals the DB cannot replay (§7.4).
        let Some(enc_pub) = user.enc_pub_bytes() else {
            return Response::json(500, json_err("stored enc pubkey invalid"));
        };
        let k = derive_shared_key(&node.node_enc_priv, &enc_pub);
        if prove_session_secret(&k, &user_id, &self.cfg.server_id, ts) != code_proof {
            return Response::json(401, json_err("factor 3 failed"));
        }

        // Factor 4 (optional): entry proof-of-work (pylaia, §7.4).
        // The client must solve a small PoW on the proklesis nonce to rate-limit
        // login attempts. The challenge is the same nonce used for the challenge
        // signature; the target difficulty is from the node config.
        if self.cfg.require_entry_pow {
            let pylaia_nonce = body
                .get("pylaia_nonce")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if pylaia_nonce == 0 {
                return Response::json(400, json_err("missing pylaia nonce"));
            }
            let challenge = pylaia_challenge(&self.cfg.server_id, &nonce);
            if !verify_pow(challenge.as_bytes(), pylaia_nonce, self.cfg.pylaia_target) {
                return Response::json(401, json_err("pylaia proof-of-work not satisfied"));
            }
        }

        // Consume the challenge only once *every* factor has passed. A failed
        // or forged attempt must neither replay the nonce nor burn the
        // legitimate user's challenge — and consuming here (on success, which
        // is persisted) keeps memory and disk in agreement (AME-35).
        st.proklesis.remove(&nonce);
        st.omphalos_step
            .insert(user_id.clone(), otp_step as usize + 1);

        // Fresh per-node session token (bound to the derived key and exp).
        let exp = now + self.cfg.session_ttl_secs;
        let token = session_token(&k, &self.cfg.server_id, exp);
        st.sessions.insert(
            token.clone(),
            Session {
                user_id: user_id.clone(),
                exp,
            },
        );

        // Accounts registered before the hestia existed are still empty; every
        // field of the identity document is public, so the node can fill the
        // gap on login instead of leaving those spaces bare forever.
        let created_at = user.created_at;
        let prosopeion = Self::prosopeion_of(&user);
        self.ensure_hestia(&mut st, &user_id, &prosopeion, created_at);

        Response::json(
            200,
            serde_json::json!({
                "user": user_id,
                "token": token,
                "exp": exp,
            })
            .to_string(),
        )
    }

    /// `POST /omphalos` — rotate the OTP anchor (OMPHALOS) and chain length.
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
        if new_k == 0 {
            return Response::json(400, json_err("seed_iter must be > 0"));
        }
        let mut st = node.state.lock().unwrap();
        let Some(user) = st.users.get(&user_id) else {
            return Response::json(404, json_err("unknown user"));
        };
        if new_k <= user.otp_k as u64 {
            return Response::json(
                400,
                json_err("seed_iter must be strictly greater than the current one"),
            );
        }
        let user = user.clone();
        let rotated = UserRecord {
            otp_anchor_hex: new_anchor.to_string(),
            otp_k: new_k as usize,
            ..user
        };
        st.users.insert(user_id.clone(), rotated);
        // Old chain consumed steps are dead; reset the replay floor.
        st.omphalos_step.insert(user_id.clone(), 1);
        Response::json(
            200,
            serde_json::json!({ "rotated": true, "seed_iter": new_k }).to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;
    use std::collections::BTreeMap;

    fn auth_req(body: serde_json::Value) -> Request {
        Request {
            method: "POST".to_string(),
            path: "auth".to_string(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: body.to_string().into_bytes(),
        }
    }

    /// A failed login must leave the challenge intact: burning it on a bad
    /// attempt would both diverge memory/disk and let a forged request DoS the
    /// legitimate user's login.
    #[test]
    fn a_failed_login_does_not_burn_the_challenge() {
        let node = Node::new(Config::default());
        let user = "jose_0123456789abcdef";
        {
            let mut st = node.state.lock().unwrap();
            st.proklesis.insert(
                "nonce-1".to_string(),
                ProklesisRecord {
                    user_id: user.to_string(),
                    ts: 1,
                    expires_at: u64::MAX,
                },
            );
        }

        // Factor 1 fails (empty signature): the response is 401 ...
        let resp = node.auth.handle_auth(
            &node,
            &auth_req(serde_json::json!({ "user": user, "nonce": "nonce-1", "ts": 1 })),
        );
        assert_eq!(resp.status, 401);

        // ... and the challenge is still there for a real attempt.
        let st = node.state.lock().unwrap();
        assert!(
            st.proklesis.contains_key("nonce-1"),
            "a failed attempt must not consume the challenge"
        );
        assert!(st.sessions.is_empty());
    }
}
