//! Bandwidth module: PoW challenges (mochthos), band credit (choregia), storage quotas (moira).

use hdap_core::crypto::aead_seal;
use hdap_core::doc::parse as parse_doc;
use hdap_core::pow::{pow_preimage, verify_pow, PowProof};
use hdap_core::protocol::MochthosDoc;

use crate::config::Config;
use crate::http::{Request, Response};
use crate::node::{content_hash, json_err, mochthos_challenge, require_json, sig_from_b64};
use crate::store::{BandObject, Blob, State};

pub struct BandwidthModule {
    cfg: Config,
}

impl BandwidthModule {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    /// `POST /mochthos/issue` — redeem a PoW solution for band credit.
    pub fn handle_mochthos(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let challenge = body.get("challenge").and_then(|v| v.as_str()).unwrap_or("");
        let nonce = body.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
        // The difficulty is *derived* from the client's hashrate claim with the
        // same formula the client used, so the client cannot name its own bar —
        // a lowbits request is simply refused as an implausible claim. Sending
        // the client a `target_bits` to verify against would let a client mine
        // zero bits and get band for free (§ PowPolicy).
        let claimed_hps = body
            .get("hashrate")
            .and_then(|v| v.as_f64())
            .unwrap_or(f64::NAN);
        let Some(hps) = hdap_core::pow::Hashrate::new(claimed_hps) else {
            return Response::json(400, json_err("implausible hashrate claim"));
        };
        let target_bits = self.cfg.pow.bits_for(hps);

        // A mochthos is honored only by the node that issued it (anti
        // double-spend): a challenge minted by another pyle is worthless here.
        if challenge != mochthos_challenge(&self.cfg.server_id) {
            return Response::json(
                400,
                json_err("mochthos not issued by this pyle (honored only by its issuer)"),
            );
        }
        if !verify_pow(challenge.as_bytes(), nonce, target_bits) {
            return Response::json(400, json_err("proof-of-work not satisfied"));
        }
        let mut st = node.state.lock().unwrap();
        let key = format!("{challenge}|{nonce}");
        if !st.mochthos_used.insert(key) {
            return Response::json(400, json_err("mochthos already redeemed on this pyle"));
        }

        // Create the .hdap.pow document
        let proof = PowProof {
            nonce,
            solution_hex: hex::encode(hdap_core::crypto::sha256(
                pow_preimage(challenge.as_bytes(), nonce).as_slice(),
            )),
            leading_bits: target_bits,
            attempts: 0,
        };
        let now = node.now();
        let m = MochthosDoc {
            owner: user_id.clone(),
            issuer: self.cfg.server_id.clone(),
            proof,
            target_bits,
            bandwidth_bytes: self.cfg.choregia_per_mochthos,
            issued_at: now,
            expires_at: now.saturating_add(u64::from(self.cfg.pow.target_secs) * 4 + 3600),
            status: "unused".to_string(),
        };
        let mut d = m.to_doc();
        // The challenge and the measured hashrate travel with the proof: a
        // pyle verifying this document must be able to recompute the proof
        // itself, not trust that the issuer ran it.
        d.body
            .insert("CHALLENGE".into(), mochthos_challenge(&self.cfg.server_id));
        d.body
            .insert("HASHRATE_HPS".into(), format!("{:.0}", hps.hps()));
        let pub_hex = hex::encode(x25519_dalek::PublicKey::from(&node.node_enc_priv).to_bytes());
        d.sigs.push(hdap_core::doc::Signature {
            signer: self.cfg.server_id.clone(),
            signer_pubkey: Some(pub_hex),
            signature: String::new(),
        });
        // Sign over the canonical input (which excludes our own SIGNATURE line)
        let canonical = d.render();
        // Derive signing key from node_sign_seed in State
        let sign_key = ed25519_dalek::SigningKey::from_bytes(&st.node_sign_seed);
        let sig = hdap_core::crypto::ed25519_sign(&sign_key, canonical.as_bytes());
        d.sigs.last_mut().unwrap().signature = hex::encode(sig.to_bytes());

        // Determine the path for this .hdap.pow file
        let path = Self::next_pow_path(&st, &user_id);
        let rendered = d.render();

        // Clone master_key before mutable borrow of st
        let master_key = st.master_key;

        // Store the document
        let doc_hash = content_hash(rendered.as_bytes());
        st.objects.insert(
            State::key(&user_id, &path),
            Blob {
                owner: user_id.clone(),
                path: path.clone(),
                hash: doc_hash.clone(),
                bytes: aead_seal(&master_key, rendered.as_bytes()),
            },
        );

        // Register the live band object in plain sight (§9.3): it is not
        // spendable until the owner countersigns it (`/mochthos/countersign`).
        st.band_objects.insert(
            doc_hash.clone(),
            BandObject {
                id: doc_hash.clone(),
                owner: user_id.clone(),
                path: path.clone(),
                challenge: mochthos_challenge(&self.cfg.server_id),
                granted: self.cfg.choregia_per_mochthos,
                remaining: self.cfg.choregia_per_mochthos,
                expires_at: m.expires_at,
                countersigned: false,
            },
        );

        // Update choregia credit
        let credit = st.choregia.entry(user_id.clone()).or_insert(0);
        *credit = credit.saturating_add(self.cfg.choregia_per_mochthos);
        let total = *credit;

        // Return the document with path and body for the client to countersign
        Response::json(
            200,
            serde_json::json!({
                "doc": {
                    "id": doc_hash,
                    "path": path,
                    "body": rendered,
                },
                "countersign_required": true,
                "total_choregia": total,
            })
            .to_string(),
        )
    }

    /// Determine the next available pow path for a user (e.g., pow/1.hdap.pow,
    /// pow/2.hdap.pow, etc.). Takes the already-locked state: the caller holds
    /// `node.state` for the whole issuance, and re-locking it here would deadlock
    /// (`std::sync::Mutex` is not reentrant).
    fn next_pow_path(st: &State, user_id: &str) -> String {
        let mut n = 1u32;
        loop {
            let path = format!("pow/{}.hdap.pow", n);
            let key = crate::store::State::key(user_id, &path);
            if !st.objects.contains_key(&key) {
                return path;
            }
            n += 1;
        }
    }

    /// `POST /mochthos/countersign` — the owner dual-signs the `.hdap.pow`,
    /// binding their countersignature to the issuer's proof and making the band
    /// spendable (§9.3). Without this, a server-only proof would let the issuer
    /// mint band the owner never agreed to.
    pub fn handle_countersign(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let body = match require_json(&req.body) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let signer_pubkey = body
            .get("signer_pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let signature = body.get("signature").and_then(|v| v.as_str()).unwrap_or("");
        if path.is_empty() || signer_pubkey.is_empty() || signature.is_empty() {
            return Response::json(400, json_err("path, signer_pubkey and signature required"));
        }
        let Ok(pub_bytes) = hex::decode(signer_pubkey) else {
            return Response::json(400, json_err("signer_pubkey must be hex"));
        };
        let Ok(pub_bytes) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
            return Response::json(400, json_err("signer_pubkey must be 32 bytes"));
        };
        let Some(tag) = sig_from_b64(signature) else {
            return Response::json(400, json_err("signature must be base64"));
        };

        let mut st = node.state.lock().unwrap();
        // Find the owner's band object at this path (idempotent: a repeated
        // countersign of an already-spendable object is a no-op success).
        let Some(band) = st
            .band_objects
            .values()
            .find(|b| b.owner == user_id && b.path == path)
        else {
            return Response::json(404, json_err("no band object at that path"));
        };
        let id = band.id.clone();
        let already = band.countersigned;
        if already {
            return Response::json(
                200,
                serde_json::json!({ "countersigned": true }).to_string(),
            );
        }
        let Some(blob) = st.objects.get(&State::key(&user_id, path)) else {
            return Response::json(404, json_err("band document missing"));
        };
        let master_key = st.master_key;
        let Ok(plain) = hdap_core::crypto::aead_open(&master_key, &blob.bytes) else {
            return Response::json(500, json_err("cannot open band document"));
        };
        let Ok(mut doc) = parse_doc(&String::from_utf8_lossy(&plain)) else {
            return Response::json(500, json_err("band document corrupt"));
        };
        // The countersignature must come from the session owner's *registered*
        // key — never a key the caller just declared.
        let Some(owner_pub) = st.users.get(&user_id).and_then(|u| u.sign_pub_bytes()) else {
            return Response::json(403, json_err("session user has no signing key"));
        };
        if owner_pub != pub_bytes {
            return Response::json(
                401,
                json_err("signer_pubkey does not match session identity"),
            );
        }
        // The owner appends their own signature slot and signs `signature_input(1)`,
        // exactly as the client built it (§4.2 rule 6).
        doc.sigs.push(hdap_core::doc::Signature {
            signer: user_id.clone(),
            signer_pubkey: Some(signer_pubkey.to_string()),
            signature: signature.to_string(),
        });
        let Ok(input) = doc.signature_input(1) else {
            return Response::json(500, json_err("bad band document signatures"));
        };
        if hdap_core::crypto::ed25519_verify(&owner_pub, input.as_bytes(), &tag).is_err() {
            return Response::json(401, json_err("countersignature invalid"));
        }
        // Persist the dual-signed document (issuer sig + owner sig) in place.
        let rendered = doc.render();
        st.objects.insert(
            State::key(&user_id, path),
            Blob {
                owner: user_id.clone(),
                path: path.to_string(),
                hash: content_hash(rendered.as_bytes()),
                bytes: aead_seal(&master_key, rendered.as_bytes()),
            },
        );
        if let Some(b) = st.band_objects.get_mut(&id) {
            b.countersigned = true;
        }
        Response::json(
            200,
            serde_json::json!({ "countersigned": true }).to_string(),
        )
    }

    /// `GET /mochthos/band` — list the authenticated owner's live band objects
    /// (`granted` / `remaining` / `countersigned`), §9.4.
    pub fn handle_band_list(&self, node: &crate::node::Node, req: &Request) -> Response {
        let Some(user_id) = node.session_user(req) else {
            return Response::json(401, json_err("unauthorized"));
        };
        let st = node.state.lock().unwrap();
        let band: Vec<serde_json::Value> = st
            .band_objects
            .values()
            .filter(|b| b.owner == user_id)
            .map(|b| {
                serde_json::json!({
                    "id": b.id,
                    "path": b.path,
                    "issuer": self.cfg.server_id,
                    "granted": b.granted,
                    "remaining": b.remaining,
                    "countersigned": b.countersigned,
                    "expires_at": b.expires_at,
                })
            })
            .collect();
        Response::json(200, serde_json::json!({ "band": band }).to_string())
    }
}
