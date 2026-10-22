//! Global authentication (3 factors) and session tokens
//! (especificacao-hdap.md §7).

use crate::crypto::{
    ed25519_sign, hmac_sha256, otp_chain, otp_reveal, otp_verify, sha256_hex, x25519_shared,
    CryptoError, CryptoResult,
};
use ed25519_dalek::{Signature, SigningKey};
use x25519_dalek::StaticSecret;

/// Challenge issued by a server for factor 1 (possession). Nonce + timestamp,
/// one-time use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: String,
    pub ts: u64,
}

impl Challenge {
    pub fn canonical_text(&self) -> String {
        format!("hdap:challenge:{}:{}", self.nonce, self.ts)
    }
}

/// OTP step witness (factor 2 — knowledge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpWitness {
    /// Step index r (1 <= r <= k).
    pub step: usize,
    /// Revealed preimage bytes.
    pub proof: Vec<u8>,
}

/// Proof of all three factors for a single login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProof {
    /// base64 of the Ed25519 signature over `Challenge::canonical_text()`.
    pub signature_b64: String,
    pub otp: Option<OtpWitness>,
    /// HMAC proof of the factor-3 shared key `k` (does not reveal `k`).
    pub code_proof_b64: String,
}

/// Prove factor 1: sign the challenge text.
pub fn prove_possession(sign_key: &SigningKey, ch: &Challenge) -> (String, Signature) {
    let msg = ch.canonical_text();
    let sig = ed25519_sign(sign_key, msg.as_bytes());
    (msg, sig)
}

/// Verify factor 1 server-side.
pub fn verify_possession(
    pubkey_bytes: &[u8; 32],
    challenge_text: &str,
    signature_b64: &str,
) -> CryptoResult<()> {
    use base64::Engine;
    use ed25519_dalek::Verifier;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|_| CryptoError::VerificationFailed)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| CryptoError::VerificationFailed)?;
    let pk = ed25519_dalek::VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|_| CryptoError::VerificationFailed)?;
    pk.verify(challenge_text.as_bytes(), &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Generate an OTP chain of `k` steps from the identity seed. Returns
/// `(anchor_hex, chain)` where `chain[k]` is the anchor.
pub fn make_otp_chain(seed: &[u8; 32], k: usize) -> (String, Vec<[u8; 32]>) {
    otp_chain(seed, k)
}

/// Reveal the preimage at step `r` (factor 2).
pub fn prove_knowledge(chain: &[[u8; 32]], r: usize) -> Option<OtpWitness> {
    otp_reveal(chain, r).map(|proof| OtpWitness {
        step: r,
        proof: proof.to_vec(),
    })
}

/// Verify factor 2 against the public anchor.
pub fn verify_knowledge(anchor_hex: &str, witness: &OtpWitness) -> bool {
    otp_verify(anchor_hex, witness.step, &witness.proof)
}

/// Factor 3: HMAC proof that this peer knows the shared session key `k`.
///
/// `k` is **derived** by both sides as `X25519(priv_enc, pub_enc)` — the
/// user with `priv_enc(U) · pub_enc(S)` and the server with
/// `priv_enc(S) · pub_enc(U)`. No party stores the other's secret and the
/// server never persists `k` (especificacao-hdap.md §7.4).
pub fn prove_session_secret(k: &[u8], user: &str, server: &str, ts: u64) -> String {
    use base64::Engine;
    let msg = format!("hdap:code:{user}:{server}:{ts}");
    let mac = hmac_sha256(k, msg.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac)
}

/// A per-server session token from the shared key `k`
/// (`HMAC(k, "hdap:session"||server_id||exp)`). Because `k` is bound to the
/// node's ENC keypair, tokens are valid only on the issuing node (§7.2).
pub fn session_token(k: &[u8], server_id: &str, exp: u64) -> String {
    sha256_hex(&hmac_sha256(
        k,
        format!("hdap:session:{server_id}:{exp}").as_bytes(),
    ))
}

/// Derive the factor-3 shared key `k = X25519(local_enc_priv, peer_enc_pub)`.
/// The node derives it from its own ENC secret key and the user's published
/// ENC public key; the user derives it from its ENC secret key and the
/// node's published ENC public key. Same `k`, no stored secret.
pub fn derive_shared_key(local_enc_priv: &StaticSecret, peer_enc_pub: &[u8; 32]) -> [u8; 32] {
    x25519_shared(local_enc_priv, peer_enc_pub)
}

/// A session bundle produced after successful 3FA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    pub server_id: String,
    pub exp: u64,
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ed25519_keygen, x25519_keygen};
    use rand_core::OsRng;

    #[test]
    fn factor1_possession_roundtrip() {
        let key = ed25519_keygen(&mut OsRng);
        let ch = Challenge {
            nonce: "deadbeef".into(),
            ts: 1_700_000_000,
        };
        let (msg, sig) = prove_possession(&key, &ch);
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        assert!(verify_possession(&key.verifying_key().to_bytes(), &msg, &b64).is_ok());
        assert!(verify_possession(&key.verifying_key().to_bytes(), "other", &b64).is_err());
    }

    #[test]
    fn factor2_knowledge_roundtrip() {
        let seed = [0x42u8; 32];
        let k = 8;
        let (anchor, chain) = make_otp_chain(&seed, k);
        let w = prove_knowledge(&chain, 3).unwrap();
        assert!(verify_knowledge(&anchor, &w));
        // reusing same step still verifies (chain is commutative by H^r), but
        // the spec consumes each preimage once server-side.
        let (_, chain2) = make_otp_chain(&seed, k);
        let _ = chain2;
        // wrong step fails
        let bad = OtpWitness {
            step: 4,
            proof: w.proof.clone(),
        };
        assert!(!verify_knowledge(&anchor, &bad));
    }

    #[test]
    fn factor3_session_secret_and_token() {
        let secret = [7u8; 32];
        let p = prove_session_secret(&secret, "jose_x", "server-a", 123);
        let wrong = prove_session_secret(&[8u8; 32], "jose_x", "server-a", 123);
        assert_ne!(p, wrong);

        let t1 = session_token(&secret, "server-a", 1000);
        let t2 = session_token(&secret, "server-a", 1000);
        let t3 = session_token(&secret, "server-b", 1000);
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    #[test]
    fn factor3_shared_key_derived_from_each_side() {
        let user_enc = x25519_keygen(&mut OsRng);
        let node_enc = x25519_keygen(&mut OsRng);
        let user_pub = crate::crypto::x25519_public(&user_enc);
        let node_pub = crate::crypto::x25519_public(&node_enc);
        // User side: priv_enc(U) · pub_enc(S); node side: priv_enc(S) · pub_enc(U).
        let from_user = derive_shared_key(&user_enc, &node_pub);
        let from_node = derive_shared_key(&node_enc, &user_pub);
        assert_eq!(from_user, from_node);

        // A different node (different ENC keypair) derives a different k.
        let other_node = x25519_keygen(&mut OsRng);
        let from_other = derive_shared_key(&user_enc, &crate::crypto::x25519_public(&other_node));
        assert_ne!(from_user, from_other);

        // The proof binds user, node and ts.
        let p = prove_session_secret(&from_user, "jose_x", "node-a", 123);
        assert_eq!(p, prove_session_secret(&from_node, "jose_x", "node-a", 123));
        assert_ne!(p, prove_session_secret(&from_user, "jose_x", "node-a", 124));
    }
}
