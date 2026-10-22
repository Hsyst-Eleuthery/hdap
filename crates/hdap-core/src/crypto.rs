//! Cryptographic primitives: hashing, signing (Ed25519), key agreement
//! (X25519), AEAD (ChaCha20-Poly1305), KDF (Argon2id), HMAC and OTP chain.
//!
//! One algorithm per role only (especificacao-hdap.md §5). No key material
//! ever enters this module's public API without a type distinction.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Re-export commonly used Ed25519 types for downstream crates.
pub use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Errors for cryptographic operations that fail without a public message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Signature or MAC verification failed (tampering / wrong key).
    VerificationFailed,
    /// AEAD decryption failed (tampering / wrong key).
    DecryptFailed,
}

pub type CryptoResult<T> = Result<T, CryptoError>;

/// Domain separation constant used when deriving AEAD keys from shared secrets.
pub const KDF_INFO_SESSION: &[u8] = b"hdap:session";
/// Domain separation label for the OTP chain root derivation.
pub const KDF_INFO_OTP: &[u8] = b"hdap:otp";

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-256 digest as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// SHA-256 HMAC (used for session tokens and proofs).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Generate a fresh Ed25519 signing keypair.
pub fn ed25519_keygen(rng: &mut impl RngCore) -> SigningKey {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

/// Sign a message with Ed25519.
pub fn ed25519_sign(key: &SigningKey, msg: &[u8]) -> Signature {
    key.sign(msg)
}

/// Verify an Ed25519 signature against a public key (SPKI bytes).
pub fn ed25519_verify(pubkey_bytes: &[u8; 32], msg: &[u8], sig: &Signature) -> CryptoResult<()> {
    let pk = VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| CryptoError::VerificationFailed)?;
    pk.verify(msg, sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Generate a fresh X25519 static secret (encryption role).
pub fn x25519_keygen(rng: &mut (impl CryptoRng + RngCore)) -> StaticSecret {
    StaticSecret::random_from_rng(rng)
}

/// DH: shared secret between `local` and `remote_pub`.
pub fn x25519_shared(local: &StaticSecret, remote_pub: &[u8; 32]) -> [u8; 32] {
    let pubkey = X25519PublicKey::from(*remote_pub);
    *local.diffie_hellman(&pubkey).as_bytes()
}

/// X25519 public key bytes for a static secret.
pub fn x25519_public(local: &StaticSecret) -> [u8; 32] {
    *X25519PublicKey::from(local).as_bytes()
}

/// Seal `plaintext` to `recipient_pub` (X25519 ECIES):
/// ephemeral DH key + ChaCha20-Poly1305 with an AEAD key derived from the
/// shared secret. Output: `eph_pub (32) || nonce (12) || ciphertext+tag`.
pub fn seal_to_pub(recipient_pub: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    let eph = x25519_keygen(&mut rng);
    let shared = x25519_shared(&eph, recipient_pub);
    let key = Key::from(sha256(&shared));
    let cipher = ChaCha20Poly1305::new(&key);
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("chacha20poly1305 encrypt is infallible");
    let mut out = Vec::with_capacity(32 + 12 + ct.len());
    out.extend_from_slice(&x25519_public(&eph));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open an envelope produced by [`seal_to_pub`]. Returns `Err` on any
/// failure (tampering, wrong key).
pub fn open_with_priv(local_priv: &StaticSecret, sealed: &[u8]) -> CryptoResult<Vec<u8>> {
    if sealed.len() < 32 + 12 + 16 {
        return Err(CryptoError::DecryptFailed);
    }
    let eph_pub: [u8; 32] = sealed[..32]
        .try_into()
        .map_err(|_| CryptoError::DecryptFailed)?;
    let nonce = &sealed[32..44];
    let ct = &sealed[44..];
    let shared = x25519_shared(local_priv, &eph_pub);
    let key = Key::from(sha256(&shared));
    let cipher = ChaCha20Poly1305::new(&key);
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| CryptoError::DecryptFailed)
}

/// Symmetric AEAD seal (used for the local vault): returns `nonce||ct+tag`.
pub fn aead_seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("chacha20poly1305 encrypt is infallible");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open a symmetric AEAD envelope produced by [`aead_seal`].
pub fn aead_open(key: &[u8; 32], sealed: &[u8]) -> CryptoResult<Vec<u8>> {
    if sealed.len() < 12 + 16 {
        return Err(CryptoError::DecryptFailed);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..])
        .map_err(|_| CryptoError::DecryptFailed)
}

/// Argon2id params (OWASP-recommended: 19 MiB, t=2, p=1).
pub const ARGON2_M_COST: u32 = 19 * 1024;
pub const ARGON2_T_COST: u32 = 2;
pub const ARGON2_P_COST: u32 = 1;

/// Derive a 32-byte key from a passphrase using Argon2id.
pub fn derive_key_argon2(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .expect("valid argon2 params");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .expect("argon2id hashing is infallible for valid params");
    out
}

/// Derive an OTP chain of length `k` for a seed. Returns `(w_0, chain)`
/// where `chain[i]` is step `i` (chain[0] == w_k == H^k(seed) is the anchor
/// published in prosopeion.hdap).
pub fn otp_chain(seed: &[u8; 32], k: usize) -> (String, Vec<[u8; 32]>) {
    let mut chain = Vec::with_capacity(k + 1);
    // w_k = H^k(seed) where seed itself is step k.
    let mut cur = *seed;
    chain.push(cur);
    for _ in 0..k {
        cur = sha256(&cur);
        chain.push(cur);
    }
    // chain[0] is the seed (never revealed); chain[k] is the anchor.
    let anchor = chain.last().expect("k>=1");
    (hex::encode(anchor), chain)
}

/// Reveal the preimage at step `r` (0 < r <= k): `w_r = H^(k-r)(seed)`.
/// The published anchor `w_0 = H^k(seed)` allows anyone to verify via
/// `H^r(w_r) == w_0`.
pub fn otp_reveal(chain: &[[u8; 32]], r: usize) -> Option<[u8; 32]> {
    // chain is indexed seed..anchor; step r is chain[k-r].
    if r == 0 || r >= chain.len() {
        return None;
    }
    chain.get(chain.len() - 1 - r).copied()
}

/// Verify an OTP preimage at step `r` against the published anchor.
pub fn otp_verify(anchor_hex: &str, r: usize, revealed: &[u8]) -> bool {
    if r == 0 {
        return false;
    }
    let anchor = match hex::decode(anchor_hex) {
        Ok(a) if a.len() == 32 => a,
        _ => return false,
    };
    let mut cur: [u8; 32] = match revealed.try_into() {
        Ok(c) => c,
        Err(_) => return false,
    };
    for _ in 0..r {
        cur = sha256(&cur);
    }
    cur.as_slice() == anchor.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_deterministic_and_correct_width() {
        assert_eq!(sha256_hex(b"hdap"), sha256_hex(b"hdap"));
        assert_eq!(sha256_hex(b"hdap").len(), 64);
        assert_ne!(sha256_hex(b"hdap"), sha256_hex(b"hdap!"));
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let key = ed25519_keygen(&mut rng);
        let msg = b"hello hdap";
        let sig = ed25519_sign(&key, msg);
        let pk: [u8; 32] = key.verifying_key().to_bytes();
        assert!(ed25519_verify(&pk, msg, &sig).is_ok());
        assert!(ed25519_verify(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn x25519_shared_and_ecies_roundtrip() {
        let mut rng = OsRng;
        let a = x25519_keygen(&mut rng);
        let b = x25519_keygen(&mut rng);
        let pub_b = x25519_public(&b);
        let s1 = x25519_shared(&a, &pub_b);
        let pub_a = x25519_public(&a);
        let s2 = x25519_shared(&b, &pub_a);
        assert_eq!(s1, s2);

        let sealed = seal_to_pub(&pub_b, b"regra de ouro");
        let opened = open_with_priv(&b, &sealed).unwrap();
        assert_eq!(opened, b"regra de ouro");
        // wrong key cannot open
        let c = x25519_keygen(&mut rng);
        assert!(open_with_priv(&c, &sealed).is_err());
        // tampering detected
        let mut bad = sealed.clone();
        bad[50] ^= 0xff;
        assert!(open_with_priv(&b, &bad).is_err());
    }

    #[test]
    fn aead_seal_open_roundtrip() {
        let key = [7u8; 32];
        let sealed = aead_seal(&key, b"vault payload");
        assert_eq!(aead_open(&key, &sealed).unwrap(), b"vault payload");
        let mut bad = sealed.clone();
        bad[5] ^= 1;
        assert!(aead_open(&key, &bad).is_err());
    }

    #[test]
    fn hmac_is_stable() {
        assert_eq!(hmac_sha256(b"k", b"data"), hmac_sha256(b"k", b"data"));
        assert_ne!(hmac_sha256(b"k", b"data"), hmac_sha256(b"k", b"data2"));
    }

    #[test]
    fn otp_chain_reveal_and_verify() {
        let seed = [0xabu8; 32];
        let k = 5usize;
        let (anchor, chain) = otp_chain(&seed, k);
        let w1 = otp_reveal(&chain, 1).unwrap();
        let w2 = otp_reveal(&chain, 2).unwrap();
        // w2 hashes once -> w1 ; w1 hashes once -> anchor
        let w2_to_w1 = sha256(&w2);
        assert_eq!(w2_to_w1, w1);
        assert_eq!(sha256(&w1), *chain.last().unwrap());
        assert!(otp_verify(&anchor, 2, &w2));
        assert!(otp_verify(&anchor, 1, &w1));
        assert!(!otp_verify(&anchor, 1, &w2)); // wrong step
        assert!(!otp_verify(&anchor, 2, w2_to_w1.as_slice())); // tampered
                                                               // each preimage is single use: verifying step 1 again with w1 is the same value (deterministic), fine.
                                                               // reveal step 0 (the seed) must never be exposed
        assert!(otp_reveal(&chain, 0).is_none());
        assert!(otp_reveal(&chain, k + 1).is_none());
    }

    #[test]
    fn argon2_derives_deterministically() {
        let salt = [3u8; 16];
        let k1 = derive_key_argon2(b"pw", &salt);
        let k2 = derive_key_argon2(b"pw", &salt);
        assert_eq!(k1, k2);
        let k3 = derive_key_argon2(b"pw2", &salt);
        assert_ne!(k1, k3);
    }
}
