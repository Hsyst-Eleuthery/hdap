//! Account recovery phrase.
//!
//! A recovery phrase encodes the 32-byte identity seed as 64 hexadecimal
//! characters. From those 32 bytes, the full HDAP identity (Ed25519 signing
//! key, X25519 encryption key, OTP anchor) is deterministically derived, so a
//! user who loses `krypte.hdap` can recreate their identity from the phrase
//! alone (plus the passphrase used to seal the recovered vault).
//!
//! The phrase is displayed once when an identity is created. It is never
//! stored by the node or by HDAP itself — only the user holds it.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Number of hex characters in a recovery phrase (32 bytes).
pub const RECOVERY_HEX_LEN: usize = 64;

/// A recovery phrase: 64 hex chars encoding 32 bytes of entropy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPhrase {
    /// The 64 hex chars.
    pub chars: String,
    /// The raw entropy (32 bytes), zeroized on drop.
    pub entropy: Zeroizing<[u8; 32]>,
}

impl RecoveryPhrase {
    /// Generate a new random recovery phrase using the OS CSPRNG.
    pub fn generate() -> (Self, [u8; 32]) {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let entropy_copy = entropy;
        let chars = hex::encode(entropy);
        let phrase = RecoveryPhrase {
            chars,
            entropy: Zeroizing::new(entropy_copy),
        };
        (phrase, entropy_copy)
    }

    /// Reconstruct a `RecoveryPhrase` from a 64-char hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, RecoveryError> {
        let trimmed = hex_str.trim();
        if trimmed.len() != RECOVERY_HEX_LEN {
            return Err(RecoveryError::WrongLength {
                expected: RECOVERY_HEX_LEN,
                found: trimmed.len(),
            });
        }
        let entropy = hex::decode(trimmed)
            .map_err(|_| RecoveryError::InvalidHex)?
            .try_into()
            .map_err(|_| RecoveryError::InvalidHex)?;
        Ok(RecoveryPhrase {
            chars: trimmed.to_string(),
            entropy: Zeroizing::new(entropy),
        })
    }

    /// Display the phrase as a hex string.
    pub fn phrase(&self) -> &str {
        &self.chars
    }

    /// Derive the Ed25519 signing key from the entropy.
    pub fn sign_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.entropy)
    }

    /// Derive the X25519 encryption secret from the entropy.
    pub fn enc_secret(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(*self.entropy)
    }

    /// Derive the OTP anchor and chain length from the entropy, mirroring
    /// `Identity::generate` (otp_k = 1024).
    pub fn otp_anchor_and_k(&self) -> (String, usize) {
        let otp_k = 1024usize;
        let (anchor, _) = crate::auth::make_otp_chain(&sha256_digest(&self.entropy), otp_k);
        (anchor, otp_k)
    }
}

impl Drop for RecoveryPhrase {
    fn drop(&mut self) {
        self.entropy.zeroize();
    }
}

/// Errors parsing a recovery phrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    WrongLength { expected: usize, found: usize },
    InvalidHex,
}

/// SHA-256 digest of 32 bytes.
fn sha256_digest(bytes: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_generate_and_parse() {
        let (phrase, _entropy) = RecoveryPhrase::generate();
        let parsed = RecoveryPhrase::from_hex(phrase.phrase()).expect("roundtrip parse");
        assert_eq!(parsed.chars, phrase.chars);
        assert_eq!(*parsed.entropy, *phrase.entropy);
    }

    #[test]
    fn wrong_length_is_rejected() {
        let err = RecoveryPhrase::from_hex("deadbeef").unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::WrongLength {
                expected: 64,
                found: 8
            }
        ));
    }

    #[test]
    fn invalid_hex_is_rejected() {
        let err = RecoveryPhrase::from_hex(&"z".repeat(64)).unwrap_err();
        assert!(matches!(err, RecoveryError::InvalidHex));
    }

    #[test]
    fn keys_are_deterministic() {
        let (p1, _) = RecoveryPhrase::generate();
        let p2 = RecoveryPhrase::from_hex(p1.phrase()).unwrap();
        assert_eq!(p1.sign_key().to_bytes(), p2.sign_key().to_bytes());
        assert_eq!(p1.enc_secret().to_bytes(), p2.enc_secret().to_bytes());
    }
}
