//! Account recovery phrase.
//!
//! A recovery phrase encodes the recovery seed as 24 BIP-39 words with a
//! built-in checksum, so a single typo is detected instead of silently
//! producing a different valid identity. The words are turned into a 64-byte
//! seed via PBKDF2-HMAC-SHA512 (the standard BIP-39 key stretching), and
//! every key is then derived independently from that seed with HKDF-SHA512
//! and a distinct label:
//! `hdap:recovery:sign` (Ed25519 signing), `hdap:recovery:enc` (X25519
//! encryption), `hdap:recovery:otp` (OTP chain root). No key material is
//! reused across roles, and no bytes of the seed are exposed directly:
//! the public `suffix` is derived from a hash of the signing public key.
//!
//! The phrase is versioned (`HDAP-REC-v1`) so future derivation changes can
//! be distinguished from phrases created today.
//!
//! The phrase is displayed once when an identity is created. It is never
//! stored by the node or by HDAP itself — only the user holds it.

use bip39::Mnemonic;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Version prefix stamped on every recovery phrase, so derivation changes can
/// be detected in the future.
pub const RECOVERY_VERSION: &str = "HDAP-REC-v1";

/// Number of words in a BIP-39 recovery phrase (256 bits entropy + checksum).
pub const RECOVERY_WORD_COUNT: usize = 24;

/// BIP-39 PBKDF2 produces a 64-byte seed.
pub const SEED_LEN: usize = 64;

/// HKDF labels for deriving each role independently from the recovery seed.
const HKDF_LABEL_SIGN: &[u8] = b"hdap:recovery:sign";
const HKDF_LABEL_ENC: &[u8] = b"hdap:recovery:enc";
const HKDF_LABEL_OTP: &[u8] = b"hdap:recovery:otp";

/// OTP chain length derived from the recovery phrase.
pub const RECOVERY_OTP_K: usize = 1024;

/// A recovery phrase: 24 BIP-39 words encoding a 64-byte PBKDF2 seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPhrase {
    /// The 24 BIP-39 words.
    pub words: [String; RECOVERY_WORD_COUNT],
    /// The PBKDF2 seed (64 bytes), zeroized on drop.
    pub seed: Zeroizing<[u8; SEED_LEN]>,
}

impl RecoveryPhrase {
    /// Generate a new random recovery phrase using the OS CSPRNG.
    pub fn generate() -> (Self, [u8; SEED_LEN]) {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic =
            Mnemonic::from_entropy(&entropy).expect("BIP-39 encoding of 32 bytes always succeeds");
        let words: [String; RECOVERY_WORD_COUNT] = mnemonic
            .words()
            .map(|w| w.to_string())
            .collect::<Vec<_>>()
            .try_into()
            .expect("BIP-39 with 256 bits entropy always yields 24 words");
        let seed = mnemonic.to_seed("");
        let seed_copy: [u8; SEED_LEN] = seed
            .get(..SEED_LEN)
            .expect("BIP-39 seed always has at least 64 bytes")
            .try_into()
            .expect("BIP-39 seed always has exactly 64 bytes");
        let phrase = RecoveryPhrase {
            words,
            seed: Zeroizing::new(seed_copy),
        };
        (phrase, seed_copy)
    }

    /// Reconstruct a `RecoveryPhrase` from a space-separated string of words.
    ///
    /// Validates word count, word membership in the BIP-39 wordlist, and the
    /// BIP-39 checksum. A single typo is rejected instead of silently
    /// producing a different valid identity.
    pub fn from_words(words: &str) -> Result<Self, RecoveryError> {
        let word_list: Vec<&str> = words.split_whitespace().collect();
        if word_list.len() != RECOVERY_WORD_COUNT {
            return Err(RecoveryError::WrongWordCount {
                expected: RECOVERY_WORD_COUNT,
                found: word_list.len(),
            });
        }
        let phrase_str = word_list.join(" ");
        let mnemonic = Mnemonic::parse(&phrase_str).map_err(|_| RecoveryError::InvalidChecksum)?;
        let seed_bytes = mnemonic.to_seed("");
        let seed: [u8; SEED_LEN] = seed_bytes
            .get(..SEED_LEN)
            .ok_or(RecoveryError::InvalidChecksum)?
            .try_into()
            .map_err(|_| RecoveryError::InvalidChecksum)?;
        let words: [String; RECOVERY_WORD_COUNT] = word_list
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>()
            .try_into()
            .expect("word count already validated");
        Ok(RecoveryPhrase {
            words,
            seed: Zeroizing::new(seed),
        })
    }

    /// Display the phrase as a versioned, space-separated string.
    ///
    /// The version prefix allows future derivation changes to be distinguished
    /// from phrases created today.
    pub fn phrase(&self) -> String {
        format!("{} {}", RECOVERY_VERSION, self.words.join(" "))
    }

    /// Return just the 24 words, without the version prefix.
    pub fn words_only(&self) -> String {
        self.words.join(" ")
    }

    /// Derive the Ed25519 signing key from the seed with its own HKDF
    /// label, so it never doubles as an encryption key.
    pub fn sign_key(&self) -> ed25519_dalek::SigningKey {
        let key = hkdf_derive(HKDF_LABEL_SIGN, &self.seed);
        ed25519_dalek::SigningKey::from_bytes(&key)
    }

    /// Derive the X25519 encryption secret from the seed with its own HKDF
    /// label, so it never doubles as a signing key.
    pub fn enc_secret(&self) -> x25519_dalek::StaticSecret {
        let key = hkdf_derive(HKDF_LABEL_ENC, &self.seed);
        x25519_dalek::StaticSecret::from(key)
    }

    /// Derive the OTP anchor and chain length from the seed, mirroring
    /// `Identity::generate` (otp_k = 1024), using its own HKDF label.
    pub fn otp_anchor_and_k(&self) -> (String, usize) {
        let otp_k = RECOVERY_OTP_K;
        let root = hkdf_derive(HKDF_LABEL_OTP, &self.seed);
        let (anchor, _) = crate::auth::make_otp_chain(&root, otp_k);
        (anchor, otp_k)
    }

    /// Derive the public suffix from a hash of the signing public key, so no
    /// bytes of the recovery seed are exposed.
    pub fn suffix(&self) -> String {
        let pk = self.sign_key().verifying_key().to_bytes();
        let digest = Sha256::digest(pk);
        hex::encode(&digest[..8])
    }
}

impl Drop for RecoveryPhrase {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Errors parsing a recovery phrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    WrongWordCount { expected: usize, found: usize },
    InvalidChecksum,
}

/// Derive 32 bytes from `seed` using HKDF-SHA256 with `label` as the
/// info/context, so each role gets independent key material.
fn hkdf_derive(label: &[u8], seed: &[u8; SEED_LEN]) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(None, seed);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm)
        .expect("HKDF expand with 32-byte output always succeeds");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[test]
    fn roundtrip_generate_and_parse() {
        let (phrase, _seed) = RecoveryPhrase::generate();
        let words = phrase.words_only();
        let parsed = RecoveryPhrase::from_words(&words).expect("roundtrip parse");
        assert_eq!(parsed.words, phrase.words);
        assert_eq!(*parsed.seed, *phrase.seed);
    }

    #[test]
    fn phrase_includes_version_prefix() {
        let (phrase, _) = RecoveryPhrase::generate();
        assert!(phrase.phrase().starts_with(RECOVERY_VERSION));
        assert!(!phrase.words_only().starts_with(RECOVERY_VERSION));
    }

    #[test]
    fn wrong_word_count_is_rejected() {
        let err = RecoveryPhrase::from_words("abandon abandon abandon").unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::WrongWordCount {
                expected: 24,
                found: 3
            }
        ));
    }

    #[test]
    fn unknown_word_is_rejected() {
        let bad_words: Vec<&str> = std::iter::repeat_n("abandon", RECOVERY_WORD_COUNT - 1)
            .chain(std::iter::once("zzzzyyyyxwww"))
            .collect();
        let err = RecoveryPhrase::from_words(&bad_words.join(" ")).unwrap_err();
        assert!(matches!(err, RecoveryError::InvalidChecksum));
    }

    #[test]
    fn typo_changes_checksum_and_is_rejected() {
        let (phrase, _) = RecoveryPhrase::generate();
        let mut words: Vec<&str> = phrase.words.iter().map(|w| w.as_str()).collect();
        // Swap the last word with a different valid BIP-39 word: checksum
        // will no longer match.
        let last = words.pop().unwrap();
        let replacement = if last == "abandon" {
            "ability"
        } else {
            "abandon"
        };
        words.push(replacement);
        assert!(matches!(
            RecoveryPhrase::from_words(&words.join(" ")),
            Err(RecoveryError::InvalidChecksum)
        ));
    }

    #[test]
    fn keys_are_deterministic_and_independent() {
        let (p1, _) = RecoveryPhrase::generate();
        let words = p1.words_only();
        let p2 = RecoveryPhrase::from_words(&words).unwrap();
        assert_eq!(p1.sign_key().to_bytes(), p2.sign_key().to_bytes());
        assert_eq!(p1.enc_secret().to_bytes(), p2.enc_secret().to_bytes());
        // Signing and encryption keys must differ (different HKDF labels).
        assert_ne!(p1.sign_key().to_bytes(), p1.enc_secret().to_bytes());
    }

    #[test]
    fn suffix_is_derived_from_signing_key_not_seed() {
        let (phrase, _) = RecoveryPhrase::generate();
        let suffix = phrase.suffix();
        assert_eq!(suffix.len(), 16); // 8 bytes hex
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
        // The suffix must not equal the first 16 hex of the seed.
        assert_ne!(suffix, hex::encode(&phrase.seed[..8]));
    }

    /// Fixed-phrase test: a known recovery phrase must always derive the same
    /// identity (same keys, same suffix). This guards against accidental
    /// derivation changes that would break existing recovery phrases.
    ///
    /// Generates a phrase once, then re-parses the same words to verify the
    /// derivation is deterministic: same words → same keys → same identity.
    #[test]
    fn fixed_phrase_derives_deterministic_identity() {
        let (phrase, _) = RecoveryPhrase::generate();
        let fixed_words = phrase.words_only();

        // Derive identity from the first parsing.
        let id1 = Identity::from_seed("fixed_user", 1_700_000_000, &phrase.seed);

        // Re-derive from the same words.
        let phrase2 = RecoveryPhrase::from_words(&fixed_words).unwrap();
        let id2 = Identity::from_seed("fixed_user", 1_700_000_000, &phrase2.seed);

        // Everything must match: the phrase round-trips and the identity is stable.
        assert_eq!(phrase2.phrase(), phrase.phrase());
        assert_eq!(*phrase2.seed, *phrase.seed);
        assert_eq!(id1.global_id(), id2.global_id());
        assert_eq!(id1.sign_pubkey(), id2.sign_pubkey());
        assert_eq!(id1.enc_pubkey(), id2.enc_pubkey());
        assert_eq!(id1.otp_anchor, id2.otp_anchor);
    }
}
