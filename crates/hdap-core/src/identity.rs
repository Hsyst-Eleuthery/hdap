//! Global identity: a single `nickname_<sufixo>` per user, independent of
//! any server, anchored in `prosopeion.hdap` (especificacao-hdap.md §3-§4).

use crate::crypto::{
    ed25519_keygen, otp_chain, x25519_keygen, x25519_public, CryptoError, CryptoResult,
};
use crate::doc::{Doc, DocType};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::StaticSecret;

/// This crate emits `nickname_<sufixo>`; the prefix is fixed for usability
/// but any `[a-zA-Z0-9_]` nickname is allowed by the spec.
pub const IDENTITY_USER_PREFIX: &str = "user";

/// Suffix length in hex chars (64 random bits).
pub const SUFFIX_HEX_LEN: usize = 16;

/// Longest nickname allowed before the `_suffix` (spec §3.1).
pub const NICKNAME_MAX: usize = 32;

/// Why a nickname was refused. Callers show this instead of a bare "invalid".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NicknameError {
    Empty,
    TooLong,
    BadChar(char),
    /// The input already carried a `_suffix`, i.e. it was a global id, not a
    /// bare nickname. Accepting it would make `jose_ab..` + `_cd..`.
    AlreadyAbsolute,
}

impl std::fmt::Display for NicknameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NicknameError::Empty => write!(f, "nickname vazio"),
            NicknameError::TooLong => write!(f, "nickname acima de {NICKNAME_MAX} caracteres"),
            NicknameError::BadChar(c) => write!(f, "caractere inválido {c:?} no nickname"),
            NicknameError::AlreadyAbsolute => write!(
                f,
                "isso já é um id absoluto (nickname_sufixo); use apenas o nickname"
            ),
        }
    }
}

impl std::error::Error for NicknameError {}

/// Fold a nickname to its canonical form: lowercased, accents transliterated,
/// whitespace turned into `_`, anything else outside `[a-z0-9_]` dropped, runs
/// of `_` collapsed, and leading/trailing `_` trimmed.
///
/// A space becoming `_` is deliberate: `José Lima` should read as
/// `jose_lima`, not `josecosta`. Collapsing keeps `José  Costa` and
/// `José_Lima` on the same account.
///
/// The result is what gets embedded in `nickname_suffix`, so two people who
/// type `José`, `jose` and `jose ` must land on the same account rather
/// than three unrelated ones.
pub fn normalize_nickname(raw: &str) -> String {
    let lowered = raw.trim().to_lowercase();
    let mut out = String::with_capacity(lowered.len());
    let mut last_us = true; // leading `_` is dropped
    for ch in lowered.chars() {
        // Fold the char, then treat any whitespace it produced as a separator.
        let folded = fold_char(ch);
        for f in folded.chars() {
            if f.is_ascii_alphanumeric() {
                out.push(f);
                last_us = false;
            } else if (f == '_' || f.is_whitespace()) && !last_us {
                out.push('_');
                last_us = true;
            }
            // everything else is dropped
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

/// Accent/case folding for the Latin-1 and Latin-Extended-A ranges that show
/// up in Brazilian and Spanish nicknames. Anything outside falls through.
fn fold_char(ch: char) -> String {
    const FOLD: &[(char, &str)] = &[
        ('á', "a"),
        ('à', "a"),
        ('ã', "a"),
        ('â', "a"),
        ('ä', "a"),
        ('é', "e"),
        ('è', "e"),
        ('ê', "e"),
        ('ë', "e"),
        ('í', "i"),
        ('ì', "i"),
        ('î', "i"),
        ('ï', "i"),
        ('ó', "o"),
        ('ò', "o"),
        ('õ', "o"),
        ('ô', "o"),
        ('ö', "o"),
        ('ú', "u"),
        ('ù', "u"),
        ('û', "u"),
        ('ü', "u"),
        ('ç', "c"),
        ('ñ', "n"),
    ];
    for (from, to) in FOLD {
        if ch == *from {
            return (*to).to_string();
        }
    }
    ch.to_string()
}

/// Normalize then validate a *bare* nickname (no `_suffix`).
///
/// Rejects an input that already looks like a global id, because appending a
/// second suffix would produce `jose_ab.._cd..` and break addressing.
pub fn canonical_nickname(raw: &str) -> Result<String, NicknameError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(NicknameError::Empty);
    }
    if parse_global_id(trimmed).is_some() {
        return Err(NicknameError::AlreadyAbsolute);
    }
    let norm = normalize_nickname(trimmed);
    if norm.is_empty() {
        return Err(NicknameError::Empty);
    }
    if norm.len() > NICKNAME_MAX {
        return Err(NicknameError::TooLong);
    }
    if let Some(c) = norm
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '_')
    {
        return Err(NicknameError::BadChar(c));
    }
    Ok(norm)
}

/// How the OTP chain root was derived, so the client can always rebuild the
/// correct chain from the stored anchor, regardless of derivation era.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OtpDerivation {
    /// v1/legacy: raw seed bytes as chain root.
    V1,
    /// v2/Teleios: SHA-256(signing key) as chain root.
    #[default]
    V2,
    /// Recovery phrase: HKDF(seed, "hdap:recovery:otp") as chain root.
    Recovery,
}

#[derive(Clone)]
pub struct Identity {
    pub nickname: String,
    pub suffix_hex: String,
    pub sign_key: SigningKey,
    pub enc_secret: StaticSecret,
    /// OTP chain length (k); chain[0] == seed, chain[k] == anchor.
    pub otp_k: usize,
    /// OTP anchor hex (published).
    pub otp_anchor: String,
    /// How the OTP chain root was derived.
    pub otp_derivation: OtpDerivation,
    /// OTP-chain root for recovery-phrase accounts. Present when the identity
    /// was created from a recovery phrase; used to rebuild the OTP chain at
    /// login without depending on the signing key.
    pub recovery_root: Option<[u8; 32]>,
    pub created_at: u64,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("global_id", &self.global_id())
            .field("otp_k", &self.otp_k)
            .field("sign_pubkey", &hex::encode(self.sign_pubkey()))
            .field("otp_derivation", &self.otp_derivation)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Identity {
    /// Generate a fresh identity from a provided seed (CSPRNG).
    ///
    /// `nickname` is stored verbatim: callers must pass it through
    /// [`canonical_nickname`] first so the `nickname_suffix` id is canonical.
    /// Use [`Identity::try_generate`] to get that check for free.
    pub fn generate(nickname: &str, created_at: u64) -> Identity {
        let mut rng = OsRng;
        let mut suffix = [0u8; 8];
        rng.fill_bytes(&mut suffix);
        let suffix_hex = hex::encode(suffix);

        let sign_key = ed25519_keygen(&mut rng);
        let enc_secret = x25519_keygen(&mut rng);
        let otp_k = 1024;
        let (anchor, _) = crate::auth::make_otp_chain(&sha256ed(&sign_key), otp_k);

        Identity {
            nickname: nickname.to_string(),
            suffix_hex,
            sign_key,
            enc_secret,
            otp_k,
            otp_anchor: anchor,
            otp_derivation: OtpDerivation::V2,
            recovery_root: None,
            created_at,
        }
    }

    /// Validate the nickname, then generate. The canonical form is what gets
    /// stored, so `José ` and `jose` produce the same `global_id()` shape.
    pub fn try_generate(nickname: &str, created_at: u64) -> Result<Identity, NicknameError> {
        Ok(Identity::generate(
            &canonical_nickname(nickname)?,
            created_at,
        ))
    }

    /// Rebuild an identity from a 64-byte BIP-39 recovery seed plus nickname.
    ///
    /// All key material is deterministically derived from `seed` with
    /// independent HKDF labels, so no key material is reused across roles:
    /// - suffix: first 8 hex of SHA-256(signing public key) — no seed bytes
    ///   are exposed
    /// - sign key: HKDF(seed, "hdap:recovery:sign") → Ed25519
    /// - enc secret: HKDF(seed, "hdap:recovery:enc") → X25519
    /// - OTP anchor: HKDF(seed, "hdap:recovery:otp") → chain, k = 1024
    pub fn from_seed(nickname: &str, created_at: u64, seed: &[u8; 64]) -> Identity {
        let hkdf_sign = Hkdf::<Sha512>::new(None, seed);
        let mut sign_key_material = [0u8; 32];
        hkdf_sign
            .expand(b"hdap:recovery:sign", &mut sign_key_material)
            .expect("HKDF expand always succeeds");
        let sign_key = ed25519_dalek::SigningKey::from_bytes(&sign_key_material);
        let suffix_hex = {
            let pk = sign_key.verifying_key().to_bytes();
            let digest = Sha256::digest(pk);
            hex::encode(&digest[..8])
        };

        let hkdf_enc = Hkdf::<Sha512>::new(None, seed);
        let mut enc_key_material = [0u8; 32];
        hkdf_enc
            .expand(b"hdap:recovery:enc", &mut enc_key_material)
            .expect("HKDF expand always succeeds");
        let enc_secret = x25519_dalek::StaticSecret::from(enc_key_material);

        let hkdf_otp = Hkdf::<Sha512>::new(None, seed);
        let mut otp_root = [0u8; 32];
        hkdf_otp
            .expand(b"hdap:recovery:otp", &mut otp_root)
            .expect("HKDF expand always succeeds");
        // The vault root is not stored on disk; the OTP root doubles as the
        // recovery root so factor 2 can be rebuilt at login from the vault.
        let otp_k = 1024;
        let (anchor, _) = crate::auth::make_otp_chain(&otp_root, otp_k);

        Identity {
            nickname: nickname.to_string(),
            suffix_hex,
            sign_key,
            enc_secret,
            otp_k,
            otp_anchor: anchor,
            otp_derivation: OtpDerivation::Recovery,
            recovery_root: Some(otp_root),
            created_at,
        }
    }

    /// Rebuild the identity from a `prosopeion.hdap` doc + local secrets.
    /// `recovery_root` is the optional OTP-chain root recovered from the vault;
    /// when present the account was created from a recovery phrase.
    pub fn from_doc(
        doc: &Doc,
        sign_key: SigningKey,
        enc_secret: StaticSecret,
        recovery_root: Option<[u8; 32]>,
    ) -> CryptoResult<Identity> {
        if doc.doc_type != DocType::Prosopeion {
            return Err(CryptoError::VerificationFailed);
        }
        let nickname = doc
            .body
            .get("NICKNAME")
            .ok_or(CryptoError::VerificationFailed)?
            .clone();
        let suffix_hex = doc
            .body
            .get("SUFFIX")
            .ok_or(CryptoError::VerificationFailed)?
            .clone();
        let otp_k: usize = doc
            .body
            .get("SEED_ITER")
            .ok_or(CryptoError::VerificationFailed)?
            .parse()
            .map_err(|_| CryptoError::VerificationFailed)?;
        let otp_anchor = doc
            .body
            .get("OMPHALOS")
            .ok_or(CryptoError::VerificationFailed)?
            .clone();

        // sanity: the doc's sign_pubkey matches the local private key
        let expected_pk = sign_key.verifying_key().to_bytes();
        let doc_pk_hex = doc
            .body
            .get("SIGN_PUBKEY")
            .ok_or(CryptoError::VerificationFailed)?;
        if hex::encode(expected_pk) != *doc_pk_hex {
            return Err(CryptoError::VerificationFailed);
        }

        let created_at = doc.created_at;
        let otp_derivation = if recovery_root.is_some() {
            OtpDerivation::Recovery
        } else {
            OtpDerivation::V2
        };
        Ok(Identity {
            nickname,
            suffix_hex,
            sign_key,
            enc_secret,
            otp_k,
            otp_anchor,
            otp_derivation,
            recovery_root,
            created_at,
        })
    }

    /// `nickname_<sufixo>`.
    pub fn global_id(&self) -> String {
        format!("{}_{}", self.nickname, self.suffix_hex)
    }

    /// Vault seed: SHA-256 of the signing public key. Used to seal the vault.
    pub fn seed(&self) -> [u8; 32] {
        sha256ed(&self.sign_key)
    }

    /// Build the public `prosopeion.hdap` document (canonical, unsigned).
    pub fn prosopeion_doc(&self) -> Doc {
        let mut d = Doc::new(DocType::Prosopeion, 1, None, self.created_at);
        d.body.insert("NICKNAME".into(), self.nickname.clone());
        d.body.insert("SUFFIX".into(), self.suffix_hex.clone());
        d.body.insert(
            "SIGN_PUBKEY".into(),
            hex::encode(self.sign_key.verifying_key().to_bytes()),
        );
        d.body.insert(
            "ENC_PUBKEY".into(),
            hex::encode(x25519_public(&self.enc_secret)),
        );
        d.body.insert("OMPHALOS".into(), self.otp_anchor.clone());
        d.body.insert("SEED_ITER".into(), self.otp_k.to_string());
        d.body.insert("CREATED".into(), self.created_at.to_string());
        d
    }

    /// The public `prosopeion.hdap`, self-signed by the identity's own key.
    ///
    /// The node verifies this signature: a brand-new identity therefore has to
    /// prove possession of the key it claims (no registering with someone
    /// else's `SIGN_PUBKEY`), and a rotation by an existing identity has to
    /// carry the *previous* key's signature as well (`sync_prosopeion`). The
    /// unsigned `prosopeion_doc` stays available for local rendering/editing.
    pub fn signed_prosopeion_doc(&self) -> Doc {
        use crate::doc::Signature;
        use base64::Engine as _;
        let mut d = self.prosopeion_doc();
        let mut sig = Signature {
            signer: self.global_id(),
            signer_pubkey: Some(hex::encode(self.sign_key.verifying_key().to_bytes())),
            signature: String::new(),
        };
        d.sigs.push(sig.clone());
        let input = d
            .signature_input(0)
            .expect("a freshly built prosopeion is signable");
        sig.signature = base64::engine::general_purpose::STANDARD
            .encode(self.sign_key.sign(input.as_bytes()).to_bytes());
        d.sigs[0].signature = sig.signature;
        d
    }

    /// Sign arbitrary protocol bytes with this identity's Ed25519 key.
    pub fn sign_bytes(&self, msg: &[u8]) -> [u8; 64] {
        self.sign_key.sign(msg).to_bytes()
    }

    /// Public signing key bytes (for verification at the server).
    pub fn sign_pubkey(&self) -> [u8; 32] {
        self.sign_key.verifying_key().to_bytes()
    }

    /// Public signing key as `VerifyingKey`.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.sign_key.verifying_key()
    }

    /// Encryption public key bytes.
    pub fn enc_pubkey(&self) -> [u8; 32] {
        x25519_public(&self.enc_secret)
    }

    /// Rebuild the OTP chain that matches this identity's published anchor.
    ///
    /// Tries each known derivation (V1 raw seed, V2 SHA-256(sign key)) and
    /// uses the one that reproduces the stored `otp_anchor`. This lets
    /// identities created under any derivation era keep logging in after an
    /// upgrade, and keeps the failure explicit when no derivation matches.
    pub fn otp_chain(&self) -> Vec<[u8; 32]> {
        self.otp_chain_for(self.otp_k)
    }

    /// Try each derivation root and return the chain whose anchor matches
    /// `self.otp_anchor`.
    /// Build the chain for a (possibly larger) `k`, using the derivation that
    /// reproduces the stored `otp_anchor`. Every derivation is tried; the
    /// recorded `otp_derivation` is only a hint.
    pub fn otp_chain_for(&self, k: usize) -> Vec<[u8; 32]> {
        let sign_key_root = sha256ed(&self.sign_key);
        let anchor = &self.otp_anchor;

        // Recovery-phrase accounts: try the OTP root first, since it is the
        // derivation that produced the anchor. Factor 2 stays independent of
        // factor 1 because the OTP root comes from HKDF(seed, "hdap:recovery:otp").
        if let Some(root) = self.recovery_root {
            if crate::auth::make_otp_chain(&root, self.otp_k)
                .0
                .eq_ignore_ascii_case(anchor)
            {
                return crate::auth::make_otp_chain(&root, k).1;
            }
        }

        // Try V2 first (the current default), then V1 (legacy raw seed).
        if crate::auth::make_otp_chain(&sign_key_root, self.otp_k)
            .0
            .eq_ignore_ascii_case(anchor)
        {
            return crate::auth::make_otp_chain(&sign_key_root, k).1;
        }
        if otp_chain(&sign_key_root, self.otp_k)
            .0
            .eq_ignore_ascii_case(anchor)
        {
            return otp_chain(&sign_key_root, k).1;
        }

        // No derivation matched: fall back to V2 so the failure stays
        // explicit (login will reject with "factor 2 failed").
        crate::auth::make_otp_chain(&sign_key_root, k).1
    }

    /// Published anchor for a rotated chain length.
    pub fn otp_anchor_for(&self, k: usize) -> String {
        self.otp_chain_for(k)
            .last()
            .map(hex::encode)
            .unwrap_or_default()
    }
}

fn sha256ed(key: &SigningKey) -> [u8; 32] {
    crate::crypto::sha256(&key.to_bytes())
}

/// Parse the global id `nickname_sufixo` into its parts.
pub fn parse_global_id(id: &str) -> Option<(&str, &str)> {
    let (nick, suffix) = id.rsplit_once('_')?;
    if suffix.len() != SUFFIX_HEX_LEN || !suffix.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some((nick, suffix))
}

#[cfg(test)]
mod tests {
    use crate::vault::{Vault, VaultSecrets};
    use crate::{Identity, RecoveryPhrase};
    use ed25519_dalek::SigningKey;
    use x25519_dalek::StaticSecret;

    /// The one rule that matters for addressing: a bare nickname must never
    /// be usable as if it were a global id, and spelling variants of the same
    /// name must collapse onto one account.
    #[test]
    fn a_bare_nickname_is_folded_to_one_spelling() {
        for (spelled, folded) in [
            ("José Lima", "jose_lima"),
            ("josé lima", "jose_lima"),
            ("  José   Lima  ", "jose_lima"),
            ("José_Lima", "jose_lima"),
            ("jose", "jose"),
            ("MARIA da Silva", "maria_da_silva"),
            ("joao123", "joao123"),
        ] {
            assert_eq!(normalize_nickname(spelled), folded, "from {spelled:?}");
        }
    }

    /// Punctuation and symbols must not become separators, or `jose!!` and
    /// `jose  ` would not agree.
    #[test]
    fn punctuation_never_becomes_a_separator() {
        for spelled in ["jose!!", "jose??", "jose...", "jose-", "jose"] {
            assert_eq!(normalize_nickname(spelled), "jose", "from {spelled:?}");
        }
    }

    /// An input that already carries a suffix is rejected by `canonical_nickname`
    /// rather than given a second one.
    #[test]
    fn a_global_id_is_never_double_suffixed() {
        let id = Identity::try_generate("José", 1_700_000_000).expect("generate");
        let gid = id.global_id();
        assert!(gid.contains('_'), "{gid:?}");
        assert_eq!(
            canonical_nickname(&gid),
            Err(NicknameError::AlreadyAbsolute),
            "the global id must come back unchanged, not jose_ab.._cd.."
        );
        // And the bare nickname is what normalizes, sans suffix.
        assert_eq!(normalize_nickname(&id.nickname), "jose");
    }
    use super::*;

    #[test]
    fn identity_global_id_and_properties_roundtrip() {
        let id = Identity::generate("jose", 1_700_000_000);
        let gid = id.global_id();
        assert!(gid.starts_with("jose_"));
        assert_eq!(gid.len(), "jose_".len() + SUFFIX_HEX_LEN);

        // canonical doc re-render stable
        let doc = id.prosopeion_doc();
        let text = doc.render();
        let back = crate::doc::parse(&text).unwrap();
        assert_eq!(back.render(), text);

        // rebuild identity from doc + keys
        let rebuilt = Identity::from_doc(
            &back,
            id.sign_key.clone(),
            StaticSecret::from(id.enc_secret.to_bytes()),
            None,
        )
        .unwrap();
        assert_eq!(rebuilt.global_id(), gid);
        assert_eq!(rebuilt.otp_anchor, id.otp_anchor);
    }

    /// A v1 account (raw-seed anchor) must still be able to log in after the
    /// server upgrades to Teleios: the client picks the derivation matching
    /// the published anchor instead of blindly applying HKDF.
    #[test]
    fn a_legacy_v1_otp_anchor_still_rebuilds_a_verifiable_chain() {
        let mut id = Identity::generate("jose", 1_700_000_000);
        let (legacy_anchor, legacy_chain) = otp_chain(&sha256ed(&id.sign_key), id.otp_k);
        id.otp_anchor = legacy_anchor;

        let rebuilt = id.otp_chain();
        assert_eq!(rebuilt, legacy_chain);
        let witness = crate::auth::prove_knowledge(&rebuilt, 7).expect("witness");
        assert!(crate::auth::verify_knowledge_bounded(
            &id.otp_anchor,
            &witness,
            id.otp_k
        ));
    }

    /// End-to-end recovery: create an identity from a recovery phrase, seal the
    /// vault, reload it, and prove the OTP chain is still verifiable. This
    /// exercises the full recovery path a user follows after losing krypte.hdap.
    #[test]
    fn recovery_phrase_roundtrip_rebuilds_identity_and_otp_chain() {
        let (phrase, seed) = RecoveryPhrase::generate();
        let words = phrase.words_only();

        // 1. Create identity from the recovery phrase.
        let id = Identity::from_seed("recover_test", 1_700_000_000, &seed);
        assert_eq!(id.otp_derivation, OtpDerivation::Recovery);
        assert!(id.recovery_root.is_some());

        // 2. Seal the vault as identity_store::save would.
        let secrets = VaultSecrets {
            seed: id.seed(),
            sign_secret: id.sign_key.to_bytes(),
            enc_secret: id.enc_secret.to_bytes(),
            recovery_root: id.recovery_root,
        };
        let vault = Vault::seal(&secrets, b"passphrase");
        let raw = vault.to_bytes();

        // 3. Reload the vault as identity_store::load would.
        let re_vault = Vault::from_bytes(&raw).unwrap();
        let re_secrets = re_vault.open(b"passphrase").unwrap();
        let doc = id.prosopeion_doc();
        let re_id = Identity::from_doc(
            &doc,
            SigningKey::from_bytes(&re_secrets.sign_secret),
            StaticSecret::from(re_secrets.enc_secret),
            re_secrets.recovery_root,
        )
        .unwrap();

        // 4. Identity must be identical.
        assert_eq!(re_id.global_id(), id.global_id());
        assert_eq!(re_id.sign_pubkey(), id.sign_pubkey());
        assert_eq!(re_id.enc_pubkey(), id.enc_pubkey());
        assert_eq!(re_id.otp_anchor, id.otp_anchor);
        assert_eq!(re_id.otp_derivation, OtpDerivation::Recovery);

        // 5. OTP chain must be rebuildable from the vault root and produce a
        //    verifiable witness.
        let chain = re_id.otp_chain();
        let witness = crate::auth::prove_knowledge(&chain, 7).expect("witness");
        assert!(crate::auth::verify_knowledge_bounded(
            &re_id.otp_anchor,
            &witness,
            re_id.otp_k
        ));

        // 6. The recovery phrase must round-trip through parsing.
        let re_phrase = RecoveryPhrase::from_words(&words).unwrap();
        assert_eq!(re_phrase.phrase(), phrase.phrase());
    }

    #[test]
    fn parse_global_id_validates_suffix() {
        let id = Identity::generate("jose", 1);
        let gid = id.global_id();
        let (nick, suffix) = parse_global_id(&gid).unwrap();
        assert_eq!(nick, "jose");
        assert_eq!(suffix.len(), 16);
        assert!(parse_global_id("jose_xyz").is_none()); // suffix length
        assert!(parse_global_id("x_y_zzz").is_none()); // not hex / wrong len
    }

    #[test]
    fn distinct_suffixes_for_distinct_ids() {
        let a = Identity::generate("jose", 1);
        let b = Identity::generate("jose", 1);
        assert_ne!(a.suffix_hex, b.suffix_hex);
    }
}
