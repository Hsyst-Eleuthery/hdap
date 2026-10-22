//! Global identity: a single `nickname_<sufixo>` per user, independent of
//! any server, anchored in `prosopeion.hdap` (especificacao-hdap.md §3-§4).

use crate::crypto::{
    ed25519_keygen, otp_chain, x25519_keygen, x25519_public, CryptoError, CryptoResult,
};
use crate::doc::{Doc, DocType};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
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
    pub created_at: u64,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("global_id", &self.global_id())
            .field("otp_k", &self.otp_k)
            .field("sign_pubkey", &hex::encode(self.sign_pubkey()))
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
        let (anchor, _) = otp_chain(&sha256ed(&sign_key), otp_k);

        Identity {
            nickname: nickname.to_string(),
            suffix_hex,
            sign_key,
            enc_secret,
            otp_k,
            otp_anchor: anchor,
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

    /// Rebuild the identity from a `prosopeion.hdap` doc + local secrets.
    pub fn from_doc(
        doc: &Doc,
        sign_key: SigningKey,
        enc_secret: StaticSecret,
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
        Ok(Identity {
            nickname,
            suffix_hex,
            sign_key,
            enc_secret,
            otp_k,
            otp_anchor,
            created_at,
        })
    }

    /// `nickname_<sufixo>`.
    pub fn global_id(&self) -> String {
        format!("{}_{}", self.nickname, self.suffix_hex)
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
        )
        .unwrap();
        assert_eq!(rebuilt.global_id(), gid);
        assert_eq!(rebuilt.otp_anchor, id.otp_anchor);
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
