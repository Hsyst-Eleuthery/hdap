//! HDAP protocol primitives: document format, crypto, identity, pow,
//! adeia, metabibasis, prytaneion and pheme. No network I/O here; the
//! server and CLI crates consume this crate.

pub mod auth;
pub mod crypto;
pub mod doc;
pub mod identity;
pub mod pow;
pub mod protocol;
pub mod time;
pub mod uri;
pub mod vault;

/// Geração do protocolo. O formato dos documentos permanece `FORMAT_VERSION`
/// para compatibilidade; esta constante identifica a versão de interoperabilidade
/// anunciada por `/health` na v2 (Téleia vási / Teleios).
pub const PROTOCOL_VERSION: u64 = 2;
/// Nome legível da geração do protocolo.
pub const PROTOCOL_CODENAME: &str = "Teleios";

pub use auth::{
    derive_shared_key, prove_session_secret, session_token, verify_knowledge_bounded,
    verify_possession, AuthProof, Challenge, OtpWitness, SessionToken,
};
pub use crypto::{hkdf_sha256, seal_to_pub, sha256, sha256_hex, KDF_INFO_ECIES, KDF_INFO_OTP, KDF_INFO_SESSION, MAX_OTP_CHAIN_LEN};
pub use doc::{parse, Doc, DocType, ParseError, Signature, FORMAT_VERSION, MAGIC};
pub use identity::{Identity, IDENTITY_USER_PREFIX};
pub use pow::{solve_pow, verify_pow, PowProof};
pub use protocol::{
    adeia_doc_with_diadosi, house_move_payload, sig_to_b64, transfer_payload, DiadosiDoc,
    DiadosiMode, DiadosiPolicy, ExousiaDoc, MetabibasisDoc, MochthosDoc, PhemeCandidateDoc,
    PrytaneionDoc, SyncDoc, SyngrapheDoc, TimiDoc, TransferAcceptDoc, TransferRequestDoc,
    TransferTarget, TRANSFER_KIND_ACCEPT, TRANSFER_KIND_REQUEST, TRANSFER_TARGET_DIR,
    TRANSFER_TARGET_FILE, TRANSFER_TARGET_IDENTITY,
};
pub use time::{clock_skew_within, client_ts_matches, is_expired, unix_secs_utc};
pub use uri::parse_access_uri;
pub use vault::{Vault, VaultSecrets};
