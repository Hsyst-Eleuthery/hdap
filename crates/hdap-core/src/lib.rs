//! HDAP protocol primitives: document format, crypto, identity, pow,
//! adeia, metabibasis, prytaneion and pheme. No network I/O here; the
//! server and CLI crates consume this crate.

pub mod auth;
pub mod crypto;
pub mod doc;
pub mod identity;
pub mod pow;
pub mod protocol;
pub mod uri;
pub mod vault;

pub use auth::{session_token, verify_possession, AuthProof, Challenge, SessionToken};
pub use crypto::{seal_to_pub, sha256, sha256_hex};
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
pub use uri::parse_access_uri;
pub use vault::{Vault, VaultSecrets};
