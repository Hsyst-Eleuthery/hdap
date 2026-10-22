//! Node state: users, sessions, choregia, content, `prytaneion`, TCD, DNS
//! and federation peers.
//!
//! This type is the *working copy* the protocol logic mutates, guarded by a
//! single lock in `Node`. It is not the system of record anymore: `db.rs`
//! mirrors every collection into SQLite and reloads it on boot. Keeping the
//! in-memory map means the hot path stays allocation-cheap while the archive
//! survives a restart.

use std::collections::{BTreeMap, VecDeque};

pub use hdap_core::doc::Doc;

/// A registered user: public identity facts only (especificacao §7).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserRecord {
    pub user_id: String,
    pub nickname: String,
    pub suffix_hex: String,
    pub sign_pub_hex: String,
    pub enc_pub_hex: String,
    pub otp_anchor_hex: String,
    pub otp_k: usize,
    pub created_at: u64,
    /// Current home pyle. Empty on legacy records and on identities that have
    /// never moved; readers treat empty as "this pyle". A relayed house move
    /// writes the *new* home here, so a third pyle that only saw the signed
    /// move knows where the blobs actually live instead of mistaking its stub
    /// for the complete namespace.
    #[serde(default)]
    pub home_pyle: String,
}

impl UserRecord {
    pub fn sign_pub_bytes(&self) -> Option<[u8; 32]> {
        let raw = hex::decode(&self.sign_pub_hex).ok()?;
        raw.try_into().ok()
    }

    pub fn enc_pub_bytes(&self) -> Option<[u8; 32]> {
        let raw = hex::decode(&self.enc_pub_hex).ok()?;
        raw.try_into().ok()
    }
}

/// A live session token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub user_id: String,
    pub exp: u64,
}

/// A rolling band-grant window: how much band this account was granted, and
/// when the window began. `granted` is server state and is the reason a
/// proof-of-work bypass is not worth anything.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BandWindow {
    /// Unix seconds when the current window opened.
    pub started_at: u64,
    /// Band granted inside the current window, in bytes.
    pub granted: u64,
}

/// One-armed challenge record (factor 1), consumed after use (anti-replay).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProklesisRecord {
    pub user_id: String,
    pub ts: u64,
    pub expires_at: u64,
}

/// A stored content blob (integrity hash plus bytes).
///
/// The bytes are deliberately **not** serialized into the metadata dump:
/// the persistence layer puts them in their own `blobs` table keyed by
/// namespace_owner/path, so rewriting a user's `adeia.hdap` never rewrites a
/// 100 MB upload sitting in the same space.
///
/// `owner` here means **namespace_owner** — the user whose `HDAP$/<owner>/`
/// directory contains this blob. It is *not* necessarily the content author
/// (which is carried by `X-HDAP-Sphragis` and recorded in `prytaneion` as
/// `origin_user`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    /// Namespace owner: the user whose storage space holds this blob.
    pub owner: String,
    pub path: String,
    pub hash: String,
    pub bytes: Vec<u8>,
}

/// Matrix entry tracking replicas and deletions for a content hash (§10).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrytaneionEntry {
    pub content_hash: String,
    pub origin_server: String,
    pub origin_user: String,
    /// Author's Ed25519 signing public key (hex), so a replica can still verify
    /// the `sphragis` after the origin pyle is gone.
    #[serde(default)]
    pub origin_user_pubkey: String,
    /// Original path, used to name the cached copy locally.
    #[serde(default)]
    pub origin_path: String,
    /// Base64 Ed25519 signature over the plaintext bytes, captured at upload.
    #[serde(default)]
    pub sphragis: String,
    pub replicas: Vec<String>,
    pub deletions: Vec<String>,
    pub created_at: u64,
}

/// A federated peer we have handshaken with. Membership is provisioned out of
/// band (pinned `node_id -> pubkey` allowlist), not first-come TOFU.
///
/// `endpoint` is the peer's host:port for outbound replication dialing.
/// `tls_pin` is the SHA-256 of the peer's TLS cert DER (for pinning).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerRecord {
    pub node_id: String,
    pub sign_pub_hex: String,
    pub endpoint: String,
    pub tls_pin: Option<String>,
}

/// A local mirror of a remote user's namespace.
///
/// Created by the on-demand pull-through (`POST /resolve` in `node/mirror.rs`):
/// when a `HDAP!<pyle>@<user>/<path>` URI names another node, the local node
/// copies the whole namespace of `<user>` from that pyle and serves it from
/// here. `origin_pyle` is the pyle the bytes came from, `origin_server` the
/// node that authored them (usually the same), and `pulled_at` is when the
/// local mirror was written. A mirrored namespace is read-only: the local
/// author is not the owner, so `authorize` already refuses writes to it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MirrorOrigin {
    /// Pyle the namespace was pulled from (`server_id` of the remote node).
    pub origin_pyle: String,
    /// Origin server recorded in `prytaneion` for the mirrored content.
    pub origin_server: String,
    /// Node-clock timestamp of the pull.
    pub pulled_at: u64,
}

/// One `metabibasis` cession: the cedente keeps read-only on `path`, forever.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cession {
    /// Who received the path.
    pub to: String,
    /// The cedente's path that was given away (as it was at cession time).
    pub path: String,
    /// When the cession was recorded (node clock).
    pub at: u64,
}

/// A live band object: the `.hdap.pow` the client countersigned, and the
/// `syngraphe` treaties that replace it as the band is spent (§10, §9.4).
///
/// This is the object the prompt asks to live in plain sight (`pow/1.hdap.pow`)
/// and to be *consumed* by uploads, instead of a bare integer the client can
/// never see, show to a peer, or audit. `id` is the hash of the original proof
/// document and stays stable across the pow → syngraphe replacement, so a
/// treaty always cites the same handle even after the `.pow` file is gone.
///
/// `owner` = **namespace_owner** (the user whose band this is). `issuer` is
/// the node that minted the proof (`ISSUER` in the doc). The `countersigned`
/// flag means the namespace_owner dual-signed the band object, making it
/// spendable for their own uploads.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BandObject {
    /// Stable handle: `sha256` of the original `.hdap.pow` render.
    pub id: String,
    /// Namespace owner: the user whose band this is.
    pub owner: String,
    /// Path of the document currently representing this band
    /// (`pow/N.hdap.pow` while untouched, `pow/N.hdap.syngraphe` once spent).
    pub path: String,
    /// Challenge carried by the original proof (lets a peer recompute it).
    pub challenge: String,
    /// Bytes granted by the issuer.
    pub granted: u64,
    /// Bytes still spendable from this object.
    pub remaining: u64,
    /// Issuer-side expiry (unix seconds).
    pub expires_at: u64,
    /// True once the owner countersigned the proof. Band is spendable only
    /// after the dual signature exists — a server-only proof would let the
    /// issuer mint band the owner never agreed to.
    pub countersigned: bool,
}

/// One asset in a transfer manifest, as stored by the node. Mirrors
/// `hdap_core::TransferTarget` but is persisted and serde-friendly.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransferAsset {
    pub source: String,
    pub dest: String,
    pub hash: String,
    pub size: u64,
}

/// A pending or completed ownership transfer (`metabibasis`).
///
/// The signed request/accept documents are kept verbatim so any node can
/// re-verify the chain; the parsed fields exist for authorization and
/// persistence, never as a replacement for the documents.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransferRecord {
    pub request_id: String,
    pub request_doc: String,
    pub request_hash: String,
    pub old_owner: String,
    pub new_owner: String,
    pub old_nickname: String,
    pub new_nickname: String,
    pub old_uri: String,
    pub new_uri: String,
    pub old_pyle: String,
    pub new_pyle: String,
    pub old_owner_pubkey: String,
    pub new_owner_pubkey: String,
    pub old_pyle_pubkey: String,
    pub new_pyle_pubkey: String,
    pub old_pyle_tls_pin: String,
    pub new_pyle_tls_pin: String,
    pub target_kind: String,
    /// Paths the cession covers (whole directory, single file, or `""` for
    /// an identity). Older records may lack it; authorization then falls back
    /// to the individual asset sources.
    #[serde(default)]
    pub scopes: Vec<String>,
    pub assets: Vec<TransferAsset>,
    pub created_at: u64,
    /// `pending`, `accepted` or `completed`.
    pub status: String,
    pub accept_doc: Option<String>,
    pub accept_hash: Option<String>,
    pub record_path: Option<String>,
}

impl TransferRecord {
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }
}

/// All mutable node state, guarded by a single lock in `Node`.
#[derive(Default)]
pub struct State {
    /// Per-node master key for at-rest blob encryption (ChaCha20-Poly1305).
    pub master_key: [u8; 32],
    /// The node's Ed25519 signing seed. Persisted because the node *signs*
    /// documents (`.hdap.pow`, `syngraphe`, `apographon`): a fresh seed on
    /// every boot would make every document this node ever issued
    /// unverifiable, which would quietly break band across a restart.
    pub node_sign_seed: [u8; 32],
    /// Node identity (mirror of `Config::server_id`).
    pub whoami: String,
    pub users: BTreeMap<String, UserRecord>,
    /// token -> session.
    pub sessions: BTreeMap<String, Session>,
    /// challenge nonce -> record (consumed on use).
    pub proklesis: BTreeMap<String, ProklesisRecord>,
    /// user_id -> highest OTP step already accepted (replay guard).
    pub omphalos_step: BTreeMap<String, usize>,
    /// user_id -> credited band bytes (not yet consumed).
    pub choregia: BTreeMap<String, u64>,
    /// band object id -> live `.hdap.pow` / `syngraphe` grant. This is the
    /// durable, client-visible record of band; `choregia` is the fast integer
    /// mirror used on the hot upload path.
    pub band_objects: BTreeMap<String, BandObject>,
    /// user_id -> rolling band grant window. This is what caps how fast a
    /// client can turn CPU (or the absence of it) into storage.
    pub band_windows: BTreeMap<String, BandWindow>,
    /// user_id -> bytes stored on this node (moira quota usage).
    pub stored: BTreeMap<String, u64>,
    /// challenge|nonce already credited (single-use per issuer node; avoids
    /// replaying the same proof-of-work to farm band).
    pub mochthos_used: std::collections::BTreeSet<String>,
    /// user/dir joined -> blob.
    pub objects: BTreeMap<String, Blob>,
    /// content hash -> `prytaneion` entry.
    pub prytaneion: BTreeMap<String, PrytaneionEntry>,
    /// target_id -> score in the distributed trust table.
    pub pheme: BTreeMap<String, i64>,
    /// user_id -> published permissions doc text.
    pub permissions: BTreeMap<String, String>,
    /// `ceessions[cedente] = [(cessionário, path alvo)]`: the read-only keeps
    /// a `metabibasis` grants the cedente (§11.3 "read-only garantido e
    /// irrevogável"). Kept outside `permissions` because it is NOT a document
    /// the owner can edit: a later `adeia` edition must never be able to buy
    /// back write access to a path already given away.
    pub ceessions: BTreeMap<String, Vec<Cession>>,
    /// alias -> URI (DDNS §13).
    pub kerux: BTreeMap<String, String>,
    /// alias -> user_id who owns it (so editing `kerux.hdap` can re-index
    /// only that user's aliases instead of guessing the delimiter).
    pub kerux_owner: BTreeMap<String, String>,
    /// pyle id -> rendered `timi.hdap` doc text (§16, optional katallaxia).
    pub timi: BTreeMap<String, String>,
    /// node_id -> peer record.
    pub peers: BTreeMap<String, PeerRecord>,
    /// `<owner>/<path>` -> the `adeia` text that was in force when the replica
    /// was pulled. Replicas keep serving old *public* content by that snapshot
    /// even after the owner publishes a newer `adeia` (or the origin pyle is
    /// gone); the origin's current `permissions` still governs new content.
    pub replica_acls: BTreeMap<String, String>,
    /// namespace_owner -> local mirror of that owner's remote space. The book
    /// of pull-through copies: a mirrored owner's blobs live under
    /// `objects["<owner>/..."]` exactly like local content, and this records
    /// where they came from (so the space is known to be a replica, and a
    /// re-resolve can tell "already local" from "needs pulling").
    pub mirrors: BTreeMap<String, MirrorOrigin>,
    /// namespace_owner -> node ids that pulled that owner's namespace from us.
    /// The origin is the authority for deletions, but it cannot dial peers it
    /// has never heard of: this records who holds a replica so a delete can be
    /// pushed to every one of them (and cascaded by mirrors).
    pub watchers: BTreeMap<String, std::collections::BTreeSet<String>>,
    /// fed nonce -> ts (replay window guard).
    pub fed_nonces: BTreeMap<String, u64>,
    /// Federated op ids already applied (`pheme`/`prytaneion` updates), kept
    /// *apart* from `fed_nonces`: the replay window prunes by age, but
    /// idempotency must hold forever or a peer could re-apply the same
    /// reputation bump or deletion after the window elapses.
    pub fed_applied: std::collections::BTreeSet<String>,
    /// per-peer rate limiter: node_id or ip -> request timestamps.
    pub rate: BTreeMap<String, VecDeque<u64>>,
    /// request_id -> transfer request/acceptance. This is node-level state,
    /// not a map a user can edit: an `adeia` rewrite must never resurrect
    /// write access or erase the proof that a transfer happened.
    pub transfers: BTreeMap<String, TransferRecord>,
}

impl State {
    pub fn key(user: &str, path: &str) -> String {
        format!("{user}/{path}")
    }
}
