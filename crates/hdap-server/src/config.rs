//! Server configuration (per-node policy).

pub use hdap_core::pow::PowPolicy;

/// A pre-provisioned federation peer (optional out-of-band pin).
///
/// Federation is open by design: any node may handshake and is trusted for its
/// own id after the key it presents is pinned on first contact. This map lets an
/// operator *strengthen* that by pre-pinning `node_id -> pubkey` and an endpoint
/// out of band, so a later caller cannot claim the id with another key. The
/// `pubkey` is the peer's *persistent* Ed25519 verifying key (the
/// `node_sign_pub` it publishes on `/health` and signs federation documents
/// with). `endpoint` is `host:port`; `tls_pin` is the SHA-256 of the peer's
/// cert DER, required for any non-loopback dialing (AME-37) so replicated
/// plaintext never travels in the clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPeer {
    pub pubkey: String,
    pub endpoint: String,
    pub tls_pin: Option<String>,
}

/// Per-node configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Unique node identifier (also root HMAC label for sessions).
    pub server_id: String,
    /// Bytes of storage band credited per accepted proof-of-work.
    pub choregia_per_mochthos: u64,
    /// Session lifetime in seconds.
    pub session_ttl_secs: u64,
    /// Factor-1 challenge lifetime in seconds.
    pub proklesis_ttl_secs: u64,
    /// Whether an entry proof-of-work is required on every login.
    pub require_entry_pow: bool,
    /// Whether `/ktema` uploads must carry an Ed25519 signature by the
    /// authenticated uploader over the raw bytes (`x-hdap-sphragis`). On by
    /// default: the golden rule is that every `ktema` has a `sphragis`, and a
    /// hash alone only proves integrity, never authorship. Tests that are not
    /// about authorship turn it off.
    pub require_content_signature: bool,
    /// Leading-zero bits for the entry proof-of-work.
    pub pylaia_target: usize,
    /// Band proof-of-work policy. Expressed as a target *time* with absolute
    /// work bounds, so it adapts to the client without letting the client
    /// lower its own bar (`hdap_core::pow::PowPolicy`).
    pub pow: PowPolicy,
    /// Band ceiling per account per rolling hour, in bytes (`0` = unlimited).
    ///
    /// This is the anti-abuse backstop that makes proof-of-work bypass
    /// worthless: even a client that skips the PoW entirely cannot turn zero
    /// CPU into unbounded storage, because the *rate* at which band is granted
    /// is server state, not something the client negotiates.
    pub band_bytes_per_hour: u64,
    /// Whether to expose the hashrate the node believes each client has, and
    /// to refuse clients whose claim is outside `[min,max]` instead of
    /// clamping them silently.
    pub pow_strict_hashrate: bool,
    /// Maximum accepted request body in bytes.
    pub max_body_bytes: usize,
    /// Maximum accepted upload in bytes.
    pub max_upload_bytes: u64,
    /// Per-user storage quota in bytes (`0` = unlimited).
    pub moira_bytes: u64,
    /// Rate limit: max requests per second and burst, per peer (`0` disables).
    pub rate_limit_per_sec: u32,
    /// Rate limiter burst.
    pub rate_limit_burst: u32,
    /// Federation timestamp window tolerance (± seconds).
    pub fed_window_secs: i64,
    /// Optional federation pins: `node_id -> FederationPeer`.
    ///
    /// An empty map does **not** close the node. Federation is always open:
    /// unknown peers are admitted on first contact and their presented key is
    /// pinned. Entries here only pre-pin a key/endpoint so a later caller with
    /// the same id but a different key is rejected. Content is still verified
    /// against its author signature and hash, so an impostor can be reached but
    /// cannot forge content (AME-34).
    pub federation_peers: std::collections::BTreeMap<String, FederationPeer>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server_id: "node-a".to_string(),
            choregia_per_mochthos: 4 * 1024 * 1024,
            session_ttl_secs: 12 * 3600,
            proklesis_ttl_secs: 60,
            require_entry_pow: true,
            require_content_signature: true,
            pylaia_target: 12,
            pow: PowPolicy::default(),
            max_body_bytes: 64 * 1024 * 1024,
            max_upload_bytes: 100 * 1024 * 1024,
            moira_bytes: 0,
            rate_limit_per_sec: 10,
            rate_limit_burst: 20,
            fed_window_secs: 30,
            federation_peers: std::collections::BTreeMap::new(),
            band_bytes_per_hour: 64 * 1024 * 1024,
            pow_strict_hashrate: false,
        }
    }
}
