//! State model types shared by the GUI.
//!
//! Extracted from `app.rs` so the main application file stays focused on the
//! egui view layer. Network types live in `net.rs`.

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use hdap_core::pow::Canceller;

/// A login session against one pyle (per-node session, skill.md §7.3).
#[derive(Clone, Debug)]
pub struct Session {
    pub user_id: String,
    pub token: String,
    pub exp: u64,
    pub server_id: String,
    /// Pin the node advertised on `/health`. Adopted by `App::poll_connect` when
    /// the user connected with an empty pin field, so later requests are
    /// actually anchored (real TOFU) instead of re-accepting any cert.
    pub tls_pin: Option<String>,
}

impl Session {
    pub fn friendly_ttl(&self) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let left = self.exp.saturating_sub(now);
        format!("{left}s")
    }
}

/// Transient notification shown as a toast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Success,
    Error,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub id: u64,
    pub kind: ToastKind,
    pub text: String,
    pub born: f64,
}

/// A running proof-of-work, reported to the GUI in real time (HPS-style
/// "mining" dialog). The solver runs on a background thread; the view polls
/// `attempts`/`result` each frame.
pub struct PowState {
    pub target_bits: usize,
    pub attempts: Arc<AtomicU64>,
    pub started: std::time::Instant,
    pub canceller: Arc<Canceller>,
    pub result: Pending<Result<u64, String>>,
}

/// Integrated file preview state (text, image, audio).
#[derive(Debug, Clone)]
pub struct PreviewState {
    pub path: String,
    pub content_type: PreviewContentType,
    pub data: Vec<u8>,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewContentType {
    Text,
    Image,
    Audio,
    Unknown,
}

impl PreviewState {
    pub fn from_path(path: &str) -> Option<Self> {
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let content_type = match ext.as_str() {
            "txt" | "md" | "rs" | "toml" | "json" | "yaml" | "yml" | "log" | "csv" | "html"
            | "css" | "js" | "ts" | "py" | "sh" | "cfg" | "conf" | "ini" | "text" => {
                PreviewContentType::Text
            }
            "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "ico" | "svg" => {
                PreviewContentType::Image
            }
            "mp3" | "wav" | "ogg" | "flac" | "m4a" | "aac" | "opus" => PreviewContentType::Audio,
            _ => PreviewContentType::Unknown,
        };
        Some(Self {
            path: path.to_string(),
            content_type,
            data: Vec::new(),
            hash: String::new(),
        })
    }
}

/// One pyle in the global discovery bubble.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BubblePeer {
    pub node_id: String,
    pub endpoint: String,
    pub tier: String,
    pub verified: bool,
    pub failures: u32,
    pub last_seen: u64,
}

/// Summary shown as `Bolha: N pyles (core, extended, untrusted)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BubbleStatus {
    pub total: usize,
    pub core: usize,
    pub extended: usize,
    pub untrusted: usize,
    pub peers: Vec<BubblePeer>,
}

/// Result of `POST /resolve_hash`: either a copy already here (`local`) or a
/// blob pulled from a ledger-named pyle (`fetched`), cached in our namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HashLookup {
    pub status: String,
    pub owner: String,
    pub path: String,
    pub source: String,
    pub verified: bool,
    /// Every pyle the ledger names for this digest (origin first), so a hash
    /// search answers "who has a copy" instead of only "where did this one
    /// download come from".
    pub holders: Vec<String>,
    pub error: String,
}

/// A background worker result slot, polled by `tick`.
pub type Pending<T> = Arc<Mutex<Option<T>>>;

/// `(session, next OTP step, rendered /health payload)` from a connect.
pub type ConnectDone = Result<(crate::state::Session, usize, serde_json::Value), String>;

/// `(new_pyle, installed adeia edition, installed adeia text)`.
pub type HouseMoveDone = (String, u64, String);

/// Hard ceiling on one connect attempt. The worker itself is bounded per
/// request (8s connect / 20s I/O) but a whole login is several round-trips,
/// so without this the wizard could sit on "conectando" for minutes.
pub const CONNECT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(45);
