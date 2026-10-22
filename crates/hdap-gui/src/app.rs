use crate::i18n::{Lang, Strings};
use hdap_cli::flow::{
    accept_transfer, authenticate, delete, download, fetch_prices, list_ktema, publish_alias,
    register, request_transfer, resolve, resolve_cross_pyle, resolve_user,
    sync_all as flow_sync_all, transfer_inbox, CrossPyle, FlowError, KtemaEntry, MatrixEntry,
    SyncSnapshot, TimiQuote, TransferInboxItem, TrustRow,
};
use hdap_cli::http_client::HttpClient;
use hdap_cli::identity_store;
use hdap_core::identity::{canonical_nickname, Identity};
use hdap_core::pow::Canceller;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

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

/// The configuration documents the spec defines for a `ktema`: file name,
/// template id, and what it is for. This is the catalog the Config panel
/// renders, so "configure this" is a list the user can read instead of a
/// file they have to go hunting for in a grid.
pub const CONFIG_DOCS: [(&str, &str, &str); 6] = [
    ("adeia.hdap", "adeia", "quem pode ler e escrever"),
    ("diadosi.hdap", "diadosi", "backups assinados da casa"),
    ("kerux.hdap", "kerux", "seus nomes públicos"),
    ("timi.hdap", "timi", "seu preço por GiB/dia"),
    ("prytaneion.hdap", "prytaneion", "matriz de réplicas"),
    ("prosopeion.hdap", "prosopeion", "sua identidade pública"),
];

impl App {
    /// Is `name` present in the current listing?
    pub fn has_entry(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e.name == name)
    }

    /// Open a configuration document in the editor by catalog name, and make
    /// the Config panel the visible one. Used by the Config panel and by
    /// double-clicking a `.hdap` in the grid.
    pub fn open_config(&mut self, name: &str) {
        self.select(name);
        crate::editor::open(self, name);
        self.side_panel = Some(SidePanel::Editor);
    }
}
pub fn is_document(path: &str) -> bool {
    path.ends_with(".hdap")
}

/// How the file grid is sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Name,
    Size,
}

/// Which optional right-hand panel the toolbar has open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidePanel {
    Prices,
    Aliases,
    Editor,
    Config,
    HouseMove,
    Diadosi,
}

/// A background worker result slot, polled by `tick`.
type Pending<T> = Arc<Mutex<Option<T>>>;

/// `(new_pyle, installed adeia edition, installed adeia text)`.
type HouseMoveDone = (String, u64, String);

/// Hard ceiling on one connect attempt. The worker itself is bounded per
/// request (8s connect / 20s I/O) but a whole login is several round-trips,
/// so without this the wizard could sit on "conectando" for minutes.
const CONNECT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(45);

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

/// State model of the explorer. All network access is done here; the egui
/// view just reads/renders and forwards user intents (skill.md principle 6).
pub struct App {
    // connection
    pub host: String,
    pub port: String,
    pub pin: String,
    pub insecure: bool,
    // identity
    pub home_dir: String,
    pub nickname: String,
    pub password: String,
    /// UI language; every label below is read from `strings`.
    pub lang: Lang,
    /// The resolved strings of `lang` (handed out by `Strings::for_lang`).
    pub strings: &'static Strings,
    pub identity: Option<Identity>,
    // session
    pub session: Option<Session>,
    /// The connected pyle stopped answering at the transport level. Kept
    /// separate from `status` so the view can show an explicit prompt instead
    /// of leaving the explorer frozen on the last successful listing.
    pub link_down: bool,
    pub link_error: String,
    /// After a link loss, the next successful login opens the house-move
    /// panel (pre-seeded with the new pyle's adeia) instead of silently
    /// pretending nothing happened.
    pub suggest_house_move: bool,
    pub otp_step: usize,
    /// In-flight connect attempt (register+auth on a worker thread).
    pub connecting: bool,
    /// Result of the background connect attempt, polled by `tick`.
    connect_pending: Option<Pending<Result<(Session, usize), String>>>,
    /// When the in-flight connect started (for the deadline + elapsed label).
    pub connect_started: Option<std::time::Instant>,
    /// A directory listing is in flight on a worker thread.
    pub listing: bool,
    /// Result of the background listing, polled by `tick`. A newer request
    /// replaces the slot, so stale results are dropped instead of applied.
    list_pending: Option<Pending<Result<Vec<KtemaEntry>, String>>>,
    // band credit (bytes still available on this node)
    pub band: u64,
    // explorer
    /// Current directory ("" or "/" = root).
    pub cwd: String,
    pub entries: Vec<KtemaEntry>,
    /// Full path of the selected entry (if any).
    pub selected: Option<String>,
    /// Back-stack of directory paths (deepest last).
    pub back_stack: Vec<String>,
    /// Forward-stack after going back.
    pub forward_stack: Vec<String>,
    /// A local file queued for upload into `cwd`.
    pub pending_upload: Option<(String, Vec<u8>)>,
    /// Last download: `(remote_path, local_path, size_bytes, hash)`.
    pub last_download: Option<(String, String, usize, String)>,
    // logical URI (especificacao §3.3)
    /// Append `?hash=` of the selected file to the logical URI.
    pub uri_with_hash: bool,
    /// Extra side panel toggled from the toolbar (prices / aliases / editor).
    pub side_panel: Option<SidePanel>,
    /// Text the view should push to the OS clipboard this frame.
    pub pending_clipboard: Option<String>,
    /// Open config-editor session, if any.
    pub editor: Option<crate::editor::EditorState>,
    /// Draft name in the editor's "novo arquivo" form.
    pub new_file_name: String,
    /// Draft template in the editor's "novo arquivo" form.
    pub new_file_kind: crate::editor::Template,
    /// Bumped by every explicit user-facing status message, so a late
    /// listing result cannot overwrite a confirmation the user just got.
    pub status_epoch: u64,
    /// The `status_epoch` at the time the in-flight listing was requested.
    list_epoch: u64,
    /// Where the file actions (upload/edit/band) were last drawn. Kept for
    /// diagnostics: these buttons were once rendered after the file list's
    /// `ScrollArea`, which pushed them off the visible area, and nothing in
    /// the app noticed.
    pub last_actions_rect: Option<egui::Rect>,
    /// Where the sidebar band card was drawn, so the layout tests can prove
    /// the mining button is actually on screen.
    pub band_rect: Option<egui::Rect>,
    /// Where the sidebar ended up, so a layout test can prove its width does
    /// not follow the pointer or the content.
    pub sidebar_rect: Option<egui::Rect>,
    /// Where the right side panel ended up, so a layout test can prove its
    /// content never pushes it past the window edge (`exact_size` alone is not
    /// enough: an over-wide child drifts the whole panel to the right).
    pub right_rect: Option<egui::Rect>,
    /// Last URI string the view drew in the toolbar row, so a layout test can
    /// prove the bar is not a bare "/" anymore.
    pub last_uri_shown: String,
    /// Where that URI bar was drawn (must stay in the top toolbar).
    pub uri_rect: Option<egui::Rect>,
    /// State of the integrated file preview (text, image, audio).
    pub preview: Option<PreviewState>,

    /// What the user typed in the URI bar. Kept separate from
    /// `logical_uri()` so a hand-typed path survives the next redraw instead
    /// of being overwritten by the location the view thinks you are at.
    pub uri_edit: String,
    /// True while the URI field has focus and the text is the user's, not ours.
    pub uri_editing: bool,
    /// A bare DDNS alias typed in the URI bar is being resolved via `/kerux`.
    uri_alias_busy: bool,
    uri_alias_pending: Option<Pending<Result<String, String>>>,
    uri_alias_raw: String,
    // grid
    pub sort_key: SortKey,
    pub sort_desc: bool,
    /// Non-empty: keep only entries whose name matches (case-insensitive).
    pub search: String,
    // output
    pub status: String,
    /// Tagged so the view can show transient spinners per action.
    pub busy: Option<String>,
    /// Toast notifications (transient).
    pub toasts: Vec<Toast>,
    next_toast_id: u64,
    /// Active PoW (None when not mining).
    pub pow: Option<PowState>,
    /// Market prices from `/timi` (katallaxia).
    pub prices: Vec<TimiQuote>,
    // login sync (especificacao §7 / `GET /sync`)
    /// A full `/sync` snapshot is in flight (fetched on a worker thread).
    pub syncing: bool,
    sync_pending: Option<Pending<Result<SyncSnapshot, String>>>,
    /// Config documents cached from the last sync: name -> node-truth text.
    /// The Config panel reads these, so it never shows a stale or guessed
    /// "pronto", and `open_config` can hand the editor the exact node bytes.
    pub sync_docs: std::collections::BTreeMap<String, String>,
    /// `prytaneion` matrix rows from the last sync (§10.2).
    pub matrix: Vec<MatrixEntry>,
    /// Published aliases (`alias`, `uri`) from the last sync (§13).
    pub aliases: Vec<(String, String)>,
    /// Trust scores from the last sync (§12).
    pub pheme: Vec<TrustRow>,
    /// Bytes currently stored on the node (moira usage).
    pub stored_bytes: u64,
    /// Storage quota (0 = unlimited); matches the node at login.
    pub moira_bytes: u64,
    /// Written after the last sync: path -> the entry echoed by that node. The
    /// full recursive tree, so the explorer can open any folder instantly
    /// right after login (path "" buckets the root). The live listing that
    /// lands afterwards is authoritative; this is only the offline-precise
    /// snapshot the login `sync` delivered.
    pub tree: std::collections::BTreeMap<String, Vec<KtemaEntry>>,
    /// Short human summary of the last successful sync (shown in the band
    /// card / status bar so the freshness is visible).
    pub last_sync: String,
    // visiting other users (especificacao §3.3/§8)
    /// While non-empty, the grid shows *this* user's space (the node only
    /// lists what that owner's `adeia` lets us read).
    pub visiting: String,
    /// The origin pyle we dialed to reach `visiting` (empty for a same-pyle
    /// open). Reload re-resolves it, so a grant made *after* the first visit is
    /// picked up without retyping the access URI.
    pub visiting_server: String,
    /// True when the visited space is a *mirror* of another pyle — a read-only
    /// replica. A space owned by someone registered on **this** pyle is not a
    /// mirror: its `adeia` can grant write, so the GUI must not pre-block it
    /// (the server is the authority and answers 403 when it is not granted).
    pub visiting_remote: bool,
    /// Timestamp of the last successful mirror adeia refresh. Used to
    /// periodically refresh the origin's ACL without hammering the server.
    pub last_mirror_adeia_refresh: Option<std::time::Instant>,
    /// Free-form nickname typed in the sidebar "Pessoas" box.
    pub person_input: String,
    /// Feedback about the last visit attempt (not found / opened / self).
    pub visit_status: String,
    /// A `GET /registry` lookup is in flight.
    pub visit_busy: bool,
    visit_pending: Option<Pending<Result<String, String>>>,
    /// A `POST /resolve` for another pyle is in flight (pull-through mirror).
    pub mirror_busy: bool,
    mirror_pending: Option<Pending<Result<CrossPyle, String>>>,
    /// The `(server, owner, path)` to open once the mirror succeeds.
    mirror_target: Option<(String, String, String)>,
    // metabibasis transfer (§11)
    /// Target path(s) to hand over (comma-separated), defaulting to the
    /// selected grid entry.
    pub transfer_target: String,
    /// `file`, `dir` or `identity` (the request kind).
    pub transfer_kind: String,
    /// Destination access URI (`HDAP!pyle@user/path`).
    pub transfer_new_uri: String,
    /// Pending offers shown in the transfer panel.
    pub transfer_inbox: Vec<TransferInboxItem>,
    /// Feedback about the last transfer attempt.
    pub transfer_status: String,
    /// A transfer request/acceptance is in flight.
    pub transfer_busy: bool,
    transfer_pending: Option<Pending<Result<(bool, String), String>>>,
    /// Alias to resolve/publish.
    pub alias_input: String,
    pub alias_uri_input: String,
    pub alias_result: Option<String>,
    // global discovery bubble (GET /bubble)
    pub bubble: BubbleStatus,
    /// "ver lista" expanded state for the peer detail list.
    pub bubble_open: bool,
    pub bubble_filter: String,
    pub bubble_busy: bool,
    bubble_pending: Option<Pending<Result<BubbleStatus, String>>>,
    // explicit house move (POST /house_move): user signs a newer `adeia` and
    // names the new home pyle; the old home may be offline, peers relay it.
    pub house_move_new_pyle: String,
    pub house_move_adeia: String,
    pub house_move_status: String,
    pub house_move_busy: bool,
    house_move_pending: Option<Pending<Result<HouseMoveDone, String>>>,
    // signed fallback proxy (POST /diadosi)
    pub diadosi_fallbacks: String,
    pub diadosi_status: String,
    pub diadosi_busy: bool,
    diadosi_pending: Option<Pending<Result<u64, String>>>,
    // content-addressed lookup (POST /resolve_hash)
    /// 64-hex digest typed in the bubble window.
    pub hash_input: String,
    pub hash_result: Option<HashLookup>,
    pub hash_busy: bool,
    hash_pending: Option<Pending<Result<HashLookup, String>>>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: "8443".into(),
            pin: String::new(),
            insecure: false,
            home_dir: String::new(),
            // No hardcoded default: a nickname is the key to a home folder,
            // and a pre-filled sample name was exactly what made a second GUI
            // silently open another person's vault as "jose".
            nickname: String::new(),
            password: String::new(),
            lang: Lang::Pt,
            strings: Strings::for_lang(Lang::Pt),
            identity: None,
            session: None,
            link_down: false,
            link_error: String::new(),
            suggest_house_move: false,
            otp_step: 1,
            connecting: false,
            connect_pending: None,
            connect_started: None,
            listing: false,
            list_pending: None,
            band: 0,
            cwd: String::new(),
            entries: Vec::new(),
            uri_with_hash: false,
            side_panel: None,
            pending_clipboard: None,
            editor: None,
            new_file_name: String::new(),
            new_file_kind: crate::editor::Template::Adeia,
            status_epoch: 0,
            list_epoch: 0,
            last_actions_rect: None,
            band_rect: None,
            sidebar_rect: None,
            right_rect: None,
            last_uri_shown: String::new(),
            uri_rect: None,
            uri_edit: String::new(),
            uri_editing: false,
            uri_alias_busy: false,
            uri_alias_pending: None,
            uri_alias_raw: String::new(),
            selected: None,
            back_stack: Vec::new(),
            forward_stack: Vec::new(),
            pending_upload: None,
            last_download: None,
            preview: None,
            sort_key: SortKey::Name,
            sort_desc: false,
            search: String::new(),
            status: "disconnected".into(),
            busy: None,
            toasts: Vec::new(),
            next_toast_id: 1,
            pow: None,
            prices: Vec::new(),
            alias_input: String::new(),
            alias_uri_input: String::new(),
            alias_result: None,
            bubble: BubbleStatus::default(),
            bubble_open: false,
            bubble_filter: String::new(),
            bubble_busy: false,
            bubble_pending: None,
            house_move_new_pyle: String::new(),
            house_move_adeia: String::new(),
            house_move_status: String::new(),
            house_move_busy: false,
            house_move_pending: None,
            diadosi_fallbacks: String::new(),
            diadosi_status: String::new(),
            diadosi_busy: false,
            diadosi_pending: None,
            hash_input: String::new(),
            hash_result: None,
            hash_busy: false,
            hash_pending: None,
            syncing: false,
            sync_pending: None,
            sync_docs: Default::default(),
            matrix: Vec::new(),
            aliases: Vec::new(),
            pheme: Vec::new(),
            stored_bytes: 0,
            moira_bytes: 0,
            tree: Default::default(),
            last_sync: String::new(),
            visiting: String::new(),
            visiting_server: String::new(),
            visiting_remote: false,
            last_mirror_adeia_refresh: None,
            person_input: String::new(),
            visit_status: String::new(),
            visit_busy: false,
            visit_pending: None,
            mirror_busy: false,
            mirror_pending: None,
            mirror_target: None,
            transfer_target: String::new(),
            transfer_kind: "file".into(),
            transfer_new_uri: String::new(),
            transfer_inbox: Vec::new(),
            transfer_status: String::new(),
            transfer_busy: false,
            transfer_pending: None,
        }
    }
}

/// Only pathsafe, filesystem-friendly characters for the per-nickname home
/// folder. Lower-case so two spellings of one nickname collide; accented
/// vowels fold onto their base letters so "José"/"Jose" stay one folder.
/// Free function because it is a small pure helper, not behavior of the app.
///
/// This must agree with [`canonical_nickname`], which is what ends up in the
/// `nickname_suffix` id: if the folder said `jose` and the id said `jose_`,
/// the vault and the account would disagree.
fn sanitize_name(name: &str) -> String {
    let norm = canonical_nickname(name).unwrap_or_default();
    if norm.is_empty() {
        "anon".to_string()
    } else {
        norm
    }
}

/// Resolve the vault directory from an explicit home field, a nickname, and the
/// `HDAP_HOME` base. Kept separate from [`App::home_path`] so the whole
/// precedence can be tested without mutating process-wide environment state,
/// which would race with the other tests running in parallel.
fn resolve_home(explicit: &str, nickname: &str) -> std::path::PathBuf {
    resolve_home_with(explicit, nickname, &|key| std::env::var_os(key))
}

fn resolve_home_with(
    explicit: &str,
    nickname: &str,
    get_env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> std::path::PathBuf {
    let base = if !explicit.trim().is_empty() {
        std::path::PathBuf::from(explicit)
    } else {
        match get_env("HDAP_HOME") {
            Some(base) if !base.is_empty() => std::path::PathBuf::from(base),
            _ => default_data_base(get_env),
        }
    };
    // Always append the nickname subdirectory to ensure multi-user isolation.
    // An explicit home (or HDAP_HOME) is the BASE, not the full vault path.
    base.join(sanitize_name(nickname))
}

/// Persistent default for the vault. The old default was the system temp
/// directory, which meant a reboot handed the user a brand-new identity —
/// the one thing a vault must never do. Prefer XDG on Linux, APPDATA on
/// Windows, and `$HOME`/`$USERPROFILE` as a last portable fallback. Temp is
/// used only when the OS gives us no home at all.
fn default_data_base(get_env: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> std::path::PathBuf {
    let nonempty = |key: &str| get_env(key).filter(|v| !v.is_empty());
    if let Some(xdg) = nonempty("XDG_DATA_HOME") {
        return std::path::PathBuf::from(xdg).join("hdap");
    }
    if cfg!(windows) {
        if let Some(appdata) = nonempty("APPDATA") {
            return std::path::PathBuf::from(appdata).join("hdap");
        }
    }
    if let Some(home) = nonempty("HOME") {
        return std::path::PathBuf::from(home).join(".local/share/hdap");
    }
    if let Some(profile) = nonempty("USERPROFILE") {
        return std::path::PathBuf::from(profile).join(".hdap");
    }
    std::env::temp_dir().join("hdap-gui")
}

impl App {
    /// Where the home dir lives. An empty field no longer collapses every user
    /// into one shared folder (that made a second GUI always log in as the
    /// first identity): it is derived from the nickname, so "maria" and
    /// "jose" get separate vaults without forcing the user to fiddle with a
    /// path. Respect an explicit home the moment one is typed.
    ///
    /// `HDAP_HOME` overrides the *base* of the default location. The default
    /// now lives under XDG/APPDATA/HOME, because the vault holds `krypte.hdap`
    /// (the identity itself) and must survive a reboot. The nickname
    /// subdirectory is still appended, so two identities never share one vault.
    pub fn home_path(&self) -> std::path::PathBuf {
        resolve_home(&self.home_dir, self.nickname.as_str())
    }

    /// File holding the next unused OTP step. The node refuses a replayed
    /// step, so this must survive a restart — otherwise a fresh GUI could log
    /// in only once per node.
    fn otp_step_file(&self) -> std::path::PathBuf {
        self.home_path().join("omphalos.step")
    }

    fn load_otp_step(&self) -> Option<usize> {
        std::fs::read_to_string(self.otp_step_file())
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn save_otp_step(&self, step: usize) {
        let _ = std::fs::create_dir_all(self.home_path());
        let _ = std::fs::write(self.otp_step_file(), format!("{}\n", step + 1));
    }

    /// `host:port` for human-facing messages.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host.trim(), self.port.trim())
    }

    pub fn client(&self) -> Result<HttpClient, FlowError> {
        let port: u16 = self
            .port
            .parse()
            .map_err(|_| FlowError::Proto("invalid port".into()))?;
        if self.insecure {
            Ok(HttpClient::new(&self.host, port))
        } else {
            Ok(HttpClient::new_tls(&self.host, port, self.pin.clone()))
        }
    }

    /// `load` or create+`save` the identity under `home_dir/krypte.hdap` and
    /// `home_dir/prosopeion.hdap` (krypte = encrypted vault, prosopeion =
    /// public profile).
    pub fn ensure_identity(&mut self) -> Result<Identity, FlowError> {
        if let Some(id) = &self.identity {
            return Ok(id.clone());
        }
        let home_dir = self.home_path();
        std::fs::create_dir_all(&home_dir).map_err(FlowError::Io)?;
        let krypte = home_dir.join("krypte.hdap");
        let pros = home_dir.join("prosopeion.hdap");
        // Se já houver identidade salva em disco, verificamos se o nickname
        // digitado pelo usuário corresponde. Se corresponder, usamos a identidade
        // carregada (ela já traz o home folder correto). Se NÃO corresponder,
        // geramos uma nova identidade com o nickname da sessão corrente para
        // evitar que o nickname salvo de uma sessão anterior force o login.
        // Compare on the canonical form, not the raw text: typing `José` must land
        // on the vault that `jose` created, otherwise every accent variant
        // silently forks a brand new identity.
        let typed = canonical_nickname(self.nickname.trim()).unwrap_or_default();
        if let Ok(id) = load_local(&self.password, &krypte, &pros) {
            let expected = &typed;
            if !expected.is_empty() && id.nickname == *expected {
                // Nicknames correspondem: usamos a identidade salva.
                self.identity = Some(id.clone());
                return Ok(id);
            }
            // Nicknames divergem: gerar nova identidade com o nickname corrente.
            // Isso evita que o nickname salvo de uma sessão anterior seja usado.
            drop(id); // liberar o id carregado indevidamente
        }
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // `try_generate` normalizes and rejects an absolute id pasted into the
        // nickname box, so `nickname_suffix` can never end up doubled.
        let id = Identity::try_generate(&self.nickname, created)
            .map_err(|e| FlowError::Proto(format!("nickname inválido: {e}")))?;
        identity_store::save(&id, self.password.as_bytes(), &krypte, &pros)
            .map_err(|e| FlowError::Proto(format!("save identity: {e:?}")))?;
        self.identity = Some(id.clone());
        Ok(id)
    }

    /// Push a transient toast notification.
    /// Set the status bar as a deliberate, user-facing message. Bumps the
    /// epoch so an in-flight listing that lands afterwards will not stomp it.
    pub fn say(&mut self, text: impl Into<String>) {
        self.status = text.into();
        self.status_epoch = self.status_epoch.wrapping_add(1);
    }

    /// Apply a language and remember it next to this vault.
    pub fn set_lang(&mut self, lang: Lang) {
        self.lang = lang;
        self.strings = Strings::for_lang(lang);
        let _ = std::fs::create_dir_all(self.home_dir.trim());
        if !self.home_dir.trim().is_empty() {
            let _ = std::fs::write(
                std::path::Path::new(&self.home_dir).join(".hdap-lang"),
                lang.code(),
            );
        }
    }

    /// Restore a persisted language for this vault (call once, before login).
    pub fn load_lang(&mut self) {
        let code = std::fs::read_to_string(std::path::Path::new(&self.home_dir).join(".hdap-lang"))
            .unwrap_or_default();
        for l in Lang::ALL {
            if l.code() == code.trim() {
                self.lang = l;
                self.strings = Strings::for_lang(l);
                return;
            }
        }
    }

    pub fn notify(&mut self, kind: ToastKind, text: impl Into<String>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        self.toasts.push(Toast {
            id: self.next_toast_id,
            kind,
            text: text.into(),
            born: now,
        });
        self.next_toast_id += 1;
        if self.toasts.len() > 6 {
            self.toasts.remove(0);
        }
    }

    /// Drop toasts older than `ttl_secs`; poll background work (connect, PoW).
    /// Called once per frame; must stay fast — no blocking I/O here.
    pub fn tick(&mut self, now: f64, ttl_secs: f64) {
        self.toasts.retain(|t| now - t.born < ttl_secs);
        self.poll_connect();
        self.poll_sync();
        self.poll_list();
        self.poll_visit();
        self.poll_uri_alias();
        self.poll_mirror();
        self.poll_transfer();
        self.poll_bubble();
        self.poll_hash();
        self.poll_house_move();
        self.poll_diadosi();
        if self.pow.is_some() {
            let finished: Option<Result<u64, String>> = self
                .pow
                .as_ref()
                .and_then(|p| p.result.lock().ok())
                .and_then(|mut lock| lock.take());
            if let Some(res) = finished {
                self.pow = None;
                self.busy = None;
                match res {
                    Ok(total) => {
                        self.band = total;
                        let m = crate::i18n::fill1(self.strings.st_band_now, &format!("{total}"));
                        self.notify(ToastKind::Success, m.clone());
                        self.status = m;
                    }
                    Err(e) => {
                        let m = crate::i18n::fill1(self.strings.st_band_failed, &e);
                        self.notify(ToastKind::Error, m.clone());
                        self.status = crate::i18n::fill1(self.strings.st_band_failed, &e);
                    }
                }
            }
        }
        // Periodically refresh the mirror's adeia from the origin (every 30s).
        self.maybe_refresh_mirror_adeia();
    }

    /// Periodically refresh the mirror's adeia from the origin (every 30s).
    /// This keeps the mirror's ACL in sync with the origin without manual refresh.
    fn maybe_refresh_mirror_adeia(&mut self) {
        if !self.visiting_remote || self.mirror_busy {
            return;
        }
        let now = std::time::Instant::now();
        let due = self
            .last_mirror_adeia_refresh
            .is_none_or(|last| now.duration_since(last).as_secs() > 30);
        if !due {
            return;
        }
        let Some(tok) = self.session_token() else {
            return;
        };
        let server = self.visiting_server.clone();
        let owner = self.visiting.clone();
        let c = match self.client() {
            Ok(c) => c,
            Err(_) => return,
        };
        let c = c.clone();
        let tok = tok.to_string();
        let slot: Pending<Result<CrossPyle, String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        self.mirror_pending = Some(slot);
        self.mirror_busy = true;
        self.mirror_target = Some((server.clone(), owner.clone(), String::new()));
        self.busy = Some("mirror-adeia-auto".into());
        std::thread::spawn(move || {
            let uri = format!("HDAP!{server}@{owner}/");
            let out = resolve_cross_pyle(&c, &tok, &uri).map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    /// Start a proof-of-work for band on a background thread and show the
    /// mining dialog (`self.pow = Some(...)`). The result is polled by `tick`.
    /// `target_bits == 0` uses the node's advertised difficulty.
    pub fn begin_band(&mut self, target_bits: usize) {
        let Some(tok) = self.session_token() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let Some(identity) = self.identity.clone() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        // Learn the real difficulty so the progress dialog is truthful.
        let bits = match hdap_cli::flow::proklesis_bits(&c, &tok) {
            Ok((_, bits)) if target_bits == 0 => bits,
            Ok(_) => target_bits,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_proklesis_err, &format!("{e}"));
                return;
            }
        };
        let canceller = Arc::new(Canceller::default());
        let attempts = Arc::new(AtomicU64::new(0));
        let result: Arc<Mutex<Option<Result<u64, String>>>> = Arc::new(Mutex::new(None));
        let result_ref = Arc::clone(&result);
        let attempts_out = Arc::clone(&attempts);
        let cc = Arc::clone(&canceller);
        let started = std::time::Instant::now();
        std::thread::spawn(move || {
            let watcher = attempts_out;
            let out = hdap_cli::flow::band_mochthos_progress(&c, &tok, &identity, bits, &cc, |n| {
                watcher.store(n, std::sync::atomic::Ordering::Relaxed);
            });
            let wrapped: Result<u64, String> = match out {
                Ok(total) => Ok(total),
                Err(e) => Err(e.to_string()),
            };
            *result_ref.lock().unwrap() = Some(wrapped);
        });
        self.pow = Some(PowState {
            target_bits: bits,
            attempts,
            started,
            canceller,
            result,
        });
        self.busy = Some("band".into());
        self.status = self.strings.st_mining_band.to_string();
    }

    /// Abort an in-flight PoW and clear the dialog.
    pub fn cancel_band(&mut self) {
        if let Some(p) = &self.pow {
            p.canceller.cancel();
        }
        self.pow = None;
        self.busy = None;
        self.status = self.strings.pow_canceled.to_string();
        self.notify(ToastKind::Info, self.strings.pow_canceled.to_string());
    }

    /// Register on the node (idempotent) and log in (3FA) — on a worker
    /// thread, so the UI never freezes. `tick` picks up the result.
    pub fn connect(&mut self) {
        if self.connecting {
            return;
        }
        if self.nickname.trim().is_empty() {
            self.status = self.strings.st_no_nick.to_string();
            return;
        }
        self.load_lang();
        let id = match self.ensure_identity() {
            Ok(id) => id,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_identity_err, &format!("{e}"));
                return;
            }
        };
        let client = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        let uid = id.global_id();
        // A persisted step survives restarts; the in-memory value is only the
        // fallback for a brand-new home.
        let step = self.load_otp_step().unwrap_or(self.otp_step);
        let result: Pending<Result<(Session, usize), String>> = Arc::new(Mutex::new(None));
        let result_ref = Arc::clone(&result);
        self.connect_pending = Some(result);
        self.connecting = true;
        self.connect_started = Some(std::time::Instant::now());
        let deadline = self.connect_started.unwrap() + CONNECT_DEADLINE;
        self.busy = Some("connect".into());
        self.status = self.strings.st_connecting.to_string();
        std::thread::spawn(move || {
            // A panicking worker would leave the slot empty and the wizard
            // stuck on "conectando" forever, so never let one escape.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                do_connect(&client, &id, &uid, step, deadline)
            }))
            .unwrap_or_else(|_| Err("falha interna no login (pânico)".into()));
            if let Ok(mut slot) = result_ref.lock() {
                *slot = Some(outcome);
            }
        });
    }

    /// Give up on a connect attempt that outran `CONNECT_DEADLINE`, so the
    /// wizard can never sit on "conectando ao pyle..." indefinitely. The
    /// worker thread is left to finish into a dropped slot.
    pub fn cancel_connect(&mut self) {
        if !self.connecting {
            return;
        }
        self.connecting = false;
        self.connect_started = None;
        self.connect_pending = None;
        if self.busy.as_deref() == Some("connect") {
            self.busy = None;
        }
        self.status = self.strings.st_connect_canceled.to_string();
    }

    /// Seconds elapsed on the in-flight connect (0 when idle).
    pub fn connect_elapsed(&self) -> f64 {
        self.connect_started
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(0.0)
    }

    /// Collect a finished connect attempt (called from `tick`).
    fn poll_connect(&mut self) {
        if !self.connecting {
            return;
        }
        if self.connect_elapsed() > CONNECT_DEADLINE.as_secs_f64() {
            let secs = CONNECT_DEADLINE.as_secs();
            self.cancel_connect();
            let node = self.endpoint();
            let m = crate::i18n::fill2(self.strings.st_timeout, &format!("{secs}"), &node);
            self.status = m.clone();
            self.notify(ToastKind::Error, m);
            return;
        }
        let finished: Option<Result<(Session, usize), String>> = self
            .connect_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        if let Some(res) = finished {
            self.connecting = false;
            self.connect_started = None;
            self.connect_pending = None;
            self.busy = None;
            match res {
                Ok((session, step)) => {
                    // Persist the consumed step so the next process resumes
                    // here instead of replaying it.
                    self.otp_step = step + 1;
                    self.save_otp_step(step);
                    // The stored identity decides the real name; the wizard's
                    // nickname field was only the key to the right folder.
                    if let Some(id) = &self.identity {
                        self.nickname = id.nickname.clone();
                    }
                    let used_pin = self.pin.trim().to_string();
                    let advertised = session.tls_pin.clone().filter(|p| !p.is_empty());
                    self.session = Some(session);
                    self.forward_stack.clear();
                    let uid = self.user_id().unwrap_or_default();
                    self.status = crate::i18n::fill1(self.strings.st_connected_as, &uid);
                    match (used_pin.as_str(), &advertised) {
                        // Real TOFU: the user left the pin empty, so adopt the
                        // pin the node advertised. Every later request is then
                        // anchored to this exact certificate.
                        ("", Some(p)) => {
                            let p = p.clone();
                            self.pin = p;
                            self.notify(ToastKind::Success, self.strings.st_pin_fixed.to_string());
                        }
                        // The handshake already enforced the pin, so reaching
                        // here means the node is consistent; warn anyway if the
                        // advertised pin drifted.
                        (used, Some(p)) if used != p => {
                            let pm = crate::i18n::fill1(self.strings.st_pin_changed, p);
                            self.notify(ToastKind::Error, pm);
                        }
                        _ => {}
                    }
                    self.notify(
                        ToastKind::Success,
                        self.strings.st_connected_pyle.to_string(),
                    );
                    self.sync_all();
                    self.refresh_bubble();
                }
                Err(e) => {
                    let em = crate::i18n::fill1(self.strings.st_connect_failed, &e);
                    self.status = em.clone();
                    self.notify(ToastKind::Error, em);
                }
            }
        }
    }

    pub fn disconnect(&mut self) {
        self.cancel_connect();
        self.session = None;
        self.band = 0;
        self.cancel_band();
        // Drop every pending worker: a snapshot or listing that lands after a
        // disconnect must not talk about a session that no longer exists.
        self.syncing = false;
        self.sync_pending = None;
        self.listing = false;
        self.list_pending = None;
        self.visit_busy = false;
        self.visit_pending = None;
        self.mirror_busy = false;
        self.mirror_pending = None;
        self.mirror_target = None;
        self.uri_alias_busy = false;
        self.uri_alias_pending = None;
        self.uri_alias_raw.clear();
        self.transfer_busy = false;
        self.transfer_pending = None;
        self.bubble_busy = false;
        self.bubble_pending = None;
        self.bubble = BubbleStatus::default();
        self.bubble_open = false;
        self.entries.clear();
        self.tree.clear();
        self.selected = None;
        self.back_stack.clear();
        self.forward_stack.clear();
        self.link_down = false;
        self.link_error.clear();
        self.suggest_house_move = false;
        self.status = self.strings.st_disconnected.to_string();
    }

    /// Record a transport-level failure without throwing the session away.
    /// The view asks the user whether to leave for the login screen; only a
    /// deliberate action drops the session, so a transient reset cannot log
    /// the user out mid-edit.
    fn note_link_failure(&mut self, err: &str) {
        if self.session.is_none() || !is_transport_failure(err) {
            return;
        }
        let first = !self.link_down;
        self.link_down = true;
        self.link_error = err.to_string();
        if first {
            let msg = crate::i18n::fill2(self.strings.link_down_body, &self.endpoint(), err);
            self.notify(ToastKind::Error, msg);
        }
    }

    /// Leave the dead pyle for the wizard. The identity and the last known
    /// adeia stay in memory/disk, so logging into another pyle can sign a
    /// house move without the old home being online.
    pub fn leave_for_login(&mut self) {
        self.disconnect();
        self.suggest_house_move = true;
        self.status = self.strings.link_down_after.to_string();
        self.notify(ToastKind::Info, self.strings.link_down_after.to_string());
    }

    pub fn dismiss_link_down(&mut self) {
        self.link_down = false;
    }

    pub fn user_id(&self) -> Option<String> {
        self.session.as_ref().map(|s| s.user_id.clone())
    }

    /// The namespace the grid currently operates on (§3.3 `@user` in the
    /// access URI): our own by default, or the owner we are visiting.
    pub fn active_owner(&self) -> Option<String> {
        if self.visiting.is_empty() {
            self.user_id()
        } else {
            Some(self.visiting.clone())
        }
    }

    /// True while exploring someone else's space. Reading/downloading is
    /// allowed (the owner's `adeia` decides), writing is not — the GUI
    /// disables destructive actions instead of letting them fail on the node.
    pub fn read_only(&self) -> bool {
        // Only a *mirrored* (remote) space is physically read-only. A space
        // whose owner lives on this same pyle can accept writes when their
        // `adeia` grants them, so the GUI must not decide that for the node.
        !self.visiting.is_empty() && self.visiting_remote
    }

    /// Open another user's space. Accepts three shapes, so one field covers all
    /// the ways a person is named:
    ///
    /// * a full access URI `HDAP!<pyle>@<user>/<path>` — the space lives on
    ///   another pyle, so pull it here first ([`begin_cross_pyle`]);
    /// * a global `user_id` (`nick_hex`) — the person is already identified, no
    ///   registry round-trip is needed;
    /// * a bare nickname — ask this node's registry to resolve it.
    ///
    /// The node returns only what the owner's `adeia` grants (§8); a forbidden
    /// space surfaces as a message, never as a silent empty folder.
    pub fn visit(&mut self, input: &str) {
        if self.visit_busy || self.mirror_busy {
            return;
        }
        let raw = input.trim();
        if raw.is_empty() {
            self.status = self.strings.st_no_nick.to_string();
            return;
        }
        if let Some((server, user, path)) = hdap_core::parse_access_uri(raw) {
            self.person_input.clear();
            self.begin_cross_pyle(&server, &user, &path);
            return;
        }
        if hdap_core::identity::parse_global_id(raw).is_some() {
            self.person_input.clear();
            self.open_user(raw.to_string());
            return;
        }
        let nick = raw.to_string();
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        let slot: Pending<Result<String, String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        self.visit_pending = Some(slot);
        self.visit_busy = true;
        self.busy = Some("visit".into());
        self.status = crate::i18n::fill1(self.strings.st_searching, &nick);
        std::thread::spawn(move || {
            let out = resolve_user(&c, &nick).map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    /// Switch the view to `uid`'s space (or back home when it is our own id).
    fn open_user(&mut self, uid: String) {
        if Some(&uid) == self.user_id().as_ref() {
            self.visiting = String::new();
            self.visiting_server.clear();
            self.visiting_remote = false;
            self.visit_status = self.strings.v_own.to_string();
        } else {
            self.visiting = uid.clone();
            self.visiting_server.clear();
            // A bare global id is resolved on *this* pyle: not a mirror.
            self.visiting_remote = false;
            self.visit_status = crate::i18n::fill1(self.strings.v_open_lbl, &uid);
        }
        self.cwd = String::new();
        self.selected = None;
        self.refresh();
        self.notify(
            ToastKind::Info,
            if self.read_only() {
                crate::i18n::fill1(self.strings.v_opening, &uid)
            } else {
                self.strings.v_own_toast.to_string()
            },
        );
    }

    /// Apply a finished nickname lookup (called from `tick`).
    fn poll_visit(&mut self) {
        if !self.visit_busy {
            return;
        }
        let finished: Option<Result<String, String>> = self
            .visit_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        let Some(res) = finished else { return };
        self.visit_busy = false;
        self.visit_pending = None;
        if self.busy.as_deref() == Some("visit") {
            self.busy = None;
        }
        match res {
            Ok(uid) => self.open_user(uid),
            Err(e) => {
                self.note_link_failure(&e);
                self.visit_status = crate::i18n::fill1(self.strings.v_not_found, &e);
                let em = crate::i18n::fill1(self.strings.st_visit_fail, &e);
                self.status = em.clone();
                self.notify(ToastKind::Error, em);
            }
        }
    }

    /// Step out of a visited space back to our own root.
    pub fn return_home(&mut self) {
        self.visiting = String::new();
        self.visiting_server.clear();
        self.visiting_remote = false;
        self.visit_status.clear();
        // Do *not* delegate to `cd("")`: it early-returns when we are already at
        // the root of the visited space, so the grid would keep the other user's
        // entries while `active_owner()` says we are home. Relist unconditionally.
        self.back_stack.clear();
        self.forward_stack.clear();
        self.selected = None;
        self.cwd = String::new();
        self.refresh();
    }

    /// Reload the current space. In a cross-pyle space this must re-resolve the
    /// origin, not merely relist the local mirror: a grant published after the
    /// first visit only arrives on a fresh `POST /resolve`, and without this the
    /// user had to retype the access URI to see it.
    pub fn sync_space(&mut self) {
        if !self.visiting.is_empty() && !self.visiting_server.is_empty() {
            self.begin_cross_pyle(
                &self.visiting_server.clone(),
                &self.visiting.clone(),
                &self.cwd.clone(),
            );
        } else {
            self.refresh();
        }
    }

    /// Fetch the latest `adeia` from the origin for the current mirror and
    /// re-apply it locally. This keeps the mirror's ACL in sync with the
    /// origin without a full re-resolve of the file list. Runs in a
    /// background thread; the `poll_mirror` handler will merge the fresh ACL.
    /// Open a space that lives on another pyle: ask our node to resolve the
    /// URI, pulling (mirroring) that user's namespace here on demand. Runs on
    /// a worker thread; [`poll_mirror`] opens the space when it lands.
    pub fn begin_cross_pyle(&mut self, server: &str, user: &str, path: &str) {
        if self.mirror_busy {
            return;
        }
        let Some(tok) = self.session_token() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        let uri = format!("HDAP!{server}@{user}/{path}");
        let slot: Pending<Result<CrossPyle, String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        self.mirror_pending = Some(slot);
        self.mirror_busy = true;
        self.mirror_target = Some((server.to_string(), user.to_string(), path.to_string()));
        self.busy = Some("mirror".into());
        self.status = crate::i18n::fill1(self.strings.st_mirroring, server);
        std::thread::spawn(move || {
            let out = resolve_cross_pyle(&c, &tok, &uri).map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    /// Apply a finished cross-pyle resolve (called from `tick`).
    fn poll_mirror(&mut self) {
        if !self.mirror_busy {
            return;
        }
        let finished: Option<Result<CrossPyle, String>> = self
            .mirror_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        let Some(res) = finished else { return };
        self.mirror_busy = false;
        self.mirror_pending = None;
        if self.busy.as_deref() == Some("mirror") {
            self.busy = None;
        }
        match res {
            Ok(cp) => {
                let (server, owner, path) = self
                    .mirror_target
                    .take()
                    .unwrap_or_else(|| (cp.pyle.clone(), cp.owner.clone(), cp.path.clone()));
                // Opening a URI that names *our own* id must land in our own
                // writable space, not in read-only "visiting" mode.
                if Some(&owner) == self.user_id().as_ref() {
                    self.visiting.clear();
                    self.visiting_server.clear();
                    self.visiting_remote = false;
                    self.visit_status = self.strings.v_own.to_string();
                } else {
                    self.visiting = owner.clone();
                    self.visiting_server = server;
                    // `status == "local"` means the owner lives on this pyle:
                    // writable if their adeia grants it. Anything else was
                    // pulled from another pyle — a read-only mirror.
                    self.visiting_remote = cp.status != "local";
                    self.visit_status =
                        crate::i18n::fill1(self.strings.v_open_lbl, &self.visiting.clone());
                }
                self.cwd = path.trim_matches('/').to_string();
                self.selected = None;
                self.back_stack.clear();
                self.forward_stack.clear();
                // Record the successful adeia refresh timestamp.
                self.last_mirror_adeia_refresh = Some(std::time::Instant::now());
                self.refresh();
                // An empty-looking mirror with files withheld is the one case
                // that silently lied before: the resolve succeeded, but the
                // owner granted nothing, so the file never came. Say so.
                let m = if cp.denied > 0 {
                    crate::i18n::fill2(
                        self.strings.st_mirror_denied,
                        &format!("{}", cp.denied),
                        &cp.pyle,
                    )
                } else if cp.copied > 0 {
                    crate::i18n::fill2(
                        self.strings.st_mirrored,
                        &format!("{}", cp.copied),
                        &cp.pyle,
                    )
                } else {
                    crate::i18n::fill1(self.strings.st_mirror_local, &cp.pyle)
                };
                self.notify(ToastKind::Info, m.clone());
                self.status = m;
            }
            Err(e) => {
                self.note_link_failure(&e);
                let em = crate::i18n::fill1(self.strings.st_mirror_fail, &e);
                self.status = em.clone();
                self.notify(ToastKind::Error, em);
            }
        }
    }

    /// Pre-fill the transfer form with the currently selected entry.
    pub fn seed_transfer(&mut self) {
        match self.selected_entry().cloned() {
            Some(entry) => {
                self.transfer_kind = if entry.is_dir { "dir" } else { "file" }.to_string();
                self.transfer_target = entry.path;
                self.transfer_status.clear();
            }
            None => {
                self.transfer_status = self.strings.tr_no_selection.to_string();
            }
        }
    }

    /// Accept a nickname (or a full `HDAP!` URI) as the transfer destination.
    pub fn resolve_transfer_owner(&mut self) {
        let input = self.transfer_new_uri.trim().to_string();
        if input.is_empty() {
            self.transfer_status = self.strings.tr_no_nick.to_string();
            return;
        }
        if hdap_core::parse_access_uri(&input).is_some() {
            self.transfer_status = self.strings.tr_resolved.to_string();
            return;
        }
        let pyle = self
            .session
            .as_ref()
            .map(|s| s.server_id.clone())
            .unwrap_or_else(|| self.host.trim().to_string());
        let user_id = if input.contains('_') {
            input
        } else {
            let c = match self.client() {
                Ok(c) => c,
                Err(e) => {
                    self.transfer_status =
                        crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                    return;
                }
            };
            match resolve_user(&c, &input) {
                Ok(id) => id,
                Err(e) => {
                    self.transfer_status =
                        self.strings.tr_resolve_failed.to_string() + ": " + &e.to_string();
                    return;
                }
            }
        };
        self.transfer_new_uri = format!("HDAP!{pyle}@{user_id}/");
        self.transfer_status = crate::i18n::fill1(self.strings.tr_resolved, &user_id);
    }

    /// Ask the source pyle to create and deliver a transfer request (§11).
    /// No second vault is needed: the assignee signs the acceptance later.
    pub fn transfer_selected(&mut self) {
        if self.transfer_busy {
            return;
        }
        let target = self.transfer_target.trim().to_string();
        if target.is_empty() && self.transfer_kind != "identity" {
            self.transfer_status = self.strings.tr_no_target.to_string();
            return;
        }
        let new_uri = self.transfer_new_uri.trim().to_string();
        if new_uri.is_empty() {
            self.transfer_status = self.strings.tr_fill_both.to_string();
            return;
        }
        if hdap_core::parse_access_uri(&new_uri).is_none() {
            self.transfer_status = self.strings.tr_bad_uri.to_string();
            return;
        }
        let Some(tok) = self.session_token() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let Some(old_id) = self.identity.clone() else {
            self.transfer_status = self.strings.tr_no_identity.to_string();
            return;
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.transfer_status =
                    crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        let kind = self.transfer_kind.clone();
        let targets: Vec<String> = if kind == "identity" {
            Vec::new()
        } else {
            target
                .split(',')
                .map(|s| s.trim().trim_start_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        let slot: Pending<Result<(bool, String), String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        self.transfer_pending = Some(slot);
        self.transfer_busy = true;
        self.transfer_status = crate::i18n::fill1(self.strings.tr_active, &target);
        self.busy = Some("transfer".into());
        std::thread::spawn(move || {
            let out = request_transfer(&c, &tok, &old_id, &new_uri, &kind, &targets)
                .map(|r| (false, r.request_id))
                .map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    /// Refresh the offers addressed to the authenticated user.
    pub fn refresh_transfer_inbox(&mut self) {
        let Some(tok) = self.session_token() else {
            self.transfer_status = self.strings.tr_no_session.to_string();
            return;
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.transfer_status =
                    crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        match transfer_inbox(&c, &tok) {
            Ok(items) => {
                self.transfer_inbox = items;
                if self.transfer_inbox.is_empty() {
                    self.transfer_status = self.strings.tr_inbox_empty.to_string();
                }
            }
            Err(e) => {
                self.transfer_status = crate::i18n::fill1(self.strings.tr_fail, &e.to_string());
            }
        }
    }

    /// Sign and send the acceptance for one inbox offer.
    pub fn accept_transfer_item(&mut self, request_id: &str) {
        if self.transfer_busy {
            return;
        }
        let Some(tok) = self.session_token() else {
            self.transfer_status = self.strings.tr_no_session.to_string();
            return;
        };
        let Some(identity) = self.identity.clone() else {
            self.transfer_status = self.strings.tr_no_identity.to_string();
            return;
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.transfer_status =
                    crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        let id = request_id.to_string();
        let slot: Pending<Result<(bool, String), String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        self.transfer_pending = Some(slot);
        self.transfer_busy = true;
        self.transfer_status = crate::i18n::fill1(self.strings.tr_accepting, &id);
        self.busy = Some("transfer".into());
        std::thread::spawn(move || {
            let out = accept_transfer(&c, &tok, &identity, &id)
                .map(|_| (true, id))
                .map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    /// Apply a finished transfer (called from `tick`).
    fn poll_transfer(&mut self) {
        if !self.transfer_busy {
            return;
        }
        let finished: Option<Result<(bool, String), String>> = self
            .transfer_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        let Some(res) = finished else { return };
        self.transfer_busy = false;
        self.transfer_pending = None;
        if self.busy.as_deref() == Some("transfer") {
            self.busy = None;
        }
        match res {
            Ok((accepted, id)) => {
                if accepted {
                    self.transfer_inbox.retain(|i| i.request_id != id);
                    self.transfer_status = crate::i18n::fill1(self.strings.tr_accepted, &id);
                    self.sync_all();
                    self.refresh_bubble();
                } else {
                    self.transfer_status = crate::i18n::fill1(self.strings.tr_done, &id);
                }
                self.notify(ToastKind::Success, self.strings.tr_done_toast.to_string());
                self.refresh();
            }
            Err(e) => {
                self.transfer_status = crate::i18n::fill1(self.strings.tr_fail, &e);
                self.notify(
                    ToastKind::Error,
                    crate::i18n::fill1(self.strings.tr_fail, &e),
                );
            }
        }
    }

    /// Access URI for one entry. Used by the grid's context menu so copying
    /// the URI of a file does not require selecting it first.
    pub fn entry_uri(&self, entry: &KtemaEntry) -> String {
        let server = self
            .session
            .as_ref()
            .map(|s| s.server_id.clone())
            .unwrap_or_else(|| self.host.trim().to_string());
        let user = self.active_owner().unwrap_or_else(|| "<user>".to_string());
        let path = entry.path.trim_start_matches('/');
        let mut uri = format!("HDAP!{server}@{user}/{path}");
        if !entry.is_dir && !entry.hash.is_empty() {
            uri.push_str(&format!("?hash={}", entry.hash));
        }
        uri
    }

    /// The access URI of the current location (especificacao §3.3):
    /// `HDAP!<servidor>@<user>/<caminho>?hash=<64hex>`.
    ///
    /// The `?hash=` part is only emitted when asked for *and* a file is
    /// actually selected — a URI that promises verification it cannot do is
    /// worse than one that stays silent.
    pub fn logical_uri(&self) -> String {
        let server = self
            .session
            .as_ref()
            .map(|s| s.server_id.clone())
            .unwrap_or_else(|| self.host.trim().to_string());
        let user = self.active_owner().unwrap_or_else(|| "<user>".to_string());
        // A selected *file* has a path of its own. Keeping the directory here
        // while appending the file's hash would name the parent and promise
        // the child's content — the URI would resolve to the wrong object.
        let path = match (self.uri_with_hash, self.selected_entry()) {
            (true, Some(e)) if !e.is_dir => e.path.clone(),
            _ => self.cwd.clone(),
        };
        let path = path.trim_start_matches('/');
        let mut uri = format!("HDAP!{server}@{user}/{path}");
        if self.uri_with_hash {
            if let Some(h) = self.selected_hash() {
                uri.push_str(&format!("?hash={h}"));
            }
        }
        uri
    }
}

/// What a hand-typed URI bar produced, if it was not usable.
///
/// The bar is editable, so it needs a verdict rather than silence: either
/// `UriEdit::Accepted` (navigate), or a reason to say why not.
#[derive(Debug, Clone, PartialEq)]
pub enum UriEdit {
    /// Blank or identical to where you already are — nothing to do.
    Unchanged,
    /// Go to this path inside the current space.
    Accepted(String),
    /// `HDAP!<servidor>@<usuario>/<caminho>` — another space was named.
    OtherSpace {
        server: String,
        user: String,
        path: String,
    },
    /// Malformed. The message is meant to be shown as-is.
    Invalid(String),
}

impl App {
    /// Parse what the user typed in the URI bar.
    ///
    /// Accepts three shapes, because that is what a person actually tries:
    ///   * `docs/a.txt` — a path in the space you are looking at;
    ///   * `/docs/a.txt` — same, absolute-looking;
    ///   * `HDAP!node@jose_ab../docs/a.txt` — the full spec form, which can name
    ///     a *different* server or a *different* user.
    ///
    /// Returns `OtherSpace` rather than silently navigating: switching identity
    /// or node is not something to infer from a text box.
    pub fn parse_uri_input(&self, raw: &str) -> UriEdit {
        let text = raw.trim();
        if text.is_empty() {
            return UriEdit::Unchanged;
        }

        if let Some(rest) = text
            .strip_prefix("HDAP!")
            .or_else(|| text.strip_prefix("hdap!"))
        {
            // HDAP!<server>@<user>/<path>
            let (server, tail) = match rest.split_once('@') {
                Some(p) => p,
                None => {
                    return UriEdit::Invalid(
                        "faltou o @: o formato é HDAP!servidor@usuário/caminho".into(),
                    )
                }
            };
            if server.trim().is_empty() {
                return UriEdit::Invalid("faltou o nome do servidor".into());
            }
            let (user, path) = match tail.split_once('/') {
                Some((u, p)) => (u, p),
                // `HDAP!node@user` is the root of that space, not an error.
                None => (tail, ""),
            };
            let user = user.trim();
            if user.is_empty() {
                return UriEdit::Invalid("faltou o usuário".into());
            }
            return UriEdit::OtherSpace {
                server: server.trim().to_string(),
                user: user.to_string(),
                path: path.trim_matches('/').to_string(),
            };
        }

        // A bare path. Refuse `..` rather than silently clamping it: a URI that
        // means something different from what was typed is worse than an error.
        let path = text.trim_start_matches('/');
        if path.split('/').any(|seg| seg == "..") {
            return UriEdit::Invalid("`..` não é aceito na URI".into());
        }
        if path.trim().is_empty() {
            return UriEdit::Unchanged;
        }
        UriEdit::Accepted(path.to_string())
    }

    /// Apply the verdict from [`parse_uri_input`], setting a human status when it
    /// cannot be honoured. Returns true when the view changed.
    pub fn apply_uri_edit(&mut self, raw: &str) -> bool {
        match self.parse_uri_input(raw) {
            UriEdit::Unchanged => false,
            UriEdit::Accepted(path) => {
                self.set_cwd(&path);
                true
            }
            UriEdit::OtherSpace { server, user, path } => {
                let here_user = self.user_id().unwrap_or_default();
                let here_server = self
                    .session
                    .as_ref()
                    .map(|s| s.server_id.clone())
                    .unwrap_or_else(|| self.host.trim().to_string());
                if server == here_server {
                    if user == here_user || user == self.visiting {
                        self.set_cwd(&path);
                        true
                    } else {
                        self.status = format!("{} ({server}@{user})", self.strings.uri_other_space);
                        false
                    }
                } else {
                    // A different pyle: ask our node to pull that user's space
                    // here on demand, then open it locally.
                    self.begin_cross_pyle(&server, &user, &path);
                    false
                }
            }
            UriEdit::Invalid(why) => {
                self.status = format!("URI inválida: {why}");
                false
            }
        }
    }

    /// Whether a URI-bar input should be tried as a DDNS alias before being
    /// treated as a relative path. Paths and access URIs keep the fast local
    /// route; a single bare token is the one shape that can be an alias.
    /// Existing entries win, so typing a real folder name never pays a network
    /// round-trip.
    pub fn should_resolve_ddns(&self, raw: &str) -> bool {
        let text = raw.trim();
        if text.is_empty()
            || text.contains('/')
            || text.chars().any(char::is_whitespace)
            || text.starts_with("HDAP!")
            || text.starts_with("hdap!")
            || hdap_core::identity::parse_global_id(text).is_some()
        {
            return false;
        }
        !self
            .entries
            .iter()
            .any(|e| e.name == text || e.path.trim_matches('/') == text)
    }

    /// Submit the editable URI bar. A bare token may be a DDNS alias, so it is
    /// resolved through `/kerux` on a worker thread; if the alias does not
    /// exist we still navigate to the local path the user typed.
    pub fn submit_uri(&mut self, raw: &str) {
        if self.uri_alias_busy {
            return;
        }
        let text = raw.trim().to_string();
        if !self.should_resolve_ddns(&text) {
            self.apply_uri_edit(&text);
            return;
        }
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        let slot: Pending<Result<String, String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        self.uri_alias_pending = Some(slot);
        self.uri_alias_busy = true;
        self.uri_alias_raw = text.clone();
        self.status = crate::i18n::fill1(self.strings.uri_alias_lookup, &text);
        std::thread::spawn(move || {
            // `/kerux` is public, so the alias lookup needs no session token.
            let out = resolve(&c, &text).map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    /// Apply a finished DDNS lookup. On success the returned target goes
    /// through the normal URI parser, so a full `HDAP!` target still triggers
    /// the cross-pyle pull. A miss falls back to local navigation.
    fn poll_uri_alias(&mut self) {
        if !self.uri_alias_busy {
            return;
        }
        let finished: Option<Result<String, String>> = self
            .uri_alias_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        let Some(res) = finished else { return };
        self.uri_alias_busy = false;
        self.uri_alias_pending = None;
        let raw = std::mem::take(&mut self.uri_alias_raw);
        match res {
            Ok(uri) => {
                let msg = crate::i18n::fill2(self.strings.uri_alias_ok, &raw, &uri);
                self.notify(ToastKind::Success, msg);
                self.apply_uri_edit(&uri);
            }
            Err(_) => {
                let msg = crate::i18n::fill1(self.strings.uri_alias_missing, &raw);
                let changed = self.apply_uri_edit(&raw);
                if changed {
                    self.status = msg.clone();
                }
                self.notify(ToastKind::Info, msg);
            }
        }
    }

    /// The entry backing the current selection, if the grid still has it.
    pub fn selected_entry(&self) -> Option<&KtemaEntry> {
        let sel = self.selected.as_ref()?;
        self.entries.iter().find(|e| &e.path == sel)
    }

    /// Content hash of the selected entry (empty for directories).
    pub fn selected_hash(&self) -> Option<String> {
        self.selected_entry()
            .map(|e| e.hash.clone())
            .filter(|h| !h.is_empty())
    }

    /// Open/close a right-hand panel; clicking the active toolbar button
    /// closes it, so the panel is never a panel you cannot get rid of.
    pub fn toggle_panel(&mut self, panel: SidePanel) {
        if self.side_panel == Some(panel) {
            self.side_panel = None;
        } else {
            self.side_panel = Some(panel);
        }
    }

    /// Ask the view to put `text` on the system clipboard. `app.rs` stays
    /// GUI-agnostic, so it cannot call `ctx.copy_text` itself; the view drains
    /// this buffer each frame.
    pub fn request_clipboard(&mut self, text: &str) {
        self.pending_clipboard = Some(text.to_string());
        self.status = crate::i18n::fill1(self.strings.st_copied, text);
    }

    pub fn session_token(&self) -> Option<String> {
        self.session.as_ref().map(|s| s.token.clone())
    }

    /// Reload the listing of `self.cwd` on a worker thread, so navigating to a
    /// dead or slow node never blocks the UI. `tick` applies the result.
    pub fn refresh(&mut self) {
        let Some(tok) = self.session_token() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let owner = self.active_owner().unwrap_or_default();
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        let cwd = self.cwd.clone();
        // While the live listing is on its way, paint our own folder from the
        // login-sync snapshot when we hold it. The tree mirrors *our* storage,
        // so it is never used to seed someone else's space. The worker result
        // remains authoritative and replaces this seed of the grid.
        if self.visiting.is_empty() && !self.tree.is_empty() {
            let mut entries = self.tree.get(&self.cwd).cloned().unwrap_or_default();
            entries.sort_by_key(|e| e.is_dir);
            self.entries = entries;
            self.selected = None;
        }
        let slot: Pending<Result<Vec<KtemaEntry>, String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        // A newer request supersedes any in-flight one: the old slot is
        // dropped, so its late result can never overwrite the current view.
        self.list_pending = Some(slot);
        self.listing = true;
        self.list_epoch = self.status_epoch;
        self.busy = Some("list".into());
        self.status = crate::i18n::fill1(self.strings.st_loading_dir, display_dir(&cwd));
        std::thread::spawn(move || {
            let out = list_ktema(&c, &tok, &owner, &cwd).map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    /// Sync everything with the node after login (§7): push the local identity
    /// (idempotent register/rotate) and pull the full `/sync` snapshot on a
    /// worker thread, so band, files, config docs, matrix, aliases, prices and
    /// trust are all fresh the moment the explorer appears. Its result is
    /// applied by `poll_sync`.
    pub fn sync_all(&mut self) {
        let Some(tok) = self.session_token() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let Some(id) = self.identity.clone() else {
            self.status = self.strings.tr_no_identity.to_string();
            return;
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        let slot: Pending<Result<SyncSnapshot, String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        // The config docs the client last saw go back to the node (forward-only
        // reconciliation), so the server is kept on the same truth as the
        // interface. `sync_all` runs right after login, when the cache is still
        // empty; every later refresh sends the docs the node itself produced.
        let docs = self.sync_docs.clone();
        self.sync_pending = Some(slot);
        self.syncing = true;
        self.busy = Some("sync".into());
        self.status = self.strings.st_syncing.to_string();
        std::thread::spawn(move || {
            let out = flow_sync_all(&c, &tok, &id, &docs).map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    /// Apply a finished `/sync` snapshot (called from `tick`).
    fn poll_sync(&mut self) {
        if !self.syncing {
            return;
        }
        let finished: Option<Result<SyncSnapshot, String>> = self
            .sync_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        let Some(res) = finished else { return };
        self.syncing = false;
        self.sync_pending = None;
        if self.busy.as_deref() == Some("sync") {
            self.busy = None;
        }
        if self.session.is_none() {
            // The snapshot answers a session we no longer hold; say nothing.
            return;
        }
        match res {
            Ok(snap) => {
                // Serve the whole snapshot to every panel: nothing is stale.
                self.band = snap.band;
                self.stored_bytes = snap.stored;
                self.moira_bytes = snap.moira_bytes;
                self.otp_step = snap.otp_step.max(self.otp_step);
                self.sync_docs = snap.docs.clone();
                self.aliases = snap.kerux.clone();
                self.matrix = snap.prytaneion.clone();
                self.pheme = snap.pheme.clone();
                self.prices = snap.timi.clone();
                // The bundle carries the COMPLETE recursive tree: bucket it by
                // directory so the explorer can paint any folder instantly.
                self.tree = build_tree(&snap.ktema);
                if self.cwd.is_empty() {
                    // Seed the grid with the root bucket ("" = root).
                    let mut entries = self.tree.get("").cloned().unwrap_or_default();
                    entries.sort_by_key(|e| e.is_dir);
                    self.entries = entries;
                    self.selected = None;
                }
                let docs_n = snap.docs.len();
                let items = crate::i18n::fill1(self.strings.u_items, &snap.ktema.len().to_string());
                let ds = crate::i18n::fill1(self.strings.u_docs, &docs_n.to_string());
                self.last_sync = format!("{} · {items} · {ds}", clock_str());
                self.status = crate::i18n::fill1(self.strings.st_synced, &self.last_sync);
                self.notify(
                    ToastKind::Success,
                    crate::i18n::fill1(self.strings.st_synced, &self.last_sync),
                );
                let _used = (snap.user_id,);
                self.refresh_bubble();
                if self.suggest_house_move {
                    self.suggest_house_move = false;
                    self.open_house_move();
                    self.notify(ToastKind::Info, self.strings.link_down_after.to_string());
                }
            }
            Err(e) => {
                self.note_link_failure(&e);
                let em = crate::i18n::fill1(self.strings.st_sync_failed, &e);
                self.status = em.clone();
                self.notify(ToastKind::Error, em);
            }
        }
    }

    /// Apply a finished directory listing (called from `tick`).
    fn poll_list(&mut self) {
        if !self.listing {
            return;
        }
        let finished: Option<Result<Vec<KtemaEntry>, String>> = self
            .list_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        let Some(res) = finished else { return };
        self.listing = false;
        self.list_pending = None;
        if self.busy.as_deref() == Some("list") {
            self.busy = None;
        }
        match res {
            Ok(mut entries) => {
                // directories first, then by current sort key
                entries.sort_by(|a, b| {
                    a.is_dir.cmp(&b.is_dir).then_with(|| match self.sort_key {
                        SortKey::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                        SortKey::Size => a.size.cmp(&b.size),
                    })
                });
                if self.sort_desc {
                    entries.reverse();
                }
                if !self.search.is_empty() {
                    let q = self.search.to_lowercase();
                    entries.retain(|e| e.name.to_lowercase().contains(&q) || e.is_dir);
                }
                self.entries = entries;
                if let Some(sel) = &self.selected {
                    if !self.entries.iter().any(|e| &e.path == sel) {
                        self.selected = None;
                    }
                }
                if self.status_epoch == self.list_epoch {
                    self.status = format!(
                        "{}: {}",
                        display_dir(&self.cwd),
                        crate::i18n::fill1(self.strings.u_items, &self.entries.len().to_string())
                    );
                }
            }
            Err(e) => {
                // Never keep the previous space's rows on screen: a failed
                // listing (e.g. 403 when the owner granted us nothing) must
                // clear the grid, not leave another folder's entries under the
                // visited owner's name.
                self.entries.clear();
                self.selected = None;
                self.note_link_failure(&e);
                let em = crate::i18n::fill1(self.strings.st_list_failed, &e);
                self.status = em.clone();
                self.notify(ToastKind::Error, em);
            }
        }
    }

    /// Set the current directory *without* pushing history. This is how a URI
    /// typed by hand takes effect: it replaces where you are instead of
    /// growing an undo trail nobody asked for.
    pub fn set_cwd(&mut self, dir: &str) {
        let dir = dir.trim_matches('/').to_string();
        if dir == self.cwd {
            return;
        }
        self.back_stack.clear();
        self.forward_stack.clear();
        self.selected = None;
        self.cwd = dir;
        self.refresh();
    }

    /// Navigate into `dir` (its full path, "" for root), pushing history.
    pub fn cd(&mut self, dir: &str) {
        let dir = dir.trim_matches('/').to_string();
        if dir == self.cwd {
            return;
        }
        self.back_stack.push(self.cwd.clone());
        self.forward_stack.clear();
        self.selected = None;
        self.cwd = dir;
        self.refresh();
    }

    /// Jump back one level on the history stack.
    pub fn back(&mut self) {
        if let Some(prev) = self.back_stack.pop() {
            self.forward_stack.push(self.cwd.clone());
            self.cwd = prev;
            self.selected = None;
            self.refresh();
        }
    }

    /// Go forward again after going back.
    pub fn forward(&mut self) {
        if let Some(next) = self.forward_stack.pop() {
            self.back_stack.push(self.cwd.clone());
            self.cwd = next;
            self.selected = None;
            self.refresh();
        }
    }

    /// Step to the parent directory.
    pub fn up(&mut self) {
        if self.cwd.is_empty() {
            return;
        }
        self.back_stack.push(self.cwd.clone());
        self.forward_stack.clear();
        self.cwd = match self.cwd.rfind('/') {
            Some(i) => self.cwd[..i].to_string(),
            None => String::new(),
        };
        self.selected = None;
        self.refresh();
    }

    pub fn select(&mut self, path: &str) {
        self.selected = Some(path.to_string());
    }

    /// Open an entry: directories navigate, files select.
    pub fn open_entry(&mut self, path: &str, is_dir: bool) {
        if is_dir {
            self.cd(path);
        } else if is_document(path) {
            // A double click is "open this". For a `.hdap` that means the
            // editor, not a silent select — otherwise the file grid looks
            // broken for the only kind of file that has a dedicated view.
            crate::editor::open(self, path);
        } else {
            self.select(path);
        }
    }

    /// Open a preview of a file (text, image, audio).
    pub fn open_preview(&mut self, path: &str, hash: &str) {
        if let Some(mut preview) = PreviewState::from_path(path) {
            let Some(tok) = self.session_token() else {
                self.status = self.strings.st_not_logged.to_string();
                return;
            };
            let c = match self.client() {
                Ok(c) => c,
                Err(e) => {
                    self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                    return;
                }
            };
            let owner = self.active_owner().unwrap_or_default();
            match download(&c, &tok, &owner, path) {
                Ok((data, stored_hash)) => {
                    if stored_hash != hash {
                        self.status = self.strings.v_not_found.to_string();
                        self.notify(ToastKind::Error, self.strings.v_not_found.to_string());
                        return;
                    }
                    preview.data = data;
                    preview.hash = stored_hash;
                    self.preview = Some(preview);
                    self.notify(ToastKind::Info, self.strings.v_opening.to_string());
                }
                Err(e) => {
                    let msg = crate::i18n::fill1(self.strings.st_download_fail, &format!("{e}"));
                    self.status = msg.clone();
                    self.notify(ToastKind::Error, msg);
                }
            }
        }
    }

    /// Close the preview.
    pub fn close_preview(&mut self) {
        self.preview = None;
    }

    /// Cycle the file grid sort (name default; desc flips on second call).
    pub fn toggle_sort(&mut self, key: SortKey) {
        if self.sort_key == key {
            self.sort_desc = !self.sort_desc;
        } else {
            self.sort_key = key;
            self.sort_desc = false;
        }
        self.refresh();
    }

    /// Queue a local file for upload into `cwd`. Reads it now so failures are
    /// reported immediately.
    pub fn queue_upload(&mut self, path: &std::path::Path) {
        match std::fs::read(path) {
            Ok(data) => {
                let name = path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "arquivo".to_string());
                let n = data.len();
                self.pending_upload = Some((name.clone(), data));
                self.status = format!(
                    "{} ({n})",
                    crate::i18n::fill1(self.strings.st_loaded, &name)
                );
                self.notify(
                    ToastKind::Info,
                    crate::i18n::fill1(self.strings.st_loaded, &name),
                );
            }
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_read_fail, &format!("{e}"));
                self.notify(
                    ToastKind::Error,
                    crate::i18n::fill1(self.strings.st_read_fail, &format!("{e}")),
                );
            }
        }
    }

    /// Clear a pending upload.
    pub fn clear_pending(&mut self) {
        self.pending_upload = None;
    }

    /// Upload the pending file into `cwd`.
    pub fn do_upload(&mut self) {
        let Some((name, data)) = self.pending_upload.take() else {
            self.status = self.strings.st_no_queued.to_string();
            return;
        };
        if self.read_only() {
            self.pending_upload = Some((name, data));
            self.status = self.strings.st_upload_ro.to_string();
            return;
        }
        let Some(tok) = self.session_token() else {
            self.pending_upload = Some((name, data));
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let owner = self.active_owner().unwrap_or_default();
        let path = if self.cwd.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", self.cwd, name)
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.pending_upload = Some((name, data));
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        let out = match &self.identity {
            Some(identity) => {
                hdap_cli::flow::upload_with_band(&c, &tok, identity, &owner, &path, &data)
            }
            None => hdap_cli::flow::upload(
                &c,
                &tok,
                self.identity.as_ref().unwrap(),
                &owner,
                &path,
                &data,
            ),
        };
        match out {
            Ok(hash) => {
                self.status = crate::i18n::fill1(self.strings.st_uploaded, &path);
                self.notify(
                    ToastKind::Success,
                    crate::i18n::fill1(self.strings.st_uploaded, &name),
                );
                self.refresh();
                let _ = hash;
            }
            Err(e) => {
                self.pending_upload = Some((name, data));
                self.status = crate::i18n::fill1(self.strings.st_upload_fail, &format!("{e}"));
                self.notify(
                    ToastKind::Error,
                    crate::i18n::fill1(self.strings.st_upload_fail, &format!("{e}")),
                );
            }
        }
    }

    /// Fetch the global discovery bubble from `GET /bubble` on a worker
    /// thread. The UI keeps the previous snapshot until the new one lands.
    pub fn refresh_bubble(&mut self) {
        let Some(tok) = self.session_token() else {
            return;
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(_) => return,
        };
        let slot: Pending<Result<BubbleStatus, String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        self.bubble_pending = Some(slot);
        self.bubble_busy = true;
        std::thread::spawn(move || {
            let out = fetch_bubble(&c, &tok).map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    fn poll_bubble(&mut self) {
        if !self.bubble_busy {
            return;
        }
        let finished: Option<Result<BubbleStatus, String>> = self
            .bubble_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        let Some(res) = finished else { return };
        self.bubble_busy = false;
        self.bubble_pending = None;
        if let Ok(status) = res {
            self.bubble = status;
        }
    }

    /// Open the explicit house-move panel, seeding it with the `adeia` the
    /// node currently holds. Edition/`PREV_HASH` are computed at submit time
    /// so a stale form cannot silently reuse an old edition.
    pub fn open_house_move(&mut self) {
        self.side_panel = Some(SidePanel::HouseMove);
        if self.house_move_adeia.trim().is_empty() {
            self.house_move_adeia = self
                .sync_docs
                .get("adeia.hdap")
                .cloned()
                .unwrap_or_default();
        }
        if self.house_move_new_pyle.trim().is_empty() {
            self.house_move_new_pyle = String::new();
        }
        self.house_move_status.clear();
    }

    pub fn open_diadosi(&mut self) {
        self.side_panel = Some(SidePanel::Diadosi);
        self.diadosi_status.clear();
        if self.diadosi_fallbacks.trim().is_empty() {
            if let Some(old) = self.sync_docs.get("diadosi.hdap") {
                if let Ok(doc) = hdap_core::doc::parse(old) {
                    if let Some(proxy) = hdap_core::protocol::DiadosiDoc::from_doc(&doc) {
                        self.diadosi_fallbacks = proxy.fallbacks.join(";");
                    }
                }
            }
            if self.diadosi_fallbacks.trim().is_empty() {
                self.suggest_diadosi_fallbacks();
            }
        }
    }

    /// Known, dialable pyles from the discovery bubble, excluding this node.
    /// Untrusted peers are left out: a fallback must be reachable when the
    /// home is gone.
    pub fn suggested_fallbacks(&self) -> Vec<String> {
        let here = self
            .session
            .as_ref()
            .map(|s| s.server_id.as_str())
            .unwrap_or("");
        let mut out = Vec::new();
        for peer in &self.bubble.peers {
            if peer.node_id.is_empty()
                || peer.node_id == here
                || peer.endpoint.trim().is_empty()
                || peer.tier == "untrusted"
                || out.iter().any(|p| p == &peer.node_id)
            {
                continue;
            }
            out.push(peer.node_id.clone());
            if out.len() == 16 {
                break;
            }
        }
        out
    }

    /// Fill the fallback field from the bubble, with honest feedback when the
    /// bubble is empty.
    pub fn suggest_diadosi_fallbacks(&mut self) {
        let peers = self.suggested_fallbacks();
        if peers.is_empty() {
            self.diadosi_status = self.strings.diadosi_no_peers.to_string();
            return;
        }
        self.diadosi_fallbacks = peers.join(";");
        self.diadosi_status =
            crate::i18n::fill1(self.strings.diadosi_suggested, &peers.len().to_string());
    }

    /// Sign a `diadosi.hdap` for the *current* home with the fallback list the
    /// user typed, and install it on this node. The document pins the exact
    /// prosopeion/adeia hashes, so a later ACL edit requires re-signing.
    pub fn submit_diadosi(&mut self) {
        if self.diadosi_busy {
            return;
        }
        let fallbacks: Vec<String> = self
            .diadosi_fallbacks
            .split([';', ','])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if fallbacks.is_empty() || fallbacks.len() > 16 {
            self.diadosi_status = self.strings.diadosi_need_fallback.to_string();
            return;
        }
        let Some((token, server_id)) = self
            .session
            .as_ref()
            .map(|s| (s.token.clone(), s.server_id.clone()))
        else {
            self.diadosi_status = self.strings.st_not_logged.to_string();
            return;
        };
        let Some(identity) = self.identity.clone() else {
            self.diadosi_status = self.strings.st_not_logged.to_string();
            return;
        };
        let Some(properties) = self.sync_docs.get("prosopeion.hdap").cloned() else {
            self.diadosi_status = self.strings.diadosi_need_docs.to_string();
            return;
        };
        let Some(adeia) = self.sync_docs.get("adeia.hdap").cloned() else {
            self.diadosi_status = self.strings.diadosi_need_docs.to_string();
            return;
        };
        let old = self
            .sync_docs
            .get("diadosi.hdap")
            .and_then(|text| hdap_core::doc::parse(text).ok());
        let edition = old.as_ref().map(|d| d.edition + 1).unwrap_or(1);
        let prev = old
            .as_ref()
            .map(|d| hdap_core::crypto::sha256_hex(d.render().as_bytes()));
        let body = match build_diadosi(
            &identity,
            &server_id,
            &fallbacks,
            &properties,
            &adeia,
            edition,
            prev,
        ) {
            Ok(b) => b,
            Err(e) => {
                self.diadosi_status = e;
                return;
            }
        };
        let Ok(c) = self.client() else {
            self.diadosi_status = self.strings.st_not_logged.to_string();
            return;
        };
        let slot: Pending<Result<u64, String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        self.diadosi_pending = Some(slot);
        self.diadosi_busy = true;
        self.diadosi_status = self.strings.diadosi_signing.to_string();
        std::thread::spawn(move || {
            let out = post_diadosi(&c, &token, &body, edition).map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    fn poll_diadosi(&mut self) {
        if !self.diadosi_busy {
            return;
        }
        let finished: Option<Result<u64, String>> = self
            .diadosi_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        let Some(res) = finished else { return };
        self.diadosi_busy = false;
        self.diadosi_pending = None;
        match res {
            Ok(edition) => {
                let msg = crate::i18n::fill1(self.strings.diadosi_ok, &edition.to_string());
                self.diadosi_status = msg.clone();
                self.notify(ToastKind::Success, msg);
                self.sync_docs.remove("diadosi.hdap");
            }
            Err(e) => {
                let msg = crate::i18n::fill1(self.strings.diadosi_fail, &e);
                self.diadosi_status = msg.clone();
                self.notify(ToastKind::Error, msg);
            }
        }
    }

    /// Sign and submit an explicit move to a new home pyle. The signature is
    /// over `hdap:house_move:<user>:><pyle>:<sha256(properties)>:<sha256(adeia)>`,
    /// so it remains valid when relayed by peers while the old home is down.
    pub fn submit_house_move(&mut self) {
        if self.house_move_busy {
            return;
        }
        let new_pyle = self.house_move_new_pyle.trim().to_string();
        if new_pyle.is_empty() {
            self.house_move_status = self.strings.house_move_need_pyle.to_string();
            return;
        }
        let Some(identity) = self.identity.clone() else {
            self.house_move_status = self.strings.st_not_logged.to_string();
            return;
        };
        let Some(tok) = self.session_token() else {
            self.house_move_status = self.strings.st_not_logged.to_string();
            return;
        };
        let current = self
            .sync_docs
            .get("adeia.hdap")
            .cloned()
            .unwrap_or_default();
        let body = match build_house_move(
            &identity,
            &new_pyle,
            &self.house_move_adeia,
            &current,
            self.now_secs(),
        ) {
            Ok(body) => body,
            Err(e) => {
                self.house_move_status = e;
                return;
            }
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.house_move_status = format!("{e}");
                return;
            }
        };
        let displayed_pyle = new_pyle.clone();
        let installed_adeia = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["adeia"].as_str().map(str::to_string))
            .unwrap_or_default();
        let slot: Pending<Result<HouseMoveDone, String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        self.house_move_pending = Some(slot);
        self.house_move_busy = true;
        self.house_move_status = self.strings.house_move_signing.to_string();
        std::thread::spawn(move || {
            let out = post_house_move(&c, &tok, &body).map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() =
                Some(out.map(|edition| (displayed_pyle, edition, installed_adeia)));
        });
    }

    fn poll_house_move(&mut self) {
        if !self.house_move_busy {
            return;
        }
        let finished: Option<Result<HouseMoveDone, String>> = self
            .house_move_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        let Some(res) = finished else { return };
        self.house_move_busy = false;
        self.house_move_pending = None;
        match res {
            Ok((pyle, edition, adeia)) => {
                if !adeia.is_empty() {
                    self.house_move_adeia = adeia;
                }
                let msg =
                    crate::i18n::fill2(self.strings.house_move_ok, &pyle, &edition.to_string());
                self.house_move_status = msg.clone();
                self.notify(ToastKind::Success, msg);
                self.sync_all();
            }
            Err(e) => {
                self.house_move_status = crate::i18n::fill1(self.strings.house_move_fail, &e);
                self.notify(ToastKind::Error, self.house_move_status.clone());
            }
        }
    }

    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Resolve a 64-hex content hash through this node: local copy, then the
    /// global ledger, then origin/replicas. The node caches a fetched blob in
    /// our own `cache/<hash>/...` namespace and registers the replica, so the
    /// result can be opened like any other file (Cenário B: no origin needed).
    pub fn lookup_hash(&mut self) {
        if self.hash_busy {
            return;
        }
        let hash = self.hash_input.trim().to_ascii_lowercase();
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            self.hash_result = Some(HashLookup {
                error: self.strings.hash_invalid.to_string(),
                ..HashLookup::default()
            });
            return;
        }
        let Some(tok) = self.session_token() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.hash_result = Some(HashLookup {
                    error: format!("{e}"),
                    ..HashLookup::default()
                });
                return;
            }
        };
        let body = serde_json::json!({ "hash": hash }).to_string().into_bytes();
        let slot: Pending<Result<HashLookup, String>> = Arc::new(Mutex::new(None));
        let slot_ref = Arc::clone(&slot);
        self.hash_pending = Some(slot);
        self.hash_busy = true;
        self.hash_result = None;
        std::thread::spawn(move || {
            let out = fetch_hash_lookup(&c, &tok, &body).map_err(|e| e.to_string());
            *slot_ref.lock().unwrap() = Some(out);
        });
    }

    fn poll_hash(&mut self) {
        if !self.hash_busy {
            return;
        }
        let finished: Option<Result<HashLookup, String>> = self
            .hash_pending
            .as_ref()
            .and_then(|p| p.lock().ok())
            .and_then(|mut lock| lock.take());
        let Some(res) = finished else { return };
        self.hash_busy = false;
        self.hash_pending = None;
        match res {
            Ok(found) => {
                let msg = format!("{}: {} {}", found.status, found.owner, found.path);
                self.status = msg.clone();
                self.notify(ToastKind::Success, msg);
                self.hash_result = Some(found);
            }
            Err(e) => {
                self.notify(ToastKind::Error, e.clone());
                self.hash_result = Some(HashLookup {
                    error: e,
                    ..HashLookup::default()
                });
            }
        }
    }

    /// Navigate to the folder holding a hash lookup result. A fetched blob is
    /// always in our own space; a local hit may belong to the owner we are
    /// already visiting.
    pub fn open_hash_result(&mut self) {
        let Some(found) = self.hash_result.clone() else {
            return;
        };
        if !found.error.is_empty() || found.path.is_empty() {
            return;
        }
        let mine = self.user_id();
        if Some(found.owner.clone()) != mine {
            self.open_user(found.owner.clone());
        }
        self.visiting_remote = false;
        self.cwd = found
            .path
            .rsplit_once('/')
            .map(|(dir, _)| dir.to_string())
            .unwrap_or_default();
        self.refresh();
    }

    /// Fetch market prices from `/timi` (katallaxia module).
    pub fn refresh_prices(&mut self) {
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        self.busy = Some("prices".into());
        match fetch_prices(&c) {
            Ok(prices) => {
                self.prices = prices;
                self.status = self.strings.st_prices_ok.to_string();
                self.notify(ToastKind::Success, self.strings.st_prices_ok.to_string());
            }
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_prices_fail, &format!("{e}"));
                self.notify(
                    ToastKind::Error,
                    crate::i18n::fill1(self.strings.st_prices_fail, &format!("{e}")),
                );
            }
        }
        self.busy = None;
    }

    /// Publish an alias (DDNS) via `/kerux`.
    pub fn publish_alias(&mut self) {
        let Some(tok) = self.session_token() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        if self.alias_input.is_empty() || self.alias_uri_input.is_empty() {
            self.status = self.strings.al_required.to_string();
            return;
        }
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        self.busy = Some("alias-publish".into());
        match publish_alias(&c, &tok, &self.alias_input, &self.alias_uri_input) {
            Ok(()) => {
                self.alias_result = Some(crate::i18n::fill2(
                    self.strings.al_result_pub,
                    &self.alias_input,
                    &self.alias_uri_input,
                ));
                self.status = self.strings.st_alias_ok.to_string();
                self.notify(ToastKind::Success, self.strings.st_alias_ok.to_string());
            }
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_alias_fail, &format!("{e}"));
                self.notify(
                    ToastKind::Error,
                    crate::i18n::fill1(self.strings.st_alias_fail, &format!("{e}")),
                );
            }
        }
        self.busy = None;
    }

    /// Resolve an alias via `GET /kerux/{alias}`.
    pub fn resolve_alias(&mut self) {
        if self.alias_input.is_empty() {
            self.status = self.strings.al_need_alias.to_string();
            return;
        }
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        self.busy = Some("alias-resolve".into());
        match resolve(&c, &self.alias_input) {
            Ok(uri) => {
                self.alias_result = Some(uri.clone());
                self.status = self.strings.st_resolve_ok.to_string();
                self.notify(ToastKind::Success, self.strings.st_resolve_ok.to_string());
            }
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_resolve_fail, &format!("{e}"));
                self.notify(
                    ToastKind::Error,
                    crate::i18n::fill1(self.strings.st_resolve_fail, &format!("{e}")),
                );
            }
        }
        self.busy = None;
    }

    /// Download the selected entry to `dest` (as file bytes).
    pub fn download_selected_to(&mut self, dest: &std::path::Path) {
        let Some(path) = self.selected.clone() else {
            self.status = self.strings.st_nothing_selected.to_string();
            return;
        };
        let Some(tok) = self.session_token() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let owner = self.active_owner().unwrap_or_default();
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        self.busy = Some("download".into());
        match download(&c, &tok, &owner, &path) {
            Ok((bytes, hash)) => {
                let result = std::fs::write(dest, &bytes).map_err(FlowError::Io);
                match result {
                    Ok(()) => {
                        let n = bytes.len();
                        self.last_download =
                            Some((path.clone(), dest.to_string_lossy().into_owned(), n, hash));
                        let m =
                            crate::i18n::fill2(self.strings.st_downloaded, &path, &n.to_string());
                        self.status = m.clone();
                        self.notify(ToastKind::Success, m);
                    }
                    Err(e) => {
                        self.status =
                            crate::i18n::fill1(self.strings.st_save_fail, &format!("{e}"));
                        self.notify(
                            ToastKind::Error,
                            crate::i18n::fill1(self.strings.st_save_fail, &format!("{e}")),
                        );
                    }
                }
            }
            Err(e) => {
                let msg = crate::i18n::fill1(self.strings.st_download_fail, &format!("{e}"));
                self.status = msg.clone();
                self.notify(ToastKind::Error, msg);
            }
        }
        self.busy = None;
    }

    /// Delete the selected entry.
    pub fn delete_selected(&mut self) {
        let Some(path) = self.selected.clone() else {
            self.status = self.strings.st_nothing_selected.to_string();
            return;
        };
        if self.read_only() {
            self.status = self.strings.st_delete_ro.to_string();
            return;
        }
        let Some(tok) = self.session_token() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let owner = self.active_owner().unwrap_or_default();
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        match delete(&c, &tok, &owner, &path) {
            Ok(true) => {
                // Retract it from the optimistic snapshot too: `refresh` paints
                // this folder from the tree while the live listing is on its
                // way, so a file left in the tree would blink back into view.
                if let Some(bucket) = self.tree.get_mut(&self.cwd) {
                    bucket.retain(|e| e.path != path);
                }
                self.selected = None;
                self.status = crate::i18n::fill1(self.strings.st_deleted, &path);
                self.notify(
                    ToastKind::Success,
                    crate::i18n::fill1(self.strings.st_deleted, &path),
                );
                self.refresh();
            }
            Ok(false) => {
                self.status = self.strings.st_nothing_delete.to_string();
                self.notify(ToastKind::Info, self.strings.st_nothing_delete.to_string());
            }
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_delete_fail, &format!("{e}"));
                self.notify(
                    ToastKind::Error,
                    crate::i18n::fill1(self.strings.st_delete_fail, &format!("{e}")),
                );
            }
        }
    }
}

/// Blocking register+login+health, executed on the connect worker thread.
fn do_connect(
    client: &HttpClient,
    id: &Identity,
    uid: &str,
    step: usize,
    deadline: std::time::Instant,
) -> Result<(Session, usize), String> {
    // `register` is idempotent (409 == already present) and consumes no
    // server-side one-shot state, so a single stalled connection is safe to
    // retry. `authenticate` is deliberately NOT retried: OTP steps are
    // single-use, so a replay would be rejected as a stolen step.
    let out_of_time = || format!("conexão excedeu {}s", CONNECT_DEADLINE.as_secs());
    if std::time::Instant::now() >= deadline {
        return Err(out_of_time());
    }
    // Checking the deadline only *between* operations is not enough: a single
    // blocking read can sit for the full I/O timeout. So cap every request at
    // whatever budget is left, which makes the deadline authoritative.
    let budgeted = || -> HttpClient {
        let left = deadline
            .saturating_duration_since(std::time::Instant::now())
            .max(std::time::Duration::from_millis(200));
        client.clone().with_timeouts(
            client.connect_timeout.min(left),
            client.io_timeout.min(left),
        )
    };
    let send = || -> Result<(), FlowError> {
        match register(&budgeted(), id) {
            Ok(_) => Ok(()),
            Err(FlowError::Http { status: 409, .. }) => Ok(()),
            Err(e) => Err(e),
        }
    };
    let registered = match send() {
        Ok(()) => Ok(()),
        // Only a transport-level failure (timeout/reset) is worth a retry;
        // a 429/400 would just fail again and make throttling worse.
        Err(FlowError::Io(_)) => send(),
        Err(e) => Err(e),
    };
    if let Err(e) = registered {
        return Err(format!("registro: {e}"));
    }
    // Factor-2 (OTP) preimages are single-use: the node remembers the last
    // consumed step per user and refuses anything below it. A fresh process
    // starts its counter from scratch, so walk forward to the step the node
    // expects — it reports the missing step in the 401 body, so this is one
    // extra round-trip, never a blind scan. Bounded to stay inside the
    // node's rate-limit burst.
    const MAX_STEP_PROBES: usize = 4;
    let mut step = step;
    let mut auth = None;
    let mut last_err = String::new();
    for _ in 0..MAX_STEP_PROBES {
        if std::time::Instant::now() >= deadline {
            return Err(out_of_time());
        }
        match authenticate(&budgeted(), id, uid, step) {
            Ok(a) => {
                auth = Some(a);
                break;
            }
            Err(FlowError::Http {
                status: 401,
                ref body,
            }) if body.contains("replayed") => {
                let next = serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| v["next"].as_u64())
                    .map(|n| n as usize)
                    .unwrap_or(step + 1);
                last_err = format!("login: http 401: {body}");
                if next <= step {
                    return Err(format!(
                        "login: o nó recusa o passo {step} e não informou um passo \
                         maior — a identidade local e o nó divergiram; apague o \
                         home e registre de novo"
                    ));
                }
                step = next;
            }
            Err(e) => return Err(format!("login: {e}")),
        }
    }
    let Some(auth) = auth else {
        return Err(format!(
            "{last_err} — o passo de OTP local ficou atrás do nó após \
             {MAX_STEP_PROBES} tentativas"
        ));
    };
    let (server_id, tls_pin) = budgeted()
        .get("/health", &Default::default())
        .ok()
        .and_then(|r| serde_json::from_slice::<serde_json::Value>(&r.body).ok())
        .map(|v| {
            (
                v["server_id"].as_str().unwrap_or_default().to_string(),
                v["tls_pin"].as_str().map(String::from),
            )
        })
        .unwrap_or_default();
    // The step is returned so the caller can persist it: the next login must
    // not replay it.
    Ok((
        Session {
            user_id: uid.to_string(),
            token: auth.token,
            exp: auth.exp,
            server_id,
            tls_pin,
        },
        step,
    ))
}

/// A transport-level failure, not an HTTP refusal. `FlowError::Io` is
/// rendered as `io: ...` and covers refused connections, resets and timeouts;
/// an HTTP 403/404/502 must never be mistaken for "the pyle fell".
fn is_transport_failure(err: &str) -> bool {
    let e = err.trim().to_ascii_lowercase();
    e.starts_with("io:")
        || e.contains("connection refused")
        || e.contains("connection reset")
        || e.contains("timed out")
        || e.contains("timeout")
        || e.contains("resource temporarily unavailable")
        || e.contains("unreachable")
}

/// Render a directory for status lines (`""` means the node root).
fn display_dir(cwd: &str) -> &str {
    if cwd.is_empty() {
        "/"
    } else {
        cwd
    }
}

/// Local wall-clock "HH:MM:SS" for the "last sync" freshness label. Wall
/// clock, not the protocol `kairos`, because this is when *we* looked, not a
/// signed event.
fn clock_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "{:02}:{:02}:{:02}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

fn load_local(
    password: &str,
    krypte: &std::path::Path,
    pros: &std::path::Path,
) -> Result<Identity, hdap_cli::IdentityStoreError> {
    identity_store::load(password.as_bytes(), krypte, pros)
}

/// Bucket the flat snapshot `ktema` list into `dir -> entries`. A file at
/// `docs/sub/a.txt` lands in bucket `docs/sub`; the root-level files and dirs
/// land in bucket `""`. Directories appear in their *parent* bucket (the node
/// lists `docs` and `docs/sub` as `dir: true` entries with their full path).
fn build_tree(snapshot: &[KtemaEntry]) -> std::collections::BTreeMap<String, Vec<KtemaEntry>> {
    let mut tree: std::collections::BTreeMap<String, Vec<KtemaEntry>> =
        std::collections::BTreeMap::new();
    for e in snapshot {
        let dir = match e.path.rfind('/') {
            Some(i) => e.path[..i].to_string(),
            None => String::new(),
        };
        tree.entry(dir).or_default().push(e.clone());
    }
    tree
}

#[cfg(test)]
impl App {
    /// Synchronous band claim for tests (blocks until PoW done).
    fn buy_band_now_sync(&mut self) {
        let Some(tok) = self.session_token() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let Some(identity) = self.identity.clone() else {
            self.status = self.strings.st_not_logged.to_string();
            return;
        };
        let c = match self.client() {
            Ok(c) => c,
            Err(e) => {
                self.status = crate::i18n::fill1(self.strings.st_client_err, &format!("{e}"));
                return;
            }
        };
        let total = hdap_cli::flow::band_mochthos(&c, &tok, &identity, 6).expect("band claim");
        self.band = total;
        self.status = format!("banda agora {total} bytes");
    }
}

/// Build the signed `diadosi.hdap` body. The document is signed by the owner
/// over its canonical bytes, and pins the current prosopeion/adeia hashes so
/// a fallback can only promote the exact identity it was authorized for.
fn build_diadosi(
    identity: &Identity,
    home: &str,
    fallbacks: &[String],
    properties: &str,
    adeia: &str,
    edition: u64,
    prev_hash: Option<String>,
) -> Result<Vec<u8>, String> {
    let adeia_doc = hdap_core::doc::parse(adeia).map_err(|e| e.to_string())?;
    if adeia_doc.doc_type != hdap_core::doc::DocType::Adeia {
        return Err("adeia.hdap is not an adeia document".into());
    }
    let owner = identity.global_id();
    let proxy = hdap_core::protocol::DiadosiDoc {
        owner: owner.clone(),
        owner_pubkey: hex::encode(identity.sign_pubkey()),
        home_pyle: home.to_string(),
        fallbacks: fallbacks.to_vec(),
        adeia_edition: adeia_doc.edition,
        adeia_hash: hdap_core::crypto::sha256_hex(adeia.as_bytes()),
        properties_hash: hdap_core::crypto::sha256_hex(properties.as_bytes()),
        edition,
        prev_hash,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let mut doc = proxy.to_doc();
    doc.sigs.push(hdap_core::doc::Signature {
        signer: owner,
        signer_pubkey: Some(proxy.owner_pubkey.clone()),
        signature: String::new(),
    });
    let input = doc.signature_input(0).map_err(|e| e.to_string())?;
    doc.sigs[0].signature = hdap_core::sig_to_b64(&identity.sign_bytes(input.as_bytes()));
    Ok(doc.render().into_bytes())
}

fn post_diadosi(
    client: &HttpClient,
    token: &str,
    body: &[u8],
    edition: u64,
) -> Result<u64, String> {
    let resp = client
        .post_with_token("/diadosi", &std::collections::BTreeMap::new(), token, body)
        .map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(v["error"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("diadosi {}", resp.status)));
    }
    Ok(v["edition"].as_u64().unwrap_or(edition))
}

/// Build the signed `POST /house_move` body. `current` is the node-truth
/// `adeia`; the new edition is strictly newer and points `PREV_HASH` at it.
pub(crate) fn build_house_move(
    identity: &Identity,
    new_pyle: &str,
    edited_adeia: &str,
    current_adeia: &str,
    now: u64,
) -> Result<Vec<u8>, String> {
    let current = hdap_core::doc::parse(current_adeia)
        .map_err(|_| "current adeia is not a valid document".to_string())?;
    if current.doc_type != hdap_core::doc::DocType::Adeia {
        return Err("current document is not an adeia".into());
    }
    let mut next =
        hdap_core::doc::parse(edited_adeia).map_err(|e| format!("new adeia is invalid: {e:?}"))?;
    if next.doc_type != hdap_core::doc::DocType::Adeia {
        return Err("new document is not an adeia".into());
    }
    let edition = current.edition.saturating_add(1).max(next.edition);
    next.edition = edition;
    next.prev_hash = Some(hdap_core::crypto::sha256_hex(current_adeia.as_bytes()));
    if next.created_at == 0 {
        next.created_at = now;
    }
    let properties = identity.signed_prosopeion_doc().render();
    let adeia = next.render();
    let payload =
        hdap_core::house_move_payload(&identity.global_id(), new_pyle, &properties, &adeia);
    let signature = hdap_core::sig_to_b64(&identity.sign_bytes(payload.as_bytes()));
    Ok(serde_json::json!({
        "properties": properties,
        "adeia": adeia,
        "new_pyle": new_pyle,
        "signature": signature,
    })
    .to_string()
    .into_bytes())
}

fn post_house_move(client: &HttpClient, token: &str, body: &[u8]) -> Result<u64, String> {
    let resp = client
        .post_with_token(
            "/house_move",
            &std::collections::BTreeMap::new(),
            token,
            body,
        )
        .map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(v["error"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("house_move {}", resp.status)));
    }
    v["adeia_edition"]
        .as_u64()
        .ok_or_else(|| "house_move response has no edition".to_string())
}

/// `POST /resolve_hash` -> the cached/local location and provenance flag.
fn fetch_hash_lookup(client: &HttpClient, token: &str, body: &[u8]) -> Result<HashLookup, String> {
    let resp = client
        .post_with_token(
            "/resolve_hash",
            &std::collections::BTreeMap::new(),
            token,
            body,
        )
        .map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(v["error"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("resolve_hash {}", resp.status)));
    }
    Ok(HashLookup {
        status: v["status"].as_str().unwrap_or("unknown").to_string(),
        owner: v["owner"].as_str().unwrap_or("").to_string(),
        path: v["path"].as_str().unwrap_or("").to_string(),
        source: v["source"]
            .as_str()
            .or_else(|| v["origin"]["server"].as_str())
            .unwrap_or("")
            .to_string(),
        verified: v["verified"].as_bool().unwrap_or(false),
        holders: v["holders"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        error: String::new(),
    })
}

/// Parse `GET /bubble` into the summary + peer rows.
fn fetch_bubble(client: &HttpClient, token: &str) -> Result<BubbleStatus, String> {
    let resp = client
        .get_with_token("/bubble", &std::collections::BTreeMap::new(), token)
        .map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("bubble status {}", resp.status));
    }
    let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    let counts = &v["counts"];
    let mut peers = Vec::new();
    for p in v["peers"].as_array().cloned().unwrap_or_default() {
        peers.push(BubblePeer {
            node_id: p["node_id"].as_str().unwrap_or("").to_string(),
            endpoint: p["endpoint"].as_str().unwrap_or("").to_string(),
            tier: p["tier"].as_str().unwrap_or("untrusted").to_string(),
            verified: p["verified"].as_bool().unwrap_or(false),
            failures: p["failures"].as_u64().unwrap_or(0) as u32,
            last_seen: p["last_seen"].as_u64().unwrap_or(0),
        });
    }
    Ok(BubbleStatus {
        total: counts["total"].as_u64().unwrap_or(peers.len() as u64) as usize,
        core: counts["core"].as_u64().unwrap_or(0) as usize,
        extended: counts["extended"].as_u64().unwrap_or(0) as usize,
        untrusted: counts["untrusted"].as_u64().unwrap_or(0) as usize,
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdap_server::http;
    use hdap_server::node::Node;
    use std::collections::BTreeMap;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn a_transport_failure_prompts_instead_of_silently_freezing() {
        let mut app = App {
            session: Some(Session {
                user_id: "jose_0123456789abcdef".into(),
                token: "tok".into(),
                exp: u64::MAX,
                server_id: "pyle-a".into(),
                tls_pin: None,
            }),
            ..Default::default()
        };
        app.note_link_failure("io: connection refused");
        assert!(app.link_down, "an I/O failure must surface as link loss");
        assert!(!app.suggest_house_move);
        app.leave_for_login();
        assert!(app.session.is_none(), "leaving must show the login page");
        assert!(
            app.suggest_house_move,
            "the next login must offer house move"
        );

        let mut app = App {
            session: Some(Session {
                user_id: "jose_0123456789abcdef".into(),
                token: "tok".into(),
                exp: u64::MAX,
                server_id: "pyle-a".into(),
                tls_pin: None,
            }),
            ..Default::default()
        };
        app.note_link_failure("http 403: forbidden");
        assert!(!app.link_down, "an authorization refusal is not link loss");
    }

    /// Spawn an in-process node over pinned TLS (same pattern as the CLI test).
    fn spawn_server_tls() -> (String, String, String) {
        let identity = hdap_tls::self_signed("node-gui", &["127.0.0.1", "localhost"]).unwrap();
        let pin = identity.pin();
        let tls = identity.server_config().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = hdap_server::Config {
            server_id: "node-gui".to_string(),
            choregia_per_mochthos: 1024 * 1024,
            pow: hdap_core::pow::PowPolicy::new(4, 1, 6),
            require_entry_pow: false,
            require_content_signature: false,
            max_body_bytes: 10 * 1024 * 1024,
            // The test drives many steps in a tight loop; the per-peer limiter
            // would otherwise reject the burst unrelated to what is asserted.
            rate_limit_per_sec: 0,
            ..hdap_server::Config::default()
        };
        let mut node = Node::new(cfg);
        node.tls_pin = Some(pin.clone());
        let node_ref = Arc::new(node);
        let handle = Arc::clone(&node_ref);
        thread::spawn(move || {
            let _ = http::serve_tls(listener, 10 * 1024 * 1024, tls, move |req| {
                handle.handle(&req)
            });
        });
        ("127.0.0.1".to_string(), port.to_string(), pin)
    }

    /// Spawn a second, *federating* in-process node whose id is its real
    /// endpoint-derived pyle id, so another node can dial it by URI. Returns
    /// `(host, port, pin, pyle_id)`.
    fn spawn_server_tls_open() -> (String, String, String, String) {
        let identity = hdap_tls::self_signed("node-open", &["127.0.0.1", "localhost"]).unwrap();
        let pin = identity.pin();
        let tls = identity.server_config().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let pyle_id = hdap_server::pyle::id_from_endpoint(&format!("127.0.0.1:{port}"));
        let cfg = hdap_server::Config {
            server_id: pyle_id.clone(),
            choregia_per_mochthos: 1024 * 1024,
            pow: hdap_core::pow::PowPolicy::new(4, 1, 6),
            require_entry_pow: false,
            require_content_signature: false,
            max_body_bytes: 10 * 1024 * 1024,
            rate_limit_per_sec: 0,
            ..hdap_server::Config::default()
        };
        let mut node = Node::new(cfg);
        node.tls_pin = Some(pin.clone());
        let handle = Arc::new(node);
        let served = Arc::clone(&handle);
        thread::spawn(move || {
            let _ = http::serve_tls(listener, 10 * 1024 * 1024, tls, move |req| {
                served.handle(&req)
            });
        });
        ("127.0.0.1".to_string(), port.to_string(), pin, pyle_id)
    }

    /// Pump `tick` until the in-flight directory listing lands, since
    /// `refresh()` runs on a worker thread.
    fn settle(app: &mut App) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while (app.listing || app.syncing || app.connecting) && std::time::Instant::now() < deadline
        {
            app.tick(0.0, f64::INFINITY);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!app.listing, "listing hung: {}", app.status);
        assert!(!app.syncing, "sync hung: {}", app.status);
    }

    /// Build an App logged in against the given in-process node endpoint.
    fn logged_in_app_on(host: String, port: String, pin: String) -> App {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let mut app = App {
            host,
            port,
            pin,
            insecure: false,
            nickname: format!("gui{}", now % 100_000),
            password: "s3gredo".into(),
            home_dir: std::env::temp_dir()
                .join(format!("hdap-gui-test-{now}-{nanos}"))
                .to_string_lossy()
                .into_owned(),
            ..App::default()
        };
        let _ = app.ensure_identity();
        app.connect();
        // connect() is async: pump tick() until the worker reports back.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while app.connecting && std::time::Instant::now() < deadline {
            app.tick(0.0, f64::INFINITY);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(app.session.is_some(), "connect: {}", app.status);
        settle(&mut app);
        app
    }

    /// Build an App logged in against an in-process node with a fresh home.
    fn logged_in_app() -> App {
        let (host, port, pin) = spawn_server_tls();
        logged_in_app_on(host, port, pin)
    }

    /// Pump `tick` until a URI-bar DDNS lookup lands.
    fn settle_alias(app: &mut App) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while app.uri_alias_busy && std::time::Instant::now() < deadline {
            app.tick(0.0, f64::INFINITY);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!app.uri_alias_busy, "DDNS lookup hung: {}", app.status);
    }

    /// Pump `tick` until an in-flight cross-pyle resolve lands.
    fn settle_mirror(app: &mut App) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while app.mirror_busy && std::time::Instant::now() < deadline {
            app.tick(0.0, f64::INFINITY);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!app.mirror_busy, "mirror hung: {}", app.status);
    }

    /// The People field is one box for every way a person is named: a full
    /// `HDAP!<pyle>@<user>/` URI must go down the cross-pyle path (not the
    /// nickname registry), and a bare global id must open directly.
    #[test]
    fn the_people_field_accepts_a_uri_and_a_global_id() {
        let mut app = logged_in_app();
        let me = app.user_id().expect("logged in");

        // A URI naming this very pyle resolves locally through POST /resolve,
        // and opening our own id must stay a writable space.
        app.visit(&format!("HDAP!node-gui@{me}/"));
        settle_mirror(&mut app);
        settle(&mut app);
        assert!(
            !app.read_only(),
            "our own space must not be read-only: {}",
            app.status
        );

        // A bare global id is already an identity: no registry lookup, no error.
        app.visit(&me);
        settle(&mut app);
        assert!(!app.read_only());

        // Empty input is a prompt, not a request.
        app.visit("   ");
        assert_eq!(app.status, app.strings.st_no_nick);
    }

    /// Opening a file while visiting someone else's space must read from *that*
    /// space. Regression: the preview fetched with our own id, so a file that
    /// was perfectly readable answered `404 file not found`.
    #[test]
    fn preview_reads_the_file_from_the_visited_space() {
        let mut app = logged_in_app();
        let client = app.client().unwrap();

        // A second person on the same pyle, with a file of their own.
        let other = Identity::generate("vizinho", 1);
        let other_id = register(&client, &other).unwrap().user_id;
        let auth = authenticate(&client, &other, &other_id, 1).unwrap();
        hdap_cli::flow::band_mochthos(&client, &auth.token, &other, 6).unwrap();
        let data = b"conteudo do vizinho".to_vec();
        let hash =
            hdap_cli::flow::upload(&client, &auth.token, &other, &other_id, "nota.txt", &data)
                .unwrap();

        // The owner grants us read; that is what makes their space visible.
        let me = app.user_id().unwrap();
        let perms = [hdap_core::protocol::Permission {
            scope: hdap_core::protocol::Scope::User(me),
            right: hdap_core::protocol::Right::Read,
        }];
        let acl = hdap_core::protocol::adeia_doc(&other_id, 1, None, 1, &perms, None).render();
        let mut headers = BTreeMap::new();
        headers.insert(
            "authorization".to_string(),
            format!("Bearer {}", auth.token),
        );
        let resp = client
            .request("POST", "/adeia", &BTreeMap::new(), &headers, acl.as_bytes())
            .unwrap();
        assert!(
            (200..300).contains(&resp.status),
            "grant rejected: {}",
            String::from_utf8_lossy(&resp.body)
        );

        // Visiting their space, the preview must fetch from their namespace.
        app.visiting = other_id.clone();
        app.open_preview("nota.txt", &hash);

        let preview = app.preview.as_ref().expect("preview opened");
        assert_eq!(preview.data, data);
        assert!(
            !app.status.contains("404"),
            "preview hit the wrong space: {}",
            app.status
        );
    }

    /// A source pyle B seeded with one file under its owner, plus the pieces a
    /// cross-pyle test needs to drive node A.
    struct SourcePyle {
        host: String,
        port: String,
        pin: String,
        pyle_id: String,
        owner_id: String,
        token: String,
        data: Vec<u8>,
    }

    impl SourcePyle {
        fn client(&self) -> HttpClient {
            HttpClient::new_tls(&self.host, self.port.parse().unwrap(), self.pin.clone())
        }

        /// Publish the owner's `adeia` granting `guest` read on B.
        fn grant_read(&self, guest: &str) {
            let perms = [hdap_core::protocol::Permission {
                scope: hdap_core::protocol::Scope::User(guest.to_string()),
                right: hdap_core::protocol::Right::Read,
            }];
            let acl =
                hdap_core::protocol::adeia_doc(&self.owner_id, 1, None, 1, &perms, None).render();
            let mut headers = BTreeMap::new();
            headers.insert(
                "authorization".to_string(),
                format!("Bearer {}", self.token),
            );
            let resp = self
                .client()
                .request("POST", "/adeia", &BTreeMap::new(), &headers, acl.as_bytes())
                .unwrap();
            assert!((200..300).contains(&resp.status), "grant: {}", resp.status);
        }
    }

    fn source_pyle_b(path: &str, data: &[u8]) -> SourcePyle {
        let (host, port, pin, pyle_id) = spawn_server_tls_open();
        let client = HttpClient::new_tls(&host, port.parse().unwrap(), pin.clone());
        let owner = Identity::generate("vizinho", 1);
        let owner_id = register(&client, &owner).unwrap().user_id;
        let auth = authenticate(&client, &owner, &owner_id, 1).unwrap();
        hdap_cli::flow::band_mochthos(&client, &auth.token, &owner, 6).unwrap();
        hdap_cli::flow::upload(&client, &auth.token, &owner, &owner_id, path, data).unwrap();
        SourcePyle {
            host,
            port,
            pin,
            pyle_id,
            owner_id,
            token: auth.token,
            data: data.to_vec(),
        }
    }

    /// The whole cross-pyle round trip as the GUI performs it: a file uploaded
    /// on pyle B, whose owner grants us read, must be pulled into this pyle when
    /// we visit `HDAP!<B>@<owner>/docs` and show up in the grid — and its bytes
    /// must preview correctly. This is the one path server tests never cover:
    /// the *remote* (mirrored) namespace rendered by the explorer.
    #[test]
    fn a_file_uploaded_on_another_pyle_shows_up_in_the_mirror() {
        let src = source_pyle_b("docs/chegou.txt", b"arquivo que veio do outro pyle");
        let data = src.data.clone();

        // Pyle A — ours.
        let (host_a, port_a, pin_a, _id_a) = spawn_server_tls_open();
        let mut app = logged_in_app_on(host_a, port_a, pin_a);
        let me = app.user_id().unwrap();

        // The owner on B grants us read.
        src.grant_read(&me);

        // Visiting the other pyle's space mirrors the file here.
        app.visit(&format!("HDAP!{}@{}/docs", src.pyle_id, src.owner_id));
        settle_mirror(&mut app);
        settle(&mut app);
        assert!(app.visiting_remote, "must be a mirror: {}", app.status);
        assert!(
            app.entries.iter().any(|e| e.name == "chegou.txt"),
            "mirrored file missing from the grid ({}): {:?}",
            app.status,
            app.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );

        // A full grant must not be reported as a denial (the source's `pow/*`
        // artefacts are never counted as withheld content).
        assert!(
            app.toasts.iter().all(|t| !t.text.contains("adeia")),
            "a granted mirror must not claim denial: {:?}",
            app.toasts.iter().map(|t| &t.text).collect::<Vec<_>>()
        );

        // …and its content is readable from the mirror.
        let hash = app
            .entries
            .iter()
            .find(|e| e.name == "chegou.txt")
            .unwrap()
            .hash
            .clone();
        app.open_preview("docs/chegou.txt", &hash);
        let preview = app
            .preview
            .as_ref()
            .unwrap_or_else(|| panic!("preview not opened (status: {})", app.status));
        assert_eq!(preview.data, data);
    }

    /// Without a grant the source withholds the file — and the mirror must say
    /// so instead of pretending the resolve succeeded. Regression for the
    /// report "it mirrors, but the file doesn't come": the resolve returns
    /// `copied` for the public docs and a `denied` count for the rest, and the
    /// GUI surfaces the owner's missing grant.
    #[test]
    fn a_mirror_without_a_grant_says_the_files_were_withheld() {
        let src = source_pyle_b("docs/segredo.txt", b"nao autorizado");
        let (host_a, port_a, pin_a, id_a) = spawn_server_tls_open();
        let mut app = logged_in_app_on(host_a, port_a, pin_a);

        // No grant is published on B.
        app.visit(&format!("HDAP!{}@{}/docs", src.pyle_id, src.owner_id));
        settle_mirror(&mut app);
        settle(&mut app);

        assert!(
            app.entries.is_empty(),
            "the grid must not keep another space's rows: {:?}",
            app.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        // The toast names the cause and the exact withheld count (the `pow/*`
        // band artefacts must not be miscounted as denied content).
        let expected = crate::i18n::fill2(app.strings.st_mirror_denied, "1", &id_a);
        assert!(
            app.toasts.iter().any(|t| t.text == expected),
            "withheld files must be explained, not silent (want {expected:?}): {:?}",
            app.toasts.iter().map(|t| &t.text).collect::<Vec<_>>()
        );
    }

    /// A guest whose `adeia` grant includes write may edit a space that lives
    /// on **this** pyle (the server enforces the permission), while a space
    /// mirrored from another pyle stays read-only — a replica cannot be written.
    #[test]
    fn a_guest_granted_write_may_edit_a_local_space_but_not_a_mirror() {
        let mut app = logged_in_app();
        let client = app.client().unwrap();

        let other = Identity::generate("vizinho", 1);
        let other_id = register(&client, &other).unwrap().user_id;
        let auth = authenticate(&client, &other, &other_id, 1).unwrap();
        hdap_cli::flow::band_mochthos(&client, &auth.token, &other, 6).unwrap();
        hdap_cli::flow::upload(&client, &auth.token, &other, &other_id, "docs/x.txt", b"x")
            .unwrap();

        // Grant us write (which the server reads as read+write).
        let me = app.user_id().unwrap();
        let perms = [hdap_core::protocol::Permission {
            scope: hdap_core::protocol::Scope::User(me),
            right: hdap_core::protocol::Right::Write,
        }];
        let acl = hdap_core::protocol::adeia_doc(&other_id, 1, None, 1, &perms, None).render();
        let mut headers = BTreeMap::new();
        headers.insert(
            "authorization".to_string(),
            format!("Bearer {}", auth.token),
        );
        let resp = client
            .request("POST", "/adeia", &BTreeMap::new(), &headers, acl.as_bytes())
            .unwrap();
        assert!((200..300).contains(&resp.status), "grant: {}", resp.status);

        // A space owned on this pyle is not a mirror: not read-only.
        app.visiting = other_id.clone();
        app.visiting_remote = false;
        app.cwd = String::new();
        app.refresh();
        settle(&mut app);
        assert!(!app.read_only(), "local visit must be cancellable by adeia");
        assert!(
            app.entries.iter().any(|e| e.name == "docs"),
            "{}",
            app.status
        );

        // The guest uploads into the owner's directory.
        app.cwd = "docs".into();
        app.refresh();
        settle(&mut app);
        app.pending_upload = Some(("novo.txt".into(), b"novo".to_vec()));
        app.do_upload();
        settle(&mut app);
        assert!(
            app.entries.iter().any(|e| e.name == "novo.txt"),
            "guest write blocked: {}",
            app.status
        );

        // …and deletes the owner's file.
        app.select("docs/x.txt");
        app.delete_selected();
        settle(&mut app);
        assert!(
            !app.entries.iter().any(|e| e.name == "x.txt"),
            "guest delete blocked: {}",
            app.status
        );

        // A mirrored space is physically a replica: always read-only.
        app.visiting_remote = true;
        assert!(app.read_only());
    }

    /// Reload must re-resolve the origin while visiting another pyle, so a grant
    /// published after the first visit arrives without retyping the URI.
    #[test]
    fn reload_re_resolves_the_origin_while_visiting_another_pyle() {
        let mut app = logged_in_app();
        settle(&mut app);

        // At home, reload is an ordinary relist.
        app.sync_space();
        assert!(app.listing, "home reload should list locally");
        settle(&mut app);

        // Visiting a space that lives elsewhere, reload is a fresh resolve.
        app.visiting = "outro_aabbccddeeff0011".to_string();
        app.visiting_server = "pyle-unknown".to_string();
        app.sync_space();
        assert!(
            app.mirror_busy,
            "visiting reload must re-resolve the origin, not relist the mirror"
        );
        settle_mirror(&mut app);
    }

    /// "Back to my space" must relist even when the visited space was showing
    /// its root (`cwd == ""`), the case where `cd("")` is a no-op and left the
    /// grid showing the other user's files.
    #[test]
    fn return_home_reloads_when_the_visited_space_was_at_its_root() {
        let mut app = logged_in_app();
        settle(&mut app);

        app.visiting = "outro_aabbccddeeff0011".to_string();
        app.visiting_server = "pyle-unknown".to_string();
        app.cwd = String::new();
        app.entries.clear();

        app.return_home();
        assert!(app.visiting.is_empty(), "still visiting: {}", app.visiting);
        assert!(app.listing, "home must be relisted, not left stale");

        settle(&mut app);
        assert!(
            app.entries.iter().any(|e| e.name == "adeia.hdap"),
            "home listing missing after returning: {:?}",
            app.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    #[test]
    #[ignore] // manual: reproduces GUI connect with wizard defaults vs live run.sh server
    fn manual_connect_wizard_defaults_live_server() {
        let mut app = App {
            host: "127.0.0.1".into(),
            port: "8443".into(),
            pin: String::new(), // wizard default → TOFU
            nickname: "usuario".into(),
            password: "senha123".into(),
            home_dir: String::new(), // wizard default
            ..App::default()
        };
        let start = std::time::Instant::now();
        app.connect();
        let deadline = start + std::time::Duration::from_secs(20);
        while (app.connecting || app.listing) && std::time::Instant::now() < deadline {
            app.tick(0.0, f64::INFINITY);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        println!(
            "connect after {:?}: session={} status={:?}",
            start.elapsed(),
            app.session.is_some(),
            app.status
        );
        println!("pin adotado (TOFU): {:?}", app.pin);
        println!("itens em /: {}", app.entries.len());
        assert!(!app.connecting, "connect hung");
        assert!(app.session.is_some(), "TOFU connect failed: {}", app.status);
        assert!(!app.pin.is_empty(), "pin was not adopted from /health");
    }

    #[test]
    fn connect_survives_one_stalled_register_connection() {
        // A node that accepts the first connection and never answers, then
        // behaves normally: `register` must be retried once so a single
        // stalled socket cannot kill the whole login.
        let (host, port, pin) = spawn_server_tls();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut app = App {
            host,
            port: port.clone(),
            pin,
            nickname: format!("retry{}", now % 100_000),
            password: "s3gredo".into(),
            home_dir: std::env::temp_dir()
                .join(format!("hdap-gui-retry-{now}"))
                .to_string_lossy()
                .into_owned(),
            ..App::default()
        };
        let id = app.ensure_identity().expect("identity");
        // A black-holed peer makes the first register stall at the transport
        // level; the retry hits the same peer, so both fail — the point is
        // that the failure is reported as a named timeout, not raw EAGAIN.
        app.host = "10.255.255.1".into();
        app.port = "9".into();
        let start = std::time::Instant::now();
        let err = do_connect(
            &app.client().unwrap(),
            &id,
            &id.global_id(),
            1,
            std::time::Instant::now() + CONNECT_DEADLINE,
        )
        .expect_err("unreachable node must fail");
        assert!(
            err.contains("timeout"),
            "expected a named timeout, got: {err}"
        );
        assert!(
            !err.contains("Resource temporarily unavailable"),
            "EAGAIN leaked: {err}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(30),
            "took {:?}",
            start.elapsed()
        );
        let _ = std::fs::remove_dir_all(std::path::PathBuf::from(&app.home_dir));
    }

    /// Regression: the OTP (factor-2) counter used to live only in memory, so
    /// a *second* GUI process for the same home was rejected with
    /// "factor 2 step replayed" — the app could log in exactly once per node.
    /// The step must now be persisted, so a fresh process logs back in.
    /// Drive the real egui frame loop the way `eframe` does. Unit tests that
    /// call `App` methods directly never touch the renderer, so a panic in
    /// `view::render` (or a renderer that stops the app from polling workers)
    /// would only ever show up in the real window: the frame dies and the
    /// status stays "conectando ao pyle..." forever.
    fn render_frames(ctx: &egui::Context, app: &mut App, frames: usize) {
        for _ in 0..frames {
            let mut out = ctx.run_ui(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    crate::view::render(ui, app);
                });
            });
            // eframe paints these between frames; headless there is no painter,
            // so consume them instead of tripping epaint's drop assertion.
            out.textures_delta.clear();
        }
    }

    /// A node that accepts the TCP connection and then goes silent used to
    /// hold the wizard on "conectando ao pyle..." for minutes (each read
    /// burns the full I/O timeout, and the OTP walk repeats that several
    /// times). The whole attempt must be bounded by the deadline.
    /// Regression: the file actions used to be rendered *after* the listing's
    /// `ScrollArea`, which fills its panel — so the upload button was laid out
    /// outside the visible area and the app looked like it had no upload at
    /// all. A full folder is the worst case, so that is what we render.
    /// A confirmation the user just got must survive the listing that lands
    /// right after it. This was silently eating every "salvo"/"publicado"
    /// message, which made the app feel unresponsive even when it worked.
    /// A new file starts with `parsed` blank, which used to make `is_dirty`
    /// true — but `apply_form` parses `parsed` to re-render the document, so
    /// ticking a box in a brand new file produced a parse error and the form
    /// silently did nothing. The dirty flag now lives in `on_disk`.
    #[test]
    fn a_new_file_can_be_edited_by_form_before_its_first_save() {
        use crate::editor::{self, Form};

        let mut app = logged_in_app();
        editor::create(&mut app, "novo.hdap", crate::editor::Template::Adeia);
        let st = app.editor.clone().expect("editor opened");
        assert!(
            st.is_dirty(),
            "a file that is not on the node yet is unsaved"
        );
        assert!(st.error.is_empty(), "template must parse: {}", st.error);

        // Tick a permission: the document must be rewritten, not rejected.
        if let Some(mut st) = app.editor.take() {
            st.form = Form::Perms(vec![crate::editor::PermRow {
                scope: "all".into(),
                right: "read".into(),
            }]);
            editor::apply_form(&app, &mut st);
            app.editor = Some(st);
        }
        let st = app.editor.clone().unwrap();
        assert!(
            st.error.is_empty(),
            "form edit on a new file must not error: {}",
            st.error
        );
        assert!(
            st.text.contains("PERM0000: PERM "),
            "form must reach the document text:\n{}",
            st.text
        );
        assert!(st.is_dirty(), "still unsaved until the upload lands");
    }

    /// `is_dirty` compared the text against `parsed`, and `apply_form` sets
    /// both — so any form edit of an existing document looked saved and the
    /// "salvar" button went quiet. Dirty must mean "the node lacks this text".
    #[test]
    fn a_form_edit_of_an_open_file_is_dirty_until_saved() {
        use crate::editor::{self, Form};

        let mut app = logged_in_app();
        editor::open(&mut app, "adeia.hdap");
        let st = app.editor.clone().expect("editor opened");
        assert!(!st.is_dirty(), "just opened = clean");

        if let Some(mut st) = app.editor.take() {
            st.form = Form::Perms(vec![crate::editor::PermRow {
                scope: "all".into(),
                right: "read".into(),
            }]);
            editor::apply_form(&app, &mut st);
            app.editor = Some(st);
        }
        let st = app.editor.clone().unwrap();
        assert!(
            st.is_dirty(),
            "a form edit is unsaved work even though the text parses"
        );
    }

    /// The button that mines band was wired to a helper that asks the node for
    /// a challenge *before* spawning the solver — and returned early on any
    /// error, so the mining dialog never appeared. Nothing covered the GUI
    /// path: every band test used the synchronous helper instead.
    #[test]
    fn band_can_be_mined_through_the_gui_button() {
        let mut app = logged_in_app();
        assert_eq!(app.band, 0, "a fresh user has no band");
        app.begin_band(0);
        assert!(
            app.pow.is_some(),
            "the mining dialog must open right away: {}",
            app.status
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while app.pow.is_some() && std::time::Instant::now() < deadline {
            app.tick(0.0, f64::INFINITY);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(app.pow.is_none(), "the mining dialog never closed");
        assert!(
            app.band > 0,
            "mining must credit band, status: {}",
            app.status
        );
    }

    /// Double click = "open this". For a `.hdap` that has to mean the editor.
    #[test]
    fn double_clicking_a_document_opens_the_editor() {
        let mut app = logged_in_app();
        assert!(app.editor.is_none());
        app.open_entry("adeia.hdap", false);
        let st = app.editor.clone().expect(".hdap must open in the editor");
        assert_eq!(st.path, "adeia.hdap");
        assert!(st.error.is_empty(), "seeded doc must parse: {}", st.error);

        // A plain file is still just a selection.
        app.buy_band_now_sync();
        app.editor = None;
        app.open_entry("nota.txt", false);
        assert!(app.editor.is_none(), "text files are not documents");
        assert_eq!(app.selected.as_deref(), Some("nota.txt"));
    }

    #[test]
    fn a_late_listing_does_not_stomp_a_fresh_status() {
        let mut app = logged_in_app();
        let one = vec![KtemaEntry {
            name: "x".into(),
            is_dir: false,
            path: "x".into(),
            size: 1,
            hash: "c".repeat(64),
        }];
        let land_listing = |app: &mut App| {
            app.listing = true;
            let slot: Pending<Result<Vec<KtemaEntry>, String>> = Arc::new(Mutex::new(None));
            *slot.lock().unwrap() = Some(Ok(one.clone()));
            app.list_pending = Some(slot);
            app.tick(0.0, f64::INFINITY);
        };

        // A listing that was already in flight when the save reported.
        app.list_epoch = app.status_epoch;
        app.say("salvo adeia.hdap");
        land_listing(&mut app);
        assert_eq!(app.status, "salvo adeia.hdap");

        // With nothing newer, the listing status is still allowed to show.
        app.list_epoch = app.status_epoch;
        land_listing(&mut app);
        assert!(app.status.contains("itens"), "{}", app.status);
    }

    /// The whole point of the hestia seeding + guided editor, end to end:
    /// log in, find the generated ACL, open it, tick a permission in the
    /// form, save, and read the change back off the node.
    #[test]
    fn seeded_acl_can_be_edited_by_form_and_saved_back() {
        use crate::editor::{self, PermRow, Template};

        let mut app = logged_in_app();
        // Saving costs band (every upload does), so claim some first.
        app.buy_band_now_sync();
        assert!(app.band > 0, "band: {}", app.status);
        // A fresh space is never empty.
        let names: Vec<String> = app.entries.iter().map(|e| e.name.clone()).collect();
        assert!(
            names.contains(&"adeia.hdap".to_string())
                && names.contains(&"prosopeion.hdap".to_string()),
            "hestia not seeded, root = {names:?}"
        );

        // Open the ACL in the editor.
        app.select("adeia.hdap");
        editor::open(&mut app, "adeia.hdap");
        let st = app.editor.clone().expect("editor opened");
        assert!(st.error.is_empty(), "seeded adeia must parse: {}", st.error);
        assert!(
            matches!(st.form, crate::editor::Form::Perms(ref r) if r.is_empty()),
            "a new ACL grants nothing: {:?}",
            st.form
        );

        // Tick a permission in the form.
        if let Some(mut st) = app.editor.take() {
            st.form = crate::editor::Form::Perms(vec![PermRow {
                scope: "all".into(),
                right: "read".into(),
            }]);
            editor::apply_form(&app, &mut st);
            app.editor = Some(st);
        }
        let st = app.editor.clone().unwrap();
        assert!(
            st.error.is_empty(),
            "form produced invalid doc: {}",
            st.error
        );
        assert!(
            st.text.contains("PERM"),
            "the form did not reach the document text:\n{}",
            st.text
        );

        // Save it back and re-read from the node.
        editor::save(&mut app);
        settle(&mut app);
        assert!(
            !app.status.contains("falhou") && !app.status.contains("recusad"),
            "save failed: {}",
            app.status
        );
        // The config panel must now show the node truth (the save re-syncs).
        let synced = app.sync_docs.get("adeia.hdap").cloned().unwrap_or_default();
        assert!(
            synced.contains("PERM"),
            "panel doc is stale after save:\n{synced}"
        );
        let token = app.session_token().unwrap();
        let owner = app.user_id().unwrap();
        let c = app.client().unwrap();
        let (bytes, _) =
            hdap_cli::flow::download(&c, &token, &owner, "adeia.hdap").expect("read back");
        let text = String::from_utf8(bytes).expect("utf-8");
        let d = hdap_core::doc::parse(&text).expect("saved doc parses");
        assert_eq!(d.doc_type, hdap_core::doc::DocType::Adeia);
        assert_eq!(
            d.body.get("PERM0000").map(String::as_str),
            Some(format!("PERM {owner} all read").as_str()),
            "the permission did not round-trip:\n{text}"
        );

        // Creating a config file from a template also lands on the node.
        editor::create(&mut app, "kerux.hdap", Template::Kerux);
        let st = app.editor.clone().unwrap();
        assert!(st.error.is_empty(), "template invalid: {}", st.error);
        assert!(st.is_dirty(), "a new file must start unsaved");
        editor::save(&mut app);
        settle(&mut app);
        assert!(
            !app.status.contains("falhou") && !app.status.contains("recusad"),
            "kerux save failed: {}",
            app.status
        );
        let names: Vec<String> = app.entries.iter().map(|e| e.name.clone()).collect();
        assert!(
            names.contains(&"kerux.hdap".to_string()),
            "root = {names:?}"
        );
        assert!(
            app.sync_docs.keys().any(|p| p == "kerux.hdap"),
            "kerux not re-synced after save"
        );
    }

    /// A selected file has a path of its own. The URI used to name the
    /// *directory* and then append that file's hash, so it pointed at the
    /// parent while promising the child's content.
    #[test]
    fn the_logical_uri_names_the_selected_file_not_its_folder() {
        let mut app = logged_in_app();
        let uid = app.user_id().expect("logged in");
        app.cd("docs");
        app.entries.push(KtemaEntry {
            name: "a.txt".into(),
            is_dir: false,
            path: "docs/a.txt".into(),
            size: 12,
            hash: "b".repeat(64),
        });
        app.select("docs/a.txt");
        app.uri_with_hash = true;
        assert_eq!(
            app.logical_uri(),
            format!("HDAP!node-gui@{uid}/docs/a.txt?hash={}", "b".repeat(64))
        );

        // A directory has no hash, and selecting one does not navigate, so
        // the URI keeps naming the folder you are actually in.
        app.entries.push(KtemaEntry {
            name: "sub".into(),
            is_dir: true,
            path: "docs/sub".into(),
            size: 0,
            hash: String::new(),
        });
        app.select("docs/sub");
        assert_eq!(app.logical_uri(), format!("HDAP!node-gui@{uid}/docs"));
        app.cd("docs/sub");
        assert_eq!(app.logical_uri(), format!("HDAP!node-gui@{uid}/docs/sub"));
    }

    /// The identity bug: a second GUI used to open as the first logged-in
    /// user because an empty home collapsed everyone into one shared folder.
    /// Now the nickname derives its own vault, and reusing a vault under a
    /// different nickname is refused instead of silently impersonating.
    #[test]
    fn the_default_home_is_per_nickname_and_never_shared() {
        let mut app = App {
            nickname: String::new(),
            ..App::default()
        };
        assert_eq!(
            "anon",
            app.home_path().file_name().unwrap().to_str().unwrap(),
            "empty nickname falls back to 'anon', not a shared folder"
        );
        app.nickname = "José Lima".into();
        assert_eq!(
            "jose_lima",
            app.home_path().file_name().unwrap().to_str().unwrap(),
            "two spellings of one person give one folder"
        );
        // Two different nicks → two different vaults, so no cross-identity
        // login is even reachable by default.
        app.nickname = "maria".into();
        let m = app.home_path();
        app.nickname = "joao".into();
        let j = app.home_path();
        assert_ne!(m, j, "maria and joao must never share a home by default");
    }

    /// `HDAP_HOME` moves the default base; without it, the vault must live in
    /// a persistent OS data directory, never in `/tmp`. The nickname still
    /// namespaces it, so a shared base never merges two vaults.
    #[test]
    fn hdap_home_relocates_the_default_without_merging_vaults() {
        let set = |v: &str| {
            let owned = v.to_string();
            move |key: &str| match key {
                "HDAP_HOME" => Some(std::ffi::OsString::from(owned.clone())),
                _ => None,
            }
        };
        let with_env = |nickname: &str| resolve_home_with("", nickname, &set("/srv/hdap"));

        assert_eq!(
            std::path::PathBuf::from("/srv/hdap/jose_lima"),
            with_env("José Lima"),
            "HDAP_HOME replaces the base and the nickname still namespaces it"
        );
        assert_ne!(
            with_env("maria"),
            with_env("joao"),
            "two identities under one HDAP_HOME must not share a krypte.hdap"
        );
        let persistent = |key: &str| match key {
            "HOME" => Some(std::ffi::OsString::from("/srv/home")),
            "APPDATA" | "XDG_DATA_HOME" | "USERPROFILE" | "HDAP_HOME" => None,
            _ => None,
        };
        assert_eq!(
            resolve_home_with("", "maria", &persistent),
            std::path::PathBuf::from("/srv/home/.local/share/hdap/maria"),
            "the fallback base must be persistent, not the system temp dir"
        );
    }

    /// An explicit home (or HDAP_HOME) is the BASE directory; the nickname
    /// is always appended to ensure multi-user isolation. A blank home is
    /// treated as unset.
    #[test]
    fn an_explicit_home_is_the_base_directory() {
        assert_eq!(
            std::path::PathBuf::from("/srv/vaults/jose/maria"),
            resolve_home("/srv/vaults/jose", "maria"),
            "explicit home is the base; nickname is appended"
        );
        assert_eq!(
            resolve_home("   ", "jose"),
            resolve_home("", "jose"),
            "a blank home is the same as an unset one"
        );
    }

    /// Two different users on the same node must have separate vaults,
    /// separate sessions, and separate OTP chains.
    #[test]
    fn two_different_users_on_same_node_have_separate_state() {
        let tmp = std::env::temp_dir().join("hdap-gui-test-two-users");
        let _ = std::fs::remove_dir_all(&tmp);

        // User 1: alice
        let mut app1 = App {
            home_dir: tmp.to_string_lossy().to_string(),
            nickname: "alice".into(),
            password: "password1".into(),
            ..App::default()
        };
        let id1 = app1.ensure_identity().expect("alice identity created");
        assert_eq!(id1.nickname, "alice");

        // User 2: bob - same base dir, different nickname
        let mut app2 = App {
            home_dir: tmp.to_string_lossy().to_string(),
            nickname: "bob".into(),
            password: "password2".into(),
            ..App::default()
        };
        let id2 = app2.ensure_identity().expect("bob identity created");
        assert_eq!(id2.nickname, "bob");

        // They must have different vault directories
        assert_ne!(app1.home_path(), app2.home_path());

        // Their vault files must be different
        let krypte1 = app1.home_path().join("krypte.hdap");
        let krypte2 = app2.home_path().join("krypte.hdap");
        assert_ne!(krypte1, krypte2);
        assert!(krypte1.exists());
        assert!(krypte2.exists());

        // The prosopeion files must contain different nicknames
        let pros1 = std::fs::read_to_string(app1.home_path().join("prosopeion.hdap")).unwrap();
        let pros2 = std::fs::read_to_string(app2.home_path().join("prosopeion.hdap")).unwrap();
        assert!(pros1.contains("NICKNAME: alice"));
        assert!(pros2.contains("NICKNAME: bob"));

        // OTP step files don't exist yet (created on first login)
        assert!(!app1.otp_step_file().exists());
        assert!(!app2.otp_step_file().exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_right_hand_panel_toggles_closed() {
        use crate::app::SidePanel;
        let mut app = App::default();
        assert!(app.side_panel.is_none());
        app.toggle_panel(SidePanel::Prices);
        assert_eq!(app.side_panel, Some(SidePanel::Prices));
        app.toggle_panel(SidePanel::Prices);
        assert!(
            app.side_panel.is_none(),
            "clicking the active button must close the panel"
        );
        app.toggle_panel(SidePanel::Prices);
        app.toggle_panel(SidePanel::Editor);
        assert_eq!(app.side_panel, Some(SidePanel::Editor));
    }

    /// The ⧉ button parked the URI in `app.rs` and stopped there: nothing ever
    /// called `copy_text`, so the button reported "copiado" and copied
    /// nothing. The view has to drain the buffer.
    #[test]
    fn a_clipboard_request_reaches_the_egui_context() {
        let mut app = App::default();
        app.request_clipboard("HDAP!node-gui@u/docs/a.txt");
        assert_eq!(
            app.pending_clipboard.as_deref(),
            Some("HDAP!node-gui@u/docs/a.txt")
        );
        let ctx = egui::Context::default();
        let mut out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(960.0, 640.0),
                )),
                ..Default::default()
            },
            |ctx| {
                let _ =
                    egui::CentralPanel::default().show(ctx, |ui| crate::view::render(ui, &mut app));
            },
        );
        out.textures_delta.clear();
        assert!(
            app.pending_clipboard.is_none(),
            "the view must drain the clipboard buffer every frame"
        );
        let want = "HDAP!node-gui@u/docs/a.txt";
        assert!(
            out.platform_output
                .commands
                .iter()
                .any(|c| matches!(c, egui::OutputCommand::CopyText(t) if t == want)),
            "the text must reach the window system, got {:?}",
            out.platform_output.commands
        );
    }

    #[test]
    fn file_actions_stay_on_screen_with_a_full_folder() {
        let mut app = logged_in_app();
        app.entries = (0..300)
            .map(|i| KtemaEntry {
                name: format!("arquivo-{i:03}.bin"),
                is_dir: false,
                path: format!("arquivo-{i:03}.bin"),
                size: 1024 * (i as u64 + 1),
                hash: "a".repeat(64),
            })
            .collect();
        let ctx = egui::Context::default();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(960.0, 640.0),
            )),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| crate::view::render(ui, &mut app));
        });
        out.textures_delta.clear();
        let rect = app
            .last_actions_rect
            .expect("the view must report where it put the actions");
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(960.0, 640.0));
        assert!(
            screen.contains_rect(rect),
            "file actions drawn at {rect:?} fall outside the {screen:?} window"
        );
        assert!(
            rect.height() > 0.0 && rect.width() > 0.0,
            "degenerate rect {rect:?}"
        );
        // And they belong to the *toolbar*, i.e. the top of the window. A
        // regression that moved them back under the list would still be
        // "on screen" for a short folder but pushed below the fold for a
        // full one, which is exactly the bug being guarded.
        assert!(
            rect.max.y <= 160.0,
            "file actions drifted to y={} — they belong in the top toolbar",
            rect.max.y
        );
    }

    /// Documents the egui behaviour that caused the invisible upload button:
    /// a `ScrollArea` with `auto_shrink([false, false])` claims the whole
    /// panel, so whatever is laid out after it starts outside the visible
    /// rectangle. If this test ever starts failing because egui changed that
    /// contract, the layout note in `view.rs` can be revisited.
    #[test]
    fn a_greedy_scroll_area_pushes_later_widgets_off_screen() {
        let ctx = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(400.0, 300.0));
        let input = egui::RawInput {
            screen_rect: Some(screen),
            ..Default::default()
        };
        let mut below = egui::Rect::ZERO;
        let mut out = ctx.run_ui(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for i in 0..100 {
                            ui.label(format!("linha {i}"));
                        }
                    });
                // Anything here is laid out past the bottom edge.
                ui.horizontal(|ui| {
                    let _ = ui.button("subir");
                    below = ui.min_rect();
                });
            });
        });
        out.textures_delta.clear();
        assert!(
            !screen.contains_rect(below),
            "expected the trailing widget to be clipped, but it fit in {below:?}"
        );
    }

    /// The reported bug: on login the sidebar grew (equivalently, the file
    /// grid shrank) just from moving the mouse over the window. egui treats
    /// `default_size` as the *initial* width only and then lets the panel
    /// content decide the real one, so the unbreakable 64-hex server id in
    /// the sidebar, re-measured on every hover, drove the divider.
    #[test]
    fn the_sidebar_width_ignores_the_pointer_and_its_content() {
        fn sidebar_at(pos: egui::Pos2) -> egui::Rect {
            let mut app = logged_in_app();
            let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(1000.0, 640.0));
            let ctx = egui::Context::default();
            let input = egui::RawInput {
                screen_rect: Some(screen),
                events: vec![egui::Event::PointerMoved(pos)],
                ..Default::default()
            };
            // Two passes: the first lays out, the second sees the hover it
            // produced. A hover-driven relayout only shows up on the second.
            for _ in 0..2 {
                let mut out = ctx.run_ui(input.clone(), |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| crate::view::render(ui, &mut app));
                });
                out.textures_delta.clear();
            }
            app.sidebar_rect.expect("the sidebar must report its rect")
        }

        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(1000.0, 640.0));
        // Far left (over the sidebar), dead centre (over the file grid),
        // far right (over the optional side panel).
        let over_sidebar = sidebar_at(egui::pos2(60.0, 300.0));
        let over_grid = sidebar_at(screen.center());
        let over_right = sidebar_at(egui::pos2(980.0, 300.0));

        for r in [over_sidebar, over_grid, over_right] {
            assert_eq!(
                r.width(),
                230.0,
                "sidebar is {}px wide instead of 230 — hover moved the divider to {r:?}",
                r.width()
            );
        }
        assert_eq!(over_sidebar, over_grid);
        assert_eq!(over_grid, over_right);
    }

    /// The access URI follows §3.3: `HDAP!<servidor>@<user>/<caminho>`.
    #[test]
    fn logical_uri_follows_the_spec() {
        let mut app = logged_in_app();
        let uid = app.user_id().expect("logged in");
        assert_eq!(app.logical_uri(), format!("HDAP!node-gui@{uid}/"));
        app.cd("docs/sub");
        assert_eq!(app.logical_uri(), format!("HDAP!node-gui@{uid}/docs/sub"));
        // No hash unless one was asked for *and* a file is selected.
        assert!(!app.logical_uri().contains("hash"));
        app.entries.push(KtemaEntry {
            name: "a.txt".into(),
            is_dir: false,
            path: "a.txt".into(),
            size: 1,
            hash: "b".repeat(64),
        });
        app.select("a.txt");
        assert!(
            !app.logical_uri().contains("hash"),
            "no hash until requested"
        );
        app.uri_with_hash = true;
        assert!(app
            .logical_uri()
            .ends_with(&format!("?hash={}", "b".repeat(64))));
        // A directory has no content hash, so no ?hash is invented.
        app.select("docs");
        assert!(!app.logical_uri().contains("hash"), "dirs have no hash");
    }

    /// Typing a URI for another pyle kicks off an on-demand mirror: the node
    /// pulls that user's space here, then the grid opens it read-only. A pyle
    /// the node cannot reach must fail with a message and leave the view put.
    #[test]
    fn a_uri_for_another_pyle_starts_a_mirror_and_reports_failure() {
        let mut app = logged_in_app();
        let started = app.apply_uri_edit("HDAP!pyle-z@jose_0123456789abcdef/docs/a.txt");
        assert!(
            !started,
            "navigation is async; the view changes only when the mirror lands"
        );
        assert!(app.mirror_busy, "the resolve must be in flight");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while app.mirror_busy && std::time::Instant::now() < deadline {
            app.tick(0.0, f64::INFINITY);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!app.mirror_busy, "mirror hung: {}", app.status);
        assert!(
            app.visiting.is_empty(),
            "a failed mirror must not open the other space"
        );
        assert!(
            app.status.contains("outro pyle"),
            "status should explain the failure: {}",
            app.status
        );
    }

    #[test]
    fn silent_node_cannot_hold_the_login_past_the_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            while let Ok((sock, _)) = listener.accept() {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(60));
                    drop(sock);
                });
            }
        });
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = Identity::generate("mudo", now);
        let uid = id.global_id();
        // Plaintext so the stall lands on the HTTP read, not the handshake.
        let c = HttpClient::new("127.0.0.1", port)
            .with_timeouts(Duration::from_secs(30), Duration::from_secs(30));
        let budget = Duration::from_millis(1200);
        let start = std::time::Instant::now();
        let err = do_connect(&c, &id, &uid, 1, start + budget)
            .expect_err("a silent node must not log in");
        let spent = start.elapsed();
        assert!(
            spent < Duration::from_secs(4),
            "login ran for {spent:?} — the deadline did not bound it"
        );
        // Either the budgeted read times out with a named error, or the
        // deadline trips first; both are bounded and both must be honest.
        assert!(
            err.contains("timeout") || err.contains("excedeu"),
            "expected a bounded, named failure, got: {err}"
        );
        assert!(
            !err.contains("Resource temporarily unavailable"),
            "raw EAGAIN leaked: {err}"
        );
    }

    #[test]
    fn connecting_always_ends_even_if_the_worker_never_reports() {
        // The reported symptom was the wizard sitting on "conectando ao
        // pyle..." forever. Two ways that can happen — a worker that never
        // writes its slot, or one that blows the deadline — must both leave
        // the UI in a usable state.
        let mut app = logged_in_app();
        app.disconnect();

        // (a) deadline: pretend the connect started long ago.
        app.connecting = true;
        app.connect_started = Some(std::time::Instant::now() - CONNECT_DEADLINE * 3);
        app.busy = Some("connect".into());
        app.status = "conectando ao pyle...".into();
        app.tick(0.0, f64::INFINITY);
        assert!(!app.connecting, "deadline did not release the wizard");
        assert!(
            app.status.contains("abandonada"),
            "unclear status: {}",
            app.status
        );
        assert!(app.busy.is_none(), "busy spinner left running");

        // (b) a slot that never fills must not wedge either.
        app.connecting = true;
        app.connect_started = Some(std::time::Instant::now());
        app.connect_pending = Some(Arc::new(Mutex::new(None)));
        app.status = "conectando ao pyle...".into();
        app.tick(0.0, f64::INFINITY);
        assert!(app.connecting, "premature release");
        app.cancel_connect();
        assert!(!app.connecting, "cancel did not release the wizard");
        assert!(app.connect_pending.is_none());
        assert_eq!(app.status, "conexão cancelada");

        // (c) a fresh connect still works after all that.
        let mut app = logged_in_app();
        app.disconnect();
        app.connect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while (app.connecting || app.listing) && std::time::Instant::now() < deadline {
            app.tick(0.0, f64::INFINITY);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!app.connecting, "stuck again: {}", app.status);
        assert!(app.session.is_some(), "cannot reconnect: {}", app.status);
    }

    #[test]
    fn wizard_renders_while_connecting_and_the_worker_still_completes() {
        let (host, port, _pin) = spawn_server_tls();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut app = App {
            host,
            port,
            pin: String::new(),
            nickname: format!("rnd{}", now % 100_000),
            password: "s3gredo".into(),
            home_dir: std::env::temp_dir()
                .join(format!("hdap-gui-render-{now}"))
                .to_string_lossy()
                .into_owned(),
            ..App::default()
        };
        let _ = app.ensure_identity();
        app.connect();
        let ctx = egui::Context::default();
        // The wizard must survive frames while the worker is in flight...
        render_frames(&ctx, &mut app, 5);
        // ...and rendering must not be what stops the polling.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while app.connecting && std::time::Instant::now() < deadline {
            render_frames(&ctx, &mut app, 1);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            !app.connecting,
            "connect never finished while rendering: {}",
            app.status
        );
        assert!(app.session.is_some(), "no session: {}", app.status);
        let _ = std::fs::remove_dir_all(std::path::PathBuf::from(&app.home_dir));
    }

    #[test]
    fn explorer_renders_after_login_without_panicking() {
        let mut app = logged_in_app();
        let ctx = egui::Context::default();
        render_frames(&ctx, &mut app, 10);
        assert!(app.session.is_some());
        // Navigate while rendering, to exercise breadcrumbs/sidebar/grid.
        app.cd("docs");
        render_frames(&ctx, &mut app, 5);
        app.up();
        render_frames(&ctx, &mut app, 5);
    }

    #[test]
    fn relaunch_logs_in_again_instead_of_replaying_the_otp_step() {
        let (host, port, pin) = spawn_server_tls();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let home = std::env::temp_dir()
            .join(format!("hdap-gui-relaunch-{now}"))
            .to_string_lossy()
            .into_owned();

        let login = |app: &mut App| {
            app.connect();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while (app.connecting || app.listing) && std::time::Instant::now() < deadline {
                app.tick(0.0, f64::INFINITY);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            assert!(app.session.is_some(), "login falhou: {}", app.status);
        };

        let mut first = App {
            host: host.clone(),
            port: port.clone(),
            pin: pin.clone(),
            nickname: format!("rl{}", now % 100_000),
            password: "s3gredo".into(),
            home_dir: home.clone(),
            ..App::default()
        };
        login(&mut first);
        let first_step = first.otp_step;

        // Same home, brand-new App (as a relaunched process would build it).
        let mut second = App {
            host,
            port,
            pin,
            nickname: format!("rl{}", now % 100_000),
            password: "s3gredo".into(),
            home_dir: home.clone(),
            ..App::default()
        };
        login(&mut second);
        assert!(
            second.otp_step > first_step,
            "passo de OTP não avançou: {} -> {}",
            first_step,
            second.otp_step
        );
        assert!(
            !second.status.contains("replayed"),
            "replay de OTP: {}",
            second.status
        );
        let _ = std::fs::remove_dir_all(std::path::PathBuf::from(&home));
    }

    #[test]
    fn connect_with_empty_pin_adopts_node_pin_tofu() {
        let (host, port, pin) = spawn_server_tls();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut app = App {
            host,
            port,
            pin: String::new(), // wizard default → TOFU
            nickname: format!("tofu{}", now % 100_000),
            password: "s3gredo".into(),
            home_dir: std::env::temp_dir()
                .join(format!("hdap-gui-tofu-{now}"))
                .to_string_lossy()
                .into_owned(),
            ..App::default()
        };
        let _ = app.ensure_identity();
        app.connect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while app.connecting && std::time::Instant::now() < deadline {
            app.tick(0.0, f64::INFINITY);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(app.session.is_some(), "TOFU connect: {}", app.status);
        // The advertised pin must have been adopted, so later requests are
        // anchored to this exact certificate rather than trusting any peer.
        assert_eq!(app.pin, pin, "pin not adopted from /health");
        assert_eq!(
            app.session.as_ref().unwrap().tls_pin.as_deref(),
            Some(pin.as_str())
        );
        let _ = std::fs::remove_dir_all(std::path::PathBuf::from(&app.home_dir));
    }

    #[test]
    fn listing_is_async_and_never_blocks_the_caller() {
        // `refresh` must return immediately even when the node is unreachable;
        // the previous synchronous version froze the UI thread for seconds.
        let mut app = logged_in_app();
        let before = std::time::Instant::now();
        app.refresh();
        assert!(
            before.elapsed() < std::time::Duration::from_millis(200),
            "refresh() blocked for {:?}",
            before.elapsed()
        );
        settle(&mut app);
        assert!(!app.status.contains("list failed"), "{}", app.status);
    }

    #[test]
    fn unreachable_node_fails_fast_without_freezing() {
        let mut app = logged_in_app();
        // Point at a black-holed address and confirm the UI gets a result
        // instead of hanging on the socket.
        app.host = "10.255.255.1".into();
        app.port = "9".into();
        let start = std::time::Instant::now();
        app.refresh();
        let deadline = start + std::time::Duration::from_secs(20);
        while app.listing && std::time::Instant::now() < deadline {
            app.tick(0.0, f64::INFINITY);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!app.listing, "listing never finished");
        assert!(
            app.status.contains("listagem falhou"),
            "expected failure, got {}",
            app.status
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(15),
            "took {:?}",
            start.elapsed()
        );
    }

    /// A deleted file must leave the grid even when the optimistic `/sync`
    /// snapshot still lists it: the refresh seeds from that snapshot, so only
    /// the authoritative relisting can retract it.
    #[test]
    fn a_deleted_file_disappears_from_the_grid() {
        let mut app = logged_in_app();
        app.buy_band_now_sync();
        app.cwd = String::new();
        app.pending_upload = Some(("apaga.txt".into(), b"some".to_vec()));
        app.do_upload();
        settle(&mut app);

        // A full sync repopulates the optimistic tree, which now includes it.
        app.sync_all();
        settle(&mut app);
        assert!(
            app.entries.iter().any(|e| e.name == "apaga.txt"),
            "upload/sync lost the file: {:?}",
            app.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );

        app.select("apaga.txt");
        app.delete_selected();
        settle(&mut app);
        assert!(
            !app.entries.iter().any(|e| e.name == "apaga.txt"),
            "deleted file still in the grid: {:?}",
            app.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn explorer_full_cycle_with_navigation() {
        let mut app = logged_in_app();
        let uid = app.user_id().unwrap();

        // Band
        app.buy_band_now_sync();
        assert!(app.band > 0, "band: {}", app.status);
        // Upload into subdirectory "docs"
        app.cwd = "docs".into();
        app.pending_upload = Some(("oi.txt".to_string(), b"ola mundo hdap gui".to_vec()));
        app.do_upload();
        settle(&mut app);
        assert!(
            app.pending_upload.is_none(),
            "pending: {:?}",
            app.pending_upload
        );
        assert!(
            app.entries.iter().any(|e| e.name == "oi.txt" && !e.is_dir),
            "docs após upload: {:?}",
            app.entries
        );

        // Also a file at root
        app.cwd = String::new();
        app.pending_upload = Some(("raiz.txt".to_string(), b"raiz".to_vec()));
        app.do_upload();

        // Root listing shows the dir
        app.refresh();
        settle(&mut app);
        let root_has_docs = app.entries.iter().any(|e| e.name == "docs" && e.is_dir);
        let root_has_file = app
            .entries
            .iter()
            .any(|e| e.name == "raiz.txt" && !e.is_dir);
        assert!(root_has_docs && root_has_file, "root: {:?}", app.entries);

        // Navigate into docs
        app.cd("docs");
        settle(&mut app);
        assert!(app.cwd == "docs");
        assert!(
            app.entries.iter().any(|e| e.name == "oi.txt"),
            "docs: {:?}",
            app.entries
        );

        // Selection + download round-trip
        let file = app
            .entries
            .iter()
            .find(|e| e.name == "oi.txt" && !e.is_dir)
            .cloned()
            .expect("oi.txt listed");
        assert_eq!(file.size, b"ola mundo hdap gui".len() as u64);

        // Download round-trip
        app.select("docs/oi.txt");
        let dest = std::env::temp_dir().join("hdap-gui-out.txt");
        app.download_selected_to(&dest);
        let (_, _, len, _hash) = app.last_download.as_ref().unwrap();
        assert_eq!(*len, file.size as usize);

        // Delete + refresh: dir becomes implicit-empty and disappears below
        app.delete_selected();
        settle(&mut app);
        assert!(!app.entries.iter().any(|e| e.name == "oi.txt"));
        // A directory with no remaining file disappears from its parent.
        app.cd("");
        settle(&mut app);
        let dirs: Vec<String> = app
            .entries
            .iter()
            .filter(|e| e.is_dir)
            .map(|e| e.name.clone())
            .collect();
        assert!(!dirs.contains(&"docs".to_string()), "dirs: {dirs:?}");
        assert!(
            app.entries.iter().any(|e| e.name == "raiz.txt"),
            "root after delete: {:?} status={}",
            app.entries,
            app.status
        );

        let _ = std::fs::remove_file(&dest);
        let _ = std::fs::remove_dir_all(std::path::PathBuf::from(&app.home_dir));
        let _ = uid;
    }

    /// The mining button used to exist only as a small toolbar row, easy to
    /// mistake for a status readout — hence "there is no way to mine". It now
    /// lives on a permanent sidebar card, and the layout test proves the card
    /// is visible inside the window for a logged-in user.
    #[test]
    fn the_band_card_keeps_mining_on_screen() {
        let mut app = logged_in_app();
        app.begin_band(0);
        let ctx = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(960.0, 640.0));
        let input = egui::RawInput {
            screen_rect: Some(screen),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| crate::view::render(ui, &mut app));
        });
        out.textures_delta.clear();
        let card = app
            .band_rect
            .expect("the sidebar must report the band card");
        assert!(
            screen.contains_rect(card),
            "band card {card:?} falls outside {screen:?}"
        );
        assert!(
            card.min.x < 230.0 && card.min.y > 40.0,
            "the card must live in the left sidebar, got {card:?}"
        );
    }

    /// The row above the file list used to show a bare "/" for the root, which
    /// says nothing about node or identity. The toolbar must now render the
    /// full logical URI, recorded by the view for this check.
    #[test]
    fn the_uri_bar_shows_the_full_logical_uri() {
        let mut app = logged_in_app();
        let uri = app.logical_uri();
        assert!(
            uri.starts_with("HDAP!"),
            "a logical uri must name the protocol, got {uri:?}"
        );
        assert!(uri.contains("@"), "a logical uri must name the user: {uri}");
        assert!(
            uri.len() > 20,
            "the uri must carry the node and identity, got {uri:?}"
        );

        let ctx = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(960.0, 640.0));
        let input = egui::RawInput {
            screen_rect: Some(screen),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| crate::view::render(ui, &mut app));
        });
        out.textures_delta.clear();
        assert_eq!(
            app.last_uri_shown, uri,
            "the toolbar must render the logical uri, not a bare \"/\""
        );
        let bar = app.uri_rect.expect("the view must report the uri bar rect");
        assert!(
            bar.max.y < 120.0,
            "the uri bar must stay in the top toolbar, got {bar:?}"
        );
    }

    /// The config gesture is a dedicated panel listing the specification
    /// documents. It must render without a panic (it drives the real egui
    /// layout) and stay open afterwards.
    #[test]
    fn the_config_panel_renders_and_stays_open() {
        let mut app = logged_in_app();
        assert_eq!(crate::app::CONFIG_DOCS.len(), 6, "one card per spec config");
        app.toggle_panel(crate::app::SidePanel::Config);
        // The transfer form has two long inputs and an inbox that carries full
        // accounting URIs. At 320px they used to ask for more width than the
        // panel had, pushing its left edge off-screen (the "half panel cut"
        // symptom). Keep them deliberately oversized here.
        let long = "A".repeat(160);
        app.transfer_new_uri = format!("HDAP!pyle-{long}@thais_{long}/");
        app.transfer_status = long.clone();
        app.transfer_inbox.push(TransferInboxItem {
            request_id: "b".repeat(64),
            old_owner: "thais_old".into(),
            old_nickname: "cedente".into(),
            old_uri: format!("HDAP!pyle-a@thais_old/{long}"),
            new_uri: format!("HDAP!pyle-b@thais_new/{long}"),
            target_kind: "identity".into(),
            assets: 1,
            created_at: 0,
            request: String::new(),
        });
        let ctx = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(960.0, 640.0));
        let input = egui::RawInput {
            screen_rect: Some(screen),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| crate::view::render(ui, &mut app));
        });
        out.textures_delta.clear();
        assert_eq!(
            app.side_panel,
            Some(crate::app::SidePanel::Config),
            "the panel must stay open after a frame"
        );
        assert!(
            app.has_entry("adeia.hdap") && app.has_entry("prosopeion.hdap"),
            "the server must seed the identity docs a fresh user configures"
        );
        let right = app.right_rect.expect("the config panel must be laid out");
        assert!(
            right.right() <= screen.right() - 7.0,
            "over-wide config/transfer content pushed the right panel off-screen: {right:?}"
        );
        assert!(
            right.left() >= 230.0,
            "the right panel slid under the sidebar: {right:?}"
        );
        assert!(
            (right.width() - 360.0).abs() < 1.0,
            "the right panel width drifted: {right:?}"
        );
    }

    #[test]
    fn the_house_move_panel_stays_inside_its_strip() {
        let mut app = logged_in_app();
        app.open_house_move();
        app.house_move_new_pyle = format!("pyle-{}", "B".repeat(160));
        app.house_move_adeia = format!("# ADEIA\nBODY\nX={}\n", "C".repeat(300));
        let ctx = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(960.0, 640.0));
        let input = egui::RawInput {
            screen_rect: Some(screen),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| crate::view::render(ui, &mut app));
        });
        out.textures_delta.clear();
        assert_eq!(app.side_panel, Some(SidePanel::HouseMove));
        let right = app
            .right_rect
            .expect("the house-move panel must be laid out");
        assert!(
            right.left() >= 230.0 && right.right() <= screen.right() - 7.0,
            "house-move content moved the panel outside its strip: {right:?}"
        );
        assert!((right.width() - 360.0).abs() < 1.0, "{right:?}");
    }

    /// The permission rows in the adeia editor used two default-width combos, a
    /// 90px field and a button in one `ui.horizontal` — ~370px inside a 320px
    /// panel. `exact_size` did not save it: an over-wide child made egui shift
    /// the whole panel to the right, off the window edge, so half the editor
    /// could not be seen. The row must fit, and the panel must stay put.
    #[test]
    fn the_perm_editor_row_fits_inside_the_side_panel() {
        use crate::editor::{self, Form, PermRow};
        let ctx = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(960.0, 640.0));
        let mut app = logged_in_app();
        editor::open(&mut app, "adeia.hdap");
        app.side_panel = Some(crate::app::SidePanel::Editor);
        let frame = |app: &mut App, n: usize| {
            for _ in 0..n {
                let input = egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                };
                let mut out = ctx.run_ui(input, |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| crate::view::render(ui, app));
                });
                out.textures_delta.clear();
            }
        };
        for rows in [1usize, 2, 5] {
            if let Some(mut st) = app.editor.take() {
                st.form = Form::Perms((0..rows).map(|_| PermRow::default()).collect());
                app.editor = Some(st);
            }
            frame(&mut app, 2);
            let rect = app
                .right_rect
                .expect("the editor panel must report its rect");
            assert!(
                (rect.width() - 360.0).abs() < 1.0,
                "{rows} rows drifted the panel width: {rect:?}"
            );
            assert!(
                rect.left() >= 230.0,
                "{rows} rows slid the panel under the sidebar: {rect:?}"
            );
            assert!(
                rect.right() <= 952.5,
                "{rows} rows pushed the panel past the window edge: {rect:?}"
            );
        }
    }
    #[test]
    fn a_bad_hash_is_rejected_before_touching_the_network() {
        let mut app = App {
            hash_input: "not-a-digest".into(),
            ..App::default()
        };
        app.lookup_hash();
        let found = app.hash_result.expect("an error result is shown");
        assert!(found.error.contains("64"));
        assert!(!app.hash_busy, "validation happens synchronously");
    }

    #[test]
    fn a_hash_result_opens_the_cache_folder_that_holds_it() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut app = App {
            session: Some(Session {
                user_id: "me_0123456789abcdef".into(),
                token: "t".into(),
                exp: now + 3600,
                server_id: "node-gui".into(),
                tls_pin: None,
            }),
            hash_result: Some(HashLookup {
                status: "fetched".into(),
                owner: "me_0123456789abcdef".into(),
                path: "cache/deadbeef/doc.txt".into(),
                source: "pyle-a".into(),
                verified: true,
                holders: vec!["pyle-a".into()],
                error: String::new(),
            }),
            ..App::default()
        };
        app.open_hash_result();
        assert_eq!(app.cwd, "cache/deadbeef");
        assert!(
            app.visiting.is_empty(),
            "the cache belongs to our own space"
        );
    }
    #[test]
    fn a_house_move_signs_a_newer_adeia_and_a_verifiable_payload() {
        use base64::Engine as _;
        use ed25519_dalek::{Signature, Verifier};
        let id = Identity::generate("alice", 100);
        let current = hdap_core::protocol::adeia_doc(
            &id.global_id(),
            3,
            Some("11".repeat(32)),
            100,
            &[],
            None,
        )
        .render();
        let body = build_house_move(&id, "pyle-b", &current, &current, 200).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["new_pyle"], "pyle-b");
        let properties = v["properties"].as_str().unwrap();
        let adeia = v["adeia"].as_str().unwrap();
        let next = hdap_core::doc::parse(adeia).unwrap();
        assert_eq!(next.edition, 4, "the move must carry a newer edition");
        assert_eq!(
            next.prev_hash,
            Some(hdap_core::crypto::sha256_hex(current.as_bytes()))
        );
        let payload = hdap_core::house_move_payload(&id.global_id(), "pyle-b", properties, adeia);
        let sig = base64::engine::general_purpose::STANDARD
            .decode(v["signature"].as_str().unwrap())
            .unwrap();
        id.verifying_key()
            .verify(payload.as_bytes(), &Signature::from_slice(&sig).unwrap())
            .expect("the server must be able to verify this signature offline");
    }

    #[test]
    fn opening_the_house_move_panel_seeds_the_current_adeia() {
        let mut app = App::default();
        app.sync_docs
            .insert("adeia.hdap".into(), "ADEIA current".into());
        app.open_house_move();
        assert_eq!(app.side_panel, Some(SidePanel::HouseMove));
        assert_eq!(app.house_move_adeia, "ADEIA current");
    }
    #[test]
    fn the_gui_house_move_is_accepted_by_a_real_node() {
        let app = logged_in_app();
        let me = app.user_id().unwrap();
        let current =
            app.sync_docs.get("adeia.hdap").cloned().unwrap_or_else(|| {
                hdap_core::protocol::adeia_doc(&me, 1, None, 1, &[], None).render()
            });
        let body = build_house_move(
            app.identity.as_ref().unwrap(),
            "pyle-new",
            &current,
            &current,
            100,
        )
        .unwrap();
        let client = app.client().unwrap();
        let edition = post_house_move(&client, &app.session_token().unwrap(), &body).unwrap();
        assert_eq!(edition, 2);
    }

    #[test]
    fn the_uri_bar_resolves_a_ddns_alias_and_falls_back_to_a_local_path() {
        let mut app = logged_in_app();
        let me = app.user_id().unwrap();
        let client = app.client().unwrap();
        let token = app.session_token().unwrap();
        let target = format!("HDAP!node-gui@{me}/docs");
        hdap_cli::flow::publish_alias(&client, &token, "atalho", &target).unwrap();

        app.submit_uri("atalho");
        settle_alias(&mut app);
        settle(&mut app);
        assert_eq!(app.cwd, "docs", "the alias target must drive navigation");
        assert!(
            app.toasts.iter().any(|t| t.text.contains("DDNS")),
            "the user must see that DDNS resolved: {:?}",
            app.toasts
        );

        // A miss still behaves like the old path bar: it opens the literal
        // local path instead of trapping the user in an alias error.
        app.submit_uri("pasta-sem-alias");
        settle_alias(&mut app);
        settle(&mut app);
        assert_eq!(app.cwd, "pasta-sem-alias");

        // A concrete path is never turned into a DDNS request.
        assert!(!app.should_resolve_ddns("docs/nota.txt"));
        app.submit_uri("docs/nota.txt");
        assert!(!app.uri_alias_busy);
    }

    #[test]
    fn the_new_file_menu_offers_diadosi_but_routes_it_to_the_backup_panel() {
        let mut app = logged_in_app();
        assert!(
            crate::editor::Template::ALL
                .iter()
                .any(|(kind, _, _)| *kind == crate::editor::Template::Diadosi),
            "diadosi must be listed with the other document types"
        );
        crate::editor::create(&mut app, "diadosi.hdap", crate::editor::Template::Diadosi);
        assert_eq!(app.side_panel, Some(SidePanel::Diadosi));
        assert!(
            app.editor.is_none(),
            "an unsigned raw draft must not replace the signed proxy"
        );
    }

    #[test]
    fn opening_the_backup_panel_suggests_dialable_bubble_pyles() {
        let mut app = logged_in_app();
        let here = app.session.as_ref().unwrap().server_id.clone();
        app.bubble.peers = vec![
            BubblePeer {
                node_id: here.clone(),
                endpoint: "127.0.0.1:8443".into(),
                tier: "core".into(),
                verified: true,
                failures: 0,
                last_seen: 0,
            },
            BubblePeer {
                node_id: "pyle-b".into(),
                endpoint: "127.0.0.1:8444".into(),
                tier: "core".into(),
                verified: true,
                failures: 0,
                last_seen: 0,
            },
            BubblePeer {
                node_id: "pyle-c".into(),
                endpoint: "".into(),
                tier: "untrusted".into(),
                verified: false,
                failures: 3,
                last_seen: 0,
            },
        ];
        app.diadosi_fallbacks.clear();
        app.open_diadosi();
        assert_eq!(app.diadosi_fallbacks, "pyle-b");
        assert!(app.diadosi_status.contains('1'));
    }

    #[test]
    fn the_gui_diadosi_is_accepted_by_a_real_node() {
        let app = logged_in_app();
        let me = app.user_id().unwrap();
        let properties = app
            .sync_docs
            .get("prosopeion.hdap")
            .cloned()
            .expect("login sync ships the identity");
        let adeia =
            app.sync_docs.get("adeia.hdap").cloned().unwrap_or_else(|| {
                hdap_core::protocol::adeia_doc(&me, 1, None, 1, &[], None).render()
            });
        let home = app.session.as_ref().unwrap().server_id.clone();
        let body = build_diadosi(
            app.identity.as_ref().unwrap(),
            &home,
            &["pyle-b".to_string(), "pyle-c".to_string()],
            &properties,
            &adeia,
            1,
            None,
        )
        .unwrap();
        let client = app.client().unwrap();
        let edition = post_diadosi(&client, &app.session_token().unwrap(), &body, 1).unwrap();
        assert_eq!(edition, 1);
    }
}
