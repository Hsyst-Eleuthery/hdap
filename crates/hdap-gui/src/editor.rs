//! Guided config editor: a form per document type beside the raw `.hdap`
//! text, kept in sync in *both* directions (especificacao §4, §8).
//!
//! Design note: the document text is the single source of truth. The form is
//! a projection of it. Toggling a checkbox re-renders the document; typing in
//! the text pane re-parses it back into the form. When the text does not parse
//! (half-typed, or genuinely malformed) the error is shown and the form is
//! left alone rather than being clobbered with garbage.

use crate::app::App;
use egui::{Color32, RichText};
use hdap_core::doc::{self, Doc, DocType};
use hdap_core::protocol::{DiadosiDoc, Permission, PrytaneionDoc, Right, Scope};
use std::time::{SystemTime, UNIX_EPOCH};

/// What a newly created config file starts as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    /// `adeia.hdap` — ACL, starts with no grants.
    Adeia,
    /// `kerux.hdap` — alias mapping.
    Kerux,
    /// `timi.hdap` — price announcement.
    Timi,
    /// `prytaneion.hdap` — replication matrix mirror (§10.2).
    Prytaneion,
    /// `prosopeion.hdap` — public identity card (§3.1).
    Prosopeion,
    /// `diadosi.hdap` — signed home-fallback proxy. The guided backup panel
    /// creates and signs it; this entry keeps the type visible in the menu.
    Diadosi,
    /// A plain text file (not a DOC).
    Texto,
}

impl Template {
    pub const ALL: [(Template, &str, &str); 7] = [
        (Template::Adeia, "adeia", "adeia.hdap"),
        (Template::Kerux, "kerux", "kerux.hdap"),
        (Template::Timi, "timi", "timi.hdap"),
        (Template::Prytaneion, "prytaneion", "prytaneion.hdap"),
        (Template::Prosopeion, "prosopeion", "prosopeion.hdap"),
        (Template::Diadosi, "diadosi", "diadosi.hdap"),
        (Template::Texto, "texto", "nota.txt"),
    ];

    pub fn label(self) -> &'static str {
        Template::ALL.iter().find(|t| t.0 == self).unwrap().1
    }
}

/// Render a fresh document of `kind`. Every template must be something
/// `hdap_core::doc::parse` accepts, so "criar" never lands the user in an
/// error state before they have typed anything.
pub fn template_text(kind: Template, owner: &str, nickname: &str, created_at: u64) -> String {
    match kind {
        Template::Adeia => {
            hdap_core::protocol::adeia_doc(owner, 1, None, created_at, &[], None).render()
        }
        Template::Kerux => {
            let mut d = Doc::new(DocType::Kerux, 1, None, created_at);
            d.body.insert("ALIAS".into(), String::new());
            d.body.insert("TARGET_URI".into(), String::new());
            d.render()
        }
        Template::Timi => {
            let mut d = Doc::new(DocType::Timi, 1, None, created_at);
            d.body.insert("PYLE".into(), String::new());
            d.body.insert("PRICE_PER_GIB_DAY".into(), String::new());
            d.body.insert("MAX_DURATION_DAYS".into(), String::new());
            d.body.insert("VALID_KAIROS".into(), "0".into());
            d.render()
        }
        Template::Prytaneion => {
            let mut d = PrytaneionDoc {
                content_hash: String::new(),
                origin_server: owner.to_string(),
                origin_user: owner.to_string(),
                replicas: Vec::new(),
                deletions: Vec::new(),
                created_at,
            }
            .to_doc();
            d.body.insert("STATUS".into(), "mirror".into());
            d.render()
        }
        // Filled from the real local identity in `create`; this is only the
        // fallback for the (rare) case where no vault exists to copy from.
        Template::Prosopeion => {
            let mut d = Doc::new(DocType::Prosopeion, 1, None, created_at);
            d.body.insert("NICKNAME".into(), nickname.to_string());
            d.body.insert("SUFFIX".into(), String::new());
            d.body.insert("SIGN_PUBKEY".into(), String::new());
            d.body.insert("ENC_PUBKEY".into(), String::new());
            d.body.insert("OMPHALOS".into(), String::new());
            d.body.insert("SEED_ITER".into(), "0".into());
            d.render()
        }
        // A draft without a signature. The real document is produced by the
        // guided "backups de casa" panel, which signs it and calls
        // `POST /diadosi`; this skeleton only keeps the type editable.
        Template::Diadosi => DiadosiDoc {
            owner: owner.to_string(),
            owner_pubkey: String::new(),
            home_pyle: String::new(),
            fallbacks: Vec::new(),
            adeia_edition: 1,
            adeia_hash: String::new(),
            properties_hash: String::new(),
            edition: 1,
            prev_hash: None,
            created_at,
        }
        .to_doc()
        .render(),
        Template::Texto => String::new(),
    }
}

/// Seed a brand-new file in the editor. Nothing is written to the node until
/// the user presses "salvar" — creating a file is not a destructive act, but
/// uploading is, and it costs band.
pub fn create(app: &mut App, path: &str, kind: Template) {
    let Some(owner) = app.user_id() else {
        app.say(app.strings.m_no_session_edit.to_string());
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if kind == Template::Diadosi {
        // `diadosi.hdap` is a *signed* proxy. Letting the raw editor write an
        // unsigned draft over the installed document would silently disable
        // failover, so the menu entry opens the guided signing panel instead.
        app.open_diadosi();
        return;
    }
    let nickname = app.nickname.trim();
    let text = if kind == Template::Prosopeion {
        // The honest "new prosopeion" is a copy of the vault we actually have.
        match &app.identity {
            Some(id) => id.prosopeion_doc().render(),
            None => template_text(kind, &owner, nickname, now),
        }
    } else {
        template_text(kind, &owner, nickname, now)
    };
    let mut st = EditorState {
        path: path.to_string(),
        text: text.clone(),
        error: String::new(),
        edition: 1,
        ..Default::default()
    };
    reparse(&mut st);
    // `on_disk` stays empty: the node does not have this file yet, so the
    // editor reports it as unsaved until the first save lands.
    st.text = text;
    app.editor = Some(st);
    app.side_panel = Some(crate::app::SidePanel::Editor);
    app.say(crate::i18n::fill1(app.strings.m_creating, path));
}

/// The guided form for a document type. `Raw` means "this type has no form
/// yet", and the text pane is then the only editor — still valid input, just
/// not guided.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Form {
    /// ACL rows (`adeia.hdap`, §8).
    Perms(Vec<PermRow>),
    /// `ALIAS` -> `TARGET_URI` (`kerux.hdap`, §13).
    Kerux { alias: String, target_uri: String },
    /// Price announcement (`timi.hdap`, §4.3).
    Timi {
        pyle: String,
        price: String,
        max_days: String,
        valid_kairos: String,
    },
    /// Identity card (`prosopeion.hdap`, §3.1): the public half of the vault.
    Prosopeion {
        nickname: String,
        suffix: String,
        sign_pubkey: String,
        enc_pubkey: String,
        omphalos: String,
        seed_iter: String,
    },
    /// Replication matrix (`prytaneion.hdap`, §10.2): one row per content
    /// hash with its replicas and the deletion history.
    Prytaneion {
        content_hash: String,
        origin_pyle: String,
        origin_user: String,
        status: String,
        replicas: Vec<String>,
        deletions: Vec<String>,
    },
    /// No guided form for this type.
    #[default]
    Raw,
}

/// Editing session for one file.
#[derive(Debug, Clone, Default)]
pub struct EditorState {
    /// Remote path being edited.
    pub path: String,
    /// The document text as it will be saved.
    pub text: String,
    /// Text last successfully parsed into the form.
    pub parsed: String,
    /// The text currently stored on the node. `PREV_HASH` must cover *this*,
    /// because it is the previous edition of the document — hashing the
    /// working buffer would chain the document to itself.
    pub on_disk: String,
    /// Parse error to display, empty when the text is valid.
    pub error: String,
    /// The guided projection of the document.
    pub form: Form,
    /// The last known edition, to keep `EDITION`/`PREV_HASH` monotonic.
    pub edition: u64,
}

/// One ACL row, flattened for the form.
///
/// The row keeps the two coordinates separate on purpose. The old form had a
/// single "scope" string (`all`, `user:aluno`, `path:docs`) and no path field,
/// so there was no way to say "Maria may not read this file" — the exact bug
/// this release fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermRow {
    /// `true` means the rule applies to everyone; `false` means `subject`.
    pub everyone: bool,
    /// Global user id (without `user:`) when `everyone` is false.
    pub subject: String,
    /// `/` or empty means the whole house; otherwise a folder or file.
    pub path: String,
    /// Right: `deny|read|write|own`.
    pub right: String,
}

impl Default for PermRow {
    fn default() -> Self {
        Self {
            everyone: true,
            subject: String::new(),
            path: "/".into(),
            right: "read".into(),
        }
    }
}

impl PermRow {
    /// Project the row onto the protocol's scope model.
    pub fn scope(&self) -> Scope {
        let subject = self
            .subject
            .trim()
            .strip_prefix("user:")
            .unwrap_or(self.subject.trim())
            .to_string();
        let path = hdap_core::protocol::normalize_acl_path(
            self.path
                .trim()
                .strip_prefix("path:")
                .unwrap_or(self.path.trim()),
        );
        match (self.everyone || subject.is_empty(), path.is_empty()) {
            (true, true) => Scope::All,
            (true, false) => Scope::Path(path),
            (false, true) => Scope::User(subject),
            (false, false) => Scope::UserPath(subject, path),
        }
    }

    /// Render back to a canonical `PERM <owner> <sujeito> <caminho> <right>`
    /// line. Returns `None` when the right is not one of the four protocol
    /// values.
    pub fn to_line(&self, owner: &str) -> Option<String> {
        let right = RIGHTS
            .iter()
            .find(|r| **r == self.right.trim())
            .map(|r| match *r {
                "deny" => Right::Deny,
                "read" => Right::Read,
                "write" => Right::Write,
                _ => Right::Own,
            })?;
        let permission = Permission {
            scope: self.scope(),
            right,
        };
        Some(permission.to_line(owner))
    }
}

impl EditorState {
    /// True when `text` differs from the last version that parsed cleanly.
    /// Dirty means **"the node does not have this text yet"** — the only
    /// definition that survives both edit directions. `parsed` cannot answer
    /// it: `apply_form` rewrites the document from the form and realigns
    /// `parsed` with it, so a form edit would look saved the instant it
    /// happened. `on_disk` is the node's copy, and an empty `on_disk` means
    /// the file was never uploaded at all.
    pub fn is_dirty(&self) -> bool {
        self.text != self.on_disk || self.on_disk.is_empty()
    }
}

const RIGHTS: [&str; 4] = ["deny", "read", "write", "own"];

/// Localized label for a right token.
pub fn right_label(strings: &crate::i18n::Strings, right: &str) -> &'static str {
    match right {
        "deny" => strings.f_perm_right_deny,
        "write" => strings.f_perm_right_write,
        "own" => strings.f_perm_right_own,
        _ => strings.f_perm_right_read,
    }
}

/// Parse a `PERM <owner> <scope> <right>` line back into a form row. The core
/// parser owns the grammar, so the form accepts both the v1.0 compact lines
/// and the v1.001 subject + path lines.
fn parse_perm_row(line: &str) -> Option<PermRow> {
    let (_owner, scope, right) = hdap_core::protocol::parse_perm_line(line)?;
    let scope = scope.ok()?;
    let (subject, path) = match scope {
        Scope::All => (String::new(), "/".to_string()),
        Scope::User(user) => (user, "/".to_string()),
        Scope::Path(path) => (String::new(), format!("/{}", path.trim_matches('/'))),
        Scope::UserPath(user, path) => (user, format!("/{}", path.trim_matches('/'))),
    };
    Some(PermRow {
        everyone: subject.is_empty(),
        subject,
        path,
        right: right.as_str().to_string(),
    })
}

/// Re-render the document from the form rows. Returns `None` when the node's
/// owner cannot be determined (the caller keeps the previous text).
fn build_adeia(owner: &str, rows: &[PermRow], base: &Doc) -> Option<Doc> {
    let mut perms = Vec::new();
    for row in rows {
        let right = RIGHTS
            .iter()
            .find(|r| **r == row.right.trim())
            .map(|r| match *r {
                "deny" => Right::Deny,
                "read" => Right::Read,
                "write" => Right::Write,
                _ => Right::Own,
            })?;
        perms.push(Permission {
            scope: row.scope(),
            right,
        });
    }
    // Keep every body key the form does not own (notably `UUID`, §4.3).
    let mut d = base.clone();
    d.body.retain(|k, _| !is_perm_key(k));
    for (i, p) in perms.iter().enumerate() {
        d.body.insert(format!("PERM{i:04}"), p.to_line(owner));
    }
    Some(d)
}

fn build_kerux(form: &Form, base_text: &str) -> Doc {
    let Form::Kerux { alias, target_uri } = form else {
        return doc::parse(base_text).expect("kerux form over a non-doc");
    };
    let mut d = doc::parse(base_text).expect("kerux form over a non-doc");
    d.body.insert("ALIAS".into(), alias.trim().to_string());
    d.body
        .insert("TARGET_URI".into(), target_uri.trim().to_string());
    d
}

fn build_timi(form: &Form, base_text: &str) -> Doc {
    let Form::Timi {
        pyle,
        price,
        max_days,
        valid_kairos,
    } = form
    else {
        return doc::parse(base_text).expect("timi form over a non-doc");
    };
    let mut d = doc::parse(base_text).expect("timi form over a non-doc");
    d.body.insert("PYLE".into(), pyle.trim().to_string());
    d.body
        .insert("PRICE_PER_GIB_DAY".into(), price.trim().to_string());
    d.body
        .insert("MAX_DURATION_DAYS".into(), max_days.trim().to_string());
    d.body
        .insert("VALID_KAIROS".into(), valid_kairos.trim().to_string());
    d
}

fn build_prosopeion(form: &Form, base_text: &str) -> Doc {
    let Form::Prosopeion {
        nickname,
        suffix,
        sign_pubkey,
        enc_pubkey,
        omphalos,
        seed_iter,
    } = form
    else {
        return doc::parse(base_text).expect("prosopeion form over a non-doc");
    };
    let mut d = doc::parse(base_text).expect("prosopeion form over a non-doc");
    d.body
        .insert("NICKNAME".into(), nickname.trim().to_string());
    d.body.insert("SUFFIX".into(), suffix.trim().to_string());
    d.body
        .insert("SIGN_PUBKEY".into(), sign_pubkey.trim().to_string());
    d.body
        .insert("ENC_PUBKEY".into(), enc_pubkey.trim().to_string());
    d.body
        .insert("OMPHALOS".into(), omphalos.trim().to_string());
    d.body
        .insert("SEED_ITER".into(), seed_iter.trim().to_string());
    d
}

fn build_prytaneion(form: &Form, base_text: &str) -> Doc {
    let Form::Prytaneion {
        content_hash,
        origin_pyle,
        origin_user,
        status,
        replicas,
        deletions,
    } = form
    else {
        return doc::parse(base_text).expect("prytaneion form over a non-doc");
    };
    let mut d = doc::parse(base_text).expect("prytaneion form over a non-doc");
    d.body
        .insert("CONTENT_HASH".into(), content_hash.trim().to_string());
    d.body
        .insert("ORIGIN_SERVER".into(), origin_pyle.trim().to_string());
    d.body
        .insert("ORIGIN_USER".into(), origin_user.trim().to_string());
    d.body.insert("STATUS".into(), status.trim().to_string());
    d.body
        .retain(|k, _| !is_indexed_key(k, "REPLICA") && !is_indexed_key(k, "DELETION"));
    for (i, r) in replicas.iter().enumerate() {
        d.body.insert(format!("REPLICA{i:04}"), r.clone());
    }
    for (i, del) in deletions.iter().enumerate() {
        d.body.insert(format!("DELETION{i:04}"), del.clone());
    }
    d
}

/// Is `k` a `PREFIX%04d` body key (e.g. `REPLICA0003`)?
fn is_indexed_key(k: &str, prefix: &str) -> bool {
    k.strip_prefix(prefix)
        .is_some_and(|i| !i.is_empty() && i.chars().all(|c| c.is_ascii_digit()))
}

/// Keep `EDITION` at least 1 and, past the first edition, point `PREV_HASH` at
/// what the node actually holds — never at the working buffer, which would
/// chain the document to itself and break the §4.2 immutability trail.
fn chain_edition(mut d: Doc, edition: u64, on_disk: &str) -> Doc {
    d.edition = edition.max(1);
    if d.edition > 1 {
        d.prev_hash = Some(hex64(&doc_text_hash(on_disk)));
    }
    d
}

fn is_perm_key(k: &str) -> bool {
    k.strip_prefix("PERM")
        .is_some_and(|i| !i.is_empty() && i.chars().all(|c| c.is_ascii_digit()))
}

fn hex64(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn doc_text_hash(text: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    h.finalize().into()
}

/// Refresh `form`/`error` from `text`. This is the text -> form direction.
pub fn reparse(state: &mut EditorState) {
    match doc::parse(&state.text) {
        Ok(d) => {
            state.error.clear();
            state.parsed = state.text.clone();
            state.edition = d.edition;
            state.form = form_of(&d);
        }
        Err(e) => state.error = e.to_string(),
    }
}

/// Project a parsed document onto the form for its type.
fn form_of(d: &Doc) -> Form {
    let g = |k: &str| d.body.get(k).cloned().unwrap_or_default();
    match d.doc_type {
        DocType::Adeia => Form::Perms(perm_rows(d)),
        DocType::Kerux => Form::Kerux {
            alias: g("ALIAS"),
            target_uri: g("TARGET_URI"),
        },
        DocType::Timi => Form::Timi {
            pyle: g("PYLE"),
            price: g("PRICE_PER_GIB_DAY"),
            max_days: g("MAX_DURATION_DAYS"),
            valid_kairos: g("VALID_KAIROS"),
        },
        DocType::Prosopeion => Form::Prosopeion {
            nickname: g("NICKNAME"),
            suffix: g("SUFFIX"),
            sign_pubkey: g("SIGN_PUBKEY"),
            enc_pubkey: g("ENC_PUBKEY"),
            omphalos: g("OMPHALOS"),
            seed_iter: g("SEED_ITER"),
        },
        DocType::Prytaneion => Form::Prytaneion {
            content_hash: g("CONTENT_HASH"),
            origin_pyle: g("ORIGIN_SERVER"),
            origin_user: g("ORIGIN_USER"),
            status: g("STATUS"),
            replicas: indexed_values(d, "REPLICA"),
            deletions: indexed_values(d, "DELETION"),
        },
        _ => Form::Raw,
    }
}

/// All `PREFIX%04d`-keyed body values, in key order.
fn indexed_values(d: &Doc, prefix: &str) -> Vec<String> {
    let mut out: Vec<(String, String)> = d
        .body
        .iter()
        .filter(|(k, _)| is_indexed_key(k, prefix))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.into_iter().map(|(_, v)| v).collect()
}

/// Extract the ACL rows of an `adeia` document, in key order.
fn perm_rows(d: &Doc) -> Vec<PermRow> {
    let mut out = Vec::new();
    for (k, v) in &d.body {
        if let Some(i) = k.strip_prefix("PERM") {
            if i.chars().all(|c| c.is_ascii_digit()) {
                if let Some(row) = parse_perm_row(v) {
                    out.push(row);
                }
            }
        }
    }
    out
}

/// The form -> text direction: re-render the document from the guided form.
pub fn apply_form(app: &App, state: &mut EditorState) {
    let Some(owner) = app.user_id() else {
        state.error = app.strings.m_no_session_sign.to_string();
        return;
    };
    let base = match doc::parse(&state.parsed) {
        Ok(d) => d,
        Err(e) => {
            state.error = e.to_string();
            return;
        }
    };
    let mut d = match &state.form {
        Form::Perms(rows) => match build_adeia(&owner, rows, &base) {
            Some(d) => d,
            None => {
                state.error = app.strings.m_invalid_perm.to_string();
                return;
            }
        },
        Form::Kerux { .. } => build_kerux(&state.form, &state.parsed),
        Form::Timi { .. } => build_timi(&state.form, &state.parsed),
        Form::Prosopeion { .. } => build_prosopeion(&state.form, &state.parsed),
        Form::Prytaneion { .. } => build_prytaneion(&state.form, &state.parsed),
        // No guided form: the text pane is already the truth.
        Form::Raw => {
            state.parsed = state.text.clone();
            state.error.clear();
            return;
        }
    };
    d = chain_edition(d, state.edition, &state.on_disk);
    let t = d.render();
    state.text = t.clone();
    state.parsed = t;
    state.error.clear();
}

/// Open the editor on `path`, fetching its bytes from the node (which may be
/// another user's space the current `adeia` lets us read).
pub fn open(app: &mut App, path: &str) {
    let Some(token) = app.session_token() else {
        return;
    };
    let Some(owner) = app.active_owner() else {
        return;
    };
    let Ok(c) = app.client() else {
        return;
    };
    match hdap_cli::flow::download(&c, &token, &owner, path) {
        Ok((bytes, _)) => {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let mut st = EditorState {
                path: path.to_string(),
                text: text.clone(),
                // What the node holds right now; `PREV_HASH` must cover this.
                on_disk: text,
                edition: 1,
                ..Default::default()
            };
            reparse(&mut st);
            app.editor = Some(st);
            app.say(crate::i18n::fill1(app.strings.m_editing, path));
        }
        Err(e) => {
            app.say(crate::i18n::fill2(
                app.strings.m_open_fail,
                path,
                &format!("{e}"),
            ));
            app.notify(
                crate::app::ToastKind::Error,
                crate::i18n::fill2(app.strings.m_open_fail, path, &format!("{e}")),
            );
        }
    }
}

/// Save the editor buffer back to the node. Blocked while browsing someone
/// else's space: their `adeia` decides what we may touch, and the GUI does
/// not offer a save it knows the node will refuse.
pub fn save(app: &mut App) {
    let Some(state) = app.editor.clone() else {
        return;
    };
    if app.read_only() {
        app.say(app.strings.m_ro_save.to_string());
        app.notify(
            crate::app::ToastKind::Error,
            app.strings.m_ro_save.to_string(),
        );
        return;
    }
    let Some(token) = app.session_token() else {
        return;
    };
    let Some(owner) = app.active_owner() else {
        return;
    };
    let Ok(c) = app.client() else {
        return;
    };
    if !state.error.is_empty() {
        app.say(app.strings.m_not_saved.to_string());
        return;
    }
    let body = state.text.clone();
    let out = match &app.identity {
        Some(identity) => hdap_cli::flow::upload_with_band(
            &c,
            &token,
            identity,
            &owner,
            &state.path,
            body.as_bytes(),
        ),
        None => hdap_cli::flow::upload(
            &c,
            &token,
            app.identity.as_ref().unwrap(),
            &owner,
            &state.path,
            body.as_bytes(),
        ),
    };
    match out {
        Ok(hash) => {
            if let Some(st) = app.editor.as_mut() {
                st.parsed = st.text.clone();
                st.on_disk = st.text.clone();
            }
            // Config docs drive the node's structured maps (permissions,
            // aliases, prices): a full `/sync` after the save keeps every
            // panel reading the same fresh truth the node now holds.
            let path = state.path.clone();
            let is_config = &is_config_doc(&path);
            let saved_path = state.path.clone();
            app.refresh();
            if *is_config {
                app.sync_all();
            }
            app.say(crate::i18n::fill2(
                app.strings.m_saved,
                &saved_path,
                &hash[..hash.len().min(16)],
            ));
            app.notify(
                crate::app::ToastKind::Success,
                app.strings.m_cfg_saved.to_string(),
            );
        }
        Err(e) => {
            // Uploading costs band, and "insufficient band credit" is not
            // something anyone can act on without being told what to do.
            let hint = if format!("{e}").contains("band") {
                app.strings.m_band_hint
            } else {
                ""
            };
            let detail = format!("{e}{hint}");
            let msg = crate::i18n::fill2(app.strings.m_save_fail, &state.path, &detail);
            app.say(msg.clone());
            app.notify(crate::app::ToastKind::Error, msg);
        }
    }
}

/// Is this path one of the spec's root config documents? Saving one of these
/// makes the node re-index its structured maps, so the GUI re-syncs to pick
/// up the fresh projections.
pub fn is_config_doc(path: &str) -> bool {
    matches!(
        path.trim_start_matches('/'),
        "adeia.hdap"
            | "diadosi.hdap"
            | "kerux.hdap"
            | "timi.hdap"
            | "prytaneion.hdap"
            | "prosopeion.hdap"
    )
}

/// The "no file open" state: offer the config templates.
fn render_new_file(ui: &mut egui::Ui, app: &mut App) {
    ui.label(RichText::new(app.strings.new_file).strong());
    ui.label(RichText::new(app.strings.new_file_hint).small().weak());
    let mut name = app.new_file_name.clone();
    let mut kind = app.new_file_kind;
    egui::ComboBox::from_id_salt("new_kind")
        .selected_text(kind.label())
        .show_ui(ui, |ui| {
            for (k, label, _) in Template::ALL {
                ui.selectable_value(&mut kind, k, label);
            }
        });
    let resp = egui::TextEdit::singleline(&mut name)
        .hint_text(app.strings.file_name)
        .desired_width(120.0)
        .show(ui);
    if resp.response.changed() {
        app.new_file_name = name.clone();
    }
    if ui.button(app.strings.create).clicked() {
        let mut fname = name.trim().to_string();
        if fname.is_empty() {
            // Fall back to the template's own filename.
            fname = Template::ALL
                .iter()
                .find(|t| t.0 == kind)
                .map(|t| t.2)
                .unwrap_or("novo.txt")
                .to_string();
        }
        let dir = app.cwd.trim_start_matches('/');
        let path = if dir.is_empty() {
            fname
        } else {
            format!("{dir}/{fname}")
        };
        create(app, &path, kind);
    }
}

/// Render the editor panel (form on top, raw text below).
pub fn render(ui: &mut egui::Ui, app: &mut App) {
    ui.label(RichText::new(app.strings.e_title).strong());
    if app.editor.is_none() {
        render_new_file(ui, app);
        return;
    }
    let Some(state) = app.editor.clone() else {
        return;
    };
    ui.add(egui::Label::new(egui::RichText::new(state.path.clone()).monospace()).wrap());
    ui.horizontal(|ui| {
        let save_lbl = format!("💾 {}", app.strings.save);
        if ui.button(save_lbl).clicked() {
            save(app);
        }
        let revert_lbl = format!("↺ {}", app.strings.revert);
        if ui.button(revert_lbl).clicked() {
            let mut st = state.clone();
            st.text = st.parsed.clone();
            app.editor = Some(st);
        }
        let close_lbl = format!("✕ {}", app.strings.close);
        if ui.button(close_lbl).clicked() {
            app.editor = None;
        }
    });
    ui.separator();

    // The guided form is a *projection* of the document, so render it from the
    // form and write the edits straight back: that is the "check the box and
    // the text changes underneath" half of the round trip.
    let mut form = state.form.clone();
    let mut changed = false;

    match &mut form {
        Form::Raw => {}
        Form::Perms(rows) => {
            ui.label(RichText::new(app.strings.f_adeia_title).strong());
            ui.add(
                egui::Label::new(
                    RichText::new(app.strings.f_adeia_hint)
                        .small()
                        .color(crate::theme::VIOLET_MUTED),
                )
                .wrap(),
            );
            if rows.is_empty() {
                ui.add(
                    egui::Label::new(
                        RichText::new(app.strings.f_perm_empty)
                            .small()
                            .color(crate::theme::VIOLET_MUTED),
                    )
                    .wrap(),
                );
            }
            let mut remove: Option<usize> = None;
            for (i, row) in rows.iter_mut().enumerate() {
                let before = row.clone();
                egui::Frame::group(ui.style())
                    .inner_margin(egui::Margin::symmetric(6, 4))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("#{}", i + 1)).small().weak());
                            ui.label(RichText::new(app.strings.f_perm_who).small());
                            egui::ComboBox::from_id_salt(("perm_who", i))
                                .width(82.0)
                                .selected_text(if row.everyone {
                                    app.strings.f_perm_all
                                } else {
                                    app.strings.f_perm_user
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut row.everyone,
                                        true,
                                        app.strings.f_perm_all,
                                    );
                                    ui.selectable_value(
                                        &mut row.everyone,
                                        false,
                                        app.strings.f_perm_user,
                                    );
                                });
                            ui.label(RichText::new(app.strings.f_perm_right).small());
                            egui::ComboBox::from_id_salt(("perm_right", i))
                                .width(78.0)
                                .selected_text(right_label(app.strings, &row.right))
                                .show_ui(ui, |ui| {
                                    for r in RIGHTS {
                                        let label = right_label(app.strings, r);
                                        ui.selectable_value(&mut row.right, r.to_string(), label);
                                    }
                                });
                            if ui.small_button("✕").clicked() {
                                remove = Some(i);
                            }
                        });
                        if !row.everyone {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(app.strings.f_perm_user_id).small());
                                ui.add(
                                    egui::TextEdit::singleline(&mut row.subject)
                                        .desired_width(ui.available_width())
                                        .hint_text(app.strings.h_perm_user),
                                );
                            });
                        }
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(app.strings.f_perm_where).small());
                            ui.add(
                                egui::TextEdit::singleline(&mut row.path)
                                    .desired_width(ui.available_width())
                                    .hint_text(app.strings.h_perm_path),
                            );
                        });
                    });
                // Combos and text fields write the row directly; diff the
                // whole row so any edit reaches the document text.
                if before != *row {
                    changed = true;
                }
            }
            if let Some(i) = remove {
                rows.remove(i);
                changed = true;
            }
            if ui.button(app.strings.add_line).clicked() {
                rows.push(PermRow::default());
                changed = true;
            }
            ui.add(
                egui::Label::new(
                    RichText::new(app.strings.f_perm_precedence)
                        .small()
                        .color(crate::theme::VIOLET_MUTED),
                )
                .wrap(),
            );
        }
        Form::Kerux { alias, target_uri } => {
            ui.label(RichText::new(app.strings.f_kerux_title).strong());
            ui.label(RichText::new(app.strings.f_kerux_hint).small().weak());
            ui.label("ALIAS");
            if egui::TextEdit::singleline(alias)
                .desired_width(ui.available_width())
                .hint_text(app.strings.h_alias)
                .show(ui)
                .response
                .changed()
            {
                changed = true;
            }
            ui.label("TARGET_URI");
            if egui::TextEdit::singleline(target_uri)
                .desired_width(ui.available_width())
                .hint_text(app.strings.h_alias_uri)
                .show(ui)
                .response
                .changed()
            {
                changed = true;
            }
        }
        Form::Timi {
            pyle,
            price,
            max_days,
            valid_kairos,
        } => {
            ui.label(RichText::new(app.strings.f_timi_title).strong());
            ui.label(RichText::new(app.strings.f_timi_hint).small().weak());
            for (label, field, hint) in [
                ("PYLE", pyle, app.strings.h_pyle),
                ("PRICE_PER_GIB_DAY", price, app.strings.h_price),
                ("MAX_DURATION_DAYS", max_days, app.strings.h_max_days),
                ("VALID_KAIROS", valid_kairos, app.strings.h_valid_kairos),
            ] {
                ui.label(label);
                if egui::TextEdit::singleline(field)
                    .desired_width(ui.available_width())
                    .hint_text(hint)
                    .show(ui)
                    .response
                    .changed()
                {
                    changed = true;
                }
            }
        }
        Form::Prosopeion {
            nickname,
            suffix,
            sign_pubkey,
            enc_pubkey,
            omphalos,
            seed_iter,
        } => {
            ui.label(RichText::new(app.strings.f_prosopeion_title).strong());
            ui.label(RichText::new(app.strings.f_prosopeion_hint).small().weak());
            for (label, field, hint) in [
                ("NICKNAME", nickname, app.strings.h_nickname),
                ("SUFFIX", suffix, app.strings.h_suffix),
                ("SIGN_PUBKEY", sign_pubkey, app.strings.h_sign),
                ("ENC_PUBKEY", enc_pubkey, app.strings.h_enc),
                ("OMPHALOS", omphalos, app.strings.h_omphalos),
                ("SEED_ITER", seed_iter, app.strings.h_seed),
            ] {
                ui.label(label);
                if egui::TextEdit::singleline(field)
                    .desired_width(ui.available_width())
                    .hint_text(hint)
                    .show(ui)
                    .response
                    .changed()
                {
                    changed = true;
                }
            }
        }
        Form::Prytaneion {
            content_hash,
            origin_pyle,
            origin_user,
            status,
            replicas,
            deletions,
        } => {
            ui.label(RichText::new(app.strings.f_prytaneion_title).strong());
            ui.label(RichText::new(app.strings.f_prytaneion_hint).small().weak());
            for (label, field, hint) in [
                ("CONTENT_HASH", content_hash, app.strings.h_content_hash),
                ("ORIGIN_PYLE", origin_pyle, app.strings.h_origin_pyle),
                ("ORIGIN_USER", origin_user, app.strings.h_origin_user),
                ("STATUS", status, app.strings.h_status),
            ] {
                ui.label(label);
                if egui::TextEdit::singleline(field)
                    .desired_width(ui.available_width())
                    .hint_text(hint)
                    .show(ui)
                    .response
                    .changed()
                {
                    changed = true;
                }
            }
            ui.separator();
            ui.label(RichText::new(app.strings.replicates_lbl).small().strong());
            let mut remove: Option<usize> = None;
            for (i, r) in replicas.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    if egui::TextEdit::singleline(r)
                        .desired_width(ui.available_width() - 46.0)
                        .hint_text(app.strings.h_replica)
                        .show(ui)
                        .response
                        .changed()
                    {
                        changed = true;
                    }
                    if ui.small_button("✕").clicked() {
                        remove = Some(i);
                    }
                });
            }
            if let Some(i) = remove {
                replicas.remove(i);
                changed = true;
            }
            if ui.small_button(app.strings.add_replica).clicked() {
                replicas.push(String::new());
                changed = true;
            }
            ui.separator();
            ui.label(RichText::new(app.strings.deletions_lbl).small().strong());
            let mut remove: Option<usize> = None;
            for (i, del) in deletions.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    if egui::TextEdit::singleline(del)
                        .desired_width(ui.available_width() - 46.0)
                        .hint_text(app.strings.h_deletion)
                        .show(ui)
                        .response
                        .changed()
                    {
                        changed = true;
                    }
                    if ui.small_button("✕").clicked() {
                        remove = Some(i);
                    }
                });
            }
            if let Some(i) = remove {
                deletions.remove(i);
                changed = true;
            }
            if ui.small_button(app.strings.add_deletion).clicked() {
                deletions.push(String::new());
                changed = true;
            }
        }
    }

    let has_form = !matches!(form, Form::Raw);
    if changed {
        // Take the state out first: `apply_form` needs `&App` (for the owner)
        // and `&mut EditorState` at the same time.
        if let Some(mut st) = app.editor.take() {
            st.form = form;
            apply_form(app, &mut st);
            app.editor = Some(st);
        }
    }
    if has_form {
        ui.separator();
    }

    ui.label(RichText::new(app.strings.document).strong());
    ui.label(RichText::new(app.strings.document_hint).small().weak());
    let mut text = state.text.clone();
    let resp = egui::TextEdit::multiline(&mut text)
        .desired_width(ui.available_width())
        .desired_rows(14)
        .font(egui::TextStyle::Monospace)
        .show(ui);
    if resp.response.changed() {
        if let Some(st) = app.editor.as_mut() {
            st.text = text;
            reparse(st);
        }
    }
    if !state.error.is_empty() {
        ui.label(
            RichText::new(format!("⚠ {}", state.error)).color(Color32::from_rgb(230, 120, 90)),
        );
    }
    if state.is_dirty() {
        ui.label(RichText::new(app.strings.unsaved).small().weak());
    }
}

/// Config panel: the spec's configuration documents as a list the user can
/// read, each with one obvious action. "Configure this" used to mean finding
/// the file in a grid, selecting it, and hoping you guessed the right button.
pub fn render_config_panel(ui: &mut egui::Ui, app: &mut App) {
    // The parent panel is already a vertical ScrollArea. Nesting another one
    // made egui measure the content at an unconstrained width, which is what
    // pushed the left half of this panel off-screen. Keep one viewport and
    // clamp every child to the width we actually have.
    let width = ui.available_width();
    ui.set_min_width(width);
    ui.set_max_width(width);
    {
        ui.label(crate::theme::heading(app.strings.cfg_title));
        ui.add(egui::Label::new(crate::theme::muted(app.strings.cfg_about)).wrap());
        ui.separator();

        for (file, template, about) in crate::app::CONFIG_DOCS {
            let present = app.has_entry(file);
            egui::Frame::group(ui.style())
                .inner_margin(egui::Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(file).strong());
                        if present {
                            ui.label(
                                RichText::new(app.strings.cfg_ready)
                                    .small()
                                    .color(crate::theme::VIOLET_LIGHT),
                            );
                        } else {
                            ui.label(RichText::new(app.strings.cfg_absent).small().weak());
                        }
                    });
                    ui.add(
                        egui::Label::new(
                            RichText::new(about)
                                .small()
                                .color(crate::theme::VIOLET_MUTED),
                        )
                        .wrap(),
                    );
                    if present {
                        let open_lbl = format!("✏ {}", app.strings.cfg_open);
                        if ui.button(open_lbl).clicked() {
                            app.open_config(file);
                        }
                    } else if file == "diadosi.hdap" {
                        // The only trustworthy way to create this document is
                        // signing it. Point the card at the backup panel rather
                        // than generating an unsigned body.
                        let create_lbl = format!("✚ {}", app.strings.diadosi_btn);
                        if ui.button(create_lbl).clicked() {
                            app.open_diadosi();
                        }
                    } else if let Some(kind) = template_kind(template) {
                        let create_lbl = format!("✚ {}", app.strings.cfg_create);
                        if ui.button(create_lbl).clicked() {
                            create(app, file, kind);
                        }
                    }
                });
            ui.add_space(4.0);
        }

        ui.separator();
        ui.label(RichText::new(app.strings.tr_title).strong());
        ui.add(
            egui::Label::new(
                RichText::new(app.strings.tr_about)
                    .small()
                    .color(crate::theme::VIOLET_MUTED),
            )
            .wrap(),
        );
        ui.horizontal(|ui| {
            ui.label(crate::theme::muted(app.strings.tr_target));
            if ui
                .small_button(app.strings.tr_use_selected)
                .on_hover_text(app.strings.tr_use_selected_hover)
                .clicked()
            {
                app.seed_transfer();
            }
        });
        if ui
            .add(
                egui::TextEdit::singleline(&mut app.transfer_target)
                    .desired_width(ui.available_width())
                    .hint_text(app.strings.tr_target_hint),
            )
            .changed()
        {
            app.transfer_status.clear();
        }
        ui.horizontal(|ui| {
            ui.label(crate::theme::muted(app.strings.tr_kind));
            ui.selectable_value(
                &mut app.transfer_kind,
                "file".to_string(),
                app.strings.tr_kind_file,
            );
            ui.selectable_value(
                &mut app.transfer_kind,
                "dir".to_string(),
                app.strings.tr_kind_dir,
            );
            ui.selectable_value(
                &mut app.transfer_kind,
                "identity".to_string(),
                app.strings.tr_kind_identity,
            );
        });
        ui.horizontal(|ui| {
            ui.label(crate::theme::muted(app.strings.tr_new_owner));
        });
        ui.horizontal(|ui| {
            // An infinite desired width asks the parent for more than the
            // panel has, and egui answers by sliding the whole panel right
            // (half of it off-screen). Reserve room for the search button.
            let field_width = (ui.available_width() - 34.0).max(80.0);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut app.transfer_new_uri)
                        .desired_width(field_width)
                        .hint_text(app.strings.tr_new_owner_hint),
                )
                .changed()
            {
                app.transfer_status.clear();
            }
            if ui
                .small_button("🔍")
                .on_hover_text(app.strings.tr_resolve_owner)
                .clicked()
            {
                app.resolve_transfer_owner();
            }
        });
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!app.transfer_busy, egui::Button::new(app.strings.tr_go))
                .clicked()
            {
                app.transfer_selected();
            }
            if app.transfer_busy {
                ui.spinner();
            }
        });
        if !app.transfer_status.is_empty() {
            ui.add(
                egui::Label::new(RichText::new(&app.transfer_status).small().color(
                    if app.transfer_busy {
                        crate::theme::VIOLET_LIGHT
                    } else {
                        crate::theme::VIOLET_MUTED
                    },
                ))
                .wrap(),
            );
        }

        ui.separator();
        ui.horizontal(|ui| {
            ui.label(RichText::new(app.strings.tr_inbox).strong());
            if ui.small_button(app.strings.tr_inbox_refresh).clicked() {
                app.refresh_transfer_inbox();
            }
        });
        let inbox = app.transfer_inbox.clone();
        if inbox.is_empty() {
            ui.label(crate::theme::muted(app.strings.tr_inbox_empty));
        } else {
            for item in inbox {
                ui.group(|ui| {
                    let who = if item.old_nickname.is_empty() {
                        &item.old_owner
                    } else {
                        &item.old_nickname
                    };
                    ui.add(
                        egui::Label::new(format!(
                            "{} -> {} [{}] {} file(s)",
                            who, item.new_uri, item.target_kind, item.assets
                        ))
                        .wrap(),
                    );
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                !app.transfer_busy,
                                egui::Button::new(app.strings.tr_accept),
                            )
                            .clicked()
                        {
                            app.accept_transfer_item(&item.request_id);
                        }
                        ui.add(egui::Label::new(crate::theme::muted(&item.request_id)).wrap());
                    });
                });
            }
        }

        ui.separator();
        if ui.button(app.strings.close_panel).clicked() {
            app.side_panel = None;
        }
    }
}

/// Map a catalog template id to the editor template. Documents the editor can
/// only open (no template) return `None`, so the panel offers "abrir" only.
fn template_kind(id: &str) -> Option<Template> {
    match id {
        "adeia" => Some(Template::Adeia),
        "kerux" => Some(Template::Kerux),
        "timi" => Some(Template::Timi),
        "prytaneion" => Some(Template::Prytaneion),
        "prosopeion" => Some(Template::Prosopeion),
        "diadosi" => Some(Template::Diadosi),
        _ => None,
    }
}

/// Prices panel (katallaxia).
/// Prices panel (katallaxia): announcements federated from other pyles,
/// refreshed automatically by the login `/sync` (no stale page to poke).
pub fn render_prices_panel(ui: &mut egui::Ui, app: &mut App) {
    ui.label(RichText::new(app.strings.pr_title).strong());
    ui.label(crate::theme::muted(app.strings.pr_about));
    if app.prices.is_empty() {
        ui.label(RichText::new(app.strings.pr_empty).small().weak());
        if ui.button(app.strings.pr_publish).clicked() {
            app.toggle_panel(crate::app::SidePanel::Config);
        }
        if ui.small_button(app.strings.pr_refresh).clicked() {
            app.refresh_prices();
        }
        return;
    }
    for p in &app.prices {
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::symmetric(8, 6))
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&p.pyle)
                            .monospace()
                            .color(crate::theme::VIOLET_LIGHT),
                    )
                    .wrap(),
                );
                ui.label(format!(
                    "{} {} · {} {}",
                    app.strings.pr_col_unit,
                    p.price_per_gib_day,
                    app.strings.pr_col_retention,
                    crate::i18n::fill1(app.strings.u_days, &p.max_duration_days.to_string()),
                ));
            });
        ui.add_space(3.0);
    }
    if ui.small_button(app.strings.pr_refresh).clicked() {
        app.refresh_prices();
    }
}

/// Aliases panel (kerux / DDNS). The list comes from the login `/sync`, so
/// what the server resolves is exactly what is shown.
pub fn render_aliases_panel(ui: &mut egui::Ui, app: &mut App) {
    ui.label(RichText::new(app.strings.al_title).strong());
    ui.label(crate::theme::muted(app.strings.al_about));
    if app.aliases.is_empty() {
        ui.label(RichText::new(app.strings.al_empty).small().weak());
    } else {
        for (alias, uri) in &app.aliases {
            egui::Frame::group(ui.style())
                .inner_margin(egui::Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    ui.label(RichText::new(alias).strong());
                    ui.add(egui::Label::new(crate::theme::muted(uri).monospace()).wrap());
                });
            ui.add_space(3.0);
        }
    }
    ui.separator();
    ui.label(app.strings.al_col_alias);
    ui.add(egui::TextEdit::singleline(&mut app.alias_input).desired_width(ui.available_width()));
    ui.label(app.strings.al_col_uri);
    ui.add(
        egui::TextEdit::singleline(&mut app.alias_uri_input).desired_width(ui.available_width()),
    );
    ui.horizontal(|ui| {
        if ui.button(app.strings.al_publish).clicked() {
            app.publish_alias();
        }
        if ui.button(app.strings.al_resolve).clicked() {
            app.resolve_alias();
        }
    });
    if let Some(res) = &app.alias_result {
        ui.add(egui::Label::new(crate::theme::muted(res).monospace()).wrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000;

    fn base_of(kind: Template) -> Doc {
        doc::parse(&template_text(kind, "alice", "alice", T0)).expect("template must parse")
    }

    fn rows(perms: &[(&str, &str)]) -> Vec<PermRow> {
        perms
            .iter()
            .map(|(s, r)| {
                let (everyone, subject, path) = if *s == "all" {
                    (true, String::new(), "/".to_string())
                } else if let Some(u) = s.strip_prefix("user:") {
                    (false, u.to_string(), "/".to_string())
                } else if let Some(p) = s.strip_prefix("path:") {
                    (true, String::new(), format!("/{p}"))
                } else {
                    panic!("unknown scope in test: {s}")
                };
                PermRow {
                    everyone,
                    subject,
                    path,
                    right: r.to_string(),
                }
            })
            .collect()
    }

    fn rule(subject: &str, path: &str, right: &str) -> PermRow {
        PermRow {
            everyone: subject.is_empty(),
            subject: subject.to_string(),
            path: path.to_string(),
            right: right.to_string(),
        }
    }

    fn adeia_text(perms: &[(&str, &str)]) -> String {
        build_adeia("alice", &rows(perms), &base_of(Template::Adeia))
            .unwrap()
            .render()
    }

    fn form_perms(st: &EditorState) -> Vec<PermRow> {
        match &st.form {
            Form::Perms(r) => r.clone(),
            other => panic!("expected a perm form, got {other:?}"),
        }
    }

    #[test]
    fn a_checked_row_becomes_a_canonical_acl_line() {
        let t = adeia_text(&[("all", "read")]);
        let d = doc::parse(&t).expect("form output must be a valid doc");
        assert_eq!(d.doc_type, DocType::Adeia);
        assert_eq!(
            d.body.get("PERM0000").map(String::as_str),
            Some("PERM alice all read")
        );
        // Canonical output must round-trip.
        let mut st = EditorState {
            text: t.clone(),
            ..Default::default()
        };
        reparse(&mut st);
        assert_eq!(form_perms(&st), rows(&[("all", "read")]));
        assert!(st.error.is_empty());
    }

    #[test]
    fn editing_text_updates_the_form() {
        let t = adeia_text(&[("user:aluno", "write"), ("path:docs", "own")]);
        let mut st = EditorState {
            text: t,
            ..Default::default()
        };
        reparse(&mut st);
        assert_eq!(
            form_perms(&st),
            rows(&[("user:aluno", "write"), ("path:docs", "own")])
        );
    }

    #[test]
    fn a_user_can_be_denied_on_one_file_without_losing_the_house() {
        let t = build_adeia(
            "alice",
            &[
                rule("", "/", "read"),
                rule("maria", "docs/segredo.txt", "deny"),
            ],
            &base_of(Template::Adeia),
        )
        .unwrap()
        .render();
        let d = doc::parse(&t).expect("form output must be a valid doc");
        assert_eq!(
            d.body.get("PERM0000").map(String::as_str),
            Some("PERM alice all read")
        );
        assert_eq!(
            d.body.get("PERM0001").map(String::as_str),
            Some("PERM alice user:maria docs/segredo.txt deny")
        );
        // The form must show the same two rows when the document is reopened.
        let mut st = EditorState {
            text: t,
            ..Default::default()
        };
        reparse(&mut st);
        assert_eq!(
            form_perms(&st),
            vec![
                rule("", "/", "read"),
                rule("maria", "/docs/segredo.txt", "deny")
            ]
        );
    }

    #[test]
    fn broken_text_reports_an_error_without_wiping_the_form() {
        let t = adeia_text(&[("all", "read")]);
        let mut st = EditorState {
            text: t.clone(),
            ..Default::default()
        };
        reparse(&mut st);
        let good = st.form.clone();
        // Simulate the user typing garbage.
        st.text = "isso não é um documento".into();
        reparse(&mut st);
        assert!(!st.error.is_empty(), "garbage must be reported");
        assert_eq!(st.form, good, "form must survive invalid text");
    }

    #[test]
    fn form_and_text_stay_in_sync_both_ways() {
        // text -> form -> text
        let t = adeia_text(&[("all", "deny")]);
        let mut st = EditorState {
            text: t,
            ..Default::default()
        };
        reparse(&mut st);
        let Form::Perms(r) = &mut st.form else {
            panic!("perm form")
        };
        r[0].right = "write".into();
        let rendered = build_adeia("alice", r, &doc::parse(&st.parsed).unwrap())
            .unwrap()
            .render();
        let d = doc::parse(&rendered).unwrap();
        assert_eq!(
            d.body.get("PERM0000").map(String::as_str),
            Some("PERM alice all write")
        );
    }

    #[test]
    fn edition_two_carries_prev_hash() {
        let t1 = adeia_text(&[("all", "read")]);
        let d1 = chain_edition(base_of(Template::Adeia), 2, &t1);
        assert_eq!(d1.edition, 2);
        assert_eq!(d1.prev_hash, Some(hex64(&doc_text_hash(&t1))));
        // The first edition has nothing to point back to.
        let d0 = chain_edition(base_of(Template::Adeia), 1, &t1);
        assert!(d0.prev_hash.is_none());
    }

    /// The bug this pins: `PREV_HASH` used to be computed from the *working
    /// buffer*, so the previous edition was silently rewritten and the
    /// immutability trail (§4.2) pointed at text nobody ever stored.
    #[test]
    fn prev_hash_points_at_the_node_not_the_buffer() {
        let stored = adeia_text(&[("all", "read")]);
        let edited = adeia_text(&[("all", "own")]);
        let d = chain_edition(doc::parse(&stored).unwrap(), 2, &stored);
        assert_eq!(d.prev_hash, Some(hex64(&doc_text_hash(&stored))));
        assert_ne!(d.prev_hash, Some(hex64(&doc_text_hash(&edited))));
    }

    #[test]
    fn an_adeia_form_preserves_keys_it_does_not_own() {
        let mut base = base_of(Template::Adeia);
        base.body.insert("UUID".into(), "abc-123".into());
        let d = build_adeia("alice", &rows(&[("all", "read")]), &base).unwrap();
        assert_eq!(
            d.body.get("UUID").map(String::as_str),
            Some("abc-123"),
            "UUID is not a form field and must survive an edit"
        );
    }

    #[test]
    fn a_kerux_form_rewrites_both_fields() {
        let mut st = EditorState {
            text: template_text(Template::Kerux, "alice", "alice", T0),
            ..Default::default()
        };
        reparse(&mut st);
        let mut form = st.form.clone();
        let Form::Kerux { alias, target_uri } = &mut form else {
            panic!("kerux must project to a form, got {form:?}")
        };
        *alias = "artefato".into();
        *target_uri = "HDAP!node@alice/docs/a.txt?hash=ab".into();
        let d = build_kerux(&form, &st.parsed);
        assert_eq!(d.body.get("ALIAS").map(String::as_str), Some("artefato"));
        assert_eq!(
            d.body.get("TARGET_URI").map(String::as_str),
            Some("HDAP!node@alice/docs/a.txt?hash=ab")
        );
        // And back again: the text must rebuild the same form.
        let mut back = EditorState {
            text: d.render(),
            ..Default::default()
        };
        reparse(&mut back);
        assert_eq!(back.form, form, "kerux must round-trip both ways");
    }

    #[test]
    fn a_timi_form_rewrites_every_price_field() {
        let mut st = EditorState {
            text: template_text(Template::Timi, "alice", "alice", T0),
            ..Default::default()
        };
        reparse(&mut st);
        let mut form = st.form.clone();
        let Form::Timi {
            pyle,
            price,
            max_days,
            valid_kairos,
        } = &mut form
        else {
            panic!("timi must project to a form, got {form:?}")
        };
        *pyle = "node-a:8443".into();
        *price = "0.02".into();
        *max_days = "30".into();
        *valid_kairos = "0".into();
        let d = build_timi(&form, &st.parsed);
        for (k, v) in [
            ("PYLE", "node-a:8443"),
            ("PRICE_PER_GIB_DAY", "0.02"),
            ("MAX_DURATION_DAYS", "30"),
            ("VALID_KAIROS", "0"),
        ] {
            assert_eq!(d.body.get(k).map(String::as_str), Some(v), "{k}");
        }
    }

    #[test]
    fn an_unmodelled_type_falls_back_to_raw_text() {
        // Every config type now has a form; a doc type without one (here a
        // `metabibasis`, made real by the server) must still parse and edit
        // as plain text instead of being refused.
        let raw = Doc::new(DocType::Metabibasis, 1, None, T0);
        let mut st = EditorState {
            text: raw.render(),
            ..Default::default()
        };
        reparse(&mut st);
        assert!(
            st.error.is_empty(),
            "metabibasis has no form but must still parse: {}",
            st.error
        );
        assert_eq!(st.form, Form::Raw, "no form is a valid projection");
    }

    #[test]
    fn every_template_is_already_a_valid_document() {
        let now = 1_700_000_000;
        assert!(
            Template::ALL
                .iter()
                .any(|(kind, label, file)| *kind == Template::Diadosi
                    && *label == "diadosi"
                    && *file == "diadosi.hdap"),
            "diadosi must be a first-class menu type"
        );
        assert!(is_config_doc("diadosi.hdap"));
        for (kind, _, fname) in Template::ALL {
            let t = template_text(kind, "alice", "alice", now);
            if kind == Template::Texto {
                assert_eq!(fname, "nota.txt");
                assert!(t.is_empty(), "plain text starts empty");
                continue;
            }
            let d = doc::parse(&t).unwrap_or_else(|e| panic!("{kind:?} template must parse: {e}"));
            assert_eq!(d.edition, 1);
            assert_eq!(d.created_at, now);
            assert!(d.prev_hash.is_none());
            match kind {
                // An `adeia` with no grants is the correct secure default, so
                // an empty body is expected there and only there.
                Template::Adeia => {
                    assert!(
                        !d.body.keys().any(|k| k.starts_with("PERM")),
                        "adeia template must not pre-grant anything"
                    );
                }
                // `kerux` is a blank form: the fields the user fills arrive
                // empty so nothing invented ships to the node (§13).
                Template::Kerux => {
                    assert!(d.body.contains_key("ALIAS"), "kerux template loses ALIAS");
                    assert!(
                        d.body.contains_key("TARGET_URI"),
                        "kerux template loses TARGET_URI"
                    );
                }
                _ => {
                    assert!(
                        d.body.values().any(|v| !v.is_empty()),
                        "{kind:?} template has no body content"
                    );
                }
            }
        }
    }

    #[test]
    fn kerux_and_timi_templates_carry_their_spec_fields() {
        let now = 1_700_000_000;
        let k = doc::parse(&template_text(Template::Kerux, "alice", "alice", now)).unwrap();
        assert_eq!(k.doc_type, DocType::Kerux);
        assert!(k.body.contains_key("ALIAS"));
        assert!(k.body.contains_key("TARGET_URI"));
        let t = doc::parse(&template_text(Template::Timi, "alice", "alice", now)).unwrap();
        assert_eq!(t.doc_type, DocType::Timi);
        for field in [
            "PYLE",
            "PRICE_PER_GIB_DAY",
            "MAX_DURATION_DAYS",
            "VALID_KAIROS",
        ] {
            assert!(t.body.contains_key(field), "missing {field}");
        }
    }

    #[test]
    fn perm_row_parsing_rejects_nonsense() {
        assert!(parse_perm_row("PERM alice all").is_none());
        assert!(parse_perm_row("PERM alice bogus read").is_none());
        assert!(parse_perm_row("PERM alice all sideways").is_none());
        assert!(parse_perm_row("PERM alice all read extra").is_none());
        assert!(parse_perm_row("ALLOW alice all read").is_none());
        assert_eq!(
            parse_perm_row("PERM alice path:docs own"),
            Some(PermRow {
                everyone: true,
                subject: String::new(),
                path: "/docs".into(),
                right: "own".into()
            })
        );
        assert_eq!(
            parse_perm_row("PERM alice user:maria docs/segredo.txt deny"),
            Some(PermRow {
                everyone: false,
                subject: "maria".into(),
                path: "/docs/segredo.txt".into(),
                right: "deny".into()
            })
        );
    }
}
