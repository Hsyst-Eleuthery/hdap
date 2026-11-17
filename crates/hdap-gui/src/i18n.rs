//! Interface strings for the whole GUI, in four languages. The protocol core
//! stays language-neutral (fields like `ALIAS`, doc types, rights), so only
//! chrome lives here. `App` holds a `Strings` built from the chosen `Lang`;
//! the wizard offers a selector, and the choice is persisted next to the
//! vault's home.
//!
//! Translations now live in external JSON files under `locales/` and are
//! embedded at compile time with `include_str!`. A parity test in this module
//! asserts that every language defines exactly the same set of keys, so a
//! missing translation is caught at test time rather than at runtime.

use std::collections::BTreeMap;

/// Fill the `{}` slots of a localized template in order (positional, so the
/// template can live as a plain `String` in the bag — `format!` would require
/// a literal).
pub fn fill1(t: &str, a: &str) -> String {
    t.replacen("{}", a, 1)
}

pub fn fill2(t: &str, a: &str, b: &str) -> String {
    t.replacen("{}", a, 1).replacen("{}", b, 1)
}

pub fn fill3(t: &str, a: &str, b: &str, c: &str) -> String {
    t.replacen("{}", a, 1)
        .replacen("{}", b, 1)
        .replacen("{}", c, 1)
}

pub fn fill4(t: &str, a: &str, b: &str, c: &str, d: &str) -> String {
    t.replacen("{}", a, 1)
        .replacen("{}", b, 1)
        .replacen("{}", c, 1)
        .replacen("{}", d, 1)
}

/// The language of every user-facing label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Pt,
    En,
    Es,
    Fr,
}

impl Lang {
    pub const ALL: [Lang; 4] = [Lang::Pt, Lang::En, Lang::Es, Lang::Fr];

    pub fn code(self) -> &'static str {
        match self {
            Lang::Pt => "pt",
            Lang::En => "en",
            Lang::Es => "es",
            Lang::Fr => "fr",
        }
    }

    /// Short name for the selector.
    pub fn name(self) -> &'static str {
        match self {
            Lang::Pt => "Português",
            Lang::En => "English",
            Lang::Es => "Español",
            Lang::Fr => "Français",
        }
    }

    /// Embedded JSON payload for this language.
    fn json(self) -> &'static str {
        match self {
            Lang::Pt => include_str!("../locales/pt.json"),
            Lang::En => include_str!("../locales/en.json"),
            Lang::Es => include_str!("../locales/es.json"),
            Lang::Fr => include_str!("../locales/fr.json"),
        }
    }
}

/// A fully pre-rendered bag of strings for one language. Fields are grouped by
/// screen, mirroring `view.rs` / `editor.rs` / `app.rs`.
///
/// Strings are `&'static str` because they are loaded from embedded JSON at
/// compile time and leaked into `'static` memory, so the GUI keeps using
/// `&str` everywhere without any lifetime juggling.
pub struct Strings {
    /// explorer tagline under the HDAP logotype
    pub wizard_subtitle: &'static str,
    pub label_node: &'static str,
    pub label_port: &'static str,
    pub label_pin: &'static str,
    pub pin_empty_tofu: &'static str,
    pub label_options: &'static str,
    pub plaintext_dev: &'static str,
    pub label_home: &'static str,
    pub home_empty_temp: &'static str,
    pub label_nick: &'static str,
    pub nick_example: &'static str,
    pub label_pass: &'static str,
    pub label_lang: &'static str,
    pub pin_note: &'static str,
    pub connecting: &'static str,
    pub connect: &'static str,
    pub cancel: &'static str,
    /// proof-of-work modal
    pub pow_title: &'static str,
    pub pow_mining: &'static str,
    pub pow_difficulty: &'static str,
    pub pow_cancel: &'static str,
    pub pow_canceled: &'static str,
    pub pow_attempts: &'static str,
    pub pow_expected: &'static str,
    pub pow_elapsed: &'static str,
    /// pending upload banner
    pub upload_banner_lbl: &'static str,
    pub upload_now: &'static str,
    pub discard: &'static str,
    /// toolbar
    pub back: &'static str,
    pub forward: &'static str,
    pub up: &'static str,
    pub reload: &'static str,
    pub upload: &'static str,
    pub upload_hover_ro: &'static str,
    pub upload_hover: &'static str,
    pub config: &'static str,
    pub config_hover: &'static str,
    pub cfg_title: &'static str,
    pub cfg_about: &'static str,
    pub cfg_ready: &'static str,
    pub cfg_absent: &'static str,
    pub cfg_open: &'static str,
    pub cfg_create: &'static str,
    pub band_btn: &'static str,
    pub band_hover: &'static str,
    pub band_available: &'static str,
    pub band_mining: &'static str,
    pub band_mine: &'static str,
    pub band_empty: &'static str,
    pub rot_hover: &'static str,
    pub rot_busy: &'static str,
    pub rot_done: &'static str,
    pub rot_fail: &'static str,
    pub motd_hover: &'static str,
    pub sign_out: &'static str,
    pub sign_out_hover: &'static str,
    pub readonly_badge: &'static str,
    pub connected: &'static str,
    pub not_connected: &'static str,
    pub copy_uri: &'static str,
    pub uri_edit_hint: &'static str,
    pub uri_go: &'static str,
    pub uri_alias_lookup: &'static str,
    pub uri_alias_ok: &'static str,
    pub uri_alias_missing: &'static str,
    pub uri_other_space: &'static str,
    pub with_hash: &'static str,
    pub preview_title: &'static str,
    pub preview_image_error: &'static str,
    pub preview_audio_not_supported: &'static str,
    pub preview_unknown: &'static str,
    pub search: &'static str,
    pub select: &'static str,
    pub sort_name: &'static str,
    pub sort_name_hover: &'static str,
    pub sort_size: &'static str,
    pub sort_size_hover: &'static str,
    pub save: &'static str,
    pub open: &'static str,
    pub close: &'static str,
    pub close_panel: &'static str,
    pub create: &'static str,
    pub delete: &'static str,
    pub delete_hover_ro: &'static str,
    pub revert: &'static str,
    pub new_file: &'static str,
    pub new_file_hint: &'static str,
    pub document: &'static str,
    pub document_hint: &'static str,
    pub download: &'static str,
    pub back_home: &'static str,
    /// adequacy / adeia editor
    pub f_adeia_title: &'static str,
    pub f_adeia_hint: &'static str,
    pub f_kerux_title: &'static str,
    pub f_kerux_hint: &'static str,
    pub f_prosopeion_title: &'static str,
    pub f_prosopeion_hint: &'static str,
    pub f_prytaneion_title: &'static str,
    pub f_prytaneion_hint: &'static str,
    pub f_timi_title: &'static str,
    pub f_timi_hint: &'static str,
    pub f_perm_who: &'static str,
    pub f_perm_user_id: &'static str,
    pub f_perm_where: &'static str,
    pub f_perm_right: &'static str,
    pub f_perm_right_read: &'static str,
    pub f_perm_right_write: &'static str,
    pub f_perm_right_own: &'static str,
    pub f_perm_right_deny: &'static str,
    pub f_perm_user: &'static str,
    pub f_perm_all: &'static str,
    pub f_perm_empty: &'static str,
    pub f_perm_precedence: &'static str,
    /// band / mochthos
    pub m_band_hint: &'static str,
    pub m_cfg_saved: &'static str,
    pub m_creating: &'static str,
    pub m_editing: &'static str,
    pub m_invalid_perm: &'static str,
    pub m_no_session_edit: &'static str,
    pub m_no_session_sign: &'static str,
    pub m_not_saved: &'static str,
    pub m_open_fail: &'static str,
    pub m_ro_save: &'static str,
    pub m_save_fail: &'static str,
    pub m_saved: &'static str,
    /// sidebar sections
    pub s_root: &'static str,
    pub s_places: &'static str,
    pub s_people: &'static str,
    pub s_panels: &'static str,
    pub s_network: &'static str,
    pub s_identity: &'static str,
    pub s_band: &'static str,
    pub s_open: &'static str,
    pub s_up: &'static str,
    /// status bar
    pub st_connected_as: &'static str,
    pub st_connected_pyle: &'static str,
    pub st_connecting: &'static str,
    pub st_band_now: &'static str,
    pub st_band_failed: &'static str,
    pub st_identity_err: &'static str,
    pub st_disconnected: &'static str,
    pub st_connect_failed: &'static str,
    pub st_connect_canceled: &'static str,
    pub st_client_err: &'static str,
    pub st_loading_dir: &'static str,
    pub st_loaded: &'static str,
    pub st_list_failed: &'static str,
    pub st_searching: &'static str,
    pub st_read_fail: &'static str,
    pub st_uploaded: &'static str,
    pub st_upload_fail: &'static str,
    pub st_upload_ro: &'static str,
    pub st_visit_fail: &'static str,
    pub st_downloaded: &'static str,
    pub st_download_fail: &'static str,
    pub st_deleted: &'static str,
    pub st_delete_fail: &'static str,
    pub st_delete_ro: &'static str,
    pub st_nothing_selected: &'static str,
    pub st_nothing_delete: &'static str,
    pub st_not_logged: &'static str,
    pub st_no_nick: &'static str,
    pub st_no_queued: &'static str,
    pub st_pin_changed: &'static str,
    pub st_pin_fixed: &'static str,
    pub st_prices_ok: &'static str,
    pub st_prices_fail: &'static str,
    pub st_proklesis_err: &'static str,
    pub st_resolve_ok: &'static str,
    pub st_resolve_fail: &'static str,
    pub st_save_fail: &'static str,
    pub st_syncing: &'static str,
    pub st_synced: &'static str,
    pub st_sync_failed: &'static str,
    pub st_mining_band: &'static str,
    pub st_mirroring: &'static str,
    pub st_mirrored: &'static str,
    pub st_mirror_fail: &'static str,
    pub st_mirror_local: &'static str,
    pub st_mirror_denied: &'static str,
    pub st_timeout: &'static str,
    pub st_copied: &'static str,
    pub st_alias_ok: &'static str,
    pub st_alias_fail: &'static str,
    /// aliases
    pub aliases_btn: &'static str,
    pub al_title: &'static str,
    pub al_empty: &'static str,
    pub al_required: &'static str,
    pub al_need_alias: &'static str,
    pub al_col_alias: &'static str,
    pub al_col_uri: &'static str,
    pub al_publish: &'static str,
    pub al_resolve: &'static str,
    pub al_result_pub: &'static str,
    pub al_about: &'static str,
    /// prices
    pub prices_btn: &'static str,
    pub pr_title: &'static str,
    pub pr_empty: &'static str,
    pub pr_publish: &'static str,
    pub pr_refresh: &'static str,
    pub pr_about: &'static str,
    pub pr_col_pyle: &'static str,
    pub pr_col_retention: &'static str,
    pub pr_col_unit: &'static str,
    /// transfers
    pub tr_title: &'static str,
    pub tr_about: &'static str,
    pub tr_inbox: &'static str,
    pub tr_inbox_empty: &'static str,
    pub tr_inbox_refresh: &'static str,
    pub tr_new_home: &'static str,
    pub tr_new_home_hint: &'static str,
    pub tr_new_owner: &'static str,
    pub tr_new_owner_hint: &'static str,
    pub tr_target: &'static str,
    pub tr_target_hint: &'static str,
    pub tr_kind: &'static str,
    pub tr_kind_file: &'static str,
    pub tr_kind_dir: &'static str,
    pub tr_kind_identity: &'static str,
    pub tr_no_identity: &'static str,
    pub tr_no_nick: &'static str,
    pub tr_no_selection: &'static str,
    pub tr_no_session: &'static str,
    pub tr_no_target: &'static str,
    pub tr_resolve_owner: &'static str,
    pub tr_resolved: &'static str,
    pub tr_resolve_failed: &'static str,
    pub tr_accept: &'static str,
    pub tr_accepted: &'static str,
    pub tr_accepting: &'static str,
    pub tr_active: &'static str,
    pub tr_done: &'static str,
    pub tr_done_toast: &'static str,
    pub tr_fail: &'static str,
    pub tr_fill_both: &'static str,
    pub tr_go: &'static str,
    pub tr_use_selected: &'static str,
    pub tr_use_selected_hover: &'static str,
    pub tr_bad_uri: &'static str,
    pub tr_vault_mismatch: &'static str,
    /// house move / metabibasis
    pub house_move_title: &'static str,
    pub house_move_btn: &'static str,
    pub house_move_hint: &'static str,
    pub house_move_need_pyle: &'static str,
    pub house_move_new_pyle: &'static str,
    pub house_move_ok: &'static str,
    pub house_move_fail: &'static str,
    pub house_move_signing: &'static str,
    pub house_move_submit: &'static str,
    pub house_move_adeia: &'static str,
    pub house_move_about: &'static str,
    /// diadosi (home fallback)
    pub diadosi_title: &'static str,
    pub diadosi_btn: &'static str,
    pub diadosi_home: &'static str,
    pub diadosi_fallbacks: &'static str,
    pub diadosi_no_peers: &'static str,
    pub diadosi_ok: &'static str,
    pub diadosi_fail: &'static str,
    pub diadosi_signing: &'static str,
    pub diadosi_submit: &'static str,
    pub diadosi_suggest_btn: &'static str,
    pub diadosi_suggested: &'static str,
    pub diadosi_need_docs: &'static str,
    pub diadosi_need_fallback: &'static str,
    pub diadosi_hint: &'static str,
    pub diadosi_about: &'static str,
    /// bubble / notifications
    pub bubble_title: &'static str,
    pub bubble_empty: &'static str,
    pub bubble_summary: &'static str,
    pub bubble_filter_hint: &'static str,
    pub bubble_show: &'static str,
    pub bubble_hide: &'static str,
    /// hash lookup
    pub hash_lookup: &'static str,
    pub hash_search: &'static str,
    pub hash_invalid: &'static str,
    pub hash_holders: &'static str,
    /// grid / listing columns
    pub col_name: &'static str,
    pub col_size: &'static str,
    pub col_hash: &'static str,
    pub col_actions: &'static str,
    pub grid_empty: &'static str,
    /// file headers
    pub h_pyle: &'static str,
    pub h_origin_pyle: &'static str,
    pub h_replica: &'static str,
    pub h_origin_user: &'static str,
    pub h_nickname: &'static str,
    pub h_suffix: &'static str,
    pub h_sign: &'static str,
    pub h_enc: &'static str,
    pub h_omphalos: &'static str,
    pub h_seed: &'static str,
    pub h_content_hash: &'static str,
    pub h_alias: &'static str,
    pub h_alias_uri: &'static str,
    pub h_deletion: &'static str,
    pub h_perm_path: &'static str,
    pub h_perm_user: &'static str,
    pub h_price: &'static str,
    pub h_max_days: &'static str,
    pub h_valid_kairos: &'static str,
    pub h_status: &'static str,
    /// units
    pub u_band: &'static str,
    pub u_band_colon: &'static str,
    pub u_days: &'static str,
    pub u_docs: &'static str,
    pub u_expires: &'static str,
    pub u_items: &'static str,
    pub u_node: &'static str,
    pub u_retention: &'static str,
    /// misc
    pub none: &'static str,
    pub unsaved: &'static str,
    pub file_name: &'static str,
    pub person_hint: &'static str,
    pub pinned: &'static str,
    pub e_title: &'static str,
    /// resolver status
    pub resolving: &'static str,
    pub v_not_found: &'static str,
    pub v_open_lbl: &'static str,
    pub v_opening: &'static str,
    pub v_own: &'static str,
    pub v_own_toast: &'static str,
    /// link-down / offline
    pub link_down_title: &'static str,
    pub link_down_body: &'static str,
    pub link_down_after: &'static str,
    pub link_down_login: &'static str,
    pub link_down_stay: &'static str,
    pub last_download: &'static str,
    /// replication
    pub replicates_lbl: &'static str,
    pub deletions_lbl: &'static str,
    /// add line / replica / deletion
    pub add_line: &'static str,
    pub add_replica: &'static str,
    pub add_deletion: &'static str,
}

/// Build a `Strings` bag from the embedded JSON of a language.
///
/// Values are leaked into `'static` memory so callers keep using `&str`
/// without any lifetime juggling. Leaking is intentional: the strings live for
/// the whole process and are small (~332 entries per language).
fn load(lang: Lang) -> Strings {
    let map: BTreeMap<String, String> =
        serde_json::from_str(lang.json()).expect("embedded locale JSON is valid");
    let get = |name: &str| {
        map.get(name)
            .map(|s| Box::leak(s.clone().into_boxed_str()))
            .unwrap_or_else(|| panic!("missing locale key '{name}' for language {:?}", lang.code()))
    };
    Strings {
        wizard_subtitle: get("wizard_subtitle"),
        label_node: get("label_node"),
        label_port: get("label_port"),
        label_pin: get("label_pin"),
        pin_empty_tofu: get("pin_empty_tofu"),
        label_options: get("label_options"),
        plaintext_dev: get("plaintext_dev"),
        label_home: get("label_home"),
        home_empty_temp: get("home_empty_temp"),
        label_nick: get("label_nick"),
        nick_example: get("nick_example"),
        label_pass: get("label_pass"),
        label_lang: get("label_lang"),
        pin_note: get("pin_note"),
        connecting: get("connecting"),
        connect: get("connect"),
        cancel: get("cancel"),
        pow_title: get("pow_title"),
        pow_mining: get("pow_mining"),
        pow_difficulty: get("pow_difficulty"),
        pow_cancel: get("pow_cancel"),
        pow_canceled: get("pow_canceled"),
        pow_attempts: get("pow_attempts"),
        pow_expected: get("pow_expected"),
        pow_elapsed: get("pow_elapsed"),
        upload_banner_lbl: get("upload_banner_lbl"),
        upload_now: get("upload_now"),
        discard: get("discard"),
        back: get("back"),
        forward: get("forward"),
        up: get("up"),
        reload: get("reload"),
        upload: get("upload"),
        upload_hover_ro: get("upload_hover_ro"),
        upload_hover: get("upload_hover"),
        config: get("config"),
        config_hover: get("config_hover"),
        cfg_title: get("cfg_title"),
        cfg_about: get("cfg_about"),
        cfg_ready: get("cfg_ready"),
        cfg_absent: get("cfg_absent"),
        cfg_open: get("cfg_open"),
        cfg_create: get("cfg_create"),
        band_btn: get("band_btn"),
        band_hover: get("band_hover"),
        band_available: get("band_available"),
        band_mining: get("band_mining"),
        band_mine: get("band_mine"),
        band_empty: get("band_empty"),
        rot_hover: get("rot_hover"),
        rot_busy: get("rot_busy"),
        rot_done: get("rot_done"),
        rot_fail: get("rot_fail"),
        motd_hover: get("motd_hover"),
        sign_out: get("sign_out"),
        sign_out_hover: get("sign_out_hover"),
        readonly_badge: get("readonly_badge"),
        connected: get("connected"),
        not_connected: get("not_connected"),
        copy_uri: get("copy_uri"),
        uri_edit_hint: get("uri_edit_hint"),
        uri_go: get("uri_go"),
        uri_alias_lookup: get("uri_alias_lookup"),
        uri_alias_ok: get("uri_alias_ok"),
        uri_alias_missing: get("uri_alias_missing"),
        uri_other_space: get("uri_other_space"),
        with_hash: get("with_hash"),
        preview_title: get("preview_title"),
        preview_image_error: get("preview_image_error"),
        preview_audio_not_supported: get("preview_audio_not_supported"),
        preview_unknown: get("preview_unknown"),
        search: get("search"),
        select: get("select"),
        sort_name: get("sort_name"),
        sort_name_hover: get("sort_name_hover"),
        sort_size: get("sort_size"),
        sort_size_hover: get("sort_size_hover"),
        save: get("save"),
        open: get("open"),
        close: get("close"),
        close_panel: get("close_panel"),
        create: get("create"),
        delete: get("delete"),
        delete_hover_ro: get("delete_hover_ro"),
        revert: get("revert"),
        new_file: get("new_file"),
        new_file_hint: get("new_file_hint"),
        document: get("document"),
        document_hint: get("document_hint"),
        download: get("download"),
        back_home: get("back_home"),
        f_adeia_title: get("f_adeia_title"),
        f_adeia_hint: get("f_adeia_hint"),
        f_kerux_title: get("f_kerux_title"),
        f_kerux_hint: get("f_kerux_hint"),
        f_prosopeion_title: get("f_prosopeion_title"),
        f_prosopeion_hint: get("f_prosopeion_hint"),
        f_prytaneion_title: get("f_prytaneion_title"),
        f_prytaneion_hint: get("f_prytaneion_hint"),
        f_timi_title: get("f_timi_title"),
        f_timi_hint: get("f_timi_hint"),
        f_perm_who: get("f_perm_who"),
        f_perm_user_id: get("f_perm_user_id"),
        f_perm_where: get("f_perm_where"),
        f_perm_right: get("f_perm_right"),
        f_perm_right_read: get("f_perm_right_read"),
        f_perm_right_write: get("f_perm_right_write"),
        f_perm_right_own: get("f_perm_right_own"),
        f_perm_right_deny: get("f_perm_right_deny"),
        f_perm_user: get("f_perm_user"),
        f_perm_all: get("f_perm_all"),
        f_perm_empty: get("f_perm_empty"),
        f_perm_precedence: get("f_perm_precedence"),
        m_band_hint: get("m_band_hint"),
        m_cfg_saved: get("m_cfg_saved"),
        m_creating: get("m_creating"),
        m_editing: get("m_editing"),
        m_invalid_perm: get("m_invalid_perm"),
        m_no_session_edit: get("m_no_session_edit"),
        m_no_session_sign: get("m_no_session_sign"),
        m_not_saved: get("m_not_saved"),
        m_open_fail: get("m_open_fail"),
        m_ro_save: get("m_ro_save"),
        m_save_fail: get("m_save_fail"),
        m_saved: get("m_saved"),
        s_root: get("s_root"),
        s_places: get("s_places"),
        s_people: get("s_people"),
        s_panels: get("s_panels"),
        s_network: get("s_network"),
        s_identity: get("s_identity"),
        s_band: get("s_band"),
        s_open: get("s_open"),
        s_up: get("s_up"),
        st_connected_as: get("st_connected_as"),
        st_connected_pyle: get("st_connected_pyle"),
        st_connecting: get("st_connecting"),
        st_band_now: get("st_band_now"),
        st_band_failed: get("st_band_failed"),
        st_identity_err: get("st_identity_err"),
        st_disconnected: get("st_disconnected"),
        st_connect_failed: get("st_connect_failed"),
        st_connect_canceled: get("st_connect_canceled"),
        st_client_err: get("st_client_err"),
        st_loading_dir: get("st_loading_dir"),
        st_loaded: get("st_loaded"),
        st_list_failed: get("st_list_failed"),
        st_searching: get("st_searching"),
        st_read_fail: get("st_read_fail"),
        st_uploaded: get("st_uploaded"),
        st_upload_fail: get("st_upload_fail"),
        st_upload_ro: get("st_upload_ro"),
        st_visit_fail: get("st_visit_fail"),
        st_downloaded: get("st_downloaded"),
        st_download_fail: get("st_download_fail"),
        st_deleted: get("st_deleted"),
        st_delete_fail: get("st_delete_fail"),
        st_delete_ro: get("st_delete_ro"),
        st_nothing_selected: get("st_nothing_selected"),
        st_nothing_delete: get("st_nothing_delete"),
        st_not_logged: get("st_not_logged"),
        st_no_nick: get("st_no_nick"),
        st_no_queued: get("st_no_queued"),
        st_pin_changed: get("st_pin_changed"),
        st_pin_fixed: get("st_pin_fixed"),
        st_prices_ok: get("st_prices_ok"),
        st_prices_fail: get("st_prices_fail"),
        st_proklesis_err: get("st_proklesis_err"),
        st_resolve_ok: get("st_resolve_ok"),
        st_resolve_fail: get("st_resolve_fail"),
        st_save_fail: get("st_save_fail"),
        st_syncing: get("st_syncing"),
        st_synced: get("st_synced"),
        st_sync_failed: get("st_sync_failed"),
        st_mining_band: get("st_mining_band"),
        st_mirroring: get("st_mirroring"),
        st_mirrored: get("st_mirrored"),
        st_mirror_fail: get("st_mirror_fail"),
        st_mirror_local: get("st_mirror_local"),
        st_mirror_denied: get("st_mirror_denied"),
        st_timeout: get("st_timeout"),
        st_copied: get("st_copied"),
        st_alias_ok: get("st_alias_ok"),
        st_alias_fail: get("st_alias_fail"),
        aliases_btn: get("aliases_btn"),
        al_title: get("al_title"),
        al_empty: get("al_empty"),
        al_required: get("al_required"),
        al_need_alias: get("al_need_alias"),
        al_col_alias: get("al_col_alias"),
        al_col_uri: get("al_col_uri"),
        al_publish: get("al_publish"),
        al_resolve: get("al_resolve"),
        al_result_pub: get("al_result_pub"),
        al_about: get("al_about"),
        prices_btn: get("prices_btn"),
        pr_title: get("pr_title"),
        pr_empty: get("pr_empty"),
        pr_publish: get("pr_publish"),
        pr_refresh: get("pr_refresh"),
        pr_about: get("pr_about"),
        pr_col_pyle: get("pr_col_pyle"),
        pr_col_retention: get("pr_col_retention"),
        pr_col_unit: get("pr_col_unit"),
        tr_title: get("tr_title"),
        tr_about: get("tr_about"),
        tr_inbox: get("tr_inbox"),
        tr_inbox_empty: get("tr_inbox_empty"),
        tr_inbox_refresh: get("tr_inbox_refresh"),
        tr_new_home: get("tr_new_home"),
        tr_new_home_hint: get("tr_new_home_hint"),
        tr_new_owner: get("tr_new_owner"),
        tr_new_owner_hint: get("tr_new_owner_hint"),
        tr_target: get("tr_target"),
        tr_target_hint: get("tr_target_hint"),
        tr_kind: get("tr_kind"),
        tr_kind_file: get("tr_kind_file"),
        tr_kind_dir: get("tr_kind_dir"),
        tr_kind_identity: get("tr_kind_identity"),
        tr_no_identity: get("tr_no_identity"),
        tr_no_nick: get("tr_no_nick"),
        tr_no_selection: get("tr_no_selection"),
        tr_no_session: get("tr_no_session"),
        tr_no_target: get("tr_no_target"),
        tr_resolve_owner: get("tr_resolve_owner"),
        tr_resolved: get("tr_resolved"),
        tr_resolve_failed: get("tr_resolve_failed"),
        tr_accept: get("tr_accept"),
        tr_accepted: get("tr_accepted"),
        tr_accepting: get("tr_accepting"),
        tr_active: get("tr_active"),
        tr_done: get("tr_done"),
        tr_done_toast: get("tr_done_toast"),
        tr_fail: get("tr_fail"),
        tr_fill_both: get("tr_fill_both"),
        tr_go: get("tr_go"),
        tr_use_selected: get("tr_use_selected"),
        tr_use_selected_hover: get("tr_use_selected_hover"),
        tr_bad_uri: get("tr_bad_uri"),
        tr_vault_mismatch: get("tr_vault_mismatch"),
        house_move_title: get("house_move_title"),
        house_move_btn: get("house_move_btn"),
        house_move_hint: get("house_move_hint"),
        house_move_need_pyle: get("house_move_need_pyle"),
        house_move_new_pyle: get("house_move_new_pyle"),
        house_move_ok: get("house_move_ok"),
        house_move_fail: get("house_move_fail"),
        house_move_signing: get("house_move_signing"),
        house_move_submit: get("house_move_submit"),
        house_move_adeia: get("house_move_adeia"),
        house_move_about: get("house_move_about"),
        diadosi_title: get("diadosi_title"),
        diadosi_btn: get("diadosi_btn"),
        diadosi_home: get("diadosi_home"),
        diadosi_fallbacks: get("diadosi_fallbacks"),
        diadosi_no_peers: get("diadosi_no_peers"),
        diadosi_ok: get("diadosi_ok"),
        diadosi_fail: get("diadosi_fail"),
        diadosi_signing: get("diadosi_signing"),
        diadosi_submit: get("diadosi_submit"),
        diadosi_suggest_btn: get("diadosi_suggest_btn"),
        diadosi_suggested: get("diadosi_suggested"),
        diadosi_need_docs: get("diadosi_need_docs"),
        diadosi_need_fallback: get("diadosi_need_fallback"),
        diadosi_hint: get("diadosi_hint"),
        diadosi_about: get("diadosi_about"),
        bubble_title: get("bubble_title"),
        bubble_empty: get("bubble_empty"),
        bubble_summary: get("bubble_summary"),
        bubble_filter_hint: get("bubble_filter_hint"),
        bubble_show: get("bubble_show"),
        bubble_hide: get("bubble_hide"),
        hash_lookup: get("hash_lookup"),
        hash_search: get("hash_search"),
        hash_invalid: get("hash_invalid"),
        hash_holders: get("hash_holders"),
        col_name: get("col_name"),
        col_size: get("col_size"),
        col_hash: get("col_hash"),
        col_actions: get("col_actions"),
        grid_empty: get("grid_empty"),
        h_pyle: get("h_pyle"),
        h_origin_pyle: get("h_origin_pyle"),
        h_replica: get("h_replica"),
        h_origin_user: get("h_origin_user"),
        h_nickname: get("h_nickname"),
        h_suffix: get("h_suffix"),
        h_sign: get("h_sign"),
        h_enc: get("h_enc"),
        h_omphalos: get("h_omphalos"),
        h_seed: get("h_seed"),
        h_content_hash: get("h_content_hash"),
        h_alias: get("h_alias"),
        h_alias_uri: get("h_alias_uri"),
        h_deletion: get("h_deletion"),
        h_perm_path: get("h_perm_path"),
        h_perm_user: get("h_perm_user"),
        h_price: get("h_price"),
        h_max_days: get("h_max_days"),
        h_valid_kairos: get("h_valid_kairos"),
        h_status: get("h_status"),
        u_band: get("u_band"),
        u_band_colon: get("u_band_colon"),
        u_days: get("u_days"),
        u_docs: get("u_docs"),
        u_expires: get("u_expires"),
        u_items: get("u_items"),
        u_node: get("u_node"),
        u_retention: get("u_retention"),
        none: get("none"),
        unsaved: get("unsaved"),
        file_name: get("file_name"),
        person_hint: get("person_hint"),
        pinned: get("pinned"),
        e_title: get("e_title"),
        resolving: get("resolving"),
        v_not_found: get("v_not_found"),
        v_open_lbl: get("v_open_lbl"),
        v_opening: get("v_opening"),
        v_own: get("v_own"),
        v_own_toast: get("v_own_toast"),
        link_down_title: get("link_down_title"),
        link_down_body: get("link_down_body"),
        link_down_after: get("link_down_after"),
        link_down_login: get("link_down_login"),
        link_down_stay: get("link_down_stay"),
        last_download: get("last_download"),
        replicates_lbl: get("replicates_lbl"),
        deletions_lbl: get("deletions_lbl"),
        add_line: get("add_line"),
        add_replica: get("add_replica"),
        add_deletion: get("add_deletion"),
    }
}

/// Portuguese (language of authorship).
pub fn pt() -> Strings {
    load(Lang::Pt)
}

/// English.
pub fn en() -> Strings {
    load(Lang::En)
}

/// Español.
pub fn es() -> Strings {
    load(Lang::Es)
}

/// Français.
pub fn fr() -> Strings {
    load(Lang::Fr)
}

/// Return a `Strings` for the given language. The JSON is small and parsed
/// once per call; the GUI calls this once at startup.
pub fn strings_for(lang: Lang) -> Strings {
    load(lang)
}

impl Strings {
    /// Build a `Strings` bag for the given language, leaked into `'static`
    /// memory so callers can store `&'static Strings`.
    pub fn for_lang(lang: Lang) -> &'static Strings {
        Box::leak(Box::new(strings_for(lang)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every language must define exactly the same set of keys. A missing key
    /// in one locale is a bug, not a runtime surprise.
    #[test]
    fn locale_parity_all_languages_have_the_same_keys() {
        let pt: serde_json::Value = serde_json::from_str(Lang::Pt.json()).unwrap();
        let pt_keys: std::collections::BTreeSet<&str> =
            pt.as_object().unwrap().keys().map(|k| k.as_str()).collect();

        for lang in [Lang::En, Lang::Es, Lang::Fr] {
            let other: serde_json::Value = serde_json::from_str(lang.json()).unwrap();
            let other_keys: std::collections::BTreeSet<&str> = other
                .as_object()
                .unwrap()
                .keys()
                .map(|k| k.as_str())
                .collect();

            let missing: Vec<&str> = pt_keys.difference(&other_keys).copied().collect();
            let extra: Vec<&str> = other_keys.difference(&pt_keys).copied().collect();

            assert!(
                missing.is_empty() && extra.is_empty(),
                "locale {} differs from pt: missing={:?} extra={:?}",
                lang.code(),
                missing,
                extra
            );
        }
    }

    /// Each embedded JSON must deserialize into `Strings` without error.
    #[test]
    fn each_locale_deserializes_into_strings() {
        for lang in Lang::ALL {
            let _ = load(lang);
        }
    }

    /// `code()` must match the file name.
    #[test]
    fn lang_code_matches_filename() {
        assert_eq!(Lang::Pt.code(), "pt");
        assert_eq!(Lang::En.code(), "en");
        assert_eq!(Lang::Es.code(), "es");
        assert_eq!(Lang::Fr.code(), "fr");
    }
}
