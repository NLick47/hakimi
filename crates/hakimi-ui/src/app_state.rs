//! Shared UI state for the windui port.
//!
//! Every field the old `app.slint` exposed as an `in/out property` is now a
//! `Signal<T>`. A `Signal` is a `Copy` handle bound to the framework's slot
//! arena: writing it marks the UI dirty and every element bound to it redraws.
//! This replaces Slint's `AppWindow` properties plus the manual per-row
//! `VecModel` diffing, because windui's reactive lists reuse rows by key.

use std::collections::HashSet;
use std::sync::Arc;

use hakimi_core::runtime::HakimiRuntime;
use windui::prelude::*;

use crate::model::{NetEntry, SiteData};
use crate::{SettingsValues, SweepState};

/// A domain row in the site editor. Plain data: the editor view binds each
/// field to a `Signal<String>` so typing is reactive without a model rebuild.
#[derive(Clone, PartialEq)]
pub(crate) struct EditorRowState {
    pub index: usize,
    pub pattern: Signal<String>,
    pub preset: Signal<usize>,
    pub sni: Signal<String>,
    pub custom: Signal<String>,
}

impl EditorRowState {
    pub fn new(index: usize, pattern: &str, preset: i32, sni: &str, custom: &str) -> Self {
        Self {
            index,
            pattern: signal(pattern.to_string()),
            preset: signal(preset as usize),
            sni: signal(sni.to_string()),
            custom: signal(custom.to_string()),
        }
    }
}

thread_local! {
    static EDITOR_SCOPES: std::cell::RefCell<[std::mem::ManuallyDrop<windui::signal::SignalScope>; 3]> =
        std::cell::RefCell::new([
            std::mem::ManuallyDrop::new(windui::signal::SignalScope::new()),
            std::mem::ManuallyDrop::new(windui::signal::SignalScope::new()),
            std::mem::ManuallyDrop::new(windui::signal::SignalScope::new()),
        ]);
}

fn rotate(scopes: &mut [std::mem::ManuallyDrop<windui::signal::SignalScope>; 3]) {
    scopes[2].dispose();
    scopes[2] = std::mem::replace(
        &mut scopes[1],
        std::mem::ManuallyDrop::new(windui::signal::SignalScope::new()),
    );
    scopes[1] = std::mem::replace(
        &mut scopes[0],
        std::mem::ManuallyDrop::new(windui::signal::SignalScope::new()),
    );
}

pub(crate) fn with_editor_rows<R>(f: impl FnOnce() -> R) -> R {
    EDITOR_SCOPES.with(|cell| {
        let mut scopes = cell.borrow_mut();
        rotate(&mut scopes);
        scopes[0].collect(f)
    })
}

pub(crate) fn with_new_editor_row<R>(f: impl FnOnce() -> R) -> R {
    EDITOR_SCOPES.with(|cell| cell.borrow_mut()[0].collect(f))
}

/// Reclaim every generation. Used when the editor is gone for good (the window
/// was closed to the tray): nothing will read those slots again, so there is no
/// reason to keep the two grace generations alive.
pub(crate) fn release_editor_rows() {
    EDITOR_SCOPES.with(|cell| {
        let mut scopes = cell.borrow_mut();
        for scope in scopes.iter_mut() {
            scope.dispose();
        }
    })
}

/// Recompute the switcher's page-root key from the navigation signals.
/// `root` is a plain signal because a derived map only tracks one source, so
/// page / onboarding / window-open changes would otherwise miss the switcher.
/// Kept here so the tray can call it synchronously before showing the window.
pub(crate) fn sync_root(s: UiSignals) {
    let root = if !s.window_open.get() {
        0 // Closed
    } else if s.show_onboarding.get() {
        3 // Fix
    } else if s.page.get() == 1 {
        2 // Settings
    } else {
        1 // Home
    };
    if s.root.get() != root {
        tracing::info!(
            from = s.root.get(),
            to = root,
            window_open = s.window_open.get(),
            show_onboarding = s.show_onboarding.get(),
            page = s.page.get(),
            editor_open = s.editor_open.get(),
            "DBG sync_root: root changed"
        );
        s.root.set(root);
    }
}

/// Re-mount the page subtree before the tray reveals the window. The close
/// handler parks the switcher on the blank Closed page (and reclaims its
/// nodes); doing this in the tray callback — which windui runs before
/// `makeKeyAndOrderFront` — makes the first visible frame the real page rather
/// than one blank frame followed by the content.
pub(crate) fn prepare_show(s: UiSignals) {
    if !s.window_open.get() {
        s.window_open.set(true);
    }
    sync_root(s);
}

/// The full set of signals the view tree binds to. Created once on the UI
/// thread and captured by value (Signals are Copy) into widget callbacks.
#[derive(Clone, Copy)]
pub(crate) struct UiSignals {
    // -- navigation / pages --
    /// False while the window is closed to the tray. The view tree is rebuilt
    /// from this, so a closed window holds no page nodes.
    pub window_open: Signal<bool>,
    pub page: Signal<i32>,
    pub show_onboarding: Signal<bool>,
    /// Page-root key used by the view switcher. Written explicitly after every
    /// action: a derived map would only track one source signal's version, so
    /// page changes would not rebuild the switcher.
    pub root: Signal<i32>,
    pub fix_blocked: Signal<bool>,
    /// Fix-page heading copy; mixes fix_blocked with the env flags, so it is
    /// written in `sync_window` rather than derived.
    pub fix_title: Signal<String>,
    pub fix_subtitle: Signal<String>,
    pub settings_section: Signal<i32>,
    pub sites_expanded: Signal<bool>,
    // -- environment / fix --
    pub ca_installed: Signal<bool>,
    pub ca_error: Signal<String>,
    pub ca_busy: Signal<bool>,
    pub ca_action_error: Signal<String>,
    /// CA copy for the settings card and the fix row. Written imperatively by
    /// `sync_ca_status`: it mixes `ca_busy` with `ca_installed`/`ca_error`, and
    /// a windui `map` tracks only its one source signal.
    pub ca_status: Signal<String>,
    pub ca_status_sub: Signal<String>,
    pub ca_status_tone: Signal<i32>,
    pub ca_button: Signal<String>,
    pub proxy_ok: Signal<bool>,
    pub proxy_interrupted: Signal<bool>,
    /// Fix-page proxy row copy. The three states mix the takeover flag with
    /// the write result, and a windui map tracks one source, so `sync_window`
    /// writes them imperatively instead of the view deriving them.
    pub proxy_status: Signal<String>,
    pub proxy_status_sub: Signal<String>,
    pub proxy_status_tone: Signal<i32>,
    pub proxy_reapply: Signal<bool>,
    // -- status --
    pub running: Signal<bool>,
    pub status_subtitle: Signal<String>,
    /// Derived from env state: ca_ok && proxy_ok. Drives the warning banner
    /// (a single signal because windui only combines one signal at a time).
    pub env_ok: Signal<bool>,
    // -- sidebar counters (pre-formatted) --
    pub stat_sites: Signal<String>,
    pub stat_enabled: Signal<String>,
    pub stat_domains: Signal<String>,
    pub stat_slow: Signal<String>,
    pub stat_bad: Signal<String>,
    pub stat_doh: Signal<String>,
    pub stat_doh_tone: Signal<i32>,
    pub stat_mirror: Signal<String>,
    pub stat_mirror_tone: Signal<i32>,
    // -- sites / network rows --
    pub sites: Signal<Vec<SiteData>>,
    /// Hidden sites (always disabled); rendered only in the site management
    /// section, never on the home list.
    pub sites_hidden: Signal<Vec<SiteData>>,
    pub doh_rows: Signal<Vec<NetEntry>>,
    pub mirror_rows: Signal<Vec<NetEntry>>,
    pub doh_open: Signal<bool>,
    pub mirror_open: Signal<bool>,
    pub sites_summary: Signal<String>,
    /// True when every site is enabled; drives the 全选 ⇄ 取消全选 label.
    pub select_all: Signal<bool>,
    // -- settings text fields (draft values; committed on `on_commit`) --
    pub cfg_proxy_port: Signal<String>,
    pub cfg_doh_primary: Signal<String>,
    pub cfg_doh_fallback: Signal<String>,
    pub cfg_catalog_ip: Signal<String>,
    pub cfg_catalog_doh: Signal<String>,
    pub cfg_mirror_source: Signal<String>,
    pub cfg_download_mirror: Signal<bool>,
    pub cfg_download_enabled: Signal<bool>,
    pub cfg_download_segments: Signal<i32>,
    pub cfg_relay_enabled: Signal<bool>,
    pub cfg_relay_listen: Signal<String>,
    pub cfg_relay_target: Signal<String>,
    pub cfg_http1_hosts: Signal<String>,
    pub cfg_image_relay_enabled: Signal<bool>,
    pub cfg_image_relay_base: Signal<String>,
    pub cfg_image_relay_hosts: Signal<String>,
    pub cfg_image_relay_paths: Signal<String>,
    pub cfg_image_relay_ua: Signal<String>,
    pub cfg_image_relay_fallback: Signal<bool>,
    pub cfg_auto_start: Signal<bool>,
    pub cfg_start_hidden: Signal<bool>,
    pub cfg_auto_connect: Signal<bool>,
    pub auto_start_warning: Signal<String>,
    /// Save error for the auto-start switch, else the OS-disabled warning.
    /// Written in `apply_snapshot` so a later warning change still shows.
    pub startup_error: Signal<String>,
    pub cfg_error: Signal<String>,
    pub cfg_error_key: Signal<String>,
    pub cfg_data_dir: Signal<String>,
    pub cfg_version: Signal<String>,
    pub cfg_core_version: Signal<String>,
    // -- updates --
    pub update_checking: Signal<bool>,
    pub update_available: Signal<bool>,
    pub update_status: Signal<String>,
    /// 检查 / 检查中… / 下载 — mixes checking with available, so it is written
    /// in `s_update_signals` rather than derived.
    pub update_button: Signal<String>,
    /// Download URL for the available release, written on the UI thread only.
    pub release_url: Signal<String>,
    // -- site editor --
    pub editor_open: Signal<bool>,
    pub editor_id: Signal<String>,
    pub editor_name: Signal<String>,
    pub editor_homepage: Signal<String>,
    pub editor_default_preset: Signal<i32>,
    pub editor_default_custom: Signal<String>,
    pub editor_default_sni: Signal<String>,
    pub editor_verify: Signal<usize>,
    pub editor_off_armed: Signal<bool>,
    pub editor_is_new: Signal<bool>,
    pub editor_deletable: Signal<bool>,
    pub editor_error: Signal<String>,
    pub editor_rows: Signal<Vec<EditorRowState>>,
    /// Hidden sites shown in the management section, session-scoped.
    pub sites_hidden_shown: Signal<bool>,
    /// Number of hidden sites, written in `apply_snapshot` next to the lists.
    pub sites_hidden_count: Signal<i32>,
}

impl Default for UiSignals {
    fn default() -> Self {
        Self {
            window_open: signal(true),
            page: signal(0),
            show_onboarding: signal(false),
            root: signal(0),
            fix_blocked: signal(false),
            fix_title: signal(String::new()),
            fix_subtitle: signal(String::new()),
            settings_section: signal(0),
            sites_expanded: signal(false),
            ca_installed: signal(false),
            ca_error: signal(String::new()),
            ca_busy: signal(false),
            ca_action_error: signal(String::new()),
            proxy_ok: signal(true),
            proxy_interrupted: signal(false),
            proxy_status: signal(String::new()),
            proxy_status_sub: signal(String::new()),
            proxy_status_tone: signal(0),
            proxy_reapply: signal(false),
            ca_status: signal(String::new()),
            ca_status_sub: signal(String::new()),
            ca_status_tone: signal(0),
            ca_button: signal("安装".to_string()),
            running: signal(false),
            status_subtitle: signal(String::new()),
            env_ok: signal(true),
            stat_sites: signal(String::new()),
            stat_enabled: signal(String::new()),
            stat_domains: signal(String::new()),
            stat_slow: signal(String::new()),
            stat_bad: signal(String::new()),
            stat_doh: signal(String::new()),
            stat_doh_tone: signal(0),
            stat_mirror: signal(String::new()),
            stat_mirror_tone: signal(0),
            sites: signal(Vec::new()),
            sites_hidden: signal(Vec::new()),
            doh_rows: signal(Vec::new()),
            mirror_rows: signal(Vec::new()),
            doh_open: signal(false),
            mirror_open: signal(false),
            sites_summary: signal(String::new()),
            select_all: signal(false),
            cfg_proxy_port: signal(String::new()),
            cfg_doh_primary: signal(String::new()),
            cfg_doh_fallback: signal(String::new()),
            cfg_catalog_ip: signal(String::new()),
            cfg_catalog_doh: signal(String::new()),
            cfg_mirror_source: signal(String::new()),
            cfg_download_mirror: signal(false),
            cfg_download_enabled: signal(false),
            cfg_download_segments: signal(2),
            cfg_relay_enabled: signal(false),
            cfg_relay_listen: signal(String::new()),
            cfg_relay_target: signal(String::new()),
            cfg_http1_hosts: signal(String::new()),
            cfg_image_relay_enabled: signal(false),
            cfg_image_relay_base: signal(String::new()),
            cfg_image_relay_hosts: signal(String::new()),
            cfg_image_relay_paths: signal(String::new()),
            cfg_image_relay_ua: signal(String::new()),
            cfg_image_relay_fallback: signal(true),
            cfg_auto_start: signal(false),
            cfg_start_hidden: signal(false),
            cfg_auto_connect: signal(false),
            auto_start_warning: signal(String::new()),
            startup_error: signal(String::new()),
            cfg_error: signal(String::new()),
            cfg_error_key: signal(String::new()),
            cfg_data_dir: signal(String::new()),
            cfg_version: signal(String::new()),
            cfg_core_version: signal(String::new()),
            update_checking: signal(false),
            update_available: signal(false),
            update_status: signal("尚未检查".to_string()),
            update_button: signal("检查".to_string()),
            release_url: signal(String::new()),
            editor_open: signal(false),
            editor_id: signal(String::new()),
            editor_name: signal(String::new()),
            editor_homepage: signal(String::new()),
            editor_default_preset: signal(0),
            editor_default_custom: signal(String::new()),
            editor_default_sni: signal(String::new()),
            editor_verify: signal(0),
            editor_off_armed: signal(false),
            editor_is_new: signal(true),
            editor_deletable: signal(false),
            editor_error: signal(String::new()),
            editor_rows: signal(Vec::new()),
            sites_hidden_shown: signal(false),
            sites_hidden_count: signal(0),
        }
    }
}

/// The subset of process-wide inputs the `refresh` path needs. Keeping these
/// together avoids a dozen thread-locals and is shared with background threads.
pub(crate) struct AppContext {
    pub runtime: Arc<HakimiRuntime>,
    pub spawner: tokio::runtime::Handle,
    pub expanded: std::cell::RefCell<HashSet<String>>,
    pub sweep: Arc<SweepState>,
}

/// Actions sent from widget callbacks / background threads to the single UI
/// handler. Every state mutation and runtime call happens in one place, so the
/// event-loop reentrancy rules that Slint imposed are preserved.
pub(crate) enum Action {
    // navigation
    OpenFix,
    DismissInterrupt,
    FinishOnboarding,
    SetPage(i32),
    SetSection(i32),
    /// macOS reveal path; Windows resident mode opens the window directly
    /// from the tray callback instead.
    #[cfg_attr(windows, allow(dead_code))]
    ShowMain,
    Quit,
    ToggleAutoStart,
    ToggleStartHidden,
    // acceleration
    ToggleMaster,
    ToggleGroup(String, bool),
    SelectAll(bool),
    ToggleOpen(String),
    ProbeSelected,
    ReapplyProxy,
    // hiding
    HideSite(String),
    UnhideSite(String),
    ToggleShowHidden,
    // settings
    SaveString(String, String),
    SaveBool(String, bool),
    CaAction(i32),
    OpenDataDir,
    OpenSite(String),
    CheckUpdate,
    OpenUpdate,
    // site editor
    OpenEditor(String),
    CloseEditor,
    AddDomain,
    RemoveDomain(usize),
    SaveEditor,
    DeleteSite(String),
    ResetCatalogUrls,
    // background results
    ProbeFinished,
    CaOutcome { message: Option<String> },
    UpdateResult {
        status: String,
        available: bool,
        url: String,
    },
    EnvChanged(crate::ui_state::EnvState),
}

/// Snapshot pushed into the signals after a settings derivation, replacing the
/// old `apply_ui_update` diff. windui signals are cheap to write and reactive
/// lists reuse rows by key, so whole-signal assignment is both simpler and
/// keeps half-typed fields (their signals are only written when changed).
pub(crate) struct UiSnapshot {
    pub sites: Vec<SiteData>,
    pub sites_hidden: Vec<SiteData>,
    pub subtitle: String,
    pub sites_summary: String,
    pub running: bool,
    /// Bumped on every configuration mutation. The settings fields are only
    /// rewritten when this changes, so the one-second refresh cannot overwrite
    /// a field the user is editing.
    pub config_revision: u64,
    pub settings: SettingsValues,
    pub net_doh: String,
    pub net_doh_tone: i32,
    pub net_mirror: String,
    pub net_mirror_tone: i32,
    pub doh_rows: Vec<NetEntry>,
    pub mirror_rows: Vec<NetEntry>,
}
