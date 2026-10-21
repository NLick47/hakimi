use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hakimi_core::instance::{InstanceLock, InstanceLockError};
use hakimi_core::runtime::HakimiRuntime;
use hakimi_core::config::{AppConfig, GroupConfig};
use hakimi_core::strategy::Strategy;
use serde_json::Value;
use slint::{Color, Model, ModelRc, SharedString, VecModel};

slint::include_modules!();

mod ui_state;

pub(crate) fn data_dir() -> Option<PathBuf> {
    std::env::var_os("HAKIMI_DATA_DIR").map(PathBuf::from)
}

/// The window is a fixed light (Acrylic/Fluent) surface, so keep the macOS title bar
/// in the same appearance even when the system is in dark mode.
#[cfg(target_os = "macos")]
fn use_light_appearance() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSAppearance, NSAppearanceNameAqua, NSApplication};

    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    if let Some(appearance) = unsafe { NSAppearance::appearanceNamed(NSAppearanceNameAqua) } {
        app.setAppearance(Some(&appearance));
    }
}

#[cfg(not(target_os = "macos"))]
fn use_light_appearance() {}

/// Raise the app after a tray click. AppKit only activates the app when the
/// click lands on its own window or menu, so a background app stays behind
/// whatever else is on screen.
#[cfg(target_os = "macos")]
fn activate_app() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSApplication;

    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);
}

#[cfg(not(target_os = "macos"))]
fn activate_app() {}

/// Bring the main window back to the front. A minimized window is still
/// "shown" as far as Slint is concerned, so `show()` alone is a no-op: the
/// minimized state has to be dropped first.
fn reveal_window(app: &AppWindow) {
    let window = app.window();
    window.set_minimized(false);
    let _ = window.show();
    activate_app();
}

fn text(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(Value::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

use ui_state::{apply_settle, SettlePhase, BAD_COLOR, IDLE_COLOR, OK_COLOR, SLOW_COLOR};

fn color(hex: &str) -> Color {
    let value = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0x88_88_88);
    Color::from_argb_encoded(0xFF00_0000 | value)
}

// Plain-data snapshots cross the thread boundary; Slint types are built on the UI thread.

#[derive(Clone, PartialEq)]
struct DomainData {
    host: String,
    status: String,
    status_hex: &'static str,
    latency: String,
}

#[derive(Clone, PartialEq)]
struct SiteData {
    id: String,
    name: String,
    initial: String,
    icon_key: String,
    tile_hex: &'static str,
    summary: String,
    summary_hex: &'static str,
    enabled: bool,
    open: bool,
    first: bool,
    last: bool,
    url: String,
    strategy: i32,
    sni: String,
    custom: bool,
    domains: Vec<DomainData>,
}

fn build_site_entry(site: &SiteData) -> SiteEntry {
    let domains: Vec<DomainEntry> = site
        .domains
        .iter()
        .map(|row| DomainEntry {
            host: SharedString::from(row.host.clone()),
            status: SharedString::from(row.status.clone()),
            status_color: color(row.status_hex),
            latency: SharedString::from(row.latency.clone()),
        })
        .collect();
    SiteEntry {
        id: SharedString::from(site.id.clone()),
        name: SharedString::from(site.name.clone()),
        icon: ASSETS
            .with(|assets| assets.borrow().get(&site.icon_key).cloned())
            .unwrap_or_default(),
        initial: SharedString::from(site.initial.clone()),
        tile_color: color(site.tile_hex),
        summary: SharedString::from(site.summary.clone()),
        summary_color: color(site.summary_hex),
        enabled: site.enabled,
        open: site.open,
        first: site.first,
        last: site.last,
        url: SharedString::from(site.url.clone()),
        strategy: site.strategy,
        sni: SharedString::from(site.sni.clone()),
        custom: site.custom,
        domains: ModelRc::new(VecModel::from(domains)),
    }
}

/// Strategy index used by the UI: 0 auto, 1 direct, 2 ech, 3 fake SNI.
fn strategy_index(raw: &str) -> i32 {
    match raw {
        "direct" => 1,
        "ech" => 2,
        "sni" => 3,
        _ => 0,
    }
}

fn strategy_from_index(index: i32) -> Strategy {
    match index {
        1 => Strategy::Direct,
        2 => Strategy::Ech,
        3 => Strategy::FakeSni,
        _ => Strategy::Auto,
    }
}

/// Direct is not offered in the editor: `auto` already tries direct first, so a
/// group pinned to direct is shown as auto and widened on the next save.
fn editor_strategy_index(strategy: Strategy) -> i32 {
    match strategy {
        Strategy::Ech => 2,
        Strategy::FakeSni => 3,
        Strategy::Auto | Strategy::Direct => 0,
    }
}

/// Built-in group ids. Anything else was added by the user and may be removed
/// from the UI.
fn builtin_group_ids() -> std::collections::HashSet<String> {
    hakimi_core::config::default_groups()
        .into_iter()
        .map(|group| group.id)
        .collect()
}

/// Muted brand-ish tiles for groups without a real favicon.
const TILE_PALETTE: [&str; 8] = [
    "#5B7A9D", "#4E9E6F", "#C2913A", "#B0685E", "#7D6B9E", "#3F8C8C", "#96693F", "#8A6A8A",
];

fn tile_color(id: &str) -> &'static str {
    let hash: usize = id.bytes().map(|b| b as usize).sum();
    TILE_PALETTE[hash % TILE_PALETTE.len()]
}

/// Domain status as (word, color hex, latency text) from a diagnostics record.
fn domain_status(
    state: &str,
    latency_ms: Option<u64>,
    group_enabled: bool,
    master_running: bool,
) -> (String, &'static str, String) {
    if !group_enabled {
        return ("未选择".into(), IDLE_COLOR, "—".into());
    }
    if !master_running {
        return ("已暂停".into(), IDLE_COLOR, "—".into());
    }
    match state {
        "failed" => ("超时".into(), BAD_COLOR, "—".into()),
        "checking" => ("检测中".into(), IDLE_COLOR, "…".into()),
        "direct" => ("直连".into(), IDLE_COLOR, "—".into()),
        "normal" => match latency_ms {
            Some(ms) if ms > 150 => ("较慢".into(), SLOW_COLOR, format!("{ms} ms")),
            Some(ms) => ("正常".into(), OK_COLOR, format!("{ms} ms")),
            None => ("正常".into(), OK_COLOR, "—".into()),
        },
        _ => ("—".into(), IDLE_COLOR, "—".into()),
    }
}

pub(crate) fn build_snapshot(
    status: &Value,
    config: &Value,
    expanded: &HashSet<String>,
    master_running: bool,
    starting: bool,
    settle: Option<SettlePhase>,
) -> (Vec<SiteData>, String) {
    let mut diagnostics: HashMap<String, &Value> = HashMap::new();
    if let Some(domains) = status.get("domains").and_then(Value::as_array) {
        for record in domains {
            let host = text(record, "domain");
            if !host.is_empty() {
                diagnostics.insert(host, record);
            }
        }
    }

    let mut sites: Vec<SiteData> = Vec::new();
    let mut selected = 0usize;
    let builtins = builtin_group_ids();

    if let Some(groups) = config.get("groups").and_then(Value::as_array) {
        for group in groups {
            let id = text(group, "id");
            let name = text(group, "name");
            let enabled = group
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if enabled {
                selected += 1;
            }
            // A paused runtime shows the same "off" state as a disabled group.
            let active = enabled && master_running;

            let domains_config: Vec<String> = group
                .get("domains")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .filter(|host| !host.starts_with("*."))
                        .take(12)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();

            let mut rows: Vec<DomainData> = Vec::new();
            let mut slow = 0usize;
            let mut bad = 0usize;
            let mut checking = 0usize;
            let mut tested = 0usize;
            for host in &domains_config {
                let (word, word_hex, latency) = match diagnostics.get(host) {
                    Some(record) if enabled => {
                        tested += 1;
                        let state = text(record, "state");
                        let latency_ms = record.get("latencyMs").and_then(Value::as_u64);
                        if active {
                            match state.as_str() {
                                "failed" => bad += 1,
                                "checking" => checking += 1,
                                "normal" if latency_ms.map(|ms| ms > 150).unwrap_or(false) => slow += 1,
                                _ => {}
                            }
                        }
                        domain_status(&state, latency_ms, enabled, active)
                    }
                    _ => domain_status("", None, enabled, active),
                };
                rows.push(DomainData {
                    host: host.clone(),
                    status: word,
                    status_hex: word_hex,
                    latency,
                });
            }

            let count = domains_config.len();
            let (summary, summary_hex) = if !enabled {
                (format!("{count} 个域名 · 未选择"), IDLE_COLOR)
            } else if !master_running {
                (format!("{count} 个域名 · 已暂停"), IDLE_COLOR)
            } else if bad > 0 {
                let text = match (bad == count, slow) {
                    (true, _) => format!("{count} 个域名 · 全部超时"),
                    (false, 0) => format!("{count} 个域名 · {bad} 个超时"),
                    (false, n) => format!("{count} 个域名 · {bad} 个超时 · {n} 个较慢"),
                };
                (text, BAD_COLOR)
            } else if slow > 0 {
                let text = if slow == count {
                    format!("{count} 个域名 · 全部较慢")
                } else {
                    format!("{count} 个域名 · {slow} 个较慢")
                };
                (text, SLOW_COLOR)
            } else if checking > 0 {
                (format!("{count} 个域名 · 检测中"), IDLE_COLOR)
            } else if tested == 0 {
                (format!("{count} 个域名 · 未检测"), IDLE_COLOR)
            } else {
                (format!("{count} 个域名 · 全部正常"), OK_COLOR)
            };

            let primary = domains_config
                .first()
                .cloned()
                .unwrap_or_else(|| "example.com".into());

            let initial = name.chars().next().map(String::from).unwrap_or_default();
            let id_key = id.clone();
            let tile_hex = tile_color(&id);
            let icon_key = icon_key_for(&id);
            let strategy = strategy_index(&text(group, "strategy"));
            let sni = text(group, "sni");
            let custom = !builtins.contains(&id);

            sites.push(SiteData {
                icon_key,
                id,
                name,
                initial,
                tile_hex,
                summary,
                summary_hex,
                enabled,
                open: expanded.contains(&id_key),
                first: false,
                last: false,
                url: format!("https://{primary}/"),
                strategy,
                sni,
                custom,
                domains: rows,
            });
        }
    }

    // Mark the first and last rows so the group card can draw its separators.
    let total = sites.len();
    for (index, site) in sites.iter_mut().enumerate() {
        site.first = index == 0;
        site.last = index + 1 == total;
    }

    // Probing makes the raw summaries flap between 超时/较慢 while the engine
    // hunts for a working IP. With hysteresis a summary is only shown once it
    // has been stable for a moment; before that a fresh site holds on 测速中.
    if let Some(phase) = settle {
        apply_settle(&mut sites, phase);
    }
    let failed_sites = sites
        .iter()
        .filter(|site| site.enabled && site.summary.contains("超时"))
        .count();

    let subtitle = if selected == 0 {
        "未选择站点，勾选后即可加速".to_string()
    } else if failed_sites > 0 {
        if master_running {
            format!("正在加速 {selected} 个站点 · {failed_sites} 个异常")
        } else {
            format!("已选择 {selected} 个站点 · {failed_sites} 个异常")
        }
    } else if starting || master_running {
        format!("正在加速 {selected} 个站点")
    } else {
        format!("已选择 {selected} 个站点")
    };

    (sites, subtitle)
}

/// How long a summary must stay unchanged before it replaces the displayed one.
/// Lifecycle of a manual 测速 sweep. The flags are read by the refresh path
/// (`phase`) and written by the sweep task; owning them in one place keeps the
/// display policy inputs explicit instead of ambient.
#[derive(Default)]
struct SweepState {
    running: AtomicBool,
    commit_once: AtomicBool,
}

impl SweepState {
    fn phase(&self) -> SettlePhase {
        if self.running.load(Ordering::SeqCst) {
            SettlePhase::Sweeping
        } else if self.commit_once.swap(false, Ordering::SeqCst) {
            SettlePhase::Commit
        } else {
            SettlePhase::Tracking
        }
    }
}

thread_local! {
    // The tray lives for the whole process; dropping the handle would remove
    // the platform icon while the app keeps running.
    static TRAY: std::cell::RefCell<Option<TrayRoot>> = const { std::cell::RefCell::new(None) };
    static ASSETS: std::cell::RefCell<HashMap<String, slint::Image>> =
        std::cell::RefCell::new(HashMap::new());
    // Persistent models live on the UI thread so refreshes can be per-row:
    // unchanged rows keep their identity, so hover state, running animations
    // and the scroll position all survive, and no-op snapshots cost nothing.
    static SITES_MODEL: std::cell::RefCell<Option<Rc<VecModel<SiteEntry>>>> =
        const { std::cell::RefCell::new(None) };
    static PREV_STATE: std::cell::RefCell<Option<UiState>> =
        const { std::cell::RefCell::new(None) };
}

/// Bundled site logos, matched against a group id. Exact ids and `<key>-…`
/// slugs count; a bare `contains` would hand the E-Hentai logo to any domain
/// that happens to have "eh" in the middle of its slug.
const SITE_ICONS: [&str; 10] = [
    "pixiv", "hitomi", "poipiku", "booth", "steam", "github", "ao3", "eh", "hanime",
    "nhentai",
];

fn icon_key_for(id: &str) -> String {
    SITE_ICONS
        .iter()
        .copied()
        .find(|key| {
            let key = *key;
            id.eq_ignore_ascii_case(key)
                || id
                    .strip_prefix(key)
                    .is_some_and(|rest| rest.starts_with('-'))
        })
        .map(|key| key.to_string())
        .unwrap_or_default()
}

/// Sidebar counters for the desktop layout.
fn set_stats(app: &AppWindow, sites: &[SiteData]) {
    let domains: usize = sites.iter().map(|site| site.domains.len()).sum();
    let slow = sites
        .iter()
        .flat_map(|site| &site.domains)
        .filter(|domain| domain.status == "较慢")
        .count();
    let bad = sites
        .iter()
        .flat_map(|site| &site.domains)
        .filter(|domain| domain.status == "超时")
        .count();
    app.set_stat_sites(SharedString::from(format!("{}", sites.len())));
    app.set_stat_enabled(SharedString::from(format!(
        "{}",
        sites.iter().filter(|site| site.enabled).count()
    )));
    app.set_stat_domains(SharedString::from(format!("{domains}")));
    app.set_stat_slow(SharedString::from(format!("{slow}")));
    app.set_stat_bad(SharedString::from(format!("{bad}")));
}

/// The plain-data snapshot used to decide whether the UI needs touching at all.
#[derive(Clone, PartialEq)]
struct UiState {
    sites: Vec<SiteData>,
    subtitle: String,
    sites_summary: String,
    running: bool,
    ca: (bool, bool, bool),
    settings: SettingsValues,
}

/// Applies a snapshot to the window, updating only what actually changed.
/// The snapshot is consumed (moved) so an unchanged tick costs one comparison
/// and zero clones.
fn apply_ui_update(
    app: &AppWindow,
    sites: Vec<SiteData>,
    subtitle: String,
    running: bool,
    ca: (bool, bool, bool),
    settings: SettingsValues,
) {
    let sites_summary = format!(
        "{} 个 · 已启用 {}",
        sites.len(),
        sites.iter().filter(|site| site.enabled).count()
    );
    let unchanged = PREV_STATE.with(|slot| {
        slot.borrow().as_ref().is_some_and(|prev| {
            prev.sites == sites
                && prev.subtitle == subtitle
                && prev.sites_summary == sites_summary
                && prev.running == running
                && prev.ca == ca
                && prev.settings == settings
        })
    });
    if unchanged {
        return;
    }

    let prev = PREV_STATE.with(|slot| slot.borrow_mut().take());
    let prev_sites: Option<&[SiteData]> = prev.as_ref().map(|state| state.sites.as_slice());
    if prev_sites != Some(sites.as_slice()) {
        SITES_MODEL.with(|cell| {
            let mut slot = cell.borrow_mut();
            let model = slot.get_or_insert_with(|| {
                let model = Rc::new(VecModel::default());
                app.set_sites(ModelRc::new(model.clone()));
                model
            });
            match prev_sites {
                Some(old) if old.len() == sites.len() => {
                    for index in 0..sites.len() {
                        if old[index] != sites[index] {
                            model.set_row_data(index, build_site_entry(&sites[index]));
                        }
                    }
                }
                _ => {
                    let entries: Vec<SiteEntry> = sites.iter().map(build_site_entry).collect();
                    model.set_vec(entries);
                }
            }
        });
    }

    // Settings text fields only get written when the underlying value actually
    // changed, so a half-typed input is never clobbered by the refresh tick.
    if prev.as_ref().map(|state| &state.settings) != Some(&settings) {
        let old = prev.as_ref().map(|state| &state.settings);
        let changed = |pick: fn(&SettingsValues) -> &String| {
            old.is_none_or(|prev| pick(prev) != pick(&settings))
        };
        if changed(|s| &s.proxy_port) {
            app.set_cfg_proxy_port(SharedString::from(settings.proxy_port.clone()));
        }
        if changed(|s| &s.doh_primary) {
            app.set_cfg_doh_primary(SharedString::from(settings.doh_primary.clone()));
        }
        if changed(|s| &s.doh_fallback) {
            app.set_cfg_doh_fallback(SharedString::from(settings.doh_fallback.clone()));
        }
        if changed(|s| &s.catalog_ip) {
            app.set_cfg_catalog_ip(SharedString::from(settings.catalog_ip.clone()));
        }
        if changed(|s| &s.catalog_doh) {
            app.set_cfg_catalog_doh(SharedString::from(settings.catalog_doh.clone()));
        }
    }

    if prev.as_ref().map(|state| state.ca) != Some(ca) {
        app.set_ca_installed(ca.2);
    }

    if prev.as_ref().map(|state| state.running) != Some(running) {
        app.set_running(running);
        TRAY.with(|tray| {
            if let Some(tray) = tray.borrow().as_ref() {
                tray.set_running(running);
            }
        });
    }
    if prev.as_ref().map(|state| state.subtitle.as_str()) != Some(subtitle.as_str()) {
        app.set_status_subtitle(SharedString::from(subtitle.clone()));
    }
    if prev.as_ref().map(|state| state.sites_summary.as_str()) != Some(sites_summary.as_str()) {
        app.set_sites_summary(SharedString::from(sites_summary.clone()));
    }
    // Sidebar counters. Cheap to write, and they only move when a probe lands.
    set_stats(app, &sites);

    PREV_STATE.with(|slot| {
        *slot.borrow_mut() = Some(UiState {
            sites,
            subtitle,
            sites_summary,
            running,
            ca,
            settings,
        });
    });
}

pub(crate) fn load_assets() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");
    ASSETS.with(|assets| {
        let mut map = assets.borrow_mut();
        for key in SITE_ICONS {
            if let Ok(image) = slint::Image::load_from_path(&dir.join(format!("{key}.png"))) {
                map.insert(key.to_string(), image);
            }
        }
    });
}

/// Settings values pushed into the window. Text fields keep the raw string so
/// the user can type freely; validation happens on commit.
#[derive(Clone, PartialEq)]
pub(crate) struct SettingsValues {
    pub proxy_port: String,
    pub doh_primary: String,
    pub doh_fallback: String,
    pub catalog_ip: String,
    pub catalog_doh: String,
}

pub(crate) fn settings_values(config: &Value) -> SettingsValues {
    let field = |section: &str, key: &str| {
        config
            .get(section)
            .map(|value| text(value, key))
            .unwrap_or_default()
    };
    SettingsValues {
        proxy_port: field("proxy", "port"),
        doh_primary: field("doh", "primary"),
        doh_fallback: field("doh", "fallback"),
        catalog_ip: field("catalogs", "ip"),
        catalog_doh: field("catalogs", "doh"),
    }
}


// -- settings writes ------------------------------------------------------------

/// Commit one text setting. Returns `Some(error)` when the value was rejected;
/// the refresh tick then restores the field to the stored value.
fn apply_setting_string(runtime: &HakimiRuntime, key: &str, value: &str) -> Option<String> {
    let result = runtime.config().mutate(|config| {
        match key {
            "proxy.port" => {
                let port: u16 = value
                    .parse()
                    .ok()
                    .filter(|port| *port != 0)
                    .context("端口需为 1–65535 的数字")?;
                config.proxy.port = port;
            }
            "doh.primary" => config.doh.primary = value.to_string(),
            "doh.fallback" => config.doh.fallback = value.to_string(),
            "catalogs.ip" => config.catalogs.ip = value.to_string(),
            "catalogs.doh" => config.catalogs.doh = value.to_string(),
            other => bail!("未知设置项 {other}"),
        }
        Ok(())
    });
    match result {
        Ok(_) => {
            // Bind/port changes land on the next launch: the running proxy is
            // already bound and the PAC points at the live address.
            None
        }
        Err(error) => Some(format!("{error:#}")),
    }
}

/// How a CA action ended. The UI only shows these three states — no stderr,
/// no password diagnostics; the user just needs to know whether it worked.
#[derive(Clone, Copy, PartialEq, Debug)]
enum CaOutcome {
    Done,
    Cancelled,
    Failed,
}

impl CaOutcome {
    fn message(self) -> Option<&'static str> {
        match self {
            CaOutcome::Done => None,
            CaOutcome::Cancelled => Some("已取消，未做更改"),
            CaOutcome::Failed => Some("未成功，请重试"),
        }
    }
}

/// Judge an install/uninstall/repair by what the trust store says afterwards,
/// not by the exit status: `security` can report success after a dismissed
/// dialog, and a leftover trusted copy would still verify.
fn ca_outcome(result: Result<bool>, want_installed: bool) -> CaOutcome {
    match result {
        Ok(installed) if installed == want_installed => CaOutcome::Done,
        Ok(_) => CaOutcome::Failed,
        Err(error) => {
            let text = format!("{error:#}").to_ascii_lowercase();
            if text.contains("cancel") {
                CaOutcome::Cancelled
            } else {
                CaOutcome::Failed
            }
        }
    }
}

// -- site editor ----------------------------------------------------------------

/// Site editor input, kept independent of Slint so it can be unit tested.
struct SiteDraft {
    id: String,
    is_new: bool,
    name: String,
    domains: String,
    strategy: Strategy,
    sni: String,
}

/// Build the group a draft describes. Existing groups keep `echShared` and
/// `experimental` so editing a site never silently drops them.
fn build_group(config: &AppConfig, draft: &SiteDraft) -> Result<GroupConfig> {
    let mut domains: Vec<String> = Vec::new();
    for part in draft
        .domains
        .split(|c: char| c.is_whitespace() || c == ',' || c == '，')
    {
        // Hostnames are case-insensitive; storing them as typed used to make
        // `Example.COM` a different site from `example.com`.
        let raw = part.trim();
        if raw.is_empty() {
            continue;
        }
        // A pasted URL carries the host in its authority; strip the scheme,
        // credentials, port and path before validating it as a domain.
        let host = match hakimi_core::domain::host_from_url(raw) {
            Some(host) => host.to_string(),
            None if raw.contains("://") => bail!("网址 {raw} 无效，请填写域名或 http(s) 网址"),
            None => raw.to_string(),
        }
        .to_ascii_lowercase();
        hakimi_core::domain::DomainPattern::parse(&host)
            .with_context(|| format!("域名 {host} 无效"))?;
        if !domains.iter().any(|existing| existing == &host) {
            domains.push(host);
        }
    }
    if domains.is_empty() {
        bail!("请至少填写一个域名");
    }
    if !domains.iter().any(|host| !host.starts_with("*.")) {
        bail!("至少需要一个精确域名（不能只有 *. 通配）");
    }
    for other in &config.groups {
        if !draft.is_new && other.id == draft.id {
            continue;
        }
        if let Some(conflict) = domains.iter().find(|domain| {
            other
                .domains
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(domain))
        }) {
            bail!("域名 {conflict} 已属于站点「{}」", other.name);
        }
    }
    let name = if draft.name.trim().is_empty() {
        domains[0].clone()
    } else {
        draft.name.trim().to_string()
    };
    let sni = draft.sni.trim().to_ascii_lowercase();
    if !sni.is_empty() {
        hakimi_core::domain::normalize_hostname(&sni).context("SNI 主机格式不正确")?;
    }

    let existing = if draft.is_new {
        None
    } else {
        config.group(&draft.id).cloned()
    };
    let mut group = existing.unwrap_or_default();
    group.id = if draft.is_new {
        unique_group_id(config, &domains[0])
    } else {
        draft.id.clone()
    };
    group.name = name;
    group.domains = domains;
    group.strategy = draft.strategy;
    // An empty preset is meaningful for fake SNI: it means "send no SNI".
    group.sni = if draft.strategy == Strategy::FakeSni || !sni.is_empty() {
        Some(sni)
    } else {
        None
    };
    if draft.is_new {
        group.enabled = true;
        group.experimental = false;
        group.ech_shared = false;
    }
    Ok(group)
}

/// Read the editor fields and persist the group.
fn save_site(runtime: &HakimiRuntime, app: &AppWindow) -> Result<()> {
    let draft = SiteDraft {
        id: app.get_editor_id().to_string(),
        is_new: app.get_editor_is_new(),
        name: app.get_editor_name().to_string(),
        domains: app.get_editor_domains().to_string(),
        strategy: strategy_from_index(app.get_editor_strategy()),
        sni: app.get_editor_sni().to_string(),
    };
    let config = runtime.config().snapshot();
    let group = build_group(&config, &draft)?;
    tracing::info!(
        id = %group.id,
        name = %group.name,
        domains = group.domains.len(),
        strategy = ?group.strategy,
        sni = group.sni.as_deref().unwrap_or(""),
        is_new = draft.is_new,
        "site saved"
    );
    runtime.upsert_group(group)?;
    Ok(())
}

/// Derive a config-safe group id from the first domain, e.g.
/// `www.example.com` -> `www-example-com`.
fn unique_group_id(config: &hakimi_core::config::AppConfig, domain: &str) -> String {
    let base: String = domain
        .trim_start_matches("*.")
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let base = base.trim_matches('-').to_string();
    let base = if base.is_empty() {
        "site".to_string()
    } else {
        base.chars().take(48).collect()
    };
    if config.group(&base).is_none() {
        return base;
    }
    for suffix in 2..1000 {
        let candidate = format!("{base}-{suffix}");
        if config.group(&candidate).is_none() {
            return candidate;
        }
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    format!("{base}-{stamp}")
}

// -- offscreen rendering (development aid) ------------------------------------

fn sample_status() -> Value {
    serde_json::json!({
        "ca": { "present": true, "supported": true, "installed": false },
        "domains": [
            { "domain": "www.pixiv.net", "state": "normal", "latencyMs": 23 },
            { "domain": "i.pximg.net", "state": "normal", "latencyMs": 31 },
            { "domain": "s.pximg.net", "state": "normal", "latencyMs": 44 },
            { "domain": "booth.pximg.net", "state": "normal", "latencyMs": 38 },
            { "domain": "novel.pixiv.net", "state": "normal", "latencyMs": 52 },
            { "domain": "e-hentai.org", "state": "normal", "latencyMs": 48 },
            { "domain": "forums.e-hentai.org", "state": "normal", "latencyMs": 212 },
            { "domain": "exhentai.org", "state": "normal", "latencyMs": 61 },
            { "domain": "hitomi.la", "state": "normal", "latencyMs": 95 },
            { "domain": "ltn.gold-usergeneratedcontent.net", "state": "failed" },
            { "domain": "github.com", "state": "normal", "latencyMs": 120 },
            { "domain": "raw.githubusercontent.com", "state": "normal", "latencyMs": 145 },
            { "domain": "api.github.com", "state": "normal", "latencyMs": 132 },
            { "domain": "ao3.org", "state": "normal", "latencyMs": 180 },
            { "domain": "archiveofourown.org", "state": "normal", "latencyMs": 175 },
            { "domain": "steamcommunity.com", "state": "normal", "latencyMs": 88 },
            { "domain": "store.steampowered.com", "state": "normal", "latencyMs": 96 },
            { "domain": "poipiku.me", "state": "normal", "latencyMs": 71 },
            { "domain": "poipiku.art", "state": "normal", "latencyMs": 66 }
        ]
    })
}

fn sample_config() -> Value {
    serde_json::json!({
        "proxy": { "port": 8443 },
        "doh": {
            "primary": "https://doh.cleanbrowsing.org/doh/security-filter/",
            "fallback": "https://doh.applied-privacy.net/query"
        },
        "catalogs": {
            "ip": "https://gitee.com/hakimi/catalogs/ip.json",
            "doh": "https://gitee.com/hakimi/catalogs/doh.json"
        },
        "groups": [
            { "id": "pixiv", "name": "Pixiv", "enabled": true, "strategy": "ech",
              "domains": ["www.pixiv.net", "i.pximg.net", "s.pximg.net", "booth.pximg.net", "novel.pixiv.net"] },
            { "id": "eh", "name": "E-Hentai", "enabled": true,
              "domains": ["e-hentai.org", "forums.e-hentai.org", "exhentai.org"] },
            { "id": "hitomi", "name": "Hitomi", "enabled": true,
              "domains": ["hitomi.la", "ltn.gold-usergeneratedcontent.net"] },
            { "id": "github", "name": "GitHub", "enabled": true, "strategy": "sni", "sni": "www.baidu.com",
              "domains": ["github.com", "raw.githubusercontent.com", "api.github.com"] },
            { "id": "ao3", "name": "AO3", "enabled": true,
              "domains": ["ao3.org", "archiveofourown.org"] },
            { "id": "steam", "name": "Steam", "enabled": true,
              "domains": ["steamcommunity.com", "store.steampowered.com"] },
            { "id": "poipiku", "name": "Poipiku", "enabled": true, "strategy": "direct",
              "domains": ["poipiku.me", "poipiku.art"] },
            { "id": "hitomi", "name": "Hitomi", "enabled": true,
              "domains": ["hitomi.la", "ltn.gold-usergeneratedcontent.net"] },
            { "id": "nhentai", "name": "nhentai", "enabled": true,
              "domains": ["nhentai.net", "i.nhentai.net"] },
            { "id": "hanime", "name": "Hanime", "enabled": true,
              "domains": ["hanime.tv", "www.hanime.tv"] }
        ]
    })
}

/// Renders the window into a raw RGBA file so the layout can be reviewed
/// without a display. Usage: `hakimi-ui --shot <prefix> [--page N] [--running]`.
fn shot(prefix: &str, page: i32, running: bool) -> Result<()> {
    use_light_appearance();
    let app = AppWindow::new()?;
    load_assets();

    let status = sample_status();
    let config = sample_config();
    let mut expanded = HashSet::new();
    if page == 0 {
        expanded.insert("pixiv".to_string());
    }

    let (sites, subtitle) = build_snapshot(&status, &config, &expanded, running, false, None);
    let entries: Vec<SiteEntry> = sites.iter().map(build_site_entry).collect();
    let ca = &status["ca"];
    let settings = settings_values(&config);

    app.set_sites(ModelRc::new(VecModel::from(entries)));
    app.set_cfg_proxy_port(SharedString::from(settings.proxy_port.clone()));
    app.set_cfg_doh_primary(SharedString::from(settings.doh_primary.clone()));
    app.set_cfg_doh_fallback(SharedString::from(settings.doh_fallback.clone()));
    app.set_cfg_catalog_ip(SharedString::from(settings.catalog_ip.clone()));
    app.set_cfg_catalog_doh(SharedString::from(settings.catalog_doh.clone()));
    app.set_cfg_data_dir(SharedString::from("~/Library/Application Support/hakimi"));
    app.set_cfg_version(SharedString::from(env!("CARGO_PKG_VERSION")));
    app.set_status_subtitle(SharedString::from(subtitle));
    app.set_running(running);
    app.set_page(page);
    // Offscreen states for reviewing the environment-check UI.
    let broken = std::env::var("HAKIMI_UI_BROKEN").is_ok();
    let fix_page = std::env::var("HAKIMI_UI_FIXPAGE").is_ok();
    app.set_ca_installed(!broken && !fix_page && ca.get("installed").and_then(Value::as_bool).unwrap_or(false));
    if broken || fix_page {
        app.set_ca_error(SharedString::from("已导入，但尚未受信任"));
    }
    app.set_show_onboarding(fix_page || std::env::var("HAKIMI_UI_FIXMANUAL").is_ok());
    app.set_fix_blocked(fix_page);
    if let Ok(message) = std::env::var("HAKIMI_UI_CA_ERROR") {
        app.set_ca_action_error(SharedString::from(message));
    }
    if std::env::var("HAKIMI_UI_CA_BUSY").is_ok() {
        app.set_ca_busy(true);
    }
    app.set_sites_summary(SharedString::from(format!(
        "{} 个 · 已启用 {}",
        sites.len(),
        sites.iter().filter(|site| site.enabled).count()
    )));
    set_stats(&app, &sites);
    if std::env::var("HAKIMI_UI_SITES").is_ok() {
        app.set_sites_expanded(true);
    }
    match std::env::var("HAKIMI_UI_EDITOR").as_deref() {
        Ok("new") => {
            app.set_editor_is_new(true);
            app.set_editor_strategy(3);
            app.set_editor_sni(SharedString::from(""));
            app.set_editor_open(true);
        }
        Ok(_) => {
            app.set_editor_is_new(false);
            app.set_editor_id(SharedString::from("pixiv"));
            app.set_editor_name(SharedString::from("Pixiv"));
            app.set_editor_domains(SharedString::from(
                "pixiv.net\nwww.pixiv.net\ni.pximg.net\ns.pximg.net",
            ));
            app.set_editor_strategy(3);
            app.set_editor_sni(SharedString::from(""));
            app.set_editor_deletable(false);
            app.set_editor_open(true);
        }
        Err(_) => {}
    }
    app.show()?;

    // let the first render pass settle
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(60));
    }

    let buffer = app.window().take_snapshot()?;
    let mut bytes = Vec::with_capacity(buffer.as_slice().len() * 4);
    for pixel in buffer.as_slice() {
        bytes.extend_from_slice(&[pixel.r, pixel.g, pixel.b, pixel.a]);
    }
    std::fs::write(format!("{prefix}.rgba"), bytes)?;
    println!(
        "wrote {prefix}.rgba ({}x{})",
        buffer.width(),
        buffer.height()
    );
    Ok(())
}

thread_local! {
    static CONFIG_CACHE: std::cell::RefCell<Option<(u64, Value)>> =
        const { std::cell::RefCell::new(None) };
    // The acceleration state machine lives on the UI thread.
    static MODEL: std::cell::RefCell<ui_state::AppModel> =
        std::cell::RefCell::new(ui_state::AppModel::default());
}

/// Re-reads the world and applies it to the window. Runs on the UI thread;
/// the diff in apply_ui_update makes a no-op refresh nearly free.
fn refresh(
    app: &AppWindow,
    runtime: &Arc<HakimiRuntime>,
    expanded: &HashSet<String>,
    sweep: &SweepState,
) {
    let status = runtime.status_json();
    let revision = runtime.config_revision();
    let config = cached_config(revision, || runtime.config_json());
    let running = runtime.is_started() && !runtime.status().paused();
    // Running intent without a started runtime means "still starting": the
    // summaries must not claim 已暂停 while the proxy is coming up.
    let starting = MODEL.with(|m| m.borrow().accel()) == ui_state::AccelState::Running && !running;
    let phase = if starting {
        SettlePhase::Starting
    } else {
        sweep.phase()
    };
    let (sites, subtitle) =
        build_snapshot(&status, &config, expanded, running, starting, Some(phase));
    let ca = &status["ca"];
    let ca_state = (
        ca.get("present").and_then(Value::as_bool).unwrap_or(false),
        ca.get("supported").and_then(Value::as_bool).unwrap_or(false),
        ca.get("installed").and_then(Value::as_bool).unwrap_or(false),
    );
    let settings = settings_values(&config);
    apply_ui_update(app, sites, subtitle, running, ca_state, settings);
    // Environment state comes from the probe thread; the window already
    // mirrors the model, so there is nothing else to do here.
}

fn cached_config(revision: u64, fetch: impl FnOnce() -> Value) -> Value {
    CONFIG_CACHE.with(|cell| {
        let mut slot = cell.borrow_mut();
        match slot.as_ref() {
            Some((cached_revision, config)) if *cached_revision == revision => config.clone(),
            _ => {
                let config = fetch();
                *slot = Some((revision, config.clone()));
                config
            }
        }
    })
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(index) = args.iter().position(|arg| arg == "--shot") {
        let prefix = args
            .get(index + 1)
            .cloned()
            .unwrap_or_else(|| "/tmp/hakimi-ui".into());
        let page = args
            .iter()
            .position(|arg| arg == "--page")
            .and_then(|i| args.get(i + 1))
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(0);
        let running = args.iter().any(|arg| arg == "--running");
        return shot(&prefix, page, running);
    }

    // Single instance: a second long-running app would fight over the proxy port.
    let instance_dir = match data_dir() {
        Some(dir) => dir,
        None => hakimi_core::paths::Paths::default_location()?.root().to_path_buf(),
    };
    let _instance_lock = match InstanceLock::acquire(&instance_dir) {
        Ok(lock) => lock,
        Err(InstanceLockError::AlreadyRunning { .. }) => {
            // Visible feedback instead of a silently dead second launch.
            let notice = AlreadyRunningWindow::new()?;
            notice.show()?;
            let timer = slint::Timer::default();
            timer.start(
                slint::TimerMode::SingleShot,
                Duration::from_millis(2500),
                || {
                    let _ = slint::quit_event_loop();
                },
            );
            notice.run()?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    use_light_appearance();

    // The runtime lives on the UI thread: every interaction is a direct
    // synchronous call, so a click applies within the same frame. Only the
    // genuinely async parts (serving the proxy, waiting for shutdown) run on a
    // dedicated tokio runtime in the background.
    let runtime = HakimiRuntime::new(data_dir())?;
    let sweep = std::sync::Arc::new(SweepState::default());

    // The state machine decides the startup posture. This one synchronous
    // probe is the only environment check on the UI thread; after this, the
    // probe thread streams results in. The proxy effects map onto the start
    // mode because they need the PAC URL, which only exists post-bind.
    let startup_effects = MODEL.with(|m| m.borrow_mut().startup(ui_state::probe_env(&runtime)));
    let start_mode = ui_state::execute_startup(&startup_effects, &runtime);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let spawner = rt.handle().clone();
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let background = {
        let runtime = runtime.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || {
            rt.block_on(async move {
                let start_result = match start_mode {
                    ui_state::StartMode::Takeover => runtime.start().await,
                    ui_state::StartMode::Deferred => runtime.start_deferring_proxy().await,
                };
                if let Err(error) = start_result {
                    eprintln!("hakimi-ui failed to start the proxy: {error:#}");
                }
                shutdown.notified().await;
                let _ = runtime.stop().await;
            });
        })
    };

    let app = AppWindow::new()?;
    load_assets();
    app.set_cfg_data_dir(SharedString::from(runtime.paths().root().display().to_string()));
    app.set_cfg_version(SharedString::from(env!("CARGO_PKG_VERSION")));

    // System tray: keeps the app alive with the window closed, and mirrors the
    // window actions. The tray must be created on the main thread.
    let tray = TrayRoot::new()?;
    tray.on_show_main({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                reveal_window(&app);
            }
        }
    });
    tray.on_toggle_master({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.invoke_toggle_master();
            }
        }
    });
    tray.on_probe_all({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.invoke_probe_all();
            }
        }
    });
    tray.on_quit(|| {
        // Quitting goes through the normal path below: run() returns, the
        // background thread stops the proxy and restores the system proxy.
        let _ = slint::quit_event_loop();
    });
    TRAY.with(|slot| *slot.borrow_mut() = Some(tray));

    let expanded: Rc<std::cell::RefCell<HashSet<String>>> =
        Rc::new(std::cell::RefCell::new(HashSet::new()));
    if let Ok(id) = std::env::var("HAKIMI_UI_EXPAND") {
        expanded.borrow_mut().insert(id);
    }

    // -- callbacks: direct calls, applied in the same frame --
    {
        let weak = app.as_weak();
        app.on_open_fix(move || {
            // Remember the manual visit in the model: the periodic environment
            // sync derives the page from state and would otherwise slam it shut
            // on the very next tick.
            MODEL.with(|m| m.borrow_mut().open_fix());
            if let Some(app) = weak.upgrade() {
                MODEL.with(|m| ui_state::sync_window(&m.borrow(), &app));
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_toggle_master(move || {
            // Use the last known environment (fresh within a second of the
            // probe stream) so the click never waits on a subprocess.
            let effects = MODEL.with(|m| {
                let env = m.borrow().env().clone();
                m.borrow_mut().toggle(env)
            });
            ui_state::execute(&effects, &runtime);
            if let Some(app) = weak.upgrade() {
                MODEL.with(|m| ui_state::sync_window(&m.borrow(), &app));
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_toggle_group(move |id, enabled| {
            let _ = runtime.set_group_enabled(id.as_str(), enabled);
            if let Some(app) = weak.upgrade() {
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_select_all(move |enabled| {
            let _ = runtime.config().mutate(|config| {
                for group in &mut config.groups {
                    group.enabled = enabled;
                }
                Ok(())
            });
            if let Some(app) = weak.upgrade() {
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_toggle_open(move |id| {
            let mut set = expanded.borrow_mut();
            let id = id.to_string();
            if !set.remove(&id) {
                set.insert(id);
            }
            drop(set);
            if let Some(app) = weak.upgrade() {
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
        });
    }
    {
        let runtime = runtime.clone();
        let spawner = spawner.clone();
        let sweep = sweep.clone();
        app.on_probe_all(move || {
            // One atomic sweep on the runtime: the UI only flips the phase and
            // awaits completion, no per-domain bookkeeping here.
            sweep.running.store(true, Ordering::SeqCst);
            let runtime = runtime.clone();
            let sweep = sweep.clone();
            spawner.spawn(async move {
                runtime.probe_sweep().await;
                sweep.running.store(false, Ordering::SeqCst);
                sweep.commit_once.store(true, Ordering::SeqCst);
            });
        });
    }
    {
        let runtime = runtime.clone();
        let weak = app.as_weak();
        app.on_finish_onboarding(move || {
            let effects = MODEL.with(|m| m.borrow_mut().dismiss_fix());
            ui_state::execute(&effects, &runtime);
            if let Some(app) = weak.upgrade() {
                MODEL.with(|m| ui_state::sync_window(&m.borrow(), &app));
            }
        });
    }
    {
        let runtime = runtime.clone();
        app.on_reapply_proxy(move || {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                if let Err(error) = runtime.apply_system_proxy() {
                    eprintln!("hakimi-ui: manual system proxy re-apply failed: {error:#}");
                }
            });
        });
    }
    app.on_open_site(|url| {
        std::thread::spawn(move || {
            let _ = open::that(url.to_string());
        });
    });
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_settings_action(move |kind| {
            let Some(app) = weak.upgrade() else { return };
            // Installing may raise a system password prompt; keep that off the
            // UI thread. The outcome is posted back as one of three short
            // states, so a dismissed dialog can never read as success.
            app.set_ca_busy(true);
            app.set_ca_action_error(SharedString::new());
            app.set_ob_installing(true);
            tracing::info!(kind, "ca action requested");

            let runtime = runtime.clone();
            // The expanded-row set is an Rc owned by the UI thread; carry a
            // plain copy across so the refresh keeps the same rows open.
            let open_ids: Vec<String> = expanded.borrow().iter().cloned().collect();
            let weak = app.as_weak();
            let sweep = sweep.clone();
            std::thread::spawn(move || {
                let started = std::time::Instant::now();
                let outcome = match kind {
                    1 => ca_outcome(runtime.ca_install().map(|status| status.installed), true),
                    2 => ca_outcome(runtime.ca_uninstall().map(|status| status.installed), false),
                    3 => ca_outcome(runtime.ca_repair().map(|status| status.installed), true),
                    _ => CaOutcome::Done,
                };
                tracing::info!(
                    kind,
                    outcome = ?outcome,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "ca action finished"
                );
                let message = outcome.message();
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(app) = weak.upgrade() else { return };
                    app.set_ca_busy(false);
                    app.set_ob_installing(false);
                    if let Some(message) = message {
                        app.set_ca_action_error(SharedString::from(message));
                    }
                    // Re-read the trust state now instead of waiting a tick.
                    let open: HashSet<String> = open_ids.into_iter().collect();
                    refresh(&app, &runtime, &open, &sweep);
                });
            });
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_save_string(move |key, value| {
            let key = key.to_string();
            let value = value.trim().to_string();
            let error = apply_setting_string(&runtime, &key, &value);
            if let Some(app) = weak.upgrade() {
                let failed = error.is_some();
                app.set_cfg_error(SharedString::from(error.unwrap_or_default()));
                // Lets the offending field draw a red border instead of only
                // showing a message at the bottom of the page.
                app.set_cfg_error_key(SharedString::from(if failed {
                    key.clone()
                } else {
                    String::new()
                }));
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
        });
    }
    {
        let runtime = runtime.clone();
        app.on_open_data_dir(move || {
            let dir = runtime.paths().root().to_path_buf();
            std::thread::spawn(move || {
                let _ = open::that(dir);
            });
        });
    }
    {
        let runtime = runtime.clone();
        let weak = app.as_weak();
        app.on_open_editor(move |id| {
            let Some(app) = weak.upgrade() else { return };
            let config = runtime.config().snapshot();
            let builtins = builtin_group_ids();
            match config.group(id.as_str()) {
                Some(group) => {
                    app.set_editor_is_new(false);
                    app.set_editor_id(SharedString::from(group.id.clone()));
                    app.set_editor_name(SharedString::from(group.name.clone()));
                    app.set_editor_domains(SharedString::from(group.domains.join("\n")));
                    app.set_editor_strategy(editor_strategy_index(group.strategy));
                    app.set_editor_sni(SharedString::from(group.sni.clone().unwrap_or_default()));
                    app.set_editor_deletable(!builtins.contains(&group.id));
                }
                None => {
                    app.set_editor_is_new(true);
                    app.set_editor_id(SharedString::new());
                    app.set_editor_name(SharedString::new());
                    app.set_editor_domains(SharedString::new());
                    app.set_editor_strategy(0);
                    app.set_editor_sni(SharedString::new());
                    app.set_editor_deletable(false);
                }
            }
            app.set_editor_error(SharedString::new());
            app.set_editor_open(true);
        });
    }
    {
        let weak = app.as_weak();
        app.on_close_editor(move || {
            if let Some(app) = weak.upgrade() {
                app.set_editor_open(false);
                app.set_editor_error(SharedString::new());
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let sweep = sweep.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_save_editor(move || {
            let Some(app) = weak.upgrade() else { return };
            let result = save_site(&runtime, &app);
            match result {
                Ok(()) => {
                    app.set_editor_open(false);
                    app.set_editor_error(SharedString::new());
                    refresh(&app, &runtime, &expanded.borrow(), &sweep);
                }
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), "site save rejected");
                    app.set_editor_error(SharedString::from(format!("{error:#}")));
                }
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_delete_site(move |id| {
            let Some(app) = weak.upgrade() else { return };
            match runtime.remove_group(id.as_str()) {
                Ok(_) => {
                    tracing::info!(id = %id, "site removed");
                    app.set_editor_open(false);
                    app.set_editor_error(SharedString::new());
                    refresh(&app, &runtime, &expanded.borrow(), &sweep);
                }
                Err(error) => app.set_editor_error(SharedString::from(format!("{error:#}"))),
            }
        });
    }

    // The environment probe is an input stream: it runs off the UI thread (it
    // spawns `security` and `networksetup`) and posts results through the
    // event loop, where the state machine transitions and the window mirrors.
    let probe_stop = Arc::new(AtomicBool::new(false));
    {
        let probe_stop = probe_stop.clone();
        let probe_runtime = runtime.clone();
        let weak = app.as_weak();
        std::thread::spawn(move || {
            while !probe_stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1000));
                if probe_stop.load(Ordering::SeqCst) {
                    break;
                }
                let env = ui_state::probe_env(&probe_runtime);
                let runtime = probe_runtime.clone();
                let weak = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(app) = weak.upgrade() else {
                        return;
                    };
                    MODEL.with(|m| {
                        let mut model = m.borrow_mut();
                        let effects = model.env_changed(env);
                        ui_state::execute(&effects, &runtime);
                        ui_state::sync_window(&model, &app);
                    });
                });
            }
        });
    }

    // Periodic refresh picks up background activity (probe results, EWMA latency).
    let timer = slint::Timer::default();
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(1000),
            move || {
                if let Some(app) = weak.upgrade() {
                    refresh(&app, &runtime, &expanded.borrow(), &sweep);
                }
            },
        );
    }

    refresh(&app, &runtime, &expanded.borrow(), &sweep);
    if std::env::var("HAKIMI_UI_PAGE").as_deref() == Ok("1") {
        app.set_page(1);
    }
    app.run()?;

    // Quitting stops the proxy and restores the system proxy state.
    drop(timer);
    probe_stop.store(true, Ordering::SeqCst);
    shutdown.notify_one();
    let _ = background.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(domains: &str, strategy: Strategy, sni: &str) -> SiteDraft {
        SiteDraft {
            id: String::new(),
            is_new: true,
            name: String::new(),
            domains: domains.into(),
            strategy,
            sni: sni.into(),
        }
    }

    #[test]
    fn new_site_gets_a_config_safe_id() {
        let config = AppConfig::default();
        let group = build_group(&config, &draft("www.example.com", Strategy::Auto, "")).unwrap();
        assert_eq!(group.id, "www-example-com");
        assert_eq!(group.name, "www.example.com");
        assert!(group.enabled);
        assert_eq!(group.sni, None);
    }

    #[test]
    fn empty_sni_is_preserved_for_fake_sni() {
        let config = AppConfig::default();
        let group = build_group(&config, &draft("example.com", Strategy::FakeSni, " ")).unwrap();
        assert_eq!(group.sni.as_deref(), Some(""));
    }

    #[test]
    fn sni_is_dropped_for_other_strategies() {
        let config = AppConfig::default();
        let group = build_group(&config, &draft("example.com", Strategy::Ech, "")).unwrap();
        assert_eq!(group.sni, None);
    }

    #[test]
    fn rejects_domains_without_an_exact_entry() {
        let config = AppConfig::default();
        assert!(build_group(&config, &draft("*.example.com", Strategy::Auto, "")).is_err());
    }

    #[test]
    fn rejects_domains_owned_by_another_group() {
        let config = AppConfig::default();
        let error = build_group(&config, &draft("github.com", Strategy::Auto, "")).unwrap_err();
        assert!(format!("{error:#}").contains("GitHub"));
    }

    #[test]
    fn rejects_malformed_domains() {
        let config = AppConfig::default();
        assert!(build_group(&config, &draft("example..com", Strategy::Auto, "")).is_err());
    }

    #[test]
    fn ca_actions_are_judged_by_the_resulting_trust_state() {
        // A cancelled dialog must never read as success.
        let cancelled = anyhow::anyhow!("user canceled the authorization dialog");
        assert_eq!(ca_outcome(Err(cancelled), true), CaOutcome::Cancelled);

        // `security` can exit 0 while nothing got trusted: the store decides.
        assert_eq!(ca_outcome(Ok(false), true), CaOutcome::Failed);
        assert_eq!(ca_outcome(Ok(true), false), CaOutcome::Failed);
        assert_eq!(ca_outcome(Ok(true), true), CaOutcome::Done);
        assert_eq!(ca_outcome(Ok(false), false), CaOutcome::Done);

        let failed = anyhow::anyhow!("security add-trusted-cert failed: boom");
        assert_eq!(ca_outcome(Err(failed), true), CaOutcome::Failed);

        assert_eq!(CaOutcome::Cancelled.message(), Some("已取消，未做更改"));
        assert_eq!(CaOutcome::Failed.message(), Some("未成功，请重试"));
        assert_eq!(CaOutcome::Done.message(), None);
    }




    #[test]
    fn probe_sweep_phases_drive_the_display() {
        let config = serde_json::json!({
            "groups": [
                { "id": "flip", "name": "Flip", "enabled": true, "domains": ["flip.example"] }
            ]
        });

        // While the sweep runs, every active site holds 测速中.
        let status_bad = serde_json::json!({
            "domains": [{ "domain": "flip.example", "state": "failed" }]
        });
        let (sites, _) = build_snapshot(
            &status_bad, &config, &HashSet::new(), true, false, Some(ui_state::SettlePhase::Sweeping),
        );
        assert_eq!(sites[0].summary, "1 个域名 · 测速中");

        // When the sweep finishes the fresh results commit at once.
        let status_slow = serde_json::json!({
            "domains": [{ "domain": "flip.example", "state": "normal", "latencyMs": 200 }]
        });
        let (sites, _) = build_snapshot(
            &status_slow, &config, &HashSet::new(), true, false, Some(ui_state::SettlePhase::Commit),
        );
        assert_eq!(sites[0].summary, "1 个域名 · 全部较慢");

        // Afterwards background tracking keeps a brief flip from showing.
        let (sites, _) = build_snapshot(
            &status_bad, &config, &HashSet::new(), true, false, Some(ui_state::SettlePhase::Tracking),
        );
        assert_eq!(sites[0].summary, "1 个域名 · 全部较慢");
    }

    #[test]
    fn icon_keys_match_whole_ids_and_slugs_only() {
        assert_eq!(icon_key_for("eh"), "eh");
        assert_eq!(icon_key_for("ao3"), "ao3");
        // A site added from pixiv.net gets the slug `pixiv-net`.
        assert_eq!(icon_key_for("pixiv-net"), "pixiv");
        // Must not hand the E-Hentai logo to a slug that merely contains "eh".
        assert_eq!(icon_key_for("mehta-com"), "");
        // Sites that ship their own logo match by id.
        assert_eq!(icon_key_for("nhentai"), "nhentai");
        assert_eq!(icon_key_for("hanime"), "hanime");
    }

    fn draft_with(
        id: &str,
        is_new: bool,
        domains: &str,
        strategy: Strategy,
        sni: &str,
    ) -> SiteDraft {
        SiteDraft {
            id: id.into(),
            is_new,
            name: String::new(),
            domains: domains.into(),
            strategy,
            sni: sni.into(),
        }
    }

    #[test]
    fn editing_a_site_keeps_its_id_and_shared_flags() {
        let mut config = AppConfig::default();
        let mut existing = config.group("pixiv").unwrap().clone();
        existing.ech_shared = true;
        existing.experimental = true;
        config.groups = vec![existing];

        let group = build_group(
            &config,
            &draft_with("pixiv", false, "pixiv.net\nwww.pixiv.net", Strategy::FakeSni, ""),
        )
        .unwrap();

        assert_eq!(group.id, "pixiv");
        assert!(group.ech_shared, "editing must not drop echShared");
        assert!(group.experimental, "editing must not drop experimental");
        assert_eq!(group.domains, vec!["pixiv.net", "www.pixiv.net"]);
    }

    #[test]
    fn generated_ids_avoid_existing_groups() {
        let mut config = AppConfig::default();
        let mut taken = config.group("pixiv").unwrap().clone();
        taken.id = "example-com".into();
        taken.domains = vec!["other.example".into()];
        config.groups.push(taken);

        let group = build_group(&config, &draft("example.com", Strategy::Auto, "")).unwrap();
        assert_eq!(group.id, "example-com-2");
    }

    #[test]
    fn domains_accept_commas_and_whitespace() {
        let config = AppConfig::default();
        let group = build_group(
            &config,
            &draft("a.example, b.example，c.example\nd.example", Strategy::Auto, ""),
        )
        .unwrap();
        assert_eq!(
            group.domains,
            vec!["a.example", "b.example", "c.example", "d.example"]
        );
    }

    #[test]
    fn domains_are_lowercased_and_deduped() {
        let config = AppConfig::default();
        let group = build_group(
            &config,
            &draft("Example.COM example.com", Strategy::Auto, ""),
        )
        .unwrap();
        assert_eq!(group.domains, vec!["example.com"]);
        assert_eq!(group.name, "example.com", "name falls back to the first domain");
    }

    #[test]
    fn sni_hostnames_are_normalized() {
        let config = AppConfig::default();
        let group = build_group(
            &config,
            &draft("example.com", Strategy::FakeSni, "  WWW.Baidu.COM "),
        )
        .unwrap();
        assert_eq!(group.sni.as_deref(), Some("www.baidu.com"));
    }

    #[test]
    fn rejects_malformed_sni() {
        let config = AppConfig::default();
        assert!(build_group(
            &config,
            &draft("example.com", Strategy::FakeSni, "not a host")
        )
        .is_err());
    }

    #[test]
    fn pasted_urls_contribute_their_host() {
        let config = AppConfig::default();
        let group = build_group(
            &config,
            &draft(
                "https://www.example.com/en/\nHTTPS://cdn.example.net:8443/x?q=1",
                Strategy::Auto,
                "",
            ),
        )
        .unwrap();
        assert_eq!(group.domains, vec!["www.example.com", "cdn.example.net"]);
        assert_eq!(group.name, "www.example.com");
    }

    #[test]
    fn urls_without_a_usable_host_are_rejected() {
        let config = AppConfig::default();
        for input in ["https://", "https:///path", "://example.com"] {
            let error = build_group(&config, &draft(input, Strategy::Auto, "")).unwrap_err();
            assert!(
                format!("{error:#}").contains("网址"),
                "{input} should read as a URL problem: {error:#}"
            );
        }
    }

    #[test]
    fn rejects_an_empty_domain_list() {
        let config = AppConfig::default();
        assert!(build_group(&config, &draft(" ,  , ", Strategy::Auto, "")).is_err());
    }

    #[test]
    fn strategies_round_trip_through_the_editor() {
        assert_eq!(strategy_from_index(editor_strategy_index(Strategy::Auto)), Strategy::Auto);
        assert_eq!(strategy_from_index(editor_strategy_index(Strategy::Ech)), Strategy::Ech);
        assert_eq!(
            strategy_from_index(editor_strategy_index(Strategy::FakeSni)),
            Strategy::FakeSni
        );
        // Direct is intentionally shown as Auto: auto already tries direct first.
        assert_eq!(editor_strategy_index(Strategy::Direct), 0);
    }

    fn snapshot() -> (Vec<SiteData>, String) {
        let config = serde_json::json!({
            "groups": [
                { "id": "ok", "name": "OK", "enabled": true,
                  "domains": ["a.example", "b.example"] },
                { "id": "slow", "name": "Slow", "enabled": true,
                  "domains": ["c.example"] },
                { "id": "bad", "name": "Bad", "enabled": true,
                  "domains": ["d.example"] },
                { "id": "off", "name": "Off", "enabled": false,
                  "domains": ["e.example"] }
            ]
        });
        let status = serde_json::json!({
            "domains": [
                { "domain": "a.example", "state": "normal", "latencyMs": 20 },
                { "domain": "b.example", "state": "normal", "latencyMs": 30 },
                { "domain": "c.example", "state": "normal", "latencyMs": 200 },
                { "domain": "d.example", "state": "failed" },
                { "domain": "e.example", "state": "normal", "latencyMs": 20 }
            ]
        });
        build_snapshot(&status, &config, &HashSet::new(), true, false, None)
    }

    #[test]
    fn site_summaries_reflect_state_with_matching_colours() {
        let (sites, _) = snapshot();
        let by_id = |id: &str| sites.iter().find(|site| site.id == id).unwrap();

        assert_eq!(by_id("ok").summary, "2 个域名 · 全部正常");
        assert_eq!(by_id("ok").summary_hex, OK_COLOR);

        assert_eq!(by_id("slow").summary, "1 个域名 · 全部较慢");
        assert_eq!(by_id("slow").summary_hex, SLOW_COLOR);

        assert_eq!(by_id("bad").summary, "1 个域名 · 全部超时");
        assert_eq!(by_id("bad").summary_hex, BAD_COLOR);

        assert_eq!(by_id("off").summary, "1 个域名 · 未选择");
        assert_eq!(by_id("off").summary_hex, IDLE_COLOR);
    }

    #[test]
    fn paused_snapshot_reports_paused_instead_of_timing_out() {
        let config = serde_json::json!({
            "groups": [
                { "id": "ok", "name": "OK", "enabled": true, "domains": ["a.example"] }
            ]
        });
        let status = serde_json::json!({ "domains": [
            { "domain": "a.example", "state": "failed" }
        ]});
        let (sites, subtitle) = build_snapshot(&status, &config, &HashSet::new(), false, false, None);
        assert_eq!(sites[0].summary, "1 个域名 · 已暂停");
        assert_eq!(sites[0].summary_hex, IDLE_COLOR);
        assert_eq!(subtitle, "已选择 1 个站点", "paused runs must not claim activity");
    }

    #[test]
    fn custom_groups_are_marked_for_deletion() {
        let config = serde_json::json!({
            "groups": [
                { "id": "pixiv", "name": "Pixiv", "enabled": true, "domains": ["pixiv.net"] },
                { "id": "mine", "name": "Mine", "enabled": true, "domains": ["mine.example"] }
            ]
        });
        let (sites, _) = build_snapshot(&serde_json::json!({}), &config, &HashSet::new(), true, false, None);
        assert!(!sites.iter().find(|s| s.id == "pixiv").unwrap().custom);
        assert!(sites.iter().find(|s| s.id == "mine").unwrap().custom);
    }

}
