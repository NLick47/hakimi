#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use std::cell::RefCell;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use hakimi_core::config::{
    AppConfig, DomainRule, DownloadConfig, GroupConfig, RouteAttempt, RoutePolicy,
    DEFAULT_MIRROR_SOURCE,
};
use hakimi_core::instance::{InstanceLock, InstanceLockError};
use hakimi_core::runtime::HakimiRuntime;
use serde_json::Value;
use windui::prelude::*;

mod app_state;
mod assets;
mod autostart;
// Only the macOS windowed lifecycle installs the reopen hook; keep the module
// compiled on Windows so its off-macOS test still runs.
#[cfg_attr(windows, allow(dead_code))]
mod macos_reopen;
mod model;
mod theme;
mod tray;
mod ui_state;
mod update;
mod view;
#[cfg(windows)]
mod window_placement;

pub(crate) use app_state::{Action, AppContext, EditorRowState, UiSignals};
#[cfg(test)]
pub(crate) use model::build_snapshot;
#[cfg(test)]
pub(crate) use model::icon_key_for;
pub(crate) use model::{
    build_sites, builtin_group_ids, doh_entries, doh_summary, finish_snapshot, format_route,
    mirror_entries, mirror_summary, normalize_domain_host, parse_route, route_from_preset,
    route_preset_index, text, DohObservation, NetStatus, SiteData, SweepState,
};
#[cfg(test)]
pub(crate) use ui_state::SettlePhase;

pub(crate) fn data_dir() -> Option<PathBuf> {
    std::env::var_os("HAKIMI_DATA_DIR").map(PathBuf::from)
}

// -- native-window helpers (framework-agnostic; kept from the Slint build) ----

/// The window is a fixed light surface, so keep the macOS title bar in the same
/// appearance even when the system is in dark mode.
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

/// A fixed light surface needs a light title bar too; otherwise a system-dark
/// caption reads as a rendering bug. windui does not expose a window handle at
/// construction, so call this from the first UI tick once the HWND exists.
#[cfg(windows)]
fn apply_light_title_bar() {
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR,
        DWMWA_USE_IMMERSIVE_DARK_MODE,
    };

    let Some(handle) = windui::platform::native_window_handle() else {
        return;
    };
    let hwnd = handle as *mut core::ffi::c_void;
    let set = |attribute: u32, value: &u32| unsafe {
        DwmSetWindowAttribute(
            hwnd,
            attribute,
            value as *const u32 as *const core::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        ) == 0
    };
    let light = 0u32;
    if !set(DWMWA_USE_IMMERSIVE_DARK_MODE as u32, &light) {
        let _ = set(19, &light); // pre-20H1 attribute
    }
    // COLORREF is 0x00BBGGRR.
    let _ = set(DWMWA_CAPTION_COLOR as u32, &0x00F5_F4F3); // #F3F4F5
    let _ = set(DWMWA_TEXT_COLOR as u32, &0x0024_1F1B); // #1B1F24
    let _ = set(DWMWA_BORDER_COLOR as u32, &0x00E8_E4E1); // #E1E4E8
}

#[cfg(not(windows))]
fn apply_light_title_bar() {}

/// Raise the app after a tray click on macOS.
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

/// Switch to an accessory app while the window is closed so the Dock icon goes
/// away; the tray and the proxy stay alive.
#[cfg(target_os = "macos")]
pub(crate) fn set_dock_visible(visible: bool) {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};

    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    let current = app.activationPolicy();
    let policy = if visible {
        NSApplicationActivationPolicy::Regular
    } else {
        NSApplicationActivationPolicy::Accessory
    };
    tracing::info!(visible, ?current, ?policy, "DBG set_dock_visible");
    if current != policy {
        let _ = app.setActivationPolicy(policy);
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn set_dock_visible(_visible: bool) {}

/// Top-left corner that centres a `width` x `height` window on the primary
/// screen, in the framework's macOS convention (origin top-left, y down).
///
/// Computed before the window exists so it can be passed to `App::position`:
/// centring from the first tick would move an already-visible window, which
/// reads as the window jumping across the screen.
#[cfg(target_os = "macos")]
fn centered_position(width: i32, height: i32) -> Option<(i32, i32)> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSScreen;

    let mtm = MainThreadMarker::new()?;
    let primary = NSScreen::screens(mtm).firstObject()?;
    let screen = primary.visibleFrame();
    let full = primary.frame();
    // `App::position` places the window frame, and the title bar adds to the
    // content height the app declares. Centring the frame therefore centres the
    // whole window, title bar included.
    let title_bar = 32.0;
    let frame_h = height as f64 + title_bar;
    // AppKit measures y from the bottom of the screen; `App::position` from the
    // top of the primary screen.
    let x = screen.origin.x + (screen.size.width - width as f64) / 2.0;
    let y_from_bottom = screen.origin.y + (screen.size.height - frame_h) / 2.0;
    let y = full.size.height - y_from_bottom - frame_h;
    Some((x.round() as i32, y.round() as i32))
}

#[cfg(not(target_os = "macos"))]
fn centered_position(_width: i32, _height: i32) -> Option<(i32, i32)> {
    None
}

#[cfg(target_os = "macos")]
fn quit_app() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSApplication;

    let Some(mtm) = MainThreadMarker::new() else {
        std::process::exit(0);
    };
    NSApplication::sharedApplication(mtm).terminate(None);
}

#[cfg(not(target_os = "macos"))]
fn quit_app() {
    std::process::exit(0);
}

#[cfg(target_os = "macos")]
fn minimize_window() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSApplication;

    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    if let Some(window) = app.keyWindow() {
        window.performMiniaturize(None);
    }
}

#[cfg(not(target_os = "macos"))]
fn minimize_window() {}

// -- settings derivation (framework-agnostic) ---------------------------------

/// Settings values pushed into the UI. Text fields keep the raw string so the
/// user can type freely; validation happens on commit.
#[derive(Clone, PartialEq)]
pub(crate) struct SettingsValues {
    pub proxy_port: String,
    pub doh_primary: String,
    pub doh_fallback: String,
    pub catalog_ip: String,
    pub catalog_doh: String,
    pub mirror_source: String,
    pub download_mirror: bool,
    pub download_enabled: bool,
    pub download_segments: String,
    pub relay_enabled: bool,
    pub relay_listen: String,
    pub relay_target: String,
    pub http1_hosts: String,
    pub image_relay_enabled: bool,
    pub image_relay_base: String,
    pub image_relay_hosts: String,
    pub image_relay_paths: String,
    pub image_relay_user_agent: String,
    pub image_relay_fallback: bool,
    pub auto_start: bool,
    pub start_hidden: bool,
    pub auto_connect: bool,
}

pub(crate) fn settings_values(config: &Value) -> SettingsValues {
    let field = |section: &str, key: &str| {
        config
            .get(section)
            .map(|value| text(value, key))
            .unwrap_or_default()
    };
    let catalog_defaults = hakimi_core::config::CatalogSources::default();
    let catalog = |key: &str| match config.get("catalogs").and_then(|value| value.get(key)) {
        Some(Value::String(url)) => url.clone(),
        Some(_) => String::new(),
        None => match key {
            "ip" => catalog_defaults.ip.clone(),
            _ => catalog_defaults.doh.clone(),
        },
    };
    let download = config
        .get("advanced")
        .and_then(|advanced| advanced.get("download"));
    let download_defaults = DownloadConfig::default();
    let mirror_source = match download.and_then(|download| download.get("mirrorSource")) {
        Some(Value::String(source)) => source.clone(),
        Some(_) => String::new(),
        None => download_defaults.mirror_source.clone(),
    };
    let download_enabled = download
        .and_then(|download| download.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(download_defaults.enabled);
    let download_segments = download
        .and_then(|download| download.get("segments"))
        .and_then(Value::as_u64)
        .unwrap_or(download_defaults.segments as u64)
        .clamp(2, 12);
    let relay = config
        .get("advanced")
        .and_then(|advanced| advanced.get("relay"));
    let relay_field = |key: &str| relay.map(|value| text(value, key)).unwrap_or_default();
    let startup = config
        .get("advanced")
        .and_then(|advanced| advanced.get("startup"));
    let startup_flag = |key: &str| {
        startup
            .and_then(|value| value.get(key))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    let relay_rule = config
        .get("advanced")
        .and_then(|advanced| advanced.get("imageRelays"))
        .and_then(Value::as_array)
        .and_then(|rules| rules.iter().find(|rule| text(rule, "id") == "pixiv"));
    let relay_rule_flag = |key: &str, fallback: bool| {
        relay_rule
            .and_then(|rule| rule.get(key))
            .and_then(Value::as_bool)
            .unwrap_or(fallback)
    };
    SettingsValues {
        proxy_port: field("proxy", "port"),
        doh_primary: field("doh", "primary"),
        doh_fallback: field("doh", "fallback"),
        catalog_ip: catalog("ip"),
        catalog_doh: catalog("doh"),
        download_mirror: !mirror_source.trim().is_empty(),
        mirror_source,
        download_enabled,
        download_segments: download_segments.to_string(),
        relay_enabled: relay
            .and_then(|value| value.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        relay_listen: relay_field("listen"),
        relay_target: relay_field("target"),
        http1_hosts: config
            .get("advanced")
            .and_then(|advanced| advanced.get("http1Hosts"))
            .and_then(Value::as_array)
            .map(|hosts| {
                hosts
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        image_relay_enabled: relay_rule_flag("enabled", false),
        image_relay_base: relay_rule
            .map(|rule| text(rule, "base"))
            .unwrap_or_default(),
        image_relay_hosts: relay_rule
            .and_then(|rule| rule.get("hosts"))
            .and_then(Value::as_array)
            .map(|hosts| {
                hosts
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        image_relay_user_agent: relay_rule
            .map(|rule| text(rule, "userAgent"))
            .unwrap_or_default(),
        image_relay_paths: relay_rule
            .and_then(|rule| rule.get("paths"))
            .and_then(Value::as_array)
            .map(|paths| {
                paths
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        image_relay_fallback: relay_rule_flag("fallbackDirect", true),
        auto_start: startup_flag("autoStart"),
        start_hidden: startup_flag("startHidden"),
        auto_connect: startup_flag("autoConnect"),
    }
}

/// The image relay the settings card owns. Creating it lazily keeps a fresh
/// install free of a rule the user never asked for.
fn pixiv_image_relay(
    config: &mut hakimi_core::config::AppConfig,
) -> &mut hakimi_core::config::ImageRelayRule {
    let index = config
        .advanced
        .image_relays
        .iter()
        .position(|rule| rule.id == "pixiv");
    let index = match index {
        Some(index) => index,
        None => {
            config
                .advanced
                .image_relays
                .push(hakimi_core::config::ImageRelayRule {
                    enabled: false,
                    ..hakimi_core::config::ImageRelayRule::pixiv_default()
                });
            config.advanced.image_relays.len() - 1
        }
    };
    &mut config.advanced.image_relays[index]
}

fn apply_setting_string(runtime: &HakimiRuntime, key: &str, value: &str) -> Option<String> {
    // A field that was empty and is committed empty again is not an edit: the
    // commit fires on focus loss, so merely clicking a blank field would rewrite
    // the config and persist whatever empty value was read back. Only a real
    // change reaches the writer.
    if matches!(key, "catalogs.ip" | "catalogs.doh") && value.trim().is_empty() {
        let current = runtime.config().snapshot();
        let existing = match key {
            "catalogs.ip" => &current.catalogs.ip,
            _ => &current.catalogs.doh,
        };
        if existing.trim().is_empty() {
            return None;
        }
    }
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
            "advanced.download.mirrorSource" => {
                config.advanced.download.mirror_source = value.to_string()
            }
            "advanced.download.segments" => {
                let segments: usize = value
                    .trim()
                    .parse()
                    .context("下载并发需为 2–12 之间的整数")?;
                if !(2..=12).contains(&segments) {
                    bail!("下载并发需在 2–12 之间");
                }
                config.advanced.download.segments = segments;
            }
            "advanced.relay.listen" => {
                config.advanced.relay.listen = if value.trim().is_empty() {
                    None
                } else {
                    Some(
                        value
                            .trim()
                            .parse()
                            .context("监听地址需为 IP:端口，例如 127.0.0.1:17844")?,
                    )
                };
            }
            "advanced.relay.target" => {
                config.advanced.relay.target = if value.trim().is_empty() {
                    None
                } else {
                    Some(value.trim().to_string())
                };
            }
            "advanced.http1Hosts" => {
                config.advanced.http1_hosts = split_entries(value);
            }
            "advanced.imageRelays.pixiv.base" => pixiv_image_relay(config).base = value.to_string(),
            "advanced.imageRelays.pixiv.hosts" => {
                pixiv_image_relay(config).hosts = split_entries(value);
            }
            "advanced.imageRelays.pixiv.paths" => {
                pixiv_image_relay(config).paths = split_entries(value);
            }
            "advanced.imageRelays.pixiv.userAgent" => {
                pixiv_image_relay(config).user_agent =
                    (!value.is_empty()).then(|| value.to_string());
            }
            other => bail!("未知设置项 {other}"),
        }
        Ok(())
    });
    if result.is_ok() && key == "advanced.download.mirrorSource" {
        runtime.request_mirror_refresh();
    }
    if result.is_ok() && key == "advanced.http1Hosts" {
        if let Err(error) = runtime.update_config(runtime.config().snapshot().as_ref().clone()) {
            return Some(format!("{error:#}"));
        }
    }
    match result {
        Ok(_) => None,
        Err(error) => Some(format!("{error:#}")),
    }
}

fn apply_setting_bool(runtime: &HakimiRuntime, key: &str, value: bool) -> Option<String> {
    let result = runtime.config().mutate(|config| {
        match key {
            "advanced.download.mirrorSource" => {
                config.advanced.download.mirror_source = if value {
                    DEFAULT_MIRROR_SOURCE.to_string()
                } else {
                    String::new()
                };
            }
            "advanced.download.enabled" => {
                config.advanced.download.enabled = value;
            }
            "advanced.relay.enabled" => {
                config.advanced.relay.enabled = value;
                if value {
                    if config.advanced.relay.listen.is_none() {
                        config.advanced.relay.listen =
                            Some(std::net::SocketAddr::from(([127, 0, 0, 1], 17844)));
                    }
                    if config.advanced.relay.target.is_none() {
                        config.advanced.relay.target =
                            Some("region1.v2.argotunnel.com:7844".to_string());
                    }
                }
            }
            "advanced.imageRelays.pixiv.enabled" => {
                pixiv_image_relay(config).enabled = value;
            }
            "advanced.imageRelays.pixiv.fallbackDirect" => {
                pixiv_image_relay(config).fallback_direct = value;
            }
            "advanced.startup.autoStart" => {
                autostart::apply(value)?;
                config.advanced.startup.auto_start = value;
            }
            "advanced.startup.startHidden" => {
                config.advanced.startup.start_hidden = value;
            }
            "advanced.startup.autoConnect" => {
                config.advanced.startup.auto_connect = value;
            }
            other => bail!("未知设置项 {other}"),
        }
        Ok(())
    });
    if result.is_ok() && key == "advanced.download.mirrorSource" {
        runtime.request_mirror_refresh();
    }
    match result {
        Ok(_) => None,
        Err(error) => Some(format!("{error:#}")),
    }
}

// -- CA outcome (framework-agnostic) ------------------------------------------

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

// -- site editor logic (framework-agnostic) -----------------------------------

#[derive(Clone)]
struct DomainDraft {
    pattern: String,
    preset: i32,
    sni: String,
    custom: String,
}

struct SiteDraft {
    id: String,
    is_new: bool,
    name: String,
    domains: Vec<DomainDraft>,
    homepage: String,
    default_preset: i32,
    default_custom: String,
    default_sni: String,
    verify: i32,
}

fn domain_sni_hosts(route: &RoutePolicy) -> Option<Vec<String>> {
    match route.attempts.as_slice() {
        [RouteAttempt::Sni { sni }] => Some(sni.clone()),
        [RouteAttempt::Sni { sni }, RouteAttempt::Direct] => Some(sni.clone()),
        _ => None,
    }
}

fn split_entries(raw: &str) -> Vec<String> {
    raw.split(|c| c == ',' || c == '，')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_sni_hosts(raw: &str) -> Result<Vec<String>> {
    split_entries(raw)
        .into_iter()
        .map(|host| {
            hakimi_core::domain::normalize_hostname(&host)
                .map(|host| host.to_ascii_lowercase())
                .with_context(|| format!("SNI 主机 {host} 格式不正确"))
        })
        .collect()
}

fn build_group(config: &AppConfig, draft: &SiteDraft) -> Result<GroupConfig> {
    let existing = if draft.is_new {
        None
    } else {
        config.group(&draft.id).cloned()
    };
    let mut domains: Vec<DomainRule> = Vec::new();
    for row in &draft.domains {
        let pattern = normalize_domain_host(&row.pattern)?;
        if domains.iter().any(|rule| rule.pattern == pattern) {
            continue;
        }
        let route = match row.preset {
            0 => None,
            1 => Some(RoutePolicy::direct()),
            2 => Some(RoutePolicy::ech_shared()),
            3 => Some(RoutePolicy::sni(parse_sni_hosts(&row.sni)?)),
            4 => Some(parse_route(&row.custom)?),
            _ => None,
        };
        domains.push(DomainRule { pattern, route });
    }
    if domains.is_empty() {
        bail!("请至少填写一个域名");
    }
    if !domains.iter().any(|rule| !rule.pattern.starts_with("*.")) {
        bail!("至少需要一个精确域名（不能只有 *. 通配）");
    }
    for other in &config.groups {
        if !draft.is_new && other.id == draft.id {
            continue;
        }
        if let Some(conflict) = domains.iter().find(|rule| {
            other
                .domains
                .iter()
                .any(|existing| existing.pattern.eq_ignore_ascii_case(&rule.pattern))
        }) {
            bail!("域名 {} 已属于站点「{}」", conflict.pattern, other.name);
        }
    }
    let default_route = match draft.default_preset {
        3 => RoutePolicy::sni(parse_sni_hosts(&draft.default_sni)?),
        4 => parse_route(&draft.default_custom)?,
        _ => route_from_preset(draft.default_preset).unwrap_or_default(),
    };
    let name = if draft.name.trim().is_empty() {
        domains[0].pattern.clone()
    } else {
        draft.name.trim().to_string()
    };
    let homepage = match draft.homepage.trim() {
        "" => None,
        raw => {
            let candidate = if raw.contains("://") {
                raw.to_string()
            } else {
                format!("https://{raw}")
            };
            hakimi_core::config::validate_catalog_url(&candidate, "访问地址")
                .with_context(|| "访问地址格式不正确")?;
            Some(candidate)
        }
    };

    let mut group = existing.unwrap_or_default();
    group.id = if draft.is_new {
        unique_group_id(config, &domains[0].pattern)
    } else {
        draft.id.clone()
    };
    group.name = name;
    group.domains = domains;
    group.homepage = homepage;
    group.default_route = default_route;
    group.verify = model::verify_from_preset(draft.verify);
    if draft.is_new {
        group.enabled = true;
    }
    Ok(group)
}

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

// -- refresh derivation (framework-agnostic) ----------------------------------

thread_local! {
    static CONFIG_CACHE: RefCell<Option<(u64, Arc<Value>)>> =
        const { RefCell::new(None) };
    static REFRESH_CACHE: RefCell<Option<RefreshCache>> =
        const { RefCell::new(None) };
    static MODEL: RefCell<ui_state::AppModel> =
        RefCell::new(ui_state::AppModel::default());
    static UPDATE_LAST_ATTEMPT: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

struct RefreshCache {
    status_revision: u64,
    config_revision: u64,
    expanded: HashSet<String>,
    status: Arc<Value>,
    raw_sites: Vec<SiteData>,
    selected: usize,
    settings: SettingsValues,
}

const UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

const WINDOW_WIDTH: i32 = 760;
const WINDOW_HEIGHT: i32 = 600;

fn network_status(runtime: &HakimiRuntime, settings: &SettingsValues) -> NetStatus {
    let resolver = runtime.resolver();
    let endpoints = resolver.effective_endpoints();
    let health = resolver.health_snapshot();
    let (doh, doh_tone) = doh_summary(
        endpoints.len(),
        health.iter().filter(|entry| entry.observed).count(),
        health.iter().filter(|entry| entry.healthy).count(),
    );
    let observations: Vec<DohObservation> = health
        .iter()
        .map(|row| DohObservation {
            url: row.url.clone(),
            healthy: row.healthy,
            observed: row.observed,
            latency_ms: row.latency_ms,
            last_error: row.last_error.clone(),
        })
        .collect();
    let doh_rows = doh_entries(endpoints.as_ref(), &observations);

    let mirrors = runtime.mirrors();
    let status = mirrors.status();
    let enabled = !settings.mirror_source.trim().is_empty();
    let (mirror, mirror_tone) = mirror_summary(
        enabled,
        status.len(),
        status.iter().filter(|row| row.cooldown_secs == 0).count(),
    );
    let mirror_rows = mirror_entries(enabled, &status);

    NetStatus {
        doh,
        doh_tone,
        mirror,
        mirror_tone,
        doh_entries: doh_rows,
        mirror_entries: mirror_rows,
    }
}

fn cached_config(revision: u64, fetch: impl FnOnce() -> Value) -> Arc<Value> {
    CONFIG_CACHE.with(|cell| {
        let mut slot = cell.borrow_mut();
        match slot.as_ref() {
            Some((cached_revision, config)) if *cached_revision == revision => config.clone(),
            _ => {
                let config = Arc::new(fetch());
                *slot = Some((revision, config.clone()));
                config
            }
        }
    })
}

/// Compute a fresh UI snapshot from the runtime. The revision cache avoids
/// re-serialising the whole status on an idle tick.
fn refresh_snapshot(ctx: &AppContext) -> app_state::UiSnapshot {
    let runtime = &ctx.runtime;
    let status_revision = runtime.status_revision();
    let config_revision = runtime.config_revision();
    let running = runtime.is_started() && !runtime.status().paused();
    let starting = MODEL.with(|m| m.borrow().accel()) == ui_state::AccelState::Running && !running;
    let phase = if starting {
        ui_state::SettlePhase::Starting
    } else {
        ctx.sweep.phase()
    };
    let expanded = &*ctx.expanded.borrow();

    let cached_status = REFRESH_CACHE.with(|cell| {
        cell.borrow()
            .as_ref()
            .filter(|cache| cache.status_revision == status_revision)
            .map(|cache| cache.status.clone())
    });
    let cached = REFRESH_CACHE.with(|cell| {
        cell.borrow().as_ref().and_then(|cache| {
            (cache.status_revision == status_revision
                && cache.config_revision == config_revision
                && &cache.expanded == expanded)
                .then(|| {
                    (
                        cache.raw_sites.clone(),
                        cache.selected,
                        cache.settings.clone(),
                    )
                })
        })
    });
    let expanded_only = REFRESH_CACHE.with(|cell| {
        cell.borrow().as_ref().and_then(|cache| {
            (cache.status_revision == status_revision
                && cache.config_revision == config_revision
                && &cache.expanded != expanded)
                .then(|| {
                    let mut sites = cache.raw_sites.clone();
                    for site in &mut sites {
                        site.open = expanded.contains(&site.id);
                    }
                    (sites, cache.selected, cache.settings.clone())
                })
        })
    });

    let (raw_sites, selected, settings) = if let Some(hit) = expanded_only {
        REFRESH_CACHE.with(|cell| {
            if let Some(cache) = cell.borrow_mut().as_mut() {
                cache.expanded = expanded.clone();
                cache.raw_sites = hit.0.clone();
            }
        });
        hit
    } else {
        match cached {
            Some(hit) => hit,
            None => {
                let status = cached_status.unwrap_or_else(|| Arc::new(runtime.status_json()));
                let config = cached_config(config_revision, || runtime.config_json());
                let (raw_sites, selected) = build_sites(&status, &config, expanded);
                let settings = settings_values(&config);
                REFRESH_CACHE.with(|cell| {
                    *cell.borrow_mut() = Some(RefreshCache {
                        status_revision,
                        config_revision,
                        expanded: expanded.clone(),
                        status: status.clone(),
                        raw_sites: raw_sites.clone(),
                        selected,
                        settings: settings.clone(),
                    });
                });
                (raw_sites, selected, settings)
            }
        }
    };

    let (sites, subtitle) = finish_snapshot(raw_sites, selected, running, starting, Some(phase));
    let net = network_status(runtime, &settings);
    let sites_summary = format!(
        "{} 个 · 已启用 {}",
        sites.len(),
        sites.iter().filter(|site| site.enabled).count()
    );

    app_state::UiSnapshot {
        sites,
        subtitle,
        sites_summary,
        running,
        config_revision,
        settings,
        net_doh: net.doh,
        net_doh_tone: net.doh_tone,
        net_mirror: net.mirror,
        net_mirror_tone: net.mirror_tone,
        doh_rows: net.doh_entries,
        mirror_rows: net.mirror_entries,
    }
}

/// The application: owns the signals and handles every Action on the UI thread.
struct Ui {
    signals: UiSignals,
    ctx: AppContext,
    /// Shared cell holding the channel sender. The channel is created after the
    /// App, so the handler receives a clone of this cell and the sender is
    /// stashed into it immediately after `app.channel()` returns.
    tx: std::rc::Rc<RefCell<Option<Sender<Action>>>>,
    /// Guards against a second update check. Shared with the tokio task, so it
    /// must be atomic rather than a thread-local (the worker has its own TLS).
    update_in_flight: Arc<AtomicBool>,
    hidden: Arc<AtomicBool>,
    quitting: Arc<AtomicBool>,
    shutdown: Arc<tokio::sync::Notify>,
    settings_revision: std::cell::Cell<Option<u64>>,
    /// Set when the window closes; the next tick reclaims the editor signals.
    ///
    /// They cannot be freed inside `on_close_request`: clearing `editor_rows`
    /// only marks the keyed list for rebuild, and the rows still on screen read
    /// their `visible_signal`s during that frame's layout. One tick later the
    /// nodes are gone and the slots are safe to dispose.
    reclaim_editor_rows: std::cell::Cell<bool>,
}

impl Ui {
    fn tx(&self) -> Sender<Action> {
        self.tx
            .borrow()
            .clone()
            .expect("UI channel sender installed before any action")
    }

    fn apply_snapshot(&self, snap: app_state::UiSnapshot) {
        let s = &self.signals;
        let domains: usize = snap.sites.iter().map(|site| site.domains.len()).sum();
        let slow = snap
            .sites
            .iter()
            .flat_map(|site| &site.domains)
            .filter(|d| d.status == "较慢")
            .count();
        let bad = snap
            .sites
            .iter()
            .flat_map(|site| &site.domains)
            .filter(|d| d.status == "超时")
            .count();
        // Only write signals whose value actually changed. Writing an unchanged
        // signal still marks the reactive tree dirty, which rebuilds every site
        // row (and re-decodes every logo) on each idle tick — the source of
        // scroll jank. A no-op tick must touch zero signals.
        let set_str = |sig: Signal<String>, value: String| {
            if sig.get() != value {
                sig.set(value);
            }
        };
        let set_i32 = |sig: Signal<i32>, value: i32| {
            if sig.get() != value {
                sig.set(value);
            }
        };
        let set_bool = |sig: Signal<bool>, value: bool| {
            if sig.get() != value {
                sig.set(value);
            }
        };
        set_str(s.stat_sites, snap.sites.len().to_string());
        set_str(
            s.stat_enabled,
            snap.sites
                .iter()
                .filter(|site| site.enabled)
                .count()
                .to_string(),
        );
        set_str(s.stat_domains, domains.to_string());
        set_str(s.stat_slow, slow.to_string());
        set_str(s.stat_bad, bad.to_string());
        let all_selected = !snap.sites.is_empty() && snap.sites.iter().all(|site| site.enabled);
        if s.sites.get() != snap.sites {
            s.sites.set(snap.sites);
        }
        set_str(s.status_subtitle, snap.subtitle);
        set_str(s.sites_summary, snap.sites_summary);
        set_bool(s.running, snap.running);
        set_str(s.stat_doh, snap.net_doh);
        set_i32(s.stat_doh_tone, snap.net_doh_tone);
        set_str(s.stat_mirror, snap.net_mirror);
        set_i32(s.stat_mirror_tone, snap.net_mirror_tone);
        if s.doh_rows.get() != snap.doh_rows {
            s.doh_rows.set(snap.doh_rows);
        }
        if s.mirror_rows.get() != snap.mirror_rows {
            s.mirror_rows.set(snap.mirror_rows);
        }

        // Settings fields are rewritten only when the configuration actually
        // changed. Comparing values is not enough: clearing a field makes the
        // signal differ from the stored value, and the next one-second refresh
        // would put the old text back before the commit ever runs.
        let st = &snap.settings;
        let config_changed = self.settings_revision.replace(Some(snap.config_revision))
            != Some(snap.config_revision);
        let assign_str = |sig: Signal<String>, value: &str| {
            if config_changed && sig.get() != value {
                sig.set(value.to_string());
            }
        };
        assign_str(s.cfg_proxy_port, &st.proxy_port);
        assign_str(s.cfg_doh_primary, &st.doh_primary);
        assign_str(s.cfg_doh_fallback, &st.doh_fallback);
        assign_str(s.cfg_catalog_ip, &st.catalog_ip);
        assign_str(s.cfg_catalog_doh, &st.catalog_doh);
        assign_str(s.cfg_mirror_source, &st.mirror_source);
        let segments: i32 = st.download_segments.parse().unwrap_or(2);
        if config_changed && s.cfg_download_segments.get() != segments {
            s.cfg_download_segments.set(segments);
        }
        assign_str(s.cfg_relay_listen, &st.relay_listen);
        assign_str(s.cfg_relay_target, &st.relay_target);
        assign_str(s.cfg_http1_hosts, &st.http1_hosts);
        assign_str(s.cfg_image_relay_base, &st.image_relay_base);
        assign_str(s.cfg_image_relay_hosts, &st.image_relay_hosts);
        assign_str(s.cfg_image_relay_paths, &st.image_relay_paths);
        assign_str(s.cfg_image_relay_ua, &st.image_relay_user_agent);
        if s.cfg_download_mirror.get() != st.download_mirror {
            s.cfg_download_mirror.set(st.download_mirror);
        }
        if s.cfg_download_enabled.get() != st.download_enabled {
            s.cfg_download_enabled.set(st.download_enabled);
        }
        if s.cfg_relay_enabled.get() != st.relay_enabled {
            s.cfg_relay_enabled.set(st.relay_enabled);
        }
        if s.cfg_image_relay_enabled.get() != st.image_relay_enabled {
            s.cfg_image_relay_enabled.set(st.image_relay_enabled);
        }
        if s.cfg_image_relay_fallback.get() != st.image_relay_fallback {
            s.cfg_image_relay_fallback.set(st.image_relay_fallback);
        }
        if s.cfg_auto_start.get() != st.auto_start {
            s.cfg_auto_start.set(st.auto_start);
        }
        if s.cfg_start_hidden.get() != st.start_hidden {
            s.cfg_start_hidden.set(st.start_hidden);
        }
        if s.cfg_auto_connect.get() != st.auto_connect {
            s.cfg_auto_connect.set(st.auto_connect);
        }

        // Windows can disable the Startup entry from Task Manager without
        // touching the file; surface it instead of claiming it will run.
        let warning = if st.auto_start {
            autostart::login_state()
                .problem()
                .unwrap_or_default()
                .to_string()
        } else {
            String::new()
        };
        if s.auto_start_warning.get() != warning {
            s.auto_start_warning.set(warning);
        }

        if s.select_all.get() != all_selected {
            s.select_all.set(all_selected);
        }
        let startup_error = if s.cfg_error_key.get() == "advanced.startup.autoStart" {
            s.cfg_error.get()
        } else {
            s.auto_start_warning.get()
        };
        if s.startup_error.get() != startup_error {
            s.startup_error.set(startup_error);
        }
    }

    fn refresh(&self) {
        let snap = refresh_snapshot(&self.ctx);
        self.apply_snapshot(snap);
    }

    fn release_view_state(&self) {
        let s = &self.signals;
        // On Windows the window itself is destroyed (resident mode), so the
        // tree, its text layouts and its GPU buffers go with it. On macOS the
        // window is only hidden: parking the switcher on the Closed page drops
        // the page subtree and the signals it created too; prepare_show()
        // re-mounts it before the tray reveals the window again.
        if s.window_open.get() {
            s.window_open.set(false);
        }
        if s.editor_open.get() {
            s.editor_open.set(false);
        }
        if !s.editor_rows.get().is_empty() {
            s.editor_rows.set(Vec::new());
        }
        self.reclaim_editor_rows.set(true);
        s.editor_error.set(String::new());

        REFRESH_CACHE.with(|cell| *cell.borrow_mut() = None);
        // Site rows are rebuilt by the next refresh; dropping the snapshot
        // releases every string it carried while the window is gone.
        if !s.sites.get().is_empty() {
            s.sites.set(Vec::new());
        }
        if !s.doh_rows.get().is_empty() {
            s.doh_rows.set(Vec::new());
        }
        if !s.mirror_rows.get().is_empty() {
            s.mirror_rows.set(Vec::new());
        }
        if s.doh_open.get() {
            s.doh_open.set(false);
        }
        if s.mirror_open.get() {
            s.mirror_open.set(false);
        }
        self.sync_root();

        // Decoded logos are cached in a thread-local; the rows that used them
        // are gone, so the cache would otherwise keep the pixmaps forever.
        assets::clear_logo_cache();
    }

    fn request_quit(&self) {
        if self.quitting.swap(true, Ordering::SeqCst) {
            return;
        }
        tracing::info!("quit requested");
        let runtime = self.ctx.runtime.clone();
        let shutdown = self.shutdown.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match rt {
                Ok(rt) => {
                    if let Err(error) = rt.block_on(runtime.stop()) {
                        tracing::warn!(error = %format!("{error:#}"), "runtime stop on quit failed");
                    }
                }
                Err(error) => {
                    tracing::warn!(error = %error, "could not build a shutdown runtime");
                }
            }
            shutdown.notify_one();
            quit_app();
        });
    }

    fn sync_model(&self) {
        MODEL.with(|m| ui_state::sync_window(&m.borrow(), &self.signals));
    }

    /// Recompute the page-root key after any action that can change which
    /// subtree is mounted. Must be a plain signal write: the switcher keys on
    /// the signal's version, which a derived map would not advance.
    fn sync_root(&self) {
        app_state::sync_root(self.signals);
    }

    fn handle(&self, action: Action) {
        let s = &self.signals;
        let runtime = &self.ctx.runtime;
        let tx = self.tx();
        match action {
            Action::OpenFix => {
                s.ca_action_error.set(String::new());
                MODEL.with(|m| m.borrow_mut().open_fix());
                self.sync_model();
            }
            Action::DismissInterrupt => {
                MODEL.with(|m| m.borrow_mut().dismiss_interrupt());
                self.sync_model();
            }
            Action::FinishOnboarding => {
                let effects = MODEL.with(|m| m.borrow_mut().dismiss_fix());
                ui_state::execute(&effects, runtime);
                self.sync_model();
            }
            Action::SetPage(page) => s.page.set(page),
            Action::SetSection(section) => s.settings_section.set(section),
            Action::ShowMain => {
                tracing::info!(
                    window_open_before = s.window_open.get(),
                    root_before = s.root.get(),
                    "DBG ShowMain: handling"
                );
                set_dock_visible(true);
                activate_app();
                if !s.window_open.get() {
                    s.window_open.set(true);
                }
                self.refresh();
                self.sync_root();
                tracing::info!(root_after = s.root.get(), "DBG ShowMain: done");
            }
            Action::Quit => self.request_quit(),
            Action::ToggleMaster => {
                let turning_on =
                    MODEL.with(|m| m.borrow().accel() != ui_state::AccelState::Running);
                if turning_on && !runtime.config().snapshot().groups.iter().any(|g| g.enabled) {
                    return;
                }
                let effects = MODEL.with(|m| {
                    let env = m.borrow().env().clone();
                    m.borrow_mut().toggle(env)
                });
                ui_state::execute(&effects, runtime);
                self.sync_model();
                self.refresh();
            }
            Action::ToggleGroup(id, enabled) => {
                if let Err(error) = runtime.set_group_enabled(&id, enabled) {
                    tracing::warn!(error = %format!("{error:#}"), "could not toggle the site");
                }
                self.refresh();
            }
            Action::SelectAll(enabled) => {
                let _ = runtime.config().mutate(|config| {
                    for group in &mut config.groups {
                        group.enabled = enabled;
                    }
                    Ok(())
                });
                if !enabled {
                    let effects = MODEL.with(|m| m.borrow_mut().stop());
                    ui_state::execute(&effects, runtime);
                }
                self.sync_model();
                self.refresh();
            }
            Action::ToggleOpen(id) => {
                let mut set = self.ctx.expanded.borrow_mut();
                if !set.remove(&id) {
                    set.insert(id);
                }
                drop(set);
                self.refresh();
            }
            Action::ProbeSelected => {
                if self.ctx.sweep.running.swap(true, Ordering::SeqCst) {
                    return;
                }
                self.refresh();
                let sweep = self.ctx.sweep.clone();
                let runtime = runtime.clone();
                let tx = tx.clone();
                self.ctx.spawner.spawn(async move {
                    runtime.probe_sweep().await;
                    sweep.running.store(false, Ordering::SeqCst);
                    sweep.commit_once.store(true, Ordering::SeqCst);
                    let _ = tx.send(Action::ProbeFinished);
                });
            }
            Action::ProbeFinished => self.refresh(),
            Action::ReapplyProxy => {
                let runtime = runtime.clone();
                std::thread::spawn(move || {
                    if let Err(error) = runtime.apply_system_proxy() {
                        eprintln!("hakimi-ui: manual system proxy re-apply failed: {error:#}");
                    }
                });
            }
            Action::SaveString(key, value) => {
                let value = value.trim().to_string();
                let error = apply_setting_string(runtime, &key, &value);
                let failed = error.is_some();
                s.cfg_error.set(error.unwrap_or_default());
                s.cfg_error_key
                    .set(if failed { key } else { String::new() });
                self.refresh();
            }
            Action::SaveBool(key, value) => {
                let error = apply_setting_bool(runtime, &key, value);
                let failed = error.is_some();
                s.cfg_error.set(error.unwrap_or_default());
                s.cfg_error_key
                    .set(if failed { key } else { String::new() });
                self.refresh();
            }
            Action::CaAction(kind) => {
                // The buttons stay clickable while busy (the label flips to
                // 处理中…); a second click here would spawn a concurrent
                // install/uninstall whose outcome races this one's.
                if s.ca_busy.get() {
                    return;
                }
                s.ca_busy.set(true);
                s.ca_action_error.set(String::new());
                ui_state::sync_ca_status(s);
                let runtime = runtime.clone();
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let outcome = match kind {
                        1 => ca_outcome(runtime.ca_install().map(|st| st.installed), true),
                        2 => ca_outcome(runtime.ca_uninstall().map(|st| st.installed), false),
                        3 => ca_outcome(runtime.ca_repair().map(|st| st.installed), true),
                        _ => CaOutcome::Done,
                    };
                    let _ = tx.send(Action::CaOutcome {
                        message: outcome.message().map(str::to_string),
                    });
                });
            }
            Action::CaOutcome { message } => {
                s.ca_busy.set(false);
                if let Some(message) = message {
                    s.ca_action_error.set(message);
                }
                // The row and the footer must reflect the outcome now, not on
                // the next one-second probe tick: a successful install flips
                // the status green and re-enables the finish button at once.
                let env = ui_state::probe_env(runtime, false);
                let effects = MODEL.with(|m| m.borrow_mut().env_changed(env));
                ui_state::execute(&effects, runtime);
                self.sync_model();
                self.refresh();
            }
            Action::OpenDataDir => {
                let dir = runtime.paths().root().to_path_buf();
                std::thread::spawn(move || {
                    open_external(&dir);
                });
            }
            Action::OpenSite(url) => {
                std::thread::spawn(move || {
                    open_external(&url);
                });
            }
            Action::CheckUpdate => {
                UPDATE_LAST_ATTEMPT.with(|slot| slot.set(Some(Instant::now())));
                self.start_update_check();
            }
            Action::OpenUpdate => {
                let url = s.release_url.get();
                if !url.is_empty() {
                    let _ = tx.send(Action::OpenSite(url));
                }
            }
            Action::UpdateResult {
                status,
                available,
                url,
            } => {
                s_update_signals(s, false, &status, available, url);
            }
            Action::EnvChanged(env) => {
                let effects = MODEL.with(|m| m.borrow_mut().env_changed(env));
                ui_state::execute(&effects, runtime);
                self.sync_model();
            }
            Action::ToggleAutoStart | Action::ToggleStartHidden => {
                let is_auto = matches!(action, Action::ToggleAutoStart);
                let key = if is_auto {
                    "advanced.startup.autoStart"
                } else {
                    "advanced.startup.startHidden"
                };
                let startup = &runtime.config().snapshot().advanced.startup;
                let enabled = if is_auto {
                    !startup.auto_start
                } else {
                    !startup.start_hidden
                };
                let error = apply_setting_bool(runtime, key, enabled);
                if let Some(message) = &error {
                    tracing::warn!(error = %message, "tray startup toggle failed");
                }
                s.cfg_error.set(error.clone().unwrap_or_default());
                s.cfg_error_key.set(if error.is_some() {
                    key.to_string()
                } else {
                    String::new()
                });
                self.refresh();
            }
            Action::OpenEditor(id) => {
                let config = runtime.config().snapshot();
                let builtins = builtin_group_ids();
                match config.group(&id) {
                    Some(group) => {
                        s.editor_is_new.set(false);
                        s.editor_id.set(group.id.clone());
                        s.editor_name.set(group.name.clone());
                        s.editor_homepage
                            .set(group.homepage.clone().unwrap_or_default());
                        let preset = route_preset_index(&group.default_route);
                        s.editor_default_preset.set(preset);
                        s.editor_default_custom.set(if preset == 4 {
                            format_route(&group.default_route)
                        } else {
                            String::new()
                        });
                        s.editor_default_sni.set(if preset == 3 {
                            domain_sni_hosts(&group.default_route)
                                .map(|hosts| hosts.join(", "))
                                .unwrap_or_default()
                        } else {
                            String::new()
                        });
                        s.editor_verify
                            .set(model::verify_preset_index(group.verify) as usize);
                        s.editor_off_armed.set(false);
                        s.editor_deletable.set(!builtins.contains(&group.id));
                        let rows: Vec<EditorRowState> = app_state::with_editor_rows(|| {
                            group
                                .domains
                                .iter()
                                .enumerate()
                                .map(|(i, rule)| {
                                    let (preset, sni, custom) = match &rule.route {
                                        None => (0, String::new(), String::new()),
                                        Some(route) if route == &RoutePolicy::direct() => {
                                            (1, String::new(), String::new())
                                        }
                                        Some(route) if route == &RoutePolicy::ech_shared() => {
                                            (2, String::new(), String::new())
                                        }
                                        Some(route) => match domain_sni_hosts(route) {
                                            Some(hosts) => (3, hosts.join(", "), String::new()),
                                            None => (4, String::new(), format_route(route)),
                                        },
                                    };
                                    EditorRowState::new(i, &rule.pattern, preset, &sni, &custom)
                                })
                                .collect()
                        });
                        s.editor_rows.set(rows);
                    }
                    None => {
                        s.editor_is_new.set(true);
                        s.editor_id.set(String::new());
                        s.editor_name.set(String::new());
                        s.editor_rows.set(app_state::with_editor_rows(|| {
                            vec![EditorRowState::new(0, "", 0, "", "")]
                        }));
                        s.editor_homepage.set(String::new());
                        s.editor_default_preset.set(0);
                        s.editor_default_custom.set(String::new());
                        s.editor_default_sni.set(String::new());
                        s.editor_verify.set(0);
                        s.editor_off_armed.set(false);
                        s.editor_deletable.set(false);
                    }
                }
                s.editor_error.set(String::new());
                s.editor_open.set(true);
            }
            Action::CloseEditor => {
                s.editor_open.set(false);
                s.editor_off_armed.set(false);
                s.editor_error.set(String::new());
            }
            Action::AddDomain => {
                // The new row joins the current generation: the rows already on
                // screen stay mounted and keep their signals, so only this one
                // is registered.
                let mut rows = s.editor_rows.get();
                let index = rows.len();
                app_state::with_new_editor_row(|| {
                    rows.push(EditorRowState::new(index, "", 0, "", ""));
                });
                s.editor_rows.set(rows);
            }
            Action::RemoveDomain(index) => {
                let mut rows = s.editor_rows.get();
                if rows.len() > 1 && index < rows.len() {
                    rows.remove(index);
                    for (i, row) in rows.iter_mut().enumerate() {
                        row.index = i;
                    }
                    s.editor_rows.set(rows);
                }
            }
            Action::SaveEditor => {
                if s.editor_verify.get() == 2 && !s.editor_off_armed.get() {
                    s.editor_off_armed.set(true);
                    s.editor_error
                        .set("关闭校验会接受任意上游证书；再点一次保存确认。".into());
                    return;
                }
                let draft = SiteDraft {
                    id: s.editor_id.get(),
                    is_new: s.editor_is_new.get(),
                    name: s.editor_name.get(),
                    domains: s
                        .editor_rows
                        .get()
                        .into_iter()
                        .map(|row| DomainDraft {
                            pattern: row.pattern.get(),
                            preset: row.preset.get() as i32,
                            sni: row.sni.get(),
                            custom: row.custom.get(),
                        })
                        .collect(),
                    homepage: s.editor_homepage.get(),
                    default_preset: s.editor_default_preset.get(),
                    default_custom: s.editor_default_custom.get(),
                    default_sni: s.editor_default_sni.get(),
                    verify: s.editor_verify.get() as i32,
                };
                let config = runtime.config().snapshot();
                let saved = build_group(&config, &draft).and_then(|group| {
                    tracing::info!(id = %group.id, "site saved");
                    runtime.upsert_group(group).map(|_| ())
                });
                match saved {
                    Ok(()) => {
                        s.editor_open.set(false);
                        s.editor_off_armed.set(false);
                        s.editor_error.set(String::new());
                        self.refresh();
                    }
                    Err(error) => s.editor_error.set(format!("{error:#}")),
                }
            }
            Action::DeleteSite(id) => match runtime.remove_group(&id) {
                Ok(_) => {
                    tracing::info!(id = %id, "site removed");
                    s.editor_open.set(false);
                    s.editor_error.set(String::new());
                    self.refresh();
                }
                Err(error) => s.editor_error.set(format!("{error:#}")),
            },
            Action::ResetCatalogUrls => {
                let defaults = hakimi_core::config::CatalogSources::default();
                let result = runtime.config().mutate(|config| {
                    config.catalogs.ip = defaults.ip.clone();
                    config.catalogs.doh = defaults.doh.clone();
                    Ok(())
                });
                match result {
                    Ok(_) => {
                        tracing::info!("catalog URLs restored to their defaults");
                        s.cfg_error.set(String::new());
                        s.cfg_error_key.set(String::new());
                        self.refresh();
                    }
                    Err(error) => {
                        let message = format!("{error:#}");
                        s.cfg_error.set(message);
                        s.cfg_error_key.set("catalogs.ip".into());
                    }
                }
            }
        }
    }

    /// Starts a check unless one is already in flight. All state is written to
    /// signals on the UI thread; the tokio task only computes the result and
    /// posts it back through the channel.
    fn start_update_check(&self) {
        if self.update_in_flight.swap(true, Ordering::SeqCst) {
            return;
        }
        s_update_signals(&self.signals, true, "正在检查更新…", false, String::new());
        tracing::info!("checking for updates");
        let tx = self.tx();
        let in_flight = self.update_in_flight.clone();
        self.ctx.spawner.spawn(async move {
            let (status, available, url) = match update::check().await {
                Ok(update::CheckOutcome::Available(release)) => (
                    format!("发现新版本 v{}", release.version),
                    true,
                    release.url,
                ),
                Ok(update::CheckOutcome::UpToDate) => {
                    ("已是最新版本".to_string(), false, String::new())
                }
                Err(error) => {
                    tracing::info!(error = %format!("{error:#}"), "the update check failed");
                    ("暂时无法检查更新".to_string(), false, String::new())
                }
            };
            in_flight.store(false, Ordering::SeqCst);
            let _ = tx.send(Action::UpdateResult {
                status,
                available,
                url,
            });
        });
    }
}

/// Write all update-related signals in one place, only on the UI thread.
fn s_update_signals(s: &UiSignals, checking: bool, status: &str, available: bool, url: String) {
    if s.update_checking.get() != checking {
        s.update_checking.set(checking);
    }
    if s.update_status.get() != status {
        s.update_status.set(status.to_string());
    }
    if s.update_available.get() != available {
        s.update_available.set(available);
    }
    if s.release_url.get() != url {
        s.release_url.set(url);
    }
    let label = if available {
        "下载"
    } else if checking {
        "检查中…"
    } else {
        "检查"
    };
    if s.update_button.get() != label {
        s.update_button.set(label.to_string());
    }
}

fn maybe_auto_update(ui: &Ui) {
    let due = UPDATE_LAST_ATTEMPT
        .with(|slot| slot.get().is_none_or(|at| at.elapsed() >= UPDATE_INTERVAL));
    if due {
        UPDATE_LAST_ATTEMPT.with(|slot| slot.set(Some(Instant::now())));
        ui.start_update_check();
    }
}

// -- launch options -----------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct LaunchOptions {
    autostart: bool,
    hidden: bool,
    show: bool,
}

fn launch_options(args: &[String]) -> LaunchOptions {
    LaunchOptions {
        autostart: args.iter().any(|arg| arg == autostart::AUTOSTART_ARG),
        hidden: args.iter().any(|arg| arg == "--hidden"),
        show: args.iter().any(|arg| arg == "--show"),
    }
}

fn starts_hidden(options: LaunchOptions, config_hidden: bool) -> bool {
    (options.autostart || options.hidden || config_hidden) && !options.show
}

/// Singleton key of the main window. On Windows the window is created on
/// demand and destroyed on close, so this is what keeps tray clicks from
/// opening a second one (an already-open window is focused instead).
#[cfg_attr(not(windows), allow(dead_code))]
const MAIN_WINDOW_KEY: &str = "main";

/// Window-level shortcuts shared by the main-window and resident paths.
fn shortcut_handler(
    ui: std::rc::Rc<Ui>,
) -> impl FnMut(&mut windui::event::ShortcutCtx, windui::event::KeyEvent) -> bool + 'static {
    move |ctx, ev| {
        if !ev.ctrl || ev.shift || ev.alt {
            return false;
        }
        match ev.key {
            Key::Char('w') | Key::Char('W') => {
                ctx.request_close();
                true
            }
            Key::Char('m') | Key::Char('M') => {
                minimize_window();
                true
            }
            Key::Char('q') | Key::Char('Q') => {
                ui.request_quit();
                true
            }
            _ => false,
        }
    }
}

/// Tray click / "显示主窗口": bring the UI back.
///
/// Windows resident mode keeps no window while closed, so this asks for a new
/// on-demand window (`.single(main)` focuses an already-open one). macOS keeps
/// a hidden main window: remount the page tree synchronously, then show it.
pub(crate) fn tray_show(ctx: &mut TrayCtx, ui: &std::rc::Rc<Ui>, signals: UiSignals) {
    set_dock_visible(true);
    app_state::prepare_show(signals);
    #[cfg(windows)]
    ctx.open_window(main_window_request(ui.clone(), ui.tx()));
    #[cfg(not(windows))]
    {
        ui.handle(Action::ShowMain);
        ctx.show_window();
    }
}

/// Build the main UI as an on-demand window (Windows resident mode).
///
/// Every open gets a fresh request: signals created while building the content
/// belong to that window and are reclaimed when it is destroyed, so closing
/// returns the whole UI — widget tree, text layouts, decoded logos and the
/// renderer's back buffers — instead of parking it in a hidden window.
#[cfg(windows)]
fn main_window_request(ui: std::rc::Rc<Ui>, tx: Sender<Action>) -> WindowRequest {
    let close_ui = ui.clone();
    let refresh_ui = ui.clone();
    let content_ui = ui.clone();
    let shortcut_ui = ui.clone();

    let title_bar_pending = std::cell::Cell::new(true);
    let mut window = Window::new("hakimi", WINDOW_WIDTH, WINDOW_HEIGHT)
        .icon(assets::window_icon())
        .resizable(false)
        .bg(theme::WINDOW_BG)
        .single(MAIN_WINDOW_KEY);
    // Reopen where the user left it; a first open (or a frame stranded on an
    // unplugged monitor) falls back to windui's monitor-aware centering.
    window = match window_placement::restore() {
        Some((x, y)) => window.position(x, y),
        None => window.centered(true),
    };
    window
        .on_close_request(move |_ctx| {
            tracing::info!("main window closing: releasing the UI");
            window_placement::remember_current();
            close_ui.release_view_state();
            true
        })
        .on_shortcut(shortcut_handler(shortcut_ui))
        // The HWND exists only once the window is created, so the palette is
        // applied on the first short tick rather than before the request.
        .on_interval(Duration::from_millis(120), move |_ctx| {
            if title_bar_pending.replace(false) {
                apply_light_title_bar();
            }
        })
        .on_interval(Duration::from_millis(1000), move |_ctx| {
            // Deferred from the close handler: the rows are off the tree.
            if refresh_ui.reclaim_editor_rows.replace(false) {
                app_state::release_editor_rows();
            }
            if !refresh_ui.signals.editor_open.get() {
                refresh_ui.refresh();
            }
        })
        .content(move || {
            // App-level signals outlive the window: restore the page state and
            // refresh before building so the first frame is already right.
            tracing::info!("main window: building content");
            content_ui.signals.window_open.set(true);
            content_ui.sync_root();
            content_ui.refresh();
            view::view(content_ui.signals, tx)
        })
}

/// Windows: run without a main window and open the UI on demand. Closing the
/// window destroys it, which is what actually returns its memory.
///
/// windui keeps its shared Direct2D/DirectWrite device chain for the process
/// lifetime unless asked to release it. The local windui fork exposes
/// `release_shared_device_if_idle()`; this tick calls it once the window is
/// really gone, returning the UI's GPU/font caches (tens of MB for this UI)
/// to the system. The next open recreates them lazily. The API itself refuses
/// while any window is alive, so a fast reopen is safe.
#[cfg(windows)]
fn run_resident(mut app: App, ui: std::rc::Rc<Ui>, tx: Sender<Action>, start_hidden: bool) {
    let tick_ui = ui.clone();
    app = app.on_interval(Duration::from_millis(1000), move |_ctx| {
        // Runs with zero windows too: finish the editor-scope reclaim deferred
        // by the close handler and keep the daily update check alive.
        if tick_ui.reclaim_editor_rows.replace(false) {
            app_state::release_editor_rows();
        }
        // Only UI-originated memory: the proxy runtime is untouched. No-op
        // while a window is open or after the chain was already released.
        if !window_open(MAIN_WINDOW_KEY) && windui::platform::release_shared_device_if_idle() {
            tracing::info!("released the shared UI device caches");
        }
        tick_ui
            .hidden
            .store(!window_open(MAIN_WINDOW_KEY), Ordering::Relaxed);
        maybe_auto_update(&tick_ui);
    });

    if start_hidden {
        set_dock_visible(false);
        ui.hidden.store(true, Ordering::Relaxed);
        tracing::info!("starting with only the tray icon");
    } else {
        set_dock_visible(true);
        app = app.start_window(main_window_request(ui.clone(), tx.clone()));
    }
    app = app
        .screenshot_window(main_window_request(ui.clone(), tx))
        .screenshot_from_args();

    if !app.run_resident() {
        tracing::error!("resident mode could not start");
    }
}

/// macOS: keep a hidden main window (windui's resident mode is not implemented
/// there yet), so the page tree stays mounted and only the data is dropped.
#[cfg(not(windows))]
fn run_windowed(mut app: App, ui: std::rc::Rc<Ui>, tx: Sender<Action>, start_hidden: bool) {
    {
        let close_ui = ui.clone();
        app = app.on_close_request(move |_ctx| {
            set_dock_visible(false);
            close_ui.release_view_state();
            true
        });
    }

    {
        let show_ui = ui.clone();
        app = app.on_show(move |_ctx| {
            // The tray callback already re-mounted the page tree before the
            // window was shown (see app_state::prepare_show). Keep the signal
            // writes: they are idempotent and cover other reveal paths.
            set_dock_visible(true);
            if !show_ui.signals.window_open.get() {
                show_ui.signals.window_open.set(true);
            }
            show_ui.sync_root();
            show_ui.refresh();
        });
    }

    app = app.on_shortcut(shortcut_handler(ui.clone()));

    // One-second refresh: recompute the snapshot and push changed signals.
    let timer_ui = ui.clone();
    let mut title_bar_done = false;
    app = app.on_interval(Duration::from_millis(1000), move |ctx| {
        if !title_bar_done {
            title_bar_done = true;
            apply_light_title_bar();
        }
        // Deferred from the close handler: the rows are off the tree by now.
        if timer_ui.reclaim_editor_rows.replace(false) {
            app_state::release_editor_rows();
        }
        let visible = ctx.window_state().visible;
        if visible && !timer_ui.signals.editor_open.get() {
            timer_ui.refresh();
        }
        timer_ui.hidden.store(!visible, Ordering::Relaxed);
        maybe_auto_update(&timer_ui);
    });

    // Attach the content tree in BOTH branches. A hidden launch still owns a
    // hidden window that the tray reveals later; without this it would be blank.
    let app = app
        .screenshot_from_args()
        .content(view::view(ui.signals, tx));
    macos_reopen::install();
    if start_hidden {
        set_dock_visible(false);
        tracing::info!("starting with only the tray icon");
        app.start_hidden().run();
    } else {
        set_dock_visible(true);
        app.run();
    }
}

// -- entry point --------------------------------------------------------------

#[cfg(windows)]
fn open_external(target: impl AsRef<std::ffi::OsStr>) {
    use windows::core::{w, HSTRING, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let target = HSTRING::from(target.as_ref().to_string_lossy().as_ref());
    unsafe {
        let _ = ShellExecuteW(
            None,
            w!("open"),
            &target,
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}

#[cfg(not(windows))]
fn open_external(target: impl AsRef<std::ffi::OsStr>) {
    let _ = open::that(target);
}

fn main() -> Result<()> {
    use_light_appearance();

    // Install the old light palette before any widget tree is built. windui
    // reads `theme::current()` at construction time (spacing, default colours),
    // and `App::theme` installs it again for every paint frame.
    windui::theme::set_current(std::rc::Rc::new(theme::app_theme()));

    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = launch_options(&args);

    // Single instance: a second long-running app would fight over the proxy port.
    let instance_dir = match data_dir() {
        Some(dir) => dir,
        None => hakimi_core::paths::Paths::default_location()?
            .root()
            .to_path_buf(),
    };
    // Hold the guard for the whole process: dropping it would release the
    // advisory lock and let a second app fight over the proxy port.
    let _instance_lock = match InstanceLock::acquire(&instance_dir) {
        Ok(lock) => lock,
        Err(InstanceLockError::AlreadyRunning { .. }) => {
            if options.autostart {
                return Ok(());
            }
            // A short-lived notice window; windui has no second-window dialog
            // primitive here, so print a clear message and exit.
            eprintln!("hakimi 已经在运行，请使用已打开的窗口");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    let runtime = HakimiRuntime::new(data_dir())?;
    let sweep = Arc::new(SweepState::default());
    let startup = runtime.config().snapshot().advanced.startup.clone();

    if let Err(error) = autostart::apply(startup.auto_start) {
        tracing::warn!(error = %format!("{error:#}"), "could not update the login item");
    }

    let startup_effects = MODEL.with(|m| {
        m.borrow_mut()
            .startup(ui_state::probe_env(&runtime, false), startup.auto_connect)
    });
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

    let mut expanded = HashSet::new();
    if let Ok(id) = std::env::var("HAKIMI_UI_EXPAND") {
        expanded.insert(id);
    }

    let ctx = AppContext {
        runtime: runtime.clone(),
        spawner: spawner.clone(),
        expanded: RefCell::new(expanded),
        sweep: sweep.clone(),
    };

    // The UI is shared between the channel handler and the one-second timer.
    // Signals are Copy handles, so all three views observe the same state.
    let ui = std::rc::Rc::new(Ui {
        signals: UiSignals::default(),
        ctx,
        tx: std::rc::Rc::new(RefCell::new(None)),
        update_in_flight: Arc::new(AtomicBool::new(false)),
        hidden: Arc::new(AtomicBool::new(false)),
        quitting: Arc::new(AtomicBool::new(false)),
        shutdown: shutdown.clone(),
        settings_revision: std::cell::Cell::new(None),
        reclaim_editor_rows: std::cell::Cell::new(false),
    });
    if std::env::var("HAKIMI_UI_PAGE").as_deref() == Ok("1") {
        ui.signals.page.set(1);
    }
    if let Ok(section) = std::env::var("HAKIMI_UI_SECTION") {
        if let Ok(section) = section.parse::<i32>() {
            ui.signals.settings_section.set(section);
        }
    }

    // Install signal values that never come from the refresh path.
    ui.signals
        .cfg_data_dir
        .set(runtime.paths().root().display().to_string());
    ui.signals
        .cfg_version
        .set(env!("CARGO_PKG_VERSION").to_string());
    ui.signals
        .cfg_core_version
        .set(hakimi_core::VERSION.to_string());
    ui.sync_model();
    ui.sync_root();
    ui.refresh();

    // Create the channel first: every UI action, tray click and background
    // result is a message handled on the UI thread by `Ui::handle`.
    //
    // Windows runs in resident mode: there is no main window at all and the UI
    // is an on-demand window whose close destroys it (see `run_resident`).
    // macOS still needs the hidden main window because windui's resident mode
    // is not implemented there yet.
    #[cfg(windows)]
    let mut app = App::resident("hakimi");
    #[cfg(not(windows))]
    let mut app = App::new("hakimi", WINDOW_WIDTH, WINDOW_HEIGHT).hide_on_close();
    app = app
        .icon(assets::window_icon())
        .theme(theme::app_theme())
        .bg(theme::WINDOW_BG)
        // GPU (Direct2D on Windows) first, with automatic fallback to software.
        // Software rasterising the modal's translucent scrim is far too slow.
        .renderer(Renderer::Auto)
        .resizable(false);
    if let Some((x, y)) = centered_position(WINDOW_WIDTH, WINDOW_HEIGHT) {
        app = app.position(x, y);
    }
    let handler_ui = ui.clone();
    let tx = app.channel::<Action>(move |_ctx, action| {
        // With no window kept alive, "show the main window" is a creation
        // request. `.single(main)` focuses an already-open window instead of
        // opening a second one.
        #[cfg(windows)]
        if matches!(action, Action::ShowMain) {
            set_dock_visible(true);
            activate_app();
            handler_ui.refresh();
            _ctx.open_window(main_window_request(handler_ui.clone(), handler_ui.tx()));
            return;
        }
        handler_ui.handle(action);
        // Page/window/onboarding changes must advance the switcher's key.
        handler_ui.sync_root();
    });
    *ui.tx.borrow_mut() = Some(tx.clone());
    if std::env::var("HAKIMI_UI_EDITOR").is_ok() {
        ui.handle(Action::OpenEditor(String::new()));
    }

    // Tray keeps the app alive with the window closed and mirrors key actions.
    app = app.tray(tray::build(
        ui.clone(),
        ui.signals,
        ui.signals.running,
        ui.signals.cfg_auto_start,
        ui.signals.cfg_start_hidden,
        assets::tray_icon_rgba(),
    ));

    // A background thread streams environment probes; results are posted
    // through the channel so the UI thread stays responsive. The daily update
    // check is driven from the same tick, independent of window visibility.
    let probe_stop = Arc::new(AtomicBool::new(false));
    {
        let probe_stop = probe_stop.clone();
        let probe_runtime = runtime.clone();
        let probe_tx = tx.clone();
        let probe_hidden = ui.hidden.clone();
        std::thread::spawn(move || {
            let mut tick = 0u32;
            while !probe_stop.load(Ordering::SeqCst) {
                let hidden = probe_hidden.load(Ordering::Relaxed);
                std::thread::sleep(if hidden {
                    Duration::from_secs(15)
                } else {
                    Duration::from_secs(1)
                });
                if probe_stop.load(Ordering::SeqCst) {
                    break;
                }
                tick = tick.wrapping_add(1);
                let env = ui_state::probe_env(&probe_runtime, !hidden && tick.is_multiple_of(10));
                let _ = probe_tx.send(Action::EnvChanged(env));
            }
        });
    }

    let start_hidden = starts_hidden(options, startup.start_hidden);
    #[cfg(windows)]
    run_resident(app, ui.clone(), tx, start_hidden);
    #[cfg(not(windows))]
    run_windowed(app, ui.clone(), tx, start_hidden);

    probe_stop.store(true, Ordering::SeqCst);
    shutdown.notify_one();
    let _ = background.join();
    Ok(())
}

#[cfg(test)]
mod tests;
