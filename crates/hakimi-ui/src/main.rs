use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hakimi_core::runtime::HakimiRuntime;
use serde_json::Value;
use slint::{Color, ModelRc, SharedString, VecModel, Weak};

slint::include_modules!();


enum Command {
    ToggleMaster,
    ToggleGroup(String, bool),
    SelectAll(bool),
    ToggleExpand(String),
    ProbeAll,
    Open(String),
    SettingsAction(i32),
}

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

fn text(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(Value::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

const OK_COLOR: &str = "#6B7684";
const SLOW_COLOR: &str = "#C2913A";
const BAD_COLOR: &str = "#C05B5B";
const IDLE_COLOR: &str = "#8A95A2";

fn color(hex: &str) -> Color {
    let value = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0x88_88_88);
    Color::from_argb_encoded(0xFF00_0000 | value)
}

// Plain-data snapshots cross the thread boundary; Slint types are built on the UI thread.

struct DomainData {
    host: String,
    status: String,
    status_hex: &'static str,
    latency: String,
}

struct SiteData {
    id: String,
    name: String,
    initial: String,
    icon_key: String,
    tile_hex: &'static str,
    summary: String,
    enabled: bool,
    open: bool,
    first: bool,
    last: bool,
    url: String,
    domains: Vec<DomainData>,
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
    let mut failed_sites = 0usize;

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
            let summary = if !enabled {
                format!("{count} 个域名 · 未选择")
            } else if !master_running {
                format!("{count} 个域名 · 已暂停")
            } else if bad > 0 {
                failed_sites += 1;
                match (bad == count, slow) {
                    (true, _) => format!("{count} 个域名 · 全部超时"),
                    (false, 0) => format!("{count} 个域名 · {bad} 个超时"),
                    (false, n) => format!("{count} 个域名 · {bad} 个超时 · {n} 个较慢"),
                }
            } else if slow > 0 {
                if slow == count {
                    format!("{count} 个域名 · 全部较慢")
                } else {
                    format!("{count} 个域名 · {slow} 个较慢")
                }
            } else if checking > 0 {
                format!("{count} 个域名 · 检测中")
            } else if tested == 0 {
                format!("{count} 个域名 · 未检测")
            } else {
                format!("{count} 个域名 · 全部正常")
            };

            let primary = domains_config
                .first()
                .cloned()
                .unwrap_or_else(|| "example.com".into());

            let initial = name.chars().next().map(String::from).unwrap_or_default();
            let id_key = id.clone();
            let tile_hex = tile_color(&id);
            let icon_key = ["pixiv", "eh", "hitomi", "booth"]
                .into_iter()
                .find(|key| id.contains(key))
                .unwrap_or_default()
                .to_string();

            sites.push(SiteData {
                icon_key,
                id,
                name,
                initial,
                tile_hex,
                summary,
                enabled,
                open: expanded.contains(&id_key),
                first: false,
                last: false,
                url: format!("https://{primary}/"),
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

    let subtitle = if selected == 0 {
        "未选择站点，勾选后即可加速".to_string()
    } else if failed_sites > 0 {
        if master_running {
            format!("正在加速 {selected} 个站点 · {failed_sites} 个异常")
        } else {
            format!("已选择 {selected} 个站点 · {failed_sites} 个异常")
        }
    } else if master_running {
        format!("正在加速 {selected} 个站点")
    } else {
        format!("已选择 {selected} 个站点")
    };

    (sites, subtitle)
}

thread_local! {
    static ASSETS: std::cell::RefCell<HashMap<String, slint::Image>> =
        std::cell::RefCell::new(HashMap::new());
}

pub(crate) fn load_assets() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");
    ASSETS.with(|assets| {
        let mut map = assets.borrow_mut();
        for key in ["pixiv", "eh", "hitomi", "booth"] {
            if let Ok(image) = slint::Image::load_from_path(&dir.join(format!("{key}.png"))) {
                map.insert(key.to_string(), image);
            }
        }
    });
}

/// Settings sections. The certificate row mirrors the live CA status so the
/// user can trust the local CA without leaving the app.
pub(crate) fn settings_rows(status: &Value) -> Vec<SettingsEntry> {
    let ca = status.get("ca");
    let installed = ca
        .and_then(|ca| ca.get("installed"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let supported = ca
        .and_then(|ca| ca.get("supported"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let present = ca
        .and_then(|ca| ca.get("present"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let (cert_subtitle, cert_action, cert_kind, cert_tone) = if !supported {
        ("当前系统不支持自动安装".to_string(), String::new(), 0, 0)
    } else if installed {
        ("已安装并受信任".to_string(), "移除".to_string(), 2, 1)
    } else if present {
        ("已生成，尚未信任".to_string(), "安装".to_string(), 1, 0)
    } else {
        ("尚未生成本地证书".to_string(), String::new(), 0, 0)
    };

    let mut rows = vec![
        SettingsEntry {
            title: "网络".into(),
            subtitle: "监听端口 · PAC · 加密 DNS".into(),
            icon_kind: 0,
            action_label: SharedString::new(),
            action_kind: 0,
            action_tone: 0,
            first: false,
            last: false,
        },
        SettingsEntry {
            title: "证书".into(),
            subtitle: SharedString::from(cert_subtitle),
            icon_kind: 1,
            action_label: SharedString::from(cert_action),
            action_kind: cert_kind,
            action_tone: cert_tone,
            first: false,
            last: false,
        },
        SettingsEntry {
            title: "站点管理".into(),
            subtitle: "分组 · 开关 · 域名".into(),
            icon_kind: 2,
            action_label: SharedString::new(),
            action_kind: 0,
            action_tone: 0,
            first: false,
            last: false,
        },
        SettingsEntry {
            title: "目录".into(),
            subtitle: "IP 与域名数据源".into(),
            icon_kind: 3,
            action_label: SharedString::new(),
            action_kind: 0,
            action_tone: 0,
            first: false,
            last: false,
        },
        SettingsEntry {
            title: "关于".into(),
            subtitle: "版本 · 检查更新".into(),
            icon_kind: 4,
            action_label: SharedString::new(),
            action_kind: 0,
            action_tone: 0,
            first: false,
            last: true,
        },
    ];
    let total = rows.len();
    for (index, row) in rows.iter_mut().enumerate() {
        row.first = index == 0;
        row.last = index + 1 == total;
    }
    rows
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
        "groups": [
            { "id": "pixiv", "name": "Pixiv", "enabled": true,
              "domains": ["www.pixiv.net", "i.pximg.net", "s.pximg.net", "booth.pximg.net", "novel.pixiv.net"] },
            { "id": "e-hentai", "name": "E-Hentai", "enabled": true,
              "domains": ["e-hentai.org", "forums.e-hentai.org", "exhentai.org"] },
            { "id": "hitomi", "name": "Hitomi", "enabled": true,
              "domains": ["hitomi.la", "ltn.gold-usergeneratedcontent.net"] },
            { "id": "github", "name": "GitHub", "enabled": true,
              "domains": ["github.com", "raw.githubusercontent.com", "api.github.com"] },
            { "id": "ao3", "name": "AO3", "enabled": true,
              "domains": ["ao3.org", "archiveofourown.org"] },
            { "id": "steam", "name": "Steam", "enabled": true,
              "domains": ["steamcommunity.com", "store.steampowered.com"] },
            { "id": "poipiku", "name": "Poipiku", "enabled": true,
              "domains": ["poipiku.me", "poipiku.art"] },
            { "id": "nhentai", "name": "nhentai", "enabled": false,
              "domains": ["nhentai.net"] },
            { "id": "bangumi", "name": "Bangumi", "enabled": false,
              "domains": ["bgm.tv"] }
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

    let (sites, subtitle) = build_snapshot(&status, &config, &expanded, running);
    let entries: Vec<SiteEntry> = sites
        .into_iter()
        .map(|site| {
            let domains: Vec<DomainEntry> = site
                .domains
                .into_iter()
                .map(|row| DomainEntry {
                    host: SharedString::from(row.host),
                    status: SharedString::from(row.status),
                    status_color: color(row.status_hex),
                    latency: SharedString::from(row.latency),
                })
                .collect();
            SiteEntry {
                id: SharedString::from(site.id),
                name: SharedString::from(site.name),
                icon: ASSETS
                    .with(|assets| assets.borrow().get(&site.icon_key).cloned())
                    .unwrap_or_default(),
                initial: SharedString::from(site.initial),
                tile_color: color(site.tile_hex),
                summary: SharedString::from(site.summary),
                enabled: site.enabled,
                open: site.open,
                first: site.first,
                last: site.last,
                url: SharedString::from(site.url),
                domains: ModelRc::new(VecModel::from(domains)),
            }
        })
        .collect();

    let settings: Vec<SettingsEntry> = settings_rows(&status)
        .into_iter()
        .map(|entry| SettingsEntry {
            title: entry.title,
            subtitle: entry.subtitle,
            icon_kind: entry.icon_kind,
            action_label: entry.action_label,
            action_kind: entry.action_kind,
            action_tone: entry.action_tone,
            first: entry.first,
            last: entry.last,
        })
        .collect();

    app.set_sites(ModelRc::new(VecModel::from(entries)));
    app.set_settings(ModelRc::new(VecModel::from(settings)));
    app.set_status_subtitle(SharedString::from(subtitle));
    app.set_running(running);
    app.set_page(page);
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

    use_light_appearance();
    let app = AppWindow::new()?;
    load_assets();
    let (tx, rx) = channel::<Command>();

    app.on_toggle_master({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Command::ToggleMaster);
        }
    });
    app.on_toggle_group({
        let tx = tx.clone();
        move |id, enabled| {
            let _ = tx.send(Command::ToggleGroup(id.to_string(), enabled));
        }
    });
    app.on_select_all({
        let tx = tx.clone();
        move |enabled| {
            let _ = tx.send(Command::SelectAll(enabled));
        }
    });
    app.on_toggle_open({
        let tx = tx.clone();
        move |id| {
            let _ = tx.send(Command::ToggleExpand(id.to_string()));
        }
    });
    app.on_probe_all({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Command::ProbeAll);
        }
    });
    app.on_open_site({
        let tx = tx.clone();
        move |url| {
            let _ = tx.send(Command::Open(url.to_string()));
        }
    });
    app.on_settings_action({
        let tx = tx.clone();
        move |kind| {
            let _ = tx.send(Command::SettingsAction(kind as i32));
        }
    });

    let weak = app.as_weak();
    let shutdown = Arc::new(AtomicBool::new(false));
    if std::env::var("HAKIMI_UI_PAGE").as_deref() == Ok("1") {
        app.set_page(1);
    }
    let worker_shutdown = shutdown.clone();
    let worker = std::thread::spawn(move || {
        if let Err(error) = worker_loop(rx, weak, worker_shutdown) {
            eprintln!("hakimi-ui worker failed: {error:#}");
        }
    });

    app.run()?;
    // Stop the runtime so it can restore the OS proxy settings it took over.
    shutdown.store(true, Ordering::SeqCst);
    let _ = worker.join();
    Ok(())
}

fn worker_loop(
    rx: Receiver<Command>,
    weak: Weak<AppWindow>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let runtime = HakimiRuntime::new(data_dir())?;
        runtime.clone().start().await?;
        runtime.resume();
        let mut expanded: HashSet<String> = HashSet::new();
        if let Ok(id) = std::env::var("HAKIMI_UI_EXPAND") {
            expanded.insert(id);
        }

        while !shutdown.load(Ordering::SeqCst) {
            while let Ok(command) = rx.try_recv() {
                match command {
                    Command::ToggleMaster => {
                        if runtime.is_started() && !runtime.status().paused() {
                            runtime.pause();
                        } else {
                            runtime.resume();
                        }
                    }
                    Command::ToggleGroup(id, enabled) => {
                        let _ = runtime.set_group_enabled(&id, enabled);
                    }
                    Command::SelectAll(enabled) => {
                        let _ = runtime.config().mutate(|config| {
                            for group in &mut config.groups {
                                group.enabled = enabled;
                            }
                            Ok(())
                        });
                    }
                    Command::ToggleExpand(id) => {
                        if !expanded.remove(&id) {
                            expanded.insert(id);
                        }
                    }
                    Command::ProbeAll => {
                        let config = runtime.config().snapshot();
                        let semaphore = Arc::new(tokio::sync::Semaphore::new(8));
                        let mut seen = HashSet::new();
                        for group in config.enabled_groups() {
                            for host in group.exact_domains() {
                                if !seen.insert(host.to_string()) {
                                    continue;
                                }
                                let permit = semaphore.clone().acquire_owned().await?;
                                let runtime = runtime.clone();
                                let host = host.to_string();
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let _ = runtime.probe_domain(&host).await;
                                });
                            }
                        }
                    }
                    Command::Open(url) => {
                        let _ = open::that(url);
                    }
                    Command::SettingsAction(kind) => match kind {
                        1 => {
                            // Installing the CA may raise a system password prompt.
                            let _ = runtime.ca_install();
                        }
                        2 => {
                            let _ = runtime.ca_uninstall();
                        }
                        _ => {}
                    },
                }
            }

            let status = runtime.status_json();
            let config = runtime.config_json();
            let running = runtime.is_started() && !runtime.status().paused();
            let (sites, subtitle) = build_snapshot(&status, &config, &expanded, running);
            let handle = weak.clone();
            // Slint types hold an Rc, so they are built on the UI thread from plain data.
            let _ = slint::invoke_from_event_loop(move || {
                let Some(app) = handle.upgrade() else {
                    return;
                };
                let entries: Vec<SiteEntry> = sites
                    .into_iter()
                    .map(|site| {
                        let domains: Vec<DomainEntry> = site
                            .domains
                            .into_iter()
                            .map(|row| DomainEntry {
                                host: SharedString::from(row.host),
                                status: SharedString::from(row.status),
                                status_color: color(row.status_hex),
                                latency: SharedString::from(row.latency),
                            })
                            .collect();
                        SiteEntry {
                            id: SharedString::from(site.id),
                            name: SharedString::from(site.name),
                            icon: ASSETS
                                .with(|assets| assets.borrow().get(&site.icon_key).cloned())
                                .unwrap_or_default(),
                            initial: SharedString::from(site.initial),
                            tile_color: color(site.tile_hex),
                            summary: SharedString::from(site.summary),
                            enabled: site.enabled,
                            open: site.open,
                            first: site.first,
                            last: site.last,
                            url: SharedString::from(site.url),
                            domains: ModelRc::new(VecModel::from(domains)),
                        }
                    })
                    .collect();
                let settings = settings_rows(&status);
                app.set_sites(ModelRc::new(VecModel::from(entries)));
                app.set_settings(ModelRc::new(VecModel::from(settings)));
                app.set_status_subtitle(SharedString::from(subtitle));
                app.set_running(running);
            });

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(1200)) => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }

        runtime.clone().stop().await?;
        Ok(())
    })
}
