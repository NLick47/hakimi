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
}

fn data_dir() -> Option<PathBuf> {
    std::env::var_os("HAKIMI_DATA_DIR").map(PathBuf::from)
}

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
fn domain_status(state: &str, latency_ms: Option<u64>, group_enabled: bool) -> (String, &'static str, String) {
    if !group_enabled {
        return ("未加速".into(), IDLE_COLOR, "—".into());
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

fn build_snapshot(
    status: &Value,
    config: &Value,
    expanded: &HashSet<String>,
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
            for host in &domains_config {
                let (word, word_hex, latency) = match diagnostics.get(host) {
                    Some(record) if enabled => {
                        let state = text(record, "state");
                        let latency_ms = record.get("latencyMs").and_then(Value::as_u64);
                        match state.as_str() {
                            "failed" => bad += 1,
                            "checking" => checking += 1,
                            "normal" if latency_ms.map(|ms| ms > 150).unwrap_or(false) => slow += 1,
                            _ => {}
                        }
                        domain_status(&state, latency_ms, enabled)
                    }
                    _ => domain_status("", None, enabled),
                };
                rows.push(DomainData {
                    host: host.clone(),
                    status: word,
                    status_hex: word_hex,
                    latency,
                });
            }

            let summary = if !enabled {
                format!("{} 个域名 · 未加速", domains_config.len())
            } else if bad > 0 {
                failed_sites += 1;
                match slow {
                    0 => format!("{} 个域名 · {} 个超时", domains_config.len(), bad),
                    _ => format!(
                        "{} 个域名 · {} 个超时 · {} 个较慢",
                        domains_config.len(),
                        bad,
                        slow
                    ),
                }
            } else if slow > 0 {
                format!("{} 个域名 · {} 个较慢", domains_config.len(), slow)
            } else if checking > 0 {
                format!("{} 个域名 · 检测中", domains_config.len())
            } else {
                format!("{} 个域名 · 全部正常", domains_config.len())
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
                url: format!("https://{primary}/"),
                domains: rows,
            });
        }
    }

    let subtitle = if selected == 0 {
        "未选择站点".to_string()
    } else if failed_sites > 0 {
        format!("已勾选 {selected} 个站点 · {failed_sites} 个异常")
    } else {
        format!("已勾选 {selected} 个站点")
    };

    (sites, subtitle)
}

thread_local! {
    static ASSETS: std::cell::RefCell<HashMap<String, slint::Image>> =
        std::cell::RefCell::new(HashMap::new());
}

fn load_assets() {
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

fn settings_model() -> ModelRc<SettingsEntry> {
    let rows = vec![
        SettingsEntry {
            title: "网络".into(),
            subtitle: "监听端口 · PAC · 加密 DNS".into(),
            icon_kind: 0,
        },
        SettingsEntry {
            title: "证书".into(),
            subtitle: "本地 CA 安装与信任".into(),
            icon_kind: 1,
        },
        SettingsEntry {
            title: "站点管理".into(),
            subtitle: "分组 · 开关 · 域名".into(),
            icon_kind: 2,
        },
        SettingsEntry {
            title: "目录".into(),
            subtitle: "IP 与域名数据源".into(),
            icon_kind: 3,
        },
        SettingsEntry {
            title: "关于".into(),
            subtitle: "版本 · 检查更新".into(),
            icon_kind: 4,
        },
    ];
    ModelRc::new(VecModel::from(rows))
}

fn main() -> Result<()> {
    let app = AppWindow::new()?;
    app.set_settings(settings_model());
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

    let weak = app.as_weak();
    let shutdown = Arc::new(AtomicBool::new(false));
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
        let mut expanded: HashSet<String> = HashSet::new();

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
                }
            }

            let status = runtime.status_json();
            let config = runtime.config_json();
            let (sites, subtitle) = build_snapshot(&status, &config, &expanded);
            let running = runtime.is_started() && !runtime.status().paused();
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
                            url: SharedString::from(site.url),
                            domains: ModelRc::new(VecModel::from(domains)),
                        }
                    })
                    .collect();
                app.set_sites(ModelRc::new(VecModel::from(entries)));
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
