use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

use hakimi_core::strategy::Strategy;
use serde_json::Value;

use crate::ui_state::{apply_settle, SettlePhase, BAD_COLOR, IDLE_COLOR, OK_COLOR, SLOW_COLOR};

pub(crate) fn text(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(Value::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

// Plain-data snapshots cross the thread boundary; Slint types are built on the UI thread.

#[derive(Clone, PartialEq)]
pub(crate) struct DomainData {
    pub(crate) host: String,
    pub(crate) status: String,
    pub(crate) status_hex: &'static str,
    pub(crate) latency: String,
}

#[derive(Clone, PartialEq)]
pub(crate) struct SiteData {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) initial: String,
    pub(crate) icon_key: String,
    pub(crate) tile_hex: &'static str,
    pub(crate) summary: String,
    pub(crate) summary_hex: &'static str,
    pub(crate) enabled: bool,
    pub(crate) open: bool,
    pub(crate) first: bool,
    pub(crate) last: bool,
    pub(crate) url: String,
    pub(crate) strategy: i32,
    pub(crate) sni: String,
    pub(crate) custom: bool,
    pub(crate) domains: Vec<DomainData>,
}

/// Strategy index used by the UI: 0 auto, 1 direct, 2 ech, 3 fake SNI.
pub(crate) fn strategy_index(raw: &str) -> i32 {
    match raw {
        "direct" => 1,
        "ech" => 2,
        "sni" => 3,
        _ => 0,
    }
}

pub(crate) fn strategy_from_index(index: i32) -> Strategy {
    match index {
        1 => Strategy::Direct,
        2 => Strategy::Ech,
        3 => Strategy::FakeSni,
        _ => Strategy::Auto,
    }
}

/// Direct is not offered in the editor: `auto` already tries direct first, so a
/// group pinned to direct is shown as auto and widened on the next save.
pub(crate) fn editor_strategy_index(strategy: Strategy) -> i32 {
    match strategy {
        Strategy::Ech => 2,
        Strategy::FakeSni => 3,
        Strategy::Auto | Strategy::Direct => 0,
    }
}

/// Built-in group ids. Anything else was added by the user and may be removed
/// from the UI.
pub(crate) fn builtin_group_ids() -> std::collections::HashSet<String> {
    hakimi_core::config::default_groups()
        .into_iter()
        .map(|group| group.id)
        .collect()
}

/// Muted brand-ish tiles for groups without a real favicon.
const TILE_PALETTE: [&str; 8] = [
    "#5B7A9D", "#4E9E6F", "#C2913A", "#B0685E", "#7D6B9E", "#3F8C8C", "#96693F", "#8A6A8A",
];

pub(crate) fn tile_color(id: &str) -> &'static str {
    let hash: usize = id.bytes().map(|b| b as usize).sum();
    TILE_PALETTE[hash % TILE_PALETTE.len()]
}

/// Domain status as (word, color hex, latency text) from a diagnostics record.
pub(crate) fn domain_status(
    state: &str,
    latency_ms: Option<u64>,
    group_enabled: bool,
) -> (String, &'static str, String) {
    if !group_enabled {
        return ("未选择".into(), IDLE_COLOR, "—".into());
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

/// Builds the raw per-site rows from the status/config JSON. Summaries here
/// are the live values, before the settle/hysteresis pass.
pub(crate) fn build_sites(
    status: &Value,
    config: &Value,
    expanded: &HashSet<String>,
) -> (Vec<SiteData>, usize) {
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

            let raw_domains: Vec<String> = group
                .get("domains")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let domains_config: Vec<String> = raw_domains
                .iter()
                .filter(|host| !host.starts_with("*."))
                .take(12)
                .cloned()
                .collect();

            let mut rows: Vec<DomainData> = Vec::new();
            let mut slow = 0usize;
            let mut bad = 0usize;
            let mut checking = 0usize;
            let mut tested = 0usize;
            for host in &domains_config {
                let (word, word_hex, latency) = match diagnostics.get(host) {
                    Some(record) if enabled => {
                        let state = text(record, "state");
                        if state == "paused" || state == "disabled" {
                            // A routing bypass is not a health result.
                            domain_status("", None, enabled)
                        } else {
                            tested += 1;
                            let latency_ms = record.get("latencyMs").and_then(Value::as_u64);
                            // Health is an observation, not a function of the
                            // global switch: a paused app still knows its sites.
                            match state.as_str() {
                                "failed" => bad += 1,
                                "checking" => checking += 1,
                                "normal" if latency_ms.map(|ms| ms > 150).unwrap_or(false) => {
                                    slow += 1
                                }
                                _ => {}
                            }
                            domain_status(&state, latency_ms, enabled)
                        }
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

            let count = domains_config.len();
            let (summary, summary_hex) = if !enabled {
                (format!("{count} 个域名 · 未选择"), IDLE_COLOR)
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
                (format!("{count} 个域名 · 待检测"), IDLE_COLOR)
            } else {
                (format!("{count} 个域名 · 全部正常"), OK_COLOR)
            };

            let primary = domains_config
                .first()
                .cloned()
                .or_else(|| {
                    raw_domains
                        .iter()
                        .find_map(|host| host.strip_prefix("*.").map(ToOwned::to_owned))
                })
                .unwrap_or_else(|| "example.com".into());

            let initial = name.chars().next().map(String::from).unwrap_or_default();
            let id_key = id.clone();
            let tile_hex = tile_color(&id);
            let icon_key = icon_key_for(&id);
            let strategy = strategy_index(&text(group, "strategy"));
            let sni = text(group, "sni");
            let custom = !builtins.contains(&id);
            // The preset/catalog owns the canonical landing page; custom groups
            // fall back to their first exact routed domain.
            let homepage = group
                .get("homepage")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|url| {
                    let lower = url.to_ascii_lowercase();
                    lower.starts_with("https://") || lower.starts_with("http://")
                })
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| format!("https://{primary}/"));

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
                url: homepage,
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

    (sites, selected)
}

/// Applies the display hysteresis and derives the subtitle. Takes the raw rows
/// by value so an unchanged refresh tick can clone the cached rows and reuse
/// the expensive part (the status snapshot) without re-reading it.
pub(crate) fn finish_snapshot(
    mut sites: Vec<SiteData>,
    selected: usize,
    master_running: bool,
    starting: bool,
    settle: Option<SettlePhase>,
) -> (Vec<SiteData>, String) {
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

    let all_untested = sites
        .iter()
        .filter(|site| site.enabled)
        .all(|site| site.domains.iter().all(|domain| domain.status == "—"));
    let subtitle = if selected == 0 {
        "未选择站点，勾选后即可加速".to_string()
    } else if matches!(settle, Some(SettlePhase::Sweeping)) {
        let total: usize = sites
            .iter()
            .filter(|site| site.enabled)
            .map(|site| site.domains.len())
            .sum();
        let pending = sites
            .iter()
            .filter(|site| site.enabled)
            .flat_map(|site| &site.domains)
            .filter(|domain| domain.status == "检测中")
            .count();
        if pending == 0 {
            format!("正在检测 {total} 个域名 · 结果会自动更新")
        } else {
            format!("正在检测 {pending}/{total} 个域名 · 结果会自动更新")
        }
    } else if all_untested {
        // Selection never starts a test: point at the explicit action instead
        // of leaving "待检测" unexplained.
        format!("已选择 {selected} 个站点 · 点击检测选中获取健康状态")
    } else if failed_sites > 0 {
        if starting || master_running {
            format!("正在加速 {selected} 个站点 · {failed_sites} 个异常")
        } else {
            format!("已选择 {selected} 个站点 · {failed_sites} 个异常 · 加速已暂停")
        }
    } else if starting || master_running {
        format!("正在加速 {selected} 个站点")
    } else {
        format!("已选择 {selected} 个站点 · 加速已暂停")
    };

    (sites, subtitle)
}

/// Convenience wrapper used by tests and the offscreen `--shot` renderer.
pub(crate) fn build_snapshot(
    status: &Value,
    config: &Value,
    expanded: &HashSet<String>,
    master_running: bool,
    starting: bool,
    settle: Option<SettlePhase>,
) -> (Vec<SiteData>, String) {
    let (sites, selected) = build_sites(status, config, expanded);
    finish_snapshot(sites, selected, master_running, starting, settle)
}

/// Lifecycle of a manual 测速 sweep. The flags are read by the refresh path
/// (`phase`) and written by the sweep task; owning them in one place keeps the
/// display policy inputs explicit instead of ambient.
#[derive(Default)]
pub(crate) struct SweepState {
    pub(crate) running: AtomicBool,
    pub(crate) commit_once: AtomicBool,
}

impl SweepState {
    pub(crate) fn phase(&self) -> SettlePhase {
        if self.running.load(Ordering::SeqCst) {
            SettlePhase::Sweeping
        } else if self.commit_once.swap(false, Ordering::SeqCst) {
            SettlePhase::Commit
        } else {
            SettlePhase::Tracking
        }
    }
}

/// Bundled site logos, matched against a group id. Exact ids and `<key>-…`
/// slugs count; a bare `contains` would hand the E-Hentai logo to any domain
/// that happens to have "eh" in the middle of its slug.
pub(crate) const SITE_ICONS: [&str; 10] = [
    "pixiv", "hitomi", "poipiku", "booth", "steam", "github", "ao3", "eh", "hanime", "nhentai",
];

pub(crate) fn icon_key_for(id: &str) -> String {
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
