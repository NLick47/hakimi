use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};
use hakimi_core::config::{DomainRule, EchSource, RouteAttempt, RoutePolicy};
use hakimi_core::domain::{host_from_url, normalize_hostname, DomainPattern};
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
    pub(crate) custom: bool,
    pub(crate) domains: Vec<DomainData>,
}

/// UI preset index: 0 auto, 1 direct, 2 ECH, 3 SNI, 4 custom.
pub(crate) fn route_preset_index(route: &RoutePolicy) -> i32 {
    if route == &RoutePolicy::auto() {
        0
    } else if route == &RoutePolicy::direct() {
        1
    } else if route == &RoutePolicy::ech_shared() {
        2
    } else if route == &RoutePolicy::sni(Vec::new()) {
        3
    } else {
        4
    }
}

pub(crate) fn route_from_preset(index: i32) -> Option<RoutePolicy> {
    match index {
        0 => Some(RoutePolicy::auto()),
        1 => Some(RoutePolicy::direct()),
        2 => Some(RoutePolicy::ech_shared()),
        3 => Some(RoutePolicy::sni(Vec::new())),
        _ => None,
    }
}

/// Compact, round-trippable route syntax used by the site editor.
///
/// Examples: `auto`, `direct`, `ech+direct`, `ech:own`, `sni:www.baidu.com+direct`.
pub(crate) fn format_route(route: &RoutePolicy) -> String {
    if route == &RoutePolicy::auto() {
        return "auto".into();
    }
    route
        .attempts
        .iter()
        .map(|attempt| match attempt {
            RouteAttempt::Direct => "direct".to_string(),
            RouteAttempt::Ech {
                ech: EchSource::Own,
            } => "ech:own".to_string(),
            RouteAttempt::Ech {
                ech: EchSource::Shared,
            } => "ech".to_string(),
            RouteAttempt::Sni { sni } if sni.is_empty() => "sni".to_string(),
            RouteAttempt::Sni { sni } => format!("sni:{}", sni.join(",")),
        })
        .collect::<Vec<_>>()
        .join("+")
}

pub(crate) fn parse_route(spec: &str) -> Result<RoutePolicy> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("线路不能为空");
    }
    if spec.eq_ignore_ascii_case("auto") {
        return Ok(RoutePolicy::auto());
    }
    let mut attempts = Vec::new();
    for part in spec.split('+') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let attempt = if part.eq_ignore_ascii_case("direct") {
            RouteAttempt::Direct
        } else if part.eq_ignore_ascii_case("ech") || part.eq_ignore_ascii_case("ech:shared") {
            RouteAttempt::Ech {
                ech: EchSource::Shared,
            }
        } else if part.eq_ignore_ascii_case("ech:own") {
            RouteAttempt::Ech {
                ech: EchSource::Own,
            }
        } else if part.eq_ignore_ascii_case("sni") {
            RouteAttempt::Sni { sni: Vec::new() }
        } else if let Some(hosts) = part.strip_prefix("sni:") {
            let hosts = hosts
                .split(',')
                .map(str::trim)
                .filter(|host| !host.is_empty())
                .map(|host| {
                    normalize_hostname(host)
                        .with_context(|| format!("SNI 主机 {host} 格式不正确"))
                        .map(|host| host.to_ascii_lowercase())
                })
                .collect::<Result<Vec<_>>>()?;
            RouteAttempt::Sni { sni: hosts }
        } else {
            bail!("无法识别的线路 `{part}`");
        };
        attempts.push(attempt);
    }
    if attempts.is_empty() {
        bail!("线路不能为空");
    }
    Ok(RoutePolicy::new(attempts))
}

/// Normalize one host from a manual entry or pasted URL.
pub(crate) fn normalize_domain_host(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("域名不能为空");
    }
    let mut host = match host_from_url(raw) {
        Some(host) => host.to_string(),
        None if raw.contains("://") => bail!("网址 {raw} 无效，请填写域名或 http(s) 网址"),
        None => raw.to_string(),
    }
    .to_ascii_lowercase();
    if !raw.contains("://") {
        host = host
            .split('/')
            .next()
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("")
            .split('#')
            .next()
            .unwrap_or("")
            .to_string();
        if host.matches(':').count() == 1 {
            host = host.split(':').next().unwrap_or("").to_string();
        }
    }
    let host = host.trim_end_matches('.').to_string();
    if host.is_empty() {
        bail!("域名不能为空");
    }
    DomainPattern::parse(&host).with_context(|| format!("域名 {host} 无效"))?;
    Ok(host)
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

            let rules: Vec<DomainRule> = group
                .get("domains")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(|value| {
                            let pattern = text(value, "pattern");
                            if pattern.is_empty() {
                                return None;
                            }
                            let route = value.get("route").and_then(|route| {
                                serde_json::from_value::<RoutePolicy>(route.clone()).ok()
                            });
                            Some(DomainRule { pattern, route })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let domains_config: Vec<String> = rules
                .iter()
                .filter(|rule| !rule.pattern.starts_with("*."))
                .take(12)
                .map(|rule| rule.pattern.clone())
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
                    rules
                        .iter()
                        .find_map(|rule| rule.pattern.strip_prefix("*.").map(ToOwned::to_owned))
                })
                .unwrap_or_else(|| "example.com".into());

            let initial = name.chars().next().map(String::from).unwrap_or_default();
            let id_key = id.clone();
            let tile_hex = tile_color(&id);
            let icon_key = icon_key_for(&id);
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
