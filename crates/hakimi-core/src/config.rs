use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::domain::{normalize_hostname, DomainMatcher, DomainPattern};
use crate::paths::Paths;
use crate::strategy::TlsMode;
use crate::util::{atomic_write_json, decode_key_material, now, read_json};

pub const MAX_GROUPS: usize = 128;
pub const MAX_DOMAINS_PER_GROUP: usize = 512;
pub const MAX_TOTAL_DOMAINS: usize = 5000;
pub const MAX_CUSTOM_DOH: usize = 32;
pub const MAX_ROUTE_ATTEMPTS: usize = 8;
pub const MAX_SNI_HOSTS_PER_ATTEMPT: usize = 16;

/// Default remote IP catalog, shared by the desktop and Android builds.
pub const DEFAULT_CATALOG_IP: &str = "https://gitee.com/mom09/hakimi/raw/master/ips.json";

/// Default remote DoH catalog, shared by the desktop and Android builds.
pub const DEFAULT_CATALOG_DOH: &str = "https://gitee.com/mom09/hakimi/raw/master/doh.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppConfig {
    pub doh: DohConfig,
    pub catalogs: CatalogSources,
    pub proxy: ProxyConfig,
    pub groups: Vec<GroupConfig>,
    /// Monotonic local catalog revision. Incremented when accepted remote IP catalog content
    /// changes; cached IPs remember the revision that produced them.
    pub catalog_version: u64,
    pub advanced: AdvancedConfig,
    pub log: LogConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            doh: DohConfig::default(),
            catalogs: CatalogSources::default(),
            proxy: ProxyConfig::default(),
            groups: default_groups(),
            catalog_version: 0,
            advanced: AdvancedConfig::default(),
            log: LogConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DohConfig {
    pub primary: String,
    pub fallback: String,
    pub custom: Vec<DohEndpoint>,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            primary: "https://doh.cleanbrowsing.org/doh/security-filter/".to_string(),
            fallback: "https://doh.applied-privacy.net/query".to_string(),
            custom: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DohEndpoint {
    pub name: String,
    pub url: String,
    pub bootstrap_ip: Option<IpAddr>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for DohEndpoint {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            bootstrap_ip: None,
            enabled: true,
        }
    }
}

impl DohEndpoint {
    pub fn display_name(&self) -> String {
        if !self.name.trim().is_empty() {
            return self.name.clone();
        }
        url::Url::parse(&self.url)
            .ok()
            .and_then(|url| url.host_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| self.url.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct CatalogSources {
    /// Primary remote IP catalog. Empty disables remote IP catalogs.
    pub ip: String,
    /// Primary remote DoH catalog. Empty disables the remote DoH catalog.
    pub doh: String,
    pub ip_mirrors: Vec<String>,
    pub doh_mirrors: Vec<String>,
    /// Optional Ed25519 public key (base64 or hex, 32 bytes). When set, catalog signatures
    /// are mandatory and a failing signature keeps the previous cache.
    pub signature_public_key: Option<String>,
    /// Optional signature URL. Defaults to `<catalog url>.sig`.
    pub signature_url: Option<String>,
    pub timeout_secs: u64,
}

impl Default for CatalogSources {
    fn default() -> Self {
        Self {
            ip: DEFAULT_CATALOG_IP.to_string(),
            doh: DEFAULT_CATALOG_DOH.to_string(),
            ip_mirrors: Vec::new(),
            doh_mirrors: Vec::new(),
            signature_public_key: None,
            signature_url: None,
            timeout_secs: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    #[default]
    Pac,
    Http,
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyConfig {
    pub mode: ProxyMode,
    pub port: u16,
    pub bind: IpAddr,
    /// Apply/restore the OS proxy setting when the runtime starts/stops.
    pub takeover: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            mode: ProxyMode::Pac,
            port: 8443,
            bind: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            takeover: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct AdvancedConfig {
    /// Fake SNI candidates in order. An empty string means "send no SNI".
    pub fake_sni_candidates: Vec<String>,
    pub max_candidates_per_domain: usize,
    pub ip_timeout_ms: u64,
    pub last_good_days: i64,
    /// Concurrent startup warm-up connections. Higher values shorten cold start but generate
    /// more simultaneous DNS/TLS traffic.
    pub prewarm_concurrency: usize,
    /// How long a selected route (IP + TLS strategy) is reused for new upstream connections.
    /// Established pooled connections are reused independently of this value.
    pub plan_cache_secs: u64,
    /// Idle timeout for pooled upstream HTTP/1.1 and HTTP/2 connections.
    pub upstream_idle_secs: u64,
    /// Maximum idle HTTP/1.1 connections kept per authority. Image hosts in
    /// `http1Hosts` use at least `http1MaxConcurrent` instead, so a following
    /// image burst can reuse the connections it just opened.
    pub upstream_max_idle_per_host: usize,
    /// Host patterns forced to HTTP/1.1 upstream. Image CDNs often throttle a single TCP
    /// connection; independent HTTP/1.1 connections let concurrent images aggregate
    /// bandwidth. Patterns use the same rules as group domains (`*.example.com`).
    pub http1_hosts: Vec<String>,
    /// Maximum concurrent upstream requests (and therefore connections) per `http1Hosts`
    /// authority. Too many simultaneous TLS connections make image loading worse.
    pub http1_max_concurrent: usize,
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            fake_sni_candidates: vec![
                String::new(),
                "www.baidu.com".to_string(),
                "www.cloudflare.com".to_string(),
                "www.bing.com".to_string(),
                "www.apple.com".to_string(),
            ],
            max_candidates_per_domain: 8,
            ip_timeout_ms: 2_000,
            last_good_days: 7,
            prewarm_concurrency: 8,
            plan_cache_secs: 600,
            // A lean background profile: idle connections are the biggest
            // per-connection cost, and the proxy sits idle most of the time.
            upstream_idle_secs: 120,
            upstream_max_idle_per_host: 8,
            http1_hosts: vec![
                // pximg origins advertise h2 but throttle per connection; parallel h1
                // connections each get their own TCP window and are faster in aggregate.
                "*.pximg.net".to_string(),
                "img.poipiku.com".to_string(),
                "cdn.poipiku.com".to_string(),
            ],
            http1_max_concurrent: 32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LogConfig {
    pub level: String,
    pub format: LogFormat,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Text,
        }
    }
}

/// Where the ECHConfigList for an ECH attempt may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EchSource {
    /// Only the domain's own HTTPS RR.
    Own,
    /// The domain's own HTTPS RR, then Cloudflare's shared `cloudflare-ech.com` config.
    #[default]
    Shared,
}

/// One ordered TLS attempt for a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum RouteAttempt {
    Direct,
    Ech {
        #[serde(default)]
        ech: EchSource,
    },
    Sni {
        /// Fake SNI hosts. Empty means the global `advanced.fakeSniCandidates` list.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sni: Vec<String>,
    },
}

impl RouteAttempt {
    pub fn mode(&self) -> TlsMode {
        match self {
            Self::Direct => TlsMode::Direct,
            Self::Ech { .. } => TlsMode::Ech,
            Self::Sni { .. } => TlsMode::FakeSni,
        }
    }

    pub fn ech_source(&self) -> Option<EchSource> {
        match self {
            Self::Ech { ech } => Some(*ech),
            _ => None,
        }
    }

    pub fn sni_hosts(&self) -> Option<&[String]> {
        match self {
            Self::Sni { sni } => Some(sni),
            _ => None,
        }
    }
}

/// Ordered attempts for one domain. The engine never appends an implicit
/// fallback: what is listed here is exactly what will be tried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutePolicy {
    pub attempts: Vec<RouteAttempt>,
}

impl RoutePolicy {
    pub fn new(attempts: Vec<RouteAttempt>) -> Self {
        Self { attempts }
    }

    pub fn auto() -> Self {
        Self::new(vec![
            RouteAttempt::Direct,
            RouteAttempt::Ech {
                ech: EchSource::Own,
            },
            RouteAttempt::Sni { sni: Vec::new() },
        ])
    }

    pub fn direct() -> Self {
        Self::new(vec![RouteAttempt::Direct])
    }

    pub fn ech_shared() -> Self {
        Self::new(vec![
            RouteAttempt::Ech {
                ech: EchSource::Shared,
            },
            RouteAttempt::Direct,
        ])
    }

    pub fn sni(hosts: Vec<String>) -> Self {
        Self::new(vec![RouteAttempt::Sni { sni: hosts }, RouteAttempt::Direct])
    }

    pub fn contains_mode(&self, mode: TlsMode) -> bool {
        self.attempts.iter().any(|attempt| attempt.mode() == mode)
    }

    pub fn is_direct_only(&self) -> bool {
        self.attempts
            .iter()
            .all(|attempt| matches!(attempt, RouteAttempt::Direct))
    }
}

impl Default for RoutePolicy {
    fn default() -> Self {
        Self::auto()
    }
}

/// A domain pattern plus an optional override of the site's default route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRule {
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<RoutePolicy>,
}

impl DomainRule {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            route: None,
        }
    }

    pub fn routed(pattern: impl Into<String>, route: RoutePolicy) -> Self {
        Self {
            pattern: pattern.into(),
            route: Some(route),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GroupConfig {
    pub id: String,
    pub name: String,
    pub domains: Vec<DomainRule>,
    pub enabled: bool,
    /// Canonical page opened by the UI's "visit" button. `None` falls back to
    /// the first exact routed domain, which is the right default for custom
    /// groups but not for presets such as Pixiv (bare `pixiv.net` is not the
    /// canonical `www.pixiv.net` host).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// Route used by domain rules without an explicit route.
    #[serde(default = "RoutePolicy::auto")]
    pub default_route: RoutePolicy,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            domains: Vec::new(),
            enabled: true,
            homepage: None,
            default_route: RoutePolicy::auto(),
        }
    }
}

impl GroupConfig {
    /// First exact domain, used for startup checks and group status.
    pub fn primary_domain(&self) -> Option<&str> {
        self.domains
            .iter()
            .find(|rule| !rule.pattern.starts_with("*."))
            .map(|rule| rule.pattern.as_str())
    }

    /// First `limit` exact domains, skipping wildcards.
    pub fn probe_domains(&self, limit: usize) -> Vec<&str> {
        self.domains
            .iter()
            .filter(|rule| !rule.pattern.starts_with("*."))
            .take(limit)
            .map(|rule| rule.pattern.as_str())
            .collect()
    }

    pub fn exact_domains(&self) -> impl Iterator<Item = &str> {
        self.domains
            .iter()
            .filter(|rule| !rule.pattern.starts_with("*."))
            .map(|rule| rule.pattern.as_str())
    }

    pub fn patterns(&self) -> impl Iterator<Item = &str> {
        self.domains.iter().map(|rule| rule.pattern.as_str())
    }

    /// Resolve the route for an already-normalized host (lowercase, no root dot).
    ///
    /// Exact patterns win over wildcards; among wildcards the longest suffix
    /// wins. A rule without a route inherits `default_route`.
    pub fn route_for(&self, host: &str) -> &RoutePolicy {
        let host = host.trim_end_matches('.');
        let mut wildcard: Option<(usize, &DomainRule)> = None;
        for rule in &self.domains {
            if let Some(suffix) = rule.pattern.strip_prefix("*.") {
                if host_matches_suffix(host, suffix) {
                    let labels = suffix.bytes().filter(|byte| *byte == b'.').count() + 1;
                    if wildcard.is_none_or(|(best, _)| labels > best) {
                        wildcard = Some((labels, rule));
                    }
                }
            } else if host.eq_ignore_ascii_case(rule.pattern.as_str()) {
                return rule.route.as_ref().unwrap_or(&self.default_route);
            }
        }
        wildcard
            .map(|(_, rule)| rule.route.as_ref().unwrap_or(&self.default_route))
            .unwrap_or(&self.default_route)
    }

    pub fn domain(&self, pattern: &str) -> Option<&DomainRule> {
        self.domains
            .iter()
            .find(|rule| rule.pattern.eq_ignore_ascii_case(pattern))
    }

    pub fn route_modes(&self, host: &str) -> Vec<TlsMode> {
        self.route_for(host)
            .attempts
            .iter()
            .map(RouteAttempt::mode)
            .collect()
    }

    /// True when any route in this group may fall back to Cloudflare's shared
    /// ECH config. Startup uses this to prefetch it once per group.
    pub fn uses_shared_ech(&self) -> bool {
        let uses_shared = |route: &RoutePolicy| {
            route
                .attempts
                .iter()
                .any(|attempt| attempt.ech_source() == Some(EchSource::Shared))
        };
        uses_shared(&self.default_route)
            || self
                .domains
                .iter()
                .filter_map(|rule| rule.route.as_ref())
                .any(uses_shared)
    }
}

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    let host = host.as_bytes();
    let suffix = suffix.as_bytes();
    host.len() > suffix.len()
        && host[host.len() - suffix.len() - 1] == b'.'
        && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn default_true() -> bool {
    true
}

pub fn default_groups() -> Vec<GroupConfig> {
    fn group(
        id: &str,
        name: &str,
        domains: Vec<DomainRule>,
        default_route: RoutePolicy,
        enabled: bool,
        homepage: &str,
    ) -> GroupConfig {
        GroupConfig {
            id: id.to_string(),
            name: name.to_string(),
            domains,
            enabled,
            homepage: Some(homepage.to_string()),
            default_route,
        }
    }

    let plain = |pattern: &str| DomainRule::new(pattern);
    let ech = |pattern: &str| DomainRule::routed(pattern, RoutePolicy::ech_shared());

    vec![
        group(
            "github",
            "GitHub",
            vec![
                plain("github.com"),
                plain("api.github.com"),
                // The default certificate on the shared GitHub edge does not
                // cover gist; api.github.com makes it serve the *.github.com
                // wildcard, which does.
                DomainRule::routed(
                    "gist.github.com",
                    RoutePolicy::sni(vec!["api.github.com".to_string()]),
                ),
                plain("codeload.github.com"),
                plain("raw.githubusercontent.com"),
                plain("*.githubusercontent.com"),
                plain("*.githubassets.com"),
            ],
            RoutePolicy::sni(Vec::new()),
            true,
            "https://github.com/",
        ),
        group(
            "pixiv",
            "Pixiv",
            vec![
                ech("pixiv.net"),
                ech("www.pixiv.net"),
                ech("*.pixiv.net"),
                plain("i.pximg.net"),
                plain("s.pximg.net"),
                plain("booth.pximg.net"),
                plain("*.pximg.net"),
            ],
            RoutePolicy::sni(Vec::new()),
            true,
            "https://www.pixiv.net/",
        ),
        group(
            "ao3",
            "AO3",
            vec![
                plain("archiveofourown.org"),
                plain("www.archiveofourown.org"),
                plain("*.archiveofourown.org"),
            ],
            RoutePolicy::sni(Vec::new()),
            true,
            "https://archiveofourown.org/",
        ),
        group(
            "eh",
            "E-Hentai",
            vec![
                plain("e-hentai.org"),
                // ExHentai only answers with a valid certificate through ECH;
                // plain direct or fake SNI fails certificate validation.
                ech("exhentai.org"),
                plain("*.e-hentai.org"),
                ech("*.exhentai.org"),
                plain("ehgt.org"),
                plain("*.ehgt.org"),
            ],
            RoutePolicy::sni(Vec::new()),
            true,
            "https://e-hentai.org/",
        ),
        group(
            "hitomi",
            "Hitomi",
            vec![
                plain("hitomi.la"),
                plain("*.hitomi.la"),
                plain("ltn.gold-usergeneratedcontent.net"),
                plain("*.gold-usergeneratedcontent.net"),
            ],
            RoutePolicy::auto(),
            true,
            "https://hitomi.la/",
        ),
        group(
            "nhentai",
            "nhentai",
            vec![plain("nhentai.net"), plain("*.nhentai.net")],
            RoutePolicy::auto(),
            true,
            "https://nhentai.net/",
        ),
        group(
            "hanime",
            "Hanime",
            vec![
                plain("hanime.tv"),
                plain("www.hanime.tv"),
                plain("*.hanime.tv"),
            ],
            RoutePolicy::auto(),
            true,
            "https://hanime.tv/",
        ),
        group(
            "steam",
            "Steam",
            vec![
                plain("store.steampowered.com"),
                plain("steamcommunity.com"),
                plain("*.steamcommunity.com"),
                plain("*.steampowered.com"),
                plain("*.steamstatic.com"),
                plain("steamcdn-a.akamaihd.net"),
            ],
            RoutePolicy::sni(Vec::new()),
            true,
            "https://store.steampowered.com/",
        ),
        group(
            "poipiku",
            "Poipiku",
            vec![
                plain("poipiku.com"),
                plain("img.poipiku.com"),
                plain("cdn.poipiku.com"),
                plain("*.poipiku.com"),
            ],
            RoutePolicy::auto(),
            true,
            "https://poipiku.com/",
        ),
    ]
}

impl AppConfig {
    pub fn validate(&self) -> Result<()> {
        if self.proxy.port == 0 {
            bail!("proxy.port must not be 0");
        }
        if !self.proxy.bind.is_loopback() {
            bail!(
                "proxy.bind must be a loopback address ({} is not)",
                self.proxy.bind
            );
        }
        if !(1..=60).contains(&self.catalogs.timeout_secs) {
            bail!("catalogs.timeoutSecs must be between 1 and 60");
        }
        if !(1..=8).contains(&self.advanced.max_candidates_per_domain) {
            bail!("advanced.maxCandidatesPerDomain must be between 1 and 8");
        }
        if !(200..=10_000).contains(&self.advanced.ip_timeout_ms) {
            bail!("advanced.ipTimeoutMs must be between 200 and 10000");
        }
        if !(1..=30).contains(&self.advanced.last_good_days) {
            bail!("advanced.lastGoodDays must be between 1 and 30");
        }
        if !(1..=32).contains(&self.advanced.prewarm_concurrency) {
            bail!("advanced.prewarmConcurrency must be between 1 and 32");
        }
        if !(10..=86_400).contains(&self.advanced.plan_cache_secs) {
            bail!("advanced.planCacheSecs must be between 10 and 86400");
        }
        if !(10..=86_400).contains(&self.advanced.upstream_idle_secs) {
            bail!("advanced.upstreamIdleSecs must be between 10 and 86400");
        }
        if !(1..=128).contains(&self.advanced.upstream_max_idle_per_host) {
            bail!("advanced.upstreamMaxIdlePerHost must be between 1 and 128");
        }
        if self.advanced.http1_hosts.len() > 128 {
            bail!("advanced.http1Hosts supports at most 128 entries");
        }
        for pattern in &self.advanced.http1_hosts {
            DomainPattern::parse(pattern)
                .with_context(|| format!("invalid advanced.http1Hosts entry `{pattern}`"))?;
        }
        if !(1..=32).contains(&self.advanced.http1_max_concurrent) {
            bail!("advanced.http1MaxConcurrent must be between 1 and 32");
        }
        if self.advanced.fake_sni_candidates.len() > 16 {
            bail!("advanced.fakeSniCandidates supports at most 16 entries");
        }
        for candidate in &self.advanced.fake_sni_candidates {
            if !candidate.is_empty() {
                normalize_hostname(candidate)
                    .with_context(|| format!("invalid fake SNI candidate `{candidate}`"))?;
            }
        }

        validate_doh_url(&self.doh.primary, "doh.primary")?;
        validate_doh_url(&self.doh.fallback, "doh.fallback")?;
        if self.doh.custom.len() > MAX_CUSTOM_DOH {
            bail!("at most {MAX_CUSTOM_DOH} custom DoH endpoints are supported");
        }
        let mut custom_urls = std::collections::HashSet::new();
        for endpoint in &self.doh.custom {
            validate_doh_url(&endpoint.url, "doh.custom[].url")?;
            if !custom_urls.insert(endpoint.url.trim().to_string()) {
                bail!("duplicate custom DoH URL `{}`", endpoint.url);
            }
            if endpoint.name.trim().is_empty() && endpoint.url.trim().is_empty() {
                bail!("custom DoH entry needs a name or URL");
            }
        }

        for (configured, label) in [
            (Some(self.catalogs.ip.as_str()), "catalogs.ip"),
            (Some(self.catalogs.doh.as_str()), "catalogs.doh"),
        ] {
            if let Some(url) = configured {
                if !url.trim().is_empty() {
                    validate_catalog_url(url, label)?;
                }
            }
        }
        for url in self
            .catalogs
            .ip_mirrors
            .iter()
            .chain(self.catalogs.doh_mirrors.iter())
        {
            validate_catalog_url(url, "catalogs mirrors")?;
        }
        if let Some(key) = &self.catalogs.signature_public_key {
            let bytes = decode_key_material(key)
                .context("catalogs.signaturePublicKey is not valid base64/hex")?;
            if bytes.len() != 32 {
                bail!(
                    "catalogs.signaturePublicKey must decode to 32 bytes (got {})",
                    bytes.len()
                );
            }
        }
        if let Some(url) = &self.catalogs.signature_url {
            validate_catalog_url(url, "catalogs.signatureUrl")?;
        }

        if self.groups.len() > MAX_GROUPS {
            bail!("at most {MAX_GROUPS} groups are supported");
        }
        let mut ids = std::collections::HashSet::new();
        let mut total_domains = 0usize;
        for group in &self.groups {
            validate_group_id(&group.id)?;
            if !ids.insert(group.id.clone()) {
                bail!("duplicate group id `{}`", group.id);
            }
            if group.name.trim().is_empty() {
                bail!("group `{}` has an empty name", group.id);
            }
            if let Some(homepage) = &group.homepage {
                let raw = homepage.trim();
                if !raw.is_empty() {
                    let parsed = url::Url::parse(raw)
                        .with_context(|| format!("group `{}` homepage is not a URL", group.id))?;
                    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                        bail!(
                            "group `{}` homepage must be an absolute http(s) URL",
                            group.id
                        );
                    }
                }
            }
            if group.domains.is_empty() {
                bail!("group `{}` has no domains", group.id);
            }
            if group.domains.len() > MAX_DOMAINS_PER_GROUP {
                bail!(
                    "group `{}` has more than {MAX_DOMAINS_PER_GROUP} domains",
                    group.id
                );
            }
            if !group
                .domains
                .iter()
                .any(|rule| !rule.pattern.starts_with("*."))
            {
                bail!(
                    "group `{}` needs at least one exact domain to act as its primary domain",
                    group.id
                );
            }
            validate_route(
                &group.default_route,
                &format!("group `{}` defaultRoute", group.id),
            )?;
            let mut patterns = std::collections::HashSet::new();
            for rule in &group.domains {
                let pattern = DomainPattern::parse(&rule.pattern)
                    .with_context(|| format!("group `{}`", group.id))?;
                if !patterns.insert(pattern.as_str().to_string()) {
                    bail!(
                        "group `{}` contains duplicate domain `{}`",
                        group.id,
                        rule.pattern
                    );
                }
                if let Some(route) = &rule.route {
                    validate_route(
                        route,
                        &format!("group `{}` domain `{}`", group.id, rule.pattern),
                    )?;
                }
            }
            total_domains += group.domains.len();
        }
        if total_domains > MAX_TOTAL_DOMAINS {
            bail!("more than {MAX_TOTAL_DOMAINS} domains across all groups");
        }

        if !matches!(
            self.log.level.to_ascii_lowercase().as_str(),
            "trace" | "debug" | "info" | "warn" | "error" | "off"
        ) {
            bail!("log.level must be one of trace/debug/info/warn/error/off");
        }
        Ok(())
    }

    pub fn matcher(&self) -> Result<DomainMatcher> {
        DomainMatcher::from_groups(&self.groups)
    }

    pub fn group(&self, id: &str) -> Option<&GroupConfig> {
        self.groups.iter().find(|group| group.id == id)
    }

    pub fn group_mut(&mut self, id: &str) -> Option<&mut GroupConfig> {
        self.groups.iter_mut().find(|group| group.id == id)
    }

    pub fn enabled_groups(&self) -> impl Iterator<Item = &GroupConfig> {
        self.groups.iter().filter(|group| group.enabled)
    }
}

fn validate_route(route: &RoutePolicy, label: &str) -> Result<()> {
    if route.attempts.is_empty() {
        bail!("{label} needs at least one attempt");
    }
    if route.attempts.len() > MAX_ROUTE_ATTEMPTS {
        bail!("{label} supports at most {MAX_ROUTE_ATTEMPTS} attempts");
    }
    for (index, attempt) in route.attempts.iter().enumerate() {
        if let RouteAttempt::Sni { sni } = attempt {
            if sni.len() > MAX_SNI_HOSTS_PER_ATTEMPT {
                bail!(
                    "{label} attempt {} supports at most {MAX_SNI_HOSTS_PER_ATTEMPT} SNI hosts",
                    index + 1
                );
            }
            for host in sni {
                if !host.trim().is_empty() {
                    normalize_hostname(host).with_context(|| {
                        format!(
                            "{label} attempt {} has an invalid SNI host `{host}`",
                            index + 1
                        )
                    })?;
                }
            }
        }
    }
    Ok(())
}

pub fn validate_group_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 {
        bail!("group id must be between 1 and 64 characters");
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("group id `{id}` may only contain ASCII letters, digits, `-` and `_`");
    }
    Ok(())
}

pub fn validate_doh_url(raw: &str, label: &str) -> Result<()> {
    let url = url::Url::parse(raw.trim()).with_context(|| format!("{label} is not a URL"))?;
    if url.scheme() != "https" {
        bail!("{label} must use HTTPS (got `{}`)", url.scheme());
    }
    if url.host_str().is_none() {
        bail!("{label} has no host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("{label} must not contain credentials");
    }
    Ok(())
}

pub fn validate_catalog_url(raw: &str, label: &str) -> Result<()> {
    let url = url::Url::parse(raw.trim()).with_context(|| format!("{label} is not a URL"))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        bail!("{label} must use HTTP or HTTPS (got `{}`)", url.scheme());
    }
    if url.host_str().is_none() {
        bail!("{label} has no host");
    }
    Ok(())
}

/// Thread-safe configuration holder that keeps the derived domain matcher in sync.
pub struct ConfigManager {
    path: PathBuf,
    inner: RwLock<Inner>,
    revision: AtomicU64,
}

struct Inner {
    /// Shared immutably: `snapshot()` hands out an `Arc`, so the hot path
    /// (every new connection) never deep-clones the whole configuration.
    config: Arc<AppConfig>,
    matcher: Arc<DomainMatcher>,
}

impl ConfigManager {
    pub fn load_or_create(paths: &Paths) -> Result<Self> {
        paths.ensure()?;
        let path = paths.config_file();
        let config = if path.exists() {
            match read_json::<AppConfig>(&path) {
                Ok(config) => config,
                Err(error) => {
                    // The schema changed while the app is still unreleased. Keep
                    // the old file for inspection instead of refusing to start.
                    let backup = path.with_file_name(format!(
                        "config.invalid-{}.json",
                        now().format("%Y%m%d-%H%M%S")
                    ));
                    let _ = std::fs::rename(&path, &backup);
                    tracing::warn!(
                        error = %error,
                        backup = %backup.display(),
                        "config.json does not match this build; regenerating defaults"
                    );
                    let config = AppConfig::default();
                    atomic_write_json(&path, &config)?;
                    config
                }
            }
        } else {
            let config = AppConfig::default();
            atomic_write_json(&path, &config)?;
            config
        };
        Self::new(path, config)
    }

    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let config = read_json::<AppConfig>(&path)?;
        Self::new(path, config)
    }

    fn new(path: PathBuf, config: AppConfig) -> Result<Self> {
        config.validate()?;
        let matcher = Arc::new(config.matcher()?);
        Ok(Self {
            path,
            inner: RwLock::new(Inner {
                config: Arc::new(config),
                matcher,
            }),
            revision: AtomicU64::new(1),
        })
    }

    /// Monotonically increases on every mutation, so pollers can skip
    /// re-reading the configuration when nothing changed.
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn snapshot(&self) -> Arc<AppConfig> {
        Arc::clone(&self.inner.read().config)
    }

    /// Snapshot the config together with the revision that describes it.
    /// Reading both while holding the inner lock prevents a poller from
    /// caching an old domain set under a newer revision.
    pub fn snapshot_with_revision(&self) -> (Arc<AppConfig>, u64) {
        let inner = self.inner.read();
        (
            Arc::clone(&inner.config),
            self.revision.load(Ordering::Relaxed),
        )
    }

    pub fn matcher(&self) -> Arc<DomainMatcher> {
        Arc::clone(&self.inner.read().matcher)
    }

    /// Snapshot the config and matcher under one read lock. Routing needs both
    /// on every cold connection; taking the lock twice is unnecessary.
    pub fn snapshot_and_matcher(&self) -> (Arc<AppConfig>, Arc<DomainMatcher>) {
        let inner = self.inner.read();
        (Arc::clone(&inner.config), Arc::clone(&inner.matcher))
    }

    pub fn update(&self, config: AppConfig) -> Result<()> {
        config.validate()?;
        let matcher = Arc::new(config.matcher()?);
        atomic_write_json(&self.path, &config)?;
        let mut guard = self.inner.write();
        guard.config = Arc::new(config);
        guard.matcher = matcher;
        // Publish the revision while the new config is still write-locked, so
        // `snapshot_with_revision` can never pair a new config with an old
        // revision (or vice versa).
        self.revision.fetch_add(1, Ordering::Relaxed);
        drop(guard);
        Ok(())
    }

    pub fn mutate<F>(&self, f: F) -> Result<AppConfig>
    where
        F: FnOnce(&mut AppConfig) -> Result<()>,
    {
        let mut config = (*self.snapshot()).clone();
        f(&mut config)?;
        self.update(config.clone())?;
        Ok(config)
    }

    pub fn set_group_enabled(&self, id: &str, enabled: bool) -> Result<AppConfig> {
        self.mutate(|config| {
            let group = config
                .group_mut(id)
                .with_context(|| format!("unknown group `{id}`"))?;
            group.enabled = enabled;
            Ok(())
        })
    }

    pub fn set_group_default_route(&self, id: &str, route: RoutePolicy) -> Result<AppConfig> {
        self.mutate(|config| {
            let group = config
                .group_mut(id)
                .with_context(|| format!("unknown group `{id}`"))?;
            group.default_route = route;
            Ok(())
        })
    }

    pub fn upsert_group(&self, group: GroupConfig) -> Result<AppConfig> {
        self.mutate(|config| {
            if let Some(existing) = config.group_mut(&group.id) {
                *existing = group;
            } else {
                config.groups.push(group);
            }
            Ok(())
        })
    }

    pub fn remove_group(&self, id: &str) -> Result<AppConfig> {
        self.mutate(|config| {
            let before = config.groups.len();
            config.groups.retain(|group| group.id != id);
            if config.groups.len() == before {
                bail!("unknown group `{id}`");
            }
            Ok(())
        })
    }

    pub fn set_catalog_version(&self, version: u64) -> Result<AppConfig> {
        self.mutate(|config| {
            config.catalog_version = version;
            Ok(())
        })
    }

    pub fn add_custom_doh(&self, endpoint: DohEndpoint) -> Result<AppConfig> {
        self.mutate(|config| {
            config.doh.custom.push(endpoint);
            Ok(())
        })
    }

    pub fn remove_custom_doh(&self, url: &str) -> Result<AppConfig> {
        self.mutate(|config| {
            let before = config.doh.custom.len();
            config.doh.custom.retain(|entry| entry.url != url);
            if config.doh.custom.len() == before {
                bail!("unknown custom DoH URL `{url}`");
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate_and_match_document() {
        let config = AppConfig::default();
        config.validate().unwrap();
        assert_eq!(config.groups.len(), 9);
        let eh = config.group("eh").unwrap();
        assert!(eh.enabled);
        assert!(config.groups.iter().all(|group| group.enabled));
        assert_eq!(
            config.group("poipiku").unwrap().default_route.attempts[0].mode(),
            TlsMode::Direct
        );
        // The three adult sites ship enabled with their own CDN domains.
        let hitomi = config.group("hitomi").unwrap();
        assert!(hitomi.enabled);
        assert!(hitomi
            .domains
            .iter()
            .any(|rule| rule.pattern == "*.gold-usergeneratedcontent.net"));
        assert!(config
            .group("nhentai")
            .unwrap()
            .domains
            .iter()
            .any(|rule| rule.pattern == "*.nhentai.net"));
        assert!(config
            .group("hanime")
            .unwrap()
            .domains
            .iter()
            .any(|rule| rule.pattern == "*.hanime.tv"));
        assert_eq!(
            config.group("pixiv").unwrap().homepage.as_deref(),
            Some("https://www.pixiv.net/")
        );
        assert!(config.groups.iter().all(|group| group
            .homepage
            .as_deref()
            .is_some_and(|url| url.starts_with("https://"))));
        assert!(config
            .group("pixiv")
            .unwrap()
            .domains
            .iter()
            .any(|rule| rule.pattern == "s.pximg.net"));
        assert!(config
            .advanced
            .http1_hosts
            .iter()
            .any(|pattern| pattern == "*.pximg.net"));
        assert_eq!(
            config.group("github").unwrap().primary_domain(),
            Some("github.com")
        );
        assert_eq!(
            config.group("pixiv").unwrap().probe_domains(3),
            vec!["pixiv.net", "www.pixiv.net", "i.pximg.net"]
        );
        let matcher = config.matcher().unwrap();
        assert_eq!(
            matcher.match_host("raw.githubusercontent.com"),
            Some("github")
        );
        assert_eq!(matcher.match_host("i.pximg.net"), Some("pixiv"));
    }

    #[test]
    fn per_domain_routes_select_ech_fake_sni_or_direct() {
        let config = AppConfig::default();
        let pixiv = config.group("pixiv").unwrap();
        assert_eq!(
            pixiv.route_for("www.pixiv.net").attempts[0].mode(),
            TlsMode::Ech
        );
        assert_eq!(
            pixiv.route_for("pixiv.net").attempts[0].mode(),
            TlsMode::Ech
        );
        // pximg hosts inherit the site's fake-SNI default.
        assert_eq!(
            pixiv.route_for("i.pximg.net").attempts[0].mode(),
            TlsMode::FakeSni
        );
        assert_eq!(
            pixiv.route_for("s.pximg.net").attempts[0].mode(),
            TlsMode::FakeSni
        );
        // Exact rules beat the broader wildcard.
        assert_eq!(
            pixiv.route_for("accounts.pixiv.net").attempts[0].mode(),
            TlsMode::Ech
        );
        let ao3 = config.group("ao3").unwrap();
        assert_eq!(
            ao3.route_for("archiveofourown.org").attempts[0].mode(),
            TlsMode::FakeSni
        );
        let eh = config.group("eh").unwrap();
        assert_eq!(
            eh.route_for("e-hentai.org").attempts[0].mode(),
            TlsMode::FakeSni
        );
        assert_eq!(
            eh.route_for("exhentai.org").attempts[0].mode(),
            TlsMode::Ech
        );
        assert_eq!(
            eh.route_for("www.exhentai.org").attempts[0].mode(),
            TlsMode::Ech
        );
        let github = config.group("github").unwrap();
        assert_eq!(
            github.route_for("raw.githubusercontent.com").attempts[0].mode(),
            TlsMode::FakeSni
        );
        // gist needs the api.github.com SNI to receive a certificate that
        // covers gist.github.com.
        assert_eq!(
            github.route_for("gist.github.com").attempts[0],
            RouteAttempt::Sni {
                sni: vec!["api.github.com".to_string()]
            }
        );
        // Hosts that answer directly start with a direct attempt so the
        // common case does not pay for a failed fake-SNI handshake.
        for id in ["hitomi", "nhentai", "hanime", "poipiku"] {
            assert_eq!(
                config.group(id).unwrap().default_route.attempts[0].mode(),
                TlsMode::Direct,
                "{id} should prefer direct"
            );
        }
        let steam = config.group("steam").unwrap();
        assert_eq!(
            steam.route_for("store.steampowered.com").attempts[0].mode(),
            TlsMode::FakeSni
        );
        assert_eq!(
            steam.route_for("steamcommunity.com").attempts[0].mode(),
            TlsMode::FakeSni
        );
    }

    #[test]
    fn route_policy_roundtrips_as_attempts() {
        let route = RoutePolicy::new(vec![
            RouteAttempt::Ech {
                ech: EchSource::Shared,
            },
            RouteAttempt::Sni {
                sni: vec!["www.baidu.com".into()],
            },
            RouteAttempt::Direct,
        ]);
        let text = serde_json::to_string(&route).unwrap();
        assert!(text.contains(r#""mode":"ech""#));
        assert!(text.contains(r#""ech":"shared""#));
        let decoded: RoutePolicy = serde_json::from_str(&text).unwrap();
        assert_eq!(decoded, route);
    }

    #[test]
    fn incompatible_config_is_backed_up_and_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(
            paths.config_file(),
            br#"{"groups":[{"id":"old","domains":["old.example"],"strategy":"auto"}]}"#,
        )
        .unwrap();

        let manager = ConfigManager::load_or_create(&paths).unwrap();
        assert!(manager.snapshot().group("old").is_none());
        assert!(manager.snapshot().group("pixiv").is_some());
        let backups: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("config.invalid-")
            })
            .collect();
        assert_eq!(
            backups.len(),
            1,
            "the old config must be kept for inspection"
        );
    }

    #[test]
    fn rejects_external_bind() {
        let mut config = AppConfig::default();
        config.proxy.bind = "0.0.0.0".parse().unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_groups() {
        let mut config = AppConfig::default();
        let mut duplicate = config.groups[0].clone();
        duplicate.domains = vec![DomainRule::new("example.com")];
        config.groups.push(duplicate);
        assert!(config.validate().is_err());
    }

    /// Number of groups in the shipped defaults, derived instead of hard-coded
    /// so adding a site does not break unrelated tests.
    fn config_defaults() -> usize {
        AppConfig::default().groups.len()
    }

    #[test]
    fn config_roundtrip_uses_camel_case() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let manager = ConfigManager::load_or_create(&paths).unwrap();
        let text = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(text.contains("\"catalogVersion\""));
        assert!(text.contains("\"maxCandidatesPerDomain\""));
        let manager2 = ConfigManager::load(paths.config_file()).unwrap();
        assert_eq!(manager2.snapshot().groups.len(), config_defaults());
        manager.set_group_enabled("eh", false).unwrap();
        assert!(manager2.snapshot().group("eh").unwrap().enabled); // other holders are not auto-reloaded
        let manager3 = ConfigManager::load(paths.config_file()).unwrap();
        assert!(!manager3.snapshot().group("eh").unwrap().enabled);
    }

    #[test]
    fn rejects_invalid_domains() {
        let mut config = AppConfig::default();
        config.groups[0]
            .domains
            .push(DomainRule::new("bad domain.com"));
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_non_http_homepages() {
        let mut config = AppConfig::default();
        config.groups[0].homepage = Some("file:///etc/passwd".into());
        assert!(config.validate().is_err());
        config.groups[0].homepage = Some("https://example.com/".into());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn default_pixiv_group_covers_login_subdomains() {
        let config = AppConfig::default();
        let matcher = config.matcher().unwrap();
        assert_eq!(matcher.match_host("accounts.pixiv.net"), Some("pixiv"));
        assert_eq!(matcher.match_host("oauth.secure.pixiv.net"), Some("pixiv"));
        assert_eq!(matcher.match_host("app-api.pixiv.net"), Some("pixiv"));
    }
}
