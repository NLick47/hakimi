use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::domain::{normalize_hostname, DomainMatcher, DomainPattern};
use crate::paths::Paths;
use crate::strategy::Strategy;
use crate::util::{atomic_write_json, decode_key_material, read_json};

pub const MAX_GROUPS: usize = 128;
pub const MAX_DOMAINS_PER_GROUP: usize = 512;
pub const MAX_TOTAL_DOMAINS: usize = 5000;
pub const MAX_CUSTOM_DOH: usize = 32;
/// Bumped when `default_groups()` gains a domain that existing configs must
/// also receive. Each bump needs a matching step in `migrate_defaults`.
pub const CURRENT_DEFAULTS_VERSION: u32 = 1;

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
    /// Built-in defaults revision this config has been migrated to.
    pub defaults_version: u32,
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
            defaults_version: CURRENT_DEFAULTS_VERSION,
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
            ip: String::new(),
            doh: String::new(),
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
    /// Maximum idle HTTP/1.1 connections kept per authority.
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GroupConfig {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub strategy: Strategy,
    pub enabled: bool,
    pub sni: Option<String>,
    pub experimental: bool,
    /// Canonical page opened by the UI's "visit" button. `None` falls back to
    /// the first exact routed domain, which is the right default for custom
    /// groups but not for presets such as Pixiv (bare `pixiv.net` is not the
    /// canonical `www.pixiv.net` host).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// Use Cloudflare's shared ECH config (cloudflare-ech.com) when the domain itself
    /// publishes no ECHConfig. Needed for Cloudflare-fronted sites such as www.pixiv.net.
    pub ech_shared: bool,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            domains: Vec::new(),
            strategy: Strategy::Auto,
            enabled: true,
            sni: None,
            experimental: false,
            homepage: None,
            ech_shared: false,
        }
    }
}

impl GroupConfig {
    /// First exact domain, used for startup checks and group status.
    pub fn primary_domain(&self) -> Option<&str> {
        self.domains
            .iter()
            .find(|domain| !domain.starts_with("*."))
            .map(String::as_str)
    }

    /// First `limit` exact domains, skipping wildcards.
    pub fn probe_domains(&self, limit: usize) -> Vec<&str> {
        self.domains
            .iter()
            .filter(|domain| !domain.starts_with("*."))
            .take(limit)
            .map(String::as_str)
            .collect()
    }

    pub fn exact_domains(&self) -> impl Iterator<Item = &str> {
        self.domains
            .iter()
            .filter(|domain| !domain.starts_with("*."))
            .map(String::as_str)
    }
}

fn default_true() -> bool {
    true
}

pub fn default_groups() -> Vec<GroupConfig> {
    fn group(
        id: &str,
        name: &str,
        domains: &[&str],
        strategy: Strategy,
        enabled: bool,
        experimental: bool,
        homepage: &str,
    ) -> GroupConfig {
        GroupConfig {
            id: id.to_string(),
            name: name.to_string(),
            domains: domains.iter().map(|d| d.to_string()).collect(),
            strategy,
            enabled,
            sni: None,
            experimental,
            homepage: Some(homepage.to_string()),
            ech_shared: false,
        }
    }
    vec![
        group(
            "github",
            "GitHub",
            &[
                "github.com",
                "api.github.com",
                "raw.githubusercontent.com",
                "*.githubusercontent.com",
                "*.githubassets.com",
            ],
            Strategy::Auto,
            true,
            false,
            "https://github.com/",
        ),
        {
            let mut group = group(
                "pixiv",
                "Pixiv",
                &[
                    "pixiv.net",
                    "www.pixiv.net",
                    "*.pixiv.net",
                    "i.pximg.net",
                    "s.pximg.net",
                    "booth.pximg.net",
                    "*.pximg.net",
                ],
                Strategy::Auto,
                true,
                false,
                "https://www.pixiv.net/",
            );
            group.ech_shared = true;
            group
        },
        group(
            "ao3",
            "AO3",
            &["archiveofourown.org", "*.archiveofourown.org"],
            Strategy::Auto,
            true,
            false,
            "https://archiveofourown.org/",
        ),
        group(
            "eh",
            "E-Hentai",
            &[
                "e-hentai.org",
                "exhentai.org",
                "*.e-hentai.org",
                "*.exhentai.org",
                "ehgt.org",
                "*.ehgt.org",
            ],
            Strategy::Auto,
            false,
            true,
            "https://e-hentai.org/",
        ),
        group(
            "hitomi",
            "Hitomi",
            &[
                "hitomi.la",
                "*.hitomi.la",
                "ltn.gold-usergeneratedcontent.net",
                "*.gold-usergeneratedcontent.net",
            ],
            Strategy::Auto,
            true,
            false,
            "https://hitomi.la/",
        ),
        group(
            "nhentai",
            "nhentai",
            &["nhentai.net", "*.nhentai.net"],
            Strategy::Auto,
            true,
            false,
            "https://nhentai.net/",
        ),
        group(
            "hanime",
            "Hanime",
            &["hanime.tv", "www.hanime.tv", "*.hanime.tv"],
            Strategy::Auto,
            true,
            false,
            "https://hanime.tv/",
        ),
        group(
            "steam",
            "Steam",
            &[
                "store.steampowered.com",
                "steamcommunity.com",
                "*.steamcommunity.com",
                "*.steampowered.com",
                "*.steamstatic.com",
            ],
            Strategy::Auto,
            true,
            false,
            "https://store.steampowered.com/",
        ),
        group(
            "poipiku",
            "Poipiku",
            &[
                "poipiku.com",
                "img.poipiku.com",
                "cdn.poipiku.com",
                "*.poipiku.com",
            ],
            Strategy::Direct,
            true,
            false,
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
                    let parsed = url::Url::parse(raw).with_context(|| {
                        format!("group `{}` homepage is not a URL", group.id)
                    })?;
                    if !matches!(parsed.scheme(), "http" | "https")
                        || parsed.host_str().is_none()
                    {
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
            if !group.domains.iter().any(|domain| !domain.starts_with("*.")) {
                bail!(
                    "group `{}` needs at least one exact domain to act as its primary domain",
                    group.id
                );
            }
            let mut patterns = std::collections::HashSet::new();
            for raw in &group.domains {
                let pattern =
                    DomainPattern::parse(raw).with_context(|| format!("group `{}`", group.id))?;
                if !patterns.insert(pattern.as_str().to_string()) {
                    bail!("group `{}` contains duplicate domain `{raw}`", group.id);
                }
            }
            if let Some(sni) = &group.sni {
                if !sni.is_empty() {
                    normalize_hostname(sni).with_context(|| {
                        format!("group `{}` has an invalid SNI override", group.id)
                    })?;
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

/// Append built-in groups a config predates and fill in newly introduced
/// built-in metadata (currently the homepage URL), keeping custom groups and
/// explicit user values untouched. Returns how many entries changed.
fn merge_missing_defaults(config: &mut AppConfig) -> usize {
    let mut changed = 0;
    for mut default_group in default_groups() {
        match config
            .groups
            .iter_mut()
            .find(|group| group.id == default_group.id)
        {
            Some(existing) => {
                let has_homepage = existing
                    .homepage
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|url| !url.is_empty());
                if !has_homepage {
                    if let Some(homepage) = default_group.homepage.take() {
                        existing.homepage = Some(homepage);
                        changed += 1;
                    }
                }
            }
            None => {
                config.groups.push(default_group);
                changed += 1;
            }
        }
    }
    changed
}

/// Apply domain additions that built-in groups gained after this config was
/// written. `merge_missing_defaults` only handles whole groups; domains need a
/// version marker because a user may have edited a built-in group's domain
/// list on purpose.
fn migrate_defaults(config: &mut AppConfig) -> usize {
    let mut changed = 0;
    if config.defaults_version < 1 {
        // The pixiv login/OAuth flow runs on subdomains that the old preset
        // did not intercept (it listed only the bare and www hosts).
        if let Some(group) = config.groups.iter_mut().find(|group| group.id == "pixiv") {
            if !group.domains.iter().any(|domain| domain == "*.pixiv.net") {
                group.domains.push("*.pixiv.net".to_string());
                changed += 1;
            }
        }
        config.defaults_version = CURRENT_DEFAULTS_VERSION;
        changed += 1;
    }
    changed
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
        let mut config = if path.exists() {
            read_json::<AppConfig>(&path).with_context(|| {
                format!(
                    "failed to parse {}; fix or remove the file to regenerate defaults",
                    path.display()
                )
            })?
        } else {
            let config = AppConfig::default();
            atomic_write_json(&path, &config)?;
            config
        };
        // A config written by an older build lacks sites that have since been
        // added to the defaults. Built-in groups cannot be deleted from the UI,
        // so a missing id means "predates this site", not "user removed it".
        let restored = merge_missing_defaults(&mut config);
        // Domain additions cannot use the same "missing id" test: users may
        // edit a built-in group's domain list, so a version marker decides
        // which migrations have already run.
        let migrated = migrate_defaults(&mut config);
        if restored + migrated > 0 {
            tracing::info!(
                restored,
                migrated,
                "updated built-in site defaults in the config"
            );
            atomic_write_json(&path, &config)?;
        }
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
            inner: RwLock::new(Inner { config: Arc::new(config), matcher }),
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
        drop(guard);
        self.revision.fetch_add(1, Ordering::Relaxed);
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

    pub fn set_group_strategy(&self, id: &str, strategy: Strategy) -> Result<AppConfig> {
        self.mutate(|config| {
            let group = config
                .group_mut(id)
                .with_context(|| format!("unknown group `{id}`"))?;
            group.strategy = strategy;
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
        assert!(!eh.enabled);
        assert!(eh.experimental);
        assert_eq!(config.group("poipiku").unwrap().strategy, Strategy::Direct);
        // The three adult sites ship enabled with their own CDN domains.
        let hitomi = config.group("hitomi").unwrap();
        assert!(hitomi.enabled);
        assert!(hitomi
            .domains
            .iter()
            .any(|domain| domain == "*.gold-usergeneratedcontent.net"));
        assert!(config
            .group("nhentai")
            .unwrap()
            .domains
            .iter()
            .any(|domain| domain == "*.nhentai.net"));
        assert!(config
            .group("hanime")
            .unwrap()
            .domains
            .iter()
            .any(|domain| domain == "*.hanime.tv"));
        assert!(config.group("pixiv").unwrap().ech_shared);
        assert_eq!(
            config.group("pixiv").unwrap().homepage.as_deref(),
            Some("https://www.pixiv.net/")
        );
        assert!(config
            .groups
            .iter()
            .all(|group| group
                .homepage
                .as_deref()
                .is_some_and(|url| url.starts_with("https://"))));
        assert!(config
            .group("pixiv")
            .unwrap()
            .domains
            .iter()
            .any(|domain| domain == "s.pximg.net"));
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
    fn group_ech_shared_roundtrip() {
        let group: GroupConfig = serde_json::from_str(
            r#"{"id":"p","name":"P","domains":["pixiv.net"],"echShared":true}"#,
        )
        .unwrap();
        assert!(group.ech_shared);
        let text = serde_json::to_string(&group).unwrap();
        assert!(text.contains("\"echShared\":true"));
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
        duplicate.domains = vec!["example.com".into()];
        config.groups.push(duplicate);
        assert!(config.validate().is_err());
    }

    /// Number of groups in the shipped defaults, derived instead of hard-coded
    /// so adding a site does not break unrelated tests.
    fn config_defaults() -> usize {
        AppConfig::default().groups.len()
    }

    #[test]
    fn merge_adds_only_missing_builtin_sites() {
        let mut config = AppConfig::default();
        config.groups.retain(|group| group.id != "nhentai");
        let mut custom = GroupConfig::default();
        custom.id = "custom".into();
        custom.name = "Custom".into();
        custom.domains = vec!["custom.example".into()];
        config.groups.push(custom);
        // Older configs predate the homepage field: fill it from defaults too.
        config.group_mut("github").unwrap().homepage = None;

        assert_eq!(merge_missing_defaults(&mut config), 2);
        assert!(config.group("nhentai").is_some());
        assert_eq!(
            config.group("github").unwrap().homepage.as_deref(),
            Some("https://github.com/")
        );
        assert_eq!(
            config
                .groups
                .iter()
                .filter(|group| group.id == "custom")
                .count(),
            1,
            "custom groups must keep working"
        );

        // Idempotent: a second pass adds nothing.
        assert_eq!(merge_missing_defaults(&mut config), 0);
    }

    #[test]
    fn an_old_config_gains_new_sites_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let mut old = AppConfig::default();
        old.groups
            .retain(|group| !matches!(group.id.as_str(), "hitomi" | "nhentai" | "hanime"));
        old.group_mut("github").unwrap().homepage = None;
        atomic_write_json(&paths.config_file(), &old).unwrap();

        let manager = ConfigManager::load_or_create(&paths).unwrap();
        let snapshot = manager.snapshot();
        for id in ["hitomi", "nhentai", "hanime"] {
            assert!(snapshot.group(id).is_some(), "{id} should be restored");
        }
        assert_eq!(
            snapshot.group("github").unwrap().homepage.as_deref(),
            Some("https://github.com/"),
            "existing built-ins gain newly introduced homepage defaults"
        );

        // The merge is persisted, so the next load starts from the new list.
        let reloaded = ConfigManager::load_or_create(&paths).unwrap();
        assert_eq!(reloaded.snapshot().groups.len(), AppConfig::default().groups.len());
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
        manager.set_group_enabled("eh", true).unwrap();
        assert!(!manager2.snapshot().group("eh").unwrap().enabled); // other holders are not auto-reloaded
        let manager3 = ConfigManager::load(paths.config_file()).unwrap();
        assert!(manager3.snapshot().group("eh").unwrap().enabled);
    }

    #[test]
    fn rejects_invalid_domains() {
        let mut config = AppConfig::default();
        config.groups[0].domains.push("bad domain.com".into());
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
        assert_eq!(
            matcher.match_host("oauth.secure.pixiv.net"),
            Some("pixiv")
        );
        assert_eq!(matcher.match_host("app-api.pixiv.net"), Some("pixiv"));
    }

    #[test]
    fn older_configs_gain_pixiv_login_domains() {
        let mut config = AppConfig::default();
        config.defaults_version = 0;
        let pixiv = config
            .groups
            .iter_mut()
            .find(|group| group.id == "pixiv")
            .unwrap();
        pixiv.domains.retain(|domain| domain != "*.pixiv.net");

        assert_eq!(migrate_defaults(&mut config), 2);
        assert_eq!(config.defaults_version, CURRENT_DEFAULTS_VERSION);
        assert!(config
            .group("pixiv")
            .unwrap()
            .domains
            .iter()
            .any(|domain| domain == "*.pixiv.net"));
    }

    #[test]
    fn defaults_migration_is_idempotent() {
        let mut config = AppConfig::default();
        assert_eq!(migrate_defaults(&mut config), 0);
    }
}
