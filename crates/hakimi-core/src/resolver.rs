use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine;
use futures_util::stream::{FuturesUnordered, StreamExt};
use parking_lot::RwLock;
use rand::Rng;
use serde::Serialize;

use crate::cache::{CacheManager, CachedAnswer, CachedEch};
use crate::catalog::CatalogManager;
use crate::config::{AppConfig, ConfigManager, DohEndpoint};
use crate::dns::{self, ResolvedAnswer, TYPE_A, TYPE_AAAA, TYPE_HTTPS};
use crate::strategy::DohSource;
use crate::util::{now, redact_url};

const SHARED_ECH_DOMAIN: &str = "cloudflare-ech.com";
const SHARED_ECH_TTL_SECS: u32 = 30 * 60;
/// The DNS wire-format message is limited to 64 KiB. Enforce the limit while
/// reading, not after `Response::bytes()` has already buffered an unbounded
/// chunked response from a broken or hostile DoH endpoint.
const MAX_DOH_RESPONSE_BYTES: usize = 65_535;
/// After a DoH TTL expires, serve the still-usable answer for this short grace
/// period while a background query refreshes it. Without the grace, every
/// expired entry paid the full DoH timeout before the page could connect.
const STALE_WHILE_REVALIDATE_SECS: i64 = 60;
/// A stale answer is returned immediately while DoH refreshes it in the
/// background. If DoH is down, one attempt per stale request would multiply
/// the failure traffic; keep one attempt per domain per window instead.
const STALE_REFRESH_BACKOFF: Duration = Duration::from_secs(5);
const STALE_REFRESH_BACKOFF_MAX: usize = 1024;
/// Negative-answer TTLs. An authoritative empty answer is trusted for a full
/// DNS window; a total endpoint failure only backs off briefly so a flapping
/// endpoint recovers on the next attempt.
const NEGATIVE_NODATA_SECS: u32 = 60;
const NEGATIVE_HTTPS_NODATA_SECS: u32 = 300;
const NEGATIVE_FAILURE_SECS: u32 = 10;

#[derive(Debug, Clone)]
pub struct EffectiveEndpoint {
    pub name: String,
    pub url: String,
    pub bootstrap_ip: Option<IpAddr>,
    pub source: DohSource,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DohAttemptError {
    pub endpoint: String,
    pub source: DohSource,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DohHealth {
    pub name: String,
    pub url: String,
    pub source: DohSource,
    pub healthy: bool,
    pub latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct DohResolution {
    pub ips: Vec<IpAddr>,
    pub hints: Vec<IpAddr>,
    pub source: DohSource,
    pub endpoint: String,
    pub stale: bool,
    pub ttl: u32,
    pub fallback_used: bool,
}

#[derive(Debug, Clone)]
pub struct EchOutcome {
    pub config: Vec<u8>,
    pub source: DohSource,
    pub endpoint: Option<String>,
    pub stale: bool,
}

pub struct TypeQuery {
    answer: ResolvedAnswer,
    source: DohSource,
    endpoint: String,
    attempts: Vec<DohAttemptError>,
    fallback_used: bool,
}

/// Resolver surface used by the decision engine; wrapped behind a trait so tests never need
/// network access.
#[async_trait::async_trait]
pub trait IpResolver: Send + Sync {
    async fn doh_ips(&self, domain: &str) -> Result<DohResolution>;
    async fn doh_ech_config(&self, domain: &str, allow_shared: bool) -> Result<EchOutcome>;
}

#[async_trait::async_trait]
impl IpResolver for Resolver {
    async fn doh_ips(&self, domain: &str) -> Result<DohResolution> {
        self.resolve_ips(domain).await
    }

    async fn doh_ech_config(&self, domain: &str, allow_shared: bool) -> Result<EchOutcome> {
        self.ech_config(domain, allow_shared).await
    }
}

/// Global DoH resolver. Endpoint order is primary -> fallback -> user custom -> remote catalog,
/// deduplicated by URL. Fresh cache entries are used directly; a just-expired answer is served
/// while a background query refreshes it, and an older usable answer is used only after a live
/// failure.
type EndpointCache = Option<(u64, u64, Arc<Vec<EffectiveEndpoint>>)>;

/// Keep a bounded number of reqwest clients, and never evict the built-in
/// primary/fallback while a custom or catalog endpoint is available to drop.
/// The old policy cleared the whole map when a fifth endpoint appeared, which
/// threw away the HTTP/2 connection and TLS session of the hot endpoints on
/// every health check.
const MAX_DOH_CLIENTS: usize = 16;

struct CachedDohClient {
    client: reqwest::Client,
    source: DohSource,
    created_at: Instant,
}

#[derive(Clone)]
pub struct Resolver {
    cache: Arc<CacheManager>,
    config: Arc<ConfigManager>,
    catalogs: Arc<CatalogManager>,
    clients: Arc<RwLock<HashMap<String, CachedDohClient>>>,
    health: Arc<RwLock<HashMap<String, DohHealth>>>,
    shared_ech_lock: Arc<tokio::sync::Mutex<()>>,
    query_locks: Arc<parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// One stale-answer refresh attempt per domain per window. The map is
    /// bounded like the query locks; entries are cheap and expire quickly.
    stale_refresh_after: Arc<parking_lot::Mutex<HashMap<String, Instant>>>,
    /// Config/catalog revisions plus the derived endpoint list. A DoH query
    /// used to rebuild and re-clone this list on every cache miss.
    endpoint_cache: Arc<RwLock<EndpointCache>>,
}

async fn read_limited_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_DOH_RESPONSE_BYTES as u64)
    {
        bail!("DoH response is larger than {MAX_DOH_RESPONSE_BYTES} bytes");
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(MAX_DOH_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| anyhow::anyhow!("reading DoH response: {}", error.without_url()))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_DOH_RESPONSE_BYTES {
            bail!("DoH response is larger than {MAX_DOH_RESPONSE_BYTES} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl Resolver {
    pub fn new(
        cache: Arc<CacheManager>,
        config: Arc<ConfigManager>,
        catalogs: Arc<CatalogManager>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cache,
            config,
            catalogs,
            clients: Arc::new(RwLock::new(HashMap::new())),
            health: Arc::new(RwLock::new(HashMap::new())),
            shared_ech_lock: Arc::new(tokio::sync::Mutex::new(())),
            query_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            stale_refresh_after: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            endpoint_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// The configured endpoints in race order.
    ///
    /// This list only changes when the config or the remote DoH catalog
    /// changes, so a DoH cache miss reuses the previous allocation instead of
    /// re-cloning every URL and custom endpoint.
    pub fn effective_endpoints(&self) -> Arc<Vec<EffectiveEndpoint>> {
        let (config, config_revision) = self.config.snapshot_with_revision();
        // Read the catalog revision before taking the catalog snapshot: a
        // concurrent refresh can then only cache a newer list under an older
        // revision, which the next call refreshes again. The reverse order
        // could pin stale endpoints under the new revision indefinitely.
        let catalog_revision = self.catalogs.revision();
        if let Some((cached_config, cached_catalog, endpoints)) =
            self.endpoint_cache.read().as_ref()
        {
            if *cached_config == config_revision && *cached_catalog == catalog_revision {
                return endpoints.clone();
            }
        }
        let endpoints = Arc::new(Self::build_endpoints(
            &config,
            self.catalogs.remote_doh_endpoints(),
        ));
        *self.endpoint_cache.write() = Some((config_revision, catalog_revision, endpoints.clone()));
        endpoints
    }

    fn build_endpoints(config: &AppConfig, remote: Vec<DohEndpoint>) -> Vec<EffectiveEndpoint> {
        let mut endpoints = Vec::new();
        let push = |endpoint: DohEndpoint, source: DohSource, out: &mut Vec<EffectiveEndpoint>| {
            let url = endpoint.url.trim().to_string();
            if url.is_empty() {
                return;
            }
            if let Some(existing) = out.iter_mut().find(|existing| existing.url == url) {
                // A user custom entry that reuses a built-in URL may override its
                // bootstrap/name, but the built-in keeps its primary/fallback position.
                if source == DohSource::Custom && existing.source != DohSource::Custom {
                    existing.bootstrap_ip = endpoint.bootstrap_ip;
                    existing.name = endpoint.display_name();
                }
                return;
            }
            out.push(EffectiveEndpoint {
                name: endpoint.display_name(),
                url,
                bootstrap_ip: endpoint.bootstrap_ip,
                source,
            });
        };
        push(
            DohEndpoint {
                name: "primary".into(),
                url: config.doh.primary.clone(),
                bootstrap_ip: None,
                enabled: true,
            },
            DohSource::Primary,
            &mut endpoints,
        );
        push(
            DohEndpoint {
                name: "fallback".into(),
                url: config.doh.fallback.clone(),
                bootstrap_ip: None,
                enabled: true,
            },
            DohSource::Fallback,
            &mut endpoints,
        );
        for endpoint in config.doh.custom.iter().filter(|endpoint| endpoint.enabled) {
            push(endpoint.clone(), DohSource::Custom, &mut endpoints);
        }
        for endpoint in remote {
            push(endpoint, DohSource::Custom, &mut endpoints);
        }
        endpoints
    }

    pub fn health_snapshot(&self) -> Vec<DohHealth> {
        // Health entries are keyed by endpoint URL and outlive a config edit.
        // Drop entries for endpoints that are no longer configured so status
        // and the UI do not keep showing a removed primary/fallback/custom DoH.
        let endpoints = self.effective_endpoints();
        let live: HashSet<&str> = endpoints
            .iter()
            .map(|endpoint| endpoint.url.as_str())
            .collect();
        let mut health = self.health.write();
        health.retain(|url, _| live.contains(url.as_str()));
        let mut values: Vec<DohHealth> = health.values().cloned().collect();
        drop(health);
        values.sort_by(|a, b| a.url.cmp(&b.url));
        values
    }

    fn fresh_ip_resolution(
        &self,
        domain: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<DohResolution> {
        for qtype in [TYPE_A, TYPE_AAAA] {
            if let Some(answer) = self.cache.doh_answer(domain, qtype) {
                if answer.is_fresh(now) && !answer.ips.is_empty() {
                    let ttl = remaining_ttl(&answer, now);
                    return Some(DohResolution {
                        ips: answer.ips,
                        hints: answer.hints,
                        source: DohSource::Cache,
                        endpoint: "cache".to_string(),
                        stale: false,
                        ttl,
                        fallback_used: false,
                    });
                }
            }
        }
        None
    }

    /// Select a cached IP answer without waiting for DoH. `extra_secs` bounds
    /// how far past the DNS TTL the answer may be served in the background
    /// refresh path; `None` is the last-resort fallback used after a live
    /// failure.
    fn stale_ip_resolution(
        &self,
        domain: &str,
        at: chrono::DateTime<chrono::Utc>,
        extra_secs: Option<i64>,
    ) -> Option<DohResolution> {
        for qtype in [TYPE_A, TYPE_AAAA] {
            if let Some(answer) = self.cache.doh_answer(domain, qtype) {
                if answer.ips.is_empty() || answer.is_fresh(at) {
                    continue;
                }
                if let Some(extra) = extra_secs {
                    if answer.ttl_secs == 0 {
                        continue;
                    }
                    let age = at.signed_duration_since(answer.fetched_at).num_seconds();
                    if age > answer.ttl_secs as i64 + extra {
                        continue;
                    }
                }
                return Some(DohResolution {
                    ips: answer.ips,
                    hints: answer.hints,
                    source: DohSource::Cache,
                    endpoint: "stale-cache".to_string(),
                    stale: true,
                    ttl: 0,
                    fallback_used: false,
                });
            }
        }
        None
    }

    fn fresh_ech(&self, domain: &str) -> Result<Option<EchOutcome>> {
        if let Some(cached) = self.cache.ech(domain, true) {
            let config = base64::engine::general_purpose::STANDARD
                .decode(&cached.ech_config)
                .context("decoding cached ECH config")?;
            return Ok(Some(EchOutcome {
                config,
                source: DohSource::Cache,
                endpoint: None,
                stale: false,
            }));
        }
        Ok(None)
    }

    async fn query_lock(&self, key: String) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.query_locks.lock();
            if locks.len() > 1024 {
                locks.retain(|_, lock| Arc::strong_count(lock) > 1);
            }
            locks
                .entry(key)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    fn try_query_lock(&self, key: String) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let lock = {
            let mut locks = self.query_locks.lock();
            if locks.len() > 1024 {
                locks.retain(|_, lock| Arc::strong_count(lock) > 1);
            }
            locks
                .entry(key)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        lock.try_lock_owned().ok()
    }

    /// Refresh an expired answer without making the request wait for DoH.
    /// `try_query_lock` deliberately skips spawning another refresh when a
    /// foreground resolve already owns this domain's single-flight lock.
    fn spawn_ip_refresh(&self, domain: String) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let domain = normalize_query_name(&domain);
        // A burst of asset connections can all hit the same stale answer.
        // Without a per-domain gate, each request would spawn another full
        // DoH attempt after the previous one failed, amplifying an outage.
        {
            let now = Instant::now();
            let mut refresh_after = self.stale_refresh_after.lock();
            if refresh_after.get(&domain).is_some_and(|until| *until > now) {
                return;
            }
            if refresh_after.len() >= STALE_REFRESH_BACKOFF_MAX {
                refresh_after.retain(|_, until| *until > now);
                if refresh_after.len() >= STALE_REFRESH_BACKOFF_MAX {
                    refresh_after.clear();
                }
            }
            refresh_after.insert(domain.clone(), now + STALE_REFRESH_BACKOFF);
        }
        let resolver = self.clone();
        handle.spawn(async move {
            let Some(_guard) = resolver.try_query_lock(format!("ip|{domain}")) else {
                return;
            };
            if resolver.fresh_ip_resolution(&domain, now()).is_some() {
                return;
            }
            if let Err(error) = resolver.resolve_live_ips(&domain).await {
                tracing::debug!(
                    domain = %domain,
                    error = %error,
                    "background DoH refresh failed; keeping the stale answer"
                );
            }
        });
    }

    /// Resolve A/AAAA candidates. IPv4 answers come first; AAAA is queried when A yields no
    /// addresses (the design keeps IPv6 as a later-phase feature).
    pub async fn resolve_ips(&self, domain: &str) -> Result<DohResolution> {
        let domain = normalize_query_name(domain);
        let at = now();

        if let Some(resolution) = self.fresh_ip_resolution(&domain, at) {
            return Ok(resolution);
        }

        // A just-expired answer is still a useful route. Return it immediately
        // and let a background query renew the cache, instead of putting the
        // first request after the TTL behind a potentially multi-second DoH
        // timeout. The grace window is intentionally short.
        if let Some(resolution) =
            self.stale_ip_resolution(&domain, at, Some(STALE_WHILE_REVALIDATE_SECS))
        {
            self.spawn_ip_refresh(domain.clone());
            return Ok(resolution);
        }

        // Single-flight: the startup warm-up and the first browser request often ask for
        // the same name at the same time.
        let _guard = self.query_lock(format!("ip|{domain}")).await;
        let at = now();
        if let Some(resolution) = self.fresh_ip_resolution(&domain, at) {
            return Ok(resolution);
        }

        self.resolve_live_ips(&domain).await
    }

    async fn resolve_live_ips(&self, domain: &str) -> Result<DohResolution> {
        let mut attempts = Vec::new();
        let mut fallback_used = false;
        let mut last_error: Option<anyhow::Error> = None;
        let mut ips = Vec::new();
        let mut hints = Vec::new();
        let mut ttl = u32::MAX;
        let mut source = DohSource::Primary;
        let mut endpoint = String::new();

        match self.query_one_type(domain, TYPE_A).await {
            Ok(query) => {
                source = query.source;
                endpoint = query.endpoint;
                fallback_used |= query.fallback_used;
                attempts.extend(query.attempts);
                ttl = ttl.min(if query.answer.ttl == 0 {
                    u32::MAX
                } else {
                    query.answer.ttl
                });
                for ip in query.answer.ips {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
                for hint in query.answer.hints {
                    if !hints.contains(&hint) {
                        hints.push(hint);
                    }
                }
            }
            Err(error) => {
                last_error = Some(error);
            }
        }

        if ips.is_empty() && last_error.is_none() {
            match self.query_one_type(domain, TYPE_AAAA).await {
                Ok(query) => {
                    source = query.source;
                    endpoint = query.endpoint;
                    fallback_used |= query.fallback_used;
                    attempts.extend(query.attempts);
                    ttl = ttl.min(if query.answer.ttl == 0 {
                        u32::MAX
                    } else {
                        query.answer.ttl
                    });
                    for ip in query.answer.ips {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                    for hint in query.answer.hints {
                        if !hints.contains(&hint) {
                            hints.push(hint);
                        }
                    }
                }
                Err(error) => {
                    last_error = Some(error);
                }
            }
        }

        if !ips.is_empty() {
            return Ok(DohResolution {
                ips,
                hints,
                source,
                endpoint,
                stale: false,
                ttl: if ttl == u32::MAX { 0 } else { ttl },
                fallback_used,
            });
        }

        // Another request may have completed a refresh while this query was
        // running; prefer that answer over the last-resort stale entry.
        if let Some(mut resolution) = self.fresh_ip_resolution(domain, now()) {
            resolution.fallback_used = fallback_used;
            return Ok(resolution);
        }

        if let Some(mut resolution) = self.stale_ip_resolution(domain, now(), None) {
            resolution.fallback_used = fallback_used;
            return Ok(resolution);
        }

        if let Some(error) = last_error {
            return Err(error);
        }
        bail!(
            "DoH returned no A/AAAA records for `{domain}`{}",
            if attempts.is_empty() {
                String::new()
            } else {
                format!(
                    " ({})",
                    attempts
                        .iter()
                        .map(|attempt| attempt.error.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            }
        )
    }

    /// Fetch the ECHConfigList from the domain's HTTPS RR. A fresh cached config wins; on a
    /// live failure an expired config is used as a last resort.
    ///
    /// When `allow_shared` is set and the domain publishes no ECHConfig, fall back to
    /// Cloudflare's shared `cloudflare-ech.com` config (the approach used by the Piku
    /// project for Pixiv). This only works for Cloudflare-fronted hostnames.
    pub async fn ech_config(&self, domain: &str, allow_shared: bool) -> Result<EchOutcome> {
        let domain = normalize_query_name(domain);
        if let Some(outcome) = self.fresh_ech(&domain)? {
            return Ok(outcome);
        }
        let _guard = self.query_lock(format!("ech|{domain}")).await;
        if let Some(outcome) = self.fresh_ech(&domain)? {
            return Ok(outcome);
        }

        let mut live_error: Option<anyhow::Error> = None;
        let mut live_failed = false;
        match self.query_one_type(&domain, TYPE_HTTPS).await {
            Ok(query) => {
                // A successful NODATA answer is authoritative when every
                // endpoint agreed. If another endpoint failed, keep the stale
                // config as a last resort, matching the documented policy.
                live_failed |= !query.attempts.is_empty();
                if let Some(ech) = query.answer.ech {
                    self.cache.put_ech(CachedEch {
                        domain: domain.clone(),
                        ech_config: base64::engine::general_purpose::STANDARD.encode(&ech),
                        ttl_secs: query.answer.ttl,
                        fetched_at: now(),
                    });
                    return Ok(EchOutcome {
                        config: ech,
                        source: query.source,
                        endpoint: Some(query.endpoint),
                        stale: false,
                    });
                }
            }
            Err(error) => {
                live_failed = true;
                live_error = Some(error);
            }
        }

        if allow_shared && domain != SHARED_ECH_DOMAIN {
            match self.shared_cloudflare_ech().await {
                Ok(outcome) => {
                    // Cache the shared config under the requesting host too, so subsequent
                    // decisions for this host skip the (always empty) HTTPS RR query.
                    self.cache.put_ech(CachedEch {
                        domain: domain.clone(),
                        ech_config: base64::engine::general_purpose::STANDARD
                            .encode(&outcome.config),
                        ttl_secs: SHARED_ECH_TTL_SECS,
                        fetched_at: now(),
                    });
                    return Ok(outcome);
                }
                Err(error) => {
                    tracing::debug!(
                        domain = %domain,
                        error = %error,
                        "shared Cloudflare ECH config is unavailable"
                    );
                }
            }
        }

        // Do not override an authoritative live NODATA answer with a stale
        // config. The domain may have removed ECH; offering the old config can
        // turn every connection into a handshake failure. Stale is only a
        // last resort when the live query (or one endpoint in the pair) failed.
        if live_failed {
            if let Some(cached) = self.cache.ech(&domain, false) {
                let config = base64::engine::general_purpose::STANDARD
                    .decode(&cached.ech_config)
                    .context("decoding cached ECH config")?;
                tracing::warn!(
                    domain = %domain,
                    error = ?live_error,
                    "using stale ECH config after DoH failure"
                );
                return Ok(EchOutcome {
                    config,
                    source: DohSource::Cache,
                    endpoint: None,
                    stale: true,
                });
            }
        }

        if let Some(error) = live_error {
            return Err(error);
        }
        bail!("HTTPS RR for `{domain}` does not contain an ECH config")
    }

    /// Cloudflare's shared ECH config used for `www.pixiv.net` and other CF-fronted sites.
    /// Piku pins AliDNS; we first try the configured DoH pool (CleanBrowsing serves it too)
    /// and then AliDNS as a fallback.
    async fn shared_cloudflare_ech(&self) -> Result<EchOutcome> {
        let _guard = self.shared_ech_lock.lock().await;
        if let Some(cached) = self.cache.ech(SHARED_ECH_DOMAIN, true) {
            let config = base64::engine::general_purpose::STANDARD
                .decode(&cached.ech_config)
                .context("decoding cached shared ECH config")?;
            return Ok(EchOutcome {
                config,
                source: DohSource::Cache,
                endpoint: None,
                stale: false,
            });
        }

        let mut live_failed = false;
        match self.query_one_type(SHARED_ECH_DOMAIN, TYPE_HTTPS).await {
            Ok(query) => {
                live_failed |= !query.attempts.is_empty();
                if let Some(ech) = query.answer.ech {
                    self.cache.put_ech(CachedEch {
                        domain: SHARED_ECH_DOMAIN.to_string(),
                        ech_config: base64::engine::general_purpose::STANDARD.encode(&ech),
                        ttl_secs: query.answer.ttl.max(SHARED_ECH_TTL_SECS),
                        fetched_at: now(),
                    });
                    tracing::info!(
                        endpoint = %query.endpoint,
                        "using shared Cloudflare ECH config"
                    );
                    return Ok(EchOutcome {
                        config: ech,
                        source: query.source,
                        endpoint: Some(query.endpoint),
                        stale: false,
                    });
                }
            }
            Err(_) => live_failed = true,
        }

        let alidns = EffectiveEndpoint {
            name: "AliDNS".to_string(),
            url: "https://dns.alidns.com/dns-query".to_string(),
            bootstrap_ip: None,
            source: DohSource::Custom,
        };
        match self
            .query_endpoint(&alidns, SHARED_ECH_DOMAIN, TYPE_HTTPS)
            .await
        {
            Ok(answer) => {
                if let Some(ech) = answer.ech {
                    self.cache.put_ech(CachedEch {
                        domain: SHARED_ECH_DOMAIN.to_string(),
                        ech_config: base64::engine::general_purpose::STANDARD.encode(&ech),
                        ttl_secs: answer.ttl.max(SHARED_ECH_TTL_SECS),
                        fetched_at: now(),
                    });
                    tracing::info!("using shared Cloudflare ECH config from AliDNS");
                    return Ok(EchOutcome {
                        config: ech,
                        source: DohSource::Custom,
                        endpoint: Some("AliDNS".to_string()),
                        stale: false,
                    });
                }
            }
            Err(_) => live_failed = true,
        }

        if live_failed {
            if let Some(cached) = self.cache.ech(SHARED_ECH_DOMAIN, false) {
                let config = base64::engine::general_purpose::STANDARD
                    .decode(&cached.ech_config)
                    .context("decoding stale shared ECH config")?;
                return Ok(EchOutcome {
                    config,
                    source: DohSource::Cache,
                    endpoint: None,
                    stale: true,
                });
            }
        }

        bail!("unable to fetch the shared Cloudflare ECH config")
    }

    /// Health check used at startup, after network changes, and manually. It always performs a
    /// real query (never the cache) and updates [`DohHealth`] for the UI.
    pub async fn health_check(&self) -> Vec<DohHealth> {
        // The endpoints are independent; probing them in parallel turns the
        // worst case from the sum of their timeouts into the slowest one. This
        // runs on network changes before the warm-up sweep, so it is directly
        // visible as recovery latency.
        let endpoints = self.effective_endpoints();
        let checks = endpoints.iter().map(|endpoint| async move {
            let started = Instant::now();
            let result = self.query_endpoint(endpoint, "example.com", TYPE_A).await;
            let health = DohHealth {
                name: endpoint.name.clone(),
                url: endpoint.url.clone(),
                source: endpoint.source,
                healthy: result.is_ok(),
                latency_ms: Some(started.elapsed().as_millis() as u64),
                last_error: result.as_ref().err().map(|error| format!("{error:#}")),
                checked_at: now(),
            };
            (health, result.is_err())
        });
        let results = futures_util::future::join_all(checks).await;
        let mut out = Vec::with_capacity(results.len());
        for (health, failed) in results {
            if failed {
                tracing::warn!(
                    endpoint = %redact_url(&health.url),
                    error = %health.last_error.as_deref().unwrap_or(""),
                    "DoH health check failed"
                );
            }
            self.health
                .write()
                .insert(health.url.clone(), health.clone());
            out.push(health);
        }
        out
    }

    async fn query_one_type(&self, domain: &str, qtype: u16) -> Result<TypeQuery> {
        let endpoints = self.effective_endpoints();
        if endpoints.is_empty() {
            bail!("no DoH endpoint is configured");
        }
        // A remembered NODATA or total failure skips the full endpoint race for
        // this window. Stale answers are still served by the callers above.
        if self.cache.doh_negative(domain, qtype) {
            bail!("cached negative answer for `{domain}` qtype {qtype}");
        }
        let mut attempts = Vec::new();
        // A NOERROR response with no address records is a successful exchange
        // but not a usable route. A filtering resolver can return exactly that
        // while the configured fallback still has the address, so an empty
        // answer must not win the race and cancel the other endpoint. The same
        // applies to a missing HTTPS/ECH answer: the fallback may still have
        // the ECHConfigList that the primary filtered out.
        let address_query = matches!(qtype, TYPE_A | TYPE_AAAA);
        let useful_answer = |answer: &ResolvedAnswer| {
            if address_query {
                !answer.ips.is_empty()
            } else {
                // HTTPS RRs are only fetched for ECH here. An empty HTTPS RR
                // is a valid NODATA answer, but it is not useful while another
                // endpoint in the primary/fallback pair may still return ECH.
                answer.ech.is_some()
            }
        };
        let mut empty_answer: Option<(usize, ResolvedAnswer)> = None;

        // Primary and fallback race each other: the first successful answer wins, so a
        // dead or slow primary costs nothing on cache misses instead of a full timeout.
        // The dropped loser gets no health record; periodic health checks cover that.
        if endpoints.len() >= 2 {
            let started = Instant::now();
            let mut pending: FuturesUnordered<
                futures_util::future::BoxFuture<'_, (usize, Result<ResolvedAnswer>)>,
            > = FuturesUnordered::new();
            pending.push(Box::pin(async {
                (
                    0usize,
                    self.query_endpoint(&endpoints[0], domain, qtype).await,
                )
            }));
            pending.push(Box::pin(async {
                (
                    1usize,
                    self.query_endpoint(&endpoints[1], domain, qtype).await,
                )
            }));
            while let Some((index, result)) = pending.next().await {
                let endpoint = &endpoints[index];
                match result {
                    Ok(answer) => {
                        self.record_health(endpoint, true, started.elapsed(), None);
                        if useful_answer(&answer) {
                            self.store_answer(domain, qtype, &answer);
                            return Ok(TypeQuery {
                                answer,
                                source: endpoint.source,
                                endpoint: endpoint.name.clone(),
                                fallback_used: index != 0,
                                attempts,
                            });
                        }
                        // Keep waiting for the other endpoint; if neither has
                        // an address, the empty answer still lets the caller
                        // try AAAA and report a precise error.
                        if empty_answer.is_none() {
                            empty_answer = Some((index, answer));
                        }
                    }
                    Err(error) => {
                        self.record_health(
                            endpoint,
                            false,
                            started.elapsed(),
                            Some(format!("{error:#}")),
                        );
                        tracing::debug!(
                            endpoint = %redact_url(&endpoint.url),
                            domain = %domain,
                            qtype,
                            error = %error,
                            "DoH query failed"
                        );
                        attempts.push(DohAttemptError {
                            endpoint: endpoint.name.clone(),
                            source: endpoint.source,
                            error: format!("{error:#}"),
                        });
                    }
                }
            }
            // Both raced endpoints failed (or answered empty); the remaining
            // endpoints are tried serially below so a custom endpoint can
            // still supply an address.
        }

        // For an address query, an empty answer is unusable, so trying every
        // custom endpoint is worth the latency. For HTTPS/ECH a NODATA answer
        // from the primary/fallback pair is a usable negative result; probing
        // every custom endpoint serially would add one timeout per endpoint to
        // every cold ECH route. Custom endpoints are only consulted when the
        // raced pair did not produce any answer at all.
        let pair_answered_empty = endpoints.len() >= 2 && empty_answer.is_some();
        if !(qtype == TYPE_HTTPS && pair_answered_empty) {
            for (index, endpoint) in
                endpoints
                    .iter()
                    .enumerate()
                    .skip(if endpoints.len() >= 2 { 2 } else { 0 })
            {
                let started = Instant::now();
                match self.query_endpoint(endpoint, domain, qtype).await {
                    Ok(answer) => {
                        self.record_health(endpoint, true, started.elapsed(), None);
                        if useful_answer(&answer) {
                            self.store_answer(domain, qtype, &answer);
                            return Ok(TypeQuery {
                                answer,
                                source: endpoint.source,
                                endpoint: endpoint.name.clone(),
                                fallback_used: index != 0 || !attempts.is_empty(),
                                attempts,
                            });
                        }
                        if empty_answer.is_none() {
                            empty_answer = Some((index, answer));
                        }
                    }
                    Err(error) => {
                        self.record_health(
                            endpoint,
                            false,
                            started.elapsed(),
                            Some(format!("{error:#}")),
                        );
                        tracing::debug!(
                            endpoint = %redact_url(&endpoint.url),
                            domain = %domain,
                            qtype,
                            error = %error,
                            "DoH query failed"
                        );
                        attempts.push(DohAttemptError {
                            endpoint: endpoint.name.clone(),
                            source: endpoint.source,
                            error: format!("{error:#}"),
                        });
                    }
                }
            }
        }

        // Every endpoint answered without an address. Return the empty answer
        // (instead of "all endpoints failed") so the caller queries AAAA and
        // reports that DoH had no records, not that DoH was unreachable.
        if let Some((index, answer)) = empty_answer {
            let endpoint = &endpoints[index];
            // An authoritative empty answer repeats for every cold connection:
            // remember it so the next query skips the endpoint race entirely
            let ttl = if attempts.is_empty() && qtype == TYPE_HTTPS {
                NEGATIVE_HTTPS_NODATA_SECS
            } else if attempts.is_empty() {
                NEGATIVE_NODATA_SECS
            } else {
                NEGATIVE_FAILURE_SECS
            };
            self.cache.put_doh_negative(domain, qtype, ttl);
            return Ok(TypeQuery {
                answer,
                source: endpoint.source,
                endpoint: endpoint.name.clone(),
                fallback_used: index != 0 || !attempts.is_empty(),
                attempts,
            });
        }

        let detail = attempts
            .iter()
            .map(|attempt| format!("{}: {}", attempt.endpoint, attempt.error))
            .collect::<Vec<_>>()
            .join("; ");
        self.cache
            .put_doh_negative(domain, qtype, NEGATIVE_FAILURE_SECS);
        bail!("all DoH endpoints failed: {detail}")
    }

    /// Persist a successful resolution into the answer/ECH caches.
    fn store_answer(&self, domain: &str, qtype: u16, answer: &ResolvedAnswer) {
        // A real answer supersedes any remembered negative result
        self.cache.clear_doh_negative(domain, qtype);
        if qtype == TYPE_A || qtype == TYPE_AAAA {
            self.cache.put_doh_answer(CachedAnswer {
                domain: domain.to_string(),
                qtype,
                ips: answer.ips.clone(),
                hints: answer.hints.clone(),
                ech_config: answer
                    .ech
                    .as_ref()
                    .map(|ech| base64::engine::general_purpose::STANDARD.encode(ech)),
                ttl_secs: answer.ttl,
                fetched_at: now(),
            });
        } else if qtype == TYPE_HTTPS {
            // HTTPS RRs only feed the ECH cache. A `CachedAnswer` with an
            // empty IP list is never read (fresh/stale resolution only looks
            // at A/AAAA) and used to occupy the bounded answer cache, evicting
            // real addresses. It also encoded the ECHConfigList a second time.
            if let Some(ech) = &answer.ech {
                self.cache.put_ech(CachedEch {
                    domain: domain.to_string(),
                    ech_config: base64::engine::general_purpose::STANDARD.encode(ech),
                    ttl_secs: answer.ttl,
                    fetched_at: now(),
                });
            }
        }
    }

    async fn query_endpoint(
        &self,
        endpoint: &EffectiveEndpoint,
        domain: &str,
        qtype: u16,
    ) -> Result<ResolvedAnswer> {
        let started = Instant::now();
        let result = self.query_endpoint_inner(endpoint, domain, qtype).await;
        match &result {
            Ok(_) => {}
            Err(error) => {
                // A DoH failure is one of the two classic reasons why a site
                // becomes unroutable, so it must be visible at the default log
                // level and must name the endpoint that failed.
                tracing::warn!(
                    endpoint = %endpoint.name,
                    url = %redact_url(&endpoint.url),
                    source = %endpoint.source,
                    domain = %domain,
                    qtype,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    error = %format!("{error:#}"),
                    "doh query failed"
                );
            }
        }
        result
    }

    async fn query_endpoint_inner(
        &self,
        endpoint: &EffectiveEndpoint,
        domain: &str,
        qtype: u16,
    ) -> Result<ResolvedAnswer> {
        let config = self.config.snapshot();
        let timeout = Duration::from_secs(config.catalogs.timeout_secs.max(1));
        let client = self.client_for(endpoint, timeout)?;
        let id: u16 = rand::rng().random();
        let query = dns::build_query(domain, qtype, id)?;
        let started = Instant::now();
        let response = client
            .post(&endpoint.url)
            .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
            .header(reqwest::header::ACCEPT, "application/dns-message")
            .body(query)
            .send()
            .await
            .map_err(|error| {
                // reqwest's Display repeats the request URL, including a token
                // in the path. Keep only our already-redacted endpoint in the
                // error that is stored in health/status and shown in exports.
                anyhow::anyhow!(
                    "POST {} failed: {}",
                    redact_url(&endpoint.url),
                    error.without_url()
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            bail!("DoH endpoint returned HTTP {status}");
        }
        let body = read_limited_body(response).await?;
        let parsed = dns::parse_response(&body).context("parsing DoH response")?;
        if parsed.id != id {
            bail!(
                "DoH response id mismatch (expected {id}, got {})",
                parsed.id
            );
        }
        if let Some(question) = parsed.questions.first() {
            if question.name != domain.trim_end_matches('.') || question.qtype != qtype {
                bail!(
                    "DoH response question mismatch ({} type {})",
                    question.name,
                    question.qtype
                );
            }
        }
        if parsed.rcode != 0 {
            bail!("DoH response code {}", parsed.rcode_text());
        }
        let answer = dns::extract_answer(&parsed, domain, qtype);
        // The answer set is the whole point of a DoH lookup: without it a log
        // reader cannot tell "DoH is unreachable" apart from "DoH answered but
        // the answer was empty", and those two need very different fixes.
        tracing::info!(
            endpoint = %endpoint.name,
            url = %redact_url(&endpoint.url),
            source = %endpoint.source,
            domain = %domain,
            qtype,
            elapsed_ms = started.elapsed().as_millis() as u64,
            ips = %format_ips(&answer.ips),
            hints = %format_ips(&answer.hints),
            ttl_secs = answer.ttl,
            "doh query answered"
        );
        Ok(answer)
    }

    fn client_for(
        &self,
        endpoint: &EffectiveEndpoint,
        timeout: Duration,
    ) -> Result<reqwest::Client> {
        let key = format!(
            "{}|{}|{}",
            endpoint.url,
            endpoint
                .bootstrap_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            timeout.as_secs()
        );
        if let Some(entry) = self.clients.read().get(&key) {
            return Ok(entry.client.clone());
        }
        crate::util::install_crypto_provider();
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .tcp_nodelay(true)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            // DoH must bypass the OS proxy: otherwise it could recurse into our own listener.
            .no_proxy()
            .user_agent(format!("hakimi/{}", env!("CARGO_PKG_VERSION")));
        // Test hook: extra roots for a local harness (off by default).
        for root in crate::hooks::extra_roots() {
            if let Ok(certificate) = reqwest::Certificate::from_der(root.as_ref()) {
                builder = builder.add_root_certificate(certificate);
            }
        }
        if let Some(ip) = endpoint.bootstrap_ip {
            let parsed = url::Url::parse(&endpoint.url)
                .with_context(|| format!("invalid DoH URL {}", redact_url(&endpoint.url)))?;
            let host = parsed
                .host_str()
                .context("DoH URL has no host for bootstrap")?;
            let port = parsed.port_or_known_default().unwrap_or(443);
            builder = builder.resolve(host, SocketAddr::new(ip, port));
        }
        let client = builder.build().context("building DoH client")?;
        let mut clients = self.clients.write();
        if !clients.contains_key(&key) && clients.len() >= MAX_DOH_CLIENTS {
            // Prefer evicting a catalog/custom client over the primary or
            // fallback, whose connections are used on every cache miss.
            let evict = clients
                .iter()
                .filter(|(_, entry)| entry.source == DohSource::Custom)
                .min_by_key(|(_, entry)| entry.created_at)
                .or_else(|| clients.iter().min_by_key(|(_, entry)| entry.created_at))
                .map(|(key, _)| key.clone());
            if let Some(key) = evict {
                clients.remove(&key);
            }
        }
        clients.insert(
            key,
            CachedDohClient {
                client: client.clone(),
                source: endpoint.source,
                created_at: Instant::now(),
            },
        );
        Ok(client)
    }

    fn record_health(
        &self,
        endpoint: &EffectiveEndpoint,
        healthy: bool,
        elapsed: Duration,
        error: Option<String>,
    ) {
        let previous = {
            let mut health = self.health.write();
            let previous = health.get(&endpoint.url).map(|entry| entry.healthy);
            health.insert(
                endpoint.url.clone(),
                DohHealth {
                    name: endpoint.name.clone(),
                    url: endpoint.url.clone(),
                    source: endpoint.source,
                    healthy,
                    latency_ms: Some(elapsed.as_millis() as u64),
                    last_error: error.clone(),
                    checked_at: now(),
                },
            );
            previous
        };
        // Only transitions are logged: a healthy endpoint answers every query,
        // and one line per query would drown the interesting failures.
        if previous != Some(healthy) {
            if healthy {
                tracing::info!(
                    endpoint = %endpoint.name,
                    url = %redact_url(&endpoint.url),
                    source = %endpoint.source,
                    latency_ms = elapsed.as_millis() as u64,
                    "doh endpoint is reachable"
                );
            } else {
                tracing::warn!(
                    endpoint = %endpoint.name,
                    url = %redact_url(&endpoint.url),
                    source = %endpoint.source,
                    latency_ms = elapsed.as_millis() as u64,
                    error = error.as_deref().unwrap_or("unknown"),
                    "doh endpoint is unreachable"
                );
            }
        }
    }
}

fn normalize_query_name(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn remaining_ttl(answer: &CachedAnswer, now: chrono::DateTime<chrono::Utc>) -> u32 {
    let age = now
        .signed_duration_since(answer.fetched_at)
        .num_seconds()
        .max(0) as u32;
    answer.ttl_secs.saturating_sub(age)
}

/// Compact rendering of a list of addresses for the log.
///
/// The debug rendering contains spaces, which makes the line impossible to
/// read field by field - and the answer set is the whole point of the line.
fn format_ips(ips: &[std::net::IpAddr]) -> String {
    if ips.is_empty() {
        return "none".to_string();
    }
    ips.iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheManager;
    use crate::catalog::CatalogManager;
    use crate::config::ConfigManager;
    use crate::paths::Paths;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn resolver(dir: &std::path::Path) -> (Arc<ConfigManager>, Arc<CacheManager>, Arc<Resolver>) {
        let paths = Paths::new(dir);
        paths.ensure().unwrap();
        let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
        let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
        let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
        let resolver = Resolver::new(cache.clone(), config.clone(), catalogs);
        (config, cache, resolver)
    }

    #[test]
    fn endpoint_cache_reuses_the_list_until_the_config_changes() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _, resolver) = resolver(dir.path());
        let first = resolver.effective_endpoints();
        let same = resolver.effective_endpoints();
        assert!(
            Arc::ptr_eq(&first, &same),
            "an unchanged config must reuse the cached endpoint list"
        );

        config
            .mutate(|config| {
                config.doh.custom.push(crate::config::DohEndpoint {
                    name: "added".into(),
                    url: "https://added.example/dns-query".into(),
                    bootstrap_ip: None,
                    enabled: true,
                });
                Ok(())
            })
            .unwrap();
        let changed = resolver.effective_endpoints();
        assert_eq!(changed.len(), first.len() + 1);
        assert!(!Arc::ptr_eq(&first, &changed));
    }

    #[test]
    fn endpoint_order_and_dedupe() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _, resolver) = resolver(dir.path());
        config
            .mutate(|config| {
                config.doh.fallback = config.doh.primary.clone();
                config.doh.custom.push(crate::config::DohEndpoint {
                    name: "custom".into(),
                    url: "https://custom.example/dns-query".into(),
                    bootstrap_ip: None,
                    enabled: true,
                });
                Ok(())
            })
            .unwrap();
        let endpoints = resolver.effective_endpoints();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].source, DohSource::Primary);
        assert_eq!(endpoints[1].source, DohSource::Custom);
    }

    #[test]
    fn doh_client_cache_keeps_the_hot_endpoints_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, resolver) = resolver(dir.path());
        let endpoints = resolver.effective_endpoints();
        for endpoint in endpoints.iter() {
            resolver
                .client_for(endpoint, Duration::from_secs(3))
                .unwrap();
        }
        for index in 0..(MAX_DOH_CLIENTS + 8) {
            let endpoint = EffectiveEndpoint {
                name: format!("custom{index}"),
                url: format!("https://custom{index}.example/dns-query"),
                bootstrap_ip: None,
                source: DohSource::Custom,
            };
            resolver
                .client_for(&endpoint, Duration::from_secs(3))
                .unwrap();
        }
        let clients = resolver.clients.read();
        assert!(
            clients.len() <= MAX_DOH_CLIENTS,
            "the client cache must stay bounded ({} entries)",
            clients.len()
        );
        assert_eq!(
            clients
                .values()
                .filter(|entry| entry.source == DohSource::Primary)
                .count(),
            1,
            "the primary client must survive custom-endpoint churn"
        );
        assert_eq!(
            clients
                .values()
                .filter(|entry| entry.source == DohSource::Fallback)
                .count(),
            1,
            "the fallback client must survive custom-endpoint churn"
        );
    }

    #[tokio::test]
    async fn fresh_cache_is_used_first() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_A,
            ips: vec!["20.205.243.166".parse().unwrap()],
            hints: Vec::new(),
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now(),
        });
        let resolution = resolver.resolve_ips("github.com").await.unwrap();
        assert_eq!(resolution.source, DohSource::Cache);
        assert_eq!(resolution.ips.len(), 1);
    }

    #[tokio::test]
    async fn expired_answers_are_served_without_waiting_for_doh() {
        let dir = tempfile::tempdir().unwrap();
        let (config, cache, resolver) = resolver(dir.path());
        config
            .mutate(|config| {
                // Keep the background refresh offline and deterministic.
                config.doh.primary = "https://127.0.0.1:1/dns-query".into();
                config.doh.fallback = "https://127.0.0.1:1/dns-query".into();
                config.doh.custom.clear();
                Ok(())
            })
            .unwrap();
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_A,
            ips: vec!["20.205.243.166".parse().unwrap()],
            hints: Vec::new(),
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now() - chrono::Duration::seconds(90),
        });

        let started = Instant::now();
        let resolution = resolver.resolve_ips("github.com").await.unwrap();
        assert!(resolution.stale);
        assert_eq!(resolution.source, DohSource::Cache);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "an expired-but-usable answer should not wait for DoH: {:?}",
            started.elapsed()
        );
        // Let the background refresh observe the empty endpoint list and exit.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn doh_errors_do_not_leak_endpoint_path_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _, resolver) = resolver(dir.path());
        config
            .mutate(|config| {
                // Port 1 is closed, so reqwest reports a request error. Its
                // Display includes the full URL; the status/health record must
                // not carry the credential from the path.
                config.doh.primary = "https://127.0.0.1:1/dns-query/secret-token".into();
                config.doh.fallback = config.doh.primary.clone();
                config.doh.custom.clear();
                Ok(())
            })
            .unwrap();

        let health = resolver.health_check().await;
        let errors: Vec<&str> = health
            .iter()
            .filter_map(|entry| entry.last_error.as_deref())
            .collect();
        let text = errors.join("\n");
        assert!(
            !text.contains("secret-token"),
            "DoH health must not expose a token from the endpoint path: {text}"
        );
        assert!(
            text.contains("redacted"),
            "the error should name the endpoint with its path redacted: {text}"
        );
    }

    #[tokio::test]
    async fn oversized_chunked_doh_body_is_rejected_while_streaming() {
        crate::util::install_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/dns-message\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .unwrap();
            let chunk = vec![b'x'; 4096];
            for _ in 0..20 {
                let header = format!("{:x}\r\n", chunk.len());
                if socket.write_all(header.as_bytes()).await.is_err() {
                    return;
                }
                if socket.write_all(&chunk).await.is_err() {
                    return;
                }
                if socket.write_all(b"\r\n").await.is_err() {
                    return;
                }
            }
            let _ = socket.write_all(b"0\r\n\r\n").await;
        });

        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        let error = read_limited_body(response).await.unwrap_err();
        assert!(
            error.to_string().contains("larger"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn expired_answers_are_available_for_the_revalidate_grace_window() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_A,
            ips: vec!["20.205.243.166".parse().unwrap()],
            hints: Vec::new(),
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now() - chrono::Duration::seconds(90),
        });

        let at = now();
        let stale = resolver
            .stale_ip_resolution("github.com", at, Some(STALE_WHILE_REVALIDATE_SECS))
            .expect("an expired answer within the grace window must be usable");
        assert!(stale.stale);
        assert_eq!(stale.ips.len(), 1);

        let beyond_grace = now() + chrono::Duration::seconds(90);
        assert!(
            resolver
                .stale_ip_resolution("github.com", beyond_grace, Some(60))
                .is_none(),
            "the stale-while-revalidate path must not serve arbitrarily old answers"
        );
        assert!(
            resolver
                .stale_ip_resolution("github.com", beyond_grace, None)
                .is_some(),
            "the last-resort path may still use the usable answer"
        );
    }

    #[test]
    fn https_answers_use_only_the_ech_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        let answer = ResolvedAnswer {
            ips: Vec::new(),
            hints: vec!["203.0.113.9".parse().unwrap()],
            ech: Some(vec![1, 2, 3, 4]),
            ttl: 60,
            cname: None,
            https_present: true,
        };
        resolver.store_answer("pixiv.net", TYPE_HTTPS, &answer);
        assert_eq!(
            cache.stats().doh_answers,
            0,
            "an HTTPS RR has no addresses; caching it only evicts real A/AAAA answers"
        );
        assert_eq!(cache.stats().ech_configs, 1);
    }
}
