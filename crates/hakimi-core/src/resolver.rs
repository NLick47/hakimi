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
/// Negative-answer TTLs. These are deliberately short: a resolver that filters
/// a domain answers NODATA, and caching that for a full DNS window kept the
/// domain unroutable long after another endpoint would have answered. A total
/// endpoint failure only backs off briefly so a flapping endpoint recovers on
/// the next attempt.
const NEGATIVE_NODATA_SECS: u32 = 20;
const NEGATIVE_HTTPS_NODATA_SECS: u32 = 60;
const NEGATIVE_FAILURE_SECS: u32 = 10;
/// RFC 8767: a zero-TTL answer gets a small minimum cache time, or every new
/// connection pays a full endpoint race for the same domain.
const MIN_CACHE_TTL_SECS: u32 = 5;
/// Lanes and budget for the endpoints after the first two. The remote catalog
/// decides how many there are (up to 64), and one timeout each would let a
/// silent list stretch every cold lookup to minutes. Two lanes avoid queueing
/// behind one dead endpoint; the budget is two client timeouts so the second
/// wave can still find an answer behind a stalled first.
const FALLBACK_LANES: usize = 2;
const FALLBACK_WAVES: u32 = 2;

/// How long every dialled endpoint gets to answer before the query gives up
/// on it. DoH providers abroad often need a few seconds; a shorter window
/// discarded their answers. Capped by `catalogs.timeoutSecs`.
const ENDPOINT_WINDOW: Duration = Duration::from_secs(4);

/// How long the first endpoint gets before the second is dialled as well. The
/// second is a hedge, not a second racer: a healthy endpoint answers in a few
/// hundred milliseconds, and racing both from t=0 sent every queried name to
/// two providers on every cache miss.
const PRIMARY_HEDGE: Duration = Duration::from_millis(250);

/// Distinct addresses an A/AAAA answer must carry before the query stops
/// collecting. One address is a single point of failure — and exactly what a
/// filtering resolver hands back — so a thin answer is widened with the next
/// ranked endpoint instead of being accepted as-is.
const MIN_ADDRESS_CANDIDATES: usize = 2;
/// Endpoints that contributed data to one query before collection stops. A
/// failure is not a contribution, so a dead endpoint still lets the walk reach
/// the next one.
const MAX_ANSWER_SOURCES: usize = 3;
/// Independent empty answers needed before a query concludes that the record
/// does not exist. One endpoint saying "no records" can be a filter; two are
/// not. Without this, every IPv4-only host walked the whole catalog for its
/// (always empty) AAAA query — a query storm on the most common case.
const EMPTY_CONFIRMATIONS: usize = 2;
/// Consecutive failures before an endpoint is skipped for a while. One failure
/// already triggers the hedge, but a single bad round trip must not demote the
/// endpoint the user configured first.
const ENDPOINT_FAILURE_THRESHOLD: u32 = 3;
const ENDPOINT_COOLDOWN_BASE: Duration = Duration::from_secs(30);
const ENDPOINT_COOLDOWN_MAX: Duration = Duration::from_secs(10 * 60);

/// The upper bound of one live `doh_ips` call, excluding the single-flight
/// queue wait: one endpoint window plus the serial fallback waves. Callers
/// that await a lookup inside a larger budget — the raw connect race sizes
/// its whole wall-clock budget with this — use it instead of re-deriving the
/// constants.
pub(crate) fn doh_lookup_budget(catalog_timeout_secs: u64) -> Duration {
    let request = Duration::from_secs(catalog_timeout_secs.max(1));
    ENDPOINT_WINDOW.min(request) + request * FALLBACK_WAVES
}

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
    /// Consecutive failures. Drives the endpoint order; reset by a success.
    #[serde(skip)]
    failures: u32,
    /// While this is in the future the endpoint is skipped by new queries.
    /// Kept out of the serialized snapshot: the UI shows the last observation,
    /// not the policy timer.
    #[serde(skip)]
    cooldown_until: Option<Instant>,
}

impl DohHealth {
    fn cooling(&self, now: Instant) -> bool {
        self.cooldown_until.is_some_and(|until| until > now)
    }

    fn new(
        endpoint: &EffectiveEndpoint,
        healthy: bool,
        latency_ms: Option<u64>,
        last_error: Option<String>,
        failures: u32,
        cooldown_until: Option<Instant>,
    ) -> Self {
        Self {
            name: endpoint.name.clone(),
            url: endpoint.url.clone(),
            source: endpoint.source,
            healthy,
            latency_ms,
            last_error,
            checked_at: now(),
            failures,
            cooldown_until,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DohResolution {
    pub ips: Vec<IpAddr>,
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
    /// Whether the answer may be trusted without further confirmation. A
    /// useful answer always is; an empty (NODATA) answer only when every
    /// endpoint consulted for the query actually answered — a raced endpoint
    /// cancelled by the grace window never confirmed the silence, so it must
    /// not be cached as authoritative NODATA.
    authoritative: bool,
}

/// Union of the answers one query collected from several endpoints.
///
/// The proxy wants a wide candidate set, not the first reply: a filtering
/// resolver answers with a subset (or NODATA), and discarding what another
/// endpoint returned threw away exactly the address that would have worked.
struct MergedAnswers {
    address_query: bool,
    ips: Vec<IpAddr>,
    ech: Option<Vec<u8>>,
    ttl: u32,
    cname: Option<String>,
    https_present: bool,
    /// First answer that carried nothing, kept so a total NODATA still has a
    /// precise `TypeQuery` to return.
    empty: Option<(usize, ResolvedAnswer)>,
    /// Endpoints that gave a conclusive answer (data or NODATA).
    answered: usize,
    /// Endpoints that contributed data. This is the collection cap; failures
    /// do not count, so a dead endpoint still lets the walk reach the next one.
    sources: usize,
    /// Endpoints that answered with data but added no new address.
    redundant: usize,
    /// First endpoint that contributed data, for source attribution.
    first_source: Option<usize>,
}

impl MergedAnswers {
    fn new(address_query: bool) -> Self {
        Self {
            address_query,
            ips: Vec::new(),
            ech: None,
            ttl: u32::MAX,
            cname: None,
            https_present: false,
            empty: None,
            answered: 0,
            sources: 0,
            redundant: 0,
            first_source: None,
        }
    }

    fn absorb(&mut self, index: usize, answer: ResolvedAnswer) {
        self.answered += 1;
        let before = self.ips.len();
        let useful = if self.address_query {
            !answer.ips.is_empty()
        } else {
            answer.ech.is_some()
        };
        if useful {
            self.sources += 1;
            self.first_source.get_or_insert(index);
        }
        if answer.ips.is_empty() && answer.ech.is_none() && self.empty.is_none() {
            self.empty = Some((index, answer.clone()));
        }
        if answer.ttl != 0 {
            self.ttl = self.ttl.min(answer.ttl);
        }
        self.https_present |= answer.https_present;
        if self.cname.is_none() {
            self.cname = answer.cname.clone();
        }
        for ip in answer.ips {
            if !self.ips.contains(&ip) {
                self.ips.push(ip);
            }
        }
        if self.address_query && useful && self.ips.len() == before {
            self.redundant += 1;
        }
        if self.ech.is_none() {
            self.ech = answer.ech;
        }
    }

    /// Whether this query has collected enough to stop.
    fn complete(&self) -> bool {
        // An empty answer needs as many confirmations as an ECH lookup: the
        // first NODATA may be a filter, the second makes it a conclusion.
        let confirmed_empty = self.ips.is_empty() && self.answered >= EMPTY_CONFIRMATIONS;
        if self.address_query {
            // Two addresses give the engine a real choice; one is a single
            // point of failure. A peer repeating that one address has nothing
            // left to add, so the walk stops instead of querying the catalog.
            self.ips.len() >= MIN_ADDRESS_CANDIDATES
                || self.redundant > 0
                || self.sources >= MAX_ANSWER_SOURCES
                || confirmed_empty
        } else {
            // ECH is a single domain-level value: the first copy is the whole
            // answer. Without it, a second independent NODATA is required.
            self.ech.is_some() || self.answered >= EMPTY_CONFIRMATIONS
        }
    }

    fn has_data(&self) -> bool {
        !self.ips.is_empty() || self.ech.is_some()
    }

    fn into_answer(self) -> ResolvedAnswer {
        ResolvedAnswer {
            ips: self.ips,
            ech: self.ech,
            ttl: if self.ttl == u32::MAX { 0 } else { self.ttl },
            cname: self.cname,
            https_present: self.https_present,
        }
    }
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
            push(endpoint, DohSource::Catalog, &mut endpoints);
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

    /// Merge every fresh cached A/AAAA answer into one resolution.
    ///
    /// The two record types have independent TTLs. Returning the first family
    /// that happened to be fresh dropped the other one: a dual-stack host lost
    /// its IPv6 candidate for the whole A TTL, and once the shorter-lived A
    /// answer expired the resolver served the still-fresh AAAA alone without
    /// ever re-querying A.
    fn fresh_ip_resolution(
        &self,
        domain: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<DohResolution> {
        let mut ips = Vec::new();
        let mut ttl = u32::MAX;
        for qtype in [TYPE_A, TYPE_AAAA] {
            let Some(answer) = self.cache.doh_answer(domain, qtype) else {
                continue;
            };
            if !answer.is_fresh(now) || answer.ips.is_empty() {
                continue;
            }
            ttl = ttl.min(remaining_ttl(&answer, now));
            for ip in answer.ips {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
        if ips.is_empty() {
            return None;
        }
        Some(DohResolution {
            ips,
            source: DohSource::Cache,
            endpoint: "cache".to_string(),
            stale: false,
            ttl: if ttl == u32::MAX { 0 } else { ttl },
            fallback_used: false,
        })
    }

    /// Select cached IP answers without waiting for DoH. `extra_secs` bounds
    /// how far past the DNS TTL the answers may be served in the background
    /// refresh path; `None` is the last-resort fallback used after a live
    /// failure. Both address families are merged for the same reason as in
    /// [`Self::fresh_ip_resolution`].
    fn stale_ip_resolution(
        &self,
        domain: &str,
        at: chrono::DateTime<chrono::Utc>,
        extra_secs: Option<i64>,
    ) -> Option<DohResolution> {
        let mut ips = Vec::new();
        for qtype in [TYPE_A, TYPE_AAAA] {
            let Some(answer) = self.cache.doh_answer(domain, qtype) else {
                continue;
            };
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
            for ip in answer.ips {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
        if ips.is_empty() {
            return None;
        }
        Some(DohResolution {
            ips,
            source: DohSource::Cache,
            endpoint: "stale-cache".to_string(),
            stale: true,
            ttl: 0,
            fallback_used: false,
        })
    }

    /// True when one of the cached A/AAAA answers has expired.
    ///
    /// A fresh answer from one family must not keep the other family's expired
    /// answer out of the refresh path: the two TTLs are independent, so
    /// returning early on the fresh one would leave the expired family
    /// unqueried for up to the longer TTL. Only an entry that actually had
    /// addresses counts, so an IPv4-only domain (which never caches AAAA) does
    /// not trigger a background lookup every few seconds.
    fn cached_family_expired(&self, domain: &str, at: chrono::DateTime<chrono::Utc>) -> bool {
        [TYPE_A, TYPE_AAAA].into_iter().any(|qtype| {
            self.cache
                .doh_answer(domain, qtype)
                .is_some_and(|answer| !answer.ips.is_empty() && !answer.is_fresh(at))
        })
    }

    /// Serve the cached answer for `domain`, merging both address families and
    /// renewing anything that is stale or expired in the background.
    fn cached_resolution(
        &self,
        domain: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<DohResolution> {
        let fresh = self.fresh_ip_resolution(domain, at);
        let stale = self.stale_ip_resolution(domain, at, Some(STALE_WHILE_REVALIDATE_SECS));
        let resolution = merge_cached_resolutions(fresh, stale)?;
        if resolution.stale || self.cached_family_expired(domain, at) {
            self.spawn_ip_refresh(domain.to_owned());
        }
        Some(resolution)
    }

    /// True when the background IP refresh still has work to do.
    ///
    /// A fresh answer from one family is not enough: the other family's TTL
    /// may have expired while the first one is still valid. Stopping at the
    /// first fresh family here would leave the expired one unqueried until the
    /// fresh family expires as well.
    fn ip_cache_needs_refresh(&self, domain: &str, at: chrono::DateTime<chrono::Utc>) -> bool {
        self.fresh_ip_resolution(domain, at).is_none() || self.cached_family_expired(domain, at)
    }

    fn fresh_ech(&self, domain: &str) -> Result<Option<EchOutcome>> {
        if let Some(cached) = self.cache.ech(domain, true) {
            return Ok(Some(EchOutcome {
                config: cached.ech_config,
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
            if !resolver.ip_cache_needs_refresh(&domain, now()) {
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

    /// Resolve A/AAAA candidates. IPv4 answers come first; both families are
    /// queried together so a dual-stack host gets IPv6 candidates even when
    /// IPv4 answers (the better default path) exist.
    pub async fn resolve_ips(&self, domain: &str) -> Result<DohResolution> {
        let domain = normalize_query_name(domain);
        let at = now();

        // Cached answers from both families are merged. A just-expired answer
        // is still a useful route, so it stays in the list as a fallback while
        // a background query renews it, instead of hiding it behind the other
        // family's still-fresh answer.
        if let Some(resolution) = self.cached_resolution(&domain, at) {
            return Ok(resolution);
        }

        // Single-flight: the startup warm-up and the first browser request often ask for
        // the same name at the same time.
        let _guard = self.query_lock(format!("ip|{domain}")).await;
        let at = now();
        if let Some(resolution) = self.cached_resolution(&domain, at) {
            return Ok(resolution);
        }

        self.resolve_live_ips(&domain).await
    }

    async fn resolve_live_ips(&self, domain: &str) -> Result<DohResolution> {
        let mut attempts = Vec::new();
        let mut fallback_used = false;
        let mut last_error: Option<anyhow::Error> = None;
        let mut ips = Vec::new();
        let mut ttl = u32::MAX;
        let mut source = DohSource::Primary;
        let mut endpoint = String::new();

        // A and AAAA are independent lookups. Asking for both together keeps the cold
        // path at one round trip, and it is the only way a dual-stack host gets an IPv6
        // candidate: the old "AAAA only when A came back empty" rule quietly made every
        // host with an A record IPv4-only, even when IPv4 was the filtered family.
        let (a_result, aaaa_result) = tokio::join!(
            self.query_one_type(domain, TYPE_A),
            self.query_one_type(domain, TYPE_AAAA)
        );
        // IPv4 answers stay first: they are still the better path on networks without
        // working IPv6, and the engine reorders candidates by history anyway.
        for result in [a_result, aaaa_result] {
            match result {
                Ok(query) => {
                    if endpoint.is_empty() {
                        source = query.source;
                        endpoint = query.endpoint;
                    }
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
                }
                Err(error) => {
                    if last_error.is_none() {
                        last_error = Some(error);
                    }
                }
            }
        }

        if !ips.is_empty() {
            return Ok(DohResolution {
                ips,
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
        // A remembered authoritative NODATA proves the HTTPS RR and its ECH
        // config are gone. Skipping the live query is fine; resurrecting the
        // stale config is not. A mere failure entry must keep falling through
        // to query_one_type so the stale config stays available as a last
        // resort.
        if self.cache.doh_negative_authoritative(&domain, TYPE_HTTPS) {
            bail!("HTTPS RR for `{domain}` does not contain an ECH config");
        }
        match self.query_one_type(&domain, TYPE_HTTPS).await {
            Ok(query) => {
                // A successful NODATA answer is authoritative when every
                // endpoint agreed. If another endpoint failed or was cut off
                // before answering, keep the stale config as a last resort,
                // matching the documented policy.
                live_failed |= !query.authoritative;
                if let Some(ech) = query.answer.ech {
                    self.cache.put_ech(CachedEch {
                        domain: domain.clone(),
                        ech_config: ech.clone(),
                        // Same floor as the address cache: a zero-TTL HTTPS
                        // RR must not turn every handshake into a live race
                        // (RFC 8767).
                        ttl_secs: query.answer.ttl.max(MIN_CACHE_TTL_SECS),
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
                        ech_config: outcome.config.clone(),
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
                let config = cached.ech_config;
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
        // Join the resolver's per-key single-flight instead of using a
        // second, ad-hoc global mutex. `ech_config("cloudflare-ech.com")`
        // queries this very name under `ech|{SHARED_ECH_DOMAIN}`; the two
        // paths guarded the same query through unrelated locks, so they
        // could race duplicate live lookups for it. Waiter semantics are
        // unchanged: the first caller queries, everyone else joins the same
        // queue and re-checks the cache afterwards.
        let _guard = self
            .query_lock(format!("ech|{}", SHARED_ECH_DOMAIN))
            .await;
        if let Some(cached) = self.cache.ech(SHARED_ECH_DOMAIN, true) {
            let config = cached.ech_config;
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
                live_failed |= !query.authoritative;
                if let Some(ech) = query.answer.ech {
                    self.cache.put_ech(CachedEch {
                        domain: SHARED_ECH_DOMAIN.to_string(),
                        ech_config: ech.clone(),
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
                        ech_config: ech.clone(),
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
                return Ok(EchOutcome {
                    config: cached.ech_config,
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
            // A health probe is an observation, not a routing decision: keep
            // the policy counters a real query produced instead of resetting
            // them (or counting the probe itself) here.
            let previous = self
                .health
                .read()
                .get(&endpoint.url)
                .map(|entry| (entry.failures, entry.cooldown_until))
                .unwrap_or((0, None));
            let health = DohHealth::new(
                endpoint,
                result.is_ok(),
                Some(started.elapsed().as_millis() as u64),
                result.as_ref().err().map(|error| format!("{error:#}")),
                previous.0,
                previous.1,
            );
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
        let address_query = matches!(qtype, TYPE_A | TYPE_AAAA);
        let timeout = Duration::from_secs(self.config.snapshot().catalogs.timeout_secs.max(1));
        let endpoint_deadline = tokio::time::Instant::now() + ENDPOINT_WINDOW.min(timeout);
        // Policy order: a cooling endpoint drops behind the healthy ones; the
        // user's configured order is kept among equals.
        let order = self.endpoint_order(&endpoints);
        let primary = order[0];
        let mut merged = MergedAnswers::new(address_query);
        let mut attempts: Vec<DohAttemptError> = Vec::new();
        // Per-endpoint outcome of this query: None until the endpoint produced
        // a result. The authoritative-NODATA decision reads it.
        let mut outcome: Vec<Option<bool>> = vec![None; endpoints.len()];
        // Endpoints actually contacted, in launch order.
        let mut asked: Vec<usize> = Vec::new();

        // The first two ranked endpoints. The second is a hedge: it joins when
        // the first fails, answers without enough data, or stalls past
        // PRIMARY_HEDGE. Racing both from t=0 sent every queried name to two
        // providers even when the first was healthy.
        let mut pending: FuturesUnordered<
            futures_util::future::BoxFuture<'_, (usize, Instant, Result<ResolvedAnswer>)>,
        > = FuturesUnordered::new();
        let mut cursor = 1usize;
        let mut second_started = order.len() < 2;
        asked.push(primary);
        {
            let endpoint = &endpoints[primary];
            pending.push(Box::pin(async move {
                let queued = Instant::now();
                (
                    primary,
                    queued,
                    self.query_endpoint(endpoint, domain, qtype).await,
                )
            }));
        }
        let mut hedge_at = if second_started {
            None
        } else {
            Some(tokio::time::Instant::now() + PRIMARY_HEDGE)
        };
        let stage_deadline = endpoint_deadline;
        enum StageEvent {
            Item(Option<(usize, Instant, Result<ResolvedAnswer>)>),
            Hedge,
            Deadline,
        }
        loop {
            if pending.is_empty() {
                break;
            }
            let deadline = stage_deadline;
            let event = match hedge_at {
                Some(at) if at < deadline => tokio::select! {
                    item = pending.next() => StageEvent::Item(item),
                    _ = tokio::time::sleep_until(at) => StageEvent::Hedge,
                },
                _ => match tokio::time::timeout_at(deadline, pending.next()).await {
                    Ok(item) => StageEvent::Item(item),
                    Err(_) => StageEvent::Deadline,
                },
            };
            match event {
                StageEvent::Deadline | StageEvent::Item(None) => break,
                StageEvent::Hedge => {
                    hedge_at = None;
                    if !second_started {
                        second_started = true;
                        let index = order[cursor];
                        cursor += 1;
                        asked.push(index);
                        tracing::debug!(
                            domain = %domain,
                            qtype,
                            waited_ms = PRIMARY_HEDGE.as_millis() as u64,
                            next = %endpoints[index].name,
                            "doh endpoint is slow; running the next one in parallel"
                        );
                        let endpoint = &endpoints[index];
                        pending.push(Box::pin(async move {
                            let queued = Instant::now();
                            (
                                index,
                                queued,
                                self.query_endpoint(endpoint, domain, qtype).await,
                            )
                        }));
                    }
                }
                StageEvent::Item(Some((index, queued, result))) => {
                    hedge_at = None;
                    let endpoint = &endpoints[index];
                    match result {
                        Ok(answer) => {
                            outcome[index] = Some(true);
                            self.record_health(endpoint, true, queued.elapsed(), None);
                            merged.absorb(index, answer);
                            if merged.complete() {
                                return self.finish_query(
                                    domain, qtype, &endpoints, primary, merged, attempts, &asked,
                                    &outcome,
                                );
                            }
                            // A conclusive but insufficient answer means the
                            // peer still has time to improve on it.
                            tracing::debug!(
                                domain = %domain,
                                qtype,
                                addresses = merged.ips.len(),
                                answered = merged.answered,
                                "doh answer is not enough yet; widening"
                            );
                        }
                        Err(error) => {
                            outcome[index] = Some(false);
                            self.record_health(
                                endpoint,
                                false,
                                queued.elapsed(),
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
                    // A failure or a thin answer makes the next ranked
                    // endpoint cheaper than waiting out the hedge window.
                    if !second_started && cursor < order.len() {
                        second_started = true;
                        let index = order[cursor];
                        cursor += 1;
                        asked.push(index);
                        let endpoint = &endpoints[index];
                        pending.push(Box::pin(async move {
                            let queued = Instant::now();
                            (
                                index,
                                queued,
                                self.query_endpoint(endpoint, domain, qtype).await,
                            )
                        }));
                    }
                }
            }
        }
        // Anything still in flight at the endpoint deadline is dropped
        // silently instead of being remembered as a failure.
        let mut tail_deadline = Some(endpoint_deadline);
        // The rest of the ranked list, two lanes at a time under one budget.
        // The catalog can be long; the budget bounds it.
        let budget = tokio::time::Instant::now() + timeout * FALLBACK_WAVES;
        loop {
            if tail_deadline.is_none() {
                while pending.len() < FALLBACK_LANES && cursor < order.len() {
                    let index = order[cursor];
                    cursor += 1;
                    if asked.contains(&index) {
                        continue;
                    }
                    asked.push(index);
                    let endpoint = &endpoints[index];
                    pending.push(Box::pin(async move {
                        let queued = Instant::now();
                        (
                            index,
                            queued,
                            self.query_endpoint(endpoint, domain, qtype).await,
                        )
                    }));
                }
            }
            let deadline = tail_deadline.unwrap_or(budget).min(budget);
            let next = match tokio::time::timeout_at(deadline, pending.next()).await {
                Ok(next) => next,
                Err(_) if tail_deadline.is_some() => {
                    pending = FuturesUnordered::new();
                    tail_deadline = None;
                    continue;
                }
                // The shared budget is spent. Queries still in flight are
                // dropped and keep no health record this round.
                Err(_) => break,
            };
            let Some((index, queued, result)) = next else {
                if tail_deadline.is_some() {
                    tail_deadline = None;
                    continue;
                }
                break;
            };
            let endpoint = &endpoints[index];
            match result {
                Ok(answer) => {
                    outcome[index] = Some(true);
                    self.record_health(endpoint, true, queued.elapsed(), None);
                    merged.absorb(index, answer);
                    if merged.complete() {
                        return self.finish_query(
                            domain, qtype, &endpoints, primary, merged, attempts, &asked, &outcome,
                        );
                    }
                }
                Err(error) => {
                    outcome[index] = Some(false);
                    self.record_health(
                        endpoint,
                        false,
                        queued.elapsed(),
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
        self.finish_query(
            domain, qtype, &endpoints, primary, merged, attempts, &asked, &outcome,
        )
    }

    /// Turn the collected answers into a `TypeQuery`: the union when there is
    /// data, an authoritative-NODATA decision when every asked endpoint
    /// answered, and a precise failure otherwise.
    #[allow(clippy::too_many_arguments)]
    fn finish_query(
        &self,
        domain: &str,
        qtype: u16,
        endpoints: &[EffectiveEndpoint],
        primary: usize,
        merged: MergedAnswers,
        attempts: Vec<DohAttemptError>,
        asked: &[usize],
        outcome: &[Option<bool>],
    ) -> Result<TypeQuery> {
        // `fallback_used` now means what it says: a second endpoint was
        // involved (as a source or as a failed attempt).
        let fallback_used =
            merged.sources > 1 || merged.first_source != Some(primary) || !attempts.is_empty();
        if merged.has_data() {
            let first = merged.first_source.unwrap_or(primary);
            let answer = merged.into_answer();
            self.store_answer(domain, qtype, &answer);
            let endpoint = &endpoints[first];
            return Ok(TypeQuery {
                answer,
                source: endpoint.source,
                endpoint: endpoint.name.clone(),
                fallback_used,
                attempts,
                authoritative: true,
            });
        }
        let Some((index, answer)) = merged.empty else {
            let detail = attempts
                .iter()
                .map(|attempt| format!("{}: {}", attempt.endpoint, attempt.error))
                .collect::<Vec<_>>()
                .join("; ");
            if attempts.is_empty() {
                // Nothing failed: the deadline cancelled every query while it
                // was still in flight. Caching that as a hard failure
                // black-holed the domain for NEGATIVE_FAILURE_SECS even though
                // a healthy-but-slow endpoint would answer the next attempt.
                bail!("all DoH endpoints silent: race deadline exceeded before any answered");
            }
            self.cache
                .put_doh_negative(domain, qtype, NEGATIVE_FAILURE_SECS, false);
            bail!("all DoH endpoints failed: {detail}");
        };
        // A NODATA answer repeats for every cold connection, so remember it —
        // but only as authoritative when every endpoint we asked actually
        // answered. A peer cut off by the deadline never confirmed the
        // silence, and caching that would hide a working endpoint.
        let authoritative =
            !asked.is_empty() && asked.iter().all(|&asked| outcome[asked] == Some(true));
        let ttl = if authoritative && qtype == TYPE_HTTPS {
            NEGATIVE_HTTPS_NODATA_SECS
        } else if authoritative {
            NEGATIVE_NODATA_SECS
        } else {
            NEGATIVE_FAILURE_SECS
        };
        self.cache
            .put_doh_negative(domain, qtype, ttl, authoritative);
        let endpoint = &endpoints[index];
        Ok(TypeQuery {
            answer,
            source: endpoint.source,
            endpoint: endpoint.name.clone(),
            fallback_used,
            attempts,
            authoritative,
        })
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
                ech_config: answer
                    .ech
                    .as_ref()
                    .map(|ech| base64::engine::general_purpose::STANDARD.encode(ech)),
                ttl_secs: answer.ttl.max(MIN_CACHE_TTL_SECS),
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
                    ech_config: ech.clone(),
                    // Same floor as the A/AAAA path above: a zero-TTL HTTPS
                    // RR would otherwise never count as fresh and re-query
                    // the endpoints on every cold handshake.
                    ttl_secs: answer.ttl.max(MIN_CACHE_TTL_SECS),
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
            // An HTTPS answer carries no addresses; whether it carried the
            // ECHConfig is the fact that decides the route.
            ech = answer.ech.is_some(),
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
                .filter(|(_, entry)| {
                    !matches!(
                        entry.source,
                        DohSource::Primary | DohSource::Fallback
                    )
                })
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
        let now = Instant::now();
        let (previous, entered_cooldown, failures, cooldown_until) = {
            let mut health = self.health.write();
            let previous = health.get(&endpoint.url).map(|entry| {
                (
                    entry.healthy,
                    entry.failures,
                    entry.cooldown_until,
                )
            });
            let was_cooling = previous
                .and_then(|entry| entry.2)
                .is_some_and(|until| until > now);
            let (previous_healthy, failures, cooldown_until) = match (healthy, previous) {
                (true, previous) => (previous.map(|entry| entry.0), 0, None),
                (false, Some((previous_healthy, failures, cooldown_until))) => {
                    let failures = failures.saturating_add(1);
                    let cooldown_until = if failures >= ENDPOINT_FAILURE_THRESHOLD {
                        Some(now + cooldown_delay(failures))
                    } else {
                        cooldown_until
                    };
                    (Some(previous_healthy), failures, cooldown_until)
                }
                (false, None) => (None, 1, None),
            };
            health.insert(
                endpoint.url.clone(),
                DohHealth::new(
                    endpoint,
                    healthy,
                    Some(elapsed.as_millis() as u64),
                    error.clone(),
                    failures,
                    cooldown_until,
                ),
            );
            (
                previous_healthy,
                !was_cooling && cooldown_until.is_some(),
                failures,
                cooldown_until,
            )
        };
        if entered_cooldown {
            tracing::warn!(
                endpoint = %endpoint.name,
                url = %redact_url(&endpoint.url),
                failures,
                cooldown_secs = cooldown_until
                    .map(|until| until.saturating_duration_since(now).as_secs())
                    .unwrap_or(0),
                "doh endpoint cooling down; skipping it for a while"
            );
        }
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
                    failures,
                    cooling_secs = cooldown_until
                        .map(|until| until.saturating_duration_since(now).as_secs())
                        .unwrap_or(0),
                    error = error.as_deref().unwrap_or("unknown"),
                    "doh endpoint is unreachable"
                );
            }
        }
    }

    /// Endpoints in policy order: healthy ones first (the configured order is
    /// kept among equals), cooling ones last, soonest-to-expire first. A pool
    /// where every entry is cooling still yields the least-bad endpoint.
    fn endpoint_order(&self, endpoints: &[EffectiveEndpoint]) -> Vec<usize> {
        let now = Instant::now();
        let health = self.health.read();
        let mut order: Vec<usize> = (0..endpoints.len()).collect();
        order.sort_by_key(|&index| {
            match health.get(&endpoints[index].url) {
                Some(entry) => match entry.cooldown_until {
                    Some(until) if entry.cooling(now) => (1u8, until, index),
                    _ => (0u8, now, index),
                },
                None => (0u8, now, index),
            }
        });
        order
    }
}

/// Cooldown for a consecutive-failure count: 30 s after the third failure,
/// doubling up to ten minutes.
fn cooldown_delay(failures: u32) -> Duration {
    let steps = failures
        .saturating_sub(ENDPOINT_FAILURE_THRESHOLD)
        .min(5);
    (ENDPOINT_COOLDOWN_BASE * 2u32.pow(steps)).min(ENDPOINT_COOLDOWN_MAX)
}

fn normalize_query_name(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Combine a fresh cached answer with a just-expired one. The fresh answer
/// (if any) keeps its TTL and ordering; the stale addresses are appended as
/// fallback candidates and the result is marked stale.
fn merge_cached_resolutions(
    fresh: Option<DohResolution>,
    stale: Option<DohResolution>,
) -> Option<DohResolution> {
    match (fresh, stale) {
        (None, None) => None,
        (Some(fresh), None) => Some(fresh),
        (None, Some(stale)) => Some(stale),
        (Some(mut fresh), Some(stale)) => {
            // Keep the documented IPv4-first order while placing the fresh
            // addresses of each family before its stale fallback.
            let mut v4 = Vec::new();
            let mut v6 = Vec::new();
            for ips in [&fresh.ips, &stale.ips] {
                for ip in ips {
                    let target = if ip.is_ipv4() { &mut v4 } else { &mut v6 };
                    if !target.contains(ip) {
                        target.push(*ip);
                    }
                }
            }
            v4.extend(v6);
            fresh.ips = v4;
            fresh.stale = true;
            Some(fresh)
        }
    }
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
    fn catalog_endpoints_are_named_as_catalog_not_custom() {
        // The remote catalog's endpoints must be distinguishable from the
        // ones the user typed in, and they must not be able to override a
        // custom endpoint's name or bootstrap.
        let dir = tempfile::tempdir().unwrap();
        let (config, _, _) = resolver(dir.path());
        let url = "https://from-catalog.example/dns-query";
        let endpoints = Resolver::build_endpoints(
            &config.snapshot(),
            vec![crate::config::DohEndpoint {
                name: "catalog entry".into(),
                url: url.into(),
                bootstrap_ip: Some("1.1.1.1".parse().unwrap()),
                enabled: true,
            }],
        );
        let entry = endpoints
            .iter()
            .find(|endpoint| endpoint.url == url)
            .expect("the catalog endpoint is appended");
        assert_eq!(entry.source, DohSource::Catalog);

        // A user custom entry reusing the same URL keeps its Custom source;
        // the catalog entry adds nothing.
        config
            .mutate(|config| {
                config.doh.custom.push(crate::config::DohEndpoint {
                    name: "mine".into(),
                    url: url.into(),
                    bootstrap_ip: Some("9.9.9.9".parse().unwrap()),
                    enabled: true,
                });
                Ok(())
            })
            .unwrap();
        let merged = Resolver::build_endpoints(
            &config.snapshot(),
            vec![crate::config::DohEndpoint {
                name: "catalog entry".into(),
                url: url.into(),
                bootstrap_ip: Some("1.1.1.1".parse().unwrap()),
                enabled: true,
            }],
        );
        let entries: Vec<_> = merged.iter().filter(|e| e.url == url).collect();
        assert_eq!(entries.len(), 1, "the catalog entry dedupes into the custom one");
        assert_eq!(entries[0].source, DohSource::Custom);
        assert_eq!(entries[0].name, "mine");
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
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now(),
        });
        let resolution = resolver.resolve_ips("github.com").await.unwrap();
        assert_eq!(resolution.source, DohSource::Cache);
        assert_eq!(resolution.ips.len(), 1);
    }

    /// A cached answer must not drop one address family just because the
    /// other family happens to be cached too. The live query always merges
    /// A and AAAA; the cache path used to return the first fresh family and
    /// silently lose the IPv6 candidates for the rest of the A TTL.
    #[tokio::test]
    async fn cached_answers_from_both_address_families_are_merged() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        let v4: IpAddr = "20.205.243.166".parse().unwrap();
        let v6: IpAddr = "2606:50c0:8000::153".parse().unwrap();
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_A,
            ips: vec![v4],
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now(),
        });
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_AAAA,
            ips: vec![v6],
            ech_config: None,
            ttl_secs: 300,
            fetched_at: now(),
        });

        let resolution = resolver.resolve_ips("github.com").await.unwrap();
        assert_eq!(resolution.source, DohSource::Cache);
        assert_eq!(
            resolution.ips,
            vec![v4, v6],
            "a fresh AAAA answer must not be dropped because A is cached"
        );
        assert_eq!(resolution.ttl, 60, "the earliest expiry wins");
    }

    /// A and AAAA have independent TTLs. When the shorter-lived A answer
    /// expires while AAAA is still fresh, the old code returned the IPv6
    /// answer alone and never re-queried A until AAAA expired too. The stale
    /// IPv4 fallback must stay in the candidate list and a refresh must be
    /// started.
    #[tokio::test]
    async fn an_expired_family_is_kept_beside_a_fresh_one() {
        let dir = tempfile::tempdir().unwrap();
        let (config, cache, resolver) = resolver(dir.path());
        config
            .mutate(|config| {
                // Keep the background refresh offline and deterministic.
                config.doh.primary = "https://127.0.0.1:1/dns-query".into();
                config.doh.fallback = config.doh.primary.clone();
                config.doh.custom.clear();
                Ok(())
            })
            .unwrap();
        let v4: IpAddr = "20.205.243.166".parse().unwrap();
        let v6: IpAddr = "2606:50c0:8000::153".parse().unwrap();
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_A,
            ips: vec![v4],
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now() - chrono::Duration::seconds(90),
        });
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_AAAA,
            ips: vec![v6],
            ech_config: None,
            ttl_secs: 300,
            fetched_at: now(),
        });

        let resolution = resolver.resolve_ips("github.com").await.unwrap();
        assert!(resolution.stale, "the merged answer carries a stale entry");
        assert_eq!(
            resolution.ips,
            vec![v4, v6],
            "the expired IPv4 fallback must survive while AAAA is fresh"
        );
        assert!(
            resolver.cached_family_expired("github.com", now()),
            "the expired family has to be refreshed in the background"
        );
        // Let the background refresh observe the closed endpoint and exit.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    /// The refresh worker used to stop as soon as *any* family was fresh, so
    /// an expired family behind a fresh one was never re-queried. The check
    /// must consider every cached family, but not invent work for a domain
    /// that only ever had one family.
    #[test]
    fn a_fresh_family_does_not_stop_refreshing_an_expired_one() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        let at = now();
        let v4: IpAddr = "20.205.243.166".parse().unwrap();
        let v6: IpAddr = "2606:50c0:8000::153".parse().unwrap();
        let answer = |domain: &str, qtype: u16, ip: IpAddr, fetched_at| CachedAnswer {
            domain: domain.into(),
            qtype,
            ips: vec![ip],
            ech_config: None,
            ttl_secs: 60,
            fetched_at,
        };

        // A is fresh while AAAA has expired.
        cache.put_doh_answer(answer("dual.example", TYPE_A, v4, at));
        cache.put_doh_answer(answer(
            "dual.example",
            TYPE_AAAA,
            v6,
            at - chrono::Duration::seconds(90),
        ));
        assert!(
            resolver.ip_cache_needs_refresh("dual.example", at),
            "the expired AAAA family must still be refreshed"
        );

        // An IPv4-only domain has no AAAA entry to fetch.
        cache.put_doh_answer(answer("v4.example", TYPE_A, v4, at));
        assert!(!resolver.ip_cache_needs_refresh("v4.example", at));

        // Both families fresh: nothing to do.
        cache.put_doh_answer(answer("fresh.example", TYPE_A, v4, at));
        cache.put_doh_answer(answer("fresh.example", TYPE_AAAA, v6, at));
        assert!(!resolver.ip_cache_needs_refresh("fresh.example", at));

        // A cold domain still needs a live lookup.
        assert!(resolver.ip_cache_needs_refresh("cold.example", at));
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

    /// `CachedEch` stores the raw ECHConfigList. The stale shared-config
    /// fallback used to base64-decode it, which either fails on the binary
    /// version byte or silently returns different bytes. When DoH is down the
    /// last-resort shared config must be handed to rustls verbatim.
    #[tokio::test]
    async fn stale_shared_ech_config_is_returned_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let (config, cache, resolver) = resolver(dir.path());
        config
            .mutate(|config| {
                // Both raced endpoints are offline, so the live lookup fails
                // immediately instead of waiting for a timeout.
                config.doh.primary = "https://127.0.0.1:1/dns-query".into();
                config.doh.fallback = config.doh.primary.clone();
                config.doh.custom.clear();
                Ok(())
            })
            .unwrap();

        // `shared_cloudflare_ech` tries AliDNS directly after the configured
        // endpoints. Pin that client to a closed local port so the test never
        // depends on the real network.
        let timeout = Duration::from_secs(config.snapshot().catalogs.timeout_secs.max(1));
        let key = format!("https://dns.alidns.com/dns-query||{}", timeout.as_secs());
        let alidns = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .resolve("dns.alidns.com", SocketAddr::from(([127, 0, 0, 1], 1)))
            .build()
            .unwrap();
        resolver.clients.write().insert(
            key,
            CachedDohClient {
                client: alidns,
                source: DohSource::Custom,
                created_at: Instant::now(),
            },
        );

        let ech_config = vec![0xfe, 0x0d, 0x00, 0x01, 0x00, 0x00];
        cache.put_ech(CachedEch {
            domain: SHARED_ECH_DOMAIN.into(),
            ech_config: ech_config.clone(),
            ttl_secs: 60,
            fetched_at: now() - chrono::Duration::seconds(120),
        });

        let shared = resolver
            .shared_cloudflare_ech()
            .await
            .expect("a stale shared config is the last resort when DoH is down");
        assert_eq!(
            shared.config, ech_config,
            "the raw ECHConfigList must not be base64-decoded"
        );
        assert!(shared.stale);

        // The public ECH path must use the same stale fallback for the
        // requesting host instead of surfacing the DoH failure.
        let outcome = resolver
            .ech_config("pixiv.net", true)
            .await
            .expect("the stale shared config must reach the requesting host");
        assert_eq!(outcome.config, ech_config);
        assert!(outcome.stale);
    }

    /// The endpoint order is the policy that keeps a blocked primary off the
    /// hot path. Two failures must not demote it (a single bad round trip is
    /// noise), the third cools it, a success restores it, and an expired
    /// cooldown restores it without any traffic.
    #[test]
    fn a_failing_endpoint_is_demoted_only_after_the_threshold_and_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, resolver) = resolver(dir.path());
        let endpoints = resolver.effective_endpoints();
        assert!(endpoints.len() >= 2, "the default config has a pair");
        let first = endpoints[0].clone();

        let fail = || {
            resolver.record_health(
                &first,
                false,
                Duration::from_millis(1),
                Some("blocked".into()),
            )
        };
        assert_eq!(resolver.endpoint_order(&endpoints)[0], 0);
        fail();
        fail();
        assert_eq!(
            resolver.endpoint_order(&endpoints)[0],
            0,
            "two failures are noise, not a verdict"
        );
        fail();
        let order = resolver.endpoint_order(&endpoints);
        assert_eq!(order[0], 1, "the healthy endpoint takes the first slot");
        assert_eq!(*order.last().unwrap(), 0, "the cooled endpoint sinks");

        // An expired cooldown restores the position without new traffic.
        {
            let mut health = resolver.health.write();
            let entry = health.get_mut(&first.url).unwrap();
            entry.cooldown_until = Some(Instant::now() - Duration::from_millis(1));
        }
        assert_eq!(resolver.endpoint_order(&endpoints)[0], 0);

        // A success resets the failure count and leaves it first even while a
        // new cooldown is armed.
        {
            let mut health = resolver.health.write();
            health.get_mut(&first.url).unwrap().cooldown_until =
                Some(Instant::now() + Duration::from_secs(60));
        }
        resolver.record_health(&first, true, Duration::from_millis(1), None);
        let entry = resolver.health.read().get(&first.url).cloned().unwrap();
        assert_eq!(entry.failures, 0);
        assert!(entry.cooldown_until.is_none());
        assert_eq!(resolver.endpoint_order(&endpoints)[0], 0);
    }
}
