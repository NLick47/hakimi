use parking_lot::RwLock;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Result};

use crate::cache::CacheManager;
use crate::catalog::CatalogManager;
use crate::config::ConfigManager;
use crate::dns::{TYPE_A, TYPE_AAAA};
use crate::domain::normalize_hostname_cow;
use crate::strategy::DohSource;
use crate::util::now;

mod ech;
mod endpoints;
mod health;
mod lookup;
mod query;

pub use ech::EchOutcome;
pub use endpoints::EffectiveEndpoint;
pub use health::{DohHealth, DohStatsSnapshot};
pub(crate) use query::doh_lookup_budget;

#[derive(Debug, Clone)]
pub struct DohResolution {
    pub ips: Vec<IpAddr>,
    pub source: DohSource,
    pub endpoint: String,
    pub stale: bool,
    pub ttl: u32,
    pub fallback_used: bool,
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
pub(super) type EndpointCache = Option<(u64, u64, Arc<Vec<EffectiveEndpoint>>)>;
use endpoints::CachedDohClient;
use lookup::{FAMILY_GRACE, FAMILY_REFRESH_SLOTS, fresh_resolution_from, stale_resolution_from};
use query::TypeQuery;

#[derive(Clone)]
pub struct Resolver {
    cache: Arc<CacheManager>,
    config: Arc<ConfigManager>,
    catalogs: Arc<CatalogManager>,
    clients: Arc<RwLock<HashMap<String, CachedDohClient>>>,
    health: Arc<RwLock<HashMap<String, DohHealth>>>,
    /// Per-endpoint counters since process start; see
    /// [`health::DohEndpointStats`] and [`Self::stats_snapshot`].
    stats: Arc<parking_lot::Mutex<HashMap<String, health::DohEndpointStats>>>,
    query_locks: Arc<parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// One stale-answer refresh attempt per domain per window. The map is
    /// bounded like the query locks; entries are cheap and expire quickly.
    stale_refresh_after: Arc<parking_lot::Mutex<HashMap<String, Instant>>>,
    /// Config/catalog revisions plus the derived endpoint list. A DoH query
    /// used to rebuild and re-clone this list on every cache miss.
    endpoint_cache: Arc<RwLock<EndpointCache>>,
    /// Permits for AAAA lookups that continue after the resolution returned.
    family_refresh_slots: Arc<tokio::sync::Semaphore>,
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
            stats: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            query_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            stale_refresh_after: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            endpoint_cache: Arc::new(RwLock::new(None)),
            family_refresh_slots: Arc::new(tokio::sync::Semaphore::new(FAMILY_REFRESH_SLOTS)),
        })
    }


    /// Resolve A/AAAA candidates. IPv4 answers come first; both families are
    /// queried together so a dual-stack host gets IPv6 candidates even when
    /// IPv4 answers (the better default path) exist.
    pub async fn resolve_ips(&self, domain: &str) -> Result<DohResolution> {
        let domain = normalize_hostname_cow(domain)?;
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

    pub(super) async fn resolve_live_ips(&self, domain: &str) -> Result<DohResolution> {
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
        let a = self.query_one_type(domain, TYPE_A);
        tokio::pin!(a);
        let aaaa = self.query_one_type(domain, TYPE_AAAA);
        tokio::pin!(aaaa);
        let mut a_result: Option<Result<TypeQuery>> = None;
        let mut aaaa_result: Option<Result<TypeQuery>> = None;
        tokio::select! {
            result = &mut a => a_result = Some(result),
            result = &mut aaaa => aaaa_result = Some(result),
        }
        // The A answer is never shortened: a v6-only resolution is not the
        // fallback this proxy wants on an IPv4-first network.
        if a_result.is_none() {
            a_result = Some((&mut a).await);
        }
        if aaaa_result.is_none() {
            // IPv4 is already usable, so an unfinished AAAA only adds
            // candidates. Waiting for a slow answer (or a NODATA confirmation)
            // must not hold the whole resolution; the query keeps running in
            // the background and fills the cache.
            let a_has_addresses = matches!(
                a_result.as_ref(),
                Some(Ok(query)) if !query.answer.ips.is_empty()
            );
            if a_has_addresses {
                match tokio::time::timeout(FAMILY_GRACE, &mut aaaa).await {
                    Ok(result) => aaaa_result = Some(result),
                    Err(_) => {
                        tracing::debug!(
                            domain = %domain,
                            grace_ms = FAMILY_GRACE.as_millis() as u64,
                            "AAAA is still pending; answering with IPv4 and finishing it in the background"
                        );
                        self.spawn_family_refresh(domain, TYPE_AAAA);
                    }
                }
            } else {
                aaaa_result = Some((&mut aaaa).await);
            }
        }
        // IPv4 answers stay first: they are still the better path on networks without
        // working IPv6, and the engine reorders candidates by history anyway.
        for result in std::iter::once(a_result.expect("the A query always resolves"))
            .chain(aaaa_result)
        {
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
        let families = self.cached_families(domain, now());
        if let Some(mut resolution) = fresh_resolution_from(&families) {
            resolution.fallback_used = fallback_used;
            return Ok(resolution);
        }

        if let Some(mut resolution) = stale_resolution_from(&families, None) {
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

}

#[cfg(test)]

#[cfg(test)]
mod tests;
