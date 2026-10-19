use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine;
use futures_util::future::{select, Either};
use parking_lot::RwLock;
use rand::Rng;
use serde::Serialize;

use crate::cache::{CacheManager, CachedAnswer, CachedEch};
use crate::catalog::CatalogManager;
use crate::config::{ConfigManager, DohEndpoint};
use crate::dns::{self, ResolvedAnswer, TYPE_A, TYPE_AAAA, TYPE_HTTPS};
use crate::strategy::DohSource;
use crate::util::{now, redact_url};

const SHARED_ECH_DOMAIN: &str = "cloudflare-ech.com";
const SHARED_ECH_TTL_SECS: u32 = 30 * 60;

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
/// deduplicated by URL. A live query is attempted before stale cache; fresh cache entries are
/// used directly according to their TTL.
pub struct Resolver {
    cache: Arc<CacheManager>,
    config: Arc<ConfigManager>,
    catalogs: Arc<CatalogManager>,
    clients: RwLock<HashMap<String, reqwest::Client>>,
    health: RwLock<HashMap<String, DohHealth>>,
    shared_ech_lock: tokio::sync::Mutex<()>,
    query_locks: parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
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
            clients: RwLock::new(HashMap::new()),
            health: RwLock::new(HashMap::new()),
            shared_ech_lock: tokio::sync::Mutex::new(()),
            query_locks: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    pub fn effective_endpoints(&self) -> Vec<EffectiveEndpoint> {
        let config = self.config.snapshot();
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
        for endpoint in config
            .doh
            .custom
            .into_iter()
            .filter(|endpoint| endpoint.enabled)
        {
            push(endpoint, DohSource::Custom, &mut endpoints);
        }
        for endpoint in self.catalogs.remote_doh_endpoints() {
            push(endpoint, DohSource::Custom, &mut endpoints);
        }
        endpoints
    }

    pub fn health_snapshot(&self) -> Vec<DohHealth> {
        let mut values: Vec<DohHealth> = self.health.read().values().cloned().collect();
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

    /// Resolve A/AAAA candidates. IPv4 answers come first; AAAA is queried when A yields no
    /// addresses (the design keeps IPv6 as a later-phase feature).
    pub async fn resolve_ips(&self, domain: &str) -> Result<DohResolution> {
        let domain = normalize_query_name(domain);
        let at = now();

        if let Some(resolution) = self.fresh_ip_resolution(&domain, at) {
            return Ok(resolution);
        }

        // Single-flight: the startup warm-up and the first browser request often ask for
        // the same name at the same time.
        let _guard = self.query_lock(format!("ip|{domain}")).await;
        let at = now();
        if let Some(resolution) = self.fresh_ip_resolution(&domain, at) {
            return Ok(resolution);
        }

        let mut attempts = Vec::new();
        let mut fallback_used = false;
        let mut last_error: Option<anyhow::Error> = None;
        let mut ips = Vec::new();
        let mut hints = Vec::new();
        let mut ttl = u32::MAX;
        let mut source = DohSource::Primary;
        let mut endpoint = String::new();

        match self.query_one_type(&domain, TYPE_A).await {
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
            match self.query_one_type(&domain, TYPE_AAAA).await {
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

        // Last resort: stale cache, A first then AAAA.
        for qtype in [TYPE_A, TYPE_AAAA] {
            if let Some(answer) = self.cache.doh_answer(&domain, qtype) {
                if !answer.ips.is_empty() {
                    return Ok(DohResolution {
                        ips: answer.ips,
                        hints: answer.hints,
                        source: DohSource::Cache,
                        endpoint: "stale-cache".to_string(),
                        stale: true,
                        ttl: 0,
                        fallback_used,
                    });
                }
            }
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
        match self.query_one_type(&domain, TYPE_HTTPS).await {
            Ok(query) => {
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

        if let Ok(query) = self.query_one_type(SHARED_ECH_DOMAIN, TYPE_HTTPS).await {
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

        let alidns = EffectiveEndpoint {
            name: "AliDNS".to_string(),
            url: "https://dns.alidns.com/dns-query".to_string(),
            bootstrap_ip: None,
            source: DohSource::Custom,
        };
        if let Ok(answer) = self
            .query_endpoint(&alidns, SHARED_ECH_DOMAIN, TYPE_HTTPS)
            .await
        {
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

        bail!("unable to fetch the shared Cloudflare ECH config")
    }

    /// Health check used at startup, after network changes, and manually. It always performs a
    /// real query (never the cache) and updates [`DohHealth`] for the UI.
    pub async fn health_check(&self) -> Vec<DohHealth> {
        let endpoints = self.effective_endpoints();
        let mut out = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let started = Instant::now();
            let result = self.query_endpoint(&endpoint, "example.com", TYPE_A).await;
            let latency_ms = started.elapsed().as_millis() as u64;
            let health = DohHealth {
                name: endpoint.name.clone(),
                url: endpoint.url.clone(),
                source: endpoint.source,
                healthy: result.is_ok(),
                latency_ms: Some(latency_ms),
                last_error: result.as_ref().err().map(|error| format!("{error:#}")),
                checked_at: now(),
            };
            if let Err(error) = &result {
                tracing::warn!(
                    endpoint = %redact_url(&endpoint.url),
                    error = %error,
                    "DoH health check failed"
                );
            }
            self.health
                .write()
                .insert(endpoint.url.clone(), health.clone());
            out.push(health);
        }
        out
    }

    async fn query_one_type(&self, domain: &str, qtype: u16) -> Result<TypeQuery> {
        let endpoints = self.effective_endpoints();
        if endpoints.is_empty() {
            bail!("no DoH endpoint is configured");
        }
        let mut attempts = Vec::new();

        // Primary and fallback race each other: the first successful answer wins, so a
        // dead or slow primary costs nothing on cache misses instead of a full timeout.
        // The dropped loser gets no health record; periodic health checks cover that.
        if endpoints.len() >= 2 {
            let started = Instant::now();
            let fa = Box::pin(self.query_endpoint(&endpoints[0], domain, qtype));
            let fb = Box::pin(self.query_endpoint(&endpoints[1], domain, qtype));
            let winner: Option<(usize, ResolvedAnswer)> = match select(fa, fb).await {
                Either::Left((Ok(answer), _)) => Some((0, answer)),
                Either::Right((Ok(answer), _)) => Some((1, answer)),
                Either::Left((Err(error_a), right)) => {
                    attempts.push(DohAttemptError {
                        endpoint: endpoints[0].name.clone(),
                        source: endpoints[0].source,
                        error: format!("{error_a:#}"),
                    });
                    self.record_health(
                        &endpoints[0],
                        false,
                        started.elapsed(),
                        Some(format!("{error_a:#}")),
                    );
                    match right.await {
                        Ok(answer) => Some((1, answer)),
                        Err(error_b) => {
                            attempts.push(DohAttemptError {
                                endpoint: endpoints[1].name.clone(),
                                source: endpoints[1].source,
                                error: format!("{error_b:#}"),
                            });
                            self.record_health(
                                &endpoints[1],
                                false,
                                started.elapsed(),
                                Some(format!("{error_b:#}")),
                            );
                            None
                        }
                    }
                }
                Either::Right((Err(error_b), left)) => {
                    attempts.push(DohAttemptError {
                        endpoint: endpoints[1].name.clone(),
                        source: endpoints[1].source,
                        error: format!("{error_b:#}"),
                    });
                    self.record_health(
                        &endpoints[1],
                        false,
                        started.elapsed(),
                        Some(format!("{error_b:#}")),
                    );
                    match left.await {
                        Ok(answer) => Some((0, answer)),
                        Err(error_a) => {
                            attempts.push(DohAttemptError {
                                endpoint: endpoints[0].name.clone(),
                                source: endpoints[0].source,
                                error: format!("{error_a:#}"),
                            });
                            self.record_health(
                                &endpoints[0],
                                false,
                                started.elapsed(),
                                Some(format!("{error_a:#}")),
                            );
                            None
                        }
                    }
                }
            };
            if let Some((index, answer)) = winner {
                let endpoint = &endpoints[index];
                self.record_health(endpoint, true, started.elapsed(), None);
                self.store_answer(domain, qtype, &answer);
                return Ok(TypeQuery {
                    answer,
                    source: endpoint.source,
                    endpoint: endpoint.name.clone(),
                    fallback_used: index != 0,
                    attempts,
                });
            }
            // Both raced endpoints failed; the remaining ones are tried serially below.
        }

        for endpoint in endpoints
            .iter()
            .skip(if endpoints.len() >= 2 { 2 } else { 0 })
        {
            let started = Instant::now();
            match self.query_endpoint(endpoint, domain, qtype).await {
                Ok(answer) => {
                    self.record_health(endpoint, true, started.elapsed(), None);
                    self.store_answer(domain, qtype, &answer);
                    return Ok(TypeQuery {
                        answer,
                        source: endpoint.source,
                        endpoint: endpoint.name.clone(),
                        fallback_used: !attempts.is_empty(),
                        attempts,
                    });
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
        let detail = attempts
            .iter()
            .map(|attempt| format!("{}: {}", attempt.endpoint, attempt.error))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("all DoH endpoints failed: {detail}")
    }

    /// Persist a successful resolution into the answer/ECH caches.
    fn store_answer(&self, domain: &str, qtype: u16, answer: &ResolvedAnswer) {
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
            if let Some(ech) = &answer.ech {
                self.cache.put_ech(CachedEch {
                    domain: domain.to_string(),
                    ech_config: base64::engine::general_purpose::STANDARD.encode(ech),
                    ttl_secs: answer.ttl,
                    fetched_at: now(),
                });
            }
            self.cache.put_doh_answer(CachedAnswer {
                domain: domain.to_string(),
                qtype,
                ips: Vec::new(),
                hints: answer.hints.clone(),
                ech_config: answer
                    .ech
                    .as_ref()
                    .map(|ech| base64::engine::general_purpose::STANDARD.encode(ech)),
                ttl_secs: answer.ttl,
                fetched_at: now(),
            });
        }
    }

    async fn query_endpoint(
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
        let response = client
            .post(&endpoint.url)
            .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
            .header(reqwest::header::ACCEPT, "application/dns-message")
            .body(query)
            .send()
            .await
            .with_context(|| format!("POST {}", redact_url(&endpoint.url)))?;
        let status = response.status();
        if !status.is_success() {
            bail!("DoH endpoint returned HTTP {status}");
        }
        if response
            .content_length()
            .map(|len| len > 65_535)
            .unwrap_or(false)
        {
            bail!("DoH response is larger than 65535 bytes");
        }
        let body = response.bytes().await.context("reading DoH response")?;
        if body.len() > 65_535 {
            bail!("DoH response is larger than 65535 bytes");
        }
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
        if let Some(client) = self.clients.read().get(&key) {
            return Ok(client.clone());
        }
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .tcp_nodelay(true)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            // DoH must bypass the OS proxy: otherwise it could recurse into our own listener.
            .no_proxy()
            .user_agent(format!("hakimi/{}", env!("CARGO_PKG_VERSION")));
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
        self.clients.write().insert(key, client.clone());
        Ok(client)
    }

    fn record_health(
        &self,
        endpoint: &EffectiveEndpoint,
        healthy: bool,
        elapsed: Duration,
        error: Option<String>,
    ) {
        self.health.write().insert(
            endpoint.url.clone(),
            DohHealth {
                name: endpoint.name.clone(),
                url: endpoint.url.clone(),
                source: endpoint.source,
                healthy,
                latency_ms: Some(elapsed.as_millis() as u64),
                last_error: error,
                checked_at: now(),
            },
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheManager;
    use crate::catalog::CatalogManager;
    use crate::config::ConfigManager;
    use crate::paths::Paths;

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
}
