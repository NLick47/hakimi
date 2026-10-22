use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::StatusCode;

use crate::cache::{CacheManager, IpScoreUpdate, LastGoodEntry};
use crate::catalog::RemoteIpProvider;
use crate::config::{AppConfig, ConfigManager, GroupConfig};
use crate::domain::normalize_hostname;
use crate::resolver::{DohResolution, IpResolver};
use crate::status::{AttemptRecord, DomainDiagnostics, State, StatusStore};
use crate::strategy::{CacheStatus, FailureReason, IpSource, TlsMode};
use crate::util::{network_id, now};

use super::cursor::{Route, RouteCursor};
use super::plan::{ConnectPlan, DecisionOutcome, Prober};
use super::score::{IpScore, IP_SCORE_CAP, IP_SCORE_PRUNE_TO};
use super::types::{Candidate, DohExpansion};

pub struct DecisionEngine {
    pub config: Arc<ConfigManager>,
    pub cache: Arc<CacheManager>,
    pub remote: Arc<dyn RemoteIpProvider>,
    pub resolver: Arc<dyn IpResolver>,
    pub prober: Arc<dyn Prober>,
    pub status: Arc<StatusStore>,
    /// Last successful route per authority. New pooled connections start here, so a
    /// connection failure is the only event that triggers re-resolution.
    /// Read on every new connection, written on every success. Keyed by
    /// domain first so a lookup needs no formatted key.
    pub(super) plan_cache:
        parking_lot::RwLock<HashMap<String, HashMap<(u16, bool), (Instant, Arc<ConnectPlan>)>>>,
    /// Per (domain, IP) observations. Candidates are ordered by score, so a host picks the
    /// address that has actually been fast on this network instead of a static list.
    pub(super) ip_scores: parking_lot::RwLock<HashMap<String, HashMap<IpAddr, IpScore>>>,
    /// Number of entries in `ip_scores`, maintained under its write lock. Avoids a
    /// full-map sum on every connection outcome.
    ip_score_count: AtomicUsize,
    /// Number of entries in `plan_cache`, maintained under its write lock. The
    /// cache is read on every cold connection and written on every success, so
    /// a full-map sum there would put an O(cache size) scan under an exclusive
    /// lock on the success path.
    plan_cache_count: AtomicUsize,
    /// Routes that produced an HTTP rejection (403/421/451). Keyed by
    /// `domain|mode`; entries expire after [`ROUTE_REJECTION_TTL`].
    route_rejections: parking_lot::RwLock<HashMap<String, Instant>>,
    /// True while the initial warmup is probing. Failures are published as
    /// Checking instead of Failed so the first probe's retry does not flash
    /// red; the runtime settles the remaining ones after warmup.
    warming: AtomicBool,
}

pub(super) const PLAN_CACHE_MAX: usize = 2048;
/// Leave headroom after a prune so a burst of new hosts does not sort the map
/// on every success.
pub(super) const PLAN_CACHE_PRUNE_TO: usize = PLAN_CACHE_MAX * 3 / 4;
/// How long an HTTP-rejected route stays out of the candidate set.
const ROUTE_REJECTION_TTL: Duration = Duration::from_secs(300);

/// The key a plan is stored under.  Hot-path callers already pass a
/// normalized host, so the common case borrows.
fn plan_cache_domain(domain: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.bytes().any(|byte| byte.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    }
}

impl DecisionEngine {
    pub fn new(
        config: Arc<ConfigManager>,
        cache: Arc<CacheManager>,
        remote: Arc<dyn RemoteIpProvider>,
        resolver: Arc<dyn IpResolver>,
        prober: Arc<dyn Prober>,
        status: Arc<StatusStore>,
    ) -> Arc<Self> {
        // Seed the in-memory quality map from the persisted one, so a restart
        // keeps knowing that an IP was fast or blocked on this network.
        let mut seeded_scores: HashMap<String, HashMap<IpAddr, IpScore>> = HashMap::new();
        for (domain, ip, entry) in cache.ip_scores() {
            seeded_scores.entry(domain).or_default().insert(
                ip,
                IpScore {
                    ewma_ms: entry.ewma_ms,
                    successes: entry.successes,
                    failures: entry.failures,
                },
            );
        }
        let ip_score_count = seeded_scores.values().map(|by_ip| by_ip.len()).sum();
        Arc::new(Self {
            config,
            cache,
            remote,
            resolver,
            prober,
            status,
            plan_cache: parking_lot::RwLock::new(HashMap::new()),
            ip_scores: parking_lot::RwLock::new(seeded_scores),
            ip_score_count: AtomicUsize::new(ip_score_count),
            plan_cache_count: AtomicUsize::new(0),
            route_rejections: parking_lot::RwLock::new(HashMap::new()),
            warming: AtomicBool::new(false),
        })
    }

    /// Mark the start of the initial warmup. Probe failures stay in Checking
    /// until [`Self::finish_warmup`] so a first attempt that is immediately
    /// retried does not publish Failed and then Normal.
    pub fn begin_warmup(&self) {
        self.warming.store(true, Ordering::SeqCst);
    }

    /// End the warmup window. The runtime also settles any probe that is still
    /// Checking with a recorded failure into Failed.
    pub fn finish_warmup(&self) {
        self.warming.store(false, Ordering::SeqCst);
    }

    pub async fn decide_https(self: &Arc<Self>, domain: &str) -> DecisionOutcome {
        self.decide(domain, 443, true).await
    }

    /// Decide how to reach `domain` by actually probing candidates. This is used by
    /// diagnostics and background checks; the proxy hot path uses [`Self::route`] and lets
    /// the real upstream connection perform validation instead.
    ///
    /// `tls` is false for plaintext HTTP, which can only use direct TCP (ECH and fake SNI
    /// are TLS-only).
    pub async fn decide(self: &Arc<Self>, domain: &str, port: u16, tls: bool) -> DecisionOutcome {
        let timeout = Duration::from_millis(self.config.snapshot().advanced.ip_timeout_ms);
        // A diagnostic probe is an observation, not routing: it must keep
        // working while acceleration is paused. The paused check belongs to
        // `route` (the proxy hot path), not to the probe path.
        match self.route_inner(domain, port, tls, true) {
            Route::Bypass(outcome) | Route::Blocked(outcome) => outcome,
            Route::Group(mut cursor) => loop {
                let Some(plan) = cursor.next_plan().await else {
                    return cursor
                        .outcome()
                        .cloned()
                        .unwrap_or_else(|| self.internal_failure(domain));
                };
                let result = if plan.tls {
                    self.prober
                        .probe_tls(
                            plan.ip,
                            plan.port,
                            &plan.domain,
                            plan.mode,
                            plan.sni.as_deref(),
                            plan.ech_config.as_deref(),
                            timeout,
                        )
                        .await
                        .map(|probe| probe.latency_ms)
                } else {
                    self.prober.probe_tcp(plan.ip, plan.port, timeout).await
                };
                match result {
                    Ok(latency_ms) => return cursor.note_success(Arc::new(plan), latency_ms),
                    Err(error) => {
                        cursor.note_failure(&plan, error.reason(), error.detail());
                    }
                }
            },
        }
    }

    /// Match a host to its group and return a lazy, probe-free plan generator.
    ///
    /// The caller is expected to attempt each plan for real. A successful TLS handshake
    /// validates the certificate exactly like [`Self::decide`], but costs only one
    /// handshake instead of a probe plus the actual connection.
    pub fn route(self: &Arc<Self>, domain: &str, port: u16, tls: bool) -> Route {
        self.route_inner(domain, port, tls, false)
    }

    /// Hot-path variant for callers that already normalized `domain` (the proxy
    /// does this once per CONNECT / upstream authority). Skipping the second
    /// normalize removes a String allocation and two label-validation passes
    /// from every new upstream connection.
    ///
    /// `domain` must already be lowercase ASCII without a trailing root dot.
    pub(crate) fn route_normalized(self: &Arc<Self>, domain: &str, port: u16, tls: bool) -> Route {
        self.route_with_config(Cow::Borrowed(domain), port, tls, false)
    }

    /// Routing variant used by diagnostic probes. `probing` skips the paused
    /// gate: pausing controls whether traffic is intercepted, not whether a
    /// manual health check may run.
    fn route_inner(self: &Arc<Self>, domain: &str, port: u16, tls: bool, probing: bool) -> Route {
        let normalized = match normalize_hostname(domain) {
            Ok(domain) => domain,
            Err(error) => {
                let config = self.config.snapshot();
                return Route::Blocked(self.config_failure(
                    None,
                    domain,
                    &config,
                    FailureReason::ConfigInvalid,
                    format!("invalid domain: {error}"),
                ));
            }
        };
        self.route_with_config(Cow::Owned(normalized), port, tls, probing)
    }

    fn route_with_config(
        self: &Arc<Self>,
        normalized: Cow<'_, str>,
        port: u16,
        tls: bool,
        probing: bool,
    ) -> Route {
        let (config, matcher) = self.config.snapshot_and_matcher();
        let Some((group_id, rule_index)) = matcher.match_entry_normalized(&normalized) else {
            return Route::Bypass(DecisionOutcome {
                plan: None,
                diagnostics: Arc::new(DomainDiagnostics {
                    group: None,
                    domain: normalized.into_owned(),
                    state: State::Direct,
                    strategy: None,
                    configured_modes: Vec::new(),
                    ip: None,
                    ip_source: None,
                    doh_source: None,
                    latency_ms: None,
                    last_check: now(),
                    catalog_version: config.catalog_version,
                    cache: CacheStatus::None,
                    error: None,
                    detail: Some(
                        "domain is not covered by any group; traffic is connected directly".into(),
                    ),
                    attempts: Vec::new(),
                    suggestions: Vec::new(),
                }),
            });
        };
        let Some(group) = config.group(group_id) else {
            return Route::Blocked(self.config_failure(
                Some(group_id.to_string()),
                &normalized,
                &config,
                FailureReason::ConfigInvalid,
                "matched group no longer exists in the configuration".into(),
            ));
        };
        if !group.enabled {
            return Route::Bypass(self.state_only(
                group,
                &normalized,
                &config,
                State::Disabled,
                "group is disabled; traffic is not intercepted",
            ));
        }
        if !probing && self.status.paused() {
            return Route::Bypass(self.state_only(
                group,
                &normalized,
                &config,
                State::Paused,
                "hakimi is paused; traffic is not intercepted",
            ));
        }
        self.status.mark_checking(
            Some(group.id.as_str()),
            &normalized,
            group.route_modes(&normalized),
            config.catalog_version,
        );
        // The cursor keeps an index into this immutable config snapshot, so a
        // new connection does not clone the whole group (and all its domains).
        let group_index = config
            .groups
            .iter()
            .position(|candidate| std::ptr::eq(candidate, group))
            .expect("matched group must come from the config snapshot");
        Route::Group(Box::new(RouteCursor::new(
            self.clone(),
            normalized.into_owned(),
            port,
            tls,
            group_index,
            rule_index,
            config,
            !probing,
        )))
    }

    /// Last successful plan for a new connection. Established pooled connections never
    /// consult this, so it only affects cold connections and raw CONNECT tunnels.
    pub fn cached_plan(&self, domain: &str, port: u16, tls: bool) -> Option<Arc<ConnectPlan>> {
        let (config, matcher) = self.config.snapshot_and_matcher();
        let ttl = Duration::from_secs(config.advanced.plan_cache_secs);
        // The key must be spelled the same way the plan was stored, so a
        // caller that passes a raw host still finds its entry.
        let key = plan_cache_domain(domain);
        let (at, plan) = {
            let cache = self.plan_cache.read();
            let (at, plan) = cache.get(key.as_ref())?.get(&(port, tls))?;
            (at.elapsed(), plan.clone())
        };
        if at >= ttl {
            self.forget_plan(domain, port, tls);
            return None;
        }
        let plan = plan;

        // A catalog update marks affected domains skipOnce: do not reuse the old route
        // before the new remote IPs have been attempted.
        if self.cache.has_skip_once(&plan.domain) {
            return None;
        }
        let group_id = matcher.match_normalized(&plan.domain)?;
        // The domain may have been moved to another group; its old route (and
        // especially its old fake SNI) must not leak into the new group.
        if plan.group_id != group_id {
            return None;
        }
        let group = config.group(group_id)?;
        if !group.enabled || self.status.paused() {
            return None;
        }
        if tls {
            let route = group.route_for(&plan.domain);
            if !route.contains_mode(plan.mode) {
                return None;
            }
            // A route-level fake-SNI list is authoritative. Editing it must not
            // keep using an old name for the rest of the plan-cache lifetime.
            if plan.mode == TlsMode::FakeSni {
                let allowed = route.attempts.iter().any(|attempt| {
                    attempt
                        .sni_hosts()
                        .is_some_and(|hosts| match plan.sni.as_deref() {
                            Some(sni) if hosts.is_empty() => config
                                .advanced
                                .fake_sni_candidates
                                .iter()
                                .any(|host| host.eq_ignore_ascii_case(sni)),
                            Some(sni) => hosts.iter().any(|host| host.eq_ignore_ascii_case(sni)),
                            None => {
                                hosts.is_empty() || hosts.iter().any(|host| host.trim().is_empty())
                            }
                        })
                });
                if !allowed {
                    return None;
                }
            }
        } else if plan.mode != TlsMode::Direct {
            return None;
        }
        if self.route_rejected(&plan.domain, plan.mode) {
            return None;
        }
        Some(plan)
    }

    /// True while an HTTP rejection (403/421/451) keeps this mode out of the
    /// candidate set for the domain.
    pub(super) fn route_rejected(&self, domain: &str, mode: TlsMode) -> bool {
        // The overwhelmingly common case is an empty rejection map. Check it
        // under a shared lock before formatting a key or taking the exclusive
        // lock that `note_http_rejection` needs. This runs for every route
        // attempt of every cold connection.
        if self.route_rejections.read().is_empty() {
            return false;
        }
        let key = format!("{domain}|{}", mode.as_str());
        let expired = {
            let rejections = self.route_rejections.read();
            match rejections.get(&key) {
                Some(at) if at.elapsed() < ROUTE_REJECTION_TTL => return true,
                Some(_) => true,
                None => false,
            }
        };
        if !expired {
            return false;
        }
        let mut rejections = self.route_rejections.write();
        match rejections.get(&key) {
            Some(at) if at.elapsed() < ROUTE_REJECTION_TTL => true,
            Some(_) => {
                rejections.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Called after an upstream response with a status that indicates the route
    /// itself was rejected. A TLS handshake is not enough: Pixiv's fake-SNI
    /// route completes TLS and then returns 403 from nginx. Drop that route and
    /// let the next connection try the next configured attempt.
    pub fn note_http_rejection(&self, domain: &str, port: u16, tls: bool, status: StatusCode) {
        if !matches!(status.as_u16(), 403 | 421 | 451) {
            return;
        }
        let Some(plan) = self.cached_plan(domain, port, tls) else {
            return;
        };
        if plan.mode == TlsMode::Direct {
            return;
        }
        tracing::warn!(
            domain = %plan.domain,
            mode = %plan.mode,
            sni = plan.sni.as_deref().unwrap_or(""),
            status = status.as_u16(),
            "upstream rejected the selected route; re-planning"
        );
        self.forget_plan(&plan.domain, plan.port, plan.tls);
        self.cache.mark_skip_once([plan.domain.clone()]);
        self.record_ip(&plan.domain, plan.ip, None, true);
        let mut rejections = self.route_rejections.write();
        if rejections.len() > 1024 {
            rejections.retain(|_, at| at.elapsed() < ROUTE_REJECTION_TTL);
        }
        rejections.insert(
            format!("{}|{}", plan.domain, plan.mode.as_str()),
            Instant::now(),
        );
    }

    /// Configuration edits can change the route a rejection belonged to.
    pub fn clear_route_rejections(&self) {
        self.route_rejections.write().clear();
    }

    pub fn forget_plan(&self, domain: &str, port: u16, tls: bool) {
        let key = plan_cache_domain(domain);
        let mut cache = self.plan_cache.write();
        let mut empty = false;
        if let Some(inner) = cache.get_mut(key.as_ref()) {
            if inner.remove(&(port, tls)).is_some() {
                self.plan_cache_count.fetch_sub(1, Ordering::Relaxed);
            }
            empty = inner.is_empty();
        }
        if empty {
            cache.remove(key.as_ref());
        }
    }

    /// Drop every remembered route. A network change invalidates the in-memory
    /// shortcut even though the persisted last-good entry is kept (the design
    /// deliberately tests it first on the new network): new connections should
    /// hedge it against fresh candidates instead of blocking on it through the
    /// single-route fast path.
    pub fn forget_all_plans(&self) {
        let mut cache = self.plan_cache.write();
        cache.clear();
        self.plan_cache_count.store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(super) fn score_ip(&self, domain: &str, ip: IpAddr) -> f64 {
        self.ip_scores
            .read()
            .get(domain)
            .and_then(|by_ip| by_ip.get(&ip))
            .map(|score| score.rank())
            .unwrap_or(f64::MAX)
    }

    /// Score a cursor's candidate list under one read lock. A cold route can
    /// have several candidates; taking the score lock once per candidate adds
    /// avoidable synchronization to every new connection.
    pub(super) fn score_candidates(&self, domain: &str, candidates: &[Candidate]) -> Vec<f64> {
        let scores = self.ip_scores.read();
        let by_ip = scores.get(domain);
        candidates
            .iter()
            .map(|candidate| {
                by_ip
                    .and_then(|by_ip| by_ip.get(&candidate.ip))
                    .map(IpScore::rank)
                    .unwrap_or(f64::MAX)
            })
            .collect()
    }

    pub(super) fn record_ip(
        &self,
        domain: &str,
        ip: IpAddr,
        latency_ms: Option<u64>,
        failed: bool,
    ) -> bool {
        let (degraded, score) = self.record_ip_in_memory(domain, ip, latency_ms, failed);
        // Persist both outcomes: a restart must keep knowing that this IP was
        // fast — or blocked — on this network. The cache batches disk writes.
        self.cache.record_outcome(None, score);
        degraded
    }

    /// Update the in-memory quality table and hand the sample back so the
    /// caller can persist it together with the rest of the outcome.
    pub(super) fn record_ip_in_memory<'a>(
        &self,
        domain: &'a str,
        ip: IpAddr,
        latency_ms: Option<u64>,
        failed: bool,
    ) -> (bool, Option<IpScoreUpdate<'a>>) {
        let (snapshot, degraded) = {
            let mut scores = self.ip_scores.write();
            let (is_new, snapshot, degraded) = {
                // Most outcomes update a domain that is already known; avoid
                // allocating a fresh key until the entry is actually missing.
                let by_ip = match scores.get_mut(domain) {
                    Some(by_ip) => by_ip,
                    None => scores.entry(domain.to_string()).or_default(),
                };
                let is_new = !by_ip.contains_key(&ip);
                let entry = by_ip.entry(ip).or_default();
                let degraded;
                if failed {
                    entry.failures += 1;
                    entry.ewma_ms = if entry.ewma_ms == 0.0 {
                        10_000.0
                    } else {
                        entry.ewma_ms * 0.7 + 10_000.0 * 0.3
                    };
                    degraded = false;
                } else {
                    entry.successes += 1;
                    // Pay down the failure history with each real success. Without
                    // this an IP that ever failed stays in `reprobe_failed_ips`
                    // forever, so the same addresses get re-probed every minute for
                    // the whole session even after they recovered.
                    entry.failures = entry.failures.saturating_sub(1);
                    let sample = latency_ms.unwrap_or(500) as f64;
                    // A sample far worse than the established average means the proven route
                    // degraded (network flap, congestion). Signal the caller to re-race.
                    degraded = entry.successes > 2
                        && sample > 800.0
                        && entry.ewma_ms > 0.0
                        && sample > entry.ewma_ms * 2.5;
                    entry.ewma_ms = if entry.successes == 1 {
                        sample
                    } else {
                        entry.ewma_ms * 0.7 + sample * 0.3
                    };
                }
                (
                    is_new,
                    (entry.ewma_ms, entry.successes, entry.failures),
                    degraded,
                )
            };
            if is_new {
                self.ip_score_count.fetch_add(1, Ordering::Relaxed);
            }
            // Bounded map: when full, drop the least valuable entries — the ones
            // with the worst measured quality — instead of wiping everything. A
            // flood of dead IPs must never erase knowledge of a proven route.
            let total = self.ip_score_count.load(Ordering::Relaxed);
            if total > IP_SCORE_CAP {
                let mut ranked: Vec<((String, IpAddr), f64)> = scores
                    .iter()
                    .flat_map(|(domain, by_ip)| {
                        by_ip
                            .iter()
                            .map(|(ip, score)| ((domain.clone(), *ip), score.rank()))
                    })
                    .collect();
                ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                let mut removed = 0usize;
                for ((domain, ip), _) in ranked.into_iter().take(total - IP_SCORE_PRUNE_TO) {
                    if let Some(by_ip) = scores.get_mut(&domain) {
                        if by_ip.remove(&ip).is_some() {
                            removed += 1;
                        }
                        if by_ip.is_empty() {
                            scores.remove(&domain);
                        }
                    }
                }
                self.ip_score_count.fetch_sub(removed, Ordering::Relaxed);
            }
            (snapshot, degraded)
        };
        let score = IpScoreUpdate {
            domain,
            ip,
            ewma_ms: snapshot.0,
            successes: snapshot.1,
            failures: snapshot.2,
        };
        (degraded, Some(score))
    }

    /// Store a plan that is already shared. The plan cache keeps the same
    /// allocation, so a successful connection no longer deep-copies the
    /// domain, group and SNI strings.
    pub(super) fn remember_plan_arc(&self, plan: Arc<ConnectPlan>) {
        let mut cache = self.plan_cache.write();
        let mut total = self.plan_cache_count.load(Ordering::Relaxed);
        if total >= PLAN_CACHE_MAX {
            let ttl = Duration::from_secs(self.config.snapshot().advanced.plan_cache_secs);
            let mut retained = 0;
            cache.retain(|_, inner| {
                inner.retain(|_, (at, _)| at.elapsed() < ttl);
                retained += inner.len();
                !inner.is_empty()
            });
            total = retained;
            // A crawler can push more than the cap of *fresh* plans in the TTL
            // window; keep the newest instead of scanning the full map on every
            // subsequent success.
            if total >= PLAN_CACHE_MAX {
                let mut ages: Vec<(String, u16, bool, Instant)> = Vec::new();
                for (domain, inner) in cache.iter() {
                    for ((port, tls), (at, _)) in inner.iter() {
                        ages.push((domain.clone(), *port, *tls, *at));
                    }
                }
                ages.sort_by_key(|(_, _, _, at)| *at);
                let excess = total - PLAN_CACHE_PRUNE_TO;
                let mut removed = 0;
                for (domain, port, tls, _) in ages.into_iter().take(excess) {
                    let mut empty = false;
                    if let Some(inner) = cache.get_mut(&domain) {
                        if inner.remove(&(port, tls)).is_some() {
                            removed += 1;
                        }
                        empty = inner.is_empty();
                    }
                    if empty {
                        cache.remove(&domain);
                    }
                }
                total = total.saturating_sub(removed);
            }
            self.plan_cache_count.store(total, Ordering::Relaxed);
        }
        let domain = plan_cache_domain(&plan.domain).into_owned();
        let port = plan.port;
        let tls = plan.tls;
        let entry = (Instant::now(), plan);
        match cache.get_mut(&domain) {
            Some(inner) => {
                if inner.insert((port, tls), entry).is_none() {
                    self.plan_cache_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                let mut inner = HashMap::new();
                inner.insert((port, tls), entry);
                cache.insert(domain, inner);
                self.plan_cache_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn plan_cache_len(&self) -> usize {
        self.plan_cache_count.load(Ordering::Relaxed)
    }

    /// TCP-probe IPs that accumulated failures and forgive the ones that answer
    /// again. A temporary block (GFW reset, network flap) should not bury a
    /// working address under its failure score forever.
    pub async fn reprobe_failed_ips(self: &Arc<Self>, limit: usize) -> usize {
        let candidates: Vec<(String, IpAddr)> = {
            let scores = self.ip_scores.read();
            let mut list: Vec<(&str, IpAddr, u32)> = scores
                .iter()
                .flat_map(|(domain, by_ip)| {
                    by_ip
                        .iter()
                        .filter(|(_, score)| score.failures > 0)
                        .map(|(ip, score)| (domain.as_str(), *ip, score.failures))
                })
                .collect();
            list.sort_by(|a, b| b.2.cmp(&a.2));
            list.truncate(limit);
            list.into_iter()
                .map(|(domain, ip, _)| (domain.to_string(), ip))
                .collect()
        };
        if candidates.is_empty() {
            return 0;
        }

        let mut set = tokio::task::JoinSet::new();
        for (domain, ip) in candidates {
            let engine = self.clone();
            set.spawn(async move {
                match engine
                    .prober
                    .probe_tcp(ip, 443, Duration::from_secs(3))
                    .await
                {
                    Ok(latency) => {
                        // A successful probe is a real sample: the success count
                        // rises, so the fail rate — and the rank — recover.
                        engine.record_ip(&domain, ip, Some(latency), false);
                        true
                    }
                    Err(_) => false,
                }
            });
        }
        let mut restored = 0;
        while let Some(joined) = set.join_next().await {
            if matches!(joined, Ok(true)) {
                restored += 1;
            }
        }
        if restored > 0 {
            tracing::info!(restored, "failed ip scores restored after re-probe");
        }
        restored
    }

    /// Record a raw-tunnel success (TCP only; the browser's own TLS handshake validates the
    /// certificate end to end).
    pub fn note_tunnel_success(&self, plan: &Arc<ConnectPlan>, latency_ms: u64) {
        let config = self.config.snapshot();
        self.record_success(
            plan,
            latency_ms,
            Vec::new(),
            &DohExpansion::default(),
            &config,
        );
    }

    pub(super) fn record_success(
        &self,
        plan: &Arc<ConnectPlan>,
        latency_ms: u64,
        attempts: Vec<AttemptRecord>,
        doh: &DohExpansion,
        config: &AppConfig,
    ) -> Arc<DomainDiagnostics> {
        let cache_status = match plan.source {
            IpSource::Cache => CacheStatus::Fresh,
            IpSource::DohCache => CacheStatus::Stale,
            IpSource::Remote | IpSource::Doh => CacheStatus::None,
        };
        let doh_source = match plan.source {
            IpSource::Doh | IpSource::DohCache => doh.source,
            _ => None,
        };
        if attempts.len() > 1 {
            for (index, attempt) in attempts.iter().enumerate() {
                tracing::info!(
                    domain = %plan.domain,
                    attempt = index + 1,
                    strategy = ?attempt.strategy,
                    ip = %attempt.ip,
                    source = ?attempt.source,
                    error = ?attempt.error,
                    "failed candidate before success"
                );
            }
        }
        let attempts_total = attempts.len();
        let diagnostics = Arc::new(DomainDiagnostics {
            group: Some(plan.group_id.clone()),
            domain: plan.domain.clone(),
            state: if plan.mode == TlsMode::Direct {
                State::Direct
            } else {
                State::Normal
            },
            strategy: Some(plan.mode),
            configured_modes: config
                .group(&plan.group_id)
                .map(|group| group.route_modes(&plan.domain))
                .unwrap_or_default(),
            ip: Some(plan.ip),
            ip_source: Some(plan.source),
            doh_source,
            latency_ms: Some(latency_ms),
            last_check: now(),
            catalog_version: config.catalog_version,
            cache: cache_status,
            error: None,
            detail: None,
            // The failed candidates are logged above and only shown on the
            // error page, which is built for a failed state.  Keeping them
            // would make every visited domain carry a few strings.
            attempts: Vec::new(),
            suggestions: Vec::new(),
        });
        let (degraded, score) =
            self.record_ip_in_memory(&plan.domain, plan.ip, Some(latency_ms), false);
        // One cache write for the route and the quality sample.
        self.cache.record_outcome(
            Some(LastGoodEntry {
                domain: plan.domain.clone(),
                ip: plan.ip,
                source: plan.source,
                network_id: network_id(),
                saved_at: now(),
                catalog_version: config.catalog_version,
            }),
            score,
        );
        self.remember_plan_arc(plan.clone());
        if degraded {
            // The proven route suddenly got slow: drop the cached plan so the next
            // connection re-races the routes instead of staying pinned to it.
            tracing::info!(
                domain = %plan.domain,
                latency_ms,
                "route degraded; re-racing routes on the next connection"
            );
            self.forget_plan(&plan.domain, plan.port, plan.tls);
        }
        self.status.record_arc(diagnostics.clone());
        tracing::info!(
            group = %plan.group_id,
            domain = %plan.domain,
            ip = %plan.ip,
            mode = %plan.mode,
            source = %plan.source,
            latency_ms,
            attempts = attempts_total,
            "resolved connection strategy"
        );
        diagnostics
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn failure_diagnostics(
        &self,
        group: &GroupConfig,
        domain: &str,
        config: &AppConfig,
        reason: FailureReason,
        attempts: Vec<AttemptRecord>,
        doh: &DohExpansion,
        detail: Option<String>,
    ) -> Arc<DomainDiagnostics> {
        let mut suggestions = vec![reason.suggestion().to_string()];
        if !self.remote.has_ip_catalog() {
            let extra = "No remote IP catalog is loaded; configure catalogs.ip or wait for the next refresh.";
            if !suggestions.iter().any(|item| item == extra) {
                suggestions.push(extra.to_string());
            }
        }
        if let Some(error) = &doh.error {
            suggestions.push(format!("DoH error: {error}"));
        }
        let provisional = self.warming.load(Ordering::Relaxed);
        let diagnostics = Arc::new(DomainDiagnostics {
            group: Some(group.id.clone()),
            domain: domain.to_string(),
            state: if provisional {
                State::Checking
            } else {
                State::Failed
            },
            strategy: None,
            configured_modes: group.route_modes(domain),
            ip: None,
            ip_source: None,
            doh_source: doh.source,
            latency_ms: None,
            last_check: now(),
            catalog_version: config.catalog_version,
            cache: if doh.stale {
                CacheStatus::Stale
            } else {
                CacheStatus::None
            },
            error: Some(reason),
            detail,
            attempts,
            suggestions,
        });
        self.status.record_arc(diagnostics.clone());
        tracing::warn!(
            group = %group.id,
            domain = %domain,
            reason = %reason,
            "all connection strategies failed"
        );
        diagnostics
    }

    fn internal_failure(&self, domain: &str) -> DecisionOutcome {
        let config = self.config.snapshot();
        self.config_failure(
            None,
            domain,
            &config,
            FailureReason::Internal,
            "route generator ended without a result".into(),
        )
    }

    pub(super) async fn expand_doh(
        &self,
        domain: &str,
        candidates: &mut Vec<Candidate>,
        max: usize,
    ) -> DohExpansion {
        let started = std::time::Instant::now();
        match self.resolver.doh_ips(domain).await {
            Ok(DohResolution {
                ips,
                hints,
                source,
                stale,
                ..
            }) => {
                let elapsed = started.elapsed().as_millis() as u64;
                let candidate_source = if stale {
                    IpSource::DohCache
                } else {
                    IpSource::Doh
                };
                let before = candidates.len();
                for ip in ips.into_iter().chain(hints) {
                    if candidates.len() >= max {
                        break;
                    }
                    // The candidate list is capped at eight entries, so a
                    // linear scan replaces the per-cursor hash set.
                    if !candidates.iter().any(|candidate| candidate.ip == ip) {
                        candidates.push(Candidate {
                            ip,
                            source: candidate_source,
                        });
                    }
                }
                // DoH is the expensive fallback: its cost and yield decide
                // whether the catalog needs better coverage.
                if elapsed > 1000 {
                    tracing::warn!(
                        domain = %domain,
                        source = ?source,
                        stale,
                        added = candidates.len() - before,
                        elapsed_ms = elapsed,
                        "doh expansion was slow"
                    );
                } else {
                    tracing::info!(
                        domain = %domain,
                        source = ?source,
                        stale,
                        added = candidates.len() - before,
                        elapsed_ms = elapsed,
                        "doh expansion"
                    );
                }
                DohExpansion {
                    source: Some(source),
                    error: None,
                    stale,
                }
            }
            Err(error) => {
                tracing::warn!(
                    domain = %domain,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    error = %format!("{error:#}"),
                    "doh expansion failed"
                );
                DohExpansion {
                    source: None,
                    error: Some(format!("{error:#}")),
                    stale: false,
                }
            }
        }
    }

    fn config_failure(
        &self,
        group: Option<String>,
        domain: &str,
        config: &AppConfig,
        reason: FailureReason,
        detail: String,
    ) -> DecisionOutcome {
        let diagnostics = Arc::new(DomainDiagnostics {
            group,
            domain: domain.to_string(),
            state: State::Failed,
            strategy: None,
            configured_modes: Vec::new(),
            ip: None,
            ip_source: None,
            doh_source: None,
            latency_ms: None,
            last_check: now(),
            catalog_version: config.catalog_version,
            cache: CacheStatus::None,
            error: Some(reason),
            detail: Some(detail),
            attempts: Vec::new(),
            suggestions: vec![reason.suggestion().to_string()],
        });
        self.status.record_arc(diagnostics.clone());
        DecisionOutcome {
            plan: None,
            diagnostics,
        }
    }

    fn state_only(
        &self,
        group: &GroupConfig,
        domain: &str,
        config: &AppConfig,
        state: State,
        detail: &str,
    ) -> DecisionOutcome {
        let diagnostics = Arc::new(DomainDiagnostics {
            group: Some(group.id.clone()),
            domain: domain.to_string(),
            state,
            strategy: None,
            configured_modes: group.route_modes(domain),
            ip: None,
            ip_source: None,
            doh_source: None,
            latency_ms: None,
            last_check: now(),
            catalog_version: config.catalog_version,
            cache: CacheStatus::None,
            error: None,
            detail: Some(detail.to_string()),
            attempts: Vec::new(),
            suggestions: Vec::new(),
        });
        DecisionOutcome {
            plan: None,
            diagnostics,
        }
    }
}
