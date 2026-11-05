use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::StatusCode;

use crate::cache::{CacheManager, LastGoodEntry};
use crate::catalog::RemoteIpProvider;
use crate::config::{AppConfig, ConfigManager, EchSource, GroupConfig, RoutePolicy};
use crate::domain::normalize_hostname;
use crate::resolver::{DohResolution, IpResolver};
use crate::status::{AttemptRecord, DomainDiagnostics, State, StatusStore};
use crate::strategy::{CacheStatus, DohSource, FailureReason, IpSource, TlsMode};
use crate::util::now;

use super::cursor::{Route, RouteCursor};
use super::plan::{ConnectPlan, DecisionOutcome, Prober};
use super::score::{IpScore, IP_SCORE_CAP, IP_SCORE_PRUNE_TO, UNSEEN_RANK};
use super::types::{Candidate, DohExpansion, EARLY_DOH_AFTER};

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
    pub(super) route_rejections: parking_lot::RwLock<HashMap<String, Instant>>,
    /// Individual IPs that returned an abuse/block page for a domain. Unlike
    /// `route_rejections`, only the address is dropped; other IPs on the same
    /// route mode may still work.
    pub(super) ip_rejections: parking_lot::RwLock<HashMap<String, HashMap<IpAddr, Instant>>>,
    /// Fake-SNI names that answered with a certificate which cannot cover the
    /// domain. This is the one failure that is a property of the *name*: the
    /// same CDN edge serves the same foreign certificate on every address, so
    /// redialling the name on the next cold connection only burns a handshake.
    /// Keyed by domain (the cert has to cover that name), then by the name
    /// (`None` is "no SNI"); entries expire after [`SNI_REJECTION_TTL`].
    pub(super) sni_rejections: parking_lot::RwLock<HashMap<String, HashMap<Option<String>, Instant>>>,
    /// The route that was last logged for a domain.
    ///
    /// The resolution line is by far the most frequent line in the log: a
    /// route that is reused for every connection of a domain says nothing
    /// new, while a route *change* is exactly what an operator wants to see.
    /// The map is bounded; when it overflows the stale entries are dropped,
    /// which costs one extra line per domain and nothing else.
    logged_routes: parking_lot::RwLock<HashMap<String, (IpAddr, TlsMode, Instant)>>,
    /// Live routes, remembered for the background recheck.
    ///
    /// A pooled connection never reports another handshake, so `ip_scores`
    /// freezes at connect time and the degraded check cannot fire. This is the
    /// only table that knows which plan is live and when it was last compared
    /// against an alternative.
    route_quality: parking_lot::RwLock<HashMap<String, RouteQuality>>,
    /// Token bucket for the recheck, so a burst of domains cannot turn the
    /// background task into a probe storm.
    recheck_budget: parking_lot::Mutex<(f64, Instant)>,
    /// True while the initial warmup is probing. Failures are published as
    /// Checking instead of Failed so the first probe's retry does not flash
    /// red; the runtime settles the remaining ones after warmup.
    warming: AtomicBool,
    /// Exponential backoff for re-probing addresses that keep failing. A
    /// permanently walled address otherwise tops the failure ranking and is
    /// re-probed every minute forever.
    pub(super) probe_backoff: parking_lot::Mutex<HashMap<(String, IpAddr), (u32, Instant)>>,
}

pub(super) const PLAN_CACHE_MAX: usize = 2048;
/// Leave headroom after a prune so a burst of new hosts does not sort the map
/// on every success.
pub(super) const PLAN_CACHE_PRUNE_TO: usize = PLAN_CACHE_MAX * 3 / 4;
/// How many domains keep a "last logged route" stamp.
const LOGGED_ROUTE_MAX: usize = 1024;
/// How long a route stamp survives. A domain that has not been seen for this
/// long is treated as new the next time it connects.
const LOGGED_ROUTE_TTL: Duration = Duration::from_secs(600);
/// How long an HTTP-rejected route stays out of the candidate set.
const ROUTE_REJECTION_TTL: Duration = Duration::from_secs(300);
/// How long a block-page IP stays out of a domain's candidate set.
const IP_REJECTION_TTL: Duration = Duration::from_secs(300);
/// How long a fake-SNI name stays out after answering with a foreign
/// certificate. Long enough to stop the repeat on every cold connection, short
/// enough that a changed CDN edge or a config fix recovers on its own.
pub(super) const SNI_REJECTION_TTL: Duration = Duration::from_secs(600);
/// Cap for the re-probe backoff of continuously failing addresses.
const PROBE_BACKOFF_MAX: Duration = Duration::from_secs(1800);
/// Entry cap for the same table, matching the other observation tables.
const PROBE_BACKOFF_ENTRIES: usize = 1024;
/// Cap for the live-route table. Only domains that actually connected have an
/// entry, and an idle one is evicted before the map grows past this.
const ROUTE_QUALITY_CAP: usize = 1024;
/// How long a live route may go unverified.
const RECHECK_INTERVAL: Duration = Duration::from_secs(300);
/// A challenger must beat the live route by this factor to count as faster.
const RECHECK_MARGIN: f64 = 0.75;
/// Consecutive confirmations before a route is retired, so one lucky sample
/// cannot flap a healthy route.
const RECHECK_CONFIRMATIONS: u8 = 2;
/// Checks per minute. One check costs two handshakes, live route plus rival.
const RECHECK_CHECKS_PER_MIN: f64 = 3.0;
/// A domain with no successful connection for this long is not worth a probe.
const ROUTE_ACTIVE_WINDOW: Duration = Duration::from_secs(900);

/// One live route, kept so the background task can compare it.
struct RouteQuality {
    plan: Arc<ConnectPlan>,
    last_seen: Instant,
    checked_at: Instant,
    challenger: Option<IpAddr>,
    streak: u8,
}

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

/// Addresses retired during one serial route discovery.
///
/// The pooled race keeps the same verdict in `IpGate`, including the queued
/// variants and the "an address that answered is open for its other variants"
/// state. A serial probe needs none of that: it never has two plans of one
/// address in flight, so the whole policy collapses to "this address is dead".
#[derive(Default)]
struct DeadAddresses(std::collections::HashSet<IpAddr>);

impl DeadAddresses {
    fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(&ip)
    }

    /// Record a failure verdict. Only an address-level failure retires the IP;
    /// a stalled or rejected handshake proves the address answered and leaves
    /// its other variants eligible.
    fn record(&mut self, ip: IpAddr, reason: FailureReason) {
        if reason.is_ip_level() {
            self.0.insert(ip);
        }
    }
}

/// Scope guard for the warmup window opened by [`DecisionEngine::begin_warmup`].
///
/// Dropping the guard while it is still armed finishes the window, so a
/// warm-up future cancelled mid-flight (it runs inside a shutdown `select!`)
/// cannot leave the engine warming forever — every later probe would then
/// stay provisional.
pub struct WarmupGuard<'a> {
    engine: &'a DecisionEngine,
    armed: bool,
}

impl WarmupGuard<'_> {
    /// Hand the finish to a later task (the warm-up summary). The guard then
    /// stays silent when it drops.
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WarmupGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.engine.finish_warmup();
        }
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
        // Quality scores are learned per process: they describe the path this
        // run actually measured, so nothing is carried over from a restart.
        Arc::new(Self {
            config,
            cache,
            remote,
            resolver,
            prober,
            status,
            plan_cache: parking_lot::RwLock::new(HashMap::new()),
            ip_scores: parking_lot::RwLock::new(HashMap::new()),
            ip_score_count: AtomicUsize::new(0),
            plan_cache_count: AtomicUsize::new(0),
            route_rejections: parking_lot::RwLock::new(HashMap::new()),
            ip_rejections: parking_lot::RwLock::new(HashMap::new()),
            sni_rejections: parking_lot::RwLock::new(HashMap::new()),
            logged_routes: parking_lot::RwLock::new(HashMap::new()),
            route_quality: parking_lot::RwLock::new(HashMap::new()),
            recheck_budget: parking_lot::Mutex::new((1.0, Instant::now())),
            probe_backoff: parking_lot::Mutex::new(HashMap::new()),
            warming: AtomicBool::new(false),
        })
    }

    /// Remember the route that was last logged for `domain` and report whether
    /// it changed.
    ///
    /// The stamp expires so a domain that has not been seen for a while is
    /// treated as new the next time it connects.
    fn route_changed(&self, domain: &str, ip: IpAddr, mode: TlsMode) -> bool {
        let now = Instant::now();
        // The common case is an unchanged route. A read lock is enough for
        // it, which keeps the success path off the exclusive lock.
        {
            let routes = self.logged_routes.read();
            if let Some((known_ip, known_mode, at)) = routes.get(domain) {
                if *known_ip == ip
                    && *known_mode == mode
                    && now.duration_since(*at) < LOGGED_ROUTE_TTL
                {
                    return false;
                }
            }
        }
        let mut routes = self.logged_routes.write();
        if routes.len() >= LOGGED_ROUTE_MAX {
            routes.retain(|_, (_, _, at)| now.duration_since(*at) < LOGGED_ROUTE_TTL);
            if routes.len() >= LOGGED_ROUTE_MAX {
                routes.clear();
            }
        }
        match routes.get_mut(domain) {
            // Unchanged route: refresh the stamp so the read-lock fast path
            // keeps working and the retention below never drops an active
            // domain (which would log a phantom "changed" route).
            Some((known_ip, known_mode, at)) if *known_ip == ip && *known_mode == mode => {
                *at = now;
                false
            }
            _ => {
                routes.insert(domain.to_string(), (ip, mode, now));
                true
            }
        }
    }

    /// Mark the start of the initial warmup. Probe failures stay in Checking
    /// until [`Self::finish_warmup`] so a first attempt that is immediately
    /// retried does not publish Failed and then Normal.
    ///
    /// The returned guard finishes the window on drop unless it is
    /// [`WarmupGuard::disarm`]ed: the warm-up future runs inside a
    /// shutdown `select!`, and a cancellation between here and the summary
    /// task would otherwise leave the engine warming forever — every later
    /// probe would then stay provisional.
    pub fn begin_warmup(&self) -> WarmupGuard<'_> {
        self.warming.store(true, Ordering::SeqCst);
        WarmupGuard {
            engine: self,
            armed: true,
        }
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
            Route::Group(mut cursor) => {
                // A serial probe has to apply the same address verdict the
                // pooled race applies through `IpGate`: once the TCP handshake
                // failed, no other (mode, SNI) variant on that address can
                // succeed, and dialling each of them only spends one full
                // timeout per variant. The rule itself lives in
                // `FailureReason::is_ip_level`, so the two paths cannot drift.
                //
                // This is deliberately local to the serial caller: the race
                // cannot use it because its plans are already in flight when
                // the first verdict arrives.
                let mut dead = DeadAddresses::default();
                let mut skipped = 0usize;
                loop {
                    let Some(plan) = cursor.next_plan().await else {
                        if skipped > 0 {
                            tracing::debug!(
                                domain = %domain,
                                skipped,
                                "skipped the remaining variants of an address that failed at the TCP level"
                            );
                        }
                        return cursor
                            .outcome()
                            .cloned()
                            .unwrap_or_else(|| self.internal_failure(domain));
                    };
                    if dead.contains(plan.ip) {
                        skipped += 1;
                        continue;
                    }
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
                            dead.record(plan.ip, error.reason());
                            cursor.note_failure(&plan, error.reason(), error.detail());
                        }
                    }
                }
            }
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
                rule_index,
                &config,
                State::Disabled,
                "group is disabled; traffic is not intercepted",
            ));
        }
        if !probing && self.status.paused() {
            return Route::Bypass(self.state_only(
                group,
                &normalized,
                rule_index,
                &config,
                State::Paused,
                "hakimi is paused; traffic is not intercepted",
            ));
        }
        // The matcher already resolved the rule index. Building the mode list
        // lazily avoids both a rule scan and an allocation when the status
        // debounce below decides that this reconnect needs no new record.
        self.status.mark_checking_lazy(
            Some(group.id.as_str()),
            &normalized,
            || group.route_modes_at(rule_index),
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
        if self.ip_rejected(&plan.domain, plan.ip) {
            self.forget_plan(domain, port, tls);
            return None;
        }
        let plan = plan;

        // A catalog update marks affected domains skipOnce: do not reuse the old route
        // before the new remote IPs have been attempted.
        if self.cache.has_skip_once(&plan.domain) {
            return None;
        }
        let (group_id, rule_index) = matcher.match_entry_normalized(&plan.domain)?;
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
            // The matcher and the config snapshot are published together, so
            // the rule index resolves the same route as `route_for` did while
            // avoiding a scan over every domain in the group on every reused
            // cold plan.
            let route = group.route_at(rule_index);
            if !route.contains_mode(plan.mode) {
                return None;
            }
            // A route-level fake-SNI list is authoritative. Editing it must not
            // keep using an old name for the rest of the plan-cache lifetime.
            if plan.mode == TlsMode::FakeSni {
                let allowed = route.attempts.iter().any(|attempt| {
                    attempt.sni_hosts().is_some_and(|hosts| {
                        if hosts.is_empty() {
                            // A global-list route may dial anything the ladder
                            // contains, including the two implicit entries.
                            crate::config::global_sni_allowed(
                                &plan.domain,
                                plan.sni.as_deref(),
                                &config.advanced.fake_sni_candidates,
                            )
                        } else {
                            match plan.sni.as_deref() {
                                Some(sni) => {
                                    hosts.iter().any(|host| host.eq_ignore_ascii_case(sni))
                                }
                                None => hosts.iter().any(|host| host.trim().is_empty()),
                            }
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

    /// Start cold DNS/ECH work while the browser is still doing its local TLS
    /// handshake. A MITM CONNECT already knows the destination before the
    /// first HTTP request arrives, so doing this from the request path leaves
    /// the DoH round trip on the critical path for no reason.
    ///
    /// Only cold routes are touched: a valid plan cache entry or a cached
    /// catalog/last-good address means the route already has an IP to race.
    pub(crate) fn prefetch_cold_route(&self, domain: &str, port: u16, route: &RoutePolicy) {
        if self.cached_plan(domain, port, true).is_some() {
            return;
        }
        let config = self.config.snapshot();
        let (_, last_good) = self
            .cache
            .route_hints(domain, config.advanced.last_good_days);
        let (remote, _) = self.remote.remote_ips_with_catalog(domain);
        // A domain with no known address at all and a domain with exactly one
        // known address need the same thing: a second address to fall back to.
        // The second case is the dangerous one, because a single remembered
        // address that is black-holed leaves the connection with nowhere to
        // go — and the DoH lookup that could have supplied an alternative only
        // starts once the first attempt has already burned its timeout.
        let known = last_good.is_some() as usize + remote.as_ref().map_or(0, |ips| ips.len());
        // A thin list has no fallback. A *full* list is the other dangerous
        // case: the cursor only expands to DoH after one of those candidates
        // has already failed, and all of them may be black-holed. Start the
        // lookup during the browser handshake in both cases, so the answer is
        // cached by the time the first failure releases the fallback.
        if known < EARLY_DOH_AFTER || known >= config.advanced.max_candidates_per_domain {
            let resolver = self.resolver.clone();
            let domain = domain.to_string();
            tokio::spawn(async move {
                let _ = resolver.doh_ips(&domain).await;
            });
        }

        // ECH is a second independent DoH lookup. Kick it off too so a route
        // that needs ECH does not pay for it after the browser request lands.
        let mut prefetch_own = false;
        let mut prefetch_shared = false;
        for attempt in &route.attempts {
            let Some(source) = attempt.ech_source() else {
                continue;
            };
            if self.cache.ech(domain, true).is_some() {
                continue;
            }
            match source {
                EchSource::Own => prefetch_own = true,
                EchSource::Shared => prefetch_shared = true,
            }
        }
        for allow_shared in [false, true] {
            let should = if allow_shared {
                prefetch_shared
            } else {
                prefetch_own
            };
            if !should {
                continue;
            }
            let resolver = self.resolver.clone();
            let domain = domain.to_string();
            tokio::spawn(async move {
                let _ = resolver.doh_ech_config(&domain, allow_shared).await;
            });
        }
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
    ///
    /// Every action here is mode-scoped, never IP-scoped: a route-level 403
    /// says nothing about the address (the same policy as
    /// [`Self::note_blocked_candidate`]), so a route rejection must not touch
    /// `ip_scores`. The plan comes from the cache — a pooled response cannot
    /// be attributed to the connection that produced it — which is safe
    /// precisely because no action depends on the plan's IP.
    ///
    /// Returns true when the plan (route) was actually rejected, so the pool
    /// can retire the connection that produced the response instead of handing
    /// it to the next request.
    #[must_use]
    pub fn note_http_rejection(
        &self,
        domain: &str,
        port: u16,
        tls: bool,
        status: StatusCode,
    ) -> bool {
        if !matches!(status.as_u16(), 403 | 421 | 451) {
            return false;
        }
        let Some(plan) = self.cached_plan(domain, port, tls) else {
            return false;
        };
        if plan.mode == TlsMode::Direct {
            return false;
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
        let mut rejections = self.route_rejections.write();
        if rejections.len() > 1024 {
            rejections.retain(|_, at| at.elapsed() < ROUTE_REJECTION_TTL);
        }
        rejections.insert(
            format!("{}|{}", plan.domain, plan.mode.as_str()),
            Instant::now(),
        );
        true
    }

    /// Apply the status policy shared by real upstream traffic. Candidate-level
    /// block pages take precedence for groups that opt in, so one abusive IP
    /// does not discard an otherwise healthy route mode. Everything else falls
    /// back to the route-level rejection policy.
    ///
    /// The return value says whether the response invalidated the selected
    /// route/IP; only then must the pooled connection that produced it stop
    /// serving later requests.
    #[must_use]
    pub fn note_upstream_response(
        &self,
        domain: &str,
        port: u16,
        tls: bool,
        status: StatusCode,
    ) -> bool {
        if matches!(status.as_u16(), 400 | 403 | 429 | 451)
            && self.note_blocked_candidate(domain, port, tls, status, false)
        {
            return true;
        }
        self.note_http_rejection(domain, port, tls, status)
    }

    /// A block or rate-limit page is tied to the candidate IP, not necessarily
    /// to the route mode. Penalize just that IP and re-plan; rejecting the
    /// whole mode would also discard its healthy addresses. Only groups that
    /// opt in (currently GitHub) are affected; for every other site the
    /// response remains a normal warm-up result.
    ///
    /// `penalize_ip` marks callers that can attribute the response to the
    /// connection's own plan. The warm-up dials fresh and may penalize; the
    /// traffic path looks the plan up in the cache, where a newer generation
    /// may have replaced it — penalizing then would block the current best IP
    /// for the rejection window while the real offender keeps serving. The
    /// traffic path still retires the route (`forget_plan` + `skip_once`) so
    /// the next connection re-plans; the IP-level feedback is left to warm-up
    /// and the periodic route recheck.
    pub fn note_blocked_candidate(
        &self,
        domain: &str,
        port: u16,
        tls: bool,
        status: StatusCode,
        penalize_ip: bool,
    ) -> bool {
        let Some(plan) = self.cached_plan(domain, port, tls) else {
            return false;
        };
        if plan.mode != TlsMode::Direct {
            // A masked-SNI request is rejected by the origin for the name
            // mismatch itself: api.github.com answers such warm-ups with a
            // steady 403/429, which says nothing about the address. Only a
            // block page on the real SNI proves the IP serves one.
            tracing::debug!(
                domain = %plan.domain,
                ip = %plan.ip,
                mode = %plan.mode,
                status = status.as_u16(),
                "block-page status on a masked-SNI route; not penalizing"
            );
            return false;
        }
        let config = self.config.snapshot();
        let Some(group) = config.group(&plan.group_id) else {
            return false;
        };
        if !group.recovers_blocked_ips() {
            return false;
        }
        tracing::warn!(
            domain = %plan.domain,
            ip = %plan.ip,
            mode = %plan.mode,
            status = status.as_u16(),
            "upstream returned a block page; retiring the route"
        );
        self.forget_plan(&plan.domain, plan.port, plan.tls);
        self.cache.mark_skip_once([plan.domain.clone()]);
        if !penalize_ip {
            return true;
        }
        self.record_ip(&plan.domain, plan.ip, None, true);
        let mut rejected = self.ip_rejections.write();
        if rejected.len() > 1024 {
            let now = Instant::now();
            for by_ip in rejected.values_mut() {
                by_ip.retain(|_, at| now.duration_since(*at) < IP_REJECTION_TTL);
            }
            rejected.retain(|_, by_ip| !by_ip.is_empty());
        }
        rejected
            .entry(plan.domain.clone())
            .or_default()
            .insert(plan.ip, Instant::now());
        true
    }

    /// True while `ip` is excluded for `domain` after an abuse/block response.
    pub(super) fn ip_rejected(&self, domain: &str, ip: IpAddr) -> bool {
        self.ip_rejections
            .read()
            .get(domain)
            .and_then(|by_ip| by_ip.get(&ip))
            .is_some_and(|at| at.elapsed() < IP_REJECTION_TTL)
    }

    /// True while this fake-SNI name is not worth dialling for `domain`.
    ///
    /// Only a certificate mismatch lands here: the name is what the server
    /// answered with, not the address, so another IP of the same origin would
    /// answer the same way. A reset or a stalled handshake says nothing about
    /// the name and must keep its turn.
    ///
    /// `name` is compared as the dialer spells it (lowercase, `None` for "no
    /// SNI"); both the recorder and this lookup take the name straight from the
    /// ladder, so the two spellings cannot drift.
    pub(super) fn sni_rejected(&self, domain: &str, name: Option<&str>) -> bool {
        let rejected = self.sni_rejections.read();
        let Some(by_name) = rejected.get(domain) else {
            return false;
        };
        by_name
            .iter()
            .any(|(known, at)| known.as_deref() == name && at.elapsed() < SNI_REJECTION_TTL)
    }

    /// Remember that `name` got a certificate that cannot cover `domain`.
    pub(super) fn note_sni_rejection(&self, domain: &str, name: Option<String>) {
        let mut rejected = self.sni_rejections.write();
        if rejected.len() > 1024 {
            let now = Instant::now();
            for by_name in rejected.values_mut() {
                by_name.retain(|_, at| now.duration_since(*at) < SNI_REJECTION_TTL);
            }
            rejected.retain(|_, by_name| !by_name.is_empty());
        }
        rejected
            .entry(domain.to_string())
            .or_default()
            .insert(name, Instant::now());
    }

    /// A name that just validated is no longer rejected.
    pub(super) fn clear_sni_rejection(&self, domain: &str, name: Option<&str>) {
        if self.sni_rejections.read().is_empty() {
            return;
        }
        let mut rejected = self.sni_rejections.write();
        if let Some(by_name) = rejected.get_mut(domain) {
            by_name.remove(&name.map(str::to_owned));
            if by_name.is_empty() {
                rejected.remove(domain);
            }
        }
    }

    /// Whether a failed address is due for another re-probe attempt.
    pub(super) fn probe_backoff_ready(&self, domain: &str, ip: IpAddr) -> bool {
        let map = self.probe_backoff.lock();
        map.get(&(domain.to_string(), ip))
            .is_none_or(|(_, next)| *next <= Instant::now())
    }

    fn note_probe_failure(&self, domain: &str, ip: IpAddr) {
        let mut map = self.probe_backoff.lock();
        // Bounded like every other observation table. Expired entries are
        // already "ready", so dropping them changes nothing observable.
        if map.len() >= PROBE_BACKOFF_ENTRIES {
            let now = Instant::now();
            map.retain(|_, (_, next)| *next > now);
            if map.len() >= PROBE_BACKOFF_ENTRIES {
                map.clear();
            }
        }
        let consecutive = map
            .get(&(domain.to_string(), ip))
            .map_or(0, |(n, _)| *n)
            .saturating_add(1);
        let delay_secs = 60u64
            .saturating_mul(1u64 << consecutive.saturating_sub(1).min(5))
            .min(PROBE_BACKOFF_MAX.as_secs());
        map.insert(
            (domain.to_string(), ip),
            (
                consecutive,
                Instant::now() + Duration::from_secs(delay_secs),
            ),
        );
    }

    fn note_probe_success(&self, domain: &str, ip: IpAddr) {
        self.probe_backoff.lock().remove(&(domain.to_string(), ip));
    }

    /// Configuration edits can change the route a rejection belonged to.
    pub fn clear_route_rejections(&self) {
        self.route_rejections.write().clear();
    }

    /// Forget all observations tied to the previous local network. The
    /// remembered last-good entry is intentionally kept (the fresh race still
    /// tests it first), but route decisions, rejection timers, quality
    /// rankings and the route-change log stamps were learned on a path that
    /// may no longer exist.
    pub fn on_network_change(&self) {
        self.forget_all_plans();
        self.clear_route_rejections();
        self.ip_rejections.write().clear();
        self.sni_rejections.write().clear();
        self.probe_backoff.lock().clear();
        // The stamp is (ip, mode) from the old network. Keeping it would
        // suppress the first "resolved connection strategy" line after the
        // switch whenever the new race lands on the same tuple — exactly the
        // line that shows what the new network picked.
        self.logged_routes.write().clear();
        // The live plans were measured on the old network, so their quality
        // entries are not evidence for the new one.
        self.route_quality.write().clear();
        {
            let mut scores = self.ip_scores.write();
            scores.clear();
        }
        self.ip_score_count.store(0, Ordering::Relaxed);
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
            .unwrap_or(UNSEEN_RANK)
    }

    #[cfg(test)]
    pub(crate) fn ip_failures(&self, domain: &str, ip: IpAddr) -> u32 {
        self.ip_failures_count(domain, ip)
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
                    .unwrap_or(UNSEEN_RANK)
            })
            .collect()
    }

    /// Update the in-memory quality table and report whether the proven route
    /// degraded. Nothing here touches the cache: a sample is relearned in a few
    /// connections and must never reach the disk.
    pub(super) fn record_ip(
        &self,
        domain: &str,
        ip: IpAddr,
        latency_ms: Option<u64>,
        failed: bool,
    ) -> bool {
        let mut scores = self.ip_scores.write();
        let (is_new, degraded) = {
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
                entry.failures = entry.failures.saturating_add(1);
                entry.ewma_ms = if entry.ewma_ms == 0.0 {
                    10_000.0
                } else {
                    entry.ewma_ms * 0.7 + 10_000.0 * 0.3
                };
                degraded = false;
            } else {
                entry.successes = entry.successes.saturating_add(1);
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
            (is_new, degraded)
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
        degraded
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

    /// Remember the route that just succeeded so the background task can
    /// verify it later.
    ///
    /// Called once per new connection, not per request. A reconnect on the
    /// same address keeps the challenge streak, so two confirmations can span
    /// a fresh connection; a different address starts a new comparison.
    pub(super) fn record_quality(&self, plan: &Arc<ConnectPlan>) {
        // The recheck probes TLS only, so a plaintext plan has nothing to
        // compare and must not take a slot in the table.
        if !plan.tls {
            return;
        }
        let mut quality = self.route_quality.write();
        if quality.len() >= ROUTE_QUALITY_CAP && !quality.contains_key(&plan.domain) {
            let oldest = quality
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(domain, _)| domain.clone());
            if let Some(domain) = oldest {
                quality.remove(&domain);
            }
        }
        if let Some(entry) = quality.get_mut(&plan.domain) {
            if entry.plan.ip != plan.ip {
                entry.challenger = None;
                entry.streak = 0;
            }
            entry.plan = plan.clone();
            entry.last_seen = Instant::now();
            return;
        }
        quality.insert(
            plan.domain.clone(),
            RouteQuality {
                plan: plan.clone(),
                last_seen: Instant::now(),
                checked_at: Instant::now(),
                challenger: None,
                streak: 0,
            },
        );
    }

    /// Compare up to `budget` live routes against their best alternative.
    ///
    /// Returns the plans whose alternative won twice in a row. The caller
    /// drops the plan and retires that host's pooled sockets so the next
    /// request opens a connection that re-races. A probe that cannot complete
    /// proves nothing about the address, so a failed live probe only resets
    /// the streak; a failed challenger also takes a failure record, otherwise
    /// it would be picked again on every check.
    pub(crate) async fn recheck_routes(&self, budget: usize) -> Vec<Arc<ConnectPlan>> {
        if budget == 0 {
            return Vec::new();
        }
        let due: Vec<(String, Arc<ConnectPlan>)> = {
            let quality = self.route_quality.read();
            let mut due: Vec<(Instant, String, Arc<ConnectPlan>)> = quality
                .iter()
                .filter(|(_, entry)| {
                    entry.checked_at.elapsed() >= RECHECK_INTERVAL
                        && entry.last_seen.elapsed() < ROUTE_ACTIVE_WINDOW
                })
                .map(|(domain, entry)| (entry.checked_at, domain.clone(), entry.plan.clone()))
                .collect();
            due.sort_by_key(|(checked_at, _, _)| *checked_at);
            due.into_iter()
                .take(budget)
                .map(|(_, domain, plan)| (domain, plan))
                .collect()
        };

        let timeout = Duration::from_millis(self.config.snapshot().advanced.ip_timeout_ms);
        let mut retired = Vec::new();
        for (domain, plan) in due {
            let Some(rival) = self.recheck_rival(&domain, plan.ip, self.preferred_challenger(&domain))
            else {
                self.touch_quality(&domain);
                continue;
            };
            if !self.take_recheck_token() {
                break;
            }
            let current = self
                .prober
                .probe_tls(
                    plan.ip,
                    plan.port,
                    &domain,
                    plan.mode,
                    plan.sni.as_deref(),
                    plan.ech_config.as_deref(),
                    timeout,
                )
                .await;
            let challenger = self
                .prober
                .probe_tls(
                    rival,
                    plan.port,
                    &domain,
                    plan.mode,
                    plan.sni.as_deref(),
                    plan.ech_config.as_deref(),
                    timeout,
                )
                .await;

            // A broken challenger must sink in the ranking. Without this it
            // keeps the best rank, is picked again on every check, and hides
            // the healthy candidates behind it.
            if challenger.is_err() {
                self.record_ip(&domain, rival, None, true);
            }
            let faster = match (&current, &challenger) {
                (Ok(current), Ok(challenger)) => {
                    Some(challenger.latency_ms as f64 <= current.latency_ms as f64 * RECHECK_MARGIN)
                }
                _ => None,
            };
            let confirmed = self.record_challenge(&domain, &plan, rival, faster);
            if confirmed {
                tracing::info!(
                    domain = %domain,
                    from = %plan.ip,
                    to = %rival,
                    mode = %plan.mode,
                    current_ms = current.as_ref().map(|probe| probe.latency_ms).unwrap_or(0),
                    challenger_ms = challenger.as_ref().map(|probe| probe.latency_ms).unwrap_or(0),
                    "a faster candidate was confirmed; retiring the route"
                );
                self.route_quality.write().remove(&domain);
                retired.push(plan);
            }
        }
        retired
    }

    /// Apply one challenge verdict and report whether the route is beaten.
    ///
    /// A connection can replace the live route while the probes are in flight,
    /// so a verdict computed for the old plan is discarded instead of retiring
    /// the plan that replaced it.
    pub(super) fn record_challenge(
        &self,
        domain: &str,
        plan: &ConnectPlan,
        rival: IpAddr,
        faster: Option<bool>,
    ) -> bool {
        let mut quality = self.route_quality.write();
        let Some(entry) = quality.get_mut(domain) else {
            return false;
        };
        entry.checked_at = Instant::now();
        if entry.plan.ip != plan.ip {
            return false;
        }
        match faster {
            Some(true) if entry.challenger == Some(rival) => {
                entry.streak = entry.streak.saturating_add(1);
            }
            Some(true) => {
                entry.challenger = Some(rival);
                entry.streak = 1;
            }
            _ => {
                entry.challenger = None;
                entry.streak = 0;
            }
        }
        entry.streak >= RECHECK_CONFIRMATIONS
    }

    /// Note the check without changing the verdict, used when no rival exists.
    fn touch_quality(&self, domain: &str) {
        if let Some(entry) = self.route_quality.write().get_mut(domain) {
            entry.checked_at = Instant::now();
        }
    }

    /// Best alternative for a live route, by the same score the cursor uses.
    ///
    /// `preferred` is the challenger of the previous check. Reusing it keeps
    /// two confirmations on the same pair of addresses; without that, a rank
    /// shift between checks picks a different rival and resets the streak, so
    /// a clearly faster candidate could never accumulate two wins.
    fn recheck_rival(
        &self,
        domain: &str,
        current: IpAddr,
        preferred: Option<IpAddr>,
    ) -> Option<IpAddr> {
        let config = self.config.snapshot();
        let mut ips: Vec<IpAddr> = Vec::new();
        if let Some(remote) = self.remote.remote_ips(domain) {
            ips.extend(remote.iter().copied());
        }
        // Domains whose addresses only come from DoH still need an opponent.
        // The cached answers cost nothing to read, unlike a fresh query.
        // Cached DoH answers still provide an opponent. Only A/AAAA ever
        // enter the answer cache (HTTPS RRs feed the ECH cache alone), so a
        // single address-answer lookup replaces the old `[1, 65]` pair —
        // qtype 65 could never hit, and its hints were never stored anyway.
        if let Some(answer) = self.cache.doh_answer(domain, 1) {
            ips.extend(answer.ips);
        }
        if let Some(ip) = self
            .cache
            .last_good_route(domain, config.advanced.last_good_days)
        {
            ips.push(ip);
        }
        ips.retain(|ip| *ip != current && !self.ip_rejected(domain, *ip));
        ips.sort_unstable();
        ips.dedup();
        if ips.is_empty() {
            return None;
        }
        // Keep the previous challenger unless it has a failure record; a dead
        // address must not be carried over just to keep the streak.
        if let Some(preferred) = preferred {
            if ips.contains(&preferred) && self.ip_failures_count(domain, preferred) == 0 {
                return Some(preferred);
            }
        }
        let candidates: Vec<Candidate> = ips
            .into_iter()
            .map(|ip| Candidate {
                ip,
                source: IpSource::Remote,
            })
            .collect();
        let scores = self.score_candidates(domain, &candidates);
        candidates
            .into_iter()
            .zip(scores)
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(candidate, _)| candidate.ip)
    }

    /// Failures recorded for one address, zero when it was never seen.
    fn ip_failures_count(&self, domain: &str, ip: IpAddr) -> u32 {
        self.ip_scores
            .read()
            .get(domain)
            .and_then(|by_ip| by_ip.get(&ip))
            .map(|score| score.failures)
            .unwrap_or(0)
    }

    /// The challenger of the previous check, if it is still being compared.
    fn preferred_challenger(&self, domain: &str) -> Option<IpAddr> {
        self.route_quality
            .read()
            .get(domain)
            .and_then(|entry| entry.challenger)
    }

    /// Take one check from the bucket. A check costs two handshakes, so the
    /// bucket is sized in checks but refilled at the probe rate.
    fn take_recheck_token(&self) -> bool {
        let now = Instant::now();
        let mut bucket = self.recheck_budget.lock();
        let elapsed = now.duration_since(bucket.1).as_secs_f64();
        bucket.0 = (bucket.0 + elapsed * RECHECK_CHECKS_PER_MIN / 60.0).min(2.0);
        bucket.1 = now;
        if bucket.0 >= 1.0 {
            bucket.0 -= 1.0;
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    pub(super) fn quality_len(&self) -> usize {
        self.route_quality.read().len()
    }

    #[cfg(test)]
    pub(super) fn backdate_quality(&self, domain: &str, age: Duration) {
        if let Some(entry) = self.route_quality.write().get_mut(domain) {
            entry.checked_at = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        }
    }

    #[cfg(test)]
    pub(super) fn backdate_quality_seen(&self, domain: &str, age: Duration) {
        if let Some(entry) = self.route_quality.write().get_mut(domain) {
            entry.last_seen = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        }
    }

    #[cfg(test)]
    pub(super) fn set_recheck_tokens(&self, tokens: f64) {
        self.recheck_budget.lock().0 = tokens;
    }

    #[cfg(test)]
    pub(super) fn grant_recheck_budget(&self) {
        self.set_recheck_tokens(2.0);
    }

    #[cfg(test)]
    pub(super) fn plan_cache_len(&self) -> usize {
        self.plan_cache_count.load(Ordering::Relaxed)
    }

    /// TCP-probe IPs that accumulated failures and forgive the ones that answer
    /// again. A temporary block (GFW reset, network flap) should not bury a
    /// working address under its failure score forever.
    pub async fn reprobe_failed_ips(self: &Arc<Self>, limit: usize) -> usize {
        // Snapshot the failing scores under the read lock and apply the
        // backoff filter after releasing it: `probe_backoff_ready` takes
        // another lock and allocates a key per entry, while the request path
        // writes scores under this same lock — a once-per-minute sweep must
        // not stall it for the whole scan.
        let mut list: Vec<(String, IpAddr, u32)> = {
            let scores = self.ip_scores.read();
            scores
                .iter()
                .flat_map(|(domain, by_ip)| {
                    by_ip
                        .iter()
                        .filter(|(_, score)| score.failures > 0)
                        .map(|(ip, score)| (domain.clone(), *ip, score.failures))
                })
                .collect()
        };
        list.retain(|(domain, ip, _)| self.probe_backoff_ready(domain, *ip));
        list.sort_by(|a, b| b.2.cmp(&a.2));
        list.truncate(limit);
        let candidates: Vec<(String, IpAddr)> = list
            .into_iter()
            .map(|(domain, ip, _)| (domain, ip))
            .collect();
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
                        engine.note_probe_success(&domain, ip);
                        true
                    }
                    Err(_) => {
                        engine.note_probe_failure(&domain, ip);
                        false
                    }
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
            // A periodic health event, not a problem. It repeats every minute
            // and would otherwise be one of the largest blocks in the log.
            tracing::debug!(restored, "failed ip scores restored after re-probe");
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
            // The candidates that died before the winner. This is the partial
            // failure case, so it is published at the default level; the same
            // compact rendering as the total failure line keeps both greppable.
            for (index, attempt) in attempts.iter().enumerate() {
                tracing::info!(
                    domain = %plan.domain,
                    attempt = index + 1,
                    failed = %format_attempt(attempt),
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
                .map(|group| match plan.rule_index {
                    // Index lookup for the common (matched) plan: the same
                    // route as `route_for`, without scanning every rule of
                    // the group on every successful connection.
                    Some(rule_index) => group.route_modes_at(rule_index),
                    None => group.route_modes(&plan.domain),
                })
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
        let degraded = self.record_ip(&plan.domain, plan.ip, Some(latency_ms), false);
        self.cache.put_last_good(LastGoodEntry {
            domain: plan.domain.clone(),
            ip: plan.ip,
            source: plan.source,
            saved_at: now(),
            catalog_version: config.catalog_version,
        });
        self.remember_plan_arc(plan.clone());
        self.record_quality(plan);
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
        // Only a route change is worth a line. A route that is reused for
        // every connection of a domain is the normal case and would drown
        // the log; a change is the interesting event.
        if self.route_changed(&plan.domain, plan.ip, plan.mode) {
            tracing::info!(
                group = %plan.group_id,
                domain = %plan.domain,
                ip = %plan.ip,
                mode = %plan.mode,
                source = %plan.source,
                doh_source = ?doh_source,
                latency_ms,
                attempts = attempts_total,
                "resolved connection strategy"
            );
        }
        diagnostics
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn failure_diagnostics(
        &self,
        group: &GroupConfig,
        domain: &str,
        rule_index: usize,
        config: &AppConfig,
        reason: FailureReason,
        attempts: Vec<AttemptRecord>,
        doh: &DohExpansion,
        detail: Option<String>,
        candidates: &[Candidate],
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
            // The cursor already matched the rule; index lookup instead of
            // rescanning the group's rules on every total failure.
            configured_modes: group.route_modes_at(rule_index),
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
        // The aggregate `reason` alone cannot explain a total failure: it says
        // that every strategy died, not which address died, in which mode and
        // with what error. The attempt trace is already in the diagnostics
        // (the local error page shows it), so log it here too — otherwise a
        // black-holed address is indistinguishable from a filtered SNI.
        tracing::warn!(
            group = %group.id,
            domain = %domain,
            reason = %reason,
            modes = %format_modes(&diagnostics.configured_modes),
            candidates = %format_candidates(candidates),
            doh_source = %format_optional(doh.source.map(|source| source.as_str())),
            // The error and the detail contain spaces, so they are recorded in
            // the quoted form: an unquoted value would swallow the fields that
            // follow it.
            doh_error = ?doh.error.clone().unwrap_or_default(),
            attempts = %format_attempts(&diagnostics.attempts),
            detail = ?diagnostics.detail.clone().unwrap_or_default(),
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
        limit: usize,
    ) -> DohExpansion {
        let started = std::time::Instant::now();
        match self.resolver.doh_ips(domain).await {
            Ok(DohResolution {
                ips,
                source,
                endpoint,
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
                for ip in ips.iter().copied() {
                    if candidates.len() >= limit {
                        break;
                    }
                    // The list is bounded (the initial cap plus at most one
                    // DoH fallback wave), so a linear scan replaces the
                    // per-cursor hash set.
                    if !candidates.iter().any(|candidate| candidate.ip == ip)
                        && !self.ip_rejected(domain, ip)
                    {
                        candidates.push(Candidate {
                            ip,
                            source: candidate_source,
                        });
                    }
                }
                // DoH is the expensive fallback: its cost and yield decide
                // whether the catalog needs better coverage. The answer itself
                // is logged too: "DoH added nothing" and "DoH answered with
                // the address that is already black-holed" need different
                // fixes, and only the raw IPs tell them apart.
                //
                // A cached answer cannot be slow by itself: its elapsed time is
                // the wait on the resolver's single-flight lock while another
                // request ran the real query, so it never belongs on the
                // was-slow path.
                if elapsed > 1000 && !matches!(source, DohSource::Cache) {
                    tracing::warn!(
                        domain = %domain,
                        source = ?source,
                        endpoint = %endpoint,
                        stale,
                        answered_ips = %format_ips(&ips),
                        added = candidates.len() - before,
                        elapsed_ms = elapsed,
                        "doh expansion was slow"
                    );
                } else {
                    tracing::info!(
                        domain = %domain,
                        source = ?source,
                        endpoint = %endpoint,
                        stale,
                        answered_ips = %format_ips(&ips),
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
        rule_index: usize,
        config: &AppConfig,
        state: State,
        detail: &str,
    ) -> DecisionOutcome {
        let diagnostics = Arc::new(DomainDiagnostics {
            group: Some(group.id.clone()),
            domain: domain.to_string(),
            state,
            strategy: None,
            // The caller already matched the rule; index lookup instead of
            // rescanning the group on every bypass connection.
            configured_modes: group.route_modes_at(rule_index),
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

/// Compact, greppable rendering of the configured TLS modes.
fn format_modes(modes: &[TlsMode]) -> String {
    if modes.is_empty() {
        return "none".to_string();
    }
    modes
        .iter()
        .map(|mode| mode.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

/// Compact rendering of the candidate set: `address:source` per entry.
///
/// The debug rendering of a candidate list is unreadable in a log file and
/// cannot be grepped, and the whole point of this line is to answer "which
/// addresses were even tried".
fn format_candidates(candidates: &[Candidate]) -> String {
    if candidates.is_empty() {
        return "none".to_string();
    }
    candidates
        .iter()
        .map(|candidate| format!("{}:{}", candidate.ip, candidate.source.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Compact rendering of one attempt: `mode@address#error:source[#sni]`.
///
/// The error is the part that decides what to do next (a black hole, a
/// filtered SNI, a bad certificate), so it has to be visible per attempt.
fn format_attempt(attempt: &AttemptRecord) -> String {
    let error = attempt.error.map(|reason| reason.as_str()).unwrap_or("-");
    let sni = attempt
        .sni
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| format!("#{value}"))
        .unwrap_or_default();
    format!(
        "{}@{}#{}:{}{}",
        attempt.strategy.as_str(),
        attempt.ip,
        error,
        attempt.source.as_str(),
        sni
    )
}

/// Compact rendering of the attempt trace: `mode@address:source#error`.
///
/// The error is the part that decides what to do next (a black hole, a
/// filtered SNI, a bad certificate), so it has to be visible per attempt.
fn format_attempts(attempts: &[AttemptRecord]) -> String {
    if attempts.is_empty() {
        return "none".to_string();
    }
    attempts
        .iter()
        .map(format_attempt)
        .collect::<Vec<_>>()
        .join(",")
}

/// Render an optional value without the `Some(...)` noise.
fn format_optional(value: Option<&str>) -> String {
    value.unwrap_or("none").to_string()
}

/// Compact rendering of a list of addresses.
///
/// The debug rendering of a list contains spaces, which makes the log line
/// impossible to parse field by field - and the addresses are the one thing
/// an operator has to be able to read off the line.
fn format_ips(ips: &[std::net::IpAddr]) -> String {
    if ips.is_empty() {
        return "none".to_string();
    }
    ips.iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",")
}
