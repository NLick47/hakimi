use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::cache::{CacheManager, LastGoodEntry};
use crate::catalog::RemoteIpProvider;
use crate::config::{AppConfig, ConfigManager, GroupConfig};
use crate::domain::normalize_hostname;
use crate::ip_tester::{ConnectError, ProbeSuccess, TlsContext};
use crate::resolver::{DohResolution, EchOutcome, IpResolver};
use crate::status::{AttemptRecord, DomainDiagnostics, State, StatusStore};
use crate::strategy::{CacheStatus, DohSource, FailureReason, IpSource, Strategy, TlsMode};
use crate::util::{network_id, now};

#[derive(Debug, Clone)]
pub struct ConnectPlan {
    pub domain: String,
    pub group_id: String,
    pub ip: IpAddr,
    pub port: u16,
    pub mode: TlsMode,
    /// Fake SNI used for upstream TLS. `None` means no SNI (or not applicable).
    pub sni: Option<String>,
    /// Raw ECHConfigList for `TlsMode::Ech`.
    pub ech_config: Option<Vec<u8>>,
    /// Whether this plan terminates TLS (false only for plaintext HTTP forwarding).
    pub tls: bool,
    /// Which candidate list produced this IP.
    pub source: IpSource,
}

impl ConnectPlan {
    fn identity(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.ech_config.hash(&mut hasher);
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.domain,
            self.port,
            self.tls,
            self.ip,
            self.mode.as_str(),
            self.sni.as_deref().unwrap_or(""),
            hasher.finish()
        )
    }
}

#[derive(Debug, Clone)]
pub struct DecisionOutcome {
    pub plan: Option<ConnectPlan>,
    pub diagnostics: DomainDiagnostics,
}

/// Network prober abstraction so decision rules can be unit-tested without sockets.
#[async_trait]
pub trait Prober: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn probe_tls(
        &self,
        ip: IpAddr,
        port: u16,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
        timeout: Duration,
    ) -> std::result::Result<ProbeSuccess, ConnectError>;

    async fn probe_tcp(
        &self,
        ip: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> std::result::Result<u64, ConnectError>;
}

#[async_trait]
impl Prober for TlsContext {
    async fn probe_tls(
        &self,
        ip: IpAddr,
        port: u16,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
        timeout: Duration,
    ) -> std::result::Result<ProbeSuccess, ConnectError> {
        TlsContext::probe(self, ip, port, domain, mode, sni, ech, timeout).await
    }

    async fn probe_tcp(
        &self,
        ip: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> std::result::Result<u64, ConnectError> {
        let started = Instant::now();
        let stream = tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port)))
            .await
            .map_err(|_| ConnectError::Timeout)??;
        drop(stream);
        Ok(started.elapsed().as_millis() as u64)
    }
}

#[derive(Clone, Debug)]
struct Candidate {
    ip: IpAddr,
    source: IpSource,
}

#[derive(Debug, Default)]
struct DohExpansion {
    source: Option<DohSource>,
    error: Option<String>,
    stale: bool,
}

/// Consume this many initial (catalog/cache) candidates before expanding with DoH.
const EARLY_DOH_AFTER: usize = 3;

/// Result of matching a host against the configured groups.
pub enum Route {
    /// No interception: the caller should connect directly.
    Bypass(DecisionOutcome),
    /// The host belongs to a group but cannot be routed (invalid config, CA-independent error).
    Blocked(DecisionOutcome),
    /// The host belongs to an enabled group. Plans are produced lazily and without probing:
    /// the real upstream TLS handshake is the probe, so the hot path never pays for two
    /// handshakes per connection.
    Group(Box<RouteCursor>),
}

/// Lazy, probe-free route generator. The design's candidate order (cache/remote ->
/// DoH -> stale DoH) is unchanged, but in `auto` mode the TLS routes no longer run as
/// strict priority blocks: the generator walks rounds over the candidate list, pairing
/// one IP with every configured route (direct, ECH, fake SNI). The connection race then
/// compares routes instead of stopping at the first route that merely works — a slow
/// direct connection loses to a faster accelerated one, and `last_good` remembers which
/// route won. Only DoH and ECH resolution stay lazy.
///
/// The caller attempts each returned plan for real and reports the outcome with
/// [`RouteCursor::note_failure`] / [`RouteCursor::note_success`]. Because the real
/// connection performs the same TCP + TLS + certificate validation a probe would, this
/// removes the duplicate handshake from the proxy hot path without weakening validation.
pub struct RouteCursor {
    engine: Arc<DecisionEngine>,
    domain: String,
    port: u16,
    tls: bool,
    group: GroupConfig,
    config: Arc<AppConfig>,
    network: String,
    max: usize,
    candidates: Vec<Candidate>,
    seen: HashSet<IpAddr>,
    candidate_index: usize,
    doh_loaded: bool,
    doh: DohExpansion,
    skip_once: bool,
    remote_available: bool,
    modes: Vec<TlsMode>,
    mode_index: usize,
    current: Option<Candidate>,
    ech_config: Option<Vec<u8>>,
    ech_checked: bool,
    ech_error: Option<String>,
    sni_candidates: Vec<Option<String>>,
    sni_index: usize,
    attempts: Vec<AttemptRecord>,
    last_reason: Option<FailureReason>,
    last_detail: Option<String>,
    skipped: HashSet<String>,
    finished: bool,
    failure: Option<DecisionOutcome>,
}

impl RouteCursor {
    fn new(
        engine: Arc<DecisionEngine>,
        domain: String,
        port: u16,
        tls: bool,
        group: GroupConfig,
        config: Arc<AppConfig>,
    ) -> Self {
        let network = network_id();
        let max = config.advanced.max_candidates_per_domain;
        let skip_once = engine.cache.take_skip_once(&domain);
        let last_good = engine
            .cache
            .last_good(&domain, config.advanced.last_good_days);
        let remote = engine.remote.remote_ips(&domain);
        let remote_available = engine.remote.has_ip_catalog();

        let mut candidates: Vec<Candidate> = Vec::new();
        let mut seen = HashSet::new();
        let add_remote = |candidates: &mut Vec<Candidate>, seen: &mut HashSet<IpAddr>| {
            if let Some((_, ips)) = &remote {
                for ip in ips {
                    if candidates.len() >= max {
                        break;
                    }
                    if seen.insert(*ip) {
                        candidates.push(Candidate {
                            ip: *ip,
                            source: IpSource::Remote,
                        });
                    }
                }
            }
        };
        let add_cache = |candidates: &mut Vec<Candidate>, seen: &mut HashSet<IpAddr>| {
            if let Some(entry) = &last_good {
                if candidates.len() < max && seen.insert(entry.ip) {
                    candidates.push(Candidate {
                        ip: entry.ip,
                        source: IpSource::Cache,
                    });
                }
            }
        };
        // 8.1 / 8.2: after a catalog update the new remote IPs are attempted before the
        // last-good cache; otherwise the cache is tried first.
        if skip_once {
            add_remote(&mut candidates, &mut seen);
            add_cache(&mut candidates, &mut seen);
        } else {
            add_cache(&mut candidates, &mut seen);
            add_remote(&mut candidates, &mut seen);
        }

        // Order by measured quality on this network: proven fast IPs lead, failures sink.
        // Unknown addresses keep the catalog order, so a fresh start is still deterministic.
        let rank = |candidate: &Candidate| -> f64 {
            if skip_once && candidate.source == IpSource::Remote {
                return 0.0;
            }
            engine.score_ip(&domain, candidate.ip)
        };
        candidates.sort_by(|a, b| rank(a).partial_cmp(&rank(b)).unwrap_or(std::cmp::Ordering::Equal));

        let mut modes = if tls {
            group.strategy.attempts().to_vec()
        } else {
            vec![TlsMode::Direct]
        };
        // Use the last-known-good strategy as the first attempt. Without this, a site that
        // only works with fake SNI pays a failed direct/ECH pass on every process start
        // (and every catalog-triggered re-plan), which is especially visible for image
        // hosts. `auto` still falls back to the normal order on failure.
        if tls && group.strategy == Strategy::Auto {
            if let Some(preferred) = last_good
                .as_ref()
                .map(|entry| mode_for_strategy(entry.strategy))
            {
                if modes.contains(&preferred) && modes.first() != Some(&preferred) {
                    modes.retain(|mode| *mode != preferred);
                    modes.insert(0, preferred);
                }
            }
        }
        let sni_candidates = if tls && modes.contains(&TlsMode::FakeSni) {
            engine.sni_candidates(&config, &group, &domain, &network)
        } else {
            Vec::new()
        };

        Self {
            engine,
            domain,
            port,
            tls,
            group,
            config,
            network,
            max,
            candidates,
            seen,
            candidate_index: 0,
            doh_loaded: false,
            doh: DohExpansion::default(),
            skip_once,
            remote_available,
            modes,
            mode_index: 0,
            current: None,
            ech_config: None,
            ech_checked: false,
            ech_error: None,
            sni_candidates,
            sni_index: 0,
            attempts: Vec::new(),
            last_reason: None,
            last_detail: None,
            skipped: HashSet::new(),
            finished: false,
            failure: None,
        }
    }

    pub fn group_id(&self) -> &str {
        &self.group.id
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// True when a catalog update asked this domain to try its new remote IPs before
    /// any cached route.
    pub fn skip_once(&self) -> bool {
        self.skip_once
    }

    /// Skip an already-attempted plan (for example one taken from the plan cache).
    pub fn skip_plan(&mut self, plan: &ConnectPlan) {
        self.skipped.insert(plan.identity());
    }

    pub fn outcome(&self) -> Option<&DecisionOutcome> {
        self.failure.as_ref()
    }

    /// Produce the next plan in round-robin order. Each round pairs one candidate IP
    /// with every configured TLS route, so the connection race compares routes instead
    /// of stopping at the first route that merely works. `None` means every strategy
    /// and candidate was exhausted; a failure diagnostic has been recorded in that case.
    pub async fn next_plan(&mut self) -> Option<ConnectPlan> {
        if self.finished {
            return None;
        }
        loop {
            if self.finished {
                return None;
            }
            if self.modes.is_empty() {
                self.finish_failure();
                return None;
            }
            // Advance to the next candidate when the round is done (or not started).
            if self.current.is_none() || self.mode_index >= self.modes.len() {
                match self.next_candidate().await {
                    Some(candidate) => {
                        self.current = Some(candidate);
                        self.mode_index = 0;
                    }
                    None => {
                        self.finish_failure();
                        return None;
                    }
                }
            }
            let mode = self.modes[self.mode_index];

            if mode == TlsMode::Ech && !self.ech_checked {
                self.ech_checked = true;
                match self
                    .engine
                    .resolver
                    .doh_ech_config(&self.domain, self.group.ech_shared)
                    .await
                {
                    Ok(EchOutcome {
                        config,
                        source,
                        stale,
                        ..
                    }) => {
                        self.ech_config = Some(config);
                        if self.doh.source.is_none() {
                            self.doh.source = Some(source);
                        }
                        self.doh.stale |= stale;
                    }
                    Err(error) => {
                        self.ech_error = Some(format!("{error:#}"));
                    }
                }
                if self.ech_config.is_none() {
                    if self.group.strategy == Strategy::Ech {
                        self.last_reason = Some(FailureReason::EchUnavailable);
                        self.last_detail = self
                            .ech_error
                            .clone()
                            .or_else(|| Some("no ECHConfig available".into()));
                        self.finish_failure();
                        return None;
                    }
                    // Drop the ECH route for every round; the mode index now points
                    // at the next mode, so do not advance again.
                    self.modes.retain(|m| *m != TlsMode::Ech);
                    continue;
                }
            }

            let Some(candidate) = self.current.clone() else {
                self.finish_failure();
                return None;
            };

            if mode == TlsMode::FakeSni {
                if self.sni_index >= self.sni_candidates.len() {
                    // Every fake-SNI host was tried: drop the route for every round.
                    self.modes.retain(|m| *m != TlsMode::FakeSni);
                    continue;
                }
                // Stay on this mode until the whole SNI list has been paired with
                // the current candidate, mirroring the old SNI-major sweep.
                let sni = self.sni_candidates[self.sni_index].clone();
                self.sni_index += 1;
                let plan = self.build_plan(candidate, mode, sni, None);
                if self.take_skipped(&plan) {
                    continue;
                }
                return Some(plan);
            }

            self.mode_index += 1;
            let ech = if mode == TlsMode::Ech {
                self.ech_config.clone()
            } else {
                None
            };
            let plan = self.build_plan(candidate, mode, None, ech);
            if self.take_skipped(&plan) {
                continue;
            }
            return Some(plan);
        }
    }

    fn build_plan(
        &self,
        candidate: Candidate,
        mode: TlsMode,
        sni: Option<String>,
        ech: Option<Vec<u8>>,
    ) -> ConnectPlan {
        ConnectPlan {
            domain: self.domain.clone(),
            group_id: self.group.id.clone(),
            ip: candidate.ip,
            port: self.port,
            mode,
            sni,
            ech_config: ech,
            tls: self.tls,
            source: candidate.source,
        }
    }

    fn take_skipped(&mut self, plan: &ConnectPlan) -> bool {
        self.skipped.remove(&plan.identity())
    }

    async fn next_candidate(&mut self) -> Option<Candidate> {
        loop {
            if self.candidate_index < self.candidates.len() {
                let candidate = self.candidates[self.candidate_index].clone();
                self.candidate_index += 1;
                return Some(candidate);
            }
            // Expand with DoH once a few initial candidates have been consumed instead of
            // only at full exhaustion: a stale or poisoned catalog would otherwise pay its
            // whole serial timeout before DoH is ever consulted.
            if !self.doh_loaded
                && self.candidates.len() < self.max
                && self.candidate_index >= EARLY_DOH_AFTER.min(self.candidates.len())
            {
                self.doh_loaded = true;
                let engine = self.engine.clone();
                let expansion = engine
                    .expand_doh(&self.domain, &mut self.candidates, &mut self.seen, self.max)
                    .await;
                merge_expansion(&mut self.doh, expansion);
                if self.candidate_index < self.candidates.len() {
                    continue;
                }
            }
            return None;
        }
    }

    /// Record a failed real connection attempt. The caller then asks for the next plan.
    pub fn note_failure(&mut self, plan: &ConnectPlan, reason: FailureReason, detail: String) {
        tracing::debug!(
            domain = %plan.domain,
            ip = %plan.ip,
            mode = %plan.mode,
            reason = %reason,
            detail = %detail,
            "upstream candidate failed"
        );
        self.last_reason = Some(reason);
        self.last_detail = Some(detail.clone());
        self.attempts.push(AttemptRecord {
            strategy: plan.mode,
            ip: plan.ip,
            source: plan.source,
            sni: plan.sni.clone(),
            error: Some(reason),
            detail: Some(detail),
            latency_ms: None,
        });
        self.engine.record_ip(&plan.domain, plan.ip, None, true);
    }

    /// Record a successful real connection (TLS + certificate validation already passed).
    pub fn note_success(&mut self, plan: &ConnectPlan, latency_ms: u64) -> DecisionOutcome {
        let diagnostics = self.engine.record_success(
            plan,
            latency_ms,
            std::mem::take(&mut self.attempts),
            &self.doh,
            &self.config,
        );
        if plan.mode == TlsMode::FakeSni {
            self.engine.cache.put_sni(crate::cache::CachedSni {
                group: self.group.id.clone(),
                domain: self.domain.clone(),
                network_id: self.network.clone(),
                sni: plan.sni.clone(),
                saved_at: now(),
            });
        }
        self.finished = true;
        DecisionOutcome {
            plan: Some(plan.clone()),
            diagnostics,
        }
    }

    fn finish_failure(&mut self) {
        if self.failure.is_some() {
            return;
        }
        self.finished = true;
        let reason = if let Some(reason) = self.last_reason {
            reason
        } else if self.group.strategy == Strategy::Ech && self.ech_config.is_none() {
            FailureReason::EchUnavailable
        } else if self.doh.error.is_some() {
            FailureReason::DohFailed
        } else if !self.remote_available {
            FailureReason::RemoteCatalogUnavailable
        } else {
            FailureReason::NoCandidate
        };
        let mut detail = Vec::new();
        if let Some(error) = &self.doh.error {
            detail.push(format!("DoH: {error}"));
        }
        if let Some(error) = &self.ech_error {
            detail.push(format!("ECH: {error}"));
        }
        if let Some(error) = &self.last_detail {
            detail.push(error.clone());
        }
        if !self.remote_available {
            detail.push("remote IP catalog is not loaded".into());
        }
        if self.skip_once {
            detail.push("last-good cache was skipped once after a catalog update".into());
        }
        let diagnostics = self.engine.failure_diagnostics(
            &self.group,
            &self.domain,
            &self.config,
            reason,
            std::mem::take(&mut self.attempts),
            &self.doh,
            if detail.is_empty() {
                None
            } else {
                Some(detail.join("; "))
            },
        );
        self.failure = Some(DecisionOutcome {
            plan: None,
            diagnostics,
        });
    }
}

pub struct DecisionEngine {
    pub config: Arc<ConfigManager>,
    pub cache: Arc<CacheManager>,
    pub remote: Arc<dyn RemoteIpProvider>,
    pub resolver: Arc<dyn IpResolver>,
    pub prober: Arc<dyn Prober>,
    pub status: Arc<StatusStore>,
    /// Last successful route per authority. New pooled connections start here, so a
    /// connection failure is the only event that triggers re-resolution.
    plan_cache: parking_lot::Mutex<HashMap<String, (Instant, ConnectPlan)>>,
    /// Per (domain, IP) observations. Candidates are ordered by score, so a host picks the
    /// address that has actually been fast on this network instead of a static list.
    ip_scores: parking_lot::RwLock<HashMap<String, HashMap<IpAddr, IpScore>>>,
}

#[derive(Clone, Copy, Default)]
struct IpScore {
    ewma_ms: f64,
    successes: u32,
    failures: u32,
}

impl IpScore {
    /// Lower is better. Latency dominates; failures are penalised hard.
    fn rank(&self) -> f64 {
        if self.successes == 0 && self.failures == 0 {
            return f64::MAX;
        }
        let total = (self.successes + self.failures) as f64;
        let fail_rate = self.failures as f64 / total;
        let base = if self.successes == 0 {
            10_000.0
        } else {
            self.ewma_ms.max(1.0)
        };
        base * (1.0 + fail_rate * 8.0)
    }
}

const PLAN_CACHE_MAX: usize = 2048;
/// How many (domain, ip) quality entries to keep in memory. The active set of a
/// heavy user stays well below this; growth past it evicts the worst-ranked.
const IP_SCORE_CAP: usize = 128;

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
        Arc::new(Self {
            config,
            cache,
            remote,
            resolver,
            prober,
            status,
            plan_cache: parking_lot::Mutex::new(HashMap::new()),
            ip_scores: parking_lot::RwLock::new(seeded_scores),
        })
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
                    Ok(latency_ms) => return cursor.note_success(&plan, latency_ms),
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

    /// Routing variant used by diagnostic probes. `probing` skips the paused
    /// gate: pausing controls whether traffic is intercepted, not whether a
    /// manual health check may run.
    fn route_inner(
        self: &Arc<Self>,
        domain: &str,
        port: u16,
        tls: bool,
        probing: bool,
    ) -> Route {
        let config = self.config.snapshot();
        let normalized = match normalize_hostname(domain) {
            Ok(domain) => domain,
            Err(error) => {
                return Route::Blocked(self.config_failure(
                    None,
                    domain,
                    &config,
                    FailureReason::ConfigInvalid,
                    format!("invalid domain: {error}"),
                ))
            }
        };
        let matcher = self.config.matcher();
        let Some(group_id) = matcher.match_normalized(&normalized).map(ToOwned::to_owned) else {
            return Route::Bypass(DecisionOutcome {
                plan: None,
                diagnostics: DomainDiagnostics {
                    group: None,
                    domain: normalized,
                    state: State::Direct,
                    strategy: None,
                    configured_strategy: None,
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
                },
            });
        };
        let Some(group) = config.group(&group_id).cloned() else {
            return Route::Blocked(self.config_failure(
                Some(group_id),
                &normalized,
                &config,
                FailureReason::ConfigInvalid,
                "matched group no longer exists in the configuration".into(),
            ));
        };
        if !group.enabled {
            return Route::Bypass(self.state_only(
                &group,
                &normalized,
                &config,
                State::Disabled,
                "group is disabled; traffic is not intercepted",
            ));
        }
        if !probing && self.status.paused() {
            return Route::Bypass(self.state_only(
                &group,
                &normalized,
                &config,
                State::Paused,
                "hakimi is paused; traffic is not intercepted",
            ));
        }
        self.status.mark_checking(
            Some(group.id.clone()),
            &normalized,
            Some(group.strategy),
            config.catalog_version,
        );
        Route::Group(Box::new(RouteCursor::new(
            self.clone(),
            normalized,
            port,
            tls,
            group,
            config,
        )))
    }

    /// Last successful plan for a new connection. Established pooled connections never
    /// consult this, so it only affects cold connections and raw CONNECT tunnels.
    pub fn cached_plan(&self, domain: &str, port: u16, tls: bool) -> Option<ConnectPlan> {
        let key = plan_key(domain, port, tls);
        let config = self.config.snapshot();
        let ttl = Duration::from_secs(config.advanced.plan_cache_secs);
        let mut cache = self.plan_cache.lock();
        let (at, plan) = cache.get(&key)?;
        if at.elapsed() >= ttl {
            cache.remove(&key);
            return None;
        }
        let plan = plan.clone();
        drop(cache);

        // A catalog update marks affected domains skipOnce: do not reuse the old route
        // before the new remote IPs have been attempted.
        if self.cache.has_skip_once(&plan.domain) {
            return None;
        }
        let matcher = self.config.matcher();
        let group_id = matcher.match_normalized(&plan.domain)?.to_string();
        let group = config.group(&group_id)?;
        if !group.enabled || self.status.paused() {
            return None;
        }
        if tls {
            if !group.strategy.attempts().contains(&plan.mode) {
                return None;
            }
        } else if plan.mode != TlsMode::Direct {
            return None;
        }
        Some(plan)
    }

    pub fn forget_plan(&self, domain: &str, port: u16, tls: bool) {
        self.plan_cache.lock().remove(&plan_key(domain, port, tls));
    }

    fn score_ip(&self, domain: &str, ip: IpAddr) -> f64 {
        self.ip_scores
            .read()
            .get(domain)
            .and_then(|by_ip| by_ip.get(&ip))
            .map(|score| score.rank())
            .unwrap_or(f64::MAX)
    }

    fn record_ip(&self, domain: &str, ip: IpAddr, latency_ms: Option<u64>, failed: bool) -> bool {
        let mut scores = self.ip_scores.write();
        let entry = scores
            .entry(domain.to_string())
            .or_default()
            .entry(ip)
            .or_default();
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
        let snapshot = (entry.ewma_ms, entry.successes, entry.failures);
        drop(entry);
        // Bounded map: when full, drop the least valuable entries — the ones
        // with the worst measured quality — instead of wiping everything. A
        // flood of dead IPs must never erase knowledge of a proven route.
        let total: usize = scores.values().map(|by_ip| by_ip.len()).sum();
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
            for ((domain, ip), _) in ranked.into_iter().take(total - IP_SCORE_CAP) {
                if let Some(by_ip) = scores.get_mut(&domain) {
                    by_ip.remove(&ip);
                    if by_ip.is_empty() {
                        scores.remove(&domain);
                    }
                }
            }
        }
        // Persist both outcomes: a restart must keep knowing that this IP was
        // fast — or blocked — on this network. The cache batches disk writes.
        self.cache
            .put_ip_score(domain, ip, snapshot.0, snapshot.1, snapshot.2);
        degraded
    }

    fn remember_plan(&self, plan: &ConnectPlan) {
        let key = plan_key(&plan.domain, plan.port, plan.tls);
        let mut cache = self.plan_cache.lock();
        if cache.len() > PLAN_CACHE_MAX {
            let ttl = Duration::from_secs(self.config.snapshot().advanced.plan_cache_secs);
            cache.retain(|_, (at, _)| at.elapsed() < ttl);
        }
        cache.insert(key, (Instant::now(), plan.clone()));
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
                match engine.prober.probe_tcp(ip, 443, Duration::from_secs(3)).await {
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
    pub fn note_tunnel_success(&self, plan: &ConnectPlan, latency_ms: u64) {
        let config = self.config.snapshot();
        self.record_success(
            plan,
            latency_ms,
            Vec::new(),
            &DohExpansion::default(),
            &config,
        );
    }

    fn record_success(
        &self,
        plan: &ConnectPlan,
        latency_ms: u64,
        attempts: Vec<AttemptRecord>,
        doh: &DohExpansion,
        config: &AppConfig,
    ) -> DomainDiagnostics {
        self.cache.put_last_good(LastGoodEntry {
            domain: plan.domain.clone(),
            ip: plan.ip,
            strategy: plan.mode.cache_strategy(),
            source: plan.source,
            network_id: network_id(),
            saved_at: now(),
            catalog_version: config.catalog_version,
        });
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
        let diagnostics = DomainDiagnostics {
            group: Some(plan.group_id.clone()),
            domain: plan.domain.clone(),
            state: if plan.mode == TlsMode::Direct {
                State::Direct
            } else {
                State::Normal
            },
            strategy: Some(plan.mode),
            configured_strategy: config.group(&plan.group_id).map(|group| group.strategy),
            ip: Some(plan.ip),
            ip_source: Some(plan.source),
            doh_source,
            latency_ms: Some(latency_ms),
            last_check: now(),
            catalog_version: config.catalog_version,
            cache: cache_status,
            error: None,
            detail: None,
            attempts,
            suggestions: Vec::new(),
        };
        let degraded = self.record_ip(&plan.domain, plan.ip, Some(latency_ms), false);
        self.remember_plan(plan);
        if degraded {
            // The proven route suddenly got slow: drop the cached plan so the next
            // connection re-races the routes instead of staying pinned to it.
            tracing::info!(
                domain = %plan.domain,
                latency_ms,
                "route degraded; re-racing routes on the next connection"
            );
            self.plan_cache
                .lock()
                .remove(&plan_key(&plan.domain, plan.port, plan.tls));
        }
        self.status.record(diagnostics.clone());
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
    fn failure_diagnostics(
        &self,
        group: &GroupConfig,
        domain: &str,
        config: &AppConfig,
        reason: FailureReason,
        attempts: Vec<AttemptRecord>,
        doh: &DohExpansion,
        detail: Option<String>,
    ) -> DomainDiagnostics {
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
        let diagnostics = DomainDiagnostics {
            group: Some(group.id.clone()),
            domain: domain.to_string(),
            state: State::Failed,
            strategy: None,
            configured_strategy: Some(group.strategy),
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
        };
        self.status.record(diagnostics.clone());
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

    async fn expand_doh(
        &self,
        domain: &str,
        candidates: &mut Vec<Candidate>,
        seen: &mut HashSet<IpAddr>,
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
                    if seen.insert(ip) {
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

    fn sni_candidates(
        &self,
        config: &AppConfig,
        group: &GroupConfig,
        domain: &str,
        network: &str,
    ) -> Vec<Option<String>> {
        // A group that names its own SNI is authoritative: `Some("")` means
        // "send no SNI", not "fall back to the shared candidates".
        if let Some(configured) = &group.sni {
            let value = configured.trim().to_ascii_lowercase();
            return vec![if value.is_empty() { None } else { Some(value) }];
        }

        let mut out: Vec<Option<String>> = Vec::new();
        let mut push = |candidate: Option<String>| {
            let normalized = candidate.and_then(|value| {
                if value.trim().is_empty() {
                    None
                } else {
                    Some(value.to_ascii_lowercase())
                }
            });
            if !out.contains(&normalized) {
                out.push(normalized);
            }
        };
        if let Some(cached) = self.cache.sni(&group.id, domain, network) {
            push(cached.sni);
        }
        if let Some(remote) = self.remote.remote_sni(&group.id) {
            push(Some(remote));
        }
        for candidate in &config.advanced.fake_sni_candidates {
            push(Some(candidate.clone()));
        }
        if out.is_empty() {
            out.push(None);
        }
        // Real fake-SNI hosts race first; a `None` entry (no SNI replacement) is
        // effectively a duplicate of the direct route on the same IP, so it goes last.
        out.sort_by_key(|entry| entry.is_none());
        out
    }

    fn config_failure(
        &self,
        group: Option<String>,
        domain: &str,
        config: &AppConfig,
        reason: FailureReason,
        detail: String,
    ) -> DecisionOutcome {
        let diagnostics = DomainDiagnostics {
            group,
            domain: domain.to_string(),
            state: State::Failed,
            strategy: None,
            configured_strategy: None,
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
        };
        self.status.record(diagnostics.clone());
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
        let diagnostics = DomainDiagnostics {
            group: Some(group.id.clone()),
            domain: domain.to_string(),
            state,
            strategy: None,
            configured_strategy: Some(group.strategy),
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
        };
        DecisionOutcome {
            plan: None,
            diagnostics,
        }
    }
}

fn merge_expansion(target: &mut DohExpansion, expansion: DohExpansion) {
    if target.source.is_none() {
        target.source = expansion.source;
    }
    if target.error.is_none() {
        target.error = expansion.error;
    }
    target.stale |= expansion.stale;
}

fn mode_for_strategy(strategy: Strategy) -> TlsMode {
    match strategy {
        Strategy::Direct => TlsMode::Direct,
        Strategy::Ech => TlsMode::Ech,
        Strategy::FakeSni => TlsMode::FakeSni,
        Strategy::Auto => TlsMode::Direct,
    }
}

fn plan_key(domain: &str, port: u16, tls: bool) -> String {
    format!(
        "{}|{port}|{tls}",
        domain.trim().trim_end_matches('.').to_ascii_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheManager;
    use crate::catalog::RemoteIpProvider;
    use crate::config::ConfigManager;
    use crate::paths::Paths;
    use crate::resolver::DohResolution;
    use crate::status::StatusStore;
    use crate::strategy::DohSource;
    use anyhow::Result;
    use parking_lot::Mutex;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct FakeRemote {
        ips: Mutex<Option<Vec<IpAddr>>>,
        sni: Mutex<Option<String>>,
        catalog: Mutex<bool>,
    }

    impl RemoteIpProvider for FakeRemote {
        fn remote_ips(&self, _domain: &str) -> Option<(String, Vec<IpAddr>)> {
            self.ips
                .lock()
                .clone()
                .map(|ips| ("example.com".to_string(), ips))
        }
        fn remote_sni(&self, _group_id: &str) -> Option<String> {
            self.sni.lock().clone()
        }
        fn has_ip_catalog(&self) -> bool {
            *self.catalog.lock()
        }
    }

    #[derive(Default)]
    struct FakeResolver {
        answers: Mutex<VecDeque<Result<DohResolution, String>>>,
    }

    #[async_trait]
    impl IpResolver for FakeResolver {
        async fn doh_ips(&self, _domain: &str) -> Result<DohResolution> {
            match self.answers.lock().pop_front() {
                Some(Ok(answer)) => Ok(answer),
                Some(Err(error)) => Err(anyhow::anyhow!(error)),
                None => Err(anyhow::anyhow!("no answer queued")),
            }
        }

        async fn doh_ech_config(&self, _domain: &str, _allow_shared: bool) -> Result<EchOutcome> {
            Err(anyhow::anyhow!("no ECH"))
        }
    }

    #[derive(Default)]
    struct FakeProber {
        working: Mutex<HashSet<IpAddr>>,
        working_fake_sni: Mutex<HashSet<(IpAddr, Option<String>)>>,
        calls: Mutex<Vec<(IpAddr, TlsMode, Option<String>)>>,
    }

    #[async_trait]
    impl Prober for FakeProber {
        async fn probe_tls(
            &self,
            ip: IpAddr,
            _port: u16,
            _domain: &str,
            mode: TlsMode,
            sni: Option<&str>,
            _ech: Option<&[u8]>,
            _timeout: Duration,
        ) -> std::result::Result<ProbeSuccess, ConnectError> {
            self.calls
                .lock()
                .push((ip, mode, sni.map(ToOwned::to_owned)));
            let works = match mode {
                TlsMode::FakeSni => self
                    .working_fake_sni
                    .lock()
                    .contains(&(ip, sni.map(ToOwned::to_owned))),
                _ => self.working.lock().contains(&ip),
            };
            if works {
                Ok(ProbeSuccess {
                    latency_ms: 10,
                    alpn: None,
                })
            } else {
                Err(ConnectError::TlsReset("blocked".into()))
            }
        }

        async fn probe_tcp(
            &self,
            ip: IpAddr,
            _port: u16,
            _timeout: Duration,
        ) -> std::result::Result<u64, ConnectError> {
            if self.working.lock().contains(&ip) {
                Ok(5)
            } else {
                Err(ConnectError::TcpRefused)
            }
        }
    }

    #[tokio::test]
    async fn reprobe_restores_ips_that_answer_again() {
        let h = harness(&["example.com"], Strategy::Auto);
        let ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        h.engine.record_ip("example.com", ip, None, true);
        let before = h.engine.score_ip("example.com", ip);

        // The fake prober answers for IPs in `working`.
        h.prober.working.lock().insert(ip);
        let restored = h.engine.reprobe_failed_ips(16).await;
        assert_eq!(restored, 1, "the answering ip must be restored");

        let after = h.engine.score_ip("example.com", ip);
        assert!(after < before, "rank {before} should drop to {after}");

        // An IP that still refuses connections gains nothing.
        let dead: std::net::IpAddr = "203.0.113.99".parse().unwrap();
        h.engine.record_ip("example.com", dead, None, true);
        let before_dead = h.engine.score_ip("example.com", dead);
        let restored = h.engine.reprobe_failed_ips(16).await;
        assert_eq!(
            restored, 0,
            "the recovered ip has left the re-probe set; the dead one still fails"
        );
        assert_eq!(
            h.engine.score_ip("example.com", dead),
            before_dead,
            "a dead ip must not be forgiven"
        );
    }

    #[tokio::test]
    async fn a_successful_reprobe_pays_down_the_failure_history() {
        let h = harness(&["example.com"], Strategy::Auto);
        let ip: IpAddr = "203.0.113.40".parse().unwrap();
        h.engine.record_ip("example.com", ip, None, true);
        h.prober.working.lock().insert(ip);

        assert_eq!(h.engine.reprobe_failed_ips(16).await, 1);
        let failures = h
            .engine
            .ip_scores
            .read()
            .get("example.com")
            .and_then(|by_ip| by_ip.get(&ip))
            .map(|score| score.failures)
            .unwrap();
        assert_eq!(failures, 0, "a success must forgive the failure history");
        assert_eq!(
            h.engine.reprobe_failed_ips(16).await,
            0,
            "a recovered ip must leave the re-probe set instead of being probed every minute"
        );
    }

    #[tokio::test]
    async fn persisted_scores_keep_a_blocked_ip_demoted_after_restart() {
        let h = harness(&["example.com"], Strategy::Auto);
        let ip: std::net::IpAddr = "203.0.113.30".parse().unwrap();
        h.engine.record_ip("example.com", ip, None, true);
        let demoted = h.engine.score_ip("example.com", ip);

        // A "restart": a fresh engine seeded from the same cache.
        let restarted = DecisionEngine::new(
            h.engine.config.clone(),
            h.cache.clone(),
            h.remote.clone(),
            h.resolver.clone(),
            h.prober.clone(),
            Arc::new(StatusStore::new()),
        );
        assert_eq!(
            restarted.score_ip("example.com", ip),
            demoted,
            "the restart must remember that this ip was blocked"
        );
    }

    #[test]
    fn ip_score_overflow_keeps_known_good_ips() {
        let h = harness(&["example.com"], Strategy::Auto);
        let good: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        h.engine.record_ip("example.com", good, Some(80), false);

        // Flood the map past its cap with failed routes.
        for i in 0..5000u32 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, (i >> 16) as u8, (i >> 8) as u8, i as u8));
            h.engine.record_ip("example.com", ip, None, true);
        }

        let rank = h.engine.score_ip("example.com", good);
        assert!(
            rank < f64::MAX,
            "overflow wiped the known-good ip; its measured quality must survive"
        );
    }

    struct Harness {
        _dir: tempfile::TempDir,
        engine: Arc<DecisionEngine>,
        cache: Arc<CacheManager>,
        remote: Arc<FakeRemote>,
        prober: Arc<FakeProber>,
        resolver: Arc<FakeResolver>,
    }

    fn harness(group_domains: &[&str], strategy: Strategy) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        paths.ensure().unwrap();
        let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
        config
            .upsert_group(GroupConfig {
                id: "test".into(),
                name: "Test".into(),
                domains: group_domains.iter().map(|d| d.to_string()).collect(),
                strategy,
                enabled: true,
                sni: None,
                experimental: false,
                ech_shared: false,
            })
            .unwrap();
        let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
        let remote = Arc::new(FakeRemote::default());
        let prober = Arc::new(FakeProber::default());
        let resolver = Arc::new(FakeResolver::default());
        let status = Arc::new(StatusStore::new());
        let engine = DecisionEngine::new(
            config,
            cache.clone(),
            remote.clone(),
            resolver.clone(),
            prober.clone(),
            status,
        );
        Harness {
            _dir: dir,
            engine,
            cache,
            remote,
            prober,
            resolver,
        }
    }

    #[test]
    fn explicit_group_sni_replaces_the_shared_candidates() {
        let harness = harness(&["example.com"], Strategy::FakeSni);
        let config = harness.engine.config.snapshot();
        let mut group = config.group("test").unwrap().clone();

        // An explicit empty value means "send no SNI", not "use the defaults".
        group.sni = Some(String::new());
        assert_eq!(
            harness
                .engine
                .sni_candidates(&config, &group, "example.com", "net"),
            vec![None]
        );

        group.sni = Some("WWW.Baidu.com".into());
        assert_eq!(
            harness
                .engine
                .sni_candidates(&config, &group, "example.com", "net"),
            vec![Some("www.baidu.com".to_string())]
        );

        // Without an explicit value the shared candidates still apply.
        group.sni = None;
        let candidates = harness
            .engine
            .sni_candidates(&config, &group, "example.com", "net");
        assert!(candidates.iter().any(|candidate| candidate.is_some()));
    }

    #[tokio::test]
    async fn direct_tries_remote_before_doh() {
        let harness = harness(&["example.com"], Strategy::Auto);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
        harness
            .prober
            .working
            .lock()
            .insert("1.1.1.1".parse().unwrap());
        let outcome = harness.engine.decide_https("example.com").await;
        let plan = outcome.plan.unwrap();
        assert_eq!(plan.ip.to_string(), "1.1.1.1");
        assert_eq!(plan.mode, TlsMode::Direct);
        assert_eq!(outcome.diagnostics.ip_source, Some(IpSource::Remote));
        assert!(harness.resolver.answers.lock().is_empty());
    }

    #[tokio::test]
    async fn a_manual_probe_runs_while_routing_is_paused() {
        let harness = harness(&["example.com"], Strategy::Auto);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
        harness.prober.working.lock().insert("1.1.1.1".parse().unwrap());
        harness.engine.status.set_paused(true);

        // Routing still bypasses while paused...
        assert!(matches!(
            harness.engine.route("example.com", 443, true),
            Route::Bypass(_)
        ));

        // ...but a diagnostic probe is an observation and must run.
        let outcome = harness.engine.decide_https("example.com").await;
        assert_eq!(outcome.diagnostics.state, State::Direct);
        assert_eq!(outcome.diagnostics.ip, Some("1.1.1.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn route_cursor_needs_no_probe_and_caches_the_plan() {
        let harness = harness(&["example.com"], Strategy::Direct);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
        let mut cursor = match harness.engine.route("example.com", 443, true) {
            Route::Group(cursor) => cursor,
            _ => panic!("expected a group route"),
        };
        let plan = cursor.next_plan().await.expect("a direct plan");
        assert_eq!(plan.mode, TlsMode::Direct);
        assert_eq!(plan.ip.to_string(), "1.1.1.1");
        assert!(harness.prober.calls.lock().is_empty());

        let outcome = cursor.note_success(&plan, 7);
        assert_eq!(outcome.diagnostics.state, State::Direct);
        let cached = harness
            .engine
            .cached_plan("example.com", 443, true)
            .expect("successful plan should be cached");
        assert_eq!(cached.ip, plan.ip);
        assert_eq!(cached.source, IpSource::Remote);
        assert!(harness.prober.calls.lock().is_empty());
    }

    #[tokio::test]
    async fn cached_plan_is_invalidated_when_strategy_changes() {
        let harness = harness(&["example.com"], Strategy::Auto);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
        harness
            .prober
            .working
            .lock()
            .insert("1.1.1.1".parse().unwrap());
        let outcome = harness.engine.decide_https("example.com").await;
        assert!(outcome.plan.is_some());
        assert!(harness
            .engine
            .cached_plan("example.com", 443, true)
            .is_some());

        harness
            .engine
            .config
            .set_group_strategy("test", Strategy::FakeSni)
            .unwrap();
        assert!(harness
            .engine
            .cached_plan("example.com", 443, true)
            .is_none());
    }

    #[tokio::test]
    async fn last_good_strategy_is_tried_first() {
        let harness = harness(&["example.com"], Strategy::Auto);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
        harness.cache.put_last_good(LastGoodEntry {
            domain: "example.com".into(),
            ip: "1.1.1.1".parse().unwrap(),
            strategy: Strategy::FakeSni,
            source: IpSource::Cache,
            network_id: network_id(),
            saved_at: now(),
            catalog_version: 1,
        });
        let mut cursor = match harness.engine.route("example.com", 443, true) {
            Route::Group(cursor) => cursor,
            _ => panic!("expected a group route"),
        };
        let plan = cursor.next_plan().await.expect("a plan");
        assert_eq!(plan.mode, TlsMode::FakeSni);
    }

    #[tokio::test]
    async fn catalog_update_bypasses_cached_plan_once() {
        let harness = harness(&["example.com"], Strategy::Auto);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
        harness
            .prober
            .working
            .lock()
            .insert("1.1.1.1".parse().unwrap());
        assert!(harness
            .engine
            .decide_https("example.com")
            .await
            .plan
            .is_some());
        assert!(harness
            .engine
            .cached_plan("example.com", 443, true)
            .is_some());

        harness.cache.mark_skip_once(["example.com"]);
        assert!(harness
            .engine
            .cached_plan("example.com", 443, true)
            .is_none());
        let mut cursor = match harness.engine.route("example.com", 443, true) {
            Route::Group(cursor) => cursor,
            _ => panic!("expected a group route"),
        };
        assert!(cursor.skip_once());
        let plan = cursor.next_plan().await.expect("remote plan");
        assert_eq!(plan.source, IpSource::Remote);
    }

    #[tokio::test]
    async fn falls_back_to_second_remote_ip_in_order() {
        let harness = harness(&["example.com"], Strategy::Direct);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() =
            Some(vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()]);
        harness
            .prober
            .working
            .lock()
            .insert("8.8.8.8".parse().unwrap());
        let outcome = harness.engine.decide_https("example.com").await;
        assert_eq!(outcome.plan.unwrap().ip.to_string(), "8.8.8.8");
        let calls = harness.prober.calls.lock();
        assert_eq!(calls[0].0.to_string(), "1.1.1.1");
        assert_eq!(calls[1].0.to_string(), "8.8.8.8");
    }

    #[tokio::test]
    async fn doh_is_used_after_initial_candidates_fail() {
        let harness = harness(&["example.com"], Strategy::Direct);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
        harness
            .prober
            .working
            .lock()
            .insert("9.9.9.9".parse().unwrap());
        harness.resolver.answers.lock().push_back(Ok(DohResolution {
            ips: vec!["9.9.9.9".parse().unwrap()],
            hints: Vec::new(),
            source: DohSource::Primary,
            endpoint: "primary".into(),
            stale: false,
            ttl: 60,
            fallback_used: false,
        }));
        let outcome = harness.engine.decide_https("example.com").await;
        let plan = outcome.plan.unwrap();
        assert_eq!(plan.ip.to_string(), "9.9.9.9");
        assert_eq!(outcome.diagnostics.ip_source, Some(IpSource::Doh));
        assert_eq!(outcome.diagnostics.doh_source, Some(DohSource::Primary));
    }

    #[tokio::test]
    async fn skip_once_prefers_new_remote_ip() {
        let harness = harness(&["example.com"], Strategy::Direct);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["8.8.8.8".parse().unwrap()]);
        harness.cache.put_last_good(LastGoodEntry {
            domain: "example.com".into(),
            ip: "1.1.1.1".parse().unwrap(),
            strategy: Strategy::Direct,
            source: IpSource::Remote,
            network_id: network_id(),
            saved_at: now(),
            catalog_version: 1,
        });
        harness.cache.mark_skip_once(["example.com"]);
        harness
            .prober
            .working
            .lock()
            .insert("1.1.1.1".parse().unwrap());
        harness
            .prober
            .working
            .lock()
            .insert("8.8.8.8".parse().unwrap());
        let outcome = harness.engine.decide_https("example.com").await;
        assert_eq!(outcome.plan.unwrap().ip.to_string(), "8.8.8.8");
        assert!(!harness.cache.has_skip_once("example.com"));
    }

    #[tokio::test]
    async fn auto_interleaves_the_accelerated_route_after_direct() {
        // Even when direct works, the accelerated route must be the very next
        // plan so the connection race can pick the faster one.
        let harness = harness(&["example.com"], Strategy::Auto);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        harness
            .prober
            .working_fake_sni
            .lock()
            .insert((ip, Some("www.baidu.com".into())));
        match harness.engine.route("example.com", 443, true) {
            Route::Group(mut cursor) => {
                let first = cursor.next_plan().await.unwrap();
                assert_eq!(first.mode, TlsMode::Direct);
                let second = cursor.next_plan().await.unwrap();
                assert_eq!(second.mode, TlsMode::FakeSni);
                assert_eq!(second.ip, ip);
                assert_eq!(second.sni.as_deref(), Some("www.baidu.com"));
            }
            _ => panic!("expected a group cursor"),
        }
    }

    #[tokio::test]
    async fn auto_falls_back_to_fake_sni_and_caches_it() {
        let harness = harness(&["example.com"], Strategy::Auto);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        harness
            .prober
            .working_fake_sni
            .lock()
            .insert((ip, Some("www.baidu.com".into())));
        let outcome = harness.engine.decide_https("example.com").await;
        let plan = outcome.plan.expect("fake SNI should succeed");
        assert_eq!(plan.mode, TlsMode::FakeSni);
        assert_eq!(plan.sni.as_deref(), Some("www.baidu.com"));
        let cached = harness
            .cache
            .sni("test", "example.com", &network_id())
            .expect("winning SNI should be cached");
        assert_eq!(cached.sni.as_deref(), Some("www.baidu.com"));
    }

    #[tokio::test]
    async fn failure_returns_reasons_and_attempts() {
        let harness = harness(&["example.com"], Strategy::Direct);
        *harness.remote.catalog.lock() = true;
        *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
        let outcome = harness.engine.decide_https("example.com").await;
        assert!(outcome.plan.is_none());
        assert_eq!(outcome.diagnostics.state, State::Failed);
        assert_eq!(outcome.diagnostics.attempts.len(), 1);
        assert_eq!(
            outcome.diagnostics.attempts[0].error,
            Some(FailureReason::TlsReset)
        );
    }
}
