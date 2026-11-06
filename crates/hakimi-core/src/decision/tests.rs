use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::cache::{CacheManager, LastGoodEntry};
use crate::catalog::RemoteIpProvider;
use crate::config::{ConfigManager, DomainRule, GroupConfig, RouteAttempt, RoutePolicy};
use crate::ip_tester::{ConnectError, ProbeSuccess};
use crate::paths::Paths;
use crate::resolver::{DohResolution, EchOutcome, IpResolver};
use crate::status::{State, StatusStore};
use crate::strategy::{CacheStatus, DohSource, FailureReason, IpSource, TlsMode};
use crate::util::{network_id, now};
use anyhow::Result;

use super::engine::PLAN_CACHE_MAX;
use super::*;

#[derive(Default)]
struct FakeRemote {
    ips: Mutex<Option<Vec<IpAddr>>>,
    catalog: Mutex<bool>,
}

impl RemoteIpProvider for FakeRemote {
    fn remote_ips(&self, _domain: &str) -> Option<Arc<[IpAddr]>> {
        self.ips.lock().clone().map(Arc::from)
    }
    fn has_ip_catalog(&self) -> bool {
        *self.catalog.lock()
    }
}

#[derive(Default)]
struct FakeResolver {
    answers: Mutex<VecDeque<Result<DohResolution, String>>>,
    doh_calls: AtomicUsize,
    ech_calls: AtomicUsize,
}

#[async_trait]
impl IpResolver for FakeResolver {
    async fn doh_ips(&self, _domain: &str) -> Result<DohResolution> {
        self.doh_calls.fetch_add(1, Ordering::SeqCst);
        match self.answers.lock().pop_front() {
            Some(Ok(answer)) => Ok(answer),
            Some(Err(error)) => Err(anyhow::anyhow!(error)),
            None => Err(anyhow::anyhow!("no answer queued")),
        }
    }

    async fn doh_ech_config(&self, _domain: &str, _allow_shared: bool) -> Result<EchOutcome> {
        self.ech_calls.fetch_add(1, Ordering::SeqCst);
        Err(anyhow::anyhow!("no ECH"))
    }
}

#[derive(Default)]
struct FakeProber {
    working: Mutex<HashSet<IpAddr>>,
    working_fake_sni: Mutex<HashSet<(IpAddr, Option<String>)>>,
    /// Per-address handshake latency, `10` when absent.
    latencies: Mutex<HashMap<IpAddr, u64>>,
    /// Addresses that never answer the TCP handshake.
    dead_tcp: Mutex<HashSet<IpAddr>>,
    /// Variants whose TCP leg connects but whose handshake never completes.
    stalled_tls: Mutex<Vec<(IpAddr, TlsMode)>>,
    /// Variants that answer with a certificate which cannot cover the domain.
    bad_cert: Mutex<Vec<(IpAddr, Option<String>)>>,
    calls: Mutex<Vec<(IpAddr, TlsMode, Option<String>)>>,
    tcp_calls: AtomicUsize,
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
        if self.dead_tcp.lock().contains(&ip) {
            return Err(ConnectError::TcpTimeout);
        }
        if self.stalled_tls.lock().iter().any(|(stalled_ip, stalled_mode)| *stalled_ip == ip && *stalled_mode == mode)
        {
            return Err(ConnectError::TlsTimeout);
        }
        if self
            .bad_cert
            .lock()
            .iter()
            .any(|(bad_ip, bad_sni)| *bad_ip == ip && bad_sni.as_deref() == sni)
        {
            return Err(ConnectError::CertInvalid(
                "certificate does not cover the domain".into(),
            ));
        }
        let works = match mode {
            TlsMode::FakeSni => self
                .working_fake_sni
                .lock()
                .contains(&(ip, sni.map(ToOwned::to_owned))),
            _ => self.working.lock().contains(&ip),
        };
        if works {
            Ok(ProbeSuccess {
                latency_ms: self.latencies.lock().get(&ip).copied().unwrap_or(10),
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
        self.tcp_calls.fetch_add(1, Ordering::SeqCst);
        if self.working.lock().contains(&ip) {
            Ok(5)
        } else {
            Err(ConnectError::TcpRefused)
        }
    }
}

#[tokio::test]
async fn reprobe_backs_off_addresses_that_keep_failing() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
    h.engine.record_ip("example.com", ip, None, true);

    // First re-probe runs and fails: the address enters its backoff window.
    assert_eq!(h.engine.reprobe_failed_ips(8).await, 0);
    assert_eq!(h.prober.tcp_calls.load(Ordering::SeqCst), 1);
    assert!(!h.engine.probe_backoff_ready("example.com", ip));

    // Inside the window the address is not probed again.
    h.engine.reprobe_failed_ips(8).await;
    assert_eq!(h.prober.tcp_calls.load(Ordering::SeqCst), 1);

    // Once the window passes, the probe runs again; success clears the
    // backoff and the recovered address leaves the re-probe set entirely.
    {
        let mut map = h.engine.probe_backoff.lock();
        for (_, next) in map.values_mut() {
            *next = Instant::now() - Duration::from_secs(1);
        }
    }
    h.prober.working.lock().insert(ip);
    assert_eq!(h.engine.reprobe_failed_ips(8).await, 1);
    assert_eq!(h.prober.tcp_calls.load(Ordering::SeqCst), 2);
    assert!(h.engine.probe_backoff_ready("example.com", ip));

    h.engine.reprobe_failed_ips(8).await;
    assert_eq!(h.prober.tcp_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn reprobe_restores_ips_that_answer_again() {
    let h = harness(&["example.com"], RoutePolicy::auto());
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
    let h = harness(&["example.com"], RoutePolicy::auto());
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

#[test]
fn masked_sni_block_status_does_not_penalize_the_ip() {
    // api.github.com answers warm-ups on the masked-SNI route with a steady
    // 403/429: that is the CDN rejecting the name mismatch, not a walled
    // address. Only the same status on the real SNI (direct) is a signal.
    let h = harness(&["example.com"], RoutePolicy::direct());
    let mut masked = test_plan(TlsMode::FakeSni, Some("www.bing.com"));
    masked.domain = "api.github.com".into();
    masked.group_id = "github".into();
    h.engine.remember_plan_arc(Arc::new(masked));
    assert!(h.engine.cached_plan("api.github.com", 443, true).is_some());

    assert!(!h.engine.note_blocked_candidate(
        "api.github.com",
        443,
        true,
        http::StatusCode::FORBIDDEN,
        true,
    ));
    assert!(!h
        .engine
        .ip_rejected("api.github.com", "1.1.1.1".parse().unwrap()));
    assert!(h.engine.cached_plan("api.github.com", 443, true).is_some());

    // The same status on the real SNI is a block page: penalize the IP.
    let mut direct = test_plan(TlsMode::Direct, None);
    direct.domain = "api.github.com".into();
    direct.group_id = "github".into();
    h.engine.remember_plan_arc(Arc::new(direct));
    assert!(h.engine.note_blocked_candidate(
        "api.github.com",
        443,
        true,
        http::StatusCode::FORBIDDEN,
        true,
    ));
    assert!(h
        .engine
        .ip_rejected("api.github.com", "1.1.1.1".parse().unwrap()));
    assert!(h.engine.cached_plan("api.github.com", 443, true).is_none());
}

#[tokio::test]
async fn a_timed_out_candidate_sinks_behind_an_untested_one() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    let failed: IpAddr = "203.0.113.10".parse().unwrap();
    let untested: IpAddr = "203.0.113.11".parse().unwrap();
    // Catalog order puts the dead address first; the quality rank must
    // reverse it.
    *h.remote.ips.lock() = Some(vec![failed, untested]);
    h.engine.record_ip("example.com", failed, None, true);

    let mut cursor = match h.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let plan = cursor.next_plan().await.expect("a direct plan");
    assert_eq!(
        plan.ip, untested,
        "an address that timed out must not be tried before an untested one"
    );
}

#[test]
fn ip_score_overflow_keeps_known_good_ips() {
    let h = harness(&["example.com"], RoutePolicy::auto());
    let good: std::net::IpAddr = "203.0.113.10".parse().unwrap();
    h.engine.record_ip("example.com", good, Some(80), false);

    // Flood the map past its cap with failed routes.
    for i in 0..5000u32 {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            (i >> 16) as u8,
            (i >> 8) as u8,
            i as u8,
        ));
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

fn harness(group_domains: &[&str], default_route: RoutePolicy) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .upsert_group(GroupConfig {
            id: "test".into(),
            name: "Test".into(),
            domains: group_domains
                .iter()
                .map(|domain| DomainRule::new(*domain))
                .collect(),
            enabled: true,
            homepage: None,
            default_route,
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

#[tokio::test]
async fn cold_route_prefetch_starts_dns_and_ech_work() {
    let route = RoutePolicy::ech_shared();
    let h = harness(&["example.com"], route.clone());

    h.engine.prefetch_cold_route("example.com", 443, &route);

    for _ in 0..50 {
        if h.resolver.doh_calls.load(Ordering::SeqCst) > 0
            && h.resolver.ech_calls.load(Ordering::SeqCst) > 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(
        h.resolver.doh_calls.load(Ordering::SeqCst),
        1,
        "a cold route should start one DoH IP lookup"
    );
    assert_eq!(
        h.resolver.ech_calls.load(Ordering::SeqCst),
        1,
        "a cold ECH route should start one ECH lookup"
    );
}

#[tokio::test]
async fn cold_route_prefetch_queries_doh_when_catalog_is_full() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    let dead: Vec<IpAddr> = (1..=8)
        .map(|last| format!("203.0.113.{last}").parse().unwrap())
        .collect();
    *h.remote.ips.lock() = Some(dead);

    h.engine
        .prefetch_cold_route("example.com", 443, &RoutePolicy::direct());
    for _ in 0..50 {
        if h.resolver.doh_calls.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(
        h.resolver.doh_calls.load(Ordering::SeqCst),
        1,
        "a full catalog cannot expand to DoH until a candidate fails; the lookup must start early"
    );
}

#[tokio::test]
async fn route_sni_hosts_drive_fake_sni_plans() {
    let route = RoutePolicy::new(vec![RouteAttempt::Sni {
        sni: vec!["WWW.Baidu.com".into()],
    }]);
    let harness = harness(&["example.com"], route);
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["203.0.113.10".parse().unwrap()]);
    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let plan = cursor.next_plan().await.expect("a fake-SNI plan");
    assert_eq!(plan.mode, TlsMode::FakeSni);
    assert_eq!(plan.sni.as_deref(), Some("www.baidu.com"));
}

/// The fake-SNI sweep is candidate-major: every candidate IP must get the
/// full SNI list. Previously `sni_index` was never reset when the cursor
/// advanced to the next candidate, so only the first IP was ever tried.
#[tokio::test]
async fn fake_sni_sweep_restarts_for_each_candidate() {
    let harness = harness(&["example.com"], RoutePolicy::sni(Vec::new()));
    *harness.remote.catalog.lock() = true;
    let first: IpAddr = "203.0.113.10".parse().unwrap();
    let second: IpAddr = "203.0.113.11".parse().unwrap();
    *harness.remote.ips.lock() = Some(vec![first, second]);

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let mut plans = Vec::new();
    while let Some(plan) = cursor.next_plan().await {
        plans.push(plan);
    }

    let first_plans = plans.iter().filter(|plan| plan.ip == first).count();
    let second_plans = plans.iter().filter(|plan| plan.ip == second).count();
    assert!(
        first_plans > 0,
        "the first candidate must get the SNI sweep: {plans:?}"
    );
    assert_eq!(
        first_plans, second_plans,
        "both candidate IPs must be paired with the same SNI list, got {plans:?}"
    );
}

#[tokio::test]
async fn direct_tries_remote_before_doh() {
    let harness = harness(&["example.com"], RoutePolicy::auto());
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
    let harness = harness(&["example.com"], RoutePolicy::auto());
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
    harness
        .prober
        .working
        .lock()
        .insert("1.1.1.1".parse().unwrap());
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
    let harness = harness(&["example.com"], RoutePolicy::direct());
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

    let plan_ip = plan.ip;
    let outcome = cursor.note_success(Arc::new(plan), 7);
    assert_eq!(outcome.diagnostics.state, State::Direct);
    let cached = harness
        .engine
        .cached_plan("example.com", 443, true)
        .expect("successful plan should be cached");
    assert_eq!(cached.ip, plan_ip);
    assert_eq!(cached.source, IpSource::Remote);
    assert!(harness.prober.calls.lock().is_empty());
}

#[tokio::test]
async fn cached_plan_is_invalidated_when_route_changes() {
    let harness = harness(&["example.com"], RoutePolicy::auto());
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
        .set_group_default_route(
            "test",
            RoutePolicy::new(vec![RouteAttempt::Sni { sni: Vec::new() }]),
        )
        .unwrap();
    assert!(harness
        .engine
        .cached_plan("example.com", 443, true)
        .is_none());
}

fn test_plan(mode: TlsMode, sni: Option<&str>) -> ConnectPlan {
    ConnectPlan {
        domain: "example.com".into(),
        group_id: "test".into(),
        ip: "1.1.1.1".parse().unwrap(),
        port: 443,
        mode,
        sni: sni.map(ToOwned::to_owned),
        ech_config: None,
        tls: true,
        source: IpSource::Remote,
        rule_index: None,
    }
}

#[tokio::test]
async fn duplicate_addresses_from_catalog_and_doh_are_merged() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    *h.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
    h.resolver.answers.lock().push_back(Ok(DohResolution {
        // The first address is already known from the catalog.
        ips: vec!["1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()],
        source: DohSource::Primary,
        endpoint: "primary".into(),
        stale: false,
        ttl: 60,
        fallback_used: false,
    }));
    let mut cursor = match h.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let mut seen: Vec<IpAddr> = Vec::new();
    while let Some(plan) = cursor.next_plan().await {
        seen.push(plan.ip);
    }
    let first: IpAddr = "1.1.1.1".parse().unwrap();
    assert_eq!(
        seen.iter().filter(|ip| **ip == first).count(),
        1,
        "an address known from both sources must be tried once: {seen:?}"
    );
    assert!(seen.contains(&"2.2.2.2".parse().unwrap()));
}

#[test]
fn plan_cache_stays_bounded_when_every_entry_is_fresh() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    for i in 0..(PLAN_CACHE_MAX + 100) {
        let mut plan = test_plan(TlsMode::Direct, None);
        plan.domain = format!("h{i}.example.com");
        h.engine.remember_plan_arc(Arc::new(plan));
    }
    let cache = h.engine.plan_cache.read();
    let total: usize = cache.values().map(|inner| inner.len()).sum();
    assert!(total <= PLAN_CACHE_MAX);
    assert_eq!(
        h.engine.plan_cache_len(),
        total,
        "the maintained count must match the cache after pruning"
    );
    assert!(
        cache
            .get(&format!("h{}.example.com", PLAN_CACHE_MAX + 99))
            .is_some_and(|inner| inner.contains_key(&(443, true))),
        "the newest plan must survive the prune"
    );
}

#[test]
fn plan_cache_count_tracks_inserts_replacements_and_removals() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    assert_eq!(h.engine.plan_cache_len(), 0);

    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::Direct, None)));
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::Direct, None)));
    assert_eq!(
        h.engine.plan_cache_len(),
        1,
        "replacing the same route must not double-count it"
    );

    let mut plain = test_plan(TlsMode::Direct, None);
    plain.port = 80;
    plain.tls = false;
    h.engine.remember_plan_arc(Arc::new(plain));
    assert_eq!(h.engine.plan_cache_len(), 2);

    h.engine.forget_plan("example.com", 80, false);
    assert_eq!(h.engine.plan_cache_len(), 1);
    h.engine.forget_plan("example.com", 80, false);
    assert_eq!(
        h.engine.plan_cache_len(),
        1,
        "forgetting an absent route must not underflow the count"
    );

    h.engine.forget_all_plans();
    assert_eq!(h.engine.plan_cache_len(), 0);
}

#[test]
fn network_change_clears_network_scoped_state() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::Direct, None)));
    assert!(h.engine.cached_plan("example.com", 443, true).is_some());

    h.engine
        .route_rejections
        .write()
        .insert("example.com|direct".into(), Instant::now());
    h.engine
        .ip_rejections
        .write()
        .entry("example.com".into())
        .or_default()
        .insert(ip, Instant::now());
    h.engine.record_ip("example.com", ip, Some(25), false);
    assert!(h.engine.route_rejected("example.com", TlsMode::Direct));
    assert!(h.engine.ip_rejected("example.com", ip));

    h.engine.on_network_change();

    assert!(
        h.engine.cached_plan("example.com", 443, true).is_none(),
        "a plan remembered on the old network must not survive"
    );
    assert_eq!(h.engine.plan_cache_len(), 0);
    assert!(
        !h.engine.route_rejected("example.com", TlsMode::Direct),
        "route rejection timers must not leak across networks"
    );
    assert!(
        !h.engine.ip_rejected("example.com", ip),
        "candidate rejections must not leak across networks"
    );
    assert!(
        h.engine.ip_scores.read().is_empty(),
        "quality scores describe the old network"
    );
}

#[test]
fn plan_cache_finds_entries_under_any_spelling_of_the_domain() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::Direct, None)));
    for spelling in [
        "example.com",
        "EXAMPLE.com",
        "example.com.",
        " example.com. ",
    ] {
        assert!(
            h.engine.cached_plan(spelling, 443, true).is_some(),
            "`{spelling}` must find the stored plan"
        );
    }
    // Forgetting has to use the same spelling rules.
    h.engine.forget_plan("EXAMPLE.com.", 443, true);
    assert!(h.engine.cached_plan("example.com", 443, true).is_none());
}

#[test]
fn an_expired_plan_is_dropped() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::Direct, None)));
    assert!(h.engine.cached_plan("example.com", 443, true).is_some());

    // Age the entry past the TTL (the default is ten minutes).
    {
        let mut cache = h.engine.plan_cache.write();
        let inner = cache.get_mut("example.com").expect("the domain is cached");
        let entry = inner.get_mut(&(443, true)).expect("the plan is cached");
        entry.0 = std::time::Instant::now() - Duration::from_secs(3600);
    }
    assert!(
        h.engine.cached_plan("example.com", 443, true).is_none(),
        "an expired plan must not be used"
    );
    let cache = h.engine.plan_cache.read();
    assert!(
        !cache
            .get("example.com")
            .is_some_and(|inner| inner.contains_key(&(443, true))),
        "an expired plan must be removed"
    );
    assert_eq!(h.engine.plan_cache_len(), 0);
}

#[test]
fn plan_cache_separates_ports_and_tls_flags() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let mut plain = test_plan(TlsMode::Direct, None);
    plain.port = 80;
    plain.tls = false;
    h.engine.remember_plan_arc(Arc::new(plain));
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::Direct, None)));

    assert!(h.engine.cached_plan("example.com", 443, true).is_some());
    assert!(h.engine.cached_plan("example.com", 80, false).is_some());
    assert!(h.engine.cached_plan("example.com", 80, true).is_none());
    assert!(h.engine.cached_plan("example.com", 443, false).is_none());

    h.engine.forget_plan("example.com", 443, true);
    assert!(h.engine.cached_plan("example.com", 443, true).is_none());
    assert!(
        h.engine.cached_plan("example.com", 80, false).is_some(),
        "forgetting one port must not drop the other"
    );
}

#[test]
fn cached_fake_sni_plan_follows_the_configured_route_sni() {
    let h = harness(
        &["example.com"],
        RoutePolicy::sni(vec!["old.example".into()]),
    );
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::FakeSni, Some("old.example"))));
    assert!(h.engine.cached_plan("example.com", 443, true).is_some());

    let mut group = h.engine.config.snapshot().group("test").unwrap().clone();
    group.default_route = RoutePolicy::new(vec![RouteAttempt::Sni {
        sni: vec!["new.example".into()],
    }]);
    h.engine.config.upsert_group(group).unwrap();
    assert!(
        h.engine.cached_plan("example.com", 443, true).is_none(),
        "the cached plan still used the previous fake SNI"
    );
}

#[test]
fn misdirected_request_drops_the_cached_route() {
    let h = harness(
        &["example.com"],
        RoutePolicy::sni(vec!["www.baidu.com".into()]),
    );
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::FakeSni, Some("www.baidu.com"))));
    assert!(h.engine.cached_plan("example.com", 443, true).is_some());

    assert!(
        h.engine.note_http_rejection(
            "example.com",
            443,
            true,
            http::StatusCode::MISDIRECTED_REQUEST
        ),
        "the cached fake-SNI route must be rejected"
    );

    assert!(h.engine.cached_plan("example.com", 443, true).is_none());
    assert!(h.engine.route_rejected("example.com", TlsMode::FakeSni));
}

#[tokio::test]
async fn blocked_warmup_penalizes_only_the_cached_ip() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let bad: IpAddr = "1.1.1.1".parse().unwrap();
    let good: IpAddr = "8.8.8.8".parse().unwrap();

    // The unopted test group keeps the old behavior: a block page is not a
    // candidate failure.
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::Direct, None)));
    assert!(!h.engine.note_blocked_candidate(
        "example.com",
        443,
        true,
        http::StatusCode::BAD_REQUEST,
        true
    ));
    assert!(h.engine.cached_plan("example.com", 443, true).is_some());
    assert!(!h.engine.ip_rejected("example.com", bad));

    // GitHub opts in: the same status drops only that IP. The warm-up dials
    // fresh, so its plan attribution is trusted and the IP penalty applies.
    let mut github_plan = test_plan(TlsMode::Direct, None);
    github_plan.domain = "github.com".into();
    github_plan.group_id = "github".into();
    h.engine.remember_plan_arc(Arc::new(github_plan));
    assert!(h.engine.note_blocked_candidate(
        "github.com",
        443,
        true,
        http::StatusCode::BAD_REQUEST,
        true
    ));

    assert!(h.engine.cached_plan("github.com", 443, true).is_none());
    let scores = h.engine.ip_scores.read();
    let entry = scores
        .get("github.com")
        .and_then(|by_ip| by_ip.get(&bad))
        .expect("the blocked IP should have a failure score");
    assert!(entry.failures > 0);
    drop(scores);
    assert!(h.engine.ip_rejected("github.com", bad));
    assert!(!h.engine.ip_rejected("github.com", good));
    // Only the IP is penalized; the direct mode may still work via another IP.
    assert!(!h.engine.route_rejected("github.com", TlsMode::Direct));

    h.engine
        .config
        .set_group_default_route("github", RoutePolicy::direct())
        .unwrap();
    *h.remote.catalog.lock() = true;
    *h.remote.ips.lock() = Some(vec![bad, good]);
    h.prober.working.lock().insert(good);
    let mut cursor = match h.engine.route("github.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let plan = cursor.next_plan().await.expect("good IP plan");
    assert_eq!(plan.ip, good);
}

/// Regression test (finding C1): the traffic path looks the plan up in the
/// cache, where a newer generation may have replaced the one that produced
/// the response. It must retire the route but never touch ip_scores or
/// ip_rejections.
#[tokio::test]
async fn traffic_path_block_pages_retire_without_penalizing_the_ip() {
    // The traffic path looks the plan up in the cache, where a newer
    // generation may have replaced the one that produced the response. It
    // must retire the route but never touch ip_scores or ip_rejections.
    let h = harness(&["example.com"], RoutePolicy::direct());
    let cached_ip: IpAddr = "1.1.1.1".parse().unwrap();
    let mut github_plan = test_plan(TlsMode::Direct, None);
    github_plan.domain = "github.com".into();
    github_plan.group_id = "github".into();
    h.engine.remember_plan_arc(Arc::new(github_plan));

    assert!(
        h.engine
            .note_blocked_candidate("github.com", 443, true, http::StatusCode::TOO_MANY_REQUESTS, false),
        "the route must still be reported as invalidated"
    );
    assert!(
        h.engine.cached_plan("github.com", 443, true).is_none(),
        "the plan is forgotten so the next connection re-plans"
    );
    let scores = h.engine.ip_scores.read();
    assert!(
        scores.get("github.com").is_none(),
        "an unattributable response must not write a failure record"
    );
    drop(scores);
    assert!(!h.engine.ip_rejected("github.com", cached_ip));
}

#[test]
fn real_traffic_block_pages_use_candidate_recovery_for_opted_groups() {
    // A custom group's 403 is content-level: the route must survive, or a
    // Cloudflare challenge would blacklist the only route that works.
    let h = harness(
        &["example.com"],
        RoutePolicy::sni(vec!["www.baidu.com".into()]),
    );
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::FakeSni, Some("www.baidu.com"))));
    assert!(
        !h.engine
            .note_upstream_response("example.com", 443, true, http::StatusCode::FORBIDDEN),
        "a content-level 403 must not invalidate the route"
    );
    assert!(!h.engine.route_rejected("example.com", TlsMode::FakeSni));
    assert!(h.engine.cached_plan("example.com", 443, true).is_some());

    let bad: IpAddr = "1.1.1.1".parse().unwrap();
    let mut github_plan = test_plan(TlsMode::Direct, None);
    github_plan.domain = "github.com".into();
    github_plan.group_id = "github".into();
    h.engine.remember_plan_arc(Arc::new(github_plan));
    assert!(
        h.engine.note_upstream_response(
            "github.com",
            443,
            true,
            http::StatusCode::TOO_MANY_REQUESTS
        ),
        "the connection must still be retired so the next request re-plans"
    );
    assert!(
        !h.engine.route_rejected("github.com", TlsMode::Direct),
        "a block page for one opted-in candidate must not discard the whole mode"
    );
    // The traffic path cannot attribute the response to the connection's own
    // plan (the cache may hold a newer generation), so the IP-level penalty
    // is left to the warm-up, which dials fresh.
    assert!(!h.engine.ip_rejected("github.com", bad));

    // GitHub's 403 on a masked-SNI route *is* a route verdict.
    let mut masked = test_plan(TlsMode::FakeSni, None);
    masked.domain = "api.github.com".into();
    masked.group_id = "github".into();
    h.engine.remember_plan_arc(Arc::new(masked));
    assert!(
        h.engine
            .note_upstream_response("api.github.com", 443, true, http::StatusCode::FORBIDDEN),
        "GitHub's block page must still retire the route"
    );
    assert!(h.engine.route_rejected("api.github.com", TlsMode::FakeSni));
}

/// Linux.do's exact regression: a Cloudflare 403 arrives through the very ECH
/// or fake-SNI route that passes network filtering. Both routes must stay in
/// the plan cache and in the cursor; rejecting them left the domain with
/// Direct only, which is the route the network reset.
#[tokio::test]
async fn a_custom_group_keeps_ech_and_sni_after_block_statuses() {
    let h = harness(&["example.com"], RoutePolicy::auto());
    *h.remote.catalog.lock() = true;
    *h.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);

    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::Ech, None)));
    assert!(
        !h.engine
            .note_upstream_response("example.com", 443, true, http::StatusCode::FORBIDDEN),
        "an ECH route must survive a content-level 403"
    );
    assert!(!h.engine.route_rejected("example.com", TlsMode::Ech));
    assert!(h.engine.cached_plan("example.com", 443, true).is_some());

    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::FakeSni, None)));
    assert!(
        !h.engine
            .note_upstream_response("example.com", 443, true, http::StatusCode::FORBIDDEN),
        "a fake-SNI route must survive a content-level 403"
    );
    assert!(!h.engine.route_rejected("example.com", TlsMode::FakeSni));
    assert!(h.engine.cached_plan("example.com", 443, true).is_some());

    let mut cursor = match h.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let mut modes = Vec::new();
    while let Some(plan) = cursor.next_plan().await {
        modes.push(plan.mode);
    }
    assert!(
        modes.contains(&TlsMode::FakeSni),
        "the fake-SNI attempt must stay in the ladder: {modes:?}"
    );

    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::FakeSni, None)));
    assert!(
        !h.engine.note_http_rejection(
            "example.com",
            443,
            true,
            http::StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
        ),
        "451 is content-level outside GitHub"
    );
    assert!(!h.engine.route_rejected("example.com", TlsMode::FakeSni));
}

/// 403 is a route verdict for GitHub only. Pixiv used to be the motivating
/// case for the old rule; its fake-SNI route must now keep the route.
#[test]
fn a_pixiv_403_is_content_level() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let mut plan = test_plan(TlsMode::FakeSni, None);
    plan.domain = "i.pximg.net".into();
    plan.group_id = "pixiv".into();
    h.engine.remember_plan_arc(Arc::new(plan));

    assert!(!h
        .engine
        .note_http_rejection("i.pximg.net", 443, true, http::StatusCode::FORBIDDEN));
    assert!(!h.engine.route_rejected("i.pximg.net", TlsMode::FakeSni));
    assert!(h.engine.cached_plan("i.pximg.net", 443, true).is_some());
}

#[test]
fn a_github_403_still_rejects_the_route() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let mut plan = test_plan(TlsMode::FakeSni, None);
    plan.domain = "github.com".into();
    plan.group_id = "github".into();
    h.engine.remember_plan_arc(Arc::new(plan));

    assert!(h
        .engine
        .note_http_rejection("github.com", 443, true, http::StatusCode::FORBIDDEN));
    assert!(h.engine.cached_plan("github.com", 443, true).is_none());
    assert!(h.engine.route_rejected("github.com", TlsMode::FakeSni));
}

/// 421 is a real SNI/Host mismatch and stays a route verdict for every group,
/// including custom ones.
#[test]
fn a_misdirected_request_rejects_a_custom_group_route() {
    let h = harness(&["example.com"], RoutePolicy::auto());
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::Ech, None)));

    assert!(h.engine.note_http_rejection(
        "example.com",
        443,
        true,
        http::StatusCode::MISDIRECTED_REQUEST
    ));
    assert!(h.engine.route_rejected("example.com", TlsMode::Ech));
}

#[tokio::test]
async fn catalog_update_bypasses_cached_plan_once() {
    let harness = harness(&["example.com"], RoutePolicy::auto());
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
    let harness = harness(&["example.com"], RoutePolicy::direct());
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()]);
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

/// A TCP-level failure belongs to the address, not to the variant. The pooled
/// race prunes it through `IpGate`; the serial probe must prune it too, or
/// `doctor` spends one full `ipTimeoutMs` per configured variant on a silent
/// address before reporting the same `tcp_timeout` for each of them.
#[tokio::test]
async fn a_tcp_dead_address_is_probed_once_not_once_per_variant() {
    let harness = harness(&["example.com"], RoutePolicy::auto());
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec![ip]);
    harness.prober.dead_tcp.lock().insert(ip);

    let outcome = harness.engine.decide_https("example.com").await;

    let calls = harness.prober.calls.lock().clone();
    assert_eq!(
        calls.len(),
        1,
        "the first TCP verdict must retire the address for every variant, got {calls:?}"
    );
    assert_eq!(outcome.diagnostics.error, Some(FailureReason::TcpTimeout));
}

/// The other half of the same verdict: a stalled handshake proves the address
/// answered. Retiring it there would drop the direct fallback of a filtered
/// fake SNI, which is the whole point of the auto route.
#[tokio::test]
async fn a_stalled_handshake_keeps_the_other_variants_of_the_address() {
    let harness = harness(
        &["example.com"],
        RoutePolicy::new(vec![
            RouteAttempt::Sni {
                sni: vec!["www.bing.com".into()],
            },
            RouteAttempt::Direct,
        ]),
    );
    let ip: IpAddr = "203.0.113.8".parse().unwrap();
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec![ip]);
    harness.prober.working.lock().insert(ip);
    harness
        .prober
        .stalled_tls
        .lock()
        .push((ip, TlsMode::FakeSni));

    let outcome = harness.engine.decide_https("example.com").await;

    let plan = outcome
        .plan
        .expect("the direct fallback must still be planned");
    assert_eq!(plan.ip, ip);
    assert_eq!(plan.mode, TlsMode::Direct);
    let calls = harness.prober.calls.lock().clone();
    assert_eq!(
        calls.len(),
        2,
        "both variants of the reachable address must be dialled, got {calls:?}"
    );
    assert_eq!(calls[0].1, TlsMode::FakeSni);
    assert_eq!(calls[1].1, TlsMode::Direct);
}

#[tokio::test]
async fn doh_is_used_after_initial_candidates_fail() {
    let harness = harness(&["example.com"], RoutePolicy::direct());
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
    harness
        .prober
        .working
        .lock()
        .insert("9.9.9.9".parse().unwrap());
    harness.resolver.answers.lock().push_back(Ok(DohResolution {
        ips: vec!["9.9.9.9".parse().unwrap()],
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

/// A catalog entry may legally fill the whole candidate cap. If every one of
/// those addresses is black-holed, DoH must still get a chance: otherwise a
/// full (but stale or poisoned) catalog permanently disables the fallback.
#[tokio::test]
async fn doh_is_used_when_the_catalog_fills_the_candidate_cap() {
    let harness = harness(&["example.com"], RoutePolicy::direct());
    *harness.remote.catalog.lock() = true;
    let dead: Vec<IpAddr> = (1..=8)
        .map(|last| format!("203.0.113.{last}").parse().unwrap())
        .collect();
    *harness.remote.ips.lock() = Some(dead.clone());
    harness
        .prober
        .working
        .lock()
        .insert("9.9.9.9".parse().unwrap());
    harness.resolver.answers.lock().push_back(Ok(DohResolution {
        ips: vec!["9.9.9.9".parse().unwrap()],
        source: DohSource::Primary,
        endpoint: "primary".into(),
        stale: false,
        ttl: 60,
        fallback_used: false,
    }));

    let outcome = harness.engine.decide_https("example.com").await;
    assert_eq!(
        harness.resolver.doh_calls.load(Ordering::SeqCst),
        1,
        "the full catalog must not suppress the DoH fallback"
    );
    let plan = outcome
        .plan
        .expect("the working DoH address must be used after the catalog is exhausted");
    assert_eq!(plan.ip.to_string(), "9.9.9.9");
    assert_eq!(outcome.diagnostics.ip_source, Some(IpSource::Doh));
    assert_eq!(outcome.diagnostics.doh_source, Some(DohSource::Primary));
    let calls = harness.prober.calls.lock();
    assert_eq!(
        calls.len(),
        dead.len() + 1,
        "each catalog address must be attempted before the DoH address: {calls:?}"
    );
    assert!(
        calls[..dead.len()]
            .iter()
            .all(|(ip, _, _)| dead.contains(ip)),
        "the catalog addresses must be exhausted first: {calls:?}"
    );
    let doh_ip: IpAddr = "9.9.9.9".parse().unwrap();
    assert_eq!(calls[dead.len()].0, doh_ip);
}

/// A full catalog must not truncate a multi-address DoH answer to a single
/// fallback: if the first DoH address is also black-holed, the next one has to
/// be tried too.
#[tokio::test]
async fn every_doh_address_is_tried_after_a_full_catalog_fails() {
    let harness = harness(&["example.com"], RoutePolicy::direct());
    *harness.remote.catalog.lock() = true;
    let dead: Vec<IpAddr> = (1..=8)
        .map(|last| format!("203.0.113.{last}").parse().unwrap())
        .collect();
    *harness.remote.ips.lock() = Some(dead);
    let first_doh: IpAddr = "9.9.9.9".parse().unwrap();
    let working_doh: IpAddr = "8.8.8.8".parse().unwrap();
    harness.prober.working.lock().insert(working_doh);
    harness.resolver.answers.lock().push_back(Ok(DohResolution {
        ips: vec![first_doh, working_doh],
        source: DohSource::Primary,
        endpoint: "primary".into(),
        stale: false,
        ttl: 60,
        fallback_used: false,
    }));

    let outcome = harness.engine.decide_https("example.com").await;
    let plan = outcome.plan.expect("the second DoH address must be tried");
    assert_eq!(plan.ip, working_doh);
    let calls = harness.prober.calls.lock();
    assert_eq!(calls.len(), 10, "eight catalog + two DoH probes: {calls:?}");
    assert_eq!(calls[8].0, first_doh);
    assert_eq!(calls[9].0, working_doh);
}

/// The fallback must not depend on the configured cap or on the catalog
/// having fewer addresses than the cap. Exercise every legal combination:
/// a catalog with 0..=8 addresses and `maxCandidatesPerDomain` 1..=8.
#[tokio::test]
async fn doh_fallback_works_for_every_catalog_and_cap_combination() {
    let doh_ip: IpAddr = "9.9.9.9".parse().unwrap();
    for max in 1..=8usize {
        for catalog_len in 0..=8usize {
            let harness = harness(&["example.com"], RoutePolicy::direct());
            harness
                .engine
                .config
                .mutate(|config| {
                    config.advanced.max_candidates_per_domain = max;
                    Ok(())
                })
                .unwrap();
            *harness.remote.catalog.lock() = true;
            let dead: Vec<IpAddr> = (1..=catalog_len)
                .map(|last| format!("203.0.113.{last}").parse().unwrap())
                .collect();
            *harness.remote.ips.lock() = Some(dead);
            harness.prober.working.lock().insert(doh_ip);
            harness.resolver.answers.lock().push_back(Ok(DohResolution {
                ips: vec![doh_ip],
                source: DohSource::Primary,
                endpoint: "primary".into(),
                stale: false,
                ttl: 60,
                fallback_used: false,
            }));

            let outcome = harness.engine.decide_https("example.com").await;
            let plan = outcome.plan.unwrap_or_else(|| {
                panic!("max={max} catalog_len={catalog_len}: DoH address was not used")
            });
            assert_eq!(
                plan.ip, doh_ip,
                "max={max} catalog_len={catalog_len}: wrong winning address"
            );
            assert_eq!(
                harness.resolver.doh_calls.load(Ordering::SeqCst),
                1,
                "max={max} catalog_len={catalog_len}: DoH must be queried exactly once"
            );
            let calls = harness.prober.calls.lock();
            assert_eq!(
                calls.len(),
                catalog_len.min(max) + 1,
                "max={max} catalog_len={catalog_len}: every initial candidate and \
                 then the DoH address must be probed: {calls:?}"
            );
            assert_eq!(
                calls.last().map(|call| call.0),
                Some(doh_ip),
                "max={max} catalog_len={catalog_len}: DoH must be the last attempt"
            );
        }
    }
}

/// DoH is a fallback, not an unconditional second source: a healthy catalog
/// address must satisfy the route without a lookup, even when the list is full.
#[tokio::test]
async fn a_working_full_catalog_does_not_query_doh() {
    let harness = harness(&["example.com"], RoutePolicy::direct());
    *harness.remote.catalog.lock() = true;
    let ips: Vec<IpAddr> = (1..=8)
        .map(|last| format!("203.0.113.{last}").parse().unwrap())
        .collect();
    let working = ips[2];
    *harness.remote.ips.lock() = Some(ips.clone());
    harness.prober.working.lock().insert(working);

    let outcome = harness.engine.decide_https("example.com").await;
    assert_eq!(outcome.plan.unwrap().ip, working);
    assert_eq!(
        harness.resolver.doh_calls.load(Ordering::SeqCst),
        0,
        "a working catalog address must not trigger an unnecessary lookup"
    );
}

#[tokio::test]
async fn skip_once_prefers_new_remote_ip() {
    let harness = harness(&["example.com"], RoutePolicy::direct());
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["8.8.8.8".parse().unwrap()]);
    harness.cache.put_last_good(LastGoodEntry {
        domain: "example.com".into(),
        ip: "1.1.1.1".parse().unwrap(),
        source: IpSource::Remote,
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
async fn skip_once_is_consumed_by_the_first_planner_not_by_construction() {
    let harness = harness(&["example.com"], RoutePolicy::direct());
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["8.8.8.8".parse().unwrap()]);
    harness.cache.put_last_good(LastGoodEntry {
        domain: "example.com".into(),
        ip: "1.1.1.1".parse().unwrap(),
        source: IpSource::Remote,
        saved_at: now(),
        catalog_version: 1,
    });
    harness.cache.mark_skip_once(["example.com"]);

    let follower = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    assert!(follower.skip_once());
    assert!(
        harness.cache.has_skip_once("example.com"),
        "constructing a follower/preconnect cursor must not consume the hint"
    );
    drop(follower);

    let mut leader = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    assert!(harness.cache.has_skip_once("example.com"));
    let plan = leader.next_plan().await.expect("a remote plan");
    assert_eq!(plan.ip.to_string(), "8.8.8.8");
    assert!(
        !harness.cache.has_skip_once("example.com"),
        "the first cursor that actually plans must consume the one-shot hint"
    );
}

#[tokio::test]
async fn auto_interleaves_the_accelerated_route_after_direct() {
    // Even when direct works, the accelerated route must be the very next
    // plan so the connection race can pick the faster one.
    let harness = harness(&["example.com"], RoutePolicy::auto());
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    harness
        .prober
        .working_fake_sni
        .lock()
        .insert((ip, Some("www.bing.com".into())));
    match harness.engine.route("example.com", 443, true) {
        Route::Group(mut cursor) => {
            let first = cursor.next_plan().await.unwrap();
            assert_eq!(first.mode, TlsMode::Direct);
            let second = cursor.next_plan().await.unwrap();
            assert_eq!(second.mode, TlsMode::FakeSni);
            assert_eq!(second.ip, ip);
            assert_eq!(
                second.sni, None,
                "the global ladder starts with a ClientHello that carries no SNI"
            );
            let third = cursor.next_plan().await.unwrap();
            assert_eq!(third.sni.as_deref(), Some("example.com."));
            let fourth = cursor.next_plan().await.unwrap();
            assert_eq!(fourth.sni.as_deref(), Some("www.bing.com"));
        }
        _ => panic!("expected a group cursor"),
    }
}

#[tokio::test]
async fn auto_falls_back_to_fake_sni_and_caches_it() {
    let harness = harness(&["example.com"], RoutePolicy::auto());
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    harness
        .prober
        .working_fake_sni
        .lock()
        .insert((ip, Some("www.bing.com".into())));
    let outcome = harness.engine.decide_https("example.com").await;
    let plan = outcome.plan.expect("fake SNI should succeed");
    assert_eq!(plan.mode, TlsMode::FakeSni);
    assert_eq!(plan.sni.as_deref(), Some("www.bing.com"));
    let cached = harness
        .cache
        .sni("test", "example.com", &network_id())
        .expect("winning SNI should be cached");
    assert_eq!(cached.sni.as_deref(), Some("www.bing.com"));
}

#[tokio::test]
async fn every_configured_variant_is_planned_for_a_catalog_address() {
    // Pruning an address after a TCP failure belongs to the race gate, which
    // sees the TCP handshake while the dial is still in flight. The cursor only
    // enumerates variants: it cannot observe an attempt that has not reported
    // back yet, and the old skip-set here was always applied after the whole
    // variant list had been handed to the race. See
    // `proxy::gate::tests::a_tcp_failure_retires_the_address_and_its_queue`.
    let harness = harness(
        &["example.com"],
        RoutePolicy::new(vec![
            RouteAttempt::Sni {
                sni: vec!["www.bing.com".into(), "www.apple.com".into()],
            },
            RouteAttempt::Direct,
        ]),
    );
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let mut modes = Vec::new();
    while let Some(plan) = cursor.next_plan().await {
        modes.push(plan.mode);
    }
    assert_eq!(
        modes,
        vec![TlsMode::FakeSni, TlsMode::FakeSni, TlsMode::Direct],
        "the cursor must enumerate every variant; the gate decides what dials"
    );
}

#[tokio::test]
async fn a_timed_out_fake_sni_still_allows_the_direct_fallback() {
    // A TLS handshake can be blocked for one fake SNI while the same address
    // answers the real SNI. Marking the whole address dead after that timeout
    // skipped the configured direct fallback and reported a total failure even
    // though direct would have worked.
    let harness = harness(&["example.com"], RoutePolicy::sni(Vec::new()));
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    // Every rung of the ladder fails after TCP came up. The collected names
    // also pin the ladder: no SNI, the domain's root-dot name, then the
    // configured name.
    let mut dialled = Vec::new();
    let mut address = None;
    loop {
        let plan = cursor
            .next_plan()
            .await
            .expect("the direct fallback for the same address must still be planned");
        if plan.mode == TlsMode::Direct {
            assert_eq!(Some(plan.ip), address);
            break;
        }
        if address.is_none() {
            address = Some(plan.ip);
        }
        dialled.push(plan.sni.clone());
        cursor.note_failure(
            &plan,
            FailureReason::TlsTimeout,
            "TLS handshake with 1.1.1.1:443 timed out".into(),
        );
    }
    assert_eq!(
        dialled,
        vec![
            None,
            Some("example.com.".to_string()),
            Some("www.bing.com".to_string())
        ],
        "no SNI, then the domain's root-dot name, then the configured name"
    );
}

/// A no-SNI handshake is a learned route like any other. If `cached_plan` did
/// not accept it, every later connection would re-walk the whole ladder even
/// though the first rung already works.
#[tokio::test]
async fn a_learned_no_sni_route_is_reused_from_the_plan_cache() {
    let harness = harness(&["example.com"], RoutePolicy::sni(Vec::new()));
    *harness.remote.catalog.lock() = true;
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    *harness.remote.ips.lock() = Some(vec![ip]);
    harness
        .prober
        .working_fake_sni
        .lock()
        .insert((ip, None));

    let outcome = harness.engine.decide_https("example.com").await;
    let plan = outcome.plan.expect("the no-SNI rung must work");
    assert_eq!(plan.mode, TlsMode::FakeSni);
    assert_eq!(plan.sni, None);

    let cached = harness
        .engine
        .cached_plan("example.com", 443, true)
        .expect("a learned no-SNI route must stay in the plan cache");
    assert_eq!(cached.sni, None);
    assert_eq!(cached.ip, ip);

    // The root-dot rung is a ladder entry too, so a route that only works with
    // it must be reusable instead of re-walking the ladder every connection.
    let dotted = ConnectPlan {
        sni: Some("example.com.".to_string()),
        ..(*plan).clone()
    };
    harness.engine.remember_plan_arc(Arc::new(dotted));
    let cached = harness
        .engine
        .cached_plan("example.com", 443, true)
        .expect("the root-dot name must be accepted by the plan cache");
    assert_eq!(cached.sni.as_deref(), Some("example.com."));
}

/// A name whose certificate cannot cover the domain is wrong for that domain on
/// every address, so redialling it on the next cold connection is pure waste.
#[tokio::test]
async fn a_certificate_mismatch_retires_the_name_for_that_domain() {
    let harness = harness(
        &["example.com", "other.test"],
        RoutePolicy::sni(Vec::new()),
    );
    *harness.remote.catalog.lock() = true;
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    *harness.remote.ips.lock() = Some(vec![ip]);
    // The no-SNI handshake gets a foreign certificate.
    harness.prober.bad_cert.lock().push((ip, None));

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let first = cursor.next_plan().await.expect("a fake-SNI plan");
    assert_eq!(first.sni, None);
    cursor.note_failure(&first, FailureReason::CertInvalid, "foreign cert".into());

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let next = cursor.next_plan().await.expect("a fake-SNI plan");
    assert_eq!(
        next.sni.as_deref(),
        Some("example.com."),
        "the rejected name must not be dialled again"
    );

    // The rejection is per domain: another host keeps the full ladder.
    let mut cursor = match harness.engine.route("other.test", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let other = cursor.next_plan().await.expect("a fake-SNI plan");
    assert_eq!(other.sni, None);

    // A success (a concurrent attempt on another edge, a changed certificate)
    // puts the name back without waiting for the TTL.
    harness.engine.clear_sni_rejection("example.com", None);
    assert!(!harness.engine.sni_rejected("example.com", None));
}

/// Only a certificate mismatch is a verdict about the name. A reset or a stalled
/// handshake may be about the address, so the name keeps its turn.
#[tokio::test]
async fn a_handshake_failure_keeps_the_name_in_the_sweep() {
    let harness = harness(&["example.com"], RoutePolicy::sni(Vec::new()));
    *harness.remote.catalog.lock() = true;
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    *harness.remote.ips.lock() = Some(vec![ip]);
    harness
        .prober
        .stalled_tls
        .lock()
        .push((ip, TlsMode::FakeSni));

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let first = cursor.next_plan().await.expect("a fake-SNI plan");
    cursor.note_failure(&first, FailureReason::TlsTimeout, "handshake stalled".into());

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let next = cursor.next_plan().await.expect("a fake-SNI plan");
    assert_eq!(next.sni, None, "a stalled handshake must not retire the name");
}

/// A long configured list is not a longer sweep: three names is the budget.
#[tokio::test]
async fn the_sni_sweep_stops_at_three_names() {
    let route = RoutePolicy::sni(vec![
        "a.example".into(),
        "b.example".into(),
        "c.example".into(),
        "d.example".into(),
    ]);
    let harness = harness(&["example.com"], route);
    *harness.remote.catalog.lock() = true;
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    *harness.remote.ips.lock() = Some(vec![ip]);
    harness.prober.bad_cert.lock().push((ip, None));

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let mut dialled = Vec::new();
    while let Some(plan) = cursor.next_plan().await {
        if plan.mode != TlsMode::FakeSni {
            break;
        }
        dialled.push(plan.sni.clone().unwrap_or_default());
    }
    assert_eq!(dialled, vec!["a.example", "b.example", "c.example"]);
}

/// An explicit list is dialled exactly as written, including an empty entry
/// first. The old code sorted "no SNI" to the end, which silently reversed the
/// order the user configured.
#[tokio::test]
async fn an_explicit_sni_list_keeps_the_written_order() {
    let route = RoutePolicy::sni(vec![
        String::new(),
        "example.com.".into(),
        "www.bing.com".into(),
    ]);
    let harness = harness(&["example.com"], route);
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let first = cursor.next_plan().await.expect("a fake-SNI plan");
    assert_eq!(first.sni, None);
    let second = cursor.next_plan().await.expect("a fake-SNI plan");
    assert_eq!(second.sni.as_deref(), Some("example.com."));
}

/// A rejected name is out only for the TTL: a changed certificate or a new CDN
/// edge must recover without restarting the app.
#[tokio::test]
async fn a_rejected_sni_name_returns_after_the_ttl() {
    let harness = harness(&["example.com"], RoutePolicy::sni(Vec::new()));
    *harness.remote.catalog.lock() = true;
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    *harness.remote.ips.lock() = Some(vec![ip]);
    harness.prober.bad_cert.lock().push((ip, None));

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let first = cursor.next_plan().await.expect("a fake-SNI plan");
    cursor.note_failure(&first, FailureReason::CertInvalid, "foreign cert".into());
    assert!(harness.engine.sni_rejected("example.com", None));

    {
        let mut rejected = harness.engine.sni_rejections.write();
        for by_name in rejected.values_mut() {
            for at in by_name.values_mut() {
                *at = Instant::now()
                    - super::engine::SNI_REJECTION_TTL
                    - Duration::from_secs(1);
            }
        }
    }
    assert!(
        !harness.engine.sni_rejected("example.com", None),
        "the rejection must expire on its own"
    );

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let next = cursor.next_plan().await.expect("a fake-SNI plan");
    assert_eq!(next.sni, None, "the name is dialled again after the TTL");
}

/// Learning belongs to the network it was made on: a different path may behave
/// completely differently, so the whole table is forgotten.
#[tokio::test]
async fn a_network_change_forgets_rejected_sni_names() {
    let harness = harness(&["example.com"], RoutePolicy::sni(Vec::new()));
    harness
        .engine
        .note_sni_rejection("example.com", Some("www.bing.com".into()));
    assert!(harness.engine.sni_rejected("example.com", Some("www.bing.com")));

    harness.engine.on_network_change();
    assert!(!harness.engine.sni_rejected("example.com", Some("www.bing.com")));
}

/// When every name is out, the route has no fake-SNI attempt left: it must fall
/// straight through to the next configured mode instead of dialling nothing.
#[tokio::test]
async fn a_fully_rejected_sweep_plans_no_fake_sni_attempt() {
    let harness = harness(
        &["example.com"],
        RoutePolicy::sni(vec!["www.bing.com".into()]),
    );
    *harness.remote.catalog.lock() = true;
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    *harness.remote.ips.lock() = Some(vec![ip]);
    harness
        .prober
        .bad_cert
        .lock()
        .push((ip, Some("www.bing.com".into())));

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let first = cursor.next_plan().await.expect("a fake-SNI plan");
    assert_eq!(first.mode, TlsMode::FakeSni);
    cursor.note_failure(&first, FailureReason::CertInvalid, "foreign cert".into());

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let next = cursor.next_plan().await.expect("the direct fallback");
    assert_eq!(
        next.mode,
        TlsMode::Direct,
        "an empty sweep must be skipped, not planned"
    );
}

/// The cap drops configured names from the tail, never the name this network
/// already proved.
#[tokio::test]
async fn the_cap_keeps_the_learned_name() {
    let route = RoutePolicy::sni(vec![
        "a.example".into(),
        "b.example".into(),
        "c.example".into(),
        "d.example".into(),
    ]);
    let harness = harness(&["example.com"], route);
    *harness.remote.catalog.lock() = true;
    *harness.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
    harness.cache.put_sni(crate::cache::CachedSni {
        group: "test".into(),
        domain: "example.com".into(),
        network_id: network_id(),
        sni: Some("d.example".into()),
        saved_at: now(),
    });

    let mut cursor = match harness.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group cursor"),
    };
    let mut dialled = Vec::new();
    while let Some(plan) = cursor.next_plan().await {
        if plan.mode != TlsMode::FakeSni {
            break;
        }
        dialled.push(plan.sni.unwrap_or_default());
    }
    assert_eq!(
        dialled,
        vec!["d.example", "a.example", "b.example"],
        "the learned name leads and the tail is what the cap drops"
    );
}

/// A rejection says "do not spend another handshake", not "throw the proven
/// route away": the cached plan points at an address that already answered.
#[tokio::test]
async fn a_rejection_keeps_the_learned_plan() {
    let harness = harness(&["example.com"], RoutePolicy::sni(Vec::new()));
    *harness.remote.catalog.lock() = true;
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    *harness.remote.ips.lock() = Some(vec![ip]);
    harness.prober.working_fake_sni.lock().insert((ip, None));

    let outcome = harness.engine.decide_https("example.com").await;
    assert!(outcome.plan.is_some());
    assert!(harness.engine.cached_plan("example.com", 443, true).is_some());

    harness.engine.note_sni_rejection("example.com", None);
    assert!(
        harness.engine.cached_plan("example.com", 443, true).is_some(),
        "the proven route must survive a rejection recorded elsewhere"
    );
}

/// A direct handshake that fails certificate validation says nothing about the
/// no-SNI rung, even though both have `sni = None`.
#[tokio::test]
async fn a_direct_certificate_failure_does_not_reject_the_no_sni_rung() {
    let harness = harness(&["example.com"], RoutePolicy::direct());
    *harness.remote.catalog.lock() = true;
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    *harness.remote.ips.lock() = Some(vec![ip]);
    harness.prober.bad_cert.lock().push((ip, None));

    let outcome = harness.engine.decide_https("example.com").await;
    assert_eq!(outcome.diagnostics.error, Some(FailureReason::CertInvalid));
    assert!(
        !harness.engine.sni_rejected("example.com", None),
        "only a fake-SNI attempt may reject a name"
    );
}

#[tokio::test]
async fn failure_returns_reasons_and_attempts() {
    let harness = harness(&["example.com"], RoutePolicy::direct());
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

/// The routing path of a new connection: match the group, read the route
/// hints and build the candidate list.
#[test]
#[ignore = "micro benchmark"]
fn bench_route_decision() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    *h.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
    crate::bench::measure("decision.route", 20_000, || {
        let _ = h.engine.route("example.com", 443, true);
    });
}

/// The plan cache lookup of a new connection.
#[test]
#[ignore = "micro benchmark"]
fn bench_plan_cache_lookup() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::Direct, None)));
    crate::bench::measure("decision.cached_plan", 100_000, || {
        let _ = h.engine.cached_plan("example.com", 443, true);
    });
}

/// A total failure must be published only after the racing attempts reported
/// back.
///
/// The plan list runs out long before the in-flight connections do. Publishing
/// the failure at that moment computed the aggregate reason from an empty
/// attempt history, so every real timeout was reported as "no candidate
/// address was available" and the attempt trace stayed empty.
#[tokio::test]
async fn a_failure_is_published_only_after_the_attempts_reported_back() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    *h.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);

    let mut cursor = match h.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let plan = cursor.next_plan().await.expect("a direct plan");

    // The plan list is exhausted while the connection is still in flight.
    assert!(
        cursor.next_plan().await.is_none(),
        "the cursor must run out of plans"
    );
    let published = h
        .engine
        .status
        .get("example.com")
        .expect("the cursor publishes a checking state");
    assert!(
        published.error.is_none(),
        "an exhausted plan list must not publish a failure: the attempts that \
         explain it have not reported back yet, so the reason would be a guess \
         (got {:?})",
        published.error
    );

    // Now the connection fails.
    cursor.note_failure(&plan, FailureReason::TcpTimeout, "timed out".into());

    let outcome = cursor.outcome().expect("a failure outcome");
    assert_eq!(
        outcome.diagnostics.error,
        Some(FailureReason::TcpTimeout),
        "the published reason must be the real one, not a guess made before \
         the attempts reported back"
    );
    assert_eq!(
        outcome.diagnostics.attempts.len(),
        1,
        "the attempt trace must reach the diagnostics: {:?}",
        outcome.diagnostics.attempts
    );
    assert_eq!(outcome.diagnostics.attempts[0].ip, plan.ip);
    assert_eq!(
        outcome.diagnostics.attempts[0].error,
        Some(FailureReason::TcpTimeout)
    );
}

/// The same rule applies to the pool and raw races: the reason must be the
/// error of the attempt that actually failed, never "no candidate".
#[tokio::test]
async fn an_exhausted_cursor_reports_the_last_attempt_error() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    let addresses: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()];
    *h.remote.ips.lock() = Some(addresses.clone());

    let mut cursor = match h.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let mut plans = Vec::new();
    while let Some(plan) = cursor.next_plan().await {
        plans.push(plan);
    }
    assert_eq!(plans.len(), addresses.len());
    for plan in &plans {
        cursor.note_failure(plan, FailureReason::TcpTimeout, "timed out".into());
    }

    let outcome = cursor.outcome().expect("a failure outcome");
    assert_eq!(outcome.diagnostics.error, Some(FailureReason::TcpTimeout));
    assert_eq!(
        outcome.diagnostics.attempts.len(),
        addresses.len(),
        "every candidate that was tried must appear in the trace"
    );
    for address in &addresses {
        assert!(
            outcome
                .diagnostics
                .attempts
                .iter()
                .any(|attempt| attempt.ip == *address),
            "the trace must name {address}: {:?}",
            outcome.diagnostics.attempts
        );
    }
}

/// A group with the maximum practical rule count stresses the per-cold-connection
/// route lookup. This is a benchmark only; run it with `--ignored`.
#[test]
#[ignore = "micro benchmark"]
fn bench_wide_group_route() {
    let domains: Vec<String> = (0..511)
        .map(|index| format!("host{index}.example.com"))
        .chain(std::iter::once("last.example.com".to_string()))
        .collect();
    let refs: Vec<&str> = domains.iter().map(String::as_str).collect();
    let h = harness(&refs, RoutePolicy::sni(Vec::new()));
    *h.remote.catalog.lock() = true;
    *h.remote.ips.lock() = Some(vec!["1.1.1.1".parse().unwrap()]);
    let group = h.engine.config.snapshot().group("test").unwrap().clone();
    crate::bench::measure("decision.route.wide", 20_000, || {
        let _ = h.engine.route("last.example.com", 443, true);
    });
    crate::bench::measure("group.route_modes.wide", 200_000, || {
        let _ = group.route_modes("last.example.com");
    });
}

/// The cached-plan validation also resolves the per-domain route; a wide group
/// makes the difference between an index lookup and a linear rule scan visible.
#[test]
#[ignore = "micro benchmark"]
fn bench_wide_group_plan_cache_lookup() {
    let domains: Vec<String> = (0..511)
        .map(|index| format!("host{index}.example.com"))
        .chain(std::iter::once("last.example.com".to_string()))
        .collect();
    let refs: Vec<&str> = domains.iter().map(String::as_str).collect();
    let h = harness(&refs, RoutePolicy::sni(Vec::new()));
    let mut plan = test_plan(TlsMode::Direct, None);
    plan.domain = "last.example.com".into();
    h.engine.remember_plan_arc(Arc::new(plan));
    crate::bench::measure("decision.cached_plan.wide", 100_000, || {
        let _ = h.engine.cached_plan("last.example.com", 443, true);
    });
}

/// Regression test (audit finding 5, fixed): a route-level rejection retires
/// the route only and never records an IP failure. A masked-SNI request
/// rejected by the origin says something about the name, not the address — the
/// same policy as note_blocked_candidate. The old behavior pulled the healthy
/// IP's ewma toward 10s and degraded its direct-mode ranking.
///
/// GitHub is the only group where a 403 is a route verdict, so it is the only
/// one that can exercise this path now.
#[tokio::test]
async fn route_level_403_keeps_the_ip_unpunished() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    let mut plan = test_plan(TlsMode::FakeSni, None);
    plan.domain = "api.github.com".into();
    plan.group_id = "github".into();
    h.engine.remember_plan_arc(Arc::new(plan));

    assert!(h
        .engine
        .note_http_rejection("api.github.com", 443, true, http::StatusCode::FORBIDDEN));

    assert!(
        h.engine.cached_plan("api.github.com", 443, true).is_none(),
        "the rejected route is forgotten"
    );
    assert!(
        h.engine.route_rejected("api.github.com", TlsMode::FakeSni),
        "the mode is still retired"
    );
    let scores = h.engine.ip_scores.read();
    assert!(
        scores
            .get("api.github.com")
            .and_then(|by_ip| by_ip.get(&ip))
            .is_none(),
        "a route-level rejection must not write a failure record for the address"
    );
}

/// Regression test (audit finding 6, fixed): note_http_rejection looks the
/// plan up by (host, port, tls). When connection B overwrote the plan cache,
/// connection A's 403 used to penalize the innocent IP2. After the fix a
/// route-level rejection has no per-IP side effects at all, so neither IP is
/// touched no matter which plan the cache returns.
#[tokio::test]
async fn plan_cache_overwrite_does_not_penalize_either_ip() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let real_offender: IpAddr = "203.0.113.50".parse().unwrap();
    let innocent: IpAddr = "203.0.113.51".parse().unwrap();

    let mut plan = test_plan(TlsMode::FakeSni, None);
    plan.domain = "api.github.com".into();
    plan.group_id = "github".into();
    plan.ip = real_offender;
    h.engine.remember_plan_arc(Arc::new(plan));

    // Connection B succeeds with a different ip and overwrites the plan cache.
    let mut other = test_plan(TlsMode::FakeSni, None);
    other.domain = "api.github.com".into();
    other.group_id = "github".into();
    other.ip = innocent;
    h.engine.remember_plan_arc(Arc::new(other));

    // Connection A's 403 arrives now. GitHub is the only group where that is
    // still a route-level rejection.
    assert!(h
        .engine
        .note_http_rejection("api.github.com", 443, true, http::StatusCode::FORBIDDEN));

    let scores = h.engine.ip_scores.read();
    assert!(
        scores.get("api.github.com").is_none(),
        "no ip may gain a failure record from a route-level rejection"
    );
}

/// The recheck exists for one case the scores cannot see: a pooled connection
/// never reports another handshake, so a route that is live but slower than an
/// alternative would stay chosen forever. Two confirmations are required so a
/// single lucky sample cannot move a healthy route.
#[tokio::test]
async fn a_confirmed_faster_candidate_retires_the_live_route() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let slow: IpAddr = "203.0.113.10".parse().unwrap();
    let fast: IpAddr = "203.0.113.11".parse().unwrap();
    h.remote.ips.lock().replace(vec![slow, fast]);
    h.prober.working.lock().extend([slow, fast]);
    h.prober.latencies.lock().insert(slow, 500);
    h.prober.latencies.lock().insert(fast, 100);

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = slow;
    h.engine.record_quality(&Arc::new(plan));

    assert!(
        h.engine.recheck_routes(4).await.is_empty(),
        "a route checked at connect time is not due yet"
    );

    h.engine.grant_recheck_budget();
    h.engine
        .backdate_quality("example.com", Duration::from_secs(600));
    assert!(
        h.engine.recheck_routes(4).await.is_empty(),
        "one sample must not move the route"
    );

    h.engine.grant_recheck_budget();
    h.engine
        .backdate_quality("example.com", Duration::from_secs(600));
    let retired = h.engine.recheck_routes(4).await;
    assert_eq!(
        retired.len(),
        1,
        "the second confirmation must retire the route"
    );
    assert_eq!(
        retired[0].ip, slow,
        "the live route is the one that has to go, not the challenger"
    );
}

#[tokio::test]
async fn a_slower_candidate_never_moves_the_route() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let live: IpAddr = "203.0.113.10".parse().unwrap();
    let slower: IpAddr = "203.0.113.11".parse().unwrap();
    h.remote.ips.lock().replace(vec![live, slower]);
    h.prober.working.lock().extend([live, slower]);
    h.prober.latencies.lock().insert(live, 100);
    h.prober.latencies.lock().insert(slower, 500);

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = live;
    h.engine.record_quality(&Arc::new(plan));

    for _ in 0..4 {
        h.engine.grant_recheck_budget();
        h.engine
            .backdate_quality("example.com", Duration::from_secs(600));
        assert!(
            h.engine.recheck_routes(4).await.is_empty(),
            "a challenger that loses must reset the streak"
        );
    }
}

/// A probe that cannot complete says nothing about the alternative. Treating
/// it as a win would move the route on every network hiccup.
#[tokio::test]
async fn a_failed_challenger_probe_never_moves_the_route() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let live: IpAddr = "203.0.113.10".parse().unwrap();
    let broken: IpAddr = "203.0.113.11".parse().unwrap();
    h.remote.ips.lock().replace(vec![live, broken]);
    h.prober.working.lock().insert(live);

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = live;
    h.engine.record_quality(&Arc::new(plan));

    for _ in 0..4 {
        h.engine.grant_recheck_budget();
        h.engine
            .backdate_quality("example.com", Duration::from_secs(600));
        assert!(h.engine.recheck_routes(4).await.is_empty());
    }
}

/// Without an alternative there is nothing to compare, and the check must not
/// spend a handshake on the route it already knows.
#[tokio::test]
async fn a_single_candidate_is_not_probed() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let only: IpAddr = "203.0.113.10".parse().unwrap();
    h.remote.ips.lock().replace(vec![only]);
    h.prober.working.lock().insert(only);

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = only;
    h.engine.record_quality(&Arc::new(plan));

    h.engine.grant_recheck_budget();
    h.engine
        .backdate_quality("example.com", Duration::from_secs(600));
    assert!(h.engine.recheck_routes(4).await.is_empty());
    assert!(
        h.prober.calls.lock().is_empty(),
        "no alternative means no probe"
    );
}

/// The probe budget must go to domains that are actually in use. A domain
/// with no successful connection for the active window is skipped entirely.
#[tokio::test]
async fn an_idle_domain_is_not_rechecked() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let live: IpAddr = "203.0.113.10".parse().unwrap();
    let faster: IpAddr = "203.0.113.11".parse().unwrap();
    h.remote.ips.lock().replace(vec![live, faster]);
    h.prober.working.lock().extend([live, faster]);
    h.prober.latencies.lock().insert(live, 500);
    h.prober.latencies.lock().insert(faster, 100);

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = live;
    h.engine.record_quality(&Arc::new(plan));

    h.engine.grant_recheck_budget();
    h.engine
        .backdate_quality("example.com", Duration::from_secs(600));
    h.engine
        .backdate_quality_seen("example.com", Duration::from_secs(3600));
    assert!(h.engine.recheck_routes(4).await.is_empty());
    assert!(
        h.prober.calls.lock().is_empty(),
        "an idle domain must not spend the probe budget"
    );
}

/// The budget is what keeps the background task cheap: with one token only a
/// single pair of probes may run, even when several domains are due.
#[tokio::test]
async fn the_probe_budget_caps_checks_per_window() {
    let h = harness(&["example.com", "second.test"], RoutePolicy::direct());
    let live: IpAddr = "203.0.113.10".parse().unwrap();
    let rival: IpAddr = "203.0.113.11".parse().unwrap();
    h.remote.ips.lock().replace(vec![live, rival]);
    h.prober.working.lock().extend([live, rival]);
    h.prober.latencies.lock().insert(live, 500);
    h.prober.latencies.lock().insert(rival, 100);

    for domain in ["example.com", "second.test"] {
        let mut plan = test_plan(TlsMode::Direct, None);
        plan.domain = domain.into();
        plan.ip = live;
        h.engine.record_quality(&Arc::new(plan));
        h.engine.backdate_quality(domain, Duration::from_secs(600));
    }

    h.engine.set_recheck_tokens(1.0);
    assert!(h.engine.recheck_routes(4).await.is_empty());
    assert_eq!(
        h.prober.calls.lock().len(),
        2,
        "one token must allow exactly one live-route plus one challenger probe"
    );
}

/// A plaintext plan has no TLS handshake to compare, so it must not take a
/// slot in the table nor spend the budget.
#[tokio::test]
async fn plaintext_plans_are_not_rechecked() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    h.remote
        .ips
        .lock()
        .replace(vec!["203.0.113.11".parse().unwrap()]);

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = "203.0.113.10".parse().unwrap();
    plan.tls = false;
    h.engine.record_quality(&Arc::new(plan));

    h.engine.grant_recheck_budget();
    h.engine
        .backdate_quality("example.com", Duration::from_secs(600));
    assert!(h.engine.recheck_routes(4).await.is_empty());
    assert!(h.prober.calls.lock().is_empty());
}

/// A rival that never answers must not become the permanent challenger. It
/// outranks the healthy alternative only because the recheck never recorded
/// its failure, so every check redials the dead address and the route is
/// never moved to the candidate that actually works.
#[tokio::test]
async fn a_dead_challenger_must_not_block_the_recheck_forever() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let live: IpAddr = "203.0.113.10".parse().unwrap();
    let dead: IpAddr = "203.0.113.11".parse().unwrap();
    let better: IpAddr = "203.0.113.12".parse().unwrap();
    h.remote.ips.lock().replace(vec![live, dead, better]);
    h.prober.working.lock().extend([live, better]);
    h.prober.latencies.lock().insert(live, 500);
    h.prober.latencies.lock().insert(better, 100);

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = live;
    h.engine.record_quality(&Arc::new(plan));

    let mut retired = Vec::new();
    for _ in 0..4 {
        h.engine.grant_recheck_budget();
        h.engine
            .backdate_quality("example.com", Duration::from_secs(600));
        retired = h.engine.recheck_routes(4).await;
        if !retired.is_empty() {
            break;
        }
    }

    assert!(
        h.prober.calls.lock().iter().any(|(ip, _, _)| *ip == better),
        "the healthy alternative must be tried once the dead rival fails"
    );
    assert_eq!(retired.len(), 1, "the faster candidate must eventually win");
}

/// Routes measured on the old network are not evidence for the new one. The
/// plans are dropped on a network change, so their quality entries have to go
/// too; otherwise the recheck spends probes on plans that are no longer live.
#[tokio::test]
async fn a_network_change_forgets_the_live_route_quality() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    h.remote
        .ips
        .lock()
        .replace(vec!["203.0.113.11".parse().unwrap()]);

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = "203.0.113.10".parse().unwrap();
    h.engine.record_quality(&Arc::new(plan));
    assert_eq!(h.engine.quality_len(), 1);

    h.engine.on_network_change();
    assert_eq!(
        h.engine.quality_len(),
        0,
        "a network change must drop the routes measured on the old one"
    );
}

/// The probes take time, and a new connection can move the route while they
/// are in flight. The verdict then belongs to a plan that is no longer live:
/// acting on it would drop the healthy replacement and force a pointless race.
#[tokio::test]
async fn a_verdict_for_a_replaced_plan_is_discarded() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let old: IpAddr = "203.0.113.10".parse().unwrap();
    let new: IpAddr = "203.0.113.11".parse().unwrap();
    let rival: IpAddr = "203.0.113.12".parse().unwrap();

    let mut plan_old = test_plan(TlsMode::Direct, None);
    plan_old.ip = old;
    let mut plan_new = test_plan(TlsMode::Direct, None);
    plan_new.ip = new;

    h.engine.record_quality(&Arc::new(plan_old.clone()));
    // A connection succeeded on the new address while the probes were running.
    h.engine.record_quality(&Arc::new(plan_new.clone()));

    assert!(
        !h.engine
            .record_challenge("example.com", &plan_old, rival, Some(true)),
        "a verdict for the replaced plan must not retire anything"
    );
    assert!(
        !h.engine
            .record_challenge("example.com", &plan_new, rival, Some(true)),
        "the discarded verdict must not count as the new plan's first confirmation"
    );
}

/// Two confirmations must compare the same pair of addresses. A rank shift
/// between checks would otherwise swap the challenger and reset the streak, so
/// a clearly faster candidate could never accumulate the second win.
#[tokio::test]
async fn the_same_challenger_is_kept_across_checks() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let live: IpAddr = "203.0.113.10".parse().unwrap();
    let first: IpAddr = "203.0.113.11".parse().unwrap();
    let other: IpAddr = "203.0.113.12".parse().unwrap();
    h.remote.ips.lock().replace(vec![live, first, other]);
    h.prober.working.lock().extend([live, first, other]);
    h.prober.latencies.lock().insert(live, 500);
    h.prober.latencies.lock().insert(first, 120);
    h.prober.latencies.lock().insert(other, 110);

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = live;
    h.engine.record_quality(&Arc::new(plan));

    h.engine.grant_recheck_budget();
    h.engine
        .backdate_quality("example.com", Duration::from_secs(600));
    assert!(h.engine.recheck_routes(4).await.is_empty());

    // A connection made the other candidate outrank the first challenger.
    h.engine.record_ip("example.com", other, Some(50), false);

    h.engine.grant_recheck_budget();
    h.engine
        .backdate_quality("example.com", Duration::from_secs(600));
    let retired = h.engine.recheck_routes(4).await;
    assert_eq!(
        retired.len(),
        1,
        "the second confirmation must stay on the first challenger"
    );
    assert_eq!(retired[0].ip, live);
}

/// A dead challenger must not be carried over, or a single failing address
/// would keep the streak while never beating the live route.
#[tokio::test]
async fn a_failed_challenger_is_not_preferred_again() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let live: IpAddr = "203.0.113.10".parse().unwrap();
    let dead: IpAddr = "203.0.113.11".parse().unwrap();
    let better: IpAddr = "203.0.113.12".parse().unwrap();
    h.remote.ips.lock().replace(vec![live, dead, better]);
    h.prober.working.lock().extend([live, better]);
    h.prober.latencies.lock().insert(live, 500);
    h.prober.latencies.lock().insert(better, 100);

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = live;
    h.engine.record_quality(&Arc::new(plan.clone()));

    // The previous check settled on the dead address and left a failure
    // record behind. Keeping it as the preferred challenger would redial it
    // forever and never reach the healthy candidate.
    assert!(!h
        .engine
        .record_challenge("example.com", &plan, dead, Some(true)));
    h.engine.record_ip("example.com", dead, None, true);

    h.engine.grant_recheck_budget();
    h.engine
        .backdate_quality("example.com", Duration::from_secs(600));
    h.engine.recheck_routes(4).await;
    assert!(
        h.prober.calls.lock().iter().any(|(ip, _, _)| *ip == better),
        "a challenger with a failure record must not be preferred"
    );
}

/// Addresses that only come from DoH still deserve an opponent; the cached
/// answer costs nothing to read.
#[tokio::test]
async fn a_doh_only_domain_still_gets_an_opponent() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    let live: IpAddr = "203.0.113.10".parse().unwrap();
    let doh: IpAddr = "203.0.113.12".parse().unwrap();
    h.prober.working.lock().extend([live, doh]);
    h.prober.latencies.lock().insert(live, 500);
    h.prober.latencies.lock().insert(doh, 100);
    h.cache.put_doh_answer(crate::cache::CachedAnswer {
        domain: "example.com".into(),
        qtype: 1,
        ips: vec![doh],
        ech_config: None,
        ttl_secs: 300,
        fetched_at: now(),
    });

    let mut plan = test_plan(TlsMode::Direct, None);
    plan.ip = live;
    h.engine.record_quality(&Arc::new(plan));

    let mut retired = Vec::new();
    for _ in 0..3 {
        h.engine.grant_recheck_budget();
        h.engine
            .backdate_quality("example.com", Duration::from_secs(600));
        retired = h.engine.recheck_routes(4).await;
        if !retired.is_empty() {
            break;
        }
    }
    assert_eq!(
        retired.len(),
        1,
        "a DoH-only candidate must be usable as the challenger"
    );
}

/// The default candidate order: the remembered `last_good` address leads, the
/// catalog follows. Neither address has a score on a fresh start, so the
/// insertion order is what the operator observes in the failure trace.
#[tokio::test]
async fn default_order_tries_the_last_good_cache_before_the_catalog() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    let cache_ip: IpAddr = "1.1.1.1".parse().unwrap();
    let remote_ip: IpAddr = "8.8.8.8".parse().unwrap();
    *h.remote.ips.lock() = Some(vec![remote_ip]);
    h.cache.put_last_good(LastGoodEntry {
        domain: "example.com".into(),
        ip: cache_ip,
        source: IpSource::Cache,
        saved_at: now(),
        catalog_version: 0,
    });

    let mut cursor = match h.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let first = cursor.next_plan().await.expect("the cache plan");
    assert_eq!(
        (first.ip, first.source),
        (cache_ip, IpSource::Cache),
        "the last-good cache must be tried before the catalog"
    );
    let second = cursor.next_plan().await.expect("the catalog plan");
    assert_eq!(
        (second.ip, second.source),
        (remote_ip, IpSource::Remote),
        "the catalog address follows the cached one"
    );
    assert!(
        cursor.next_plan().await.is_none(),
        "only the cache and the catalog address exist before the DoH expansion"
    );
}

/// A remembered route older than `last_good_days` is a hint that expired: it
/// must not become a candidate, while the catalog still does.
#[tokio::test]
async fn an_expired_last_good_is_not_a_candidate() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    let stale_ip: IpAddr = "1.1.1.1".parse().unwrap();
    let remote_ip: IpAddr = "8.8.8.8".parse().unwrap();
    *h.remote.ips.lock() = Some(vec![remote_ip]);
    // Saved eight days ago; the default `last_good_days` is seven.
    h.cache.put_last_good(LastGoodEntry {
        domain: "example.com".into(),
        ip: stale_ip,
        source: IpSource::Remote,
        saved_at: now() - chrono::Duration::days(8),
        catalog_version: 0,
    });
    assert!(
        h.cache.route_hints("example.com", 7).1.is_none(),
        "the routes file itself must report the entry as expired"
    );

    let mut cursor = match h.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let first = cursor
        .next_plan()
        .await
        .expect("the catalog address must still be planned");
    assert_eq!(
        (first.ip, first.source),
        (remote_ip, IpSource::Remote),
        "an expired last-good address must not be dialled"
    );
    assert!(
        cursor.next_plan().await.is_none(),
        "the expired cache entry must not reappear as a candidate"
    );
}

/// `ip_rejected` is the same verdict for every source: a black-listed address
/// is out whether the cache, the catalog or DoH offered it.
#[tokio::test]
async fn rejected_addresses_are_filtered_from_every_candidate_source() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    let rejected_cache: IpAddr = "1.1.1.1".parse().unwrap();
    let rejected_remote: IpAddr = "8.8.8.8".parse().unwrap();
    let live_remote: IpAddr = "9.9.9.9".parse().unwrap();
    let rejected_doh: IpAddr = "7.7.7.7".parse().unwrap();
    let live_doh: IpAddr = "6.6.6.6".parse().unwrap();
    *h.remote.ips.lock() = Some(vec![rejected_remote, live_remote]);
    h.cache.put_last_good(LastGoodEntry {
        domain: "example.com".into(),
        ip: rejected_cache,
        source: IpSource::Cache,
        saved_at: now(),
        catalog_version: 0,
    });
    h.resolver.answers.lock().push_back(Ok(DohResolution {
        ips: vec![rejected_doh, live_doh],
        source: DohSource::Primary,
        endpoint: "primary".into(),
        stale: false,
        ttl: 60,
        fallback_used: false,
    }));
    for ip in [rejected_cache, rejected_remote, rejected_doh] {
        h.engine
            .ip_rejections
            .write()
            .entry("example.com".into())
            .or_default()
            .insert(ip, Instant::now());
    }

    let mut cursor = match h.engine.route("example.com", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    let mut seen: Vec<(IpAddr, IpSource)> = Vec::new();
    while let Some(plan) = cursor.next_plan().await {
        seen.push((plan.ip, plan.source));
    }
    assert_eq!(
        seen,
        vec![(live_remote, IpSource::Remote), (live_doh, IpSource::Doh)],
        "a rejected address must be filtered from the cache, the catalog and DoH alike"
    );
}

/// A stale (past-TTL but still usable) DoH answer is a last resort, and the
/// diagnostics have to say so: `ip_source` is `doh-cache`, not `doh`.
#[tokio::test]
async fn a_stale_doh_answer_is_labelled_doh_cache() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    let dead: IpAddr = "1.1.1.1".parse().unwrap();
    *h.remote.ips.lock() = Some(vec![dead]);
    let stale_ip: IpAddr = "9.9.9.9".parse().unwrap();
    h.prober.working.lock().insert(stale_ip);
    h.resolver.answers.lock().push_back(Ok(DohResolution {
        ips: vec![stale_ip],
        source: DohSource::Primary,
        endpoint: "primary".into(),
        stale: true,
        ttl: 0,
        fallback_used: false,
    }));

    let outcome = h.engine.decide_https("example.com").await;
    let plan = outcome
        .plan
        .expect("the stale DoH address must still be usable");
    assert_eq!(plan.ip, stale_ip);
    assert_eq!(
        plan.source,
        IpSource::DohCache,
        "a stale answer must be labelled doh-cache"
    );
    assert_eq!(outcome.diagnostics.ip_source, Some(IpSource::DohCache));
    assert_eq!(outcome.diagnostics.cache, CacheStatus::Stale);
    assert_eq!(outcome.diagnostics.doh_source, Some(DohSource::Primary));
}

/// After a catalog update the new remote addresses lead even when the cached
/// route has the better measured score: the score of a remote candidate is
/// forced to zero for that one connection, otherwise the proven (but possibly
/// outdated) cache entry would sort ahead of the address the update wants
/// tried first.
#[tokio::test]
async fn skip_once_forces_the_catalog_ahead_of_a_proven_cache_route() {
    let h = harness(&["example.com"], RoutePolicy::direct());
    *h.remote.catalog.lock() = true;
    let cache_ip: IpAddr = "1.1.1.1".parse().unwrap();
    let remote_ip: IpAddr = "8.8.8.8".parse().unwrap();
    *h.remote.ips.lock() = Some(vec![remote_ip]);
    // The cached route is proven fast on this network; the new catalog
    // address has never been measured.
    h.engine.record_ip("example.com", cache_ip, Some(50), false);
    h.cache.put_last_good(LastGoodEntry {
        domain: "example.com".into(),
        ip: cache_ip,
        source: IpSource::Remote,
        saved_at: now(),
        catalog_version: 1,
    });
    h.cache.mark_skip_once(["example.com"]);
    h.prober.working.lock().insert(cache_ip);
    h.prober.working.lock().insert(remote_ip);

    let outcome = h.engine.decide_https("example.com").await;
    assert_eq!(
        outcome.plan.expect("one of the two addresses must win").ip,
        remote_ip,
        "the catalog address must lead while the skip-once hint is set, \
         even though the cached route has the better score"
    );
}
