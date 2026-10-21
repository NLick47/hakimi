use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::cache::{CacheManager, LastGoodEntry};
use crate::catalog::RemoteIpProvider;
use crate::config::{ConfigManager, GroupConfig};
use crate::ip_tester::{ConnectError, ProbeSuccess};
use crate::paths::Paths;
use crate::resolver::{DohResolution, EchOutcome, IpResolver};
use crate::status::{State, StatusStore};
use crate::strategy::{DohSource, FailureReason, IpSource, Strategy, TlsMode};
use crate::util::{network_id, now};
use anyhow::Result;

use super::engine::PLAN_CACHE_MAX;
use super::*;

#[derive(Default)]
struct FakeRemote {
    ips: Mutex<Option<Vec<IpAddr>>>,
    sni: Mutex<Option<String>>,
    catalog: Mutex<bool>,
}

impl RemoteIpProvider for FakeRemote {
    fn remote_ips(&self, _domain: &str) -> Option<Vec<IpAddr>> {
        self.ips.lock().clone()
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
            homepage: None,
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

/// The fake-SNI sweep is candidate-major: every candidate IP must get the
/// full SNI list. Previously `sni_index` was never reset when the cursor
/// advanced to the next candidate, so only the first IP was ever tried.
#[tokio::test]
async fn fake_sni_sweep_restarts_for_each_candidate() {
    let harness = harness(&["example.com"], Strategy::FakeSni);
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
    }
}

#[test]
fn plan_cache_stays_bounded_when_every_entry_is_fresh() {
    let h = harness(&["example.com"], Strategy::Direct);
    for i in 0..(PLAN_CACHE_MAX + 100) {
        let mut plan = test_plan(TlsMode::Direct, None);
        plan.domain = format!("h{i}.example.com");
        h.engine.remember_plan_arc(Arc::new(plan));
    }
    let cache = h.engine.plan_cache.read();
    let total: usize = cache.values().map(|inner| inner.len()).sum();
    assert!(total <= PLAN_CACHE_MAX);
    assert!(
        cache
            .get(&format!("h{}.example.com", PLAN_CACHE_MAX + 99))
            .is_some_and(|inner| inner.contains_key(&(443, true))),
        "the newest plan must survive the prune"
    );
}

#[test]
fn network_change_drops_remembered_plans() {
    let h = harness(&["example.com"], Strategy::Direct);
    h.engine.remember_plan_arc(Arc::new(test_plan(TlsMode::Direct, None)));
    assert!(h.engine.cached_plan("example.com", 443, true).is_some());

    h.engine.forget_all_plans();
    assert!(
        h.engine.cached_plan("example.com", 443, true).is_none(),
        "a plan remembered on the old network must not survive"
    );
}

#[test]
fn cached_fake_sni_plan_follows_the_configured_sni() {
    let h = harness(&["example.com"], Strategy::FakeSni);
    h.engine
        .remember_plan_arc(Arc::new(test_plan(TlsMode::FakeSni, Some("old.example"))));
    assert!(h.engine.cached_plan("example.com", 443, true).is_some());

    let mut group = h.engine.config.snapshot().group("test").unwrap().clone();
    group.sni = Some("new.example".into());
    h.engine.config.upsert_group(group).unwrap();
    assert!(
        h.engine.cached_plan("example.com", 443, true).is_none(),
        "the cached plan still used the previous fake SNI"
    );
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
