use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::cache::{CacheManager, LastGoodEntry};
use crate::catalog::RemoteIpProvider;
use crate::config::{ConfigManager, GroupConfig};
use crate::decision::{DecisionEngine, Route};
use crate::ip_tester::TlsContext;
use crate::paths::Paths;
use crate::resolver::{DohResolution, EchOutcome, IpResolver};
use crate::status::StatusStore;
use crate::strategy::{IpSource, Strategy, TlsMode};
use crate::util::now;

use super::connect::{
    connect_tcp_upstream, may_tunnel_directly, race_tcp_addresses, race_tcp_plans,
};
use super::*;

/// Loopback throughput microbenchmark for the proxy's bidirectional copy
/// buffer size. Ignored by default because it moves a large payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "loopback throughput benchmark"]
async fn copy_buffer_size_throughput() {
    async fn run(buffer: usize, total: usize) -> Duration {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut socket, _) = origin.accept().await.unwrap();
            let _ = socket.set_nodelay(true);
            let mut buf = vec![0u8; 64 * 1024];
            let mut read = 0usize;
            while read < total {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                read += n;
            }
            socket.write_all(b"ok").await.unwrap();
        });

        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (mut client, _) = relay.accept().await.unwrap();
            let _ = client.set_nodelay(true);
            let mut upstream = TcpStream::connect(origin_addr).await.unwrap();
            let _ = upstream.set_nodelay(true);
            let _ = tokio::io::copy_bidirectional_with_sizes(
                &mut client,
                &mut upstream,
                buffer,
                buffer,
            )
            .await;
        });

        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let _ = client.set_nodelay(true);
        let chunk = vec![0u8; 64 * 1024];
        let started = Instant::now();
        let mut sent = 0usize;
        while sent < total {
            let n = (total - sent).min(chunk.len());
            client.write_all(&chunk[..n]).await.unwrap();
            sent += n;
        }
        client.shutdown().await.unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        let elapsed = started.elapsed();
        origin_task.await.unwrap();
        relay_task.await.unwrap();
        elapsed
    }

    const TOTAL: usize = 128 * 1024 * 1024;
    for buffer in [8 * 1024usize, 64 * 1024] {
        let mut samples = Vec::new();
        for _ in 0..3 {
            let elapsed = run(buffer, TOTAL).await;
            let mbps = (TOTAL as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
            println!(
                "buffer={}KiB elapsed={elapsed:?} throughput={mbps:.1} MiB/s",
                buffer / 1024
            );
            samples.push(elapsed);
        }
        samples.sort();
        println!("buffer={}KiB median={:?}", buffer / 1024, samples[1]);
    }
}

#[test]
fn html_escape() {
    assert_eq!(escape_html("<a&b>"), "&lt;a&amp;b&gt;");
}

struct FakeRemote {
    ips: Vec<IpAddr>,
}

impl RemoteIpProvider for FakeRemote {
    fn remote_ips(&self, _domain: &str) -> Option<Vec<IpAddr>> {
        Some(self.ips.clone())
    }

    fn remote_sni(&self, _group_id: &str) -> Option<String> {
        None
    }

    fn has_ip_catalog(&self) -> bool {
        true
    }
}

struct FakeResolver;

#[async_trait::async_trait]
impl IpResolver for FakeResolver {
    async fn doh_ips(&self, _domain: &str) -> anyhow::Result<DohResolution> {
        Err(anyhow::anyhow!("no doh in this test"))
    }

    async fn doh_ech_config(
        &self,
        _domain: &str,
        _allow_shared: bool,
    ) -> anyhow::Result<EchOutcome> {
        Err(anyhow::anyhow!("no ech in this test"))
    }
}

#[derive(Default)]
struct SlowEchResolver {
    ech_calls: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl IpResolver for SlowEchResolver {
    async fn doh_ips(&self, _domain: &str) -> anyhow::Result<DohResolution> {
        Err(anyhow::anyhow!("no doh in this test"))
    }

    async fn doh_ech_config(
        &self,
        _domain: &str,
        _allow_shared: bool,
    ) -> anyhow::Result<EchOutcome> {
        self.ech_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(5)).await;
        Err(anyhow::anyhow!("slow ECH resolver intentionally failed"))
    }
}

fn engine_for_test(
    dir: &std::path::Path,
    strategy: Strategy,
    cached_ip: IpAddr,
    last_good_strategy: Strategy,
    remote_ips: Vec<IpAddr>,
    resolver: Arc<dyn IpResolver>,
) -> Arc<DecisionEngine> {
    let paths = Paths::new(dir);
    paths.ensure().unwrap();
    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .upsert_group(GroupConfig {
            id: "test".into(),
            name: "Test".into(),
            domains: vec!["upstream.test".into()],
            strategy,
            enabled: true,
            sni: None,
            experimental: false,
            homepage: None,
            ech_shared: false,
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    cache.put_last_good(LastGoodEntry {
        domain: "upstream.test".into(),
        ip: cached_ip,
        strategy: last_good_strategy,
        source: IpSource::Cache,
        network_id: "test".into(),
        saved_at: now(),
        catalog_version: 0,
    });
    let tls = TlsContext::new().unwrap();
    let status = Arc::new(StatusStore::new());
    DecisionEngine::new(
        config,
        cache,
        Arc::new(FakeRemote { ips: remote_ips }),
        resolver,
        tls,
        status,
    )
}

fn engine_for_direct_test(
    dir: &std::path::Path,
    cached_ip: IpAddr,
    remote_ips: Vec<IpAddr>,
) -> Arc<DecisionEngine> {
    engine_for_test(
        dir,
        Strategy::Direct,
        cached_ip,
        Strategy::Direct,
        remote_ips,
        Arc::new(FakeResolver),
    )
}

/// The raw CONNECT path must not wait ten seconds for a black-holed first
/// candidate when another candidate is reachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_tunnel_races_past_a_blackholed_candidate() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Keep the listener alive for the duration of the test; the winning
    // connect only needs the kernel handshake, not an accept.
    let _listener = listener;

    let dir = tempfile::tempdir().unwrap();
    let engine = engine_for_direct_test(
        dir.path(),
        "192.0.2.1".parse().unwrap(),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let mut cursor = match engine.route("upstream.test", port, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };

    // Baseline: the previous implementation tried candidates one at a time.
    let serial_started = Instant::now();
    let _ = connect_tcp_upstream("192.0.2.1".parse().unwrap(), 443, Duration::from_secs(1)).await;
    let _ = connect_tcp_upstream("127.0.0.1".parse().unwrap(), port, Duration::from_secs(1)).await;
    let serial_elapsed = serial_started.elapsed();

    let started = Instant::now();
    let result = race_tcp_plans(&mut cursor, Duration::from_secs(1)).await;
    let elapsed = started.elapsed();
    println!("serial fallback took {serial_elapsed:?}; raw candidate race finished in {elapsed:?}");
    let (plan, _stream, _) = result.expect("the reachable candidate must win");
    assert_eq!(plan.ip.to_string(), "127.0.0.1");
    assert!(
        elapsed < Duration::from_millis(800),
        "serial fallback would wait for the black-holed candidate; elapsed={elapsed:?}"
    );
}

/// The raw CONNECT path can only use direct plans, but an auto group whose
/// last-good strategy is ECH used to put that route first and await an HTTPS-RR
/// DoH query before every direct candidate. With a fast-failing first address that
/// lookup restarted forever and later candidates were never tried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_tunnel_never_waits_for_ech() {
    let dir = tempfile::tempdir().unwrap();
    let resolver = Arc::new(SlowEchResolver::default());
    let engine = engine_for_test(
        dir.path(),
        Strategy::Auto,
        "192.0.2.1".parse().unwrap(),
        Strategy::Ech,
        vec!["198.51.100.1".parse().unwrap()],
        resolver.clone(),
    );
    let mut cursor = match engine.route("upstream.test", 443, true) {
        Route::Group(cursor) => cursor,
        _ => panic!("expected a group route"),
    };
    assert!(cursor.restrict_to_direct());
    let plan = tokio::time::timeout(Duration::from_secs(1), cursor.next_plan())
        .await
        .expect("next_plan waited for an ECH lookup")
        .expect("a direct plan");
    assert_eq!(plan.mode, TlsMode::Direct);
    assert_eq!(
        resolver.ech_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the raw tunnel must not resolve ECH"
    );
}

/// Before the fix this helper used the 10 s system connect timeout even for
/// accelerated candidates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_candidate_uses_the_configured_timeout() {
    let started = Instant::now();
    let result = connect_tcp_upstream(
        "192.0.2.1".parse().unwrap(),
        443,
        Duration::from_millis(300),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(result.is_err(), "the TEST-NET candidate must not connect");
    assert!(
        elapsed < Duration::from_secs(2),
        "candidate timeout was not honored: {elapsed:?}"
    );
}

/// Bypass tunnels used to call `TcpStream::connect((host, port))`, which walks
/// resolved addresses serially: a black-holed first address stalled the whole
/// tunnel even when another address was reachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_address_race_beats_a_blackholed_first_address() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reachable = listener.local_addr().unwrap();

    // Serial baseline: the black-holed address consumes the whole first timeout.
    let serial_started = Instant::now();
    let _ = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect("192.0.2.1:443")).await;
    let serial_elapsed = serial_started.elapsed();

    let started = Instant::now();
    let stream = race_tcp_addresses(
        vec!["192.0.2.1:443".parse().unwrap(), reachable],
        Duration::from_secs(1),
    )
    .await
    .expect("the reachable address must win");
    let elapsed = started.elapsed();
    drop(stream);
    println!("serial first-address wait {serial_elapsed:?}; staggered race {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(800),
        "the reachable address was blocked behind the black-holed one: {elapsed:?}"
    );
}

/// All addresses black-holed: the shared deadline still bounds the attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_address_race_honors_the_deadline() {
    let started = Instant::now();
    let result = race_tcp_addresses(
        vec![
            "192.0.2.1:443".parse().unwrap(),
            "198.51.100.1:443".parse().unwrap(),
        ],
        Duration::from_millis(400),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(result.is_err(), "TEST-NET addresses must not connect");
    assert!(
        elapsed < Duration::from_secs(2),
        "the overall deadline was not honored: {elapsed:?}"
    );
}

/// A group that can use ECH or fake SNI has to keep intercepting the browser's
/// TLS.  Otherwise the second CONNECT to a host would present the origin's
/// certificate instead of the local one.
#[test]
fn only_direct_groups_may_use_the_cached_direct_tunnel() {
    assert!(may_tunnel_directly(Strategy::Direct, TlsMode::Direct));
    assert!(!may_tunnel_directly(Strategy::Auto, TlsMode::Direct));
    assert!(!may_tunnel_directly(Strategy::Ech, TlsMode::Direct));
    assert!(!may_tunnel_directly(Strategy::FakeSni, TlsMode::Direct));
    assert!(!may_tunnel_directly(Strategy::Direct, TlsMode::FakeSni));
    assert!(!may_tunnel_directly(Strategy::Direct, TlsMode::Ech));
}
