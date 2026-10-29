use super::*;
use std::sync::atomic::AtomicUsize;

use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::ca::CertificateAuthority;
use crate::cache::{CacheManager, LastGoodEntry};
use crate::catalog::CatalogManager;
use crate::config::{ConfigManager, DomainRule, GroupConfig, RoutePolicy};
use crate::decision::DecisionEngine;
use crate::paths::Paths;
use crate::resolver::{DohResolution, EchOutcome, IpResolver, Resolver};
use crate::status::{AttemptRecord, StatusStore};
use crate::strategy::IpSource;
use crate::util::now;

/// A remote catalog with one working address.
struct StubRemote;

#[async_trait::async_trait]
impl crate::catalog::RemoteIpProvider for StubRemote {
    fn remote_ips(&self, _domain: &str) -> Option<Vec<std::net::IpAddr>> {
        Some(vec!["127.0.0.1".parse().unwrap()])
    }

    fn has_ip_catalog(&self) -> bool {
        true
    }
}

/// A remote catalog that offers a second loopback address, so a rejected
/// candidate still has a fallback.
struct DualRemote;

#[async_trait::async_trait]
impl crate::catalog::RemoteIpProvider for DualRemote {
    fn remote_ips(&self, _domain: &str) -> Option<Vec<std::net::IpAddr>> {
        Some(vec!["::1".parse().unwrap()])
    }

    fn has_ip_catalog(&self) -> bool {
        true
    }
}

struct SlowResolver {
    delay: std::time::Duration,
}

#[async_trait::async_trait]
impl IpResolver for SlowResolver {
    async fn doh_ips(&self, _domain: &str) -> anyhow::Result<DohResolution> {
        tokio::time::sleep(self.delay).await;
        Err(anyhow::anyhow!("slow resolver intentionally failed"))
    }

    async fn doh_ech_config(
        &self,
        _domain: &str,
        _allow_shared: bool,
    ) -> anyhow::Result<EchOutcome> {
        tokio::time::sleep(self.delay).await;
        Err(anyhow::anyhow!("slow resolver intentionally failed"))
    }
}

fn engine_for(dir: &std::path::Path) -> (Arc<DecisionEngine>, Arc<ConfigManager>) {
    // A stub resolver, never the real one: the DoH expansion of the cursor
    // would query the network and make the timing of these tests depend on it.
    engine_for_with_resolver(dir, Some(std::time::Duration::ZERO))
}

fn engine_for_with_resolver(
    dir: &std::path::Path,
    slow: Option<std::time::Duration>,
) -> (Arc<DecisionEngine>, Arc<ConfigManager>) {
    let paths = Paths::new(dir);
    paths.ensure().unwrap();
    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.groups.clear();
            config.groups.push(GroupConfig {
                id: "test".into(),
                name: "Test".into(),
                domains: vec![DomainRule::new("upstream.test")],
                enabled: true,
                homepage: None,
                default_route: RoutePolicy::direct(),
            });
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    cache.put_last_good(LastGoodEntry {
        domain: "upstream.test".into(),
        ip: "127.0.0.1".parse().unwrap(),
        source: IpSource::Cache,
        saved_at: now(),
        catalog_version: 0,
    });
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let status = Arc::new(StatusStore::new());
    let resolver: Arc<dyn IpResolver> = match slow {
        Some(delay) => Arc::new(SlowResolver { delay }),
        None => Resolver::new(cache.clone(), config.clone(), catalogs.clone()),
    };
    let tls = TlsContext::new().unwrap();
    let engine = DecisionEngine::new(config.clone(), cache, catalogs, resolver, tls, status);
    (engine, config)
}

#[test]
fn only_safe_empty_requests_are_hedged() {
    let request = |method: Method, body: &[u8]| {
        Request::builder()
            .method(method)
            .uri("https://upstream.test/")
            .body(Either::Right(Full::new(Bytes::copy_from_slice(body))))
            .unwrap()
    };

    let get = request(Method::GET, b"");
    assert!(hedge_eligible(&get, false, false));
    assert!(
        !hedge_eligible(&get, true, false),
        "upgrade requests must not be replayed"
    );
    assert!(
        !hedge_eligible(&get, false, true),
        "image hosts keep their per-host concurrency permit"
    );
    assert!(
        !hedge_eligible(&request(Method::POST, b""), false, false),
        "only safe methods may be sent twice"
    );
    assert!(
        !hedge_eligible(&request(Method::GET, b"body"), false, false),
        "a request with a body cannot be replayed"
    );

    let declared_body = Request::builder()
        .method(Method::GET)
        .uri("https://upstream.test/")
        .header(http::header::CONTENT_LENGTH, "3")
        .body(Either::Right(Full::new(Bytes::new())))
        .unwrap();
    assert!(
        !hedge_eligible(&declared_body, false, false),
        "a declared body must be respected even when the body stream is empty"
    );
}

#[test]
fn discovery_failure_detail_does_not_leak_the_state_name() {
    let mut diagnostics =
        DomainDiagnostics::checking(Some("github".into()), "github.com", Vec::new(), 0);
    diagnostics.error = Some(FailureReason::TcpTimeout);
    diagnostics.attempts = vec![AttemptRecord {
        strategy: TlsMode::Direct,
        ip: "20.205.243.166".parse().unwrap(),
        source: IpSource::Cache,
        sni: None,
        error: Some(FailureReason::TcpTimeout),
        detail: Some("connect timed out".into()),
        latency_ms: None,
    }];

    let detail = describe_discovery_failure(&diagnostics);
    assert!(detail.contains("tcp_timeout"), "{detail}");
    assert!(detail.contains("20.205.243.166"), "{detail}");
    assert!(
        !detail.contains("Checking"),
        "the fallback must describe the failure, not leak the UI state: {detail}"
    );
}

/// A cancelled route discovery must not poison the domain. The leader's
/// cleanup code only runs when `race_plans` returns; if the caller cancels
/// (browser abort) mid-race the inflight entry stays behind and every later
/// request for that host waits on a notify that never fires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_discovery_does_not_poison_the_domain() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, config) = engine_for(dir.path());
    // Point the domain at TEST-NET-1 so the race hangs until the connect timeout.
    let cache = engine.cache.clone();
    cache.put_last_good(LastGoodEntry {
        domain: "upstream.test".into(),
        ip: "192.0.2.1".parse().unwrap(),
        source: IpSource::Cache,
        saved_at: now(),
        catalog_version: 0,
    });
    config
        .mutate(|c| {
            c.advanced.ip_timeout_ms = 1_000;
            Ok(())
        })
        .unwrap();
    let tls = TlsContext::new().unwrap();
    let pool = Arc::new(UpstreamPool::new(engine, tls, &config.snapshot()));
    let uri = "https://upstream.test/".to_string();

    // First request becomes the discovery leader and hangs in the race.
    let first = {
        let pool = pool.clone();
        let uri = uri.clone();
        tokio::spawn(async move {
            let request = Request::builder()
                .method(Method::GET)
                .uri(&uri)
                .body(Either::Right(Full::new(Bytes::new())))
                .unwrap();
            let _ = pool.send(request, false).await;
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    first.abort(); // browser cancelled the navigation
    let _ = first.await;

    // A later request for the same host must not hang on the stale entry.
    let request = Request::builder()
        .method(Method::GET)
        .uri(&uri)
        .body(Either::Right(Full::new(Bytes::new())))
        .unwrap();
    let second = pool.send(request, false);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(4), second).await;
    assert!(
        outcome.is_ok(),
        "second request hung: the cancelled leader left a poisoned single-flight entry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_block_page_penalizes_the_candidate_ip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 8192];
        let _ = socket.read(&mut buffer).await;
        let _ = socket
            .write_all(
                b"HTTP/1.1 429 Too Many Requests\r\n\
                  Content-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
    });

    let dir = tempfile::tempdir().unwrap();
    let (engine, config) = engine_for(dir.path());
    config
        .mutate(|config| {
            config.groups[0].id = "github".into();
            Ok(())
        })
        .unwrap();
    let tls = TlsContext::new().unwrap();
    let pool = UpstreamPool::new(engine.clone(), tls, &config.snapshot());
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://upstream.test:{port}/"))
        .body(Either::Right(Full::new(Bytes::new())))
        .unwrap();

    let response = pool.send(request, false).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
    assert!(
        engine.cached_plan("upstream.test", port, false).is_none(),
        "the blocked route must be dropped"
    );
    assert!(
        engine.ip_failures("upstream.test", "127.0.0.1".parse().unwrap()) > 0,
        "the blocked address should have a failure score"
    );
}

/// A route rejected by the upstream must not keep serving from the socket
/// that produced the rejection. Without retiring the pooled connection, the
/// next request bypasses the connector (and therefore the re-planned route)
/// and lands on the same rejected IP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_route_does_not_reuse_the_pooled_connection() {
    // The rejected candidate: last-good 127.0.0.1 answers 429 forever.
    let bad = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = bad.local_addr().unwrap().port();
    // The fallback candidate: remote ::1 answers 200.
    let good = TcpListener::bind(("::1", port)).await.unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));

    async fn serve(listener: TcpListener, response: &'static [u8], accepts: Arc<AtomicUsize>) {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            accepts.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                    if socket.write_all(response).await.is_err() {
                        break;
                    }
                }
            });
        }
    }

    tokio::spawn(serve(
        bad,
        b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\
          Connection: keep-alive\r\n\r\n",
        accepts.clone(),
    ));
    tokio::spawn(serve(
        good,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
          Connection: keep-alive\r\n\r\nok",
        accepts.clone(),
    ));

    let dir = tempfile::tempdir().unwrap();
    let (engine, config) = engine_for(dir.path());
    config
        .mutate(|config| {
            // GitHub opts in to candidate-level block-page recovery.
            config.groups[0].id = "github".into();
            Ok(())
        })
        .unwrap();
    // Offer a second address so re-planning can leave the blocked candidate.
    let engine = DecisionEngine::new(
        engine.config.clone(),
        engine.cache.clone(),
        Arc::new(DualRemote),
        engine.resolver.clone(),
        engine.prober.clone(),
        engine.status.clone(),
    );
    let tls = TlsContext::new().unwrap();
    let pool = UpstreamPool::new(engine.clone(), tls, &config.snapshot());
    let uri = format!("http://upstream.test:{port}/");

    let request = || {
        Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .body(Either::Right(Full::new(Bytes::new())))
            .unwrap()
    };
    let first = pool.send(request(), false).await.unwrap();
    assert_eq!(first.status(), http::StatusCode::TOO_MANY_REQUESTS);
    let _ = first.into_body().collect().await.unwrap();
    // Let hyper check the rejected connection back into the pool; the test is
    // about refusing it, not about winning a race with the release path.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let second = pool.send(request(), false).await.unwrap();
    assert_eq!(
        second.status(),
        http::StatusCode::OK,
        "the rejected connection served the next request"
    );
    let body = second.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        2,
        "the rejected connection must not be reused"
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // The replacement pool keeps the new, healthy connection: while the
    // rejection marker is active, later requests reuse it instead of paying a
    // handshake per request.
    let third = pool.send(request(), false).await.unwrap();
    assert_eq!(third.status(), http::StatusCode::OK);
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        2,
        "the replacement connection should be reused"
    );
}

/// A pooled connection that accepts a request and then goes silent must not
/// hold the page for the full header timeout. After the hedge delay the same
/// safe request is sent on the recovery pool, and the fresh answer wins.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_pooled_connection_is_hedged_on_a_fresh_one() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepted = accepts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let index = accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                if socket.read(&mut buffer).await.is_err() {
                    return;
                }
                if socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                    )
                    .await
                    .is_err()
                {
                    return;
                }
                if index == 0 {
                    // The pooled connection accepts the next request and then
                    // never answers: exactly the half-dead hop this hedge is for.
                    let _ = socket.read(&mut buffer).await;
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    return;
                }
                // Every fresh connection answers normally.
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if socket
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
                                      Connection: keep-alive\r\n\r\nok",
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let (engine, config) = engine_for(dir.path());
    config
        .mutate(|config| {
            config.advanced.upstream_header_timeout_secs = 5;
            Ok(())
        })
        .unwrap();
    let tls = TlsContext::new().unwrap();
    let pool = UpstreamPool::new(engine, tls, &config.snapshot());

    let request = |path: &str| {
        Request::builder()
            .method(Method::GET)
            .uri(format!("http://upstream.test:{port}{path}"))
            .body(Either::Right(Full::new(Bytes::new())))
            .unwrap()
    };
    let first = pool.send(request("/one"), false).await.unwrap();
    let body = first.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");

    let started = std::time::Instant::now();
    let second = pool.send(request("/two"), false).await.unwrap();
    let elapsed = started.elapsed();
    assert_eq!(second.status(), http::StatusCode::OK);
    assert!(
        elapsed < std::time::Duration::from_secs(4),
        "the stalled pooled connection held the request for {elapsed:?}"
    );
    assert_eq!(
        pool.stats_json()["hedgedRetries"],
        1,
        "the request must be hedged exactly once"
    );
    assert!(
        accepts.load(Ordering::SeqCst) >= 2,
        "the hedge must open a fresh connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hedged_request_still_obeys_the_header_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_task = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let index = accepted_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                if socket.read(&mut buffer).await.is_err() {
                    return;
                }
                if index == 0 {
                    // The first request on the pooled connection succeeds, so
                    // the next send goes through the hedge path. From then on
                    // this connection and every fresh one stay silent.
                    if socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
                              Connection: keep-alive\r\n\r\nok",
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                let _ = socket.read(&mut buffer).await;
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let (engine, config) = engine_for(dir.path());
    // The manager validates 5..600s; bypass the manager for a fast test of the
    // timer itself. The pool only consumes the snapshot.
    let mut snapshot = (*config.snapshot()).clone();
    snapshot.advanced.upstream_header_timeout_secs = 1;
    let tls = TlsContext::new().unwrap();
    let pool = UpstreamPool::new(engine, tls, &snapshot);

    let request = |path: &str| {
        Request::builder()
            .method(Method::GET)
            .uri(format!("http://upstream.test:{port}{path}"))
            .body(Either::Right(Full::new(Bytes::new())))
            .unwrap()
    };
    let first = pool.send(request("/one"), false).await.unwrap();
    let body = first.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");

    let started = std::time::Instant::now();
    let result = pool.send(request("/two"), false).await;
    let elapsed = started.elapsed();
    assert!(
        result.is_err(),
        "both the original and the hedged connection stalled"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "the single hedge/timeout timer did not fire: {elapsed:?}"
    );
    assert_eq!(pool.stats_json()["hedgedRetries"], 1);
    assert_eq!(pool.stats_json()["requestErrors"], 1);
    assert!(
        accepted.load(Ordering::SeqCst) >= 2,
        "the hedge must open a fresh connection before timing out"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_connections_are_reused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepted = accepts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                loop {
                    match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                if socket
                                    .write_all(
                                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                                    )
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                }
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let (engine, config) = engine_for(dir.path());
    let tls = TlsContext::new().unwrap();
    let pool = UpstreamPool::new(engine, tls, &config.snapshot());
    let uri = format!("http://upstream.test:{port}/");

    for _ in 0..3 {
        let request = Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .body(Either::Right(Full::new(Bytes::new())))
            .unwrap();
        let response = pool.send(request, false).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok");
    }

    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "the HTTP/1.1 connection should be reused across sequential requests"
    );
    let stats = pool.stats_json();
    assert_eq!(stats["connectionsOpened"], 1);
    assert_eq!(stats["responsesH1"], 3);
}

/// Image hosts are deliberately forced onto HTTP/1.1 so a burst can use
/// several TCP connections. The pool must keep enough of those connections
/// idle for the next burst; otherwise every image page pays for fresh TLS
/// handshakes even though the origin just served the previous one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn image_bursts_keep_the_http1_connections_idle() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepted = accepts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                    if socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });

    async fn burst(pool: Arc<UpstreamPool>, uri: String, count: usize) {
        let mut tasks = Vec::with_capacity(count);
        for _ in 0..count {
            let pool = pool.clone();
            let uri = uri.clone();
            tasks.push(tokio::spawn(async move {
                let request = Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Either::Right(Full::new(Bytes::new())))
                    .unwrap();
                let response = pool.send(request, false).await.unwrap();
                assert_eq!(response.status(), http::StatusCode::OK);
                let body = response.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(&body[..], b"ok");
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let (engine, config) = engine_for(dir.path());
    config
        .mutate(|config| {
            config.advanced.http1_hosts = vec!["upstream.test".into()];
            config.advanced.http1_max_concurrent = 4;
            config.advanced.upstream_max_idle_per_host = 1;
            Ok(())
        })
        .unwrap();
    let tls = TlsContext::new().unwrap();
    let pool = UpstreamPool::new(engine, tls, &config.snapshot());
    let uri = format!("http://upstream.test:{port}/");

    burst(pool.clone(), uri.clone(), 4).await;
    // Give hyper a moment to check the connections back into the pool.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let after_first = accepts.load(Ordering::SeqCst);
    assert_eq!(
        after_first, 4,
        "the first burst should use four h1 connections"
    );

    burst(pool, uri, 4).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        after_first,
        "the second image burst should reuse the idle h1 connections instead of reconnecting"
    );
}

/// A refused first candidate must not make the healthy fallback wait out the
/// 150 ms hedge window.  This is the latency a browser sees when a stale
/// last-good address is still cached but the origin has moved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_candidate_releases_the_hedge_window() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                    )
                    .await;
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let (engine, config) = engine_for(dir.path());
    // The cached route points at an IPv6 address with no listener on this
    // port, so the first TCP connect is refused immediately.  The remote
    // catalog then offers 127.0.0.1, where the test origin is listening.
    engine.cache.put_last_good(LastGoodEntry {
        domain: "upstream.test".into(),
        ip: "::1".parse().unwrap(),
        source: IpSource::Cache,
        saved_at: now(),
        catalog_version: 0,
    });
    let engine = DecisionEngine::new(
        config.clone(),
        engine.cache.clone(),
        Arc::new(StubRemote),
        engine.resolver.clone(),
        engine.prober.clone(),
        engine.status.clone(),
    );
    let tls = TlsContext::new().unwrap();
    let pool = UpstreamPool::new(engine, tls, &config.snapshot());
    let uri = format!("http://upstream.test:{port}/");
    let request = Request::builder()
        .method(Method::GET)
        .uri(&uri)
        .body(Either::Right(Full::new(Bytes::new())))
        .unwrap();

    let started = std::time::Instant::now();
    let response = pool.send(request, false).await.unwrap();
    let elapsed = started.elapsed();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(
        elapsed < std::time::Duration::from_millis(120),
        "the refused candidate made the fallback wait for the hedge window: {elapsed:?}"
    );
}

/// Regression probe for cold-connection latency: a single cached candidate is
/// available, but `race_plans` pre-buffers plans and `next_plan` waits for DoH
/// expansion before the race can start. The first connection should not wait
/// for DoH when a usable cached route is already known.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cached_candidate_is_not_blocked_by_slow_doh_expansion() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let read = socket.read(&mut buffer).await;
                eprintln!("[live] read={read:?}");
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                    )
                    .await;
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let (engine, config) = engine_for_with_resolver(dir.path(), Some(Duration::from_millis(1500)));
    let tls = TlsContext::new().unwrap();
    let pool = UpstreamPool::new(engine, tls, &config.snapshot());
    let uri = format!("http://upstream.test:{port}/");
    let request = Request::builder()
        .method(Method::GET)
        .uri(&uri)
        .body(Either::Right(Full::new(Bytes::new())))
        .unwrap();

    let started = std::time::Instant::now();
    let response = pool.send(request, false).await.unwrap();
    let elapsed = started.elapsed();
    println!("cached candidate response took {elapsed:?} with a 1.5s DoH delay");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(
        elapsed < Duration::from_millis(600),
        "the cached candidate was blocked by DoH expansion: {elapsed:?}"
    );
}

/// Concurrent cold connections for one domain share a single route
/// discovery.  Without the single flight every request would race the
/// candidates on its own and dial the dead one again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_cold_connections_share_one_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let paths = crate::paths::Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    // The proxy has to trust the local CA for the working candidate.
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    // The working candidate: a TLS server on 127.0.0.1.
    let live_tls = ca.server_config("upstream.test").unwrap();
    let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = live.local_addr().unwrap().port();
    let acceptor = tokio_rustls::TlsAcceptor::from(live_tls);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = live.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    |_req: hyper::Request<hyper::body::Incoming>| async {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(Bytes::from_static(b"ok")),
                        ))
                    },
                );
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(tls), service)
                .await;
            });
        }
    });

    // The stale cached candidate: the same port on the other loopback
    // address. It accepts TCP but never sends a ServerHello, so the cached
    // route hangs in its TLS handshake instead of failing fast.
    let dead = TcpListener::bind(("::1", port)).await.unwrap();
    let dead_accepts = Arc::new(AtomicUsize::new(0));
    let counter = dead_accepts.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = dead.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                // Hold the socket open; the test drops the runtime at the end.
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(socket);
            });
        }
    });

    let (engine, config) = engine_for(dir.path());
    // The last known route points at the address that never answers, so the
    // race has to try it before the working candidate.
    engine.cache.put_last_good(LastGoodEntry {
        domain: "upstream.test".into(),
        ip: "::1".parse().unwrap(),
        source: IpSource::Cache,
        saved_at: now(),
        catalog_version: 0,
    });
    // The remote catalog offers the working address.
    let engine = DecisionEngine::new(
        engine.config.clone(),
        engine.cache.clone(),
        Arc::new(StubRemote),
        engine.resolver.clone(),
        engine.prober.clone(),
        engine.status.clone(),
    );
    // Seed the plan cache with the hanging route. The next request must race
    // it against the catalog rather than waiting out its full timeout.
    let cached = Arc::new(ConnectPlan {
        domain: "upstream.test".into(),
        group_id: "test".into(),
        ip: "::1".parse().unwrap(),
        port,
        mode: TlsMode::Direct,
        sni: None,
        ech_config: None,
        tls: true,
        source: IpSource::Cache,
    });
    engine.note_tunnel_success(&cached, 5);

    let tls = TlsContext::new().unwrap();
    let pool = Arc::new(UpstreamPool::new(engine, tls, &config.snapshot()));
    let uri = format!("https://upstream.test:{port}/");

    // Ten requests at once, all to the same cold domain.
    let started = std::time::Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let pool = pool.clone();
        let uri = uri.clone();
        tasks.push(tokio::spawn(async move {
            let request = Request::builder()
                .method(Method::GET)
                .uri(&uri)
                .body(Either::Right(Full::new(Bytes::new())))
                .unwrap();
            pool.send(request, false)
                .await
                .map(|response| response.status())
                .map_err(|error| error)
        }));
    }
    for (index, task) in tasks.into_iter().enumerate() {
        let outcome = task.await.unwrap();
        assert!(outcome.is_ok(), "request {index} failed: {outcome:?}");
        assert_eq!(outcome.unwrap(), http::StatusCode::OK);
    }
    assert_eq!(
        dead_accepts.load(Ordering::SeqCst),
        1,
        "the dead candidate must be dialled once, not once per request"
    );
    assert!(
        started.elapsed() < Duration::from_millis(1_000),
        "the stalled cached route blocked the healthy candidate for {:?}",
        started.elapsed()
    );
}

#[test]
fn slow_host_markers_are_lock_free_and_bounded() {
    let hosts = SlowHosts::new();
    let ttl = Duration::from_secs(60);
    assert!(!hosts.is_slow("slow.example"));
    hosts.mark("slow.example", ttl);
    assert!(hosts.is_slow("slow.example"));
    assert!(!hosts.is_slow("healthy.example"));

    // A different host in the same slot replaces the marker: the table is a
    // bounded hint, and a forgotten host is re-marked by its next slow reply.
    let first = "slot-a.example";
    let first_hash = SlowHosts::hash(first);
    let second = (0..10_000)
        .map(|index| format!("slot-b-{index}.example"))
        .find(|host| {
            let hash = SlowHosts::hash(host);
            hash != first_hash
                && hash & (SLOW_HOST_SLOTS as u32 - 1) == first_hash & (SLOW_HOST_SLOTS as u32 - 1)
        })
        .expect("a colliding slot");
    hosts.mark(first, ttl);
    hosts.mark(&second, ttl);
    assert!(hosts.is_slow(&second));
    assert!(!hosts.is_slow(first));
}

#[inline(never)]
fn bench_slow_lookup(hosts: &SlowHosts, host: &str) -> bool {
    hosts.is_slow(host)
}

#[test]
#[ignore = "micro benchmark"]
fn bench_slow_host_lookup() {
    use std::collections::HashMap;
    use std::hint::black_box;
    use std::sync::RwLock;

    let ttl = Duration::from_secs(60);
    let hosts = SlowHosts::new();
    hosts.mark("slow.example", ttl);
    crate::bench::measure("pool.slow_host.table", 5_000_000, || {
        black_box(bench_slow_lookup(&hosts, "slow.example"));
    });

    let mut map = HashMap::new();
    for index in 0..8 {
        map.insert(format!("slow{index}.example"), Instant::now());
    }
    crate::bench::measure("pool.slow_host.table.miss", 5_000_000, || {
        black_box(bench_slow_lookup(&hosts, "healthy.example"));
    });

    let map = RwLock::new(map);
    crate::bench::measure("pool.slow_host.rwlock", 5_000_000, || {
        let hit = map
            .read()
            .unwrap()
            .get("slow3.example")
            .is_some_and(|at| at.elapsed() < ttl);
        black_box(hit);
    });
    crate::bench::measure("pool.slow_host.rwlock.miss", 5_000_000, || {
        let hit = map.read().unwrap().get("healthy.example").is_some();
        black_box(hit);
    });

    // Ten workers read the marker concurrently, like the proxy's runtime. The
    // table only needs shared read-only cache lines; every `RwLock::read`
    // performs an atomic read-modify-write on the same word.
    let per_thread = 2_000_000;
    let host_storage: Vec<String> = (0..4096).map(|index| format!("h{index}.example")).collect();
    let host_names: Vec<&str> = host_storage.iter().map(String::as_str).collect();
    let lookup: fn(&SlowHosts, &str) -> bool = black_box(bench_slow_lookup);
    let started = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..10 {
            scope.spawn(|| {
                let mut acc = 0usize;
                for _ in 0..per_thread {
                    let host = host_names[acc & (host_names.len() - 1)];
                    acc = acc.wrapping_add(hosts.is_slow(host) as usize + 1);
                }
                black_box(acc);
            });
        }
    });
    let elapsed = started.elapsed();
    println!(
        "{:<28} {:>10.1} ns/op ({:?} total)",
        "pool.slow_host.table.10t",
        elapsed.as_nanos() as f64 / (per_thread * 10) as f64,
        elapsed
    );
    let started = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..10 {
            scope.spawn(|| {
                let mut acc = 0usize;
                for _ in 0..per_thread {
                    let host = host_names[acc & (host_names.len() - 1)];
                    acc = acc.wrapping_add(map.read().unwrap().get(host).is_some() as usize + 1);
                }
                black_box(acc);
            });
        }
    });
    let elapsed = started.elapsed();
    println!(
        "{:<28} {:>10.1} ns/op ({:?} total)",
        "pool.slow_host.rwlock.10t",
        elapsed.as_nanos() as f64 / (per_thread * 10) as f64,
        elapsed
    );
}
