//! Verification tests for the audit findings.
//!
//! Tests fixed along the way assert the corrected behavior; the commit that
//! fixed each finding flipped the original bug-reproduction assertion.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use tokio::net::TcpListener;

use hakimi_core::ca::CertificateAuthority;
use hakimi_core::cache::{CacheManager, CachedEch};
use hakimi_core::catalog::CatalogManager;
use hakimi_core::config::ConfigManager;
use hakimi_core::paths::Paths;
use hakimi_core::resolver::Resolver;
use hakimi_core::util::now;

/// The trust hook lives in the environment, which is process wide: the tests
/// must not run at the same time.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const TYPE_A: u16 = 1;
const TYPE_HTTPS: u16 = 65;

fn push_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|label| !label.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn answer_a(name: &str, ttl: u32, ip: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    push_name(&mut out, name);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip);
    out
}

fn name_from_query(query: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::new();
    let mut index = 12;
    while index < query.len() {
        let len = query[index] as usize;
        if len == 0 {
            break;
        }
        index += 1;
        if len > 63 || index + len > query.len() {
            break;
        }
        if !out.is_empty() {
            out.push(b'.');
        }
        out.extend_from_slice(&query[index..index + len]);
        index += len;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[derive(Clone)]
enum Mode {
    /// An A record with a configurable TTL (the ttl=0 reproduction).
    AnswerTtl([u8; 4], u32),
    /// NOERROR with zero records (an authoritative NODATA).
    Empty,
}

struct DohServer {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
}

impl DohServer {
    async fn spawn(tls: Arc<rustls::ServerConfig>, mode: Mode) -> DohServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(tls);
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let counter = counter.clone();
                let mode = mode.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |req: hyper::Request<Incoming>| {
                        let counter = counter.clone();
                        let mode = mode.clone();
                        async move {
                            counter.fetch_add(1, Ordering::Relaxed);
                            let query = req.into_body().collect().await.map(|b| b.to_bytes());
                            let Ok(query) = query else {
                                return Ok::<_, Infallible>(
                                    hyper::Response::builder()
                                        .status(400)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                );
                            };
                            let mut response = Vec::new();
                            response.extend_from_slice(&query[0..2]);
                            response.extend_from_slice(&0x8180u16.to_be_bytes());
                            response.extend_from_slice(&1u16.to_be_bytes());
                            let answers = u16::from(matches!(&mode, Mode::AnswerTtl(..)));
                            response.extend_from_slice(&answers.to_be_bytes());
                            response.extend_from_slice(&0u16.to_be_bytes());
                            response.extend_from_slice(&0u16.to_be_bytes());
                            response.extend_from_slice(&query[12..]);
                            match &mode {
                                Mode::AnswerTtl(ip, ttl) => {
                                    let name = name_from_query(&query);
                                    response.extend_from_slice(&answer_a(&name, *ttl, *ip));
                                }
                                Mode::Empty => {}
                            }
                            Ok(hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/dns-message")
                                .body(Full::new(Bytes::from(response)))
                                .unwrap())
                        }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
                });
            }
        });
        DohServer { addr, requests }
    }
}

async fn setup(modes: &[Mode]) -> (Arc<Resolver>, Vec<DohServer>, Arc<CacheManager>) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let mut servers = Vec::new();
    for mode in modes {
        servers.push(DohServer::spawn(tls.clone(), mode.clone()).await);
    }

    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.doh.primary = format!("https://127.0.0.1:{}/dns-query", servers[0].addr.port());
            config.doh.fallback =
                format!("https://127.0.0.1:{}/dns-query", servers[1].addr.port());
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let resolver = Resolver::new(cache.clone(), config, catalogs);
    std::mem::forget(dir);
    (resolver, servers, cache)
}

/// Regression test (audit finding 2, fixed): a zero-TTL A/AAAA answer is
/// stored with a minimum cache time (RFC 8767), so the second resolve must
/// hit the cache instead of paying a full endpoint race per connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ttl_zero_answers_are_cached_with_a_minimum_ttl() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, servers, _cache) = setup(&[
        Mode::AnswerTtl([203, 0, 113, 7], 0),
        Mode::AnswerTtl([203, 0, 113, 8], 0),
    ])
    .await;

    let first = resolver.resolve_ips("example.com").await.unwrap();
    // A single address is widened with the next endpoint's answer, so the
    // collected set carries both.
    assert_eq!(
        first.ips,
        vec![
            "203.0.113.7".parse::<std::net::IpAddr>().unwrap(),
            "203.0.113.8".parse::<std::net::IpAddr>().unwrap(),
        ],
        "the thin answers are merged, primary first"
    );
    let requests_after_first: usize = servers
        .iter()
        .map(|server| server.requests.load(Ordering::Relaxed))
        .sum();
    assert!(requests_after_first > 0);

    let second = resolver.resolve_ips("example.com").await.unwrap();
    let requests_after_second: usize = servers
        .iter()
        .map(|server| server.requests.load(Ordering::Relaxed))
        .sum();

    assert_eq!(
        second.source,
        hakimi_core::strategy::DohSource::Cache,
        "a ttl=0 answer must be served from the cache via the minimum ttl"
    );
    assert_eq!(second.ips, first.ips, "the cached answer is the one that won");
    assert_eq!(
        requests_after_second, requests_after_first,
        "a cached ttl=0 answer must not re-query DoH (requests {requests_after_first} -> {requests_after_second})"
    );
}

/// Regression test (audit finding 4, fixed): mutate holds the write lock for
/// the whole snapshot-modify-overwrite cycle, so every increment from both
/// concurrent writers must survive; the unlocked version lost updates.
#[test]
fn concurrent_mutate_writers_do_not_lose_updates() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());

    const N: u64 = 300;
    let writer = |config: Arc<ConfigManager>| {
        for _ in 0..N {
            config
                .mutate(|config| {
                    config.catalog_version += 1;
                    Ok(())
                })
                .unwrap();
        }
    };
    let a = std::thread::spawn({
        let config = config.clone();
        move || writer(config)
    });
    let b = std::thread::spawn({
        let config = config.clone();
        move || writer(config)
    });
    a.join().unwrap();
    b.join().unwrap();

    let final_version = config.snapshot().catalog_version;
    assert_eq!(
        final_version,
        2 * N,
        "every concurrent mutate increment must survive"
    );
}

/// Regression test (audit finding 7, fixed): a negative-cache hit for the
/// HTTPS RR is an authoritative NODATA, so ech_config must keep failing
/// instead of resurrecting a stale ECH config that the domain has removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negative_cache_reuses_a_stale_ech_config() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, servers, cache) = setup(&[Mode::Empty, Mode::Empty]).await;

    // The domain used to publish ECH; the cached config has since expired.
    cache.put_ech(CachedEch {
        domain: "example.com".into(),
        ech_config: vec![1, 2, 3],
        ttl_secs: 1,
        fetched_at: now() - chrono::Duration::hours(2),
    });

    // First call: a live NODATA agreed on by both endpoints errors and is
    // remembered as a negative answer (existing tests cover that path).
    let error = resolver
        .ech_config("example.com", false)
        .await
        .expect_err("a live NODATA answer must not fall back to stale ECH");
    assert!(format!("{error:#}").contains("does not contain an ECH config"));
    let requests_after_first: usize = servers
        .iter()
        .map(|server| server.requests.load(Ordering::Relaxed))
        .sum();

    // Second call: the negative cache short-circuits the live query. The
    // remembered answer is authoritative NODATA, so the stale config must
    // stay retired.
    let error = resolver
        .ech_config("example.com", false)
        .await
        .expect_err("an authoritative NODATA must not resurrect the stale config");
    assert!(format!("{error:#}").contains("does not contain an ECH config"));

    let requests_after_second: usize = servers
        .iter()
        .map(|server| server.requests.load(Ordering::Relaxed))
        .sum();
    assert_eq!(
        requests_after_second, requests_after_first,
        "the negative cache short-circuits the live query entirely"
    );
}

/// Companion to the finding-7 fix: a *failure* negative entry (every endpoint
/// unreachable) is not authoritative, so the stale ECH config must stay
/// available as a last resort — both on the live failure and while the
/// failure negative cache is fresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_total_failure_still_falls_back_to_stale_ech() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, _servers, cache) = setup(&[Mode::Empty, Mode::Empty]).await;
    // Endpoints answer, but with no ECH; make the negative entry a *failure*
    // one by hand (authoritative = false), as an all-endpoints outage would.
    cache.put_doh_negative("example.com", TYPE_HTTPS, 300, false);

    cache.put_ech(CachedEch {
        domain: "example.com".into(),
        ech_config: vec![1, 2, 3],
        ttl_secs: 1,
        fetched_at: now() - chrono::Duration::hours(2),
    });

    let outcome = resolver
        .ech_config("example.com", false)
        .await
        .expect("a failure negative entry must keep the stale config available");
    assert_eq!(outcome.config, vec![1, 2, 3]);
    assert!(outcome.stale);
}
