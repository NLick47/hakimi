//! The DoH endpoint selection.
//!
//! The resolver races the primary against the fallback, falls back to the
//! next endpoint when both fail and serves a fresh answer from the cache.
//! None of that had a test: the harness only covers a completely dead DoH.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;


use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use hakimi_core::ca::CertificateAuthority;
use hakimi_core::cache::CacheManager;
use hakimi_core::catalog::CatalogManager;
use hakimi_core::config::ConfigManager;
use hakimi_core::paths::Paths;
use hakimi_core::resolver::Resolver;
use hakimi_core::strategy::DohSource;

/// The trust hook lives in the environment, which is process wide: the tests
/// must not run at the same time.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

fn push_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|label| !label.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// A DNS answer for `name` with one A record.
fn answer_a(name: &str, ttl: u32, ip: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    push_name(&mut out, name);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip);
    out
}

/// The queried name, decoded from the wire format.
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

/// A DoH server that answers every query with `ip`, or fails when `fail` is
/// set.
struct DohServer {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
}

impl DohServer {
    async fn spawn(
        tls: Arc<rustls::ServerConfig>,
        ip: [u8; 4],
        fail: bool,
    ) -> DohServer {
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
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |req: hyper::Request<Incoming>| {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, Ordering::Relaxed);
                            if fail {
                                return Ok::<_, Infallible>(hyper::Response::builder()
                                    .status(503)
                                    .body(Full::new(Bytes::from_static(b"nope")))
                                    .unwrap());
                            }
                            let query = req.into_body().collect().await.map(|b| b.to_bytes());
                            let Ok(query) = query else {
                                return Ok::<_, Infallible>(hyper::Response::builder()
                                    .status(400)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap());
                            };
                            // Echo the id and the question of the query.
                            let mut response = Vec::new();
                            response.extend_from_slice(&query[0..2]);
                            response.extend_from_slice(&0x8180u16.to_be_bytes());
                            response.extend_from_slice(&1u16.to_be_bytes());
                            response.extend_from_slice(&1u16.to_be_bytes());
                            response.extend_from_slice(&0u16.to_be_bytes());
                            response.extend_from_slice(&0u16.to_be_bytes());
                            response.extend_from_slice(&query[12..]);
                            let name = name_from_query(&query);
                            response.extend_from_slice(&answer_a(&name, 300, ip));
                            Ok(hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/dns-message")
                                .body(Full::new(Bytes::from(response)))
                                .unwrap())
                        }
                    });
                    // The DoH client offers HTTP/2, so the server has to speak
                    // whichever protocol the client picked.
                    if let Err(error) = hyper_util::server::conn::auto::Builder::new(
                        TokioExecutor::new(),
                    )
                    .serve_connection_with_upgrades(TokioIo::new(tls), service)
                    .await
                    {
                        eprintln!("[doh] connection ended: {error:?}");
                    }
                });
            }
        });
        DohServer { addr, requests }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_primary_endpoint_wins_and_the_answer_is_cached() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let primary = DohServer::spawn(tls.clone(), [93, 184, 216, 34], false).await;
    let fallback = DohServer::spawn(tls, [203, 0, 113, 7], false).await;

    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.doh.primary = format!("https://127.0.0.1:{}/dns-query", primary.addr.port());
            config.doh.fallback = format!("https://127.0.0.1:{}/dns-query", fallback.addr.port());
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let resolver = Resolver::new(cache.clone(), config.clone(), catalogs.clone());

    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(resolution.ips, vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]);
    assert_eq!(resolution.source, DohSource::Primary);
    assert!(!resolution.fallback_used);
    assert_eq!(primary.requests.load(Ordering::Relaxed), 1);
    // The resolver deliberately races the two endpoints, so the losing
    // fallback request may already be in flight before the primary wins.
    // What matters is that the primary answer is the one returned and cached.
    assert!(
        fallback.requests.load(Ordering::Relaxed) <= 1,
        "the fallback must not be retried while the primary answers"
    );

    // The second query is answered from the cache.
    let again = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(again.ips, vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]);
    assert_eq!(again.source, DohSource::Cache);
    assert_eq!(primary.requests.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_broken_primary_falls_back_to_the_second_endpoint() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let primary = DohServer::spawn(tls.clone(), [93, 184, 216, 34], true).await;
    let fallback = DohServer::spawn(tls, [203, 0, 113, 7], false).await;

    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.doh.primary = format!("https://127.0.0.1:{}/dns-query", primary.addr.port());
            config.doh.fallback = format!("https://127.0.0.1:{}/dns-query", fallback.addr.port());
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let resolver = Resolver::new(cache.clone(), config.clone(), catalogs.clone());

    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(
        resolution.ips,
        vec!["203.0.113.7".parse::<std::net::IpAddr>().unwrap()],
        "the fallback must answer when the primary fails"
    );
    assert_eq!(resolution.source, DohSource::Fallback);
    assert!(resolution.fallback_used);

    // The health snapshot knows that the primary is broken.
    let health = resolver.health_snapshot();
    let primary_health = health
        .iter()
        .find(|entry| entry.url.contains(&primary.addr.port().to_string()))
        .expect("the primary has a health entry");
    assert!(!primary_health.healthy);
}
