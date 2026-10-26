//! The DoH endpoint selection.
//!
//! The resolver races the primary against the fallback, falls back to the
//! next endpoint when both fail and serves a fresh answer from the cache.
//! None of that had a test: the harness only covers a completely dead DoH.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use hakimi_core::ca::CertificateAuthority;
use hakimi_core::cache::{CacheManager, CachedAnswer, CachedEch};
use hakimi_core::catalog::CatalogManager;
use hakimi_core::config::{ConfigManager, DohEndpoint};
use hakimi_core::paths::Paths;
use hakimi_core::resolver::Resolver;
use hakimi_core::strategy::DohSource;
use hakimi_core::util::now;

/// The trust hook lives in the environment, which is process wide: the tests
/// must not run at the same time.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const TYPE_A: u16 = 1;
const TYPE_HTTPS: u16 = 65;
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

/// A DNS answer for `name` with one HTTPS record carrying an ECHConfigList.
fn answer_https(name: &str, ttl: u32, ech: &[u8]) -> Vec<u8> {
    let mut rdata = Vec::new();
    // Priority 1, root target name.
    rdata.extend_from_slice(&1u16.to_be_bytes());
    push_name(&mut rdata, "");
    // SvcParam key 5 (ech), with the opaque config as its value.
    rdata.extend_from_slice(&5u16.to_be_bytes());
    rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
    rdata.extend_from_slice(ech);

    let mut out = Vec::new();
    push_name(&mut out, name);
    out.extend_from_slice(&TYPE_HTTPS.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
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

#[derive(Clone)]
enum DohMode {
    Answer([u8; 4]),
    /// A valid HTTP/DNS response with NOERROR and one HTTPS/ECH answer.
    HttpsEch(Vec<u8>),
    /// A valid HTTP/DNS response with NOERROR and no answer records.
    Empty,
    Fail,
}

/// A DoH server that answers every query with one A record, answers with an
/// empty NOERROR response, or fails.
struct DohServer {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
}

impl DohServer {
    async fn spawn(tls: Arc<rustls::ServerConfig>, ip: [u8; 4], fail: bool) -> DohServer {
        Self::spawn_mode(
            tls,
            if fail {
                DohMode::Fail
            } else {
                DohMode::Answer(ip)
            },
        )
        .await
    }

    async fn spawn_mode(tls: Arc<rustls::ServerConfig>, mode: DohMode) -> DohServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(tls);
        let requests = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        let connection_counter = connections.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let counter = counter.clone();
                let connection_counter = connection_counter.clone();
                let mode = mode.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    connection_counter.fetch_add(1, Ordering::Relaxed);
                    let service = service_fn(move |req: hyper::Request<Incoming>| {
                        let counter = counter.clone();
                        let mode = mode.clone();
                        async move {
                            counter.fetch_add(1, Ordering::Relaxed);
                            if matches!(&mode, DohMode::Fail) {
                                return Ok::<_, Infallible>(
                                    hyper::Response::builder()
                                        .status(503)
                                        .body(Full::new(Bytes::from_static(b"nope")))
                                        .unwrap(),
                                );
                            }
                            let query = req.into_body().collect().await.map(|b| b.to_bytes());
                            let Ok(query) = query else {
                                return Ok::<_, Infallible>(
                                    hyper::Response::builder()
                                        .status(400)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                );
                            };
                            // Echo the id and the question of the query.
                            let mut response = Vec::new();
                            response.extend_from_slice(&query[0..2]);
                            response.extend_from_slice(&0x8180u16.to_be_bytes());
                            response.extend_from_slice(&1u16.to_be_bytes());
                            let answers = u16::from(matches!(
                                &mode,
                                DohMode::Answer(_) | DohMode::HttpsEch(_)
                            ));
                            response.extend_from_slice(&answers.to_be_bytes());
                            response.extend_from_slice(&0u16.to_be_bytes());
                            response.extend_from_slice(&0u16.to_be_bytes());
                            response.extend_from_slice(&query[12..]);
                            match &mode {
                                DohMode::Answer(ip) => {
                                    let name = name_from_query(&query);
                                    response.extend_from_slice(&answer_a(&name, 300, *ip));
                                }
                                DohMode::HttpsEch(ech) => {
                                    let name = name_from_query(&query);
                                    response.extend_from_slice(&answer_https(&name, 300, ech));
                                }
                                DohMode::Empty | DohMode::Fail => {}
                            }
                            Ok(hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/dns-message")
                                .body(Full::new(Bytes::from(response)))
                                .unwrap())
                        }
                    });
                    // The DoH client offers HTTP/2, so the server has to speak
                    // whichever protocol the client picked.
                    if let Err(error) =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection_with_upgrades(TokioIo::new(tls), service)
                            .await
                    {
                        eprintln!("[doh] connection ended: {error:?}");
                    }
                });
            }
        });
        DohServer {
            addr,
            requests,
            connections,
        }
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
    assert_eq!(
        resolution.ips,
        vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
    );
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
    assert_eq!(
        again.ips,
        vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(again.source, DohSource::Cache);
    assert_eq!(primary.requests.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_primary_answer_falls_back_to_a_real_address() {
    // A filtering resolver can answer NOERROR with no records. That is a
    // successful HTTP/DNS exchange but not a usable route: the race must not
    // let it cancel the endpoint that has the address.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let primary = DohServer::spawn_mode(tls.clone(), DohMode::Empty).await;
    let fallback = DohServer::spawn_mode(tls, DohMode::Answer([203, 0, 113, 7])).await;

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
        "the fallback's real address must beat the primary's empty answer"
    );
    assert_eq!(resolution.source, DohSource::Fallback);
    assert!(resolution.fallback_used);

    // Both endpoints are queried once: the empty answer is not retried and the
    // winner is the fallback, not a second lookup against the primary.
    assert_eq!(primary.requests.load(Ordering::Relaxed), 1);
    assert_eq!(fallback.requests.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_answers_do_not_pollute_the_answer_cache() {
    // Empty A/AAAA answers carry no route. Caching them used to consume the
    // bounded DoH cache (1024 entries) and evict real answers, forcing those
    // domains to be looked up again.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let primary = DohServer::spawn_mode(tls.clone(), DohMode::Empty).await;
    let fallback = DohServer::spawn_mode(tls, DohMode::Empty).await;

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

    let error = resolver
        .resolve_ips("example.com")
        .await
        .expect_err("an empty A and AAAA answer cannot produce a route");
    assert!(format!("{error:#}").contains("no A/AAAA records"));
    assert_eq!(
        cache.stats().doh_answers,
        0,
        "empty answers must not consume the bounded DoH answer cache"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_health_check_keeps_the_primary_connection_pool_alive() {
    // A health check probes every configured endpoint, including the remote
    // catalog's entries. The client cache used to clear itself on the fifth
    // endpoint, dropping the primary/fallback HTTP/2 connection and forcing
    // the next real query to pay for a new TLS handshake.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let primary = DohServer::spawn_mode(tls.clone(), DohMode::Answer([93, 184, 216, 34])).await;
    let fallback = DohServer::spawn_mode(tls, DohMode::Answer([203, 0, 113, 7])).await;

    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.doh.primary = format!("https://127.0.0.1:{}/dns-query", primary.addr.port());
            config.doh.fallback = format!("https://127.0.0.1:{}/dns-query", fallback.addr.port());
            for index in 0..10 {
                config.doh.custom.push(DohEndpoint {
                    name: format!("catalog{index}"),
                    url: format!(
                        "https://127.0.0.1:{}/dns-query-catalog{index}",
                        primary.addr.port()
                    ),
                    bootstrap_ip: None,
                    enabled: true,
                });
            }
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let resolver = Resolver::new(cache.clone(), config.clone(), catalogs.clone());

    // Establish the pooled connections first.
    resolver.resolve_ips("first.example").await.unwrap();
    let primary_connections = primary.connections.load(Ordering::Relaxed);
    assert!(primary_connections > 0);

    // Twelve endpoints: the old cache cleared itself once the fifth client was
    // built, which included the primary and fallback clients.
    let health = resolver.health_check().await;
    assert_eq!(health.len(), 12);

    primary.connections.store(0, Ordering::Relaxed);
    fallback.connections.store(0, Ordering::Relaxed);
    resolver.resolve_ips("second.example").await.unwrap();
    assert_eq!(
        primary.connections.load(Ordering::Relaxed),
        0,
        "the primary's pooled connection must survive the health check"
    );
    assert_eq!(
        fallback.connections.load(Ordering::Relaxed),
        0,
        "the fallback's pooled connection must survive the health check"
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_https_answer_still_waits_for_fallback_ech() {
    // A filtering primary can answer HTTPS with NOERROR and no records while
    // the fallback still publishes an ECHConfigList. The empty answer must not
    // cancel the fallback before its ECH answer is seen.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let primary = DohServer::spawn_mode(tls.clone(), DohMode::Empty).await;
    let fallback = DohServer::spawn_mode(tls, DohMode::HttpsEch(vec![7, 7, 7, 7])).await;

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

    let outcome = resolver.ech_config("example.com", false).await.unwrap();
    assert_eq!(outcome.config, vec![7, 7, 7, 7]);
    assert_eq!(outcome.source, DohSource::Fallback);
    assert_eq!(primary.requests.load(Ordering::Relaxed), 1);
    assert_eq!(fallback.requests.load(Ordering::Relaxed), 1);
    assert!(
        cache.ech("example.com", true).is_some(),
        "the fallback ECH config must be cached"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authoritative_https_nodata_does_not_reuse_stale_ech() {
    // If every live endpoint agrees that the HTTPS RR has no ECH, an expired
    // config must not be used as if DoH had failed. ECH may have been removed
    // from the domain, and offering the old config can break the handshake.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let primary = DohServer::spawn_mode(tls.clone(), DohMode::Empty).await;
    let fallback = DohServer::spawn_mode(tls, DohMode::Empty).await;

    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.doh.primary = format!("https://127.0.0.1:{}/dns-query", primary.addr.port());
            config.doh.fallback = format!("https://127.0.0.1:{}/dns-query", fallback.addr.port());
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    cache.put_ech(CachedEch {
        domain: "example.com".into(),
        ech_config: vec![1, 2, 3],
        ttl_secs: 1,
        fetched_at: now() - chrono::Duration::hours(2),
    });
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let resolver = Resolver::new(cache.clone(), config.clone(), catalogs.clone());

    let error = resolver
        .ech_config("example.com", false)
        .await
        .expect_err("a live NODATA answer must not fall back to stale ECH");
    assert!(format!("{error:#}").contains("does not contain an ECH config"));
    assert_eq!(primary.requests.load(Ordering::Relaxed), 1);
    assert_eq!(fallback.requests.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_snapshot_drops_endpoints_removed_from_config() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let primary = DohServer::spawn_mode(tls.clone(), DohMode::Answer([93, 184, 216, 34])).await;
    let fallback = DohServer::spawn_mode(tls, DohMode::Answer([203, 0, 113, 7])).await;

    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.doh.primary = format!("https://127.0.0.1:{}/dns-query", primary.addr.port());
            config.doh.fallback = format!("https://127.0.0.1:{}/dns-query", fallback.addr.port());
            for index in 0..2 {
                config.doh.custom.push(DohEndpoint {
                    name: format!("custom{index}"),
                    url: format!("https://127.0.0.1:{}/custom{index}", primary.addr.port()),
                    bootstrap_ip: None,
                    enabled: true,
                });
            }
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let resolver = Resolver::new(cache, config.clone(), catalogs);

    assert_eq!(resolver.health_check().await.len(), 4);
    config
        .mutate(|config| {
            config.doh.custom.clear();
            Ok(())
        })
        .unwrap();
    let health = resolver.health_snapshot();
    assert_eq!(
        health.len(),
        2,
        "removed custom endpoints must disappear from the health snapshot"
    );
    assert!(
        health.iter().all(|entry| !entry.name.starts_with("custom")),
        "no removed endpoint may remain visible"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_answers_do_not_spawn_one_refresh_per_connection() {
    // During a DoH outage, every cold connection can hit the same stale answer.
    // The background refresh must be gated per domain instead of launching a
    // fresh pair of endpoint requests for every connection.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let primary = DohServer::spawn_mode(tls.clone(), DohMode::Fail).await;
    let fallback = DohServer::spawn_mode(tls, DohMode::Fail).await;

    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.doh.primary = format!("https://127.0.0.1:{}/dns-query", primary.addr.port());
            config.doh.fallback = format!("https://127.0.0.1:{}/dns-query", fallback.addr.port());
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    cache.put_doh_answer(CachedAnswer {
        domain: "stale.example".into(),
        qtype: TYPE_A,
        ips: vec!["203.0.113.9".parse().unwrap()],
        hints: Vec::new(),
        ech_config: None,
        ttl_secs: 30,
        fetched_at: now() - chrono::Duration::seconds(40),
    });
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let resolver = Resolver::new(cache, config, catalogs);

    for _ in 0..10 {
        let resolution = resolver.resolve_ips("stale.example").await.unwrap();
        assert!(resolution.stale);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while primary.requests.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let total =
        primary.requests.load(Ordering::Relaxed) + fallback.requests.load(Ordering::Relaxed);
    assert!(
        total >= 1,
        "the stale answer must trigger one refresh attempt"
    );
    assert!(
        total <= 4,
        "one stale burst must not launch a DoH attempt per connection (saw {total})"
    );
}
