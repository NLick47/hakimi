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
const TYPE_AAAA: u16 = 28;
const TYPE_HTTPS: u16 = 65;
const CLASS_IN: u16 = 1;

/// Two addresses per family, so an answer is already wide enough to stop
/// collecting from further endpoints.
const WIDE_V4: [[u8; 4]; 2] = [[93, 184, 216, 34], [93, 184, 216, 35]];
const WIDE_V6: [[u8; 16]; 2] = [
    [
        0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19,
        0x46,
    ],
    [
        0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19,
        0x47,
    ],
];

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

/// A DNS answer for `name` with one AAAA record.
fn answer_aaaa(name: &str, ttl: u32, ip: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    push_name(&mut out, name);
    out.extend_from_slice(&TYPE_AAAA.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&16u16.to_be_bytes());
    out.extend_from_slice(&ip);
    out
}

/// The queried type, decoded from the wire format.
fn qtype_from_query(query: &[u8]) -> u16 {
    let mut index = 12;
    while index < query.len() {
        let len = query[index] as usize;
        index += 1;
        if len == 0 {
            break;
        }
        if len > 63 || index + len > query.len() {
            return 0;
        }
        index += len;
    }
    match query.get(index..index + 2) {
        Some(bytes) => u16::from_be_bytes([bytes[0], bytes[1]]),
        None => 0,
    }
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
    /// Two A records for an A query and two AAAA records for an AAAA query:
    /// an answer wide enough to stop collection.
    Wide,
    /// Two A records, no AAAA: the common IPv4-only host.
    V4Only,
    /// Like `Wide`, but the answer arrives late enough to outlive the grace
    /// window: a slow but healthy peer.
    SlowWide(u64),
    /// A valid HTTP/DNS response with NOERROR and one HTTPS/ECH answer.
    HttpsEch(Vec<u8>),
    /// A valid HTTP/DNS response with NOERROR and no answer records.
    Empty,
    Fail,
    /// Read the query, then never answer: the client has to give up.
    Stall,
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
                        if matches!(&mode, DohMode::Stall) {
                            let _ = req.into_body().collect().await;
                            // Hold the connection open without answering until
                            // the client gives up on its own timeout.
                            let never: std::future::Pending<
                                Result<hyper::Response<Full<Bytes>>, Infallible>,
                            > = std::future::pending();
                            return never.await;
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
                            if let DohMode::SlowWide(delay_ms) = &mode {
                                tokio::time::sleep(std::time::Duration::from_millis(*delay_ms))
                                    .await;
                            }
                            // Echo the id and the question of the query.
                            let qtype = qtype_from_query(&query);
                            let mut response = Vec::new();
                            response.extend_from_slice(&query[0..2]);
                            response.extend_from_slice(&0x8180u16.to_be_bytes());
                            response.extend_from_slice(&1u16.to_be_bytes());
                            let answers: u16 = match &mode {
                                DohMode::Answer(_) | DohMode::HttpsEch(_) => 1,
                                DohMode::Wide | DohMode::SlowWide(_)
                                    if matches!(qtype, TYPE_A | TYPE_AAAA) => 2,
                                DohMode::V4Only if qtype == TYPE_A => 2,
                                _ => 0,
                            };
                            response.extend_from_slice(&answers.to_be_bytes());
                            response.extend_from_slice(&0u16.to_be_bytes());
                            response.extend_from_slice(&0u16.to_be_bytes());
                            response.extend_from_slice(&query[12..]);
                            match &mode {
                                DohMode::Answer(ip) => {
                                    let name = name_from_query(&query);
                                    response.extend_from_slice(&answer_a(&name, 300, *ip));
                                }
                                DohMode::Wide | DohMode::SlowWide(_) => {
                                    let name = name_from_query(&query);
                                    match qtype {
                                        TYPE_A => {
                                            for ip in WIDE_V4 {
                                                response.extend_from_slice(&answer_a(&name, 300, ip));
                                            }
                                        }
                                        TYPE_AAAA => {
                                            for ip in WIDE_V6 {
                                                response
                                                    .extend_from_slice(&answer_aaaa(&name, 300, ip));
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                DohMode::V4Only => {
                                    if qtype == TYPE_A {
                                        let name = name_from_query(&query);
                                        for ip in WIDE_V4 {
                                            response.extend_from_slice(&answer_a(&name, 300, ip));
                                        }
                                    }
                                }
                                DohMode::HttpsEch(ech) => {
                                    let name = name_from_query(&query);
                                    response.extend_from_slice(&answer_https(&name, 300, ech));
                                }
                                DohMode::Empty | DohMode::Fail | DohMode::Stall => {}
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
async fn a_thin_primary_answer_is_widened_and_cached() {
    install_logs();
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
    // One address is a single point of failure, so the primary's thin answer
    // is widened with the fallback's instead of being accepted as-is.
    let primary_ip: std::net::IpAddr = "93.184.216.34".parse().unwrap();
    let fallback_ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
    assert_eq!(resolution.source, DohSource::Primary);
    assert_eq!(
        resolution.ips,
        vec![primary_ip, fallback_ip],
        "the union keeps the primary's answer first"
    );
    assert!(resolution.fallback_used, "a second endpoint was involved");
    // A: primary + widened fallback. AAAA: neither has a record, and the
    // second NODATA confirms the first.
    let primary_requests = primary.requests.load(Ordering::Relaxed);
    let fallback_requests = fallback.requests.load(Ordering::Relaxed);
    assert_eq!(primary_requests, 2, "one query per record type");
    assert_eq!(
        fallback_requests, 2,
        "the thin A answer and the empty AAAA answer each need a peer"
    );

    // The second query is answered from the cache, union included.
    let again = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(
        again.ips, resolution.ips,
        "the cached answer is the one that was collected"
    );
    assert_eq!(again.source, DohSource::Cache);
    assert_eq!(primary.requests.load(Ordering::Relaxed), primary_requests);
    assert_eq!(fallback.requests.load(Ordering::Relaxed), fallback_requests);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_https_answer_behind_a_failed_peer_is_still_found() {
    install_logs();
    // primary NODATA + fallback failure is one conclusion, not two. The walk
    // must continue to the catalog instead of caching "this domain has no ECH"
    // — the old pair-only shortcut did exactly that.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, servers) = resolver_with(&[
        DohMode::Empty,
        DohMode::Fail,
        DohMode::HttpsEch(vec![9, 9, 9]),
    ])
    .await;

    let outcome = resolver.ech_config("example.com", false).await.unwrap();
    assert_eq!(outcome.config, vec![9, 9, 9]);
    assert_eq!(outcome.source, DohSource::Custom);
    assert!(
        servers[2].requests.load(Ordering::Relaxed) >= 1,
        "a failed peer does not confirm NODATA"
    );
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

    // Both endpoints are queried once per record type (A and AAAA): the empty
    // answer is not retried and the winner is the fallback, not a second lookup
    // against the primary.
    assert_eq!(primary.requests.load(Ordering::Relaxed), 2);
    assert_eq!(fallback.requests.load(Ordering::Relaxed), 2);
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

/// A resolver whose raced pair and remaining endpoints point at the given
/// modes, with a one-second DoH timeout so budget tests stay fast. The caller
/// must hold `ENV_LOCK` for the whole test: the trust hook is process wide.
async fn resolver_with(modes: &[DohMode]) -> (Arc<Resolver>, Vec<DohServer>) {
    resolver_with_timeout(modes, 1).await
}

async fn resolver_with_timeout(
    modes: &[DohMode],
    timeout_secs: u64,
) -> (Arc<Resolver>, Vec<DohServer>) {
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
        servers.push(DohServer::spawn_mode(tls.clone(), mode.clone()).await);
    }

    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.doh.primary = format!("https://127.0.0.1:{}/dns-query", servers[0].addr.port());
            config.doh.fallback =
                format!("https://127.0.0.1:{}/dns-query", servers[1].addr.port());
            for server in servers.iter().skip(2) {
                config.doh.custom.push(DohEndpoint {
                    name: format!("custom{}", servers.iter().position(|s| std::ptr::eq(s, server)).unwrap()),
                    url: format!("https://127.0.0.1:{}/dns-query", server.addr.port()),
                    bootstrap_ip: None,
                    enabled: true,
                });
            }
            config.catalogs.timeout_secs = timeout_secs;
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let resolver = Resolver::new(cache, config, catalogs);
    std::mem::forget(dir);
    (resolver, servers)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_remaining_endpoints_share_one_budget() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // Eight endpoints that accept the query and never answer: the endpoints
    // after the raced pair must not cost one full timeout each, or a long
    // catalog list stretches every cold lookup to minutes. The budget caps
    // the whole phase at two client timeouts no matter how long the list is.
    let (resolver, servers) = resolver_with(&[
        DohMode::Stall,
        DohMode::Stall,
        DohMode::Stall,
        DohMode::Stall,
        DohMode::Stall,
        DohMode::Stall,
        DohMode::Stall,
        DohMode::Stall,
        DohMode::Stall,
        DohMode::Stall,
    ])
    .await;

    let started = std::time::Instant::now();
    let error = resolver
        .resolve_ips("example.com")
        .await
        .expect_err("nothing answers");
    let elapsed = started.elapsed();
    assert!(
        format!("{error:#}").contains("all DoH endpoints failed"),
        "unexpected error: {error:#}"
    );
    // Serial probing needs 1s (raced pair) + 8s; lanes without a shared
    // budget need 1s + 4s. The budget must finish near 1s + 2s.
    assert!(
        elapsed < std::time::Duration::from_millis(4200),
        "the remaining endpoints must share one budget, took {elapsed:?}"
    );
    // The first lane pair was certainly probed.
    assert!(servers[2].requests.load(Ordering::Relaxed) >= 1);
    assert!(servers[3].requests.load(Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_working_custom_endpoint_is_not_lost_behind_a_stalled_peer() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // Custom 0 fails fast, custom 1 holds the connection open: the freed lane
    // must be refilled with custom 2, which answers. A window that never
    // refills its lanes would report a total failure.
    let (resolver, servers) = resolver_with(&[
        DohMode::Fail,
        DohMode::Fail,
        DohMode::Fail,
        DohMode::Stall,
        DohMode::Answer([203, 0, 113, 7]),
    ])
    .await;

    let started = std::time::Instant::now();
    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_millis(2000),
        "the answer must not wait for the stalled peer, took {:?}",
        started.elapsed()
    );
    assert_eq!(
        resolution.ips,
        vec!["203.0.113.7".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(resolution.source, DohSource::Custom);
    assert!(servers[4].requests.load(Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_in_the_second_wave_is_still_reached() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // The budget is two client timeouts precisely so an answer behind two
    // stalled peers is still found: the first wave burns its timeout, the
    // second wave then carries the working endpoint.
    let (resolver, servers) = resolver_with(&[
        DohMode::Fail,
        DohMode::Fail,
        DohMode::Stall,
        DohMode::Stall,
        DohMode::Answer([203, 0, 113, 7]),
    ])
    .await;

    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(
        resolution.ips,
        vec!["203.0.113.7".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(resolution.source, DohSource::Custom);
    assert!(servers[4].requests.load(Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_answer_cuts_a_stalled_peer_short() {
    // One endpoint answers NOERROR with no records, the other stalls. The
    // query must stop at the endpoint window instead of holding every request
    // parked behind the single-flight lock until the client timeout.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, servers) = resolver_with_timeout(&[DohMode::Empty, DohMode::Stall], 8).await;

    let started = std::time::Instant::now();
    let outcome = resolver.resolve_ips("example.com").await;
    let elapsed = started.elapsed();
    // Neither endpoint has an address: an error, not an eight-second wait.
    assert!(outcome.is_err(), "no endpoint has an address");
    assert!(
        elapsed >= std::time::Duration::from_millis(3_000),
        "a slow peer must get its full window, took {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(5_000),
        "an empty answer must not wait out the client timeout, took {elapsed:?}"
    );
    // The empty endpoint answered; the stalled one got its query too.
    assert!(servers[0].requests.load(Ordering::Relaxed) >= 1);
    assert!(servers[1].requests.load(Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_stalled_endpoints_cannot_hold_the_race_past_the_deadline() {
    // With no answer at all, the endpoint window ends the wait instead of
    // letting the pair run until the client timeout of the slower endpoint.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, _servers) = resolver_with_timeout(&[DohMode::Stall, DohMode::Stall], 8).await;

    let started = std::time::Instant::now();
    let outcome = resolver.resolve_ips("example.com").await;
    let elapsed = started.elapsed();
    assert!(outcome.is_err(), "nothing answers");
    assert!(
        elapsed < std::time::Duration::from_millis(5_000),
        "the endpoint window must cap the stall below the client timeout, took {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_race_does_not_black_hole_the_domain() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // Two endpoints that never answer: the race deadline cancels both
    // queries while they are still in flight. No endpoint was defeated, so
    // the outcome must not be remembered — the negative entry used to fail
    // every lookup for ten seconds even after the endpoint recovered.
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);

    let tls = ca.server_config("127.0.0.1").unwrap();
    let stalled = DohServer::spawn_mode(tls.clone(), DohMode::Stall).await;
    let stalled_peer = DohServer::spawn_mode(tls.clone(), DohMode::Stall).await;

    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.doh.primary = format!("https://127.0.0.1:{}/dns-query", stalled.addr.port());
            config.doh.fallback =
                format!("https://127.0.0.1:{}/dns-query", stalled_peer.addr.port());
            config.catalogs.timeout_secs = 8;
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let resolver = Resolver::new(cache.clone(), config.clone(), catalogs);
    std::mem::forget(dir);

    resolver
        .resolve_ips("example.com")
        .await
        .expect_err("nothing answers");
    assert!(
        !cache.doh_negative("example.com", TYPE_A),
        "a race cancellation is not an endpoint failure and must not be cached as one"
    );

    // The endpoint recovers: the next lookup must query it instead of
    // short-circuiting on a remembered failure.
    let healthy = DohServer::spawn_mode(tls, DohMode::Answer([9, 9, 9, 9])).await;
    config
        .mutate(|config| {
            let url = format!("https://127.0.0.1:{}/dns-query", healthy.addr.port());
            config.doh.primary = url.clone();
            config.doh.fallback = url;
            Ok(())
        })
        .unwrap();
    let resolution = resolver
        .resolve_ips("example.com")
        .await
        .expect("a recovered endpoint must serve the next lookup immediately");
    assert_eq!(
        resolution.ips,
        vec!["9.9.9.9".parse::<std::net::IpAddr>().unwrap()]
    );
}

// ---------------------------------------------------------------------------
// Scenarios for the collector contract: wide answers stop early, thin answers
// are widened, a stalled peer is hedged, and a repeatedly failing endpoint
// leaves the hot path. Run with `--nocapture` to read the decision log.
// ---------------------------------------------------------------------------

fn install_logs() {
    use std::sync::Once;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    static LOGS: Once = Once::new();
    LOGS.call_once(|| {
        // INFO shows every answered/failed query and the cooldown transitions.
        // `HAKIMI_TEST_LOG=debug` also shows the hedge and widening decisions.
        // Only this crate's events are kept; hyper's h2 frame spam would bury
        // them at DEBUG.
        let level = match std::env::var("HAKIMI_TEST_LOG").as_deref() {
            Ok("debug") => tracing::Level::DEBUG,
            _ => tracing::Level::INFO,
        };
        let filter = tracing_subscriber::filter::Targets::new()
            .with_target("hakimi_core", level)
            .with_default(tracing::Level::WARN);
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_target(false),
            )
            .try_init();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wide_answer_never_dials_a_second_endpoint() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, servers) = resolver_with(&[DohMode::Wide, DohMode::Wide]).await;

    let started = std::time::Instant::now();
    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(
        resolution.ips,
        vec![
            "93.184.216.34".parse::<std::net::IpAddr>().unwrap(),
            "93.184.216.35".parse::<std::net::IpAddr>().unwrap(),
            "2606:2800:220:1:248:1893:25c8:1946"
                .parse::<std::net::IpAddr>()
                .unwrap(),
            "2606:2800:220:1:248:1893:25c8:1947"
                .parse::<std::net::IpAddr>()
                .unwrap(),
        ],
        "both families are collected and kept in order"
    );
    assert!(!resolution.fallback_used);
    assert_eq!(
        servers[0].requests.load(Ordering::Relaxed),
        2,
        "one query per record type, no widening"
    );
    assert_eq!(
        servers[1].requests.load(Ordering::Relaxed),
        0,
        "a wide answer must not dial the second endpoint"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(800),
        "a local answer must not wait for a hedge, took {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_primary_is_hedged_and_the_peer_merged() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // A four-second client timeout, so waiting for the stalled primary would
    // take the 2.5 s stage deadline. The hedge must answer far sooner.
    let (resolver, servers) = resolver_with_timeout(&[DohMode::Stall, DohMode::Wide], 4).await;

    let started = std::time::Instant::now();
    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(resolution.ips.len(), 4, "the peer's answer is collected");
    assert!(resolution.fallback_used);
    assert!(
        elapsed < std::time::Duration::from_millis(1200),
        "the hedge must answer before the stage deadline, took {elapsed:?}"
    );
    assert_eq!(
        servers[0].requests.load(Ordering::Relaxed),
        2,
        "both record types reached the stalled primary"
    );
    assert_eq!(
        servers[1].requests.load(Ordering::Relaxed),
        2,
        "both record types were hedged to the peer"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_configured_ech_answer_stops_without_a_second_endpoint() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, servers) = resolver_with(&[
        DohMode::HttpsEch(vec![1, 2, 3]),
        DohMode::HttpsEch(vec![9, 9]),
    ])
    .await;

    let outcome = resolver.ech_config("example.com", false).await.unwrap();
    assert_eq!(outcome.config, vec![1, 2, 3], "the first config is the answer");
    assert_eq!(
        servers[0].requests.load(Ordering::Relaxed),
        1,
        "ECH is one domain-level value, so one query is enough"
    );
    assert_eq!(
        servers[1].requests.load(Ordering::Relaxed),
        0,
        "a second ECH copy would be the same value"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeatedly_failing_endpoint_is_skipped_once_it_cools() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, servers) =
        resolver_with(&[DohMode::Fail, DohMode::HttpsEch(vec![7])]).await;

    for domain in ["one.example", "two.example", "three.example"] {
        let outcome = resolver.ech_config(domain, false).await.unwrap();
        assert_eq!(outcome.config, vec![7]);
    }
    assert_eq!(
        servers[0].requests.load(Ordering::Relaxed),
        3,
        "one failed probe per query before the cooldown"
    );

    // The third failure armed the cooldown: the next query must skip it.
    let outcome = resolver.ech_config("four.example", false).await.unwrap();
    assert_eq!(outcome.config, vec![7]);
    assert_eq!(
        servers[0].requests.load(Ordering::Relaxed),
        3,
        "a cooling endpoint is not dialled"
    );
    assert_eq!(servers[1].requests.load(Ordering::Relaxed), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_total_nodata_is_negative_cached_and_not_requeried() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, servers) = resolver_with(&[DohMode::Empty, DohMode::Empty]).await;

    let first = resolver.resolve_ips("example.com").await;
    assert!(first.is_err(), "two NODATA answers cannot produce a route");
    let requests: usize = servers
        .iter()
        .map(|server| server.requests.load(Ordering::Relaxed))
        .sum();
    assert_eq!(
        requests, 4,
        "A and AAAA each need the pair to confirm the silence"
    );

    let second = resolver.resolve_ips("example.com").await;
    let error = format!("{:#}", second.unwrap_err());
    assert!(
        error.contains("cached negative answer"),
        "the second lookup must be served by the negative cache: {error}"
    );
    let after: usize = servers
        .iter()
        .map(|server| server.requests.load(Ordering::Relaxed))
        .sum();
    assert_eq!(after, requests, "a cached NODATA must not re-query");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ipv4_only_domain_does_not_walk_the_catalog() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // The catalog endpoints would answer A if asked. An IPv4-only name must not
    // pay one query per endpoint just because its AAAA record does not exist —
    // two independent NODATA answers are the conclusion.
    let (resolver, servers) = resolver_with(&[
        DohMode::V4Only,
        DohMode::V4Only,
        DohMode::Wide,
        DohMode::Wide,
    ])
    .await;

    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(resolution.ips.len(), 2, "only the A records exist");
    assert_eq!(
        servers[0].requests.load(Ordering::Relaxed),
        2,
        "the primary answers A and confirms the empty AAAA"
    );
    assert_eq!(
        servers[1].requests.load(Ordering::Relaxed),
        1,
        "one confirmation is enough to conclude the AAAA is absent"
    );
    assert_eq!(
        servers[2].requests.load(Ordering::Relaxed),
        0,
        "an empty answer must not walk the catalog"
    );
    assert_eq!(servers[3].requests.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identical_answers_stop_after_the_second_endpoint() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let same = [93, 184, 216, 34];
    let (resolver, servers) = resolver_with(&[
        DohMode::Answer(same),
        DohMode::Answer(same),
        DohMode::Answer(same),
        DohMode::Answer(same),
    ])
    .await;

    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(
        resolution.ips,
        vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()],
        "the repeated answer is the only candidate"
    );
    assert_eq!(servers[0].requests.load(Ordering::Relaxed), 2);
    assert_eq!(servers[1].requests.load(Ordering::Relaxed), 2);
    assert_eq!(
        servers[2].requests.load(Ordering::Relaxed),
        0,
        "a repeated answer must not walk the catalog"
    );
    assert_eq!(servers[3].requests.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_hedged_peer_is_not_discarded_before_the_window_ends() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, servers) =
        resolver_with_timeout(&[DohMode::Empty, DohMode::SlowWide(1750)], 4).await;

    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(resolution.ips.len(), 4, "A and AAAA from the slow peer");
    assert_eq!(servers[1].requests.load(Ordering::Relaxed), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nodata_peer_does_not_stop_the_widening_walk() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // The second endpoint says nothing about the address, so the walk must
    // still reach the third one, which carries the extra candidate.
    let (resolver, servers) = resolver_with(&[
        DohMode::Answer([93, 184, 216, 34]),
        DohMode::Empty,
        DohMode::Answer([203, 0, 113, 7]),
        DohMode::Empty,
    ])
    .await;

    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert!(resolution
        .ips
        .contains(&"93.184.216.34".parse::<std::net::IpAddr>().unwrap()));
    assert!(resolution
        .ips
        .contains(&"203.0.113.7".parse::<std::net::IpAddr>().unwrap()));
    assert!(
        servers[2].requests.load(Ordering::Relaxed) >= 1,
        "a NODATA peer is not a redundant answer"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_hedge_wins_before_empty_catalog_endpoints() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // The catalog would confirm NODATA immediately. The slow healthy peer must
    // get its full window before those empty answers close the query.
    let (resolver, servers) = resolver_with_timeout(
        &[
            DohMode::Empty,
            DohMode::SlowWide(1750),
            DohMode::Empty,
            DohMode::Empty,
        ],
        4,
    )
    .await;

    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(resolution.ips.len(), 4, "A and AAAA from the slow peer");
    assert_eq!(
        servers[2].requests.load(Ordering::Relaxed),
        0,
        "the catalog must not answer before the hedge finishes"
    );
    assert_eq!(servers[3].requests.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_foreign_endpoint_gets_its_full_window() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // Endpoints abroad regularly take a few seconds. Dropping one before it
    // answers leaves the domain without any route.
    let (resolver, servers) =
        resolver_with_timeout(&[DohMode::Empty, DohMode::SlowWide(3200)], 6).await;

    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(resolution.ips.len(), 4, "A and AAAA from the slow endpoint");
    assert_eq!(servers[1].requests.load(Ordering::Relaxed), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_hedge_does_not_block_the_catalog() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (resolver, servers) = resolver_with_timeout(
        &[
            DohMode::Stall,
            DohMode::Stall,
            DohMode::Wide,
            DohMode::Wide,
        ],
        1,
    )
    .await;

    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(resolution.ips.len(), 4, "the catalog endpoints still answer");
    assert!(
        servers[2].requests.load(Ordering::Relaxed) >= 1,
        "a stalled hedge must not occupy the catalog lanes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_aaaa_does_not_hold_the_ipv4_answer() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // A is complete in milliseconds; the AAAA confirmation never arrives. The
    // resolution must return the IPv4 candidates after the short window
    // instead of waiting out the endpoint window.
    let (resolver, servers) = resolver_with_timeout(&[DohMode::V4Only, DohMode::Stall], 8).await;

    let started = std::time::Instant::now();
    let resolution = resolver.resolve_ips("example.com").await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(resolution.ips.len(), 2, "the IPv4 answer is complete");
    assert!(
        elapsed >= std::time::Duration::from_millis(900),
        "the AAAA query must get its short window, took {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(2_000),
        "the AAAA confirmation must not hold the resolution, took {elapsed:?}"
    );
    assert!(
        servers[1].requests.load(Ordering::Relaxed) >= 1,
        "the AAAA query was actually attempted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_aaaa_answer_is_cached_after_the_short_window() {
    install_logs();
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    // The IPv6 answer arrives after the short window. It must not be lost: the
    // query continues in the background, so the next resolution has it.
    let (resolver, _servers) =
        resolver_with_timeout(&[DohMode::V4Only, DohMode::SlowWide(2000)], 8).await;

    let first = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(first.ips.len(), 2, "IPv4 answers first");
    assert!(first.ips.iter().all(std::net::IpAddr::is_ipv4));

    // The background query hits the same slow peer and finishes around 2 s
    // after the first answer.
    tokio::time::sleep(std::time::Duration::from_millis(2_800)).await;
    let second = resolver.resolve_ips("example.com").await.unwrap();
    assert_eq!(
        second.ips.len(),
        4,
        "the slow AAAA answer must reach the cache"
    );
    assert!(second.ips.iter().any(std::net::IpAddr::is_ipv6));
    assert_eq!(second.source, DohSource::Cache);
}
