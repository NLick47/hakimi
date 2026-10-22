//! The upstream HTTP/2 path.
//!
//! The harness can only speak HTTP/1.1 to the proxy, so the direction
//! "proxy -> origin over HTTP/2" had no coverage at all: an origin that
//! offers h2 was never exercised, neither the ALPN negotiation nor the
//! multiplexing nor the flow control for a large body.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use hakimi_core::ca::CertificateAuthority;
use hakimi_core::cache::CacheManager;
use hakimi_core::catalog::CatalogManager;
use hakimi_core::config::{ConfigManager, DomainRule, GroupConfig, RoutePolicy};
use hakimi_core::decision::DecisionEngine;
use hakimi_core::ip_tester::TlsContext;
use hakimi_core::paths::Paths;
use hakimi_core::proxy::{self, ProxyContext};
use hakimi_core::resolver::Resolver;
use hakimi_core::status::StatusStore;

/// The trust hook lives in the environment, which is process wide: the tests
/// must not run at the same time.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// What the origin saw.
#[derive(Default)]
struct OriginState {
    connections: AtomicUsize,
    h2_requests: AtomicUsize,
    versions: Mutex<Vec<http::Version>>,
    alpn: Mutex<Vec<Vec<u8>>>,
}

/// An origin that speaks HTTP/1.1 and HTTP/2 over TLS and records what the
/// client negotiated.
async fn spawn_h2_origin(tls: Arc<rustls::ServerConfig>) -> (SocketAddr, Arc<OriginState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let state = Arc::new(OriginState::default());
    let shared = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let state = shared.clone();
            tokio::spawn(async move {
                state.connections.fetch_add(1, Ordering::Relaxed);
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                state
                    .alpn
                    .lock()
                    .unwrap()
                    .push(tls.get_ref().1.alpn_protocol().unwrap_or_default().to_vec());
                let service = service_fn(move |req: hyper::Request<Incoming>| {
                    let state = state.clone();
                    async move {
                        if req.version() == http::Version::HTTP_2 {
                            state.h2_requests.fetch_add(1, Ordering::Relaxed);
                        }
                        state.versions.lock().unwrap().push(req.version());
                        let path = req.uri().path().to_string();
                        let received = req
                            .into_body()
                            .collect()
                            .await
                            .map(|b| b.to_bytes().len())
                            .unwrap_or(0);
                        let body = path
                            .strip_prefix("/bytes/")
                            .and_then(|count| count.parse::<usize>().ok())
                            .map(|count| Bytes::from(vec![7u8; count]))
                            .unwrap_or_else(|| {
                                Bytes::from(format!("origin-ok len={received}").into_bytes())
                            });
                        Ok::<_, Infallible>(hyper::Response::new(Full::new(body)))
                    }
                });
                // `auto` speaks whichever protocol the client picked.
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (addr, state)
}

/// A proxy that forwards `origin.test` to the given address.
///
/// The handle has to stay alive: dropping it closes the shutdown channel and
/// stops the accept loop.
async fn spawn_proxy(
    ca: Arc<CertificateAuthority>,
    origin: SocketAddr,
    http1_hosts: Vec<String>,
) -> (SocketAddr, proxy::ProxyHandle, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();

    // The proxy trusts the local CA for the upstream connection.
    let roots = dir.path().join("extra-root.pem");
    std::fs::write(&roots, ca.ca_pem()).unwrap();
    std::env::set_var("HAKIMI_EXTRA_ROOT_CA", &roots);
    std::env::set_var("HAKIMI_ALLOW_PRIVATE_CATALOG_IPS", "1");

    // The catalog points the domain at the origin's address.
    let catalog = serde_json::json!({
        "v": 1,
        "groups": {"test": ["origin.test"]},
        "ips": {"origin.test": [origin.ip().to_string()]},
        "sni": {},
    });
    std::fs::write(
        paths.catalog_ip_file(),
        serde_json::to_vec(&catalog).unwrap(),
    )
    .unwrap();

    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.groups.clear();
            config.groups.push(GroupConfig {
                id: "test".into(),
                name: "Test".into(),
                domains: vec![DomainRule::new("origin.test")],
                enabled: true,
                homepage: None,
                default_route: RoutePolicy::auto(),
            });
            // The DoH endpoints point at a closed port: the cursor always
            // asks for a DoH expansion once the catalog candidates run out,
            // and the test must not reach the real resolvers.
            config.doh.primary = "https://127.0.0.1:1/dns-query".into();
            config.doh.fallback = "https://127.0.0.1:1/dns-query".into();
            config.advanced.http1_hosts = http1_hosts;
            Ok(())
        })
        .unwrap();

    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    assert!(
        catalogs.has_ip_catalog(),
        "the catalog with the test address must be accepted"
    );
    let tls = TlsContext::new().unwrap();
    let status = Arc::new(StatusStore::new());
    let resolver = Resolver::new(cache.clone(), config.clone(), catalogs.clone());
    let engine = DecisionEngine::new(
        config.clone(),
        cache.clone(),
        catalogs.clone(),
        resolver.clone(),
        tls.clone(),
        status.clone(),
    );
    let upstream =
        hakimi_core::proxy::UpstreamPool::new(engine.clone(), tls.clone(), &config.snapshot());
    let status_json = Arc::new(|_every: bool| serde_json::json!({"app": "hakimi"}));
    let ctx = ProxyContext::new(
        engine,
        ca,
        config.clone(),
        cache,
        catalogs,
        status,
        resolver,
        tls,
        upstream,
        status_json,
    );
    let handle = proxy::start(ctx, "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    (handle.local_addr, handle, dir)
}

/// Send one absolute-form request through the proxy and read the answer.
async fn request(proxy: SocketAddr, port: u16, path: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(
            format!(
                "GET https://origin.test:{port}{path} HTTP/1.1\r\nHost: origin.test:{port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    let mut buffer = [0u8; 8192];
    // Read until the body is complete: the answers are framed by
    // Content-Length.
    loop {
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer))
            .await
            .expect("the proxy answered in time")
            .unwrap();
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..read]);
        if let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.trim()
                        .eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if raw.len() >= head_end + 4 + length {
                break;
            }
        }
    }
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    (status, raw[head_end + 4..].to_vec())
}

/// An origin plus a proxy that reaches it.
async fn setup_with(
    http1_hosts: Vec<String>,
) -> (
    SocketAddr,
    SocketAddr,
    Arc<OriginState>,
    proxy::ProxyHandle,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let ca_dir = tempfile::tempdir().unwrap();
    let ca_paths = Paths::new(ca_dir.path());
    ca_paths.ensure().unwrap();
    let ca = CertificateAuthority::load_or_create(&ca_paths).unwrap();
    let origin_tls = ca.server_config("origin.test").unwrap();
    let (origin_addr, state) = spawn_h2_origin(origin_tls).await;
    let (proxy_addr, handle, dir) = spawn_proxy(ca.clone(), origin_addr, http1_hosts).await;
    (proxy_addr, origin_addr, state, handle, dir, ca_dir)
}

/// Open a CONNECT tunnel to the proxy and speak HTTP/2 inside it, trusting
/// the local CA.  The connection task runs in the background.
async fn tunnel_h2(
    proxy: SocketAddr,
    port: u16,
    ca_pem: &std::path::Path,
) -> hyper::client::conn::http2::SendRequest<http_body_util::Full<Bytes>> {
    // CONNECT through the proxy.
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(
            format!("CONNECT origin.test:{port} HTTP/1.1\r\nHost: origin.test:{port}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut buffer = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "the proxy must answer the CONNECT");
        head.extend_from_slice(&buffer[..read]);
    }
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"),
        "the CONNECT must be accepted: {}",
        String::from_utf8_lossy(&head)
    );

    // TLS with the local CA as the only root, offering h2.
    let mut roots_store = rustls::RootCertStore::empty();
    for certificate in rustls_pki_types::pem::PemObject::pem_file_iter(ca_pem)
        .unwrap()
        .flatten()
    {
        roots_store.add(certificate).unwrap();
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots_store)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tls = connector
        .connect(
            rustls_pki_types::ServerName::try_from("origin.test").unwrap(),
            stream,
        )
        .await
        .unwrap();
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "the proxy must offer h2 on the MITM tunnel"
    );

    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_upstream_connection_uses_http2() {
    let (proxy_addr, origin_addr, state, _handle, _dir, _ca_dir) = setup_with(Vec::new()).await;

    let (status, body) = request(proxy_addr, origin_addr.port(), "/").await;
    assert_eq!(
        status,
        200,
        "the request must succeed: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(body, b"origin-ok len=0");
    assert_eq!(
        state.h2_requests.load(Ordering::Relaxed),
        1,
        "the origin must have seen an HTTP/2 request"
    );
    assert_eq!(
        state.versions.lock().unwrap().as_slice(),
        &[http::Version::HTTP_2]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sequential_requests_share_one_http2_connection() {
    let (proxy_addr, origin_addr, state, _handle, _dir, _ca_dir) = setup_with(Vec::new()).await;

    for _ in 0..3 {
        let (status, body) = request(proxy_addr, origin_addr.port(), "/").await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        assert_eq!(body, b"origin-ok len=0");
    }
    assert_eq!(
        state.connections.load(Ordering::Relaxed),
        1,
        "the three requests must share one upstream connection"
    );
    assert_eq!(state.h2_requests.load(Ordering::Relaxed), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_body_survives_the_http2_flow_control() {
    let (proxy_addr, origin_addr, state, _handle, _dir, _ca_dir) = setup_with(Vec::new()).await;

    let size = 1024 * 1024;
    let (status, body) = request(proxy_addr, origin_addr.port(), &format!("/bytes/{size}")).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body.len(), size, "the body must arrive complete");
    assert!(body.iter().all(|byte| *byte == 7));
    assert_eq!(state.h2_requests.load(Ordering::Relaxed), 1);
}

/// The browser side of HTTP/2: CONNECT, then TLS with the local CA, then h2
/// inside the tunnel.  The proxy terminates the browser's TLS and forwards
/// the request to the origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_browser_can_use_http2_through_the_mitm_tunnel() {
    let (proxy_addr, origin_addr, state, _handle, _dir, ca_dir) = setup_with(Vec::new()).await;

    // The MITM path needs a trusted local CA; a harness cannot install one.
    std::env::set_var("HAKIMI_ASSUME_CA_INSTALLED", "1");

    let ca_pem = ca_dir.path().join("ca").join("ca.pem");
    let mut sender = tunnel_h2(proxy_addr, origin_addr.port(), &ca_pem).await;

    // One request over h2 inside the tunnel.
    let response = sender
        .send_request(
            hyper::Request::builder()
                .uri("https://origin.test/")
                .header("host", "origin.test")
                .body(http_body_util::Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"origin-ok len=0");
    assert_eq!(
        state.h2_requests.load(Ordering::Relaxed),
        1,
        "the origin must have seen the HTTP/2 request"
    );
}

/// An image host has to be fetched over HTTP/1.1 even when the origin
/// offers h2: some CDNs throttle a single multiplexed connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_image_host_is_forced_to_http1() {
    let (proxy_addr, origin_addr, state, _handle, _dir, _ca_dir) =
        setup_with(vec!["origin.test".to_string()]).await;

    let (status, body) = request(proxy_addr, origin_addr.port(), "/").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, b"origin-ok len=0");
    let alpn = state.alpn.lock().unwrap().clone();
    assert_eq!(
        alpn,
        vec![b"http/1.1".to_vec()],
        "the image host must be fetched over HTTP/1.1"
    );
    assert_eq!(state.h2_requests.load(Ordering::Relaxed), 0);
}

/// Without the image host rule the same origin is fetched over h2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_normal_host_keeps_http2() {
    let (proxy_addr, origin_addr, state, _handle, _dir, _ca_dir) = setup_with(Vec::new()).await;

    let (status, body) = request(proxy_addr, origin_addr.port(), "/").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, b"origin-ok len=0");
    let alpn = state.alpn.lock().unwrap().clone();
    assert_eq!(alpn, vec![b"h2".to_vec()]);
    assert_eq!(state.h2_requests.load(Ordering::Relaxed), 1);
}

/// A tunnel belongs to one host: a request for another host on the same
/// tunnel must be refused, not forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_for_another_host_on_the_tunnel_is_refused() {
    let (proxy_addr, origin_addr, state, _handle, _dir, _ca_dir) = setup_with(Vec::new()).await;
    std::env::set_var("HAKIMI_ASSUME_CA_INSTALLED", "1");

    let ca_pem = _ca_dir.path().join("ca").join("ca.pem");
    let mut sender = tunnel_h2(proxy_addr, origin_addr.port(), &ca_pem).await;
    let response = sender
        .send_request(
            hyper::Request::builder()
                .method("GET")
                .uri("https://evil.test/")
                .header("host", "evil.test")
                .body(http_body_util::Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        400,
        "a foreign host on the tunnel must be refused"
    );
    assert_eq!(
        state.h2_requests.load(Ordering::Relaxed),
        0,
        "the request must not reach the origin"
    );
}

/// A request body has to survive the tunnel unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_body_survives_the_tunnel() {
    let (proxy_addr, origin_addr, state, _handle, _dir, _ca_dir) = setup_with(Vec::new()).await;
    std::env::set_var("HAKIMI_ASSUME_CA_INSTALLED", "1");

    let ca_pem = _ca_dir.path().join("ca").join("ca.pem");
    let mut sender = tunnel_h2(proxy_addr, origin_addr.port(), &ca_pem).await;
    let payload = Bytes::from(vec![9u8; 4096]);
    let response = sender
        .send_request(
            hyper::Request::builder()
                .method("POST")
                .uri("https://origin.test/")
                .header("host", "origin.test")
                .body(http_body_util::Full::new(payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    // The origin reports the length of the body it received.
    assert_eq!(
        String::from_utf8_lossy(&body),
        format!("origin-ok len={}", payload.len()),
        "the body must arrive unchanged"
    );
    assert_eq!(state.h2_requests.load(Ordering::Relaxed), 1);
}
