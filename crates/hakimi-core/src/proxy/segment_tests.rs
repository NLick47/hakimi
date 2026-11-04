//! End-to-end coverage for the segmented-download path.
//!
//! A strict local origin stands in for GitHub: it serves a multi-MiB body with
//! byte ranges, rejects HTTP/1.1 requests without a `Host` header the way nginx
//! does, and can cut the streaming response short to force a resume. The proxy
//! is driven through a browser-style client so the whole chain (forward →
//! eligibility gate → segment workers → raw h1 range requests) is exercised.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::ca::CertificateAuthority;
use crate::cache::{CacheManager, LastGoodEntry};
use crate::catalog::CatalogManager;
use crate::config::{ConfigManager, DomainRule, GroupConfig, RoutePolicy};
use crate::decision::DecisionEngine;
use crate::ip_tester::TlsContext;
use crate::mirror::MirrorList;
use crate::paths::Paths;
use crate::resolver::Resolver;
use crate::status::StatusStore;
use crate::strategy::IpSource;
use crate::util::now;

use super::*;

const PAYLOAD_LEN: usize = 4 * 1024 * 1024;
const CHUNK_BYTES: u64 = 512 * 1024;

/// Position-dependent bytes: a misplaced chunk of any size changes the content,
/// so silent corruption cannot hide behind a repeating pattern.
fn test_payload() -> Vec<u8> {
    (0..PAYLOAD_LEN).map(|index| (index % 251) as u8).collect()
}

struct OriginStats {
    /// Requests that arrived without the mandatory HTTP/1.1 `Host` header.
    missing_host: AtomicUsize,
    /// Range requests served; a test that never segments proves nothing.
    ranges: AtomicUsize,
}

struct Origin {
    addr: SocketAddr,
    payload: Arc<Vec<u8>>,
    stats: Arc<OriginStats>,
    task: tokio::task::JoinHandle<()>,
}

/// Raw HTTP/1.1 origin on loopback.
///
/// * `strict_host` answers 400 to any request without a `Host` header.
/// * `truncate_after` closes the streaming (non-range) response early, which
///   forces the segment worker to resume with a shrunk range request.
async fn spawn_origin(strict_host: bool, truncate_after: Option<usize>) -> Origin {
    let payload = Arc::new(test_payload());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(OriginStats {
        missing_host: AtomicUsize::new(0),
        ranges: AtomicUsize::new(0),
    });
    let task_payload = payload.clone();
    let task_stats = stats.clone();
    let task = tokio::spawn(async move {
        let payload = task_payload;
        let stats = task_stats;
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let payload = payload.clone();
            let stats = stats.clone();
            tokio::spawn(async move {
                let _ = serve_one(socket, payload, strict_host, truncate_after, stats).await;
            });
        }
    });
    Origin {
        addr,
        payload,
        stats,
        task,
    }
}

fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

async fn serve_one(
    mut socket: tokio::net::TcpStream,
    payload: Arc<Vec<u8>>,
    strict_host: bool,
    truncate_after: Option<usize>,
    stats: Arc<OriginStats>,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    let end = loop {
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..read]);
        if let Some(end) = head_end(&buf) {
            break end;
        }
        if buf.len() > 64 * 1024 {
            return Ok(());
        }
    };

    let head = String::from_utf8_lossy(&buf[..end]);
    let mut lines = head.split("\r\n");
    // Consume the request line; only the headers matter to these tests.
    let _request_line = lines.next().unwrap_or_default();
    let mut has_host = false;
    let mut range: Option<(u64, u64)> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "host" {
            has_host = true;
        }
        if name == "range" {
            let spec = value.strip_prefix("bytes=").unwrap_or_default();
            let (start, end) = match spec.split_once('-') {
                Some(pair) => pair,
                None => continue,
            };
            if let (Ok(start), Ok(end)) = (start.parse::<u64>(), end.parse::<u64>()) {
                range = Some((start, end));
            }
        }
    }

    // nginx answers 400 to any HTTP/1.1 request without Host; the segment
    // workers build their requests on hyper's raw conn API, which never
    // synthesizes the header.
    if strict_host && !has_host {
        stats.missing_host.fetch_add(1, Ordering::SeqCst);
        socket
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\
                  Content-Type: text/plain\r\nConnection: close\r\n\r\nno host y\r\n",
            )
            .await?;
        return Ok(());
    }

    let total = payload.len() as u64;
    match range {
        Some((start, end)) if start < total && start <= end => {
            stats.ranges.fetch_add(1, Ordering::SeqCst);
            let end = end.min(total - 1);
            let slice = &payload[start as usize..=end as usize];
            let head = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\n\
                 Content-Range: bytes {}-{}/{}\r\nAccept-Ranges: bytes\r\n\
                 Connection: close\r\n\r\n",
                slice.len(),
                start,
                end,
                total
            );
            socket.write_all(head.as_bytes()).await?;
            socket.write_all(slice).await?;
        }
        Some(_) => {
            let head = format!(
                "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\
                 Content-Range: bytes */{}\r\nConnection: close\r\n\r\n",
                total
            );
            socket.write_all(head.as_bytes()).await?;
        }
        None => {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\
                 Accept-Ranges: bytes\r\nConnection: close\r\n\r\n"
            );
            socket.write_all(head.as_bytes()).await?;
            match truncate_after {
                Some(limit) => {
                    socket
                        .write_all(&payload[..limit.min(total as usize)])
                        .await?;
                    socket.shutdown().await?;
                }
                None => socket.write_all(&payload).await?,
            }
        }
    }
    Ok(())
}

/// Proxy context wired so `github.com` routes to the loopback origin and the
/// mirror path stays off (direct segmentation is the subject here).
fn build_context(dir: &Path) -> Arc<ProxyContext> {
    let paths = Paths::new(dir);
    paths.ensure().unwrap();
    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.groups.clear();
            config.proxy.takeover = false;
            config.advanced.download.mirror_source.clear();
            config.advanced.download.segments = 4;
            config.advanced.download.chunk_bytes = CHUNK_BYTES;
            config.advanced.download.min_size_bytes = 1024 * 1024;
            Ok(())
        })
        .unwrap();
    config
        .upsert_group(GroupConfig {
            id: "gh".into(),
            name: "GitHub".into(),
            domains: vec![DomainRule::new("github.com")],
            enabled: true,
            homepage: None,
            default_route: RoutePolicy::direct(),
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    cache.put_last_good(LastGoodEntry {
        domain: "github.com".into(),
        ip: "127.0.0.1".parse().unwrap(),
        source: IpSource::Cache,
        saved_at: now(),
        catalog_version: 0,
    });
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let tls = TlsContext::new().unwrap();
    let store = Arc::new(StatusStore::new());
    let resolver = Resolver::new(cache.clone(), config.clone(), catalogs.clone());
    let engine = DecisionEngine::new(
        config.clone(),
        cache.clone(),
        catalogs.clone(),
        resolver.clone(),
        tls.clone(),
        store.clone(),
    );
    let upstream = UpstreamPool::new(engine.clone(), tls.clone(), &config.snapshot());
    ProxyContext::new(
        engine,
        ca,
        config.clone(),
        cache,
        catalogs,
        store,
        resolver,
        tls,
        upstream,
        Arc::new(MirrorList::load(None)),
        Arc::new(|_every| json!({"app": "hakimi", "test": true})),
        Arc::new(|| {}),
    )
}

struct Session {
    handle: ProxyHandle,
    client: reqwest::Client,
    url: String,
}

async fn start_session(dir: &Path, origin: &Origin) -> Session {
    let ctx = build_context(dir);
    let handle = start(ctx, "127.0.0.1:0".parse().unwrap()).await.unwrap();
    // `.proxy()` also disables env/system proxies, so the request only reaches
    // the proxy under test.
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", handle.local_addr)).unwrap())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let url = format!(
        "http://github.com:{}/o/r/releases/download/v1/file.bin",
        origin.addr.port()
    );
    Session {
        handle,
        client,
        url,
    }
}

/// Every request the raw h1 range path emits must carry `Host`: hyper's
/// `client::conn::http1` documents "req must have a Host header" and never
/// adds one (only `hyper_util`'s legacy client does, which the main pool uses).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_segment_range_request_carries_a_host_header() {
    let origin = spawn_origin(true, None).await;
    let dir = tempfile::tempdir().unwrap();
    let session = start_session(dir.path(), &origin).await;

    let response = session
        .client
        .get(&session.url)
        .send()
        .await
        .expect("the download request must reach the origin through the proxy");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let bytes = response.bytes().await;
    // Report the root cause before the generic body error it produces.
    assert_eq!(
        origin.stats.missing_host.load(Ordering::SeqCst),
        0,
        "the origin rejected range requests that arrived without a Host header"
    );
    let bytes =
        bytes.unwrap_or_else(|error| panic!("the segmented download must complete: {error}"));
    assert!(
        origin.stats.ranges.load(Ordering::SeqCst) > 0,
        "the test never segmented; the range path was not exercised"
    );
    assert_eq!(bytes.len(), origin.payload.len());
    assert!(
        bytes[..] == origin.payload[..],
        "the reassembled download must be byte-identical to the origin file"
    );

    session.handle.stop().await;
    origin.task.abort();
}

/// The streaming worker may lose its connection after reading part of chunk 0.
/// It must then resume on a shrunk range request; a Content-Length check
/// against the *full* chunk rejects the server's correct shorter answer and
/// aborts the whole download after three attempts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_that_dies_mid_chunk_resumes_with_a_shrunk_range() {
    // Inside chunk 0 (512 KiB), so the stream worker always has partial bytes.
    let origin = spawn_origin(false, Some(150_000)).await;
    let dir = tempfile::tempdir().unwrap();
    let session = start_session(dir.path(), &origin).await;

    let response = session
        .client
        .get(&session.url)
        .send()
        .await
        .expect("the download request must reach the origin through the proxy");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let bytes = response.bytes().await.unwrap_or_else(|error| {
        panic!("a dead stream must resume instead of failing the download: {error}")
    });

    assert!(
        origin.stats.ranges.load(Ordering::SeqCst) > 0,
        "the test never segmented; the resume path was not exercised"
    );
    assert_eq!(bytes.len(), origin.payload.len());
    assert!(
        bytes[..] == origin.payload[..],
        "the resumed download must be byte-identical to the origin file"
    );

    session.handle.stop().await;
    origin.task.abort();
}
