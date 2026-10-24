use std::sync::Arc;

use hakimi_core::cache::CacheManager;
use hakimi_core::catalog::CatalogManager;
use hakimi_core::config::{AppConfig, ConfigManager};
use hakimi_core::paths::Paths;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_ip_catalog_with_etag_and_skip_once() {
    let body = r#"{
        "v": 1,
        "groups": {"test": ["example.com"]},
        "ips": {"example.com": ["1.1.1.1", "8.8.8.8"]},
        "sni": {"test": "www.baidu.com"}
    }"#
    .to_string();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body_for_server = body.clone();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]).to_ascii_lowercase();
            let response = if request.contains("if-none-match") {
                "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"v1\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_for_server.len(),
                    body_for_server
                )
            };
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = stream.shutdown().await;
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    let mut value = AppConfig::default();
    value.catalogs.ip = format!("http://{addr}/ips.json");
    config.update(value).unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();

    let first = catalogs.refresh_ip(false).await.unwrap();
    assert!(first.updated);
    assert_eq!(first.version, 1);
    assert!(first.affected_domains.contains(&"example.com".to_string()));
    assert!(cache.has_skip_once("example.com"));
    let ips = catalogs.remote_ips("example.com").unwrap();
    assert_eq!(ips.len(), 2);
    assert_eq!(config.snapshot().catalog_version, 1);

    let second = catalogs.refresh_ip(false).await.unwrap();
    assert!(second.up_to_date);
    assert!(!second.updated);
    assert_eq!(second.version, 1);
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_chunked_catalog_is_rejected_while_streaming() {
    // A catalog source can omit Content-Length and keep the body open. The
    // refresh must stop at the byte cap instead of buffering an unbounded
    // chunked body until the request timeout. This server sends more than the
    // cap and then deliberately never terminates the chunked stream.
    const CAP: usize = 2 * 1024 * 1024;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = vec![0u8; 8192];
        let _ = stream.read(&mut buffer).await.unwrap();
        if stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .is_err()
        {
            return;
        }
        let body = vec![b' '; CAP + 1];
        let header = format!("{:x}\r\n", body.len());
        if stream.write_all(header.as_bytes()).await.is_err() {
            return;
        }
        if stream.write_all(&body).await.is_err() {
            return;
        }
        // Leave the body unfinished: a client that buffers the whole response
        // waits for the request timeout instead of noticing the cap.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    let mut value = AppConfig::default();
    value.catalogs.ip = format!("http://{addr}/ips.json");
    value.catalogs.timeout_secs = 5;
    config.update(value).unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config, cache).unwrap();

    let started = std::time::Instant::now();
    let error = catalogs.refresh_ip(false).await.unwrap_err();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(4),
        "the cap must stop the read before the 5s request timeout: {error:#}"
    );
    assert!(
        format!("{error:#}").contains("larger than"),
        "the error must name the byte cap: {error:#}"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_errors_do_not_leak_source_path_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    let mut value = AppConfig::default();
    value.catalogs.ip = "http://127.0.0.1:1/catalog/secret-token".into();
    value.catalogs.timeout_secs = 1;
    config.update(value).unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config, cache).unwrap();

    let error = catalogs.refresh_ip(false).await.unwrap_err();
    let text = format!("{error:#}");
    assert!(
        !text.contains("secret-token"),
        "catalog errors must not expose a token from the source path: {text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_failure_falls_back_to_mirror() {
    let good = r#"{"v":1,"groups":{"test":["example.com"]},"ips":{"example.com":["9.9.9.9"]}}"#;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let good = good.to_string();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]);
            let body = if request.contains("/good.json") {
                good.clone()
            } else {
                "{\"v\":2,\"groups\":{},\"ips\":{}}".to_string()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = stream.shutdown().await;
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    let mut value = AppConfig::default();
    value.catalogs.ip = format!("http://{addr}/bad.json");
    value.catalogs.ip_mirrors = vec![format!("http://{addr}/good.json")];
    config.update(value).unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache).unwrap();

    let report = catalogs.refresh_ip(false).await.unwrap();
    assert!(report.updated);
    assert!(
        report.source.as_deref().unwrap().ends_with("/good.json"),
        "{report:?}"
    );
    assert_eq!(
        catalogs.remote_ips("example.com").unwrap()[0].to_string(),
        "9.9.9.9"
    );
    server.await.unwrap();
}
