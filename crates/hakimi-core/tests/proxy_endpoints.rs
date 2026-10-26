use std::sync::Arc;

use hakimi_core::ca::CertificateAuthority;
use hakimi_core::cache::CacheManager;
use hakimi_core::catalog::CatalogManager;
use hakimi_core::config::ConfigManager;
use hakimi_core::decision::DecisionEngine;
use hakimi_core::ip_tester::TlsContext;
use hakimi_core::paths::Paths;
use hakimi_core::proxy::{self, ProxyContext, UpstreamPool};
use hakimi_core::resolver::Resolver;
use hakimi_core::status::StatusStore;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_pac_and_status_endpoints() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    paths.ensure().unwrap();
    let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
    config
        .mutate(|config| {
            config.groups.clear();
            config.proxy.takeover = false;
            Ok(())
        })
        .unwrap();
    let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
    let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
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
    // The endpoint asks for the small view unless the caller wants every
    // known domain.
    let asked_for_every = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = asked_for_every.clone();
    let status_json = Arc::new(move |every: bool| {
        flag.store(every, std::sync::atomic::Ordering::SeqCst);
        json!({"app": "hakimi", "test": true})
    });
    let upstream = UpstreamPool::new(engine.clone(), tls.clone(), &config.snapshot());
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
    let base = format!("http://{}", handle.local_addr);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    let response = client
        .get(format!("{base}/proxy.pac"))
        .send()
        .await
        .unwrap();
    let pac_status = response.status();
    let pac = response.text().await.unwrap();
    assert!(
        pac.contains("FindProxyForURL"),
        "status={pac_status} body={pac}"
    );
    assert!(pac.contains("return \"DIRECT\""));
    // No groups are configured, so the PAC is DIRECT-only.
    assert!(!pac.contains("PROXY "));

    let status: serde_json::Value = client
        .get(format!("{base}/hakimi/status"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .map(|text| serde_json::from_str(&text))
        .unwrap()
        .unwrap();
    assert_eq!(status["test"], true);
    assert!(
        !asked_for_every.load(std::sync::atomic::Ordering::SeqCst),
        "the plain view must stay small"
    );

    let status: serde_json::Value = client
        .get(format!("{base}/hakimi/status?all=1"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .map(|text| serde_json::from_str(&text))
        .unwrap()
        .unwrap();
    assert_eq!(status["test"], true);
    assert!(
        asked_for_every.load(std::sync::atomic::Ordering::SeqCst),
        "the diagnostics ask for every known domain"
    );

    handle.stop().await;
}
