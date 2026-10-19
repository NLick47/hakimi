use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde_json::json;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;

use crate::ca::{CaStatus, CertificateAuthority};
use crate::cache::CacheManager;
use crate::catalog::{CatalogManager, RefreshReport};
use crate::config::{AppConfig, ConfigManager, GroupConfig, ProxyMode};
use crate::decision::DecisionEngine;
use crate::ip_tester::TlsContext;
use crate::logging;
use crate::paths::Paths;
use crate::proxy::{self, ProxyContext, ProxyHandle, UpstreamPool};
use crate::resolver::Resolver;
use crate::status::{DomainDiagnostics, StatusStore};
use crate::strategy::Strategy;
use crate::system_proxy::{SystemProxyManager, SystemProxyStatus};
use crate::util::{network_id, now};

/// Shared view used by `/hakimi/status`, the CLI and the C ABI.
struct StatusProvider {
    config: Arc<ConfigManager>,
    cache: Arc<CacheManager>,
    catalogs: Arc<CatalogManager>,
    resolver: Arc<Resolver>,
    ca: Arc<CertificateAuthority>,
    status: Arc<StatusStore>,
    system_proxy: Arc<SystemProxyManager>,
    upstream: Arc<UpstreamPool>,
    started_at: DateTime<Utc>,
    proxy_running: Arc<AtomicBool>,
    proxy_listen: Arc<RwLock<Option<SocketAddr>>>,
    proxy_error: Arc<RwLock<Option<String>>>,
    current_network: Arc<RwLock<String>>,
}

impl StatusProvider {
    fn snapshot_json(&self) -> serde_json::Value {
        let config = self.config.snapshot();
        let ca = self.ca.status();
        let catalogs = self.catalogs.status();
        let groups = self.status.groups_snapshot(&config);
        let domains = self.status.domains_snapshot();
        let counts = self.status.counts();
        let cache = self.cache.stats();
        let listen = *self.proxy_listen.read();
        let pac_url = listen.map(|addr| format!("http://{addr}/proxy.pac"));
        let proxy_error = self.proxy_error.read().clone();
        let proxy_applied = if config.proxy.mode == ProxyMode::Off {
            None
        } else if let Some(url) = &pac_url {
            match config.proxy.mode {
                ProxyMode::Pac => self
                    .system_proxy
                    .status(Some(ProxyMode::Pac), Some(url.clone()))
                    .ok()
                    .map(|status| status.applied),
                ProxyMode::Http => listen.map(|addr| {
                    self.system_proxy
                        .status(Some(ProxyMode::Http), Some(addr.to_string()))
                        .ok()
                        .map(|status| status.applied)
                        .unwrap_or(false)
                }),
                ProxyMode::Off => None,
            }
        } else {
            None
        };
        let mut warnings = Vec::new();
        if !ca.installed {
            warnings.push("ca_untrusted");
        }
        if config.proxy.mode != ProxyMode::Off
            && config.proxy.takeover
            && self.proxy_running.load(Ordering::SeqCst)
            && proxy_applied == Some(false)
        {
            warnings.push("proxy_not_applied");
        }
        json!({
            "app": "hakimi",
            "version": env!("CARGO_PKG_VERSION"),
            "startedAt": self.started_at,
            "paused": self.status.paused(),
            "networkId": self.current_network.read().clone(),
            "warnings": warnings,
            "proxy": {
                "running": self.proxy_running.load(Ordering::SeqCst),
                "listen": listen.map(|addr| addr.to_string()),
                "mode": match config.proxy.mode {
                    ProxyMode::Pac => "pac",
                    ProxyMode::Http => "http",
                    ProxyMode::Off => "off",
                },
                "pacUrl": pac_url,
                "applied": proxy_applied,
                "error": proxy_error,
            },
            "ca": ca,
            "catalogs": catalogs,
            "dohHealth": self.resolver.health_snapshot(),
            "upstream": self.upstream.stats_json(),
            "cache": cache,
            "counts": counts,
            "groups": groups,
            "domains": domains,
        })
    }
}

/// Top-level core runtime. The desktop shell (C ABI) and CLI share this object.
pub struct HakimiRuntime {
    paths: Paths,
    config: Arc<ConfigManager>,
    cache: Arc<CacheManager>,
    catalogs: Arc<CatalogManager>,
    resolver: Arc<Resolver>,
    ca: Arc<CertificateAuthority>,
    tls: Arc<TlsContext>,
    status: Arc<StatusStore>,
    engine: Arc<DecisionEngine>,
    upstream: Arc<UpstreamPool>,
    system_proxy: Arc<SystemProxyManager>,
    status_provider: Arc<StatusProvider>,
    proxy_running: Arc<AtomicBool>,
    proxy_listen: Arc<RwLock<Option<SocketAddr>>>,
    proxy_error: Arc<RwLock<Option<String>>>,
    handle: RwLock<Option<ProxyHandle>>,
    shutdown: RwLock<Option<watch::Sender<bool>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    started: AtomicBool,
    started_at: DateTime<Utc>,
}

impl HakimiRuntime {
    pub fn new(data_dir: Option<PathBuf>) -> Result<Arc<Self>> {
        let paths = match data_dir {
            Some(path) => Paths::new(path),
            None => Paths::default_location()?,
        };
        paths.ensure()?;
        let config = Arc::new(ConfigManager::load_or_create(&paths)?);
        logging::init(&paths, &config.snapshot().log.level)?;
        let cache = Arc::new(CacheManager::load(paths.state_file())?);
        let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone())?;
        let ca = CertificateAuthority::load_or_create(&paths)?;
        let tls = TlsContext::new()?;
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
        let upstream = UpstreamPool::new(engine.clone(), tls.clone(), &config.snapshot());
        let system_proxy = Arc::new(SystemProxyManager::new(paths.system_proxy_state_file()));
        let started_at = now();
        let proxy_running = Arc::new(AtomicBool::new(false));
        let proxy_listen = Arc::new(RwLock::new(None));
        let proxy_error = Arc::new(RwLock::new(None));
        let current_network = Arc::new(RwLock::new(network_id()));
        let status_provider = Arc::new(StatusProvider {
            config: config.clone(),
            cache: cache.clone(),
            catalogs: catalogs.clone(),
            resolver: resolver.clone(),
            ca: ca.clone(),
            status: status.clone(),
            system_proxy: system_proxy.clone(),
            upstream: upstream.clone(),
            started_at,
            proxy_running: proxy_running.clone(),
            proxy_listen: proxy_listen.clone(),
            proxy_error: proxy_error.clone(),
            current_network,
        });
        let runtime = Arc::new(Self {
            paths,
            config,
            cache,
            catalogs,
            resolver,
            ca,
            tls,
            status,
            engine,
            upstream,
            system_proxy,
            status_provider,
            proxy_running,
            proxy_listen,
            proxy_error,
            handle: RwLock::new(None),
            shutdown: RwLock::new(None),
            tasks: Mutex::new(Vec::new()),
            started: AtomicBool::new(false),
            started_at,
        });
        // A previous crash may have left the OS proxy pointing at us.
        if runtime.system_proxy.saved_state_exists() {
            tracing::info!("found a saved system proxy state from a previous run");
        }
        Ok(runtime)
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    pub fn config(&self) -> Arc<ConfigManager> {
        self.config.clone()
    }

    pub fn cache(&self) -> Arc<CacheManager> {
        self.cache.clone()
    }

    pub fn catalogs(&self) -> Arc<CatalogManager> {
        self.catalogs.clone()
    }

    pub fn resolver(&self) -> Arc<Resolver> {
        self.resolver.clone()
    }

    pub fn ca(&self) -> Arc<CertificateAuthority> {
        self.ca.clone()
    }

    pub fn status(&self) -> Arc<StatusStore> {
        self.status.clone()
    }

    pub fn config_json(&self) -> serde_json::Value {
        serde_json::to_value(self.config.snapshot()).unwrap_or(serde_json::Value::Null)
    }

    pub fn status_json(&self) -> serde_json::Value {
        self.status_provider.snapshot_json()
    }

    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::SeqCst)
    }

    pub fn pac_url(&self) -> Option<String> {
        (*self.proxy_listen.read()).map(|addr| format!("http://{addr}/proxy.pac"))
    }

    pub fn pac_script(&self) -> String {
        let config = self.config.snapshot();
        let addr = (*self.proxy_listen.read())
            .unwrap_or_else(|| SocketAddr::new(config.proxy.bind, config.proxy.port));
        crate::pac::generate(&config, addr, self.status.paused())
    }

    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    pub async fn start(self: &Arc<Self>) -> Result<()> {
        if self.started.load(Ordering::SeqCst) {
            return Ok(());
        }
        // Cache writes are hints, not state: once the proxy runs, fsyncs leave the request
        // path and the flusher picks them up. One-shot CLI commands keep eager writes.
        self.cache
            .clone()
            .start_auto_flush(std::time::Duration::from_secs(5));
        let config = self.config.snapshot();
        let (shutdown_tx, _) = watch::channel(false);
        *self.shutdown.write() = Some(shutdown_tx.clone());

        if config.proxy.mode != ProxyMode::Off {
            let status_provider = self.status_provider.clone();
            let status_json = Arc::new(move || status_provider.snapshot_json());
            let ctx = ProxyContext::new(
                self.engine.clone(),
                self.ca.clone(),
                self.config.clone(),
                self.cache.clone(),
                self.catalogs.clone(),
                self.status.clone(),
                self.resolver.clone(),
                self.tls.clone(),
                self.upstream.clone(),
                status_json,
            );
            let bind = SocketAddr::new(config.proxy.bind, config.proxy.port);
            let handle = proxy::start(ctx, bind)
                .await
                .with_context(|| format!("starting local proxy on {bind}"))?;
            *self.proxy_listen.write() = Some(handle.local_addr);
            self.proxy_running.store(true, Ordering::SeqCst);
            tracing::info!(addr = %handle.local_addr, "local proxy started");
            *self.handle.write() = Some(handle);
        }

        if config.proxy.mode == ProxyMode::Off {
            let _ = self.system_proxy.restore();
        } else if config.proxy.takeover {
            let _ = self.apply_system_proxy_inner();
        }

        let ca_status = self.ca.status();
        if !ca_status.installed {
            tracing::warn!(
                error = ?ca_status.error,
                "local CA is not trusted; MITM strategies will show certificate errors"
            );
        }

        self.spawn_background_tasks(shutdown_tx);
        self.started.store(true, Ordering::SeqCst);
        tracing::info!(
            data_dir = %self.paths.root().display(),
            "hakimi runtime started"
        );
        Ok(())
    }

    pub async fn stop(self: &Arc<Self>) -> Result<()> {
        let was_started = self.started.swap(false, Ordering::SeqCst);
        if was_started {
            if let Some(shutdown) = self.shutdown.write().take() {
                let _ = shutdown.send(true);
            }
        }
        let handle = self.handle.write().take();
        if let Some(handle) = handle {
            handle.stop().await;
        }
        self.proxy_running.store(false, Ordering::SeqCst);
        *self.proxy_listen.write() = None;
        let tasks: Vec<JoinHandle<()>> = std::mem::take(&mut *self.tasks.lock());
        for task in tasks {
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
        // Always restore: a previous process may have crashed while the OS proxy pointed at us.
        if let Err(error) = self.system_proxy.restore() {
            tracing::warn!(error = %error, "failed to restore the system proxy");
        }
        // Final flush so the last few seconds of routes survive the shutdown.
        self.cache.flush_if_dirty();
        tracing::info!("hakimi runtime stopped");
        Ok(())
    }

    pub fn apply_system_proxy(&self) -> Result<SystemProxyStatus> {
        self.apply_system_proxy_inner()
    }

    /// Restore OS proxy settings saved by a previous `serve` (also usable from a separate
    /// process after the proxy was terminated).
    pub fn restore_system_proxy(&self) -> Result<bool> {
        self.system_proxy.restore()
    }

    fn apply_system_proxy_inner(&self) -> Result<SystemProxyStatus> {
        let config = self.config.snapshot();
        if !config.proxy.takeover || config.proxy.mode == ProxyMode::Off {
            return self.system_proxy.status(Some(config.proxy.mode), None);
        }
        let Some(listen) = *self.proxy_listen.read() else {
            return self.system_proxy.status(Some(config.proxy.mode), None);
        };
        let result = match config.proxy.mode {
            ProxyMode::Pac => self
                .system_proxy
                .apply_pac(&format!("http://{listen}/proxy.pac")),
            ProxyMode::Http => self.system_proxy.apply_http(listen),
            ProxyMode::Off => unreachable!(),
        };
        match &result {
            Ok(status) if status.applied => {
                *self.proxy_error.write() = None;
                tracing::info!(mode = %status.mode, "system proxy applied");
            }
            Ok(status) => {
                *self.proxy_error.write() = Some("system proxy setting was not applied".into());
                tracing::warn!(mode = %status.mode, "system proxy setting was not applied");
            }
            Err(error) => {
                *self.proxy_error.write() = Some(format!("{error:#}"));
                tracing::warn!(error = %error, "failed to apply the system proxy");
            }
        }
        result
    }

    pub fn pause(&self) {
        self.status.set_paused(true);
        tracing::info!("hakimi paused");
    }

    pub fn resume(&self) {
        self.status.set_paused(false);
        tracing::info!("hakimi resumed");
    }

    pub fn set_paused(&self, paused: bool) {
        if paused {
            self.pause();
        } else {
            self.resume();
        }
    }

    pub async fn diagnose(&self, domain: &str) -> DomainDiagnostics {
        self.engine.decide_https(domain).await.diagnostics
    }

    pub async fn refresh_catalogs(&self, force: bool) -> Vec<Result<RefreshReport>> {
        let config = self.config.snapshot();
        let mut results = Vec::new();
        if !config.catalogs.ip.trim().is_empty() || !config.catalogs.ip_mirrors.is_empty() {
            results.push(self.catalogs.refresh_ip(force).await);
        }
        if !config.catalogs.doh.trim().is_empty() || !config.catalogs.doh_mirrors.is_empty() {
            results.push(self.catalogs.refresh_doh(force).await);
        }
        results
    }

    pub async fn refresh_catalog(&self, kind: &str, force: bool) -> Result<RefreshReport> {
        match kind {
            "ip" => self.catalogs.refresh_ip(force).await,
            "doh" => self.catalogs.refresh_doh(force).await,
            other => anyhow::bail!("unknown catalog kind `{other}` (expected ip or doh)"),
        }
    }

    pub async fn ca_status(&self) -> CaStatus {
        self.ca.status()
    }

    pub async fn doh_health(&self) -> Vec<crate::resolver::DohHealth> {
        self.resolver.health_check().await
    }

    pub fn ca_install(&self) -> Result<CaStatus> {
        self.ca.install()
    }

    pub fn ca_uninstall(&self) -> Result<CaStatus> {
        self.ca.uninstall()
    }

    pub fn ca_repair(&self) -> Result<CaStatus> {
        self.ca.repair()
    }

    pub fn ca_regenerate(&self) -> Result<CaStatus> {
        self.ca.regenerate()
    }

    pub fn set_group_enabled(&self, id: &str, enabled: bool) -> Result<AppConfig> {
        self.config.set_group_enabled(id, enabled)
    }

    pub fn set_group_strategy(&self, id: &str, strategy: Strategy) -> Result<AppConfig> {
        self.config.set_group_strategy(id, strategy)
    }

    pub fn upsert_group(&self, group: GroupConfig) -> Result<AppConfig> {
        self.config.upsert_group(group)
    }

    pub fn remove_group(&self, id: &str) -> Result<AppConfig> {
        self.config.remove_group(id)
    }

    pub fn update_config(&self, config: AppConfig) -> Result<()> {
        if self.is_started() {
            let current = self.config.snapshot();
            if current.proxy != config.proxy {
                anyhow::bail!(
                    "proxy bind/port/mode/takeover changes require a restart; stop the runtime first"
                );
            }
            if current.advanced.upstream_idle_secs != config.advanced.upstream_idle_secs
                || current.advanced.upstream_max_idle_per_host
                    != config.advanced.upstream_max_idle_per_host
                || current.advanced.http1_hosts != config.advanced.http1_hosts
                || current.advanced.http1_max_concurrent != config.advanced.http1_max_concurrent
            {
                anyhow::bail!(
                    "upstream pool idle settings require a restart; stop the runtime first"
                );
            }
        }
        self.config.update(config)
    }

    pub fn export_diagnostics(&self) -> Result<PathBuf> {
        let mut status = self.status_json();
        status["config"] = logging::redact_config_value(self.config_json());
        logging::export_diagnostics(&self.paths, status)
    }

    pub async fn probe_domain(&self, domain: &str) -> DomainDiagnostics {
        self.engine.decide_https(domain).await.diagnostics
    }

    fn spawn_background_tasks(self: &Arc<Self>, shutdown: watch::Sender<bool>) {
        // DoH health and the initial group probes.
        let runtime = self.clone();
        let mut receiver = shutdown.subscribe();
        self.spawn(async move {
            let health = {
                let runtime = runtime.clone();
                tokio::spawn(async move { runtime.resolver.health_check().await })
            };
            runtime.warm_groups().await;
            tokio::select! {
                _ = receiver.changed() => {}
                _ = health => {}
            }
        });

        // Startup catalog refresh and periodic refresh.
        let runtime = self.clone();
        let mut receiver = shutdown.subscribe();
        self.spawn(async move {
            tokio::select! {
                _ = receiver.changed() => return,
                _ = tokio::time::sleep(Duration::from_millis(300)) => {}
            }
            loop {
                let results = tokio::select! {
                    _ = receiver.changed() => break,
                    results = runtime.refresh_catalogs(false) => results,
                };
                for result in results {
                    match result {
                        Ok(report) => tracing::info!(
                            kind = %report.kind,
                            updated = report.updated,
                            version = report.version,
                            "catalog refresh finished"
                        ),
                        Err(error) => tracing::warn!(error = %error, "catalog refresh failed"),
                    }
                }
                let hours = runtime
                    .config
                    .snapshot()
                    .catalogs
                    .refresh_hours
                    .clamp(1, 168);
                tokio::select! {
                    _ = receiver.changed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(hours * 3600)) => {}
                }
            }
        });

        // Network-change detector: re-run DoH health and probes when the local address changes.
        let runtime = self.clone();
        let mut receiver = shutdown.subscribe();
        self.spawn(async move {
            let mut current = crate::util::network_id();
            loop {
                tokio::select! {
                    _ = receiver.changed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                }
                let next = crate::util::network_id();
                if next != current {
                    tracing::info!(from = %current, to = %next, "network changed");
                    current = next.clone();
                    *runtime.status_provider.current_network.write() = next;
                    let _ = runtime.resolver.health_check().await;
                    runtime.warm_groups().await;
                }
            }
        });
    }

    fn spawn<F>(self: &Arc<Self>, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(future);
        self.tasks.lock().push(handle);
    }

    /// Warm every exact domain of every enabled group. Wildcards stay lazy because their
    /// concrete host set is unbounded. A HEAD request establishes (or reuses) the pooled
    /// upstream connection, resolves DoH/ECH only when needed, and records a reusable route.
    async fn warm_groups(self: &Arc<Self>) {
        let config = self.config.snapshot();
        if !config.advanced.prewarm {
            return;
        }
        let limit = config.advanced.prewarm_concurrency.clamp(1, 32);
        let semaphore = Arc::new(Semaphore::new(limit));
        let mut seen = HashSet::new();
        let mut primaries = Vec::new();
        let mut rest = Vec::new();
        for group in config.enabled_groups() {
            let primary = group.primary_domain().map(ToOwned::to_owned);
            for domain in group.exact_domains() {
                if !seen.insert(domain.to_string()) {
                    continue;
                }
                if primary.as_deref() == Some(domain) {
                    primaries.push(domain.to_string());
                } else {
                    rest.push(domain.to_string());
                }
            }
        }
        tracing::info!(
            primaries = primaries.len(),
            domains = primaries.len() + rest.len(),
            concurrency = limit,
            "warming upstream routes"
        );

        // Prefetch shared ECH configs so the first browser request does not pay the
        // HTTPS-RR DoH query inside the CONNECT path.
        for group in config.enabled_groups() {
            if group.ech_shared {
                if let Some(domain) = group.primary_domain().map(ToOwned::to_owned) {
                    let resolver = self.resolver.clone();
                    tokio::spawn(async move {
                        let _ = resolver.ech_config(&domain, true).await;
                    });
                }
            }
        }

        for domain in primaries {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            let upstream = self.upstream.clone();
            tokio::spawn(async move {
                let _permit = permit;
                upstream.warm(&domain, 443).await;
            });
        }
        // Give primary checks a head start so group state becomes useful earlier.
        tokio::time::sleep(Duration::from_millis(250)).await;
        for domain in rest {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            let upstream = self.upstream.clone();
            tokio::spawn(async move {
                let _permit = permit;
                upstream.warm(&domain, 443).await;
            });
        }
    }
}
