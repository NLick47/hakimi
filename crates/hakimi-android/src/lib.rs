//! Minimal JNI shell used by the Android probe app.
//!
//! It starts the shared core as a local HTTP proxy (without touching any OS
//! proxy settings). The Android app points the system/global proxy at
//! `127.0.0.1:8443` for the probe.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use hakimi_core::config::{AppConfig, DohEndpoint, GroupConfig, ProxyMode};
use hakimi_core::runtime::HakimiRuntime;
use hakimi_core::strategy::Strategy;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use parking_lot::Mutex;

struct Host {
    runtime: Arc<HakimiRuntime>,
    tokio: tokio::runtime::Runtime,
}

/// Kept behind an `Arc` so long-running operations (probe sweeps, catalog
/// refreshes) can release the mutex before blocking on the runtime. Holding
/// the global lock across a sweep would stall every status poll in the UI.
static HOST: Mutex<Option<Arc<Host>>> = Mutex::new(None);
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
/// Serializes one-time runtime construction. `Bootstrap.init` is synchronized
/// on the Java side, but the JNI entry point stays safe on its own.
static INIT_LOCK: Mutex<()> = Mutex::new(());
/// Serializes start/stop so a late stop from an old service instance cannot
/// race a start from the new one.
static LIFECYCLE_LOCK: Mutex<()> = Mutex::new(());

fn set_error(message: impl Into<String>) {
    *LAST_ERROR.lock() = Some(message.into());
}

fn clear_error() {
    *LAST_ERROR.lock() = None;
}

fn initialize(data_dir: &str) -> Result<()> {
    let _guard = INIT_LOCK.lock();
    if HOST.lock().is_some() {
        return Ok(());
    }

    let runtime = HakimiRuntime::new(Some(PathBuf::from(data_dir)))
        .context("creating the hakimi runtime")?;

    // The probe exposes a plain HTTP proxy; the Android shell points its
    // global proxy at it. Never touch the (nonexistent) Android system proxy
    // takeover path.
    let mut config = runtime.config().snapshot().as_ref().clone();
    config.proxy.mode = ProxyMode::Http;
    // Keep the port chosen in the UI across process restarts. Only the
    // platform-owned fields are forced: Android has no PAC/system-proxy
    // takeover path of its own, and the listener must stay on loopback.
    if config.proxy.port == 0 {
        config.proxy.port = 8443;
    }
    config.proxy.bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
    config.proxy.takeover = false;
    // The desktop defaults (CleanBrowsing / Applied Privacy) are often
    // unreachable from mobile networks. Seed domestic DoH endpoints only on a
    // fresh profile; afterwards the settings page owns these values.
    const DESKTOP_DOH: &str = "https://doh.cleanbrowsing.org/doh/security-filter/";
    if config.doh.primary == DESKTOP_DOH {
        config.doh.primary = "https://dns.alidns.com/dns-query".to_string();
        config.doh.fallback = "https://doh.pub/dns-query".to_string();
    }
    if config.doh.custom.is_empty() {
        config.doh.custom = vec![
            DohEndpoint {
                name: "AliDNS".to_string(),
                url: "https://dns.alidns.com/dns-query".to_string(),
                bootstrap_ip: Some("223.5.5.5".parse().unwrap()),
                enabled: true,
            },
            DohEndpoint {
                name: "DNSPod".to_string(),
                url: "https://doh.pub/dns-query".to_string(),
                bootstrap_ip: Some("1.12.12.12".parse().unwrap()),
                enabled: true,
            },
        ];
    }
    // Probe-only group: Cloudflare publishes ECHConfig for this host, so a
    // successful ECH handshake proves the Android build's ECH path end to end.
    // Idempotent: the group is persisted to config.json after the first start.
    if !config.groups.iter().any(|group| group.id == "echtest") {
        config.groups.push(GroupConfig {
            id: "echtest".to_string(),
            name: "ECH Test".to_string(),
            domains: vec!["crypto.cloudflare.com".to_string()],
            strategy: Strategy::Ech,
            enabled: true,
            sni: None,
            experimental: false,
            homepage: Some("https://crypto.cloudflare.com/cdn-cgi/trace".to_string()),
            ech_shared: true,
        });
    }
    runtime
        .update_config(config)
        .context("configuring the local probe proxy")?;

    let tokio = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("building the tokio runtime")?;

    *HOST.lock() = Some(Arc::new(Host { runtime, tokio }));
    Ok(())
}

fn host() -> Result<Arc<Host>> {
    HOST.lock()
        .clone()
        .context("nativeInit has not been called")
}

fn start_proxy() -> Result<()> {
    let _guard = LIFECYCLE_LOCK.lock();
    let host = host()?;
    host.tokio.block_on(host.runtime.start())
}

fn stop_proxy() {
    let _guard = LIFECYCLE_LOCK.lock();
    let host = HOST.lock().clone();
    if let Some(host) = host {
        let _ = host.tokio.block_on(host.runtime.stop());
    }
}

fn proxy_running() -> bool {
    match host() {
        Ok(host) => host.runtime.is_proxy_running(),
        Err(_) => false,
    }
}

fn status_json() -> String {
    match host() {
        Ok(host) => serde_json::to_string(&host.runtime.status_json())
            .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}")),
        Err(_) => "{\"error\":\"not initialized\"}".to_string(),
    }
}

fn config_json() -> String {
    match host() {
        Ok(host) => serde_json::to_string(&host.runtime.config_json())
            .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}")),
        Err(_) => "{\"error\":\"not initialized\"}".to_string(),
    }
}

/// Built-in catalog endpoints, exposed so the UI can offer a one-tap reset.
fn default_catalog_urls() -> String {
    serde_json::json!({
        "ip": hakimi_core::config::DEFAULT_CATALOG_IP,
        "doh": hakimi_core::config::DEFAULT_CATALOG_DOH,
    })
    .to_string()
}

fn apply_config(raw: &str) -> Result<()> {
    let host = host()?;
    let config: AppConfig = serde_json::from_str(raw).context("parsing config JSON")?;
    host.runtime.update_config(config)
}

fn set_group_enabled(id: &str, enabled: bool) -> Result<()> {
    host()?.runtime.set_group_enabled(id, enabled)?;
    Ok(())
}

fn upsert_group(raw: &str) -> Result<()> {
    let host = host()?;
    let group: GroupConfig = serde_json::from_str(raw).context("parsing group JSON")?;
    host.runtime.upsert_group(group)?;
    Ok(())
}

fn remove_group(id: &str) -> Result<()> {
    host()?.runtime.remove_group(id)?;
    Ok(())
}

fn ca_pem() -> String {
    match host() {
        Ok(host) => std::fs::read_to_string(host.runtime.paths().ca_cert_file())
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

fn log_path() -> String {
    match host() {
        Ok(host) => host.runtime.paths().log_file().display().to_string(),
        Err(_) => String::new(),
    }
}

fn diagnose(domain: &str) -> String {
    match host() {
        Ok(host) => {
            let diagnostics = host.tokio.block_on(host.runtime.diagnose(domain));
            serde_json::to_string(&diagnostics)
                .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"))
        }
        Err(_) => "{\"error\":\"not initialized\"}".to_string(),
    }
}

fn probe_sweep() -> Result<()> {
    let host = host()?;
    host.tokio.block_on(host.runtime.clone().probe_sweep());
    Ok(())
}

fn refresh_catalogs(force: bool) -> String {
    let Ok(host) = host() else {
        return "[]".to_string();
    };
    let results = host.tokio.block_on(host.runtime.refresh_catalogs(force));
    let items: Vec<serde_json::Value> = results
        .into_iter()
        .map(|result| match result {
            Ok(report) => serde_json::json!({ "ok": true, "report": report }),
            Err(error) => serde_json::json!({ "ok": false, "error": format!("{error:#}") }),
        })
        .collect();
    serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string())
}

fn export_diagnostics() -> Result<String> {
    let path = host()?.runtime.export_diagnostics()?;
    Ok(path.display().to_string())
}

fn set_ca_trusted(trusted: bool) {
    hakimi_core::ca::set_android_ca_trusted(trusted);
    let host = HOST.lock().clone();
    if let Some(host) = host {
        host.runtime.ca().invalidate_status();
    }
}

fn shutdown() {
    stop_proxy();
    *HOST.lock() = None;
}

fn new_string(env: &mut JNIEnv, value: impl AsRef<str>) -> jstring {
    match env.new_string(value.as_ref()) {
        Ok(value) => value.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn read_jstring(env: &mut JNIEnv, value: &JString) -> Result<String> {
    env.get_string(value)
        .map(|value| value.to_string_lossy().into_owned())
        .map_err(|error| anyhow::anyhow!("reading Java string: {error}"))
}

/// Boolean-returning JNI entry point helper: catches panics and records the
/// error for `lastError()`.
fn bool_entry(mut env: JNIEnv, action: impl FnOnce(&mut JNIEnv) -> Result<()>) -> jboolean {
    clear_error();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(&mut env)));
    match result {
        Ok(Ok(())) => JNI_TRUE,
        Ok(Err(error)) => {
            set_error(format!("{error:#}"));
            JNI_FALSE
        }
        Err(_) => {
            set_error("native panic");
            JNI_FALSE
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_init(
    env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jboolean {
    bool_entry(env, |env| {
        let data_dir = read_jstring(env, &data_dir)?;
        initialize(&data_dir)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_startProxy(
    env: JNIEnv,
    _class: JClass,
) -> jboolean {
    bool_entry(env, |_env| start_proxy())
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_stopProxy(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(stop_proxy));
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_isProxyRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if std::panic::catch_unwind(proxy_running).unwrap_or(false) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_shutdown(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(shutdown));
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_status(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(status_json))
        .unwrap_or_else(|_| "{\"error\":\"native panic\"}".to_string());
    new_string(&mut env, value)
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_caPem(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(ca_pem))
        .unwrap_or_default();
    new_string(&mut env, value)
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_logPath(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(log_path))
        .unwrap_or_default();
    new_string(&mut env, value)
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_setCaTrusted(
    _env: JNIEnv,
    _class: JClass,
    trusted: jboolean,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        set_ca_trusted(trusted != JNI_FALSE)
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_diagnose(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jstring {
    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let domain = read_jstring(&mut env, &domain).unwrap_or_default();
        if domain.is_empty() {
            "{\"error\":\"empty domain\"}".to_string()
        } else {
            diagnose(&domain)
        }
    }))
    .unwrap_or_else(|_| "{\"error\":\"native panic\"}".to_string());
    new_string(&mut env, value)
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_config(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(config_json))
        .unwrap_or_else(|_| "{\"error\":\"native panic\"}".to_string());
    new_string(&mut env, value)
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_defaultCatalogUrls(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(default_catalog_urls))
        .unwrap_or_else(|_| "{}".to_string());
    new_string(&mut env, value)
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_applyConfig(
    env: JNIEnv,
    _class: JClass,
    json: JString,
) -> jboolean {
    bool_entry(env, |env| {
        let json = read_jstring(env, &json)?;
        apply_config(&json)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_setGroupEnabled(
    env: JNIEnv,
    _class: JClass,
    id: JString,
    enabled: jboolean,
) -> jboolean {
    bool_entry(env, |env| {
        let id = read_jstring(env, &id)?;
        set_group_enabled(&id, enabled != JNI_FALSE)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_upsertGroup(
    env: JNIEnv,
    _class: JClass,
    json: JString,
) -> jboolean {
    bool_entry(env, |env| {
        let json = read_jstring(env, &json)?;
        upsert_group(&json)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_removeGroup(
    env: JNIEnv,
    _class: JClass,
    id: JString,
) -> jboolean {
    bool_entry(env, |env| {
        let id = read_jstring(env, &id)?;
        remove_group(&id)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_probeSweep(
    env: JNIEnv,
    _class: JClass,
) -> jboolean {
    bool_entry(env, |_env| probe_sweep())
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_refreshCatalogs(
    mut env: JNIEnv,
    _class: JClass,
    force: jboolean,
) -> jstring {
    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        refresh_catalogs(force != JNI_FALSE)
    }))
    .unwrap_or_else(|_| "[]".to_string());
    new_string(&mut env, value)
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_exportDiagnostics(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let value = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(export_diagnostics)) {
        Ok(Ok(path)) => path,
        Ok(Err(error)) => {
            set_error(format!("{error:#}"));
            String::new()
        }
        Err(_) => {
            set_error("native panic");
            String::new()
        }
    };
    new_string(&mut env, value)
}

#[no_mangle]
pub extern "system" fn Java_com_hakimi_probe_Native_lastError(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let value = LAST_ERROR.lock().clone().unwrap_or_default();
    new_string(&mut env, value)
}
