use std::net::SocketAddr;
use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::config::ProxyMode;
use std::time::{Duration, Instant};
use crate::util::{atomic_write_json, now, read_json};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxyStatus {
    pub supported: bool,
    pub mode: String,
    pub applied: bool,
    pub expected: Option<String>,
    pub current: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedState {
    #[serde(default)]
    platform: String,
    #[serde(default)]
    proxy_enable: Option<u32>,
    #[serde(default)]
    auto_config_url: Option<String>,
    #[serde(default)]
    proxy_server: Option<String>,
    #[serde(default)]
    proxy_override: Option<String>,
    #[serde(default)]
    mac_services: Vec<String>,
    /// WinINet's per-connection flags captured before the first takeover.
    /// The legacy registry values are not authoritative on Windows: WinINet
    /// reconciles them with `Connections\DefaultConnectionSettings` on every
    /// settings reload, so a restore that only rewrites the legacy values can
    /// be undone by the next notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    win_proxy_flags: Option<u32>,
    #[serde(default)]
    applied_at: Option<DateTime<Utc>>,
}

/// How long a PAC health result may be reused. Reading the registry is cheap
/// on Windows, so it is answered fresh on every call; macOS spawns `scutil`,
/// so it gets a short window. Any mutation of the OS proxy invalidates the
/// entry first, so this process never contradicts its own writes.
#[cfg(windows)]
const PAC_HEALTH_TTL: Duration = Duration::ZERO;
#[cfg(not(windows))]
const PAC_HEALTH_TTL: Duration = Duration::from_secs(2);

/// Applies/restores the OS proxy setting. The original state is persisted before the first
/// change, so a crash still allows the next start to restore it.
pub struct SystemProxyManager {
    state_path: std::path::PathBuf,
    // `networksetup` subprocess queries are expensive on macOS; the status only
    // changes when this manager (or the user) touches the proxy, so cache it.
    status_cache: Mutex<Option<(Instant, Option<ProxyMode>, Option<String>, SystemProxyStatus)>>,
    // The health probe has the same platform asymmetry: a registry read on
    // Windows, a subprocess on macOS. Keyed by the expected URL and
    // invalidated by every mutation, so a fresh apply is never judged by a
    // pre-apply observation.
    health_cache: Mutex<Option<(Instant, String, bool)>>,
}

impl SystemProxyManager {
    pub fn new(state_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            state_path: state_path.into(),
            status_cache: Mutex::new(None),
            health_cache: Mutex::new(None),
        }
    }

    pub fn apply_pac(&self, pac_url: &str) -> Result<SystemProxyStatus> {
        self.save_original()?;
        platform_apply_pac(&self.state_path, pac_url)?;
        self.invalidate_caches();
        self.status(Some(ProxyMode::Pac), Some(pac_url.to_string()))
    }

    pub fn apply_http(&self, proxy: SocketAddr) -> Result<SystemProxyStatus> {
        self.save_original()?;
        platform_apply_http(&self.state_path, proxy)?;
        self.invalidate_caches();
        self.status(Some(ProxyMode::Http), Some(proxy.to_string()))
    }

    pub fn restore(&self) -> Result<bool> {
        if !self.state_path.exists() {
            return Ok(false);
        }
        let state: SavedState = read_json(&self.state_path).unwrap_or_default();
        platform_restore(&state)?;
        std::fs::remove_file(&self.state_path).ok();
        self.invalidate_caches();
        Ok(true)
    }

    pub fn status(
        &self,
        mode: Option<ProxyMode>,
        expected: Option<String>,
    ) -> Result<SystemProxyStatus> {
        const STATUS_TTL: std::time::Duration = std::time::Duration::from_secs(3);
        {
            let cache = self.status_cache.lock();
            if let Some((at, cached_mode, cached_expected, status)) = cache.as_ref() {
                if at.elapsed() < STATUS_TTL && *cached_mode == mode && *cached_expected == expected
                {
                    return Ok(status.clone());
                }
            }
        }
        let CurrentProxy { supported, current } = platform_current(mode)?;
        let applied = match (&current, &expected) {
            (Some(current), Some(expected)) => current.contains(expected),
            _ => false,
        };
        let status = SystemProxyStatus {
            supported,
            mode: mode.map(mode_name).unwrap_or("off").to_string(),
            applied,
            expected: expected.clone(),
            current,
            error: None,
        };
        *self.status_cache.lock() =
            Some((std::time::Instant::now(), mode, expected, status.clone()));
        Ok(status)
    }

    /// True when at least one network service has the expected PAC URL *and* the
    /// enabled flag set — the URL alone does not route traffic.
    pub fn pac_health(&self, expected_url: &str) -> bool {
        {
            let cache = self.health_cache.lock();
            if let Some((at, url, healthy)) = cache.as_ref() {
                if url == expected_url && at.elapsed() < PAC_HEALTH_TTL {
                    return *healthy;
                }
            }
        }
        let healthy = platform_pac_health(expected_url);
        *self.health_cache.lock() = Some((Instant::now(), expected_url.to_string(), healthy));
        healthy
    }

    /// Switch every network service's automatic proxy off. Used when a stale
    /// takeover points at a paused/broken instance: browsing keeps working
    /// directly while the environment is being fixed.
    pub fn pac_disable(&self) {
        platform_pac_disable();
        self.invalidate_caches();
    }

    pub fn saved_state_exists(&self) -> bool {
        self.state_path.exists()
    }

    fn invalidate_caches(&self) {
        *self.status_cache.lock() = None;
        *self.health_cache.lock() = None;
    }

    fn save_original(&self) -> Result<()> {
        if self.state_path.exists() {
            return Ok(());
        }
        let state = platform_snapshot()?;
        if let Some(parent) = self.state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut state = state;
        state.applied_at = Some(now());
        atomic_write_json(&self.state_path, &state)?;
        Ok(())
    }
}

fn mode_name(mode: ProxyMode) -> &'static str {
    match mode {
        ProxyMode::Pac => "pac",
        ProxyMode::Http => "http",
        ProxyMode::Off => "off",
    }
}

/// The proxy address the system reports, in the same shape as the address
/// the proxy announces.
///
/// macOS prints a web proxy as two lines ("Server:" and "Port:").  Dropping
/// the port makes the comparison with the announced address fail, so the
/// proxy would look unapplied even while it routes the traffic.
fn parse_current_proxy(text: &str, mode: Option<ProxyMode>) -> Option<String> {
    let value = |key: &str| {
        text.lines().find_map(|line| {
            let (name, value) = line.trim_start().split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case(key)
                .then(|| value.trim().to_string())
        })
    };
    let server = || {
        let server = value("Server")?;
        Some(match value("Port") {
            Some(port) => format!("{server}:{port}"),
            None => server,
        })
    };
    match mode {
        Some(ProxyMode::Http) => server(),
        _ => value("URL").or_else(server),
    }
}

#[derive(Debug)]
struct CurrentProxy {
    supported: bool,
    current: Option<String>,
}

#[cfg(windows)]
fn platform_snapshot() -> Result<SavedState> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, winreg::enums::KEY_READ)
        .context("opening Internet Settings registry key")?;
    Ok(SavedState {
        platform: "windows".into(),
        proxy_enable: key.get_value("ProxyEnable").ok(),
        auto_config_url: key.get_value("AutoConfigURL").ok(),
        proxy_server: key.get_value("ProxyServer").ok(),
        proxy_override: key.get_value("ProxyOverride").ok(),
        mac_services: Vec::new(),
        win_proxy_flags: read_connection_flags(),
        applied_at: None,
    })
}

#[cfg(windows)]
const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(windows)]
const INTERNET_CONNECTIONS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

/// WinINet's authoritative proxy mode lives in the per-connection settings
/// blob, not in the legacy `AutoConfigURL`/`ProxyEnable` values. Reading the
/// blob lets a restore put back the exact mode the user had (including
/// auto-detect), instead of guessing from the legacy values.
#[cfg(windows)]
fn read_connection_flags() -> Option<u32> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_CONNECTIONS, KEY_READ)
        .ok()?;
    let blob = key.get_raw_value("DefaultConnectionSettings").ok()?;
    let flags = blob.bytes.get(8..12)?;
    Some(u32::from_le_bytes(flags.try_into().ok()?))
}

/// Write WinINet's per-connection proxy configuration.
///
/// This is the state WinINet enforces: on a settings-changed notification it
/// refreshes the legacy registry values from the blob. Writing only the legacy
/// values is therefore not enough — when the blob still says "direct", the
/// notification deletes the freshly written `AutoConfigURL` again. Updating
/// the blob first keeps the two views consistent, so both survive.
#[cfg(windows)]
fn apply_per_connection(
    flags: u32,
    pac_url: Option<&str>,
    proxy_server: Option<&str>,
    proxy_bypass: Option<&str>,
) -> Result<()> {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION,
        INTERNET_PER_CONN_AUTOCONFIG_URL, INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTIONW,
        INTERNET_PER_CONN_OPTIONW_0, INTERNET_PER_CONN_OPTION_LISTW,
        INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER,
    };

    // The API reads these buffers synchronously; keep them alive until it
    // returns.
    let mut pac: Option<Vec<u16>> = pac_url.map(|url| url.encode_utf16().chain([0]).collect());
    let mut server: Option<Vec<u16>> = proxy_server.map(|s| s.encode_utf16().chain([0]).collect());
    let mut bypass: Option<Vec<u16>> = proxy_bypass.map(|s| s.encode_utf16().chain([0]).collect());

    let string_option = |option: u32, value: *mut u16| INTERNET_PER_CONN_OPTIONW {
        dwOption: option,
        Value: INTERNET_PER_CONN_OPTIONW_0 { pszValue: value },
    };

    let mut options: Vec<INTERNET_PER_CONN_OPTIONW> = Vec::with_capacity(4);
    options.push(INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_FLAGS,
        Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: flags },
    });
    if let Some(server) = server.as_mut() {
        options.push(string_option(
            INTERNET_PER_CONN_PROXY_SERVER,
            server.as_mut_ptr(),
        ));
    }
    if let Some(bypass) = bypass.as_mut() {
        options.push(string_option(
            INTERNET_PER_CONN_PROXY_BYPASS,
            bypass.as_mut_ptr(),
        ));
    }
    if let Some(pac) = pac.as_mut() {
        options.push(string_option(
            INTERNET_PER_CONN_AUTOCONFIG_URL,
            pac.as_mut_ptr(),
        ));
    }

    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        // NULL selects the LAN connection, which the legacy values describe.
        pszConnection: std::ptr::null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    let pointer: *const std::ffi::c_void = std::ptr::from_mut(&mut list).cast();
    let ok = unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            pointer,
            list.dwSize,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("setting per-connection proxy options");
    }
    Ok(())
}

#[cfg(windows)]
fn platform_apply_pac(_state_path: &Path, pac_url: &str) -> Result<()> {
    use windows_sys::Win32::Networking::WinInet::{PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT};
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    apply_per_connection(
        PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL,
        Some(pac_url),
        None,
        None,
    )
    .context("applying the PAC through WinINet")?;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .context("opening Internet Settings registry key")?;
    // Mirror the legacy values for readers that do not go through WinINet,
    // including this crate's health probe. The blob now carries the same PAC,
    // so the notification cannot undo them.
    key.set_value("AutoConfigURL", &pac_url)
        .context("setting AutoConfigURL")?;
    // PAC takes precedence; disable the fixed proxy so a stale old value cannot win.
    key.set_value("ProxyEnable", &0u32)
        .context("disabling fixed proxy")?;
    notify_proxy_changed();
    Ok(())
}

#[cfg(windows)]
fn platform_apply_http(_state_path: &Path, proxy: SocketAddr) -> Result<()> {
    use windows_sys::Win32::Networking::WinInet::{PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY};
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let server = format!("http={proxy};https={proxy}", proxy = proxy);
    apply_per_connection(
        PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY,
        None,
        Some(&server),
        Some("<local>"),
    )
    .context("applying the HTTP proxy through WinINet")?;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .context("opening Internet Settings registry key")?;
    let _ = key.delete_value("AutoConfigURL");
    key.set_value("ProxyServer", &server)
        .context("setting ProxyServer")?;
    key.set_value("ProxyOverride", &"<local>")
        .context("setting ProxyOverride")?;
    key.set_value("ProxyEnable", &1u32)
        .context("enabling fixed proxy")?;
    notify_proxy_changed();
    Ok(())
}

#[cfg(windows)]
fn platform_pac_health(expected_url: &str) -> bool {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;
    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ)
    else {
        return false;
    };
    let Ok(url) = key.get_value::<String, _>("AutoConfigURL") else {
        return false;
    };
    url == expected_url
}

#[cfg(windows)]
fn platform_pac_disable() {
    use windows_sys::Win32::Networking::WinInet::{
        PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
    };
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
    else {
        return;
    };
    // Only this instance's PAC is ours to clear: a user-configured fixed proxy
    // stays enabled.
    let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
    let server: Option<String> = key.get_value("ProxyServer").ok();
    let bypass: Option<String> = key.get_value("ProxyOverride").ok();
    let present_server = server.as_deref().filter(|server| !server.is_empty());
    let manual = enabled == 1 && present_server.is_some();
    // Clear only the PAC bit; keep auto-detect and any manual proxy the user
    // configured for themselves.
    let mut flags = read_connection_flags().unwrap_or(PROXY_TYPE_DIRECT);
    flags &= !PROXY_TYPE_AUTO_PROXY_URL;
    if manual {
        flags |= PROXY_TYPE_PROXY;
    } else {
        flags &= !PROXY_TYPE_PROXY;
    }
    if flags == 0 {
        flags = PROXY_TYPE_DIRECT;
    }
    if let Err(error) = apply_per_connection(
        flags,
        None,
        if manual { present_server } else { None },
        if manual { bypass.as_deref() } else { None },
    ) {
        tracing::warn!(error = %error, "failed to clear the per-connection PAC setting");
    }
    let _ = key.delete_value("AutoConfigURL");
    // WinINet keeps the previous PAC in memory until it is told the settings
    // changed; without this the browser would keep dialing the dead PAC port
    // after a takeover was rolled back.
    notify_proxy_changed();
}

/// Reconcile the captured per-connection flags with the values that are
/// actually being restored: never keep a mode bit whose value is missing, and
/// never pass a value without its mode bit (that inconsistency is what makes
/// WinINet drop the PAC on the next reload). Unrelated bits, such as
/// auto-detect, are preserved.
#[cfg(windows)]
fn restore_flags(saved: Option<u32>, has_pac: bool, has_manual: bool) -> u32 {
    use windows_sys::Win32::Networking::WinInet::{
        PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
    };

    let mut flags = saved.unwrap_or(PROXY_TYPE_DIRECT);
    if has_pac {
        flags |= PROXY_TYPE_AUTO_PROXY_URL;
    } else {
        flags &= !PROXY_TYPE_AUTO_PROXY_URL;
    }
    if has_manual {
        flags |= PROXY_TYPE_PROXY;
    } else {
        flags &= !PROXY_TYPE_PROXY;
    }
    if flags == 0 {
        flags = PROXY_TYPE_DIRECT;
    }
    flags
}

#[cfg(windows)]
fn platform_restore(state: &SavedState) -> Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let auto = state
        .auto_config_url
        .as_deref()
        .filter(|url| !url.is_empty());
    let manual_server = state
        .proxy_enable
        .filter(|enabled| *enabled == 1)
        .and(state.proxy_server.as_deref())
        .filter(|server| !server.is_empty());
    let bypass = manual_server.and(state.proxy_override.as_deref());

    // Restore the per-connection state first: it is what WinINet enforces on
    // the next settings reload. Restoring only the legacy values below would
    // be reverted by that reload.
    let flags = restore_flags(
        state.win_proxy_flags,
        auto.is_some(),
        manual_server.is_some(),
    );
    if let Err(error) = apply_per_connection(flags, auto, manual_server, bypass) {
        tracing::warn!(error = %error, "failed to restore per-connection proxy settings");
    }

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .context("opening Internet Settings registry key")?;
    match state.proxy_enable {
        Some(value) => key.set_value("ProxyEnable", &value)?,
        None => {
            let _ = key.delete_value("ProxyEnable");
        }
    }
    match &state.auto_config_url {
        Some(value) => key.set_value("AutoConfigURL", value)?,
        None => {
            let _ = key.delete_value("AutoConfigURL");
        }
    }
    match &state.proxy_server {
        Some(value) => key.set_value("ProxyServer", value)?,
        None => {
            let _ = key.delete_value("ProxyServer");
        }
    }
    match &state.proxy_override {
        Some(value) => key.set_value("ProxyOverride", value)?,
        None => {
            let _ = key.delete_value("ProxyOverride");
        }
    }
    notify_proxy_changed();
    Ok(())
}

#[cfg(windows)]
fn platform_current(mode: Option<ProxyMode>) -> Result<CurrentProxy> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ)
        .context("opening Internet Settings registry key")?;
    let auto: Option<String> = key.get_value("AutoConfigURL").ok();
    let server: Option<String> = key.get_value("ProxyServer").ok();
    let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
    let current = match mode {
        Some(ProxyMode::Pac) => auto,
        Some(ProxyMode::Http) => {
            if enabled == 1 {
                server
            } else {
                None
            }
        }
        _ => auto.or(server),
    };
    Ok(CurrentProxy {
        supported: true,
        current,
    })
}

#[cfg(windows)]
fn notify_proxy_changed() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
    }
}

#[cfg(target_os = "macos")]
fn platform_snapshot() -> Result<SavedState> {
    Ok(SavedState {
        platform: "macos".into(),
        mac_services: list_network_services()?,
        ..Default::default()
    })
}

#[cfg(target_os = "macos")]
fn list_network_services() -> Result<Vec<String>> {
    let text = run_networksetup_with_timeout(&["-listallnetworkservices"], NETWORKSETUP_TIMEOUT_SECS)?;
    let text = text.as_str();
    Ok(text
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty() && !line.starts_with('*'))
        .map(|line| line.trim().to_string())
        .collect())
}

#[cfg(target_os = "macos")]
fn run_networksetup(args: &[&str]) -> Result<()> {
    run_networksetup_with_timeout(args, NETWORKSETUP_TIMEOUT_SECS).map(|_| ())
}

/// `networksetup` serialises on the system configuration daemon and is known
/// to hang for seconds when that daemon is busy. Every call is bounded so a
/// stuck invocation cannot stall the health check or a self-heal.
fn run_networksetup_with_timeout(args: &[&str], timeout_secs: u64) -> Result<String> {
    run_command_with_timeout("networksetup", args, timeout_secs)
}

/// Run a child process with a hard deadline. The program is a parameter so the
/// timeout behavior can be tested without a hanging `networksetup`.
fn run_command_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> Result<String> {
    use std::io::Read;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {program} {args:?}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    // Poll for exit FIRST and read the pipes only after: `read_to_string`
    // blocks until the pipe closes, which only happens when the child exits,
    // so reading first would make the deadline unreachable for a hung child.
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if std::time::Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{program} {args:?} timed out after {timeout_secs}s");
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    };
    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    if !status.success() {
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(stderr.as_bytes()).trim()
        );
    }
    Ok(stdout)
}

const NETWORKSETUP_TIMEOUT_SECS: u64 = 3;

#[cfg(target_os = "macos")]
fn platform_apply_pac(_state_path: &Path, pac_url: &str) -> Result<()> {
    for service in list_network_services()? {
        run_networksetup(&["-setautoproxyurl", &service, pac_url])?;
        run_networksetup(&["-setautoproxystate", &service, "on"])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_apply_http(_state_path: &Path, proxy: SocketAddr) -> Result<()> {
    for service in list_network_services()? {
        run_networksetup(&[
            "-setwebproxy",
            &service,
            &proxy.ip().to_string(),
            &proxy.port().to_string(),
        ])?;
        run_networksetup(&[
            "-setsecurewebproxy",
            &service,
            &proxy.ip().to_string(),
            &proxy.port().to_string(),
        ])?;
        run_networksetup(&["-setwebproxystate", &service, "on"])?;
        run_networksetup(&["-setsecurewebproxystate", &service, "on"])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_pac_health(expected_url: &str) -> bool {
    // `scutil --proxy` is one fast subprocess that reports the effective system
    // configuration; the per-service `networksetup` path spawns 6-10 calls that
    // serialise on configd and occasionally hang for seconds.
    if let Ok(output) = std::process::Command::new("scutil").arg("--proxy").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let enabled = text
                .lines()
                .any(|line| line.contains("ProxyAutoConfigEnable : 1"));
            let url_matches = text
                .lines()
                .any(|line| line.contains("ProxyAutoConfigURLString") && line.contains(expected_url));
            return enabled && url_matches;
        }
    }
    // Fallback: the per-service check, now bounded by the networksetup timeout.
    let Ok(services) = list_network_services() else {
        return false;
    };
    services.iter().any(|service| {
        let Ok(output) = run_networksetup_with_timeout(&["-getautoproxyurl", service], 2) else {
            return false;
        };
        // A matching URL alone is not enough: the enabled flag is what actually
        // routes traffic through the PAC.
        output.contains("Enabled: Yes") && output.contains(expected_url)
    })
}

#[cfg(target_os = "macos")]
fn platform_pac_disable() {
    if let Ok(services) = list_network_services() {
        for service in services {
            let _ = run_networksetup(&["-setautoproxystate", &service, "off"]);
        }
    }
}

#[cfg(target_os = "macos")]
fn platform_restore(state: &SavedState) -> Result<()> {
    for service in &state.mac_services {
        let _ = run_networksetup(&["-setautoproxystate", service, "off"]);
        let _ = run_networksetup(&["-setwebproxystate", service, "off"]);
        let _ = run_networksetup(&["-setsecurewebproxystate", service, "off"]);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_current(mode: Option<ProxyMode>) -> Result<CurrentProxy> {
    let services = list_network_services()?;
    let Some(service) = services.first() else {
        return Ok(CurrentProxy {
            supported: true,
            current: None,
        });
    };
    let args: Vec<&str> = match mode {
        Some(ProxyMode::Http) => vec!["-getwebproxy", service.as_str()],
        _ => vec!["-getautoproxyurl", service.as_str()],
    };
    let text = run_networksetup_with_timeout(&args, NETWORKSETUP_TIMEOUT_SECS)?;
    let current = parse_current_proxy(&text, mode);
    Ok(CurrentProxy {
        supported: true,
        current,
    })
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_snapshot() -> Result<SavedState> {
    Ok(SavedState {
        platform: std::env::consts::OS.to_string(),
        ..Default::default()
    })
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_apply_pac(_state_path: &Path, _pac_url: &str) -> Result<()> {
    anyhow::bail!("system proxy takeover is only implemented on Windows and macOS")
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_apply_http(_state_path: &Path, _proxy: SocketAddr) -> Result<()> {
    anyhow::bail!("system proxy takeover is only implemented on Windows and macOS")
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_restore(_state: &SavedState) -> Result<()> {
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_pac_health(_expected_url: &str) -> bool {
    true
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_pac_disable() {}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_current(_mode: Option<ProxyMode>) -> Result<CurrentProxy> {
    Ok(CurrentProxy {
        supported: false,
        current: None,
    })
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn snapshot_has_platform() {
        let state = platform_snapshot().unwrap();
        assert_eq!(state.platform, "windows");
    }

    #[test]
    fn restore_flags_match_the_values_being_restored() {
        use windows_sys::Win32::Networking::WinInet::{
            PROXY_TYPE_AUTO_DETECT, PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
        };

        // A captured "direct" mode gains the PAC bit when a PAC is restored.
        assert_eq!(
            restore_flags(Some(PROXY_TYPE_DIRECT), true, false),
            PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL
        );
        // A captured PAC is dropped when the snapshot has no PAC URL.
        assert_eq!(
            restore_flags(
                Some(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL),
                false,
                false
            ),
            PROXY_TYPE_DIRECT
        );
        // Manual proxy and PAC can coexist.
        assert_eq!(
            restore_flags(
                Some(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL),
                true,
                true
            ),
            PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_PROXY
        );
        // Without a captured blob, the flags are derived from the values.
        assert_eq!(
            restore_flags(None, false, true),
            PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
        );
        // Unrelated bits such as auto-detect survive the reconciliation.
        assert_eq!(
            restore_flags(Some(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT), false, false),
            PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT
        );
    }
}

#[cfg(test)]
mod process_timeout_tests {
    use super::*;

    /// A hung child must be killed at the deadline, not waited out. The old
    /// implementation blocked in `read_to_string` until the child exited, so
    /// the timeout never fired.
    #[test]
    fn process_timeout_is_enforced() {
        let started = std::time::Instant::now();
        let result = run_command_with_timeout("/bin/sh", &["-c", "sleep 8"], 1);
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "timeout not enforced: waited {elapsed:?} for a hung child"
        );
        assert!(result.is_err(), "a killed child must surface as an error");
    }
}

#[cfg(test)]
mod current_proxy_tests {
    use super::*;

    /// macOS reports a web proxy as two lines. The address has to keep the
    /// port, otherwise the proxy looks unapplied even while it is routing.
    #[test]
    fn the_web_proxy_address_keeps_its_port() {
        let text = "Enabled: Yes\nServer: 127.0.0.1\nPort: 8443\nAuthenticated Proxy Enabled: 0\n";
        let current = parse_current_proxy(text, Some(ProxyMode::Http)).unwrap();
        assert_eq!(current, "127.0.0.1:8443");
        // The comparison the status does must now succeed.
        assert!(current.contains("127.0.0.1:8443"));
    }

    #[test]
    fn the_pac_url_is_read_as_a_whole() {
        let text = "URL: http://127.0.0.1:8443/proxy.pac\nEnabled: Yes\n";
        let current = parse_current_proxy(text, Some(ProxyMode::Pac)).unwrap();
        assert_eq!(current, "http://127.0.0.1:8443/proxy.pac");
        assert!(current.contains("http://127.0.0.1:8443/proxy.pac"));
    }

    /// Without a mode the URL wins, and the web proxy is the fallback.
    #[test]
    fn the_fallback_reads_the_web_proxy() {
        let text = "Enabled: Yes\nServer: 127.0.0.1\nPort: 8443\n";
        assert_eq!(
            parse_current_proxy(text, None),
            Some("127.0.0.1:8443".to_string())
        );
        let text = "URL: http://127.0.0.1:8443/proxy.pac\nEnabled: Yes\n";
        assert_eq!(
            parse_current_proxy(text, None),
            Some("http://127.0.0.1:8443/proxy.pac".to_string())
        );
    }
}
