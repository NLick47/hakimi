use std::net::SocketAddr;
use std::path::Path;

#[cfg(target_os = "macos")]
use anyhow::bail;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::config::ProxyMode;
use std::time::Instant;
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
    #[serde(default)]
    applied_at: Option<DateTime<Utc>>,
}

/// Applies/restores the OS proxy setting. The original state is persisted before the first
/// change, so a crash still allows the next start to restore it.
pub struct SystemProxyManager {
    state_path: std::path::PathBuf,
    // `networksetup` subprocess queries are expensive on macOS; the status only
    // changes when this manager (or the user) touches the proxy, so cache it.
    status_cache: Mutex<Option<(Instant, Option<ProxyMode>, Option<String>, SystemProxyStatus)>>,
}

impl SystemProxyManager {
    pub fn new(state_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            state_path: state_path.into(),
            status_cache: Mutex::new(None),
        }
    }

    pub fn apply_pac(&self, pac_url: &str) -> Result<SystemProxyStatus> {
        self.save_original()?;
        platform_apply_pac(&self.state_path, pac_url)?;
        *self.status_cache.lock() = None;
        self.status(Some(ProxyMode::Pac), Some(pac_url.to_string()))
    }

    pub fn apply_http(&self, proxy: SocketAddr) -> Result<SystemProxyStatus> {
        self.save_original()?;
        platform_apply_http(&self.state_path, proxy)?;
        *self.status_cache.lock() = None;
        self.status(Some(ProxyMode::Http), Some(proxy.to_string()))
    }

    pub fn restore(&self) -> Result<bool> {
        if !self.state_path.exists() {
            return Ok(false);
        }
        let state: SavedState = read_json(&self.state_path).unwrap_or_default();
        platform_restore(&state)?;
        std::fs::remove_file(&self.state_path).ok();
        *self.status_cache.lock() = None;
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

    pub fn saved_state_exists(&self) -> bool {
        self.state_path.exists()
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
        applied_at: None,
    })
}

#[cfg(windows)]
const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(windows)]
fn platform_apply_pac(_state_path: &Path, pac_url: &str) -> Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .context("opening Internet Settings registry key")?;
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
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .context("opening Internet Settings registry key")?;
    let _ = key.delete_value("AutoConfigURL");
    let server = format!("http={proxy};https={proxy}", proxy = proxy);
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
fn platform_restore(state: &SavedState) -> Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

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
    let output = std::process::Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .context("running networksetup -listallnetworkservices")?;
    if !output.status.success() {
        bail!("networksetup failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty() && !line.starts_with('*'))
        .map(|line| line.trim().to_string())
        .collect())
}

#[cfg(target_os = "macos")]
fn run_networksetup(args: &[&str]) -> Result<()> {
    let output = std::process::Command::new("networksetup")
        .args(args)
        .output()
        .with_context(|| format!("running networksetup {args:?}"))?;
    if !output.status.success() {
        bail!(
            "networksetup failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

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
    let output = std::process::Command::new("networksetup")
        .args(args)
        .output()
        .context("running networksetup query")?;
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let current = text
        .lines()
        .find(|line| line.trim_start().starts_with("URL:"))
        .map(|line| line.trim_start_matches("URL:").trim().to_string())
        .or_else(|| {
            text.lines()
                .find(|line| line.trim_start().starts_with("Server:"))
                .map(|line| line.trim_start_matches("Server:").trim().to_string())
        });
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
}
