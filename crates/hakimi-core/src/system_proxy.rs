use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::ProxyMode;
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
    /// The proxy mode that was applied when the snapshot was taken. `None`
    /// means a snapshot written by an older version, which only ever took
    /// over PAC on macOS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<ProxyMode>,
    /// Original PAC settings per macOS network service. Saved before the PAC
    /// takeover so restore can put back the user's own URL/enabled flag
    /// instead of blindly disabling the protocol.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mac_pac: Vec<MacPacState>,
    /// Original web/secure proxy settings per service, for HTTP mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mac_http: Vec<MacHttpState>,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacPacState {
    service: String,
    enabled: bool,
    url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacHttpState {
    service: String,
    web_enabled: bool,
    web_server: Option<String>,
    web_port: Option<u16>,
    secure_enabled: bool,
    secure_server: Option<String>,
    secure_port: Option<u16>,
}

/// Whether this platform has a system-wide proxy setting this process can
/// change. Linux has no single one: callers point tools at the proxy through
/// environment variables instead.
pub fn takeover_supported() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

/// Applies/restores the OS proxy setting. The original state is persisted before the first
/// change, so a crash still allows the next start to restore it.
pub struct SystemProxyManager {
    state_path: std::path::PathBuf,
}

impl SystemProxyManager {
    pub fn new(state_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            state_path: state_path.into(),
        }
    }

    pub fn apply_pac(&self, pac_url: &str) -> Result<SystemProxyStatus> {
        self.save_original(ProxyMode::Pac, Some(pac_url))?;
        let failed = platform_apply_pac(&self.state_path, pac_url)?;
        let mut status = self.verify(ProxyMode::Pac, pac_url.to_string())?;
        attach_apply_warnings(&mut status, &failed);
        Ok(status)
    }

    pub fn apply_http(&self, proxy: SocketAddr) -> Result<SystemProxyStatus> {
        self.save_original(ProxyMode::Http, None)?;
        let failed = platform_apply_http(&self.state_path, proxy)?;
        let mut status = self.verify(ProxyMode::Http, proxy.to_string())?;
        attach_apply_warnings(&mut status, &failed);
        Ok(status)
    }

    pub fn restore(&self) -> Result<bool> {
        if !self.state_path.exists() {
            return Ok(false);
        }
        let state: SavedState = read_json(&self.state_path).unwrap_or_default();
        platform_restore(&state)?;
        std::fs::remove_file(&self.state_path).ok();
        Ok(true)
    }

    /// Drop the snapshot without touching the system settings.
    ///
    /// Used when the setting no longer belongs to us — another client took the
    /// system proxy over. Restoring the snapshot then would put *our* captured
    /// state back on top of theirs, so the only safe move is to forget it.
    pub fn forget(&self) {
        match std::fs::remove_file(&self.state_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(error = %error, path = %self.state_path.display(), "could not delete the system proxy snapshot")
            }
        }
    }

    /// Read the OS back and report whether it still matches `expected`.
    ///
    /// `None` means the OS could not be read at all, which is not evidence of
    /// a takeover loss — callers must not treat it as one.
    pub fn still_ours(&self, mode: ProxyMode, expected: &str) -> Option<bool> {
        self.status(Some(mode), Some(expected.to_string()))
            .ok()
            .map(|status| status.applied)
    }

    pub fn status(
        &self,
        mode: Option<ProxyMode>,
        expected: Option<String>,
    ) -> Result<SystemProxyStatus> {
        let CurrentProxy { supported, current } = platform_current(mode)?;
        let applied = match (&current, &expected) {
            (Some(current), Some(expected)) => proxy_setting_matches(current, expected),
            _ => false,
        };
        Ok(SystemProxyStatus {
            supported,
            mode: mode.map(mode_name).unwrap_or("off").to_string(),
            applied,
            expected,
            current,
            error: None,
        })
    }

    /// Read the value back once after writing. macOS propagates proxy changes
    /// through configd, so a write can take a few hundred milliseconds to show
    /// up in `scutil`; retry briefly instead of reporting a false failure.
    fn verify(&self, mode: ProxyMode, expected: String) -> Result<SystemProxyStatus> {
        let attempts = if cfg!(target_os = "macos") { 5 } else { 1 };
        let mut last = None;
        for attempt in 0..attempts {
            let status = self.status(Some(mode), Some(expected.clone()));
            if let Ok(status) = &status {
                if status.applied {
                    return Ok(status.clone());
                }
            }
            last = Some(status);
            if attempt + 1 < attempts {
                std::thread::sleep(Duration::from_millis(150));
            }
        }
        match last.expect("verify always runs at least once") {
            Ok(mut status) => {
                if status.error.is_none() {
                    status.error = Some("system proxy setting was not applied".into());
                }
                Ok(status)
            }
            Err(error) => Err(error),
        }
    }

    /// Switch every network service's automatic proxy off. Used when a stale
    /// takeover points at a paused/broken instance: browsing keeps working
    /// directly while the environment is being fixed.
    pub fn pac_disable(&self) {
        platform_pac_disable();
    }

    pub fn saved_state_exists(&self) -> bool {
        self.state_path.exists()
    }

    fn save_original(&self, mode: ProxyMode, own_pac: Option<&str>) -> Result<()> {
        if self.state_path.exists() {
            return Ok(());
        }
        let mut state = platform_snapshot(mode)?;
        // A killed previous run can leave *our* PAC enabled. Recording that as
        // the user's original state would make restore put the takeover back —
        // the "pause does not switch the proxy off" bug.
        if let Some(own) = own_pac {
            // Windows keeps the same value in the registry; clearing it keeps a
            // killed run's PAC out of the "original" state there too.
            if state.auto_config_url.as_deref() == Some(own) {
                state.auto_config_url = None;
            }
            for pac in &mut state.mac_pac {
                if pac.url.as_deref() == Some(own) {
                    pac.enabled = false;
                    pac.url = None;
                }
            }
        }
        state.mode = Some(mode);
        if let Some(parent) = self.state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        state.applied_at = Some(now());
        atomic_write_json(&self.state_path, &state)?;
        Ok(())
    }
}

/// Keep partial write failures in the status so the UI can show a warning even
/// when the currently active service did receive the setting.
fn attach_apply_warnings(status: &mut SystemProxyStatus, failed: &[String]) {
    if failed.is_empty() {
        return;
    }
    let detail = if failed.len() == 1 {
        failed[0].clone()
    } else {
        format!("{} 个网络服务写入失败（首个：{}）", failed.len(), failed[0])
    };
    status.error = Some(match status.error.take() {
        Some(existing) => format!("{existing}; {detail}"),
        None => detail,
    });
}

fn mode_name(mode: ProxyMode) -> &'static str {
    match mode {
        ProxyMode::Pac => "pac",
        ProxyMode::Http => "http",
        ProxyMode::Off => "off",
    }
}

/// Compare the OS-reported setting with the one this instance wrote.
///
/// PAC values are URLs and keep the existing substring contract. HTTP values
/// are socket addresses: macOS prints `Server: ::1` and `Port: 8443`, which
/// becomes `::1:8443`, while `SocketAddr::to_string()` keeps the IPv6 brackets
/// (`[::1]:8443`). Accept either spelling.
fn proxy_setting_matches(current: &str, expected: &str) -> bool {
    if current.contains(expected) {
        return true;
    }
    expected
        .parse::<SocketAddr>()
        .ok()
        .is_some_and(|address| current == format!("{}:{}", address.ip(), address.port()))
}

#[derive(Debug)]
struct CurrentProxy {
    supported: bool,
    current: Option<String>,
}

fn mac_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (name, value) = line.trim_start().split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(key)
            .then(|| value.trim().to_string())
    })
}

fn mac_enabled(text: &str) -> bool {
    mac_value(text, "Enabled").as_deref() == Some("Yes")
}

/// The proxy address the system reports, in the same shape as the address
/// the proxy announces.
///
/// macOS prints a web proxy as two lines ("Server:" and "Port:").  Dropping
/// the port makes the comparison with the announced address fail, so the
/// proxy would look unapplied even while it routes the traffic.
fn parse_current_proxy(text: &str, mode: Option<ProxyMode>) -> Option<String> {
    let server = || {
        let server = mac_value(text, "Server")?;
        Some(match mac_value(text, "Port") {
            Some(port) => format!("{server}:{port}"),
            None => server,
        })
    };
    match mode {
        Some(ProxyMode::Http) => server(),
        _ => mac_value(text, "URL").or_else(server),
    }
}

/// `networksetup` reports a stale URL/server even when the protocol is off.
/// Only an enabled protocol counts as "the setting is in effect".
fn parse_networksetup_proxy(text: &str, mode: ProxyMode) -> Option<String> {
    if mac_enabled(text) {
        parse_current_proxy(text, Some(mode))
    } else {
        None
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_mac_pac(text: &str) -> (bool, Option<String>) {
    (
        mac_enabled(text),
        mac_value(text, "URL").filter(|url| !url.is_empty()),
    )
}

#[cfg(any(target_os = "macos", test))]
fn parse_mac_http_proxy(text: &str) -> (bool, Option<String>, Option<u16>) {
    (
        mac_enabled(text),
        mac_value(text, "Server").filter(|server| !server.is_empty()),
        mac_value(text, "Port").and_then(|port| port.parse().ok()),
    )
}

/// The proxy settings that decide whether our write survived on macOS.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Default, PartialEq, Eq)]
struct ScutilProxyState {
    pac_enabled: bool,
    pac_url: Option<String>,
    http: Option<String>,
    https: Option<String>,
}

#[cfg(any(target_os = "macos", test))]
fn parse_scutil_proxy(text: &str) -> ScutilProxyState {
    let value = |key: &str| {
        text.lines().find_map(|line| {
            let (name, value) = line.trim_start().split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case(key)
                .then(|| value.trim().to_string())
        })
    };
    let enabled = |key: &str| value(key).as_deref() == Some("1");
    let endpoint = |enable: &str, host: &str, port: &str| {
        if !enabled(enable) {
            return None;
        }
        let host = value(host).filter(|host| !host.is_empty())?;
        Some(match value(port).filter(|port| !port.is_empty()) {
            Some(port) => format!("{host}:{port}"),
            None => host,
        })
    };
    ScutilProxyState {
        pac_enabled: enabled("ProxyAutoConfigEnable"),
        pac_url: value("ProxyAutoConfigURLString").filter(|url| !url.is_empty()),
        http: endpoint("HTTPEnable", "HTTPProxy", "HTTPPort"),
        https: endpoint("HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
    }
}

/// Guard against WinINet preferring a fixed proxy: our PAC mode writes
/// `AutoConfigURL` and disables the fixed proxy. Reading it back is enough to
/// know our write is intact.
#[cfg(any(windows, test))]
fn windows_current(
    mode: Option<ProxyMode>,
    auto: Option<String>,
    server: Option<String>,
    enabled: u32,
) -> Option<String> {
    match mode {
        Some(ProxyMode::Pac) => auto,
        Some(ProxyMode::Http) if enabled == 1 => server,
        Some(ProxyMode::Http) | Some(ProxyMode::Off) => None,
        None => auto.or(server),
    }
}

#[cfg(windows)]
fn platform_snapshot(_mode: ProxyMode) -> Result<SavedState> {
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
        win_proxy_flags: read_connection_flags(),
        applied_at: None,
        ..Default::default()
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
fn platform_apply_pac(_state_path: &Path, pac_url: &str) -> Result<Vec<String>> {
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
    Ok(Vec::new())
}

#[cfg(windows)]
fn platform_apply_http(_state_path: &Path, proxy: SocketAddr) -> Result<Vec<String>> {
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
    Ok(Vec::new())
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
    Ok(CurrentProxy {
        supported: true,
        current: windows_current(mode, auto, server, enabled),
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
fn platform_snapshot(mode: ProxyMode) -> Result<SavedState> {
    let services = list_network_services()?;
    let mut mac_pac = Vec::new();
    let mut mac_http = Vec::new();
    match mode {
        ProxyMode::Pac => {
            for service in &services {
                let text = run_networksetup_with_timeout(
                    &["-getautoproxyurl", service],
                    NETWORKSETUP_TIMEOUT_SECS,
                )?;
                let (enabled, url) = parse_mac_pac(&text);
                mac_pac.push(MacPacState {
                    service: service.clone(),
                    enabled,
                    url,
                });
            }
        }
        ProxyMode::Http => {
            for service in &services {
                let web = run_networksetup_with_timeout(
                    &["-getwebproxy", service],
                    NETWORKSETUP_TIMEOUT_SECS,
                )?;
                let secure = run_networksetup_with_timeout(
                    &["-getsecurewebproxy", service],
                    NETWORKSETUP_TIMEOUT_SECS,
                )?;
                let (web_enabled, web_server, web_port) = parse_mac_http_proxy(&web);
                let (secure_enabled, secure_server, secure_port) = parse_mac_http_proxy(&secure);
                mac_http.push(MacHttpState {
                    service: service.clone(),
                    web_enabled,
                    web_server,
                    web_port,
                    secure_enabled,
                    secure_server,
                    secure_port,
                });
            }
        }
        ProxyMode::Off => {}
    }
    Ok(SavedState {
        platform: "macos".into(),
        mac_services: services,
        mac_pac,
        mac_http,
        ..Default::default()
    })
}

#[cfg(target_os = "macos")]
fn list_network_services() -> Result<Vec<String>> {
    let text =
        run_networksetup_with_timeout(&["-listallnetworkservices"], NETWORKSETUP_TIMEOUT_SECS)?;
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
fn platform_apply_pac(_state_path: &Path, pac_url: &str) -> Result<Vec<String>> {
    let mut failed = Vec::new();
    for service in list_network_services()? {
        if let Err(error) = run_networksetup(&["-setautoproxyurl", &service, pac_url]) {
            failed.push(format!("{service}: {error:#}"));
            continue;
        }
        if let Err(error) = run_networksetup(&["-setautoproxystate", &service, "on"]) {
            failed.push(format!("{service}: {error:#}"));
        }
    }
    Ok(failed)
}

#[cfg(target_os = "macos")]
fn platform_apply_http(_state_path: &Path, proxy: SocketAddr) -> Result<Vec<String>> {
    let mut failed = Vec::new();
    for service in list_network_services()? {
        let host = proxy.ip().to_string();
        let port = proxy.port().to_string();
        let mut apply = |args: &[&str]| {
            if let Err(error) = run_networksetup(args) {
                failed.push(format!("{service}: {error:#}"));
            }
        };
        apply(&["-setwebproxy", &service, &host, &port]);
        apply(&["-setsecurewebproxy", &service, &host, &port]);
        apply(&["-setwebproxystate", &service, "on"]);
        apply(&["-setsecurewebproxystate", &service, "on"]);
    }
    Ok(failed)
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
    let mut failed = Vec::new();
    match state.mode.unwrap_or(ProxyMode::Pac) {
        ProxyMode::Pac => {
            // A snapshot from an older version has no original PAC values.
            // Switch the PAC off and leave the user's static proxies alone:
            // older builds also disabled web/secure here, which could destroy
            // a proxy the user had configured before hakimi.
            if state.mac_pac.is_empty() {
                for service in &state.mac_services {
                    if let Err(error) = run_networksetup(&["-setautoproxystate", service, "off"]) {
                        failed.push(format!("{service}: {error:#}"));
                    }
                }
            } else {
                for pac in &state.mac_pac {
                    // No original URL: leave the field alone and just switch
                    // the protocol off. Writing "" would be a needless write,
                    // and `-setautoproxyurl` enables the protocol as a side
                    // effect.
                    if let Some(url) = pac.url.as_deref().filter(|url| !url.is_empty()) {
                        if let Err(error) =
                            run_networksetup(&["-setautoproxyurl", &pac.service, url])
                        {
                            failed.push(format!("{}: {error:#}", pac.service));
                        }
                    }
                    let enable = pac.enabled && pac.url.is_some();
                    if let Err(error) = run_networksetup(&[
                        "-setautoproxystate",
                        &pac.service,
                        if enable { "on" } else { "off" },
                    ]) {
                        failed.push(format!("{}: {error:#}", pac.service));
                    }
                }
            }
        }
        ProxyMode::Http => {
            if state.mac_http.is_empty() {
                for service in &state.mac_services {
                    let _ = run_networksetup(&["-setwebproxystate", service, "off"]);
                    let _ = run_networksetup(&["-setsecurewebproxystate", service, "off"]);
                }
            } else {
                for http in &state.mac_http {
                    restore_http_service(http, &mut failed);
                }
            }
        }
        ProxyMode::Off => {}
    }
    if failed.is_empty() {
        Ok(())
    } else {
        bail!(
            "failed to restore {} proxy setting(s): {}",
            failed.len(),
            failed.join("; ")
        )
    }
}

#[cfg(target_os = "macos")]
fn restore_http_service(state: &MacHttpState, failed: &mut Vec<String>) {
    let mut restore = |kind: &str, enabled: bool, server: &Option<String>, port: Option<u16>| {
        if let (Some(server), Some(port)) = (server, port) {
            let args = [
                format!("-set{kind}proxy"),
                state.service.clone(),
                server.clone(),
                port.to_string(),
            ];
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(error) = run_networksetup(&refs) {
                failed.push(format!("{}: {error:#}", state.service));
            }
        }
        let enable = enabled && server.is_some() && port.is_some();
        let args = [
            format!("-set{kind}proxystate"),
            state.service.clone(),
            if enable { "on".into() } else { "off".into() },
        ];
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        if let Err(error) = run_networksetup(&refs) {
            failed.push(format!("{}: {error:#}", state.service));
        }
    };
    restore("web", state.web_enabled, &state.web_server, state.web_port);
    restore(
        "secureweb",
        state.secure_enabled,
        &state.secure_server,
        state.secure_port,
    );
}

#[cfg(target_os = "macos")]
fn scutil_proxy_text() -> Option<String> {
    let output = std::process::Command::new("scutil")
        .arg("--proxy")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(any(target_os = "macos", test))]
fn scutil_pac_current(text: &str) -> Option<String> {
    let state = parse_scutil_proxy(text);
    if state.pac_enabled {
        state.pac_url
    } else {
        None
    }
}

#[cfg(any(target_os = "macos", test))]
fn scutil_http_current(text: &str) -> Option<String> {
    let state = parse_scutil_proxy(text);
    if state.http.is_some() && state.http == state.https {
        state.http
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn platform_current(mode: Option<ProxyMode>) -> Result<CurrentProxy> {
    // `scutil --proxy` reports the effective system view in one fast call.
    // Only used right after applying, never from the periodic UI snapshot.
    if let Some(text) = scutil_proxy_text() {
        let current = match mode {
            Some(ProxyMode::Pac) => scutil_pac_current(&text),
            Some(ProxyMode::Http) => scutil_http_current(&text),
            Some(ProxyMode::Off) => None,
            None => scutil_pac_current(&text).or_else(|| scutil_http_current(&text)),
        };
        return Ok(CurrentProxy {
            supported: true,
            current,
        });
    }

    // Fallback for the rare case where scutil itself is unavailable.
    let services = list_network_services()?;
    let Some(service) = services.first() else {
        return Ok(CurrentProxy {
            supported: true,
            current: None,
        });
    };
    let current = match mode {
        Some(ProxyMode::Pac) => {
            let text = run_networksetup_with_timeout(
                &["-getautoproxyurl", service],
                NETWORKSETUP_TIMEOUT_SECS,
            )?;
            parse_networksetup_proxy(&text, ProxyMode::Pac)
        }
        Some(ProxyMode::Http) => {
            let web = run_networksetup_with_timeout(
                &["-getwebproxy", service],
                NETWORKSETUP_TIMEOUT_SECS,
            )?;
            let secure = run_networksetup_with_timeout(
                &["-getsecurewebproxy", service],
                NETWORKSETUP_TIMEOUT_SECS,
            )?;
            let web = parse_networksetup_proxy(&web, ProxyMode::Http);
            let secure = parse_networksetup_proxy(&secure, ProxyMode::Http);
            if web.is_some() && web == secure {
                web
            } else {
                None
            }
        }
        Some(ProxyMode::Off) => None,
        None => None,
    };
    Ok(CurrentProxy {
        supported: true,
        current,
    })
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_snapshot(_mode: ProxyMode) -> Result<SavedState> {
    Ok(SavedState {
        platform: std::env::consts::OS.to_string(),
        ..Default::default()
    })
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_apply_pac(_state_path: &Path, _pac_url: &str) -> Result<Vec<String>> {
    anyhow::bail!(
        "this platform has no system proxy to take over; point your own tools at the proxy \
         (`hakimi env` for a shell, `hakimi pac` for a PAC file)"
    )
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_apply_http(_state_path: &Path, _proxy: SocketAddr) -> Result<Vec<String>> {
    anyhow::bail!(
        "this platform has no system proxy to take over; point your own tools at the proxy \
         (`hakimi env` for a shell, `hakimi pac` for a PAC file)"
    )
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_restore(_state: &SavedState) -> Result<()> {
    Ok(())
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
        let state = platform_snapshot(ProxyMode::Pac).unwrap();
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
            restore_flags(
                Some(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT),
                false,
                false
            ),
            PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT
        );
    }
}

#[cfg(test)]
mod verification_tests {
    use super::*;

    const PAC: &str = "http://127.0.0.1:8443/proxy.pac";
    const PAC_ON: &str = "<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://127.0.0.1:8443/proxy.pac\n}\n";

    #[test]
    fn a_written_pac_is_detected() {
        assert_eq!(scutil_pac_current(PAC_ON).as_deref(), Some(PAC));
    }

    #[test]
    fn a_disabled_or_different_pac_is_not_detected() {
        let disabled = PAC_ON.replace("ProxyAutoConfigEnable : 1", "ProxyAutoConfigEnable : 0");
        assert_eq!(scutil_pac_current(&disabled), None);
        assert_ne!(
            scutil_pac_current(PAC_ON).as_deref(),
            Some("http://127.0.0.1:8443/other.pac")
        );
    }

    /// The contract is only "our write is intact". A competing static proxy is
    /// deliberately ignored: there is no polling and no takeover detection.
    #[test]
    fn static_proxies_do_not_change_what_we_verify() {
        let text = format!(
            "{PAC_ON}  HTTPEnable : 1\n  HTTPProxy : 127.0.0.1\n  HTTPPort : 10809\n  SOCKSEnable : 1\n  SOCKSProxy : 127.0.0.1\n  SOCKSPort : 10809\n"
        );
        assert_eq!(scutil_pac_current(&text).as_deref(), Some(PAC));
    }

    #[test]
    fn http_requires_both_web_and_secure_proxies() {
        let both = "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 127.0.0.1\n  HTTPPort : 8443\n  HTTPSEnable : 1\n  HTTPSProxy : 127.0.0.1\n  HTTPSPort : 8443\n}\n";
        assert_eq!(scutil_http_current(both).as_deref(), Some("127.0.0.1:8443"));

        let web_only = both.replace("HTTPSEnable : 1", "HTTPSEnable : 0");
        assert_eq!(scutil_http_current(&web_only), None);
    }

    #[test]
    fn networksetup_parsing_keeps_the_enabled_flag() {
        let on = "Enabled: Yes\nServer: 127.0.0.1\nPort: 8443\n";
        assert_eq!(
            parse_networksetup_proxy(on, ProxyMode::Http).as_deref(),
            Some("127.0.0.1:8443")
        );
        let off = "Enabled: No\nServer: 127.0.0.1\nPort: 8443\n";
        assert_eq!(parse_networksetup_proxy(off, ProxyMode::Http), None);
    }

    #[test]
    fn mac_snapshot_parsers_keep_original_values() {
        let pac = "URL: http://127.0.0.1:8443/proxy.pac\nEnabled: Yes\n";
        assert_eq!(
            parse_mac_pac(pac),
            (true, Some("http://127.0.0.1:8443/proxy.pac".into()))
        );
        let http = "Enabled: Yes\nServer: 127.0.0.1\nPort: 10809\n";
        assert_eq!(
            parse_mac_http_proxy(http),
            (true, Some("127.0.0.1".into()), Some(10809))
        );
    }

    #[test]
    fn mac_snapshot_keeps_original_values() {
        let state = SavedState {
            platform: "macos".into(),
            mode: Some(ProxyMode::Pac),
            mac_pac: vec![MacPacState {
                service: "Wi-Fi".into(),
                enabled: true,
                url: Some("http://127.0.0.1:9999/original.pac".into()),
            }],
            ..Default::default()
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: SavedState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode, Some(ProxyMode::Pac));
        assert_eq!(back.mac_pac.len(), 1);
        assert_eq!(
            back.mac_pac[0].url.as_deref(),
            Some("http://127.0.0.1:9999/original.pac")
        );
    }

    #[test]
    fn a_legacy_snapshot_still_deserializes() {
        let back: SavedState =
            serde_json::from_str(r#"{"platform":"macos","macServices":["Wi-Fi"]}"#).unwrap();
        assert_eq!(back.mode, None);
        assert!(back.mac_pac.is_empty());
    }

    #[test]
    fn windows_current_reads_the_value_we_wrote() {
        let pac = "http://127.0.0.1:8443/proxy.pac".to_string();
        // PAC mode verifies AutoConfigURL only; a later fixed-proxy toggle is
        // outside the write contract.
        assert_eq!(
            windows_current(
                Some(ProxyMode::Pac),
                Some(pac.clone()),
                Some("127.0.0.1:10809".into()),
                1
            ),
            Some(pac)
        );
        // HTTP mode requires the fixed proxy to be enabled.
        assert_eq!(
            windows_current(
                Some(ProxyMode::Http),
                None,
                Some("127.0.0.1:8443".into()),
                1
            ),
            Some("127.0.0.1:8443".into())
        );
        assert_eq!(
            windows_current(
                Some(ProxyMode::Http),
                None,
                Some("127.0.0.1:8443".into()),
                0
            ),
            None
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
        assert!(proxy_setting_matches(&current, "127.0.0.1:8443"));
    }

    #[test]
    fn an_ipv6_http_proxy_status_matches_the_host_port_form() {
        // macOS reports the host and port separately, so an IPv6 listener
        // (`[::1]:8443` as a SocketAddr) appears as `::1:8443`. Comparing it
        // with `contains("[::1]:8443")` marked a working proxy as unapplied.
        let text = "Enabled: Yes\nServer: ::1\nPort: 8443\n";
        let current = parse_current_proxy(text, Some(ProxyMode::Http)).unwrap();
        assert_eq!(current, "::1:8443");
        assert!(proxy_setting_matches(&current, "[::1]:8443"));
        assert!(!proxy_setting_matches(&current, "[::1]:8444"));
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
