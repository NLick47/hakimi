use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Atomically replace `path` with `bytes`.
///
/// The temporary file lives in the destination directory so the final rename stays on the
/// same filesystem. `tempfile::NamedTempFile::persist` replaces existing files on Windows too.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary file in {}", parent.display()))?;
    tmp.write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("persisting {}", path.display()))?;
    Ok(())
}

/// Like [`atomic_write`], but the temporary file is made private before it is renamed into
/// place, so there is no window where a secret is world-readable on Unix.
pub fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary file in {}", parent.display()))?;
    tmp.write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600));
    }
    tmp.persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("persisting {}", path.display()))?;
    Ok(())
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    atomic_write(path, &bytes)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

pub fn now_rfc3339() -> String {
    now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

pub fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, bytes).as_ref())
}

/// Accept base64 (standard or URL-safe, padded or not) or hex.
pub fn decode_key_material(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("empty key material");
    }
    if trimmed.len() % 2 == 0 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(hex::decode(trimmed)?);
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(trimmed) {
            return Ok(bytes);
        }
    }
    bail!("key material is neither hex nor base64")
}

/// True only for globally routable addresses. Remote catalogs must not point at loopback,
/// private, link-local, multicast or reserved space.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

pub fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    // Reject "this network", private, CGNAT, loopback, link-local, documentation,
    // benchmarking, multicast and reserved space.
    if a == 0 || a == 10 || a == 127 || a >= 224 {
        return false;
    }
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    if a == 169 && b == 254 {
        return false;
    }
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    if a == 192 && b == 168 {
        return false;
    }
    if a == 192 && b == 0 && c == 0 {
        return false;
    }
    if a == 192 && b == 0 && c == 2 {
        return false;
    }
    if a == 192 && b == 88 && c == 99 {
        return false;
    }
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    if a == 198 && b == 51 && c == 100 {
        return false;
    }
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    true
}

pub fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    let seg = ip.segments();
    // ULA fc00::/7
    if seg[0] & 0xfe00 == 0xfc00 {
        return false;
    }
    // Link-local fe80::/10
    if seg[0] & 0xffc0 == 0xfe80 {
        return false;
    }
    // Documentation 2001:db8::/32
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return false;
    }
    // Teredo 2001::/32, 6to4 2002::/16, discard-only 100::/64
    if seg[0] == 0x2001 && seg[1] == 0x0000 {
        return false;
    }
    if seg[0] == 0x2002 || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0) {
        return false;
    }
    // IPv4-mapped and IPv4-compatible forms: judge the embedded address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }
    if ip.to_ipv4().is_some() {
        return false;
    }
    true
}

/// Best-effort stable identifier for the current network.
///
/// The design only needs "did the network change" semantics. We use the local address chosen
/// for an outbound route; it changes with most Wi-Fi/Ethernet switches. Tests can pin a value
/// with `HAKIMI_NETWORK_ID`.
///
/// This probes the OS and is deliberately not used on hot paths: binding a UDP socket and
/// asking the routing table costs tens of microseconds on macOS. Use [`network_id`] instead
/// and let the runtime monitor call this periodically to detect network changes.
pub fn probe_network_id() -> String {
    if let Ok(value) = std::env::var("HAKIMI_NETWORK_ID") {
        if !value.trim().is_empty() {
            return value;
        }
    }
    match UdpSocket::bind("0.0.0.0:0").and_then(|socket| {
        socket.connect("1.1.1.1:53")?;
        socket.local_addr()
    }) {
        Ok(SocketAddr::V4(addr)) => format!("ip:{}", addr.ip()),
        Ok(SocketAddr::V6(addr)) => format!("ip6:{}", addr.ip()),
        Err(_) => "unknown".to_string(),
    }
}

/// Cached network id. Route planning and connection bookkeeping run this for every cold
/// connection, so it must not perform the UDP/route-table probe each time. The runtime's
/// network-change detector refreshes the cache with [`refresh_network_id`].
pub fn network_id() -> String {
    network_id_cache().read().as_ref().to_string()
}

/// Re-probe the OS, publish the result to the cached accessor, and return it.
/// Called by the network-change monitor.
pub fn refresh_network_id() -> String {
    let value = probe_network_id();
    *network_id_cache().write() = Arc::from(value.as_str());
    value
}

fn network_id_cache() -> &'static parking_lot::RwLock<Arc<str>> {
    static CACHE: std::sync::OnceLock<parking_lot::RwLock<Arc<str>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| parking_lot::RwLock::new(Arc::from(probe_network_id().as_str())))
}

pub fn redact_url(input: &str) -> String {
    match url::Url::parse(input) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => "<invalid-url>".to_string(),
    }
}

/// Summarize an IP for logs/diagnostics exports without exposing the whole address.
pub fn redact_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.x", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:…", s[0], s[1])
        }
    }
}

/// Host portion of an authority or a `Host` header, borrowed from the input.
///
/// Unlike [`parse_authority`] it allocates nothing, which matters on the
/// request path where the host is only compared, never stored.
pub fn host_header_name(value: &str) -> &str {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => value,
    }
}

pub fn parse_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = if let Some(port) = tail.strip_prefix(':') {
            port.parse().ok()?
        } else if tail.is_empty() {
            default_port
        } else {
            return None;
        };
        return Some((host.to_ascii_lowercase(), port));
    }
    if let Ok(ip) = authority.parse::<IpAddr>() {
        return Some((ip.to_string(), default_port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() => {
            let port = port.parse().ok()?;
            Some((host.to_ascii_lowercase(), port))
        }
        _ => Some((authority.to_ascii_lowercase(), default_port)),
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Keep long-lived upstream connections alive through NAT gateways and idle-timeout
/// middleboxes. TCP-level only; HTTP/2 adds its own PING keep-alive on top.
pub fn apply_tcp_keepalive(stream: &tokio::net::TcpStream) {
    let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

pub fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ip_filter() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "20.205.243.166",
            "104.16.132.229",
            "2606:4700:4700::1111",
        ] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip} should be public");
        }
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "192.0.2.10",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !is_public_ip(ip.parse().unwrap()),
                "{ip} should be rejected"
            );
        }
    }

    #[test]
    fn authority_parsing() {
        assert_eq!(
            parse_authority("github.com:443", 443),
            Some(("github.com".into(), 443))
        );
        assert_eq!(
            parse_authority("[2001:db8::1]:8443", 443),
            Some(("2001:db8::1".into(), 8443))
        );
        assert_eq!(
            parse_authority("example.com", 443),
            Some(("example.com".into(), 443))
        );
        assert_eq!(
            parse_authority("127.0.0.1:49761", 80),
            Some(("127.0.0.1".into(), 49761))
        );
    }

    #[test]
    fn key_material_formats() {
        let raw = [7u8; 32];
        assert_eq!(decode_key_material(&hex::encode(raw)).unwrap(), raw);
        assert_eq!(
            decode_key_material(&base64::engine::general_purpose::STANDARD.encode(raw)).unwrap(),
            raw
        );
    }

    #[test]
    fn refreshed_network_id_is_published_to_the_cached_accessor() {
        let refreshed = refresh_network_id();
        assert_eq!(network_id(), refreshed);
        // Repeated hot-path reads are cheap and stable until the next refresh.
        assert_eq!(network_id(), refreshed);
    }

    #[test]
    fn atomic_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("file.json");
        atomic_write_json(&path, &serde_json::json!({"a": 1})).unwrap();
        let value: serde_json::Value = read_json(&path).unwrap();
        assert_eq!(value["a"], 1);
    }
}
