use std::fmt;

use serde::{Deserialize, Serialize};

/// A concrete TLS mode chosen for one connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    Direct,
    Ech,
    #[serde(rename = "sni")]
    FakeSni,
}

impl TlsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Ech => "ech",
            Self::FakeSni => "sni",
        }
    }
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a candidate IP came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpSource {
    Cache,
    Remote,
    Doh,
    DohCache,
}

impl IpSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Remote => "remote",
            Self::Doh => "doh",
            Self::DohCache => "doh-cache",
        }
    }
}

impl fmt::Display for IpSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which DoH endpoint (or cache) produced an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DohSource {
    Primary,
    Fallback,
    Custom,
    Cache,
}

impl DohSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Fallback => "fallback",
            Self::Custom => "custom",
            Self::Cache => "cache",
        }
    }
}

impl fmt::Display for DohSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheStatus {
    Fresh,
    Stale,
    None,
}

impl fmt::Display for CacheStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::None => "none",
        })
    }
}

/// Stable failure vocabulary from section 10.2 of the design document, plus a few
/// internal categories that are useful in the error page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    DohFailed,
    DohFallback,
    RemoteCatalogUnavailable,
    RemoteIpRejected,
    /// The TCP handshake itself did not complete.
    TcpTimeout,
    /// TCP came up but the TLS handshake did not finish in time.
    TlsTimeout,
    /// The address could not be reached at the IP layer (no route, network down).
    TcpUnreachable,
    TlsReset,
    CertInvalid,
    EchUnavailable,
    SniRejected,
    CaUntrusted,
    ProxyNotApplied,
    QuicBypass,
    UnsupportedWithoutProxy,
    NoCandidate,
    TcpRefused,
    TlsError,
    ConfigInvalid,
    Internal,
}

impl FailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DohFailed => "doh_failed",
            Self::DohFallback => "doh_fallback",
            Self::RemoteCatalogUnavailable => "remote_catalog_unavailable",
            Self::RemoteIpRejected => "remote_ip_rejected",
            Self::TcpTimeout => "tcp_timeout",
            Self::TlsTimeout => "tls_timeout",
            Self::TcpUnreachable => "tcp_unreachable",
            Self::TlsReset => "tls_reset",
            Self::CertInvalid => "cert_invalid",
            Self::EchUnavailable => "ech_unavailable",
            Self::SniRejected => "sni_rejected",
            Self::CaUntrusted => "ca_untrusted",
            Self::ProxyNotApplied => "proxy_not_applied",
            Self::QuicBypass => "quic_bypass",
            Self::UnsupportedWithoutProxy => "unsupported_without_proxy",
            Self::NoCandidate => "no_candidate",
            Self::TcpRefused => "tcp_refused",
            Self::TlsError => "tls_error",
            Self::ConfigInvalid => "config_invalid",
            Self::Internal => "internal",
        }
    }

    pub fn suggestion(self) -> &'static str {
        match self {
            Self::DohFailed => {
                "Check the network and the configured DoH endpoints, then refresh the DoH health check."
            }
            Self::DohFallback => {
                "The primary DoH failed and the fallback also failed; verify both endpoints or add a custom DoH."
            }
            Self::RemoteCatalogUnavailable => {
                "Refresh the remote IP catalog or check the catalog source/mirror configuration."
            }
            Self::RemoteIpRejected => {
                "The catalog contained no acceptable public IP for this domain; rely on DoH or update the catalog."
            }
            Self::TcpTimeout => {
                "The candidate IP did not answer within 2 seconds; check local connectivity or try another network."
            }
            Self::TlsTimeout => {
                "TCP reached the address but the TLS handshake stalled. The route and the IP are healthy; try another SNI/ECH strategy."
            }
            Self::TcpUnreachable => {
                "The candidate address is unreachable at the IP layer (no route or network down). Pick another candidate."
            }
            Self::TlsReset => {
                "The TLS handshake was reset. This often means SNI filtering; try auto/ECH or a different IP."
            }
            Self::CertInvalid => {
                "The server certificate did not match the real domain. Do not disable verification; try direct or ECH."
            }
            Self::EchUnavailable => {
                "No usable ECHConfig was found in the HTTPS RR. Use auto/SNI or lock a different strategy."
            }
            Self::SniRejected => {
                "The server did not accept any fake SNI. Use direct/ECH, or configure a working group SNI."
            }
            Self::CaUntrusted => {
                "Install or repair the hakimi local CA, then restart the browser."
            }
            Self::ProxyNotApplied => {
                "The system proxy/PAC setting was not applied. Re-apply it or check the OS proxy settings."
            }
            Self::QuicBypass => {
                "The browser may bypass the proxy over QUIC; disable QUIC in the browser if needed."
            }
            Self::UnsupportedWithoutProxy => {
                "This traffic cannot be accelerated without a proxy; enable system proxy/PAC."
            }
            Self::NoCandidate => {
                "No candidate IP was available. Check the remote catalog, DoH status and group configuration."
            }
            Self::TcpRefused => {
                "The candidate IP refused the TCP connection; try another candidate or network."
            }
            Self::TlsError => {
                "The TLS handshake failed. Inspect the diagnostics attempts for the failing candidate."
            }
            Self::ConfigInvalid => "Fix the group/catalog configuration and reload it.",
            Self::Internal => "Inspect the local log and export diagnostics.",
        }
    }

    /// Whether this failure condemns the address itself.
    ///
    /// TCP come-up is a property of the address, TLS success is a property of
    /// the (address, SNI, ECH) triple. Only the first group justifies retiring
    /// every other variant on the same IP: a `tls_reset` or `cert_invalid`
    /// means the address answered, so another SNI may still work.
    pub fn is_ip_level(self) -> bool {
        matches!(
            self,
            Self::TcpTimeout | Self::TcpUnreachable | Self::TcpRefused
        )
    }
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_names() {
        assert_eq!(serde_json::to_string(&TlsMode::FakeSni).unwrap(), "\"sni\"");
        assert_eq!(
            serde_json::to_string(&IpSource::DohCache).unwrap(),
            "\"doh-cache\""
        );
        assert_eq!(
            serde_json::to_string(&FailureReason::CertInvalid).unwrap(),
            "\"cert_invalid\""
        );
    }
}
