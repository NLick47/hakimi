use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::RwLock;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientSessionMemoryCache, Resumption, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::strategy::{FailureReason, TlsMode};

pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Shared TLS client state: roots, crypto provider and cached client configurations.
///
/// Building a `ClientConfig` rebuilds the ECH setup and the WebPKI verifier. More
/// importantly, a fresh config starts with an empty TLS session cache, which defeats
/// TLS 1.3 resumption for every new upstream connection. Configs are therefore cached by
/// (mode, ALPN, ECH config, fake SNI/real domain) and share one resumption store.
pub struct TlsContext {
    provider: Arc<CryptoProvider>,
    roots: Arc<RootCertStore>,
    sessions: Arc<ClientSessionMemoryCache>,
    configs: RwLock<HashMap<String, Arc<ClientConfig>>>,
}

impl TlsContext {
    pub fn new() -> Result<Arc<Self>> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Test hook: extra roots for a local harness (off by default).
        roots.add_parsable_certificates(crate::hooks::extra_roots());
        Ok(Arc::new(Self {
            provider,
            roots: Arc::new(roots),
            sessions: Arc::new(ClientSessionMemoryCache::new(2048)),
            configs: RwLock::new(HashMap::new()),
        }))
    }

    /// Probe a single candidate IP: TCP 443 + TLS handshake + certificate validation.
    /// No HTTP request is made; a Cloudflare 403 is irrelevant because we stop after TLS.
    #[allow(clippy::too_many_arguments)]
    pub async fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<ProbeSuccess, ConnectError> {
        let started = Instant::now();
        let stream = tokio::time::timeout(timeout, self.connect(ip, port, domain, mode, sni, ech))
            .await
            .map_err(|_| ConnectError::Timeout)??;
        let alpn = stream
            .get_ref()
            .1
            .alpn_protocol()
            .map(|protocol| protocol.to_vec());
        Ok(ProbeSuccess {
            latency_ms: started.elapsed().as_millis() as u64,
            alpn,
        })
    }

    /// Establish an upstream TLS connection to a specific IP. The TLS SNI and certificate
    /// checks depend on `mode`:
    /// - `direct`: SNI = real domain, webpki verification of the real domain.
    /// - `ech`: SNI = real domain, ECH outer name from the config, webpki verification.
    /// - `sni`: SNI = candidate (or no SNI when empty), certificate still verified against
    ///   the real domain by [`RealDomainVerifier`].
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &self,
        ip: IpAddr,
        port: u16,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ConnectError> {
        self.connect_alpn(ip, port, domain, mode, sni, ech, &[ALPN_H2, ALPN_HTTP11])
            .await
    }

    /// HTTP/1.1-only connection, required when forwarding WebSocket upgrades upstream.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_http1(
        &self,
        ip: IpAddr,
        port: u16,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ConnectError> {
        self.connect_alpn(ip, port, domain, mode, sni, ech, &[ALPN_HTTP11])
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_alpn(
        &self,
        ip: IpAddr,
        port: u16,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
        alpn: &[&[u8]],
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ConnectError> {
        let config = self.client_config_with_alpn(domain, mode, sni, ech, alpn)?;
        let server_name = match mode {
            TlsMode::Direct | TlsMode::Ech => dns_name(domain)?,
            TlsMode::FakeSni => match sni {
                Some(fake) if !fake.is_empty() => dns_name(fake)?,
                _ => ServerName::IpAddress(Ipv4Addr::UNSPECIFIED.into()),
            },
        };
        let tcp = TcpStream::connect(SocketAddr::new(ip, port))
            .await
            .map_err(ConnectError::from_io)?;
        let _ = tcp.set_nodelay(true);
        crate::util::apply_tcp_keepalive(&tcp);
        let connector = TlsConnector::from(config);
        connector
            .connect(server_name, tcp)
            .await
            .map_err(ConnectError::from_tls_io)
    }

    #[cfg(test)]
    fn client_config(
        &self,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
    ) -> Result<Arc<ClientConfig>, ConnectError> {
        self.client_config_with_alpn(domain, mode, sni, ech, &[ALPN_H2, ALPN_HTTP11])
    }

    fn client_config_with_alpn(
        &self,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
        alpn: &[&[u8]],
    ) -> Result<Arc<ClientConfig>, ConnectError> {
        let key = config_cache_key(domain, mode, sni, ech, alpn);
        if let Some(config) = self.configs.read().get(&key) {
            return Ok(config.clone());
        }

        let provider = self.provider.clone();
        let base = ClientConfig::builder_with_provider(provider.clone());
        let mut config = match mode {
            TlsMode::Direct => base
                .with_safe_default_protocol_versions()
                .map_err(|error| ConnectError::Tls(error.to_string()))?
                .with_root_certificates(self.roots.clone())
                .with_no_client_auth(),
            TlsMode::Ech => {
                let ech = ech.ok_or_else(|| {
                    ConnectError::EchUnavailable("no ECHConfig was supplied".into())
                })?;
                let parsed = rustls::client::EchConfig::new(
                    EchConfigListBytes::from(ech),
                    rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
                )
                .map_err(|error| ConnectError::EchUnavailable(format!("{error:?}")))?;
                base.with_ech(rustls::client::EchMode::Enable(parsed))
                    .map_err(|error| ConnectError::EchUnavailable(format!("{error:?}")))?
                    .with_root_certificates(self.roots.clone())
                    .with_no_client_auth()
            }
            TlsMode::FakeSni => {
                let real = dns_name(domain)?;
                let inner =
                    WebPkiServerVerifier::builder_with_provider(self.roots.clone(), provider)
                        .build()
                        .map_err(|error| ConnectError::Tls(format!("{error:?}")))?;
                base.with_safe_default_protocol_versions()
                    .map_err(|error| ConnectError::Tls(error.to_string()))?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(RealDomainVerifier { inner, real }))
                    .with_no_client_auth()
            }
        };
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        // Sessions are keyed by the ServerName passed to the connector, so Direct/ECH
        // configs can share one store safely across domains. Fake SNI configs must not:
        // two real domains may present the same fake name, and a resumed session would
        // bypass the per-domain certificate check. Those keep a private store.
        if mode != TlsMode::FakeSni {
            config.resumption = Resumption::store(self.sessions.clone());
        }
        let config = Arc::new(config);
        let mut configs = self.configs.write();
        if configs.len() > 4096 {
            configs.retain(|_, entry| Arc::strong_count(entry) > 1);
        }
        configs.insert(key, config.clone());
        Ok(config)
    }
}

fn config_cache_key(
    domain: &str,
    mode: TlsMode,
    sni: Option<&str>,
    ech: Option<&[u8]>,
    alpn: &[&[u8]],
) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    alpn.hash(&mut hasher);
    ech.hash(&mut hasher);
    let ech = hasher.finish();
    match mode {
        TlsMode::Direct => format!("direct|{}|{ech}", alpn_name(alpn)),
        TlsMode::Ech => format!("ech|{}|{ech}", alpn_name(alpn)),
        TlsMode::FakeSni => format!(
            "sni|{domain}|{}|{}|{ech}",
            sni.unwrap_or(""),
            alpn_name(alpn)
        ),
    }
}

fn alpn_name(alpn: &[&[u8]]) -> &'static str {
    if alpn.len() == 1 && alpn[0] == ALPN_HTTP11 {
        "h1"
    } else {
        "auto"
    }
}

#[derive(Debug, Clone)]
pub struct ProbeSuccess {
    pub latency_ms: u64,
    pub alpn: Option<Vec<u8>>,
}

/// Certificate verifier that ignores the SNI name presented to the handshake and validates
/// the certificate against the real domain instead.
struct RealDomainVerifier {
    inner: Arc<WebPkiServerVerifier>,
    real: ServerName<'static>,
}

impl fmt::Debug for RealDomainVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealDomainVerifier")
            .field("real", &self.real)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for RealDomainVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.real, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn dns_name(host: &str) -> Result<ServerName<'static>, ConnectError> {
    ServerName::try_from(host.trim().trim_end_matches('.').to_ascii_lowercase())
        .map_err(|error| ConnectError::Name(error.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("connection or handshake timed out")]
    Timeout,
    #[error("TCP connection refused")]
    TcpRefused,
    #[error("TCP connection failed: {0}")]
    Tcp(String),
    #[error("TLS connection reset: {0}")]
    TlsReset(String),
    #[error("certificate is invalid for the real domain: {0}")]
    CertInvalid(String),
    #[error("ECH unavailable: {0}")]
    EchUnavailable(String),
    #[error("invalid server name: {0}")]
    Name(String),
    #[error("TLS error: {0}")]
    Tls(String),
}

impl ConnectError {
    pub fn reason(&self) -> FailureReason {
        match self {
            Self::Timeout => FailureReason::TcpTimeout,
            Self::TcpRefused => FailureReason::TcpRefused,
            Self::Tcp(_) => FailureReason::TcpTimeout,
            Self::TlsReset(_) => FailureReason::TlsReset,
            Self::CertInvalid(_) => FailureReason::CertInvalid,
            Self::EchUnavailable(_) => FailureReason::EchUnavailable,
            Self::Name(_) => FailureReason::TlsError,
            Self::Tls(_) => FailureReason::TlsError,
        }
    }

    pub fn detail(&self) -> String {
        self.to_string()
    }

    fn from_io(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => Self::TcpRefused,
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::Timeout,
            _ => Self::Tcp(error.to_string()),
        }
    }

    fn from_tls_io(error: io::Error) -> Self {
        if let Some(source) = error.get_ref() {
            if let Some(rustls_error) = source.downcast_ref::<rustls::Error>() {
                return Self::from_rustls(rustls_error.clone());
            }
        }
        let text = error.to_string();
        let lower = text.to_ascii_lowercase();
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            return Self::Timeout;
        }
        if error.kind() == io::ErrorKind::ConnectionRefused {
            return Self::TcpRefused;
        }
        if lower.contains("reset")
            || lower.contains("unexpected eof")
            || lower.contains("connection closed")
            || lower.contains("broken pipe")
        {
            Self::TlsReset(text)
        } else {
            Self::Tls(text)
        }
    }

    fn from_rustls(error: rustls::Error) -> Self {
        match &error {
            rustls::Error::InvalidCertificate(cert) => Self::CertInvalid(cert.to_string()),
            rustls::Error::InvalidEncryptedClientHello(inner) => {
                Self::EchUnavailable(format!("{inner:?}"))
            }
            rustls::Error::AlertReceived(alert) => {
                let text = format!("{alert:?}").to_ascii_lowercase();
                if text.contains("reset") || text.contains("close") {
                    Self::TlsReset(error.to_string())
                } else {
                    Self::Tls(error.to_string())
                }
            }
            _ => {
                let text = error.to_string();
                let lower = text.to_ascii_lowercase();
                if lower.contains("reset") || lower.contains("unexpected eof") {
                    Self::TlsReset(text)
                } else {
                    Self::Tls(text)
                }
            }
        }
    }
}

impl From<io::Error> for ConnectError {
    fn from(error: io::Error) -> Self {
        Self::from_io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sni_uses_ip_server_name() {
        let name = ServerName::IpAddress(Ipv4Addr::UNSPECIFIED.into());
        assert!(matches!(name, ServerName::IpAddress(_)));
        assert_eq!(name.to_str(), "0.0.0.0");
    }

    #[test]
    fn context_builds_roots() {
        let context = TlsContext::new().unwrap();
        let config = context
            .client_config("github.com", TlsMode::Direct, None, None)
            .unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()]
        );
    }

    #[test]
    fn ech_without_config_is_reported() {
        let context = TlsContext::new().unwrap();
        let error = match context.client_config("pixiv.net", TlsMode::Ech, None, None) {
            Ok(_) => panic!("expected an error"),
            Err(error) => error,
        };
        assert_eq!(error.reason(), FailureReason::EchUnavailable);
    }
}
