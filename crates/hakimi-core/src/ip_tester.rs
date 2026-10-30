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

/// Ceiling for the TCP leg when the caller already applies its own deadline.
const TCP_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounds for the TCP leg of one candidate. It only has to answer "is this
/// address reachable", so it gets a fraction of the candidate budget: a silent
/// address is retired before its whole SNI variant list is dialled.
const MIN_TCP_BUDGET: Duration = Duration::from_millis(500);
const MAX_TCP_BUDGET: Duration = Duration::from_secs(2);
/// A TCP handshake that consumed most of the budget still leaves the TLS leg
/// enough room to fail on its own terms instead of looking like a connect
/// timeout.
const MIN_TLS_BUDGET: Duration = Duration::from_millis(500);

/// Budget for the TCP leg of a candidate whose total budget is `timeout`.
///
/// Never above `timeout` itself: `ipTimeoutMs` is the total budget for one
/// candidate, and a floor larger than that would make a fast-fail
/// configuration slower than configured.
pub(crate) fn tcp_phase_budget(timeout: Duration) -> Duration {
    (timeout / 2)
        .clamp(MIN_TCP_BUDGET, MAX_TCP_BUDGET)
        .min(timeout)
}

/// Budget left for the TLS handshake after the TCP leg spent `elapsed`.
pub(crate) fn tls_phase_budget(timeout: Duration, elapsed: Duration) -> Duration {
    timeout
        .saturating_sub(elapsed)
        .max(MIN_TLS_BUDGET.min(timeout))
}

/// Shared TLS client state: roots, crypto provider and cached client configurations.
///
/// Building a `ClientConfig` rebuilds the ECH setup and the WebPKI verifier. More
/// importantly, a fresh config starts with an empty TLS session cache, which defeats
/// TLS 1.3 resumption for every new upstream connection. Configs are therefore cached by
/// (mode, ALPN, ECH config, fake SNI/real domain). Direct/ECH share a store; fake SNI keeps
/// a private store because its per-domain certificate verifier must not accept another
/// domain's resumed session.
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
        // The two legs are timed and classified separately, exactly like the
        // pooled connector. Collapsing both into one deadline reported a
        // filtered SNI as `tcp_timeout`: the address had answered, only the
        // handshake stalled, and the operator was pointed at the wrong layer.
        let tcp = Self::open_tcp_with(ip, port, tcp_phase_budget(timeout)).await?;
        let stream = tokio::time::timeout(
            tls_phase_budget(timeout, started.elapsed()),
            self.handshake(tcp, domain, mode, sni, ech, false),
        )
        .await
        .map_err(|_| ConnectError::TlsTimeout)??;
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
        let tcp = Self::open_tcp_with(ip, port, TCP_OPEN_TIMEOUT).await?;
        self.handshake_alpn(tcp, domain, mode, sni, ech, alpn)
            .await
    }

    /// Open the TCP leg on its own.
    ///
    /// The pooled race needs the two legs separately: the TCP result decides
    /// whether the address is reachable at all (and retires it when it is not),
    /// while the TLS result only judges the variant that was dialled. A stalled
    /// handshake on one fake SNI must not condemn the address.
    pub async fn open_tcp(
        ip: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, ConnectError> {
        Self::open_tcp_with(ip, port, timeout).await
    }

    async fn open_tcp_with(
        ip: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, ConnectError> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port)))
            .await
            .map_err(|_| ConnectError::TcpTimeout)?
            .map_err(ConnectError::from_io)?;
        let _ = stream.set_nodelay(true);
        crate::util::apply_tcp_keepalive(&stream);
        Ok(stream)
    }

    /// Run the TLS handshake over an already connected socket.
    pub async fn handshake(
        &self,
        tcp: TcpStream,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
        http1_only: bool,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ConnectError> {
        let alpn: &[&[u8]] = if http1_only {
            &[ALPN_HTTP11]
        } else {
            &[ALPN_H2, ALPN_HTTP11]
        };
        self.handshake_alpn(tcp, domain, mode, sni, ech, alpn)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn handshake_alpn(
        &self,
        tcp: TcpStream,
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
        // bypass the per-domain certificate check. Those keep a private store. Without
        // it, every new fake-SNI connection paid a full handshake even though the
        // public server offered TLS tickets.
        if mode != TlsMode::FakeSni {
            config.resumption = Resumption::store(self.sessions.clone());
        } else {
            config.resumption = Resumption::store(Arc::new(ClientSessionMemoryCache::new(64)));
        }
        let config = Arc::new(config);
        let mut configs = self.configs.write();
        if configs.len() > 512 {
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
    // The trailing root label is preserved: `host.` resolves to the same server while
    // a filter matching the bare name lets it through. rustls carries it verbatim, so
    // stripping it here would silently turn the only working spelling back into the
    // blocked one. Normalized config domains never end in a dot, so direct/ECH are
    // unaffected.
    ServerName::try_from(host.trim().to_ascii_lowercase())
        .map_err(|error| ConnectError::Name(error.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// A whole-probe deadline expired around a bare TCP connect. The TLS
    /// probe splits its legs and reports [`Self::TcpTimeout`] or
    /// [`Self::TlsTimeout`] instead, so this is only produced by
    /// `Prober::probe_tcp`.
    #[error("connection or handshake timed out")]
    ProbeTimeout,
    #[error("TCP connection timed out")]
    TcpTimeout,
    #[error("TLS handshake timed out")]
    TlsTimeout,
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
            // A whole-probe timeout covers TCP and TLS together; treat it as an
            // address-level answer, which is the conservative choice.
            Self::ProbeTimeout => FailureReason::TcpTimeout,
            Self::TcpTimeout => FailureReason::TcpTimeout,
            Self::TcpRefused => FailureReason::TcpRefused,
            Self::Tcp(_) => FailureReason::TcpUnreachable,
            Self::TlsTimeout => FailureReason::TlsTimeout,
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
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::TcpTimeout,
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
            // The socket was already connected, so this is a stalled handshake
            // rather than an unreachable address.
            return Self::TlsTimeout;
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

    #[test]
    fn fake_sni_keeps_the_trailing_root_label() {
        // 尾部根标签是绕过按字符串匹配的 SNI 过滤的唯一写法
        let name = dns_name("huggingface.co.").unwrap();
        assert_eq!(name.to_str(), "huggingface.co.");
    }

    /// A server that accepts the TCP handshake and then never speaks TLS. The
    /// address answered, so only this variant failed: reporting `tcp_timeout`
    /// here sent the operator looking at the network while the route itself was
    /// fine, and it told the race to retire a healthy address.
    #[tokio::test]
    async fn a_stalled_handshake_is_a_tls_timeout_not_an_unreachable_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hold = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(stream);
        });

        let context = TlsContext::new().unwrap();
        let error = context
            .probe(
                address.ip(),
                address.port(),
                "example.com",
                TlsMode::Direct,
                None,
                None,
                Duration::from_millis(300),
            )
            .await
            .expect_err("a silent TLS server cannot produce a probe success");

        assert_eq!(
            error.reason(),
            FailureReason::TlsTimeout,
            "a stalled handshake must not condemn the address: {error}"
        );
        assert!(
            !error.reason().is_ip_level(),
            "the address is reachable, so it must stay available to other variants: {error}"
        );
        hold.abort();
    }

    /// The other half of the split: a refused TCP connect is a verdict about the
    /// address, so it must stay address-level.
    #[tokio::test]
    async fn a_refused_port_stays_an_address_level_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let context = TlsContext::new().unwrap();
        let error = context
            .probe(
                address.ip(),
                address.port(),
                "example.com",
                TlsMode::Direct,
                None,
                None,
                Duration::from_millis(500),
            )
            .await
            .expect_err("no listener means no probe");

        assert_eq!(
            error.reason(),
            FailureReason::TcpRefused,
            "a closed port is an address verdict: {error}"
        );
        assert!(error.reason().is_ip_level());
    }

    #[test]
    fn fake_sni_client_hello_carries_the_trailing_root_label() {
        // vendor/rustls 保留尾部根标签；上游 rustls 会在这里把它裁掉，
        // 那样配置里的 `host.` 会悄悄变回被过滤的裸名字
        let context = TlsContext::new().unwrap();
        let config = context
            .client_config(
                "huggingface.co",
                TlsMode::FakeSni,
                Some("huggingface.co."),
                None,
            )
            .unwrap();
        let name = dns_name("huggingface.co.").unwrap();
        let mut conn = rustls::ClientConnection::new(config, name).unwrap();
        let mut hello: Vec<u8> = Vec::new();
        conn.write_tls(&mut hello).unwrap();
        assert!(
            hello.windows(15).any(|w| w == b"huggingface.co."),
            "SNI must keep the trailing root label"
        );
    }
}
