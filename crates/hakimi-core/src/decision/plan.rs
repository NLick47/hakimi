use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::ip_tester::{ConnectError, ProbeSuccess, TlsContext};
use crate::status::DomainDiagnostics;
use crate::strategy::{IpSource, Strategy, TlsMode};

#[derive(Debug, Clone)]
pub struct ConnectPlan {
    pub domain: String,
    pub group_id: String,
    pub ip: IpAddr,
    pub port: u16,
    pub mode: TlsMode,
    /// Fake SNI used for upstream TLS. `None` means no SNI (or not applicable).
    pub sni: Option<String>,
    /// Raw ECHConfigList for `TlsMode::Ech`.
    pub ech_config: Option<Vec<u8>>,
    /// Whether this plan terminates TLS (false only for plaintext HTTP forwarding).
    pub tls: bool,
    /// Which candidate list produced this IP.
    pub source: IpSource,
}

impl ConnectPlan {
    pub(super) fn identity(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.ech_config.hash(&mut hasher);
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.domain,
            self.port,
            self.tls,
            self.ip,
            self.mode.as_str(),
            self.sni.as_deref().unwrap_or(""),
            hasher.finish()
        )
    }
}

#[derive(Debug, Clone)]
pub struct DecisionOutcome {
    /// Shared with the plan cache and with the followers of one discovery, so
    /// a winning plan is not deep-copied for every consumer.
    pub plan: Option<Arc<ConnectPlan>>,
    /// Shared with the status store so publishing a decision does not clone
    /// the attempts/suggestions vectors.
    pub diagnostics: Arc<DomainDiagnostics>,
}

/// Network prober abstraction so decision rules can be unit-tested without sockets.
#[async_trait]
pub trait Prober: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn probe_tls(
        &self,
        ip: IpAddr,
        port: u16,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
        timeout: Duration,
    ) -> std::result::Result<ProbeSuccess, ConnectError>;

    async fn probe_tcp(
        &self,
        ip: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> std::result::Result<u64, ConnectError>;
}

#[async_trait]
impl Prober for TlsContext {
    async fn probe_tls(
        &self,
        ip: IpAddr,
        port: u16,
        domain: &str,
        mode: TlsMode,
        sni: Option<&str>,
        ech: Option<&[u8]>,
        timeout: Duration,
    ) -> std::result::Result<ProbeSuccess, ConnectError> {
        TlsContext::probe(self, ip, port, domain, mode, sni, ech, timeout).await
    }

    async fn probe_tcp(
        &self,
        ip: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> std::result::Result<u64, ConnectError> {
        let started = Instant::now();
        let stream = tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port)))
            .await
            .map_err(|_| ConnectError::Timeout)??;
        drop(stream);
        Ok(started.elapsed().as_millis() as u64)
    }
}

pub(super) fn mode_for_strategy(strategy: Strategy) -> TlsMode {
    match strategy {
        Strategy::Direct => TlsMode::Direct,
        Strategy::Ech => TlsMode::Ech,
        Strategy::FakeSni => TlsMode::FakeSni,
        Strategy::Auto => TlsMode::Direct,
    }
}
