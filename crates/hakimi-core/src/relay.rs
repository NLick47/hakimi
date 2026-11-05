//! Local raw-TCP relay for clients that cannot use an HTTP proxy.
//!
//! `cloudflared` is the motivating case. It dials Cloudflare's edge directly,
//! ignores `HTTPS_PROXY`, and needs both a working DNS answer and an
//! uncensored TLS path to `*.cftunnel.com`. The relay gives it a stable local
//! endpoint (`--edge 127.0.0.1:7844`) and picks a reachable edge address
//! behind it.
//!
//! TLS is never terminated here: bytes are copied verbatim in both
//! directions, so the client still validates Cloudflare's own certificate
//! end to end and the local CA is not involved at all.
//!
//! The relay is off unless `advanced.relay.enabled` is set. When off, the
//! runtime binds no socket and spawns no task.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use parking_lot::RwLock;
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::RelayConfig;
use crate::resolver::Resolver;
use crate::util::{apply_tcp_keepalive, parse_authority};

/// Per-candidate connect deadline. Bounded so one black-holed edge address
/// cannot hold the client's own connect attempt for its full timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Candidates raced at once. The first success wins and the rest are dropped.
const RACE_SIZE: usize = 8;
/// Delay between successive candidate starts, so the first address gets a
/// head start instead of every socket being opened at the same instant.
const RACE_STAGGER: Duration = Duration::from_millis(150);
/// Copy buffer per direction. The tunnel is a single long-lived connection,
/// so the extra memory buys throughput on high-RTT links.
const COPY_BUFFER: usize = 64 * 1024;
/// How long an address that just failed stays out of the candidate list.
const FAILURE_TTL: Duration = Duration::from_secs(60);
/// Upper bound on remembered failures; the candidate list is small, so this
/// only guards against a hand-edited config with thousands of entries.
const MAX_FAILURES: usize = 256;

/// A running relay listener.
pub struct RelayHandle {
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl RelayHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), self.task).await;
    }
}

/// Cross-connection state. Everything here is per-listener and bounded by the
/// candidate list, so a relay that is never enabled never allocates it.
struct State {
    /// The address that worked last. New connections try it first and only
    /// fall back to racing when it fails, so the steady state opens exactly
    /// one upstream socket per accepted connection.
    last_good: RwLock<Option<IpAddr>>,
    /// Addresses that failed recently, with the time of the failure.
    failures: RwLock<HashMap<IpAddr, Instant>>,
}

impl State {
    fn new() -> Self {
        Self {
            last_good: RwLock::new(None),
            failures: RwLock::new(HashMap::new()),
        }
    }

    fn note_success(&self, ip: IpAddr) {
        *self.last_good.write() = Some(ip);
        self.failures.write().remove(&ip);
    }

    fn note_failure(&self, ip: IpAddr) {
        let mut failures = self.failures.write();
        if failures.len() >= MAX_FAILURES {
            let now = Instant::now();
            failures.retain(|_, at| now.duration_since(*at) < FAILURE_TTL);
        }
        failures.insert(ip, Instant::now());
    }

    fn recently_failed(&self, ip: IpAddr) -> bool {
        let failures = self.failures.read();
        failures
            .get(&ip)
            .is_some_and(|at| at.elapsed() < FAILURE_TTL)
    }

    fn clear(&self) {
        *self.last_good.write() = None;
        self.failures.write().clear();
    }
}

/// Bind the relay and start accepting.
///
/// `resolver` is only consulted when the config lists no explicit candidates
/// and `use_doh` is on. Passing `None` falls back to the system resolver.
pub async fn start(cfg: &RelayConfig, resolver: Option<Arc<Resolver>>) -> Result<RelayHandle> {
    // Owned copy: the accept loop outlives this call, and the config snapshot
    // it came from may be replaced by a hot reload at any time.
    let cfg = cfg.clone();
    let listen = cfg
        .listen
        .context("advanced.relay.listen is required when the relay is enabled")?;
    let (host, port) = target_parts(&cfg)?;

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding the raw relay on {listen}"))?;
    let local_addr = listener.local_addr()?;

    let state = Arc::new(State::new());
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    // Resolve once up front so a misconfigured target fails the start instead
    // of every accepted connection.
    if cfg.candidates.is_empty() {
        let initial = resolve(&cfg, &host, port, resolver.as_deref()).await?;
        if initial.is_empty() {
            bail!("no upstream address for {host}:{port}");
        }
        tracing::info!(
            target = %format!("{host}:{port}"),
            candidates = initial.len(),
            "raw relay resolved its upstream"
        );
    }

    let task = tokio::spawn(async move {
        let mut backoff = Duration::from_millis(50);
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((client, peer)) => {
                            backoff = Duration::from_millis(50);
                            // Both sides must have Nagle off: the tunnel
                            // carries interactive frames (SSH, WebSocket) where
                            // delayed ACKs would add tens of milliseconds.
                            let _ = client.set_nodelay(true);
                            apply_tcp_keepalive(&client);
                            let state = state.clone();
                            let cfg = cfg.clone();
                            let resolver = resolver.clone();
                            // Connection tasks observe the same shutdown
                            // signal as the accept loop, so `stop()` closes
                            // live tunnels instead of leaving them copying
                            // bytes for an owner that is gone.
                            let mut connection_shutdown = shutdown_rx.clone();
                            tokio::spawn(async move {
                                tokio::select! {
                                    result = serve(client, peer, &cfg, &state, resolver.as_deref()) => {
                                        if let Err(error) = result {
                                            tracing::debug!(peer = %peer, error = %error, "relay connection closed");
                                        }
                                    }
                                    _ = connection_shutdown.changed() => {
                                        tracing::debug!(peer = %peer, "relay connection stopped");
                                    }
                                }
                            });
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, "relay accept failed");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(1));
                        }
                    }
                }
            }
        }
        state.clear();
        tracing::debug!("relay listener stopped");
    });

    Ok(RelayHandle {
        local_addr,
        shutdown: shutdown_tx,
        task,
    })
}

async fn serve(
    mut client: TcpStream,
    peer: SocketAddr,
    cfg: &RelayConfig,
    state: &State,
    resolver: Option<&Resolver>,
) -> Result<()> {
    let (ip, mut upstream) = dial(cfg, state, resolver).await?;
    state.note_success(ip);
    tracing::debug!(peer = %peer, upstream = %ip, "relay connected");
    let (to_upstream, to_client) =
        copy_bidirectional_with_sizes(&mut client, &mut upstream, COPY_BUFFER, COPY_BUFFER)
            .await
            .with_context(|| format!("relaying to {ip}"))?;
    tracing::debug!(
        peer = %peer,
        upstream = %ip,
        sent = to_upstream,
        received = to_client,
        "relay finished"
    );
    Ok(())
}

/// Pick an upstream: last-good first, then the candidate list.
async fn dial(
    cfg: &RelayConfig,
    state: &State,
    resolver: Option<&Resolver>,
) -> Result<(IpAddr, TcpStream)> {
    let (host, port) = target_parts(cfg)?;

    // Copy the value out so the guard is released before the await; a
    // parking_lot guard is not `Send` and would make the task non-spawnable.
    let last_good = *state.last_good.read();
    if let Some(ip) = last_good {
        match connect_one(SocketAddr::new(ip, port)).await {
            Ok(stream) => return Ok((ip, stream)),
            Err(error) => {
                tracing::debug!(ip = %ip, error = %error, "last-good relay address failed");
                state.note_failure(ip);
            }
        }
    }

    let mut candidates = if cfg.candidates.is_empty() {
        resolve(cfg, &host, port, resolver).await?
    } else {
        cfg.candidates.clone()
    };
    if candidates.is_empty() {
        bail!("no upstream address for {host}:{port}");
    }

    // Prefer addresses that have not just failed, but never end up with an
    // empty list: a stale failure record must not make the relay dead. If
    // every candidate is cooling down, the whole list is retried anyway — a
    // failed guess costs one connect timeout, a dead relay costs the tunnel.
    let healthy: Vec<IpAddr> = candidates
        .iter()
        .copied()
        .filter(|ip| !state.recently_failed(*ip))
        .collect();
    if !healthy.is_empty() {
        candidates = healthy;
    } else {
        tracing::debug!(
            candidates = candidates.len(),
            "every relay candidate is cooling down; retrying the full list"
        );
    }
    candidates.truncate(RACE_SIZE);

    match race(&candidates, port).await {
        Some((ip, stream)) => Ok((ip, stream)),
        None => {
            for ip in &candidates {
                state.note_failure(*ip);
            }
            bail!("every relay candidate failed for {host}:{port}")
        }
    }
}

/// Connect to the first candidate that answers, staggering the starts so the
/// preferred address gets a head start instead of opening every socket at once.
async fn race(candidates: &[IpAddr], port: u16) -> Option<(IpAddr, TcpStream)> {
    let mut pending = FuturesUnordered::new();
    for (index, ip) in candidates.iter().copied().enumerate() {
        let delay = RACE_STAGGER * index as u32;
        pending.push(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            (ip, connect_one(SocketAddr::new(ip, port)).await)
        });
    }
    while let Some((ip, result)) = pending.next().await {
        if let Ok(stream) = result {
            return Some((ip, stream));
        }
    }
    None
}

async fn connect_one(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
    let _ = stream.set_nodelay(true);
    apply_tcp_keepalive(&stream);
    Ok(stream)
}

async fn resolve(
    cfg: &RelayConfig,
    host: &str,
    port: u16,
    resolver: Option<&Resolver>,
) -> Result<Vec<IpAddr>> {
    if cfg.use_doh {
        if let Some(resolver) = resolver {
            match resolver.resolve_ips(host).await {
                Ok(answer) if !answer.ips.is_empty() => return Ok(answer.ips),
                Ok(_) => tracing::warn!(host = %host, "DoH returned no address; falling back"),
                Err(error) => {
                    tracing::warn!(host = %host, error = %error, "DoH lookup failed; falling back")
                }
            }
        }
    }
    // System resolver last: it is often the very thing that is broken, which
    // is why explicit candidates and DoH come first.
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}"))?
        .collect();
    Ok(dedup(addrs.into_iter().map(|addr| addr.ip())))
}

fn dedup(ips: impl Iterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for ip in ips {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

fn target_parts(cfg: &RelayConfig) -> Result<(String, u16)> {
    let target = cfg
        .target
        .as_deref()
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .context("advanced.relay.target is required when the relay is enabled")?;
    parse_authority(target, 7844).with_context(|| format!("invalid relay target `{target}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn cfg(target: SocketAddr) -> RelayConfig {
        RelayConfig {
            enabled: true,
            listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            target: Some(target.to_string()),
            candidates: vec![target.ip()],
            use_doh: false,
        }
    }

    /// A tiny echo server standing in for Cloudflare's edge.
    async fn echo_on(ip: &str) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        (addr, task)
    }

    async fn echo() -> (SocketAddr, JoinHandle<()>) {
        echo_on("127.0.0.1").await
    }

    #[test]
    fn the_relay_is_off_by_default() {
        // The whole point of the feature: an untouched config must not listen.
        assert!(!RelayConfig::default().enabled);
    }

    #[test]
    fn an_enabled_relay_needs_a_target() {
        let empty = RelayConfig {
            enabled: true,
            ..RelayConfig::default()
        };
        assert!(target_parts(&empty).is_err());
    }

    #[test]
    fn a_target_without_a_port_uses_the_tunnel_port() {
        let cfg = RelayConfig {
            target: Some("region1.v2.argotunnel.com".to_string()),
            ..RelayConfig::default()
        };
        assert_eq!(
            target_parts(&cfg).unwrap(),
            ("region1.v2.argotunnel.com".to_string(), 7844)
        );
    }

    #[tokio::test]
    async fn bytes_are_relayed_verbatim() {
        let (upstream, _task) = echo().await;
        let relay = start(&cfg(upstream), None).await.unwrap();

        let mut client = TcpStream::connect(relay.local_addr()).await.unwrap();
        client.write_all(b"hello relay").await.unwrap();
        let mut buf = [0u8; 11];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello relay");

        relay.stop().await;
    }

    #[tokio::test]
    async fn a_refused_candidate_falls_through_to_a_live_one() {
        // The first candidate is IPv6 loopback with nothing listening, so it is
        // refused immediately; the echo server only listens on IPv4 loopback.
        // (127.0.0.2 is not bindable on macOS, so the two candidates must
        // differ in address family rather than in the 127/8 host octet.)
        let (upstream, _task) = echo().await;
        let mut config = cfg(upstream);
        config.candidates = vec![IpAddr::from(std::net::Ipv6Addr::LOCALHOST), upstream.ip()];
        let relay = start(&config, None).await.unwrap();

        let mut client = TcpStream::connect(relay.local_addr()).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        relay.stop().await;
    }

    #[tokio::test]
    async fn the_last_good_address_is_reused() {
        let (upstream, _task) = echo().await;
        let relay = start(&cfg(upstream), None).await.unwrap();

        for _ in 0..3 {
            let mut client = TcpStream::connect(relay.local_addr()).await.unwrap();
            client.write_all(b"x").await.unwrap();
            let mut buf = [0u8; 1];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"x");
        }

        relay.stop().await;
    }

    #[tokio::test]
    async fn a_recently_failed_address_is_deprioritized() {
        let state = State::new();
        let bad = IpAddr::from([192, 0, 2, 1]);
        let good = IpAddr::from([192, 0, 2, 2]);
        state.note_failure(bad);
        assert!(state.recently_failed(bad));
        assert!(!state.recently_failed(good));
        // A success clears the failure record for that address.
        state.note_success(bad);
        assert!(!state.recently_failed(bad));
        assert_eq!(*state.last_good.read(), Some(bad));
    }

    #[tokio::test]
    async fn stop_closes_the_listener() {
        let (upstream, _task) = echo().await;
        let relay = start(&cfg(upstream), None).await.unwrap();
        let addr = relay.local_addr();
        relay.stop().await;
        let result = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await;
        assert!(result.map(|r| r.is_err()).unwrap_or(true));
    }
}
