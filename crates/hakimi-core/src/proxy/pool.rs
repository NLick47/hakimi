//! Pooled upstream transport.
//!
//! The proxy used to open a TCP+TLS connection (and probe it) for every browser
//! request. This module keeps hyper's connection pool alive per authority instead:
//!
//! - one HTTP/2 connection multiplexes all requests for a host;
//! - HTTP/1.1 connections are kept alive and reused when the origin does not offer h2;
//! - TLS session tickets are shared through [`crate::ip_tester::TlsContext`];
//! - a real TLS handshake performs the certificate validation, so no separate probe is
//!   needed before the request;
//! - the last successful route is remembered per authority and reused for new
//!   connections until it fails.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use http::uri::Uri;
use http::{Method, Request, Response, Uri as HttpUri};
use http_body_util::{Either, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tower_service::Service;

use crate::config::AppConfig;
use crate::decision::{ConnectPlan, DecisionEngine, Route, RouteCursor};
use crate::domain::DomainMatcher;
use crate::ip_tester::TlsContext;
use crate::strategy::{FailureReason, TlsMode};

/// Request body type understood by the pooled clients. Forwarded requests stream the
/// browser body directly; warm-up requests use an empty `Full` body.
pub(crate) type UpstreamBody = Either<Incoming, Full<Bytes>>;

/// Browser response bodies stay streaming; the pool only owns the upstream connection.
pub(crate) type UpstreamResponse = Response<UpstreamResponseBody>;

/// Response body either streams the upstream `Incoming` directly or holds a per-host
/// concurrency permit until the last byte/frame is dropped.
pub(crate) enum UpstreamResponseBody {
    Plain(Incoming),
    Limited(LimitedBody),
}

pub(crate) struct LimitedBody {
    inner: Incoming,
    _permit: OwnedSemaphorePermit,
}

impl Body for UpstreamResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            UpstreamResponseBody::Plain(body) => Pin::new(body).poll_frame(cx),
            UpstreamResponseBody::Limited(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            UpstreamResponseBody::Plain(body) => body.is_end_stream(),
            UpstreamResponseBody::Limited(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            UpstreamResponseBody::Plain(body) => body.size_hint(),
            UpstreamResponseBody::Limited(body) => body.size_hint(),
        }
    }
}

impl Body for LimitedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

const SYSTEM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WARM_TIMEOUT: Duration = Duration::from_secs(12);

/// Candidates raced in parallel per batch while a cold connection hunts for a route.
const RACE_SIZE: usize = 8;
/// Delay between race batch member starts, so the first candidate usually wins on a
/// healthy network and the race only costs extra handshakes when it is actually broken.
const RACE_STAGGER: Duration = Duration::from_millis(150);

#[derive(Default)]
pub(crate) struct UpstreamStats {
    connections_opened: AtomicU64,
    connections_h2: AtomicU64,
    connections_h1: AtomicU64,
    connection_failures: AtomicU64,
    requests: AtomicU64,
    responses_h2: AtomicU64,
    responses_h1: AtomicU64,
    request_errors: AtomicU64,
    warm_success: AtomicU64,
    warm_failures: AtomicU64,
}

impl UpstreamStats {
    pub(crate) fn snapshot_json(&self) -> serde_json::Value {
        serde_json::json!({
            "connectionsOpened": self.connections_opened.load(Ordering::Relaxed),
            "connectionsH2": self.connections_h2.load(Ordering::Relaxed),
            "connectionsH1": self.connections_h1.load(Ordering::Relaxed),
            "connectionFailures": self.connection_failures.load(Ordering::Relaxed),
            "requests": self.requests.load(Ordering::Relaxed),
            "responsesH2": self.responses_h2.load(Ordering::Relaxed),
            "responsesH1": self.responses_h1.load(Ordering::Relaxed),
            "requestErrors": self.request_errors.load(Ordering::Relaxed),
            "warmSuccess": self.warm_success.load(Ordering::Relaxed),
            "warmFailures": self.warm_failures.load(Ordering::Relaxed),
        })
    }
}

pub struct UpstreamPool {
    auto: Client<RouteConnector, UpstreamBody>,
    upgrade: Client<RouteConnector, UpstreamBody>,
    http1_hosts: Arc<DomainMatcher>,
    http1_limit: usize,
    http1_slots: Mutex<HashMap<String, Arc<Semaphore>>>,
    stats: Arc<UpstreamStats>,
}

/// One route discovery per domain at a time: concurrent cold connections for the same host
/// share a single probe instead of each racing its own candidate batch.
struct Discovery {
    inflight: Mutex<HashMap<String, Arc<Inflight>>>,
}

#[derive(Default)]
struct Inflight {
    notify: Notify,
    result: tokio::sync::Mutex<Option<Result<ConnectPlan, String>>>,
}

impl UpstreamPool {
    pub fn new(engine: Arc<DecisionEngine>, tls: Arc<TlsContext>, config: &AppConfig) -> Arc<Self> {
        let stats = Arc::new(UpstreamStats::default());
        let idle = Duration::from_secs(config.advanced.upstream_idle_secs.max(10));
        let max_idle = config.advanced.upstream_max_idle_per_host.max(1);

        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(idle)
            .pool_max_idle_per_host(max_idle)
            .timer(TokioTimer::new())
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true);

        let http1_hosts = DomainMatcher::from_patterns(
            config
                .advanced
                .http1_hosts
                .iter()
                .map(|pattern| ("http1", pattern.as_str())),
        )
        .unwrap_or_default();
        let http1_hosts = Arc::new(http1_hosts);
        let discovery = Arc::new(Discovery {
            inflight: Mutex::new(HashMap::new()),
        });
        let auto_connector = RouteConnector {
            engine: engine.clone(),
            tls: tls.clone(),
            http1_only: false,
            http1_hosts: http1_hosts.clone(),
            discovery: discovery.clone(),
            stats: stats.clone(),
        };
        let upgrade_connector = RouteConnector {
            engine: engine.clone(),
            tls,
            http1_only: true,
            http1_hosts: http1_hosts.clone(),
            discovery: discovery.clone(),
            stats: stats.clone(),
        };
        Arc::new(Self {
            auto: builder.build(auto_connector),
            upgrade: builder.build(upgrade_connector),
            http1_hosts,
            http1_limit: config.advanced.http1_max_concurrent.max(1),
            http1_slots: Mutex::new(HashMap::new()),
            stats,
        })
    }

    /// Send an upstream request through the pool. `upgrade` selects the HTTP/1.1-only
    /// client so WebSocket handshakes cannot be routed over HTTP/2.
    pub(crate) async fn send(
        &self,
        request: Request<UpstreamBody>,
        upgrade: bool,
    ) -> std::result::Result<UpstreamResponse, String> {
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        let host = request.uri().host().map(ToOwned::to_owned);
        let permit = if !upgrade {
            match host
                .as_deref()
                .filter(|host| self.http1_hosts.match_host(host).is_some())
            {
                Some(host) => {
                    let semaphore = self.host_slots(host);
                    match semaphore.acquire_owned().await {
                        Ok(permit) => Some(permit),
                        Err(_) => return Err("image connection limiter is closed".into()),
                    }
                }
                None => None,
            }
        } else {
            None
        };
        let client = if upgrade { &self.upgrade } else { &self.auto };
        let debug_host = request.uri().host().map(ToOwned::to_owned);
        let debug_path = request.uri().path().to_string();
        match client.request(request).await {
            Ok(response) => {
                if response.version() == http::Version::HTTP_2 {
                    self.stats.responses_h2.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.responses_h1.fetch_add(1, Ordering::Relaxed);
                }
                if response.status().is_client_error() || response.status().is_server_error() {
                    if let Some(host) = debug_host.as_deref() {
                        if self.http1_hosts.match_host(host).is_some() {
                            tracing::warn!(
                                host,
                                path = %debug_path,
                                status = response.status().as_u16(),
                                "image upstream returned an HTTP error"
                            );
                        }
                    }
                }
                let (parts, body) = response.into_parts();
                let body = match permit {
                    Some(permit) => UpstreamResponseBody::Limited(LimitedBody {
                        inner: body,
                        _permit: permit,
                    }),
                    None => UpstreamResponseBody::Plain(body),
                };
                Ok(Response::from_parts(parts, body))
            }
            Err(error) => {
                self.stats.request_errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    host = debug_host.as_deref().unwrap_or(""),
                    path = %debug_path,
                    error = %error,
                    "upstream request failed"
                );
                Err(format!("{error:?}"))
            }
        }
    }

    fn host_slots(&self, host: &str) -> Arc<Semaphore> {
        let mut slots = self.http1_slots.lock();
        if slots.len() > 1024 {
            slots.retain(|_, slot| Arc::strong_count(slot) > 1);
        }
        slots
            .entry(host.to_ascii_lowercase())
            .or_insert_with(|| Arc::new(Semaphore::new(self.http1_limit)))
            .clone()
    }

    /// Warm one exact host: a HEAD request makes hyper establish (or reuse) the pooled
    /// connection, resolving DoH/ECH only if no plan is cached. Status codes are ignored;
    /// the point is the transport.
    pub(crate) async fn warm(&self, host: &str, port: u16) {
        let authority = if port == 443 {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        let uri: HttpUri = match format!("https://{authority}/").parse() {
            Ok(uri) => uri,
            Err(error) => {
                tracing::debug!(host, error = %error, "cannot build warm-up URI");
                return;
            }
        };
        let request = match Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .header(http::header::ACCEPT, "*/*")
            .body(Either::Right(Full::new(Bytes::new())))
        {
            Ok(request) => request,
            Err(error) => {
                tracing::debug!(host, error = %error, "cannot build warm-up request");
                return;
            }
        };
        match tokio::time::timeout(WARM_TIMEOUT, self.auto.request(request)).await {
            Ok(Ok(response)) => {
                self.stats.warm_success.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    host,
                    status = response.status().as_u16(),
                    version = ?response.version(),
                    "upstream warmed"
                );
                // HEAD responses have no body; dropping keeps the connection in the pool.
                drop(response);
            }
            Ok(Err(error)) => {
                self.stats.warm_failures.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(host, error = ?error, "upstream warm-up failed");
            }
            Err(_) => {
                self.stats.warm_failures.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(host, "upstream warm-up timed out");
            }
        }
    }

    pub(crate) fn stats_json(&self) -> serde_json::Value {
        self.stats.snapshot_json()
    }
}

#[derive(Clone)]
struct RouteConnector {
    engine: Arc<DecisionEngine>,
    tls: Arc<TlsContext>,
    http1_only: bool,
    http1_hosts: Arc<DomainMatcher>,
    discovery: Arc<Discovery>,
    stats: Arc<UpstreamStats>,
}

impl Service<Uri> for RouteConnector {
    type Response = TokioIo<PooledIo>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.connect(uri).await })
    }
}

impl RouteConnector {
    fn candidate_timeout(&self) -> Duration {
        Duration::from_millis(
            self.engine
                .config
                .snapshot()
                .advanced
                .ip_timeout_ms
                .clamp(500, 10_000),
        )
    }

    async fn connect(&self, uri: Uri) -> Result<TokioIo<PooledIo>> {
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            other => return Err(anyhow!("unsupported upstream scheme {other:?}")),
        };
        let host = uri
            .host()
            .ok_or_else(|| anyhow!("upstream URI has no host"))?
            .to_ascii_lowercase();
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let force_http1 = self.http1_only || self.http1_hosts.match_host(&host).is_some();
        let result = if https {
            self.connect_tls(&host, port, force_http1).await
        } else {
            self.connect_plain(&host, port).await
        };
        match result {
            Ok(io) => {
                self.stats
                    .connections_opened
                    .fetch_add(1, Ordering::Relaxed);
                if io.h2 {
                    self.stats.connections_h2.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.connections_h1.fetch_add(1, Ordering::Relaxed);
                }
                Ok(TokioIo::new(io))
            }
            Err(error) => {
                self.stats
                    .connection_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    async fn connect_tls(&self, host: &str, port: u16, force_http1: bool) -> Result<PooledIo> {
        match self.engine.route(host, port, true) {
            Route::Bypass(_) => self.connect_direct_system(host, port, force_http1).await,
            Route::Blocked(outcome) => Err(anyhow!(
                "{}",
                outcome
                    .diagnostics
                    .detail
                    .unwrap_or_else(|| "route blocked".into())
            )),
            Route::Group(cursor) => self.connect_group(*cursor, true, force_http1).await,
        }
    }

    async fn connect_plain(&self, host: &str, port: u16) -> Result<PooledIo> {
        match self.engine.route(host, port, false) {
            Route::Bypass(_) => {
                let stream =
                    tokio::time::timeout(SYSTEM_CONNECT_TIMEOUT, TcpStream::connect((host, port)))
                        .await
                        .map_err(|_| anyhow!("TCP connect to {host}:{port} timed out"))?
                        .with_context(|| format!("TCP connect to {host}:{port} failed"))?;
                let _ = stream.set_nodelay(true);
                crate::util::apply_tcp_keepalive(&stream);
                Ok(PooledIo {
                    io: Transport::Tcp(stream),
                    h2: false,
                })
            }
            Route::Blocked(outcome) => Err(anyhow!(
                "{}",
                outcome
                    .diagnostics
                    .detail
                    .unwrap_or_else(|| "route blocked".into())
            )),
            Route::Group(cursor) => self.connect_group(*cursor, false, false).await,
        }
    }

    async fn connect_group(
        &self,
        mut cursor: RouteCursor,
        tls: bool,
        force_http1: bool,
    ) -> Result<PooledIo> {
        // A previously successful route wins. If it fails, it is forgotten and the lazy
        // candidate generator continues with the normal priority order. After a catalog
        // update the cursor tells us to try the new remote IPs first.
        if !cursor.skip_once() {
            if let Some(plan) = self.engine.cached_plan(cursor.domain(), cursor.port(), tls) {
                let started = std::time::Instant::now();
                match self.connect_plan(&plan, force_http1).await {
                    Ok(io) => {
                        cursor.note_success(&plan, started.elapsed().as_millis() as u64);
                        return Ok(io);
                    }
                    Err((reason, detail)) => {
                        self.engine.forget_plan(&plan.domain, plan.port, plan.tls);
                        cursor.note_failure(&plan, reason, detail);
                        cursor.skip_plan(&plan);
                    }
                }
            }
        }

        let key = format!("{}|{}|{}", cursor.domain(), cursor.port(), tls);
        let (inflight, leader) = {
            let mut map = self.discovery.inflight.lock();
            if let Some(existing) = map.get(&key) {
                (existing.clone(), false)
            } else {
                let entry = Arc::new(Inflight::default());
                map.insert(key.clone(), entry.clone());
                (entry, true)
            }
        };
        if leader {
            let outcome = self.race_plans(cursor, force_http1).await;
            let shared = match &outcome {
                Ok((plan, _)) => Ok(plan.clone()),
                Err(error) => Err(error.clone()),
            };
            *inflight.result.lock().await = Some(shared);
            inflight.notify.notify_waiters();
            self.discovery.inflight.lock().remove(&key);
            return outcome.map(|(_, io)| io).map_err(anyhow::Error::msg);
        }

        inflight.notify.notified().await;
        let plan = {
            let guard = inflight.result.lock().await;
            match guard.as_ref() {
                Some(Ok(plan)) => plan.clone(),
                Some(Err(error)) => return Err(anyhow!("{error}")),
                None => return Err(anyhow!("route discovery failed")),
            }
        };
        // The leader already validated this plan; followers just open their own connection.
        let started = std::time::Instant::now();
        match self.connect_plan(&plan, force_http1).await {
            Ok(io) => {
                self.engine
                    .note_tunnel_success(&plan, started.elapsed().as_millis() as u64);
                Ok(io)
            }
            Err((_, detail)) => {
                self.engine.forget_plan(&plan.domain, plan.port, plan.tls);
                Err(anyhow!("{detail}"))
            }
        }
    }

    /// Race candidate batches until one connects. Only the single-flight leader runs this;
    /// every other caller for the same domain waits for and reuses the winning plan.
    async fn race_plans(
        &self,
        mut cursor: RouteCursor,
        force_http1: bool,
    ) -> std::result::Result<(ConnectPlan, PooledIo), String> {
        loop {
            // Pull a batch of plans and race them. The first plan (the learned-best
            // route) gets a short head start; every other route fires together, so a
            // batch of failing candidates costs one timeout in parallel instead of
            // RACE_SIZE timeouts serially. A dead route no longer makes every
            // following candidate wait out its full timeout.
            let mut plans: Vec<ConnectPlan> = Vec::new();
            for _ in 0..RACE_SIZE {
                match cursor.next_plan().await {
                    Some(plan) => plans.push(plan),
                    None => break,
                }
            }
            if plans.is_empty() {
                let detail = cursor
                    .outcome()
                    .and_then(|outcome| outcome.diagnostics.detail.clone())
                    .or_else(|| {
                        cursor
                            .outcome()
                            .map(|outcome| format!("{:?}", outcome.diagnostics.state))
                    })
                    .unwrap_or_else(|| "no route candidate succeeded".into());
                return Err(detail);
            }

            type RaceResult = Result<(ConnectPlan, PooledIo, u64), (ConnectPlan, FailureReason, String)>;
            let mut pending = FuturesUnordered::<
                Pin<Box<dyn Future<Output = RaceResult> + Send>>,
            >::new();
            for (index, plan) in plans.into_iter().enumerate() {
                let this = self.clone();
                pending.push(Box::pin(async move {
                    // The priority route starts immediately; the rest share one short
                    // head-start delay so the race still prefers it when close.
                    if index > 0 {
                        tokio::time::sleep(RACE_STAGGER).await;
                    }
                    let started = std::time::Instant::now();
                    match this.connect_plan(&plan, force_http1).await {
                        Ok(io) => Ok((plan, io, started.elapsed().as_millis() as u64)),
                        Err((reason, detail)) => Err((plan, reason, detail)),
                    }
                }));
            }

            while let Some(result) = pending.next().await {
                match result {
                    Ok((plan, io, latency)) => {
                        cursor.note_success(&plan, latency);
                        // Dropping `pending` cancels the losing handshakes mid-flight.
                        return Ok((plan, io));
                    }
                    Err((plan, reason, detail)) => {
                        self.engine.forget_plan(&plan.domain, plan.port, plan.tls);
                        cursor.note_failure(&plan, reason, detail);
                    }
                }
            }
            // The whole batch failed; the loop pulls the next batch from the cursor.
        }
    }

    async fn connect_plan(
        &self,
        plan: &ConnectPlan,
        force_http1: bool,
    ) -> std::result::Result<PooledIo, (FailureReason, String)> {
        let address = SocketAddr::new(plan.ip, plan.port);
        if !plan.tls {
            let stream =
                tokio::time::timeout(self.candidate_timeout(), TcpStream::connect(address))
                    .await
                    .map_err(|_| {
                        (
                            FailureReason::TcpTimeout,
                            format!("TCP connect to {address} timed out"),
                        )
                    })?
                    .map_err(|error| (FailureReason::TcpRefused, error.to_string()))?;
            let _ = stream.set_nodelay(true);
            crate::util::apply_tcp_keepalive(&stream);
            return Ok(PooledIo {
                io: Transport::Tcp(stream),
                h2: false,
            });
        }

        let sni = plan.sni.as_deref();
        let ech = plan.ech_config.as_deref();
        let connector = self.tls.clone();
        let mode = plan.mode;
        let domain = plan.domain.clone();
        let result = tokio::time::timeout(self.candidate_timeout(), async move {
            if self.http1_only || force_http1 {
                connector
                    .connect_http1(plan.ip, plan.port, &domain, mode, sni, ech)
                    .await
            } else {
                connector
                    .connect(plan.ip, plan.port, &domain, mode, sni, ech)
                    .await
            }
        })
        .await;
        match result {
            Ok(Ok(stream)) => {
                let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                Ok(PooledIo {
                    io: Transport::Tls(Box::new(stream)),
                    h2,
                })
            }
            Ok(Err(error)) => Err((error.reason(), error.detail())),
            Err(_) => Err((
                FailureReason::TcpTimeout,
                format!("TLS connection to {address} timed out"),
            )),
        }
    }

    async fn connect_direct_system(
        &self,
        host: &str,
        port: u16,
        force_http1: bool,
    ) -> Result<PooledIo> {
        let addresses: Vec<std::net::IpAddr> = tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("resolving {host}:{port}"))?
            .map(|address| address.ip())
            .collect();
        // Staggered race across resolved addresses (Happy-Eyeballs style): a black-holed
        // IPv6 route no longer delays the IPv4 fallback by a full timeout.
        let mut index = 0;
        let mut last_error: Option<String> = None;
        loop {
            let batch: Vec<std::net::IpAddr> =
                addresses.iter().skip(index).take(RACE_SIZE).copied().collect();
            index += batch.len();
            if batch.is_empty() {
                return Err(anyhow!(
                    "{}",
                    last_error.unwrap_or_else(|| format!("no address found for {host}"))
                ));
            }
            type BypassResult = Result<PooledIo, String>;
            let mut pending =
                FuturesUnordered::<Pin<Box<dyn Future<Output = BypassResult> + Send>>>::new();
            for (i, address) in batch.iter().enumerate() {
                let this = self.clone();
                let address = *address;
                let host = host.to_string();
                let force = force_http1;
                pending.push(Box::pin(async move {
                    if i > 0 {
                        tokio::time::sleep(RACE_STAGGER * i as u32).await;
                    }
                    let result = tokio::time::timeout(SYSTEM_CONNECT_TIMEOUT, async {
                        if force {
                            this.tls
                                .connect_http1(address, port, &host, TlsMode::Direct, None, None)
                                .await
                        } else {
                            this.tls
                                .connect(address, port, &host, TlsMode::Direct, None, None)
                                .await
                        }
                    })
                    .await;
                    match result {
                        Ok(Ok(stream)) => {
                            let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                            Ok(PooledIo {
                                io: Transport::Tls(Box::new(stream)),
                                h2,
                            })
                        }
                        Ok(Err(error)) => Err(error.detail()),
                        Err(_) => Err("TLS connection timed out".into()),
                    }
                }));
            }
            while let Some(result) = pending.next().await {
                match result {
                    Ok(io) => return Ok(io),
                    Err(detail) => last_error = Some(detail),
                }
            }
            // The whole batch failed; try the next one.
        }
    }
}

struct PooledIo {
    io: Transport,
    h2: bool,
}

enum Transport {
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Tcp(TcpStream),
}

impl Connection for PooledIo {
    fn connected(&self) -> Connected {
        if self.h2 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}

impl AsyncRead for PooledIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            Transport::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
            Transport::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PooledIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().io {
            Transport::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
            Transport::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            Transport::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
            Transport::Tcp(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            Transport::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
            Transport::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::cache::{CacheManager, LastGoodEntry};
    use crate::catalog::CatalogManager;
    use crate::config::{ConfigManager, GroupConfig};
    use crate::decision::DecisionEngine;
    use crate::paths::Paths;
    use crate::resolver::Resolver;
    use crate::status::StatusStore;
    use crate::strategy::{IpSource, Strategy};
    use crate::util::now;

    fn engine_for(dir: &std::path::Path) -> (Arc<DecisionEngine>, Arc<ConfigManager>) {
        let paths = Paths::new(dir);
        paths.ensure().unwrap();
        let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
        config
            .mutate(|config| {
                config.groups.clear();
                config.groups.push(GroupConfig {
                    id: "test".into(),
                    name: "Test".into(),
                    domains: vec!["upstream.test".into()],
                    strategy: Strategy::Direct,
                    enabled: true,
                    sni: None,
                    experimental: false,
                    ech_shared: false,
                });
                Ok(())
            })
            .unwrap();
        let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
        cache.put_last_good(LastGoodEntry {
            domain: "upstream.test".into(),
            ip: "127.0.0.1".parse().unwrap(),
            strategy: Strategy::Direct,
            source: IpSource::Cache,
            network_id: "test".into(),
            saved_at: now(),
            catalog_version: 0,
        });
        let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
        let status = Arc::new(StatusStore::new());
        let resolver = Resolver::new(cache.clone(), config.clone(), catalogs.clone());
        let tls = TlsContext::new().unwrap();
        let engine = DecisionEngine::new(config.clone(), cache, catalogs, resolver, tls, status);
        (engine, config)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http1_connections_are_reused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepted = accepts.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 8192];
                    loop {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                if socket
                                    .write_all(
                                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                                    )
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let (engine, config) = engine_for(dir.path());
        let tls = TlsContext::new().unwrap();
        let pool = UpstreamPool::new(engine, tls, &config.snapshot());
        let uri = format!("http://upstream.test:{port}/");

        for _ in 0..3 {
            let request = Request::builder()
                .method(Method::GET)
                .uri(&uri)
                .body(Either::Right(Full::new(Bytes::new())))
                .unwrap();
            let response = pool.send(request, false).await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"ok");
        }

        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "the HTTP/1.1 connection should be reused across sequential requests"
        );
        let stats = pool.stats_json();
        assert_eq!(stats["connectionsOpened"], 1);
        assert_eq!(stats["responsesH1"], 3);
    }
}
