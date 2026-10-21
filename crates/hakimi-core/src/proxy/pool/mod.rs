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

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

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
use parking_lot::{Mutex, RwLock};
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

/// After a response takes this long, the authority is considered unhealthy for a
/// short period. New requests then use a fresh, unpooled connection so a single
/// half-dead HTTP/2 connection cannot delay a whole page load again.
const SLOW_ROUTE_MARK_MS: u64 = 5_000;
const SLOW_ROUTE_TTL: Duration = Duration::from_secs(60);

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
    slow_responses: AtomicU64,
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
            "slowResponses": self.slow_responses.load(Ordering::Relaxed),
            "warmSuccess": self.warm_success.load(Ordering::Relaxed),
            "warmFailures": self.warm_failures.load(Ordering::Relaxed),
        })
    }
}

pub struct UpstreamPool {
    auto: Client<RouteConnector, UpstreamBody>,
    upgrade: Client<RouteConnector, UpstreamBody>,
    recovery: Client<RouteConnector, UpstreamBody>,
    engine: Arc<DecisionEngine>,
    /// Read on every request, written only after a slow/failed response.
    slow_hosts: RwLock<HashMap<String, Instant>>,
    http1_hosts: Arc<DomainMatcher>,
    http1_limit: usize,
    /// Read for every image-host request; written only when a new host appears.
    http1_slots: RwLock<HashMap<String, Arc<Semaphore>>>,
    stats: Arc<UpstreamStats>,
}

/// One route discovery per domain at a time: concurrent cold connections for the same host
/// share a single probe instead of each racing its own candidate batch.
struct Discovery {
    inflight: Mutex<HashMap<String, Arc<Inflight>>>,
}

fn build_client(
    config: &AppConfig,
    connector: RouteConnector,
    max_idle: usize,
) -> Client<RouteConnector, UpstreamBody> {
    let idle = Duration::from_secs(config.advanced.upstream_idle_secs.max(10));
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(idle)
        .pool_max_idle_per_host(max_idle)
        .timer(TokioTimer::new())
        .http2_adaptive_window(true)
        // Larger than the 64 KiB h2 defaults: a 1 MB image over a 50 ms
        // link would otherwise need ~16 window updates before reaching
        // line rate. Adaptive window still grows beyond these.
        .http2_initial_stream_window_size(1024 * 1024)
        .http2_initial_connection_window_size(4 * 1024 * 1024)
        // A half-open HTTP/2 connection used to stay in the pool for up to
        // 30s (next ping) + 10s (ping timeout). That matches the 38-39s
        // stalls seen on cached 304 revalidations: the request was checked
        // out before the dead connection was detected. Keep idle
        // connections probed often enough that they are evicted before the
        // next page load, without turning this into a busy loop.
        .http2_keep_alive_interval(Duration::from_secs(10))
        .http2_keep_alive_timeout(Duration::from_secs(5))
        .http2_keep_alive_while_idle(true);
    builder.build(connector)
}

#[derive(Default)]
struct Inflight {
    notify: Notify,
    /// Set exactly once — by the leader or, on cancellation, by its guard.
    /// Sync so `Drop` can publish without an async context.
    /// The plan is shared, so publishing it to the followers of one discovery
    /// does not copy the domain, group and SNI strings.
    result: Mutex<Option<Result<Arc<ConnectPlan>, String>>>,
}

/// Guarantees single-flight cleanup no matter how the leader's future ends.
/// A cancelled race (the browser aborts the navigation) still publishes an
/// error result and removes the map entry, so followers and later requests
/// never wait on a dead entry.
struct DiscoveryGuard<'a> {
    map: &'a Mutex<HashMap<String, Arc<Inflight>>>,
    key: String,
    entry: Arc<Inflight>,
}

impl Drop for DiscoveryGuard<'_> {
    fn drop(&mut self) {
        {
            let mut slot = self.entry.result.lock();
            if slot.is_none() {
                *slot = Some(Err("route discovery was cancelled".into()));
            }
        }
        self.entry.notify.notify_waiters();
        self.map.lock().remove(&self.key);
    }
}

impl UpstreamPool {
    pub fn new(engine: Arc<DecisionEngine>, tls: Arc<TlsContext>, config: &AppConfig) -> Arc<Self> {
        let stats = Arc::new(UpstreamStats::default());
        let max_idle = config.advanced.upstream_max_idle_per_host.max(1);

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
            auto: build_client(config, auto_connector.clone(), max_idle),
            upgrade: build_client(config, upgrade_connector, max_idle),
            // No idle connections: after a slow response, use this client to
            // guarantee that the next request starts on a fresh connection
            // instead of reusing the stalled one.
            recovery: build_client(config, auto_connector, 0),
            engine,
            slow_hosts: RwLock::new(HashMap::new()),
            http1_hosts,
            http1_limit: config.advanced.http1_max_concurrent.max(1),
            http1_slots: RwLock::new(HashMap::new()),
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
        let request_id = self.stats.requests.fetch_add(1, Ordering::Relaxed) + 1;
        // `http::Uri` clones its components as cheap `Bytes` handles. Keeping one
        // around lets the logging paths borrow host/path after the request is moved,
        // instead of allocating a new String for every forwarded request.
        let uri = request.uri().clone();
        let method = request.method().clone();
        let request_version = request.version();
        let scheme = uri.scheme_str().unwrap_or("");
        let host = uri.host();
        // Forwarded URIs are built from an already-normalized host, so the
        // per-request image-host check does not need to normalize again.
        let is_http1_host =
            host.is_some_and(|host| self.http1_hosts.match_normalized(host).is_some());
        let permit = if !upgrade && is_http1_host {
            let host = host.expect("is_http1_host requires a host");
            let semaphore = self.host_slots(host);
            match semaphore.acquire_owned().await {
                Ok(permit) => Some(permit),
                Err(_) => return Err("image connection limiter is closed".into()),
            }
        } else {
            None
        };
        let tls = uri.scheme_str() != Some("http");
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let recovery = !upgrade && host.is_some_and(|host| self.is_slow(host));
        let client = if upgrade {
            &self.upgrade
        } else if recovery {
            &self.recovery
        } else {
            &self.auto
        };
        let debug_host = host;
        let debug_path = uri.path();
        let started = std::time::Instant::now();
        match client.request(request).await {
            Ok(response) => {
                if response.version() == http::Version::HTTP_2 {
                    self.stats.responses_h2.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.responses_h1.fetch_add(1, Ordering::Relaxed);
                }
                // Slow upstream responses are the raw material for latency
                // optimization: they point at candidates that deserve a re-race.
                let elapsed_ms = started.elapsed().as_millis() as u64;
                if elapsed_ms > 2000 {
                    self.stats.slow_responses.fetch_add(1, Ordering::Relaxed);
                }
                if elapsed_ms > SLOW_ROUTE_MARK_MS {
                    if let Some(host) = debug_host {
                        // The established connection may be half-dead (packet
                        // loss, a stale h2 stream, or a path change). Do not
                        // pin the next request to it or to the same cached
                        // route; use a fresh connection and let the route
                        // cursor re-race candidates.
                        self.mark_slow(host);
                        self.engine.forget_plan(host, port, tls);
                    }
                }
                if elapsed_ms > 2000 {
                    tracing::warn!(
                        request_id,
                        method = %method,
                        scheme,
                        version = ?request_version,
                        host = ?debug_host,
                        path = %debug_path,
                        status = response.status().as_u16(),
                        elapsed_ms,
                        "slow upstream response"
                    );
                } else {
                    tracing::debug!(
                        request_id,
                        method = %method,
                        scheme,
                        version = ?request_version,
                        host = ?debug_host,
                        path = %debug_path,
                        status = response.status().as_u16(),
                        elapsed_ms,
                        "upstream response"
                    );
                }
                if (response.status().is_client_error() || response.status().is_server_error())
                    && is_http1_host
                {
                    tracing::warn!(
                        host = debug_host.unwrap_or(""),
                        path = %debug_path,
                        status = response.status().as_u16(),
                        "image upstream returned an HTTP error"
                    );
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
                if let Some(host) = debug_host {
                    self.mark_slow(host);
                    self.engine.forget_plan(host, port, tls);
                }
                tracing::warn!(
                    request_id,
                    method = %method,
                    scheme,
                    version = ?request_version,
                    host = debug_host.unwrap_or(""),
                    path = %debug_path,
                    error = %format!("{error:#}"),
                    "upstream request failed"
                );
                Err(format!("{error:?}"))
            }
        }
    }

    fn is_slow(&self, host: &str) -> bool {
        // Expired entries are harmless until the next write; leaving them in
        // place keeps this read path from needing a write lock or an upgrade.
        self.slow_hosts
            .read()
            .get(host)
            .is_some_and(|at| at.elapsed() < SLOW_ROUTE_TTL)
    }

    fn mark_slow(&self, host: &str) {
        let now = Instant::now();
        let mut hosts = self.slow_hosts.write();
        if hosts.len() >= 256 {
            hosts.retain(|_, at| now.duration_since(*at) < SLOW_ROUTE_TTL);
            if hosts.len() >= 256 {
                hosts.clear();
            }
        }
        hosts.insert(host.to_owned(), now);
    }

    fn host_slots(&self, host: &str) -> Arc<Semaphore> {
        // Hot path: every image request already has a slot after the first
        // one. Read it without taking the write lock or allocating a key.
        if let Some(slot) = self.http1_slots.read().get(host) {
            return slot.clone();
        }
        let mut slots = self.http1_slots.write();
        if let Some(slot) = slots.get(host) {
            return slot.clone();
        }
        if slots.len() > 1024 {
            slots.retain(|_, slot| Arc::strong_count(slot) > 1);
        }
        let slot = Arc::new(Semaphore::new(self.http1_limit));
        slots.insert(host.to_owned(), slot.clone());
        slot
    }

    /// Warm one exact host: a HEAD request makes hyper establish (or reuse) the pooled
    /// connection, resolving DoH/ECH only if no plan is cached. Status codes are ignored;
    /// the point is the transport.
    /// Returns true when a pooled connection for `host` is (still) established.
    /// The result lets the pre-warm loop retry: a first attempt can race the DoH
    /// expansion and come back empty-handed even though the host resolves fine.
    pub(crate) async fn warm(&self, host: &str, port: u16) -> bool {
        let authority = if port == 443 {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        let uri: HttpUri = match format!("https://{authority}/").parse() {
            Ok(uri) => uri,
            Err(error) => {
                tracing::debug!(host, error = %error, "cannot build warm-up URI");
                return false;
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
                return false;
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
                return true;
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
        false
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
            .ok_or_else(|| anyhow!("upstream URI has no host"))?;
        // The brackets of an IPv6 literal belong to the authority, not to the
        // host.  Routing and the direct fallback need the bare address,
        // otherwise the literal is treated as a name and never resolves.
        let host = crate::domain::bare_host(host);
        // Forwarded URIs normally carry an already-normalized host. Warm-up
        // callers can still pass a raw config entry (uppercase, trailing dot,
        // or IDN), so normalize only those edge cases before the hot-path
        // `route_normalized` call, which assumes a canonical host.
        let host = if host.bytes().any(|byte| byte.is_ascii_uppercase())
            || host.ends_with('.')
            || !host.is_ascii()
        {
            Cow::Owned(
                crate::domain::normalize_hostname(host)
                    .unwrap_or_else(|_| host.to_ascii_lowercase()),
            )
        } else {
            Cow::Borrowed(host)
        };
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let force_http1 = self.http1_only || self.http1_hosts.match_normalized(&host).is_some();
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
        match self.engine.route_normalized(host, port, true) {
            Route::Bypass(_) => self.connect_direct_system(host, port, force_http1).await,
            Route::Blocked(outcome) => Err(anyhow!(
                "{}",
                outcome
                    .diagnostics
                    .detail
                    .as_deref()
                    .unwrap_or("route blocked")
            )),
            Route::Group(cursor) => self.connect_group(*cursor, true, force_http1).await,
        }
    }

    async fn connect_plain(&self, host: &str, port: u16) -> Result<PooledIo> {
        match self.engine.route_normalized(host, port, false) {
            Route::Bypass(_) => {
                // Same Happy-Eyeballs treatment as CONNECT tunnels: a black-holed
                // AAAA answer must not hide a working IPv4 origin behind a full
                // per-address timeout.
                let stream =
                    super::connect::connect_host_staggered(host, port, SYSTEM_CONNECT_TIMEOUT)
                        .await
                        .map_err(|(_, detail)| anyhow!(detail))?;
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
                    .as_deref()
                    .unwrap_or("route blocked")
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
        // Configuration snapshots are cheap but not free; a cold race can try
        // many candidates. Read the timeout once per new connection, not once
        // per candidate attempt.
        let timeout = self.candidate_timeout();
        // A previously successful route wins. If it fails, it is forgotten and the lazy
        // candidate generator continues with the normal priority order. After a catalog
        // update the cursor tells us to try the new remote IPs first.
        if !cursor.skip_once() {
            if let Some(plan) = self.engine.cached_plan(cursor.domain(), cursor.port(), tls) {
                let started = std::time::Instant::now();
                match self.connect_plan(&plan, force_http1, timeout).await {
                    Ok(io) => {
                        // The cached plan is shared with the plan cache; hand
                        // over the reference instead of copying it again.
                        cursor.note_success(plan, started.elapsed().as_millis() as u64);
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
            // Cleanup is tied to the leader's lifetime: cancelling the request
            // mid-race still publishes a result and removes the entry.
            let guard = DiscoveryGuard {
                map: &self.discovery.inflight,
                key: key.clone(),
                entry: inflight.clone(),
            };
            let outcome = self.race_plans(cursor, force_http1, timeout).await;
            let shared = match &outcome {
                Ok((plan, _)) => Ok(plan.clone()),
                Err(error) => Err(error.clone()),
            };
            *guard.entry.result.lock() = Some(shared);
            drop(guard); // notifies waiters and removes the map entry
            return outcome.map(|(_, io)| io).map_err(anyhow::Error::msg);
        }

        // Register the waiter before checking the result: this closes the
        // window where the leader finishes between our map lookup and our
        // wait (a lost wakeup would hang the request forever).
        let notified = inflight.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if inflight.result.lock().is_none() {
            notified.await;
        }
        let plan = {
            let guard = inflight.result.lock();
            match guard.as_ref() {
                Some(Ok(plan)) => plan.clone(),
                Some(Err(error)) => return Err(anyhow!("{error}")),
                None => return Err(anyhow!("route discovery failed")),
            }
        };
        // The leader already validated this plan; followers just open their own connection.
        let started = std::time::Instant::now();
        match self.connect_plan(&plan, force_http1, timeout).await {
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

    /// Race candidate plans as they become available. Only the single-flight leader
    /// runs this; every other caller for the same domain waits for and reuses the
    /// winning plan.
    ///
    /// Plans are streamed into the race instead of being buffered first: the first
    /// usable candidate starts connecting immediately, while the next plan is being
    /// generated. This matters because plan generation can await an ECH HTTPS-RR
    /// query or a DoH expansion; buffering would delay a perfectly good cached or
    /// catalog route behind those network round trips.
    async fn race_plans(
        &self,
        mut cursor: RouteCursor,
        force_http1: bool,
        timeout: Duration,
    ) -> std::result::Result<(Arc<ConnectPlan>, PooledIo), String> {
        type RaceResult =
            Result<(Arc<ConnectPlan>, PooledIo, u64), (ConnectPlan, FailureReason, String)>;
        enum Event {
            Plan(Option<ConnectPlan>),
            Result(RaceResult),
        }

        let mut pending: FuturesUnordered<Pin<Box<dyn Future<Output = RaceResult> + Send>>> =
            FuturesUnordered::new();
        let mut exhausted = false;
        // Plans generated together form one initial hedge wave. Plans that arrive
        // after a failed handshake start immediately instead of sleeping again.
        let mut first_start: Option<Instant> = None;

        loop {
            let event = if !exhausted && pending.len() < RACE_SIZE {
                tokio::select! {
                    plan = cursor.next_plan() => Event::Plan(plan),
                    Some(result) = pending.next(), if !pending.is_empty() => Event::Result(result),
                }
            } else if !pending.is_empty() {
                Event::Result(pending.next().await.expect("pending is not empty"))
            } else {
                return Err(discovery_failure_detail(&cursor));
            };

            match event {
                Event::Plan(Some(plan)) => {
                    let delay = match first_start {
                        None => {
                            first_start = Some(Instant::now());
                            None
                        }
                        Some(start) => {
                            let deadline = start + RACE_STAGGER;
                            let now = Instant::now();
                            (now < deadline).then(|| deadline - now)
                        }
                    };
                    let this = self.clone();
                    pending.push(Box::pin(async move {
                        if let Some(delay) = delay {
                            tokio::time::sleep(delay).await;
                        }
                        let started = Instant::now();
                        match this.connect_plan(&plan, force_http1, timeout).await {
                            Ok(io) => Ok((
                                Arc::new(plan),
                                io,
                                started.elapsed().as_millis() as u64,
                            )),
                            Err((reason, detail)) => Err((plan, reason, detail)),
                        }
                    }));
                }
                Event::Plan(None) => exhausted = true,
                Event::Result(result) => match result {
                    Ok((plan, io, latency)) => {
                        cursor.note_success(plan.clone(), latency);
                        // Dropping `pending` cancels the losing handshakes mid-flight.
                        return Ok((plan, io));
                    }
                    Err((plan, reason, detail)) => {
                        self.engine.forget_plan(&plan.domain, plan.port, plan.tls);
                        cursor.note_failure(&plan, reason, detail);
                    }
                },
            }
        }
    }

    async fn connect_plan(
        &self,
        plan: &ConnectPlan,
        force_http1: bool,
        timeout: Duration,
    ) -> std::result::Result<PooledIo, (FailureReason, String)> {
        let address = SocketAddr::new(plan.ip, plan.port);
        if !plan.tls {
            let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
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
        let domain = plan.domain.as_str();
        let result = tokio::time::timeout(timeout, async move {
            if self.http1_only || force_http1 {
                connector
                    .connect_http1(plan.ip, plan.port, domain, mode, sni, ech)
                    .await
            } else {
                connector
                    .connect(plan.ip, plan.port, domain, mode, sni, ech)
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
        // DNS and every address batch share one deadline. Without this a host
        // with several batches of black-holed addresses could keep the caller
        // waiting for `SYSTEM_CONNECT_TIMEOUT` per batch.
        let deadline = tokio::time::Instant::now() + SYSTEM_CONNECT_TIMEOUT;
        let dns_timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        let addresses: Vec<std::net::IpAddr> =
            tokio::time::timeout(dns_timeout, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| anyhow!("resolving {host}:{port} timed out"))?
                .with_context(|| format!("resolving {host}:{port}"))?
                .map(|address| address.ip())
                .collect();
        // Staggered race across resolved addresses (Happy-Eyeballs style): a black-holed
        // IPv6 route no longer delays the IPv4 fallback by a full timeout.
        let mut index = 0;
        let mut last_error: Option<String> = None;
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow!(
                    "{}",
                    last_error.unwrap_or_else(|| format!("connecting to {host} timed out"))
                ));
            }
            let batch: Vec<std::net::IpAddr> = addresses
                .iter()
                .skip(index)
                .take(RACE_SIZE)
                .copied()
                .collect();
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
                    // One shared head-start for the preferred address (matching
                    // the group race): a linear ramp would make the 8th address
                    // of a blackholed host wait over a second before trying.
                    if i > 0 {
                        let head_start = deadline
                            .saturating_duration_since(tokio::time::Instant::now())
                            .min(RACE_STAGGER);
                        if !head_start.is_zero() {
                            tokio::time::sleep(head_start).await;
                        }
                    }
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Err("TLS connection timed out".into());
                    }
                    let result = tokio::time::timeout(remaining, async {
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

fn discovery_failure_detail(cursor: &RouteCursor) -> String {
    cursor
        .outcome()
        .and_then(|outcome| outcome.diagnostics.detail.clone())
        .or_else(|| {
            cursor
                .outcome()
                .map(|outcome| format!("{:?}", outcome.diagnostics.state))
        })
        .unwrap_or_else(|| "no route candidate succeeded".into())
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
mod tests;
