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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
use crate::status::DomainDiagnostics;
use crate::strategy::{FailureReason, TlsMode};

use super::gate::IpGate;

/// Request body type understood by the pooled clients. Forwarded requests stream the
/// browser body directly; warm-up requests use an empty `Full` body.
pub(crate) type UpstreamBody = Either<Incoming, Full<Bytes>>;

/// After a response takes this long, the authority is considered unhealthy for a
/// short period. New requests then use a fresh, unpooled connection so a single
/// half-dead HTTP/2 connection cannot delay a whole page load again.
const SLOW_ROUTE_MARK_MS: u64 = 5_000;
const SLOW_ROUTE_TTL: Duration = Duration::from_secs(60);

/// A safe request that has waited this long for response headers is hedged
/// with a second attempt on the recovery pool. Idle/half-dead pooled
/// connections can otherwise hold a page load for the full header timeout
/// (the production log showed 13-39 s JavaScript stalls while every other
/// request for the same host was healthy). Capped at half the configured
/// header timeout so a retry always has time to complete.
const HEDGE_AFTER: Duration = Duration::from_secs(5);

/// Browser response bodies stay streaming; the pool only owns the upstream connection.
pub(crate) type UpstreamResponse = Response<UpstreamResponseBody>;

type ClientResult = std::result::Result<Response<Incoming>, hyper_util::client::legacy::Error>;

/// Result of a hedged send. The timer that fires the hedge also becomes the
/// header deadline, so there is only one timer per replayed request.
enum SendOutcome {
    Response(ClientResult),
    HeaderTimeout,
}

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

/// A request that may be replayed once after a hard failure. Unlike the
/// stall hedge, image hosts are included: their permit is held across the
/// replay, so the concurrency bound still holds, and a dead pooled socket
/// would otherwise surface as a broken image even though a fresh connection
/// succeeds immediately.
fn retry_eligible(request: &Request<UpstreamBody>, upgrade: bool) -> bool {
    !upgrade
        && (request.method() == Method::GET || request.method() == Method::HEAD)
        && request.body().is_end_stream()
        && request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .is_none_or(|value| value.as_bytes() == b"0")
}

/// Rebuild a replayed request: replayable requests carry no body, so the
/// clone ships an empty one.
fn replayed(parts: http::request::Parts) -> Request<UpstreamBody> {
    Request::from_parts(parts, Either::Right(Full::new(Bytes::new())))
}

/// Candidates raced in parallel per batch while a cold connection hunts for a route.
const RACE_SIZE: usize = 8;
/// Delay between race batch member starts, so the first candidate usually wins on a
/// healthy network and the race only costs extra handshakes when it is actually broken.
const RACE_STAGGER: Duration = Duration::from_millis(150);
/// Bounds for the TCP leg of a candidate. It only has to answer "is this
/// address reachable", so it gets a fraction of the candidate budget: a silent
/// address is retired before its whole SNI variant list is dialled.
const MIN_TCP_BUDGET: Duration = Duration::from_millis(500);
const MAX_TCP_BUDGET: Duration = Duration::from_secs(2);
/// A TCP handshake that consumed most of the budget still leaves the TLS leg
/// enough room to fail on its own terms instead of looking like a connect timeout.
const MIN_TLS_BUDGET: Duration = Duration::from_millis(500);

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
    hedged_retries: AtomicU64,
    error_retries: AtomicU64,
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
            "hedgedRetries": self.hedged_retries.load(Ordering::Relaxed),
            "errorRetries": self.error_retries.load(Ordering::Relaxed),
            "warmSuccess": self.warm_success.load(Ordering::Relaxed),
            "warmFailures": self.warm_failures.load(Ordering::Relaxed),
        })
    }
}

/// Bounded, lock-free markers for authorities that recently produced a slow
/// response.
///
/// The previous `RwLock<HashMap>` was read on every request once any host had
/// been marked slow (the fast-path flag never returns to `false`). That turned
/// one stalled response into a shared lock on the hot path for the rest of the
/// process lifetime. A direct-mapped table reduces the read to one short hash
/// and one atomic load. A slot collision only forgets an older marker; the
/// next slow response for that host marks it again.
struct SlowHosts {
    epoch: Instant,
    slots: Box<[AtomicU64]>,
}

const SLOW_HOST_SLOTS: usize = 256;

impl SlowHosts {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            slots: (0..SLOW_HOST_SLOTS)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    /// FNV-1a: short authority names hash in a few nanoseconds, and the table
    /// only needs a well-spread 32-bit value, not collision resistance.
    fn hash(host: &str) -> u32 {
        let mut hash = 0x811c_9dc5u32;
        for &byte in host.as_bytes() {
            hash ^= u32::from(byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        hash
    }

    fn slot(&self, hash: u32) -> &AtomicU64 {
        &self.slots[(hash as usize) & (SLOW_HOST_SLOTS - 1)]
    }

    fn is_slow(&self, host: &str) -> bool {
        let hash = Self::hash(host);
        let packed = self.slot(hash).load(Ordering::Acquire);
        if (packed >> 32) as u32 != hash {
            return false;
        }
        let now = self.epoch.elapsed().as_secs() as u32;
        (packed as u32) > now
    }

    fn mark(&self, host: &str, ttl: Duration) {
        let hash = Self::hash(host);
        let now = self.epoch.elapsed().as_secs() as u32;
        let deadline = now.saturating_add(ttl.as_secs() as u32).max(1);
        self.slot(hash).store(
            (u64::from(hash) << 32) | u64::from(deadline),
            Ordering::Release,
        );
    }
}

/// One generation of pooled clients. Swapped wholesale by
/// [`UpstreamPool::retire_pools`]; hyper's `Client` is a cheap `Arc` clone,
/// so callers copy the handles out and never hold the lock across an await.
struct PoolClients {
    auto: Client<RouteConnector, UpstreamBody>,
    http1: Client<RouteConnector, UpstreamBody>,
    upgrade: Client<RouteConnector, UpstreamBody>,
    recovery: Client<RouteConnector, UpstreamBody>,
}

pub struct UpstreamPool {
    clients: RwLock<PoolClients>,
    /// Per-host replacement pools used after the engine rejects a route or IP.
    ///
    /// A rejected route must not keep serving from the connection that
    /// produced the rejection: hyper would hand its pooled socket back for the
    /// next request, bypassing the connector and therefore the new plan. The
    /// replacement starts empty; its first request opens a freshly planned
    /// connection, then normal pooling resumes for that host. Rejecting again
    /// replaces the entry, retiring every socket in the old pool.
    rejected_clients: Mutex<HashMap<String, RejectedClient>>,
    /// Connectors reused when a replacement pool is created.
    auto_connector: RouteConnector,
    http1_connector: RouteConnector,
    /// Idle timeout and per-host idle limits for replacement pools.
    client_idle: Duration,
    max_idle: usize,
    http1_idle: usize,
    engine: Arc<DecisionEngine>,
    /// Read on every request, written only after a slow/failed response.
    slow_hosts: SlowHosts,
    /// Fast path for the common case where no host has ever been marked slow.
    slow_hosts_seen: AtomicBool,
    /// Authorities whose selected route was rejected by the upstream. Kept
    /// separate from `slow_hosts` because the response was fast and healthy at
    /// the transport level; only the route/IP behind it is unusable.
    rejected_hosts: SlowHosts,
    rejected_hosts_seen: AtomicBool,
    /// How long a host stays on the recovery pool. Kept at least as long as
    /// the client idle timeout: otherwise the normal pool could hand the same
    /// half-dead connection back after the marker expired but before hyper
    /// had closed it.
    slow_route_ttl: Duration,
    /// Lifetime of a rejection marker. It must outlive the idle timeout of the
    /// normal pool so the rejected socket is evicted before the host returns.
    rejection_ttl: Duration,
    http1_hosts: Arc<DomainMatcher>,
    http1_limit: usize,
    /// Deadline for the upstream response headers, never for the streamed body
    header_timeout: Duration,
    /// Read for every image-host request; written only when a new host appears.
    http1_slots: RwLock<HashMap<String, Arc<Semaphore>>>,
    stats: Arc<UpstreamStats>,
}

/// Replacement pools for one authority after its route was rejected.
struct RejectedClient {
    auto: Client<RouteConnector, UpstreamBody>,
    http1: Client<RouteConnector, UpstreamBody>,
    expires: Instant,
}

/// Keep the rejection-pool map bounded. Each entry holds idle sockets, so a
/// large burst of rejected hosts must not retain them indefinitely.
const REJECTED_CLIENT_CAP: usize = 32;

/// One route discovery per domain at a time: concurrent cold connections for the same host
/// share a single probe instead of each racing its own candidate batch.
struct Discovery {
    inflight: Mutex<HashMap<String, Arc<Inflight>>>,
}

/// BDP-sized h2 windows: 8 MiB carries ~100 Mbps over a 300 ms RTT. The Android
/// profile trades peak throughput for a smaller memory ceiling
#[cfg(target_os = "android")]
const H2_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
#[cfg(target_os = "android")]
const H2_CONNECTION_WINDOW: u32 = 16 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const H2_STREAM_WINDOW: u32 = 8 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const H2_CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;

fn build_client(
    idle: Duration,
    connector: RouteConnector,
    max_idle: usize,
) -> Client<RouteConnector, UpstreamBody> {
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(idle)
        .pool_max_idle_per_host(max_idle)
        .timer(TokioTimer::new())
        // Fixed windows instead of the adaptive policy: the setters below
        // disable it. Do not add `http2_adaptive_window(true)` unless these
        // lines are removed as well; otherwise the call order silently
        // decides which policy wins.
        .http2_initial_stream_window_size(H2_STREAM_WINDOW)
        .http2_initial_connection_window_size(H2_CONNECTION_WINDOW)
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
        let http1_limit = config.advanced.http1_max_concurrent.max(1);
        let header_timeout =
            Duration::from_secs(config.advanced.upstream_header_timeout_secs.max(1));
        let client_idle = Duration::from_secs(config.advanced.upstream_idle_secs.max(10));

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
        let http1_connector = RouteConnector {
            engine: engine.clone(),
            tls,
            http1_only: true,
            http1_hosts: http1_hosts.clone(),
            discovery: discovery.clone(),
            stats: stats.clone(),
        };
        Arc::new(Self {
            clients: RwLock::new(PoolClients {
                auto: build_client(client_idle, auto_connector.clone(), max_idle),
                // Image hosts are HTTP/1.1-only because a burst should spread over
                // independent TCP connections. Their idle budget therefore has to
                // track the burst concurrency, not the global small-idle profile:
                // keeping only `max_idle` connections would make the next image
                // burst reopen most of them (and pay the TLS handshakes again).
                // This pool is only selected for `http1_hosts`, so the extra idle
                // sockets do not apply to ordinary h2 origins.
                http1: build_client(
                    client_idle,
                    http1_connector.clone(),
                    max_idle.max(http1_limit),
                ),
                // The upgrade pool shares the HTTP/1.1-only connector: a
                // WebSocket handshake must never be routed over HTTP/2.
                upgrade: build_client(client_idle, http1_connector.clone(), max_idle),
                // The recovery pool starts empty, so the first request after a
                // slow response opens a fresh connection instead of reusing the
                // stalled one.  It keeps that connection afterwards: without idle
                // reuse every request in the recovery window would pay for a
                // handshake, which is exactly the cost the recovery avoids.
                recovery: build_client(client_idle, auto_connector.clone(), max_idle),
            }),
            rejected_clients: Mutex::new(HashMap::new()),
            auto_connector,
            http1_connector,
            client_idle,
            max_idle,
            http1_idle: max_idle.max(http1_limit),
            engine,
            slow_hosts: SlowHosts::new(),
            slow_hosts_seen: AtomicBool::new(false),
            rejected_hosts: SlowHosts::new(),
            rejected_hosts_seen: AtomicBool::new(false),
            // Keep the marker a little past the client's idle eviction, so a
            // request that arrives exactly at the idle boundary cannot pick
            // the bad connection out of the normal pool again.
            slow_route_ttl: client_idle.max(SLOW_ROUTE_TTL) + Duration::from_secs(5),
            rejection_ttl: client_idle + Duration::from_secs(5),
            http1_hosts,
            http1_limit,
            header_timeout,
            http1_slots: RwLock::new(HashMap::new()),
            stats,
        })
    }

    /// Send an upstream request through the pool. `upgrade` selects the HTTP/1.1-only
    /// client so WebSocket handshakes cannot be routed over HTTP/2.
    #[cfg(test)]
    pub(crate) async fn send(
        &self,
        request: Request<UpstreamBody>,
        upgrade: bool,
    ) -> std::result::Result<UpstreamResponse, String> {
        // Tests and non-hot callers can borrow the request's URI. The hot path
        // passes the URI it already keeps for the response body, saving this
        // clone per forwarded request.
        let uri = request.uri().clone();
        self.send_with_uri(request, upgrade, &uri).await
    }

    pub(crate) async fn send_with_uri(
        &self,
        mut request: Request<UpstreamBody>,
        upgrade: bool,
        uri: &Uri,
    ) -> std::result::Result<UpstreamResponse, String> {
        let request_id = self.stats.requests.fetch_add(1, Ordering::Relaxed) + 1;
        let method = request.method().clone();
        let request_version = request.version();
        let scheme = uri.scheme_str().unwrap_or("");
        let host = uri.host();
        // Forwarded URIs are built from an already-normalized host, so the
        // per-request image-host check does not need to normalize again.
        let is_http1_host = !self.http1_hosts.is_empty()
            && host.is_some_and(|host| self.http1_hosts.match_normalized(host).is_some());
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
        let tls = scheme != "http";
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let rejected = host.is_some_and(|host| self.is_rejected(host));
        let recovery = !upgrade && !rejected && host.is_some_and(|host| self.is_slow(host));
        let rejected_client = if rejected {
            Some(self.rejected_client(
                host.expect("a rejected route requires a host"),
                upgrade || is_http1_host,
            ))
        } else {
            None
        };
        // The guard must be out of scope at the await below: a generator
        // captures every in-scope value with a destructor, which would make
        // this future `!Send` even though the guard is dropped here.
        let (client, recovery_client) = {
            let clients = self.clients.read();
            let client = if let Some(client) = rejected_client.as_ref() {
                client.clone()
            } else if upgrade {
                clients.upgrade.clone()
            } else if recovery {
                clients.recovery.clone()
            } else if is_http1_host {
                clients.http1.clone()
            } else {
                clients.auto.clone()
            };
            (client, clients.recovery.clone())
        };
        let debug_host = host;
        let debug_path = uri.path();
        let retry_parts = if retry_eligible(&request, upgrade) {
            // GET/HEAD without a body can be replayed. The clone is only
            // needed to keep a second, independent request available; a POST
            // or a streaming body must never be sent twice.
            let (parts, body) = request.into_parts();
            let retry = parts.clone();
            request = Request::from_parts(parts, body);
            Some(retry)
        } else {
            None
        };
        // The stall hedge stays disabled for image hosts: their permit makes
        // a speculative second connection undesirable, and their requests are
        // short. The hard-failure replay below covers them instead.
        let hedge_enabled = retry_parts.is_some() && !is_http1_host;
        // Only hedge when there is time left for the retry to be useful.
        let hedge_after = HEDGE_AFTER.min(self.header_timeout / 2);
        let started = std::time::Instant::now();
        // Only the header wait is bounded: the body keeps streaming afterwards.
        // Hedged requests use one timer for both the hedge delay and the header
        // deadline instead of nesting a second `Timeout` future.
        let outcome = match retry_parts {
            Some(parts) => {
                self.request_with_retry(
                    &client,
                    &recovery_client,
                    request,
                    Some(parts),
                    hedge_after,
                    self.header_timeout,
                    debug_host,
                    hedge_enabled,
                )
                .await
            }
            None => {
                match tokio::time::timeout(self.header_timeout, client.request(request)).await {
                    Ok(result) => SendOutcome::Response(result),
                    Err(_) => SendOutcome::HeaderTimeout,
                }
            }
        };
        match outcome {
            SendOutcome::Response(Ok(response)) => {
                // A completed TLS handshake does not prove the route is usable:
                // a fake-SNI request can reach nginx and get a 403. Feed the
                // status back so the next connection drops that route.
                let status = response.status();
                let status_code = status.as_u16();
                let version = response.version();
                let error_status = status.is_client_error() || status.is_server_error();
                if matches!(status_code, 400 | 403 | 421 | 429 | 451) {
                    if let Some(host) = debug_host {
                        if self.engine.note_upstream_response(host, port, tls, status) {
                            // The route/IP behind this response is unusable.
                            // Retire the pooled connection as well: otherwise
                            // hyper would hand it to the next request, which
                            // would then bypass the connector and the freshly
                            // re-planned route.
                            self.mark_rejected(host);
                        }
                    }
                }
                if version == http::Version::HTTP_2 {
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
                        version = ?version,
                        host = ?debug_host,
                        path = %debug_path,
                        status = status_code,
                        elapsed_ms,
                        "slow upstream response"
                    );
                } else {
                    tracing::debug!(
                        request_id,
                        method = %method,
                        scheme,
                        version = ?version,
                        host = ?debug_host,
                        path = %debug_path,
                        status = status_code,
                        elapsed_ms,
                        "upstream response"
                    );
                }
                if error_status && is_http1_host {
                    tracing::warn!(
                        host = debug_host.unwrap_or(""),
                        path = %debug_path,
                        status = status_code,
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
            SendOutcome::Response(Err(error)) => {
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
                Err(error.to_string())
            }
            SendOutcome::HeaderTimeout => {
                // The connection accepted the request but never answered: a
                // half-dead hop. Drop it and let the next connection re-race
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
                    timeout_secs = self.header_timeout.as_secs(),
                    "upstream response header timeout"
                );
                Err("upstream response header timeout".into())
            }
        }
    }

    /// Send `request` with one replay on the `recovery` pool. The first
    /// response wins; a failed retry leaves the original attempt in place.
    ///
    /// Two failure modes are covered:
    /// - a pooled connection that is still open but no longer answers. When
    ///   hedging is enabled the replay fires after `hedge_after`, so a 60 s
    ///   header deadline does not hold the page for the whole budget while a
    ///   fresh connection succeeds immediately.
    /// - a pooled connection that fails outright (reset, closed before the
    ///   response). A safe request replays immediately instead of handing
    ///   the error to the browser.
    ///
    /// A request is replayed at most once: `retry_parts` is consumed by
    /// whichever path fires first.
    #[allow(clippy::too_many_arguments)]
    async fn request_with_retry(
        &self,
        client: &Client<RouteConnector, UpstreamBody>,
        recovery: &Client<RouteConnector, UpstreamBody>,
        request: Request<UpstreamBody>,
        retry_parts: Option<http::request::Parts>,
        hedge_after: Duration,
        header_timeout: Duration,
        host: Option<&str>,
        hedge_enabled: bool,
    ) -> SendOutcome {
        enum Event {
            First(ClientResult),
            Retry(ClientResult),
            Hedge,
            HeaderTimeout,
        }

        let first = client.request(request);
        tokio::pin!(first);
        let mut retry: Option<Pin<Box<dyn Future<Output = ClientResult> + Send + '_>>> = None;
        let mut retry_parts = retry_parts;
        // `first` must not be polled again once it resolved, so the loop
        // tracks whether it is still a live branch of the select.
        let mut first_done = false;
        let mut first_error: Option<hyper_util::client::legacy::Error> = None;
        let mut hedged = false;
        let deadline = tokio::time::Instant::now() + header_timeout;
        // With the hedge disabled the timer is a plain header deadline.
        let timer = tokio::time::sleep(if hedge_enabled {
            hedge_after.min(header_timeout)
        } else {
            header_timeout
        });
        tokio::pin!(timer);

        loop {
            let event = if let Some(retry_future) = retry.as_mut() {
                if first_done {
                    tokio::select! {
                        result = retry_future.as_mut() => Event::Retry(result),
                        _ = &mut timer => Event::HeaderTimeout,
                    }
                } else {
                    tokio::select! {
                        result = &mut first => Event::First(result),
                        result = retry_future.as_mut() => Event::Retry(result),
                        _ = &mut timer => Event::HeaderTimeout,
                    }
                }
            } else {
                tokio::select! {
                    result = &mut first => Event::First(result),
                    _ = &mut timer => if hedge_enabled && !hedged {
                        Event::Hedge
                    } else {
                        Event::HeaderTimeout
                    },
                }
            };

            match event {
                Event::First(Ok(response)) => return SendOutcome::Response(Ok(response)),
                Event::First(Err(error)) => {
                    first_done = true;
                    if retry.is_some() {
                        // A replay is already in flight; its answer is the one
                        // the browser sees. Keep the original error for the
                        // case where the replay fails as well.
                        first_error = Some(error);
                        continue;
                    }
                    if let Some(parts) = retry_parts.take() {
                        self.stats.error_retries.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(
                            host = host.unwrap_or(""),
                            error = %format!("{error:#}"),
                            "upstream request failed; replaying once on a fresh connection"
                        );
                        // The original attempt is over, so the replay runs on
                        // its own: a plain header deadline, no hedge window.
                        let replay = recovery.request(replayed(parts));
                        return match tokio::time::timeout(header_timeout, replay).await {
                            Ok(result) => SendOutcome::Response(result),
                            Err(_) => SendOutcome::HeaderTimeout,
                        };
                    }
                    return SendOutcome::Response(Err(error));
                }
                Event::Retry(Ok(response)) => return SendOutcome::Response(Ok(response)),
                Event::Retry(Err(error)) => {
                    retry = None;
                    if first_done {
                        // The original already failed; this was the last chance.
                        return SendOutcome::Response(Err(first_error.take().unwrap_or(error)));
                    }
                    // The fresh connection failed as well. Keep waiting for
                    // the original instead of turning a possible late success
                    // into an error.
                    tracing::debug!(
                        host = host.unwrap_or(""),
                        error = %format!("{error:#}"),
                        "hedged retry failed; waiting for the original request"
                    );
                }
                Event::Hedge => {
                    hedged = true;
                    self.stats.hedged_retries.fetch_add(1, Ordering::Relaxed);
                    let Some(parts) = retry_parts.take() else {
                        // The hedge can only fire while a replay is still
                        // available; the error replay would have taken it.
                        return SendOutcome::HeaderTimeout;
                    };
                    if let Some(host) = host {
                        // Keep later requests off the pool that produced the
                        // stall. The retry itself runs on the recovery pool.
                        self.mark_slow(host);
                        tracing::warn!(
                            host,
                            hedge_after_ms = hedge_after.as_millis() as u64,
                            "upstream response is stalled; hedging on a fresh connection"
                        );
                    }
                    retry = Some(Box::pin(recovery.request(replayed(parts))));
                    // The hedge window is over; the same timer now guards the
                    // header wait for both attempts.
                    timer.as_mut().reset(deadline);
                }
                Event::HeaderTimeout => return SendOutcome::HeaderTimeout,
            }
        }
    }

    fn is_slow(&self, host: &str) -> bool {
        // Nearly all requests run before any slow host has ever been observed.
        if !self.slow_hosts_seen.load(Ordering::Acquire) {
            return false;
        }
        self.slow_hosts.is_slow(host)
    }

    fn mark_slow(&self, host: &str) {
        self.slow_hosts.mark(host, self.slow_route_ttl);
        // Publish the fast-path flag after the marker: a reader that sees
        // `true` with acquire ordering observes this store's marker.
        self.slow_hosts_seen.store(true, Ordering::Release);
    }

    fn is_rejected(&self, host: &str) -> bool {
        if !self.rejected_hosts_seen.load(Ordering::Acquire) {
            return false;
        }
        self.rejected_hosts.is_slow(host)
    }

    /// Replacement pool for a host whose route was rejected.
    ///
    /// The pool is created on first use so the rejected route's socket is
    /// never available to it, then kept for the rejection window so the new,
    /// healthy route is not paid for with a handshake on every request.
    fn rejected_client(&self, host: &str, http1: bool) -> Client<RouteConnector, UpstreamBody> {
        let now = Instant::now();
        let mut clients = self.rejected_clients.lock();
        if clients
            .get(host)
            .is_some_and(|client| client.expires <= now)
        {
            clients.remove(host);
        }
        if clients.len() >= REJECTED_CLIENT_CAP {
            clients.retain(|_, client| client.expires > now);
            // A churn of rejected hosts must stay bounded. Dropping the entry
            // closest to expiry costs at most one extra handshake later.
            while clients.len() >= REJECTED_CLIENT_CAP {
                let Some(host) = clients
                    .iter()
                    .min_by_key(|(_, client)| client.expires)
                    .map(|(host, _)| host.clone())
                else {
                    break;
                };
                clients.remove(&host);
            }
        }
        let entry = clients
            .entry(host.to_owned())
            .or_insert_with(|| RejectedClient {
                auto: build_client(self.client_idle, self.auto_connector.clone(), self.max_idle),
                http1: build_client(
                    self.client_idle,
                    self.http1_connector.clone(),
                    self.http1_idle,
                ),
                expires: now + self.rejection_ttl,
            });
        if http1 {
            entry.http1.clone()
        } else {
            entry.auto.clone()
        }
    }

    fn mark_rejected(&self, host: &str) {
        // The marker must outlive the idle timeout of the pool that still
        // holds the rejected connection, so that socket is evicted before the
        // host returns to the normal pool.
        self.rejected_hosts.mark(host, self.rejection_ttl);
        self.rejected_hosts_seen.store(true, Ordering::Release);
        // Retire the previous replacement pool: it may already hold a
        // connection to the route that just got rejected.
        self.rejected_clients.lock().remove(host);
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
        let http1 = self.http1_hosts.match_host(host).is_some();
        let rejected_client = self
            .is_rejected(host)
            .then(|| self.rejected_client(host, http1));
        // Same scope rule as `send_with_uri`: the guard cannot outlive the
        // await below.
        let client = {
            let clients = self.clients.read();
            if let Some(client) = rejected_client.as_ref() {
                client.clone()
            } else if http1 {
                clients.http1.clone()
            } else {
                clients.auto.clone()
            }
        };
        match tokio::time::timeout(WARM_TIMEOUT, client.request(request)).await {
            Ok(Ok(response)) => {
                let status = response.status();
                if matches!(status.as_u16(), 400 | 403 | 429 | 451)
                    && self.engine.note_blocked_candidate(host, port, true, status)
                {
                    // Only opted-in groups (GitHub) treat this as a route
                    // failure; other sites keep the previous warm-up behavior.
                    self.stats.warm_failures.fetch_add(1, Ordering::Relaxed);
                    self.mark_rejected(host);
                    tracing::warn!(
                        host,
                        status = status.as_u16(),
                        version = ?response.version(),
                        "upstream warm-up returned a block page"
                    );
                    drop(response);
                    return false;
                }
                self.stats.warm_success.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    host,
                    status = status.as_u16(),
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

    /// Swap in a fresh client generation, dropping every pooled upstream socket.
    ///
    /// A pause/resume cycle (or a takeover interruption) leaves previously
    /// pooled connections behind a network path that may no longer exist; the
    /// first requests after the resume would otherwise fail on those dead
    /// sockets. In-flight requests hold their own client references and finish
    /// on the old sockets; idle ones close when the dropped generation does.
    pub(crate) fn retire_pools(&self) {
        {
            let mut clients = self.clients.write();
            clients.auto =
                build_client(self.client_idle, self.auto_connector.clone(), self.max_idle);
            clients.http1 = build_client(
                self.client_idle,
                self.http1_connector.clone(),
                self.http1_idle,
            );
            clients.upgrade = build_client(
                self.client_idle,
                self.http1_connector.clone(),
                self.max_idle,
            );
            clients.recovery =
                build_client(self.client_idle, self.auto_connector.clone(), self.max_idle);
        }
        // Replacement pools for rejected hosts carry sockets from the same
        // pre-interruption era; the markers themselves are harmless and can
        // simply age out.
        self.rejected_clients.lock().clear();
        tracing::info!("upstream connection pools retired");
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
        let force_http1 = self.http1_only
            || (!self.http1_hosts.is_empty() && self.http1_hosts.match_normalized(&host).is_some());
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
        // A previously successful route starts immediately, but it no longer
        // blocks the normal candidate race until its full timeout. A stale
        // cached route can otherwise add seconds to a page load before the
        // healthy candidates are even tried; instead the cached route gets the
        // same hedge window as any other first candidate.
        let cached_plan = if cursor.skip_once() {
            None
        } else {
            self.engine.cached_plan(cursor.domain(), cursor.port(), tls)
        };
        if let Some(plan) = cached_plan.as_ref() {
            // The cached route will be inserted as the first race future, so
            // do not generate the same plan again from the cursor.
            cursor.skip_plan(plan);
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
            let outcome = self
                .race_plans(cursor, cached_plan, force_http1, timeout)
                .await;
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
        cached_plan: Option<Arc<ConnectPlan>>,
        force_http1: bool,
        timeout: Duration,
    ) -> std::result::Result<(Arc<ConnectPlan>, PooledIo), String> {
        enum Event {
            Plan(Option<ConnectPlan>),
            Result(PlanAttempt),
        }

        let mut gate = IpGate::new();
        let mut pending: FuturesUnordered<PlanFuture> = FuturesUnordered::new();
        let mut exhausted = false;
        // Plans generated together form one initial hedge wave. Plans that arrive
        // after a failed handshake start immediately instead of sleeping again.
        let mut first_start: Option<Instant> = None;
        // A watch channel lets already-sleeping hedge futures abandon the rest
        // of their stagger as soon as any candidate fails. Without it, a
        // refused first candidate still costs the full 150 ms before the
        // healthy fallback is allowed to start.
        let (failure_tx, failure_rx) = tokio::sync::watch::channel(false);

        // The cached route is the first member of the race. It starts
        // immediately; generated candidates join after the normal stagger (or
        // as soon as the cached route fails), so a stale cached route can no
        // longer hold the request for its full timeout before fallback.
        if let Some(plan) = cached_plan {
            if let Some(plan) = gate.admit((*plan).clone()) {
                launch(
                    self,
                    &mut pending,
                    plan,
                    None,
                    failure_rx.clone(),
                    force_http1,
                    timeout,
                );
                first_start = Some(Instant::now());
            }
        }

        loop {
            // Release the variants of every address whose probe has answered.
            // They start without a stagger: the address is already proven, and
            // the point of the batch is to compare SNI candidates.
            let window = RACE_SIZE.saturating_sub(pending.len());
            for plan in gate.drain_ready(window) {
                launch(
                    self,
                    &mut pending,
                    plan,
                    None,
                    failure_rx.clone(),
                    force_http1,
                    timeout,
                );
            }
            if exhausted && pending.is_empty() && gate.is_idle() {
                return Err(discovery_failure_detail(&mut cursor, gate.discarded()));
            }

            let event = if !exhausted && pending.len() < RACE_SIZE {
                tokio::select! {
                    plan = cursor.next_plan() => Event::Plan(plan),
                    Some(result) = pending.next() => Event::Result(result),
                }
            } else if !pending.is_empty() {
                Event::Result(pending.next().await.expect("pending is not empty"))
            } else {
                // Without a dial in flight nothing can release the queue; this
                // only happens when the cursor produced plans and stopped
                // before any of them started.
                return Err(discovery_failure_detail(&mut cursor, gate.discarded()));
            };

            match event {
                Event::Plan(Some(plan)) => {
                    // The gate decides whether this plan may dial now, has to
                    // wait for its address' probe, or is already moot.
                    if let Some(plan) = gate.admit(plan) {
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
                        launch(
                            self,
                            &mut pending,
                            plan,
                            delay,
                            failure_rx.clone(),
                            force_http1,
                            timeout,
                        );
                    }
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
                        // An address-level failure retires every variant that
                        // has not started yet, instead of dialling each one for
                        // a full timeout against a silent address.
                        gate.record_failure(plan.ip, reason);
                        // A fast failure means the hedge window has done its
                        // job: start the next candidate immediately instead of
                        // making the user wait out the rest of the stagger.
                        // The next plan opens a fresh 150 ms window for the
                        // candidates after it.
                        first_start = None;
                        let _ = failure_tx.send(true);
                    }
                },
            }
        }
    }

    /// Open one candidate plan.
    ///
    /// The two legs are timed and classified separately. That split is what
    /// lets the gate tell "this address is unreachable" from "this SNI was
    /// rejected": only a TCP-level failure retires the address, a stalled or
    /// reset handshake still proves the address answered.
    async fn connect_plan(
        &self,
        plan: &ConnectPlan,
        force_http1: bool,
        timeout: Duration,
    ) -> std::result::Result<PooledIo, (FailureReason, String)> {
        let address = SocketAddr::new(plan.ip, plan.port);
        let started = Instant::now();

        let tcp = TlsContext::open_tcp(plan.ip, plan.port, tcp_phase_budget(timeout))
            .await
            .map_err(|error| {
                (
                    error.reason(),
                    format!("connecting to {address}: {error}"),
                )
            })?;
        if !plan.tls {
            return Ok(PooledIo {
                io: Transport::Tcp(tcp),
                h2: false,
            });
        }

        let remaining = timeout
            .saturating_sub(started.elapsed())
            .max(MIN_TLS_BUDGET.min(timeout));
        let result = tokio::time::timeout(
            remaining,
            self.tls.handshake(
                tcp,
                plan.domain.as_str(),
                plan.mode,
                plan.sni.as_deref(),
                plan.ech_config.as_deref(),
                self.http1_only || force_http1,
            ),
        )
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
                FailureReason::TlsTimeout,
                format!("TLS handshake with {address} timed out"),
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
        let resolved =
            tokio::time::timeout(dns_timeout, super::connect::lookup_host_cached(host, port))
                .await
                .map_err(|_| anyhow!("resolving {host}:{port} timed out"))?
                .with_context(|| format!("resolving {host}:{port}"))?;
        let addresses: Vec<std::net::IpAddr> = super::connect::interleave_by_family(
            resolved.iter().map(|address| address.ip()).collect(),
            std::net::IpAddr::is_ipv4,
        );
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
            let (failure_tx, failure_rx) = tokio::sync::watch::channel(false);
            for (i, address) in batch.iter().enumerate() {
                let this = self.clone();
                let address = *address;
                let host = host.to_string();
                let force = force_http1;
                let mut failure_rx = failure_rx.clone();
                pending.push(Box::pin(async move {
                    // One shared head-start for the preferred address (matching
                    // the group race): a linear ramp would make the 8th address
                    // of a blackholed host wait over a second before trying.
                    // A fast failure releases the head-start immediately.
                    if i > 0 && !*failure_rx.borrow() {
                        let head_start = deadline
                            .saturating_duration_since(tokio::time::Instant::now())
                            .min(RACE_STAGGER);
                        if !head_start.is_zero() {
                            tokio::select! {
                                _ = tokio::time::sleep(head_start) => {}
                                _ = failure_rx.changed() => {}
                            }
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
                    Err(detail) => {
                        last_error = Some(detail);
                        let _ = failure_tx.send(true);
                    }
                }
            }
            // The whole batch failed; try the next one.
        }
    }
}

fn discovery_failure_detail(cursor: &mut RouteCursor, discarded: usize) -> String {
    let base = match cursor.outcome() {
        Some(outcome) => outcome
            .diagnostics
            .detail
            .clone()
            .unwrap_or_else(|| describe_discovery_failure(&outcome.diagnostics)),
        None => "route discovery failed before any candidate was available".into(),
    };
    if discarded == 0 {
        return base;
    }
    format!(
        "{base}; {discarded} SNI/ECH variant(s) skipped after their address failed at the TCP level"
    )
}

/// One plan attempt inside a cold-route race.
type PlanAttempt = Result<(Arc<ConnectPlan>, PooledIo, u64), (ConnectPlan, FailureReason, String)>;
type PlanFuture = Pin<Box<dyn Future<Output = PlanAttempt> + Send>>;

/// Start one plan as a race member.
#[allow(clippy::too_many_arguments)]
fn launch(
    connector: &RouteConnector,
    pending: &mut FuturesUnordered<PlanFuture>,
    plan: ConnectPlan,
    delay: Option<Duration>,
    mut failure_rx: tokio::sync::watch::Receiver<bool>,
    force_http1: bool,
    timeout: Duration,
) {
    let this = connector.clone();
    pending.push(Box::pin(async move {
        if let Some(delay) = delay {
            if !*failure_rx.borrow() {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = failure_rx.changed() => {}
                }
            }
        }
        let started = Instant::now();
        match this.connect_plan(&plan, force_http1, timeout).await {
            Ok(io) => Ok((Arc::new(plan), io, started.elapsed().as_millis() as u64)),
            Err((reason, detail)) => Err((plan, reason, detail)),
        }
    }));
}

/// The TCP leg only has to prove the address is reachable, so it is capped well
/// below the candidate budget: a silent address is retired after half of it.
///
/// Never above `timeout` itself: `ipTimeoutMs` is the total budget for one
/// candidate, and a floor larger than that would make a fast-fail configuration
/// slower than configured.
fn tcp_phase_budget(timeout: Duration) -> Duration {
    (timeout / 2)
        .clamp(MIN_TCP_BUDGET, MAX_TCP_BUDGET)
        .min(timeout)
}

/// Describe a failure outcome that carries no detail.
///
/// The state must never be used as the error text: during warm-up it is
/// `Checking`, which says nothing about the failure and leaks an internal UI
/// marker into the 502 page. The reason and the attempt trace are the only
/// parts an operator can act on.
fn describe_discovery_failure(diagnostics: &DomainDiagnostics) -> String {
    let reason = diagnostics
        .error
        .map(FailureReason::as_str)
        .unwrap_or("unknown");
    if diagnostics.attempts.is_empty() {
        return format!("route discovery failed: {reason} (no attempt detail was recorded)");
    }
    let attempts = diagnostics
        .attempts
        .iter()
        .map(|attempt| {
            let error = attempt.error.map(FailureReason::as_str).unwrap_or("-");
            format!(
                "{}@{}#{}:{}",
                attempt.strategy.as_str(),
                attempt.ip,
                error,
                attempt.source.as_str()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("route discovery failed: {reason}; attempts: {attempts}")
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
