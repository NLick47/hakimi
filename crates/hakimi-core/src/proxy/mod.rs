mod pool;
mod upstream;

pub use pool::UpstreamPool;

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::upgrade;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::ca::CertificateAuthority;
use crate::cache::CacheManager;
use crate::catalog::CatalogManager;
use crate::config::ConfigManager;
use crate::decision::{ConnectPlan, DecisionEngine, Route, RouteCursor};
use crate::domain::is_ip_literal;
use crate::ip_tester::TlsContext;
use crate::resolver::Resolver;
use crate::status::StatusStore;
use crate::strategy::{FailureReason, Strategy, TlsMode};
use crate::util::parse_authority;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-direction buffer for upgraded/TCP tunnels. 64 KiB moves large responses
/// with far fewer read/write syscalls than tokio's 8 KiB default while keeping
/// per-connection memory reasonable.
pub(crate) const COPY_BUFFER_SIZE: usize = 64 * 1024;
/// Addresses raced in parallel while a direct tunnel hunts for a reachable path.
const RAW_RACE_SIZE: usize = 8;
const RAW_RACE_STAGGER: Duration = Duration::from_millis(150);

/// Shared proxy state. Runtime installs a callback used by `/hakimi/status` so the CLI and the
/// desktop shell can read the same JSON the UI uses.
pub struct ProxyContext {
    pub engine: Arc<DecisionEngine>,
    pub ca: Arc<CertificateAuthority>,
    pub config: Arc<ConfigManager>,
    pub cache: Arc<CacheManager>,
    pub catalogs: Arc<CatalogManager>,
    pub status: Arc<StatusStore>,
    pub resolver: Arc<Resolver>,
    pub tls: Arc<TlsContext>,
    pub upstream: Arc<UpstreamPool>,
    pub status_json: Arc<dyn Fn() -> serde_json::Value + Send + Sync>,
    proxy_addr: OnceLock<SocketAddr>,
}

impl ProxyContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine: Arc<DecisionEngine>,
        ca: Arc<CertificateAuthority>,
        config: Arc<ConfigManager>,
        cache: Arc<CacheManager>,
        catalogs: Arc<CatalogManager>,
        status: Arc<StatusStore>,
        resolver: Arc<Resolver>,
        tls: Arc<TlsContext>,
        upstream: Arc<UpstreamPool>,
        status_json: Arc<dyn Fn() -> serde_json::Value + Send + Sync>,
    ) -> Arc<Self> {
        Arc::new(Self {
            engine,
            ca,
            config,
            cache,
            catalogs,
            status,
            resolver,
            tls,
            upstream,
            status_json,
            proxy_addr: OnceLock::new(),
        })
    }

    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr.get().copied().unwrap_or_else(|| {
            let config = self.config.snapshot();
            SocketAddr::new(config.proxy.bind, config.proxy.port)
        })
    }

    pub fn pac_script(&self) -> String {
        crate::pac::generate(
            &self.config.snapshot(),
            self.proxy_addr(),
            self.status.paused(),
        )
    }

    pub fn pac_url(&self) -> String {
        format!("http://{}/proxy.pac", self.proxy_addr())
    }
}

pub struct ProxyHandle {
    pub local_addr: SocketAddr,
    pub pac_url: String,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl ProxyHandle {
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), self.task).await;
    }
}

pub async fn start(ctx: Arc<ProxyContext>, bind: SocketAddr) -> Result<ProxyHandle> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding local proxy on {bind}"))?;
    let local_addr = listener.local_addr()?;
    let _ = ctx.proxy_addr.set(local_addr);
    let pac_url = format!("http://{local_addr}/proxy.pac");
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _peer)) => {
                            let _ = stream.set_nodelay(true);
                            let ctx = ctx.clone();
                            tokio::spawn(async move {
                                if let Err(error) = serve_connection(stream, ctx).await {
                                    tracing::debug!(error = %error, "proxy connection closed");
                                }
                            });
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, "proxy accept failed");
                        }
                    }
                }
            }
        }
        tracing::debug!("proxy listener stopped");
    });
    Ok(ProxyHandle {
        local_addr,
        pac_url,
        shutdown: shutdown_tx,
        task,
    })
}

async fn serve_connection(stream: TcpStream, ctx: Arc<ProxyContext>) -> Result<()> {
    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle_request(req, ctx).await) }
    });
    http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .context("serving proxy HTTP/1.1 connection")
}

async fn handle_request(mut req: Request<Incoming>, ctx: Arc<ProxyContext>) -> Response<ProxyBody> {
    if is_local_request(&req, &ctx) {
        match req.uri().path() {
            "/proxy.pac" => {
                return text_response(
                    StatusCode::OK,
                    "application/x-ns-proxy-autoconfig",
                    ctx.pac_script(),
                );
            }
            "/hakimi/status" => {
                let value = (ctx.status_json)();
                return json_response(value);
            }
            "/hakimi/health" => {
                return text_response(StatusCode::OK, "text/plain; charset=utf-8", "ok");
            }
            "/hakimi/pause" if req.method() == Method::POST => {
                ctx.status.set_paused(true);
                return json_response(serde_json::json!({ "paused": true }));
            }
            "/hakimi/resume" if req.method() == Method::POST => {
                ctx.status.set_paused(false);
                return json_response(serde_json::json!({ "paused": false }));
            }
            _ => {}
        }
    }
    if req.method() == Method::CONNECT {
        return handle_connect(&mut req, ctx).await;
    }
    upstream::handle_forward(req, ctx).await
}

fn is_local_request(req: &Request<Incoming>, ctx: &ProxyContext) -> bool {
    // Borrowed where possible: this runs on every single request, so no
    // `to_owned`/`to_string` just to compare a host name.
    let borrowed = req.uri().host();
    let owned;
    let host: &str = match borrowed {
        Some(host) => host,
        None => {
            let Some(parsed) = req
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| parse_authority(value, 80))
            else {
                return false;
            };
            owned = parsed.0;
            &owned
        }
    };
    let host = host.trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip == ctx.proxy_addr().ip())
}

async fn handle_connect(
    req: &mut Request<Incoming>,
    ctx: Arc<ProxyContext>,
) -> Response<ProxyBody> {
    let authority = match req.uri().authority() {
        Some(authority) => authority.to_string(),
        None => match req.uri().path().strip_prefix("//") {
            Some(value) => value.to_string(),
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid CONNECT target",
                    "The CONNECT request did not contain an authority.",
                )
            }
        },
    };
    let Some((host, port)) = parse_authority(&authority, 443) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "Invalid CONNECT target",
            &format!("Could not parse `{authority}`."),
        );
    };

    let config = ctx.config.snapshot();
    let matcher = ctx.config.matcher();
    let group_id = if is_ip_literal(&host) {
        None
    } else {
        matcher.match_host(&host).map(ToOwned::to_owned)
    };
    let Some(group_id) = group_id else {
        return tunnel_to_host(req, &host, port).await;
    };
    let Some(group) = config.group(&group_id) else {
        return tunnel_to_host(req, &host, port).await;
    };
    if !group.enabled || ctx.status.paused() {
        return tunnel_to_host(req, &host, port).await;
    }

    // Fast path: a previously successful direct route turns CONNECT into a raw TCP tunnel,
    // with no probe, no local certificate and no extra TLS handshake.
    let candidate_timeout =
        Duration::from_millis(config.advanced.ip_timeout_ms.clamp(500, 10_000));
    let mut stale_plan = None;
    if let Some(plan) = ctx.engine.cached_plan(&host, port, true) {
        if plan.mode == TlsMode::Direct {
            let started = std::time::Instant::now();
            match connect_tcp_upstream(plan.ip, plan.port, candidate_timeout).await {
                Ok(stream) => {
                    let latency = started.elapsed().as_millis() as u64;
                    ctx.engine.note_tunnel_success(&plan, latency);
                    return tunnel_connect(req, stream);
                }
                Err((reason, detail)) => {
                    tracing::debug!(
                        domain = %host,
                        ip = %plan.ip,
                        reason = %reason,
                        detail = %detail,
                        "cached direct route failed; re-planning"
                    );
                    ctx.engine.forget_plan(&host, port, true);
                    stale_plan = Some(plan);
                }
            }
        }
    }

    // Explicitly direct groups never need MITM. When the CA is not trusted we also keep
    // Auto groups on the raw path: a direct origin still works, while an ECH/fake-SNI
    // origin would only produce a browser certificate error anyway.
    if group.strategy == Strategy::Direct || !ctx.ca.status().installed {
        return tunnel_direct_group(req, &ctx, &host, port, stale_plan.as_ref()).await;
    }

    // ECH / fake SNI / Auto without a direct route: terminate browser TLS locally and let
    // the pooled upstream client pick direct/ECH/SNI on the real request. The real
    // handshake is the probe; there is no separate decision connection.
    let tls_config = match ctx.ca.server_config(&host) {
        Ok(config) => config,
        Err(error) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "Local certificate generation failed",
                &format!("{error:#}"),
            )
        }
    };
    let on_upgrade = upgrade::on(req);
    let host_for_task = host.clone();
    let ctx_for_task = ctx.clone();
    tokio::spawn(async move {
        let result =
            async {
                let upgraded = on_upgrade.await.context("waiting for CONNECT upgrade")?;
                let acceptor = TlsAcceptor::from(tls_config);
                let tls = acceptor
                    .accept(TokioIo::new(upgraded))
                    .await
                    .context("accepting browser TLS")?;
                let alpn = tls
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|protocol| protocol.to_vec());
                let service = service_fn(move |req| {
                    let ctx = ctx_for_task.clone();
                    let host = host_for_task.clone();
                    async move {
                        Ok::<_, Infallible>(upstream::handle_mitm_request(req, ctx, host).await)
                    }
                });
                let io = TokioIo::new(tls);
                if alpn.as_deref() == Some(b"h2") {
                    http2::Builder::new(TokioExecutor::new())
                        .adaptive_window(true)
                        .serve_connection(io, service)
                        .await
                        .context("serving MITM HTTP/2 connection")
                } else {
                    http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                        .context("serving MITM HTTP/1.1 connection")
                }
            }
            .await;
        if let Err(error) = result {
            tracing::debug!(domain = %host, error = %error, "MITM connection ended");
        }
    });
    empty_response(StatusCode::OK)
}

/// Raw TCP tunnel for an explicitly direct group. Candidate order comes from the same
/// lazy route generator used by MITM upstreams; no TLS probe is performed because the
/// browser's own handshake validates the origin certificate.
async fn tunnel_direct_group(
    req: &mut Request<Incoming>,
    ctx: &Arc<ProxyContext>,
    host: &str,
    port: u16,
    failed_plan: Option<&ConnectPlan>,
) -> Response<ProxyBody> {
    let mut cursor = match ctx.engine.route(host, port, true) {
        Route::Bypass(_) => return tunnel_to_host(req, host, port).await,
        Route::Blocked(outcome) => {
            return upstream::diagnostics_error_page(host, &outcome.diagnostics, ctx)
        }
        Route::Group(cursor) => cursor,
    };
    if let Some(plan) = failed_plan {
        cursor.skip_plan(plan);
    }
    let timeout = Duration::from_millis(
        ctx.config
            .snapshot()
            .advanced
            .ip_timeout_ms
            .clamp(500, 10_000),
    );
    match race_tcp_plans(&mut cursor, timeout).await {
        Some((plan, stream, latency)) => {
            let _ = cursor.note_success(&plan, latency);
            tunnel_connect(req, stream)
        }
        None => {
            let diagnostics = cursor.outcome().map(|outcome| outcome.diagnostics.clone());
            match diagnostics {
                Some(diagnostics) => upstream::diagnostics_error_page(host, &diagnostics, ctx),
                None => error_response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream connection failed",
                    &format!("no candidate route succeeded for {host}:{port}"),
                ),
            }
        }
    }
}

/// Connect a raw tunnel with Happy-Eyeballs-style hedging: direct candidates are
/// raced in a rolling window instead of being tried one at a time. Non-direct
/// plans are skipped (the caller's browser performs the real TLS handshake, so a
/// direct candidate is the only usable one here).
async fn race_tcp_plans(
    cursor: &mut RouteCursor,
    timeout: Duration,
) -> Option<(ConnectPlan, TcpStream, u64)> {
    type RaceResult = Result<(ConnectPlan, TcpStream, u64), (ConnectPlan, FailureReason, String)>;
    enum Event {
        Plan(Option<ConnectPlan>),
        Result(RaceResult),
    }

    let mut pending: FuturesUnordered<Pin<Box<dyn Future<Output = RaceResult> + Send>>> =
        FuturesUnordered::new();
    let mut exhausted = false;
    let mut first_start: Option<Instant> = None;

    loop {
        let event = if !exhausted && pending.len() < RAW_RACE_SIZE {
            tokio::select! {
                plan = cursor.next_plan() => Event::Plan(plan),
                Some(result) = pending.next(), if !pending.is_empty() => Event::Result(result),
            }
        } else if !pending.is_empty() {
            Event::Result(pending.next().await.expect("pending is not empty"))
        } else {
            return None;
        };

        match event {
            Event::Plan(Some(plan)) => {
                if plan.mode != TlsMode::Direct {
                    continue;
                }
                let delay = match first_start {
                    None => {
                        first_start = Some(Instant::now());
                        None
                    }
                    Some(start) => {
                        let deadline = start + RAW_RACE_STAGGER;
                        let now = Instant::now();
                        (now < deadline).then(|| deadline - now)
                    }
                };
                pending.push(Box::pin(async move {
                    if let Some(delay) = delay {
                        tokio::time::sleep(delay).await;
                    }
                    let address = SocketAddr::new(plan.ip, plan.port);
                    let started = Instant::now();
                    match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
                        Ok(Ok(stream)) => {
                            let _ = stream.set_nodelay(true);
                            crate::util::apply_tcp_keepalive(&stream);
                            Ok((plan, stream, started.elapsed().as_millis() as u64))
                        }
                        Ok(Err(error)) => Err((
                            plan,
                            FailureReason::TcpRefused,
                            format!("connecting to {address} failed: {error}"),
                        )),
                        Err(_) => Err((
                            plan,
                            FailureReason::TcpTimeout,
                            format!("connecting to {address} timed out"),
                        )),
                    }
                }));
            }
            Event::Plan(None) => exhausted = true,
            Event::Result(result) => match result {
                Ok(success) => return Some(success),
                Err((plan, reason, detail)) => cursor.note_failure(&plan, reason, detail),
            },
        }
    }
}

async fn connect_tcp_upstream(
    ip: std::net::IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, (FailureReason, String)> {
    let address = SocketAddr::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            crate::util::apply_tcp_keepalive(&stream);
            Ok(stream)
        }
        Ok(Err(error)) => Err((
            FailureReason::TcpRefused,
            format!("connecting to {address} failed: {error}"),
        )),
        Err(_) => Err((
            FailureReason::TcpTimeout,
            format!("connecting to {address} timed out"),
        )),
    }
}

/// Race the addresses `host` resolves to with a Happy-Eyeballs-style staggered start.
/// `TcpStream::connect((host, port))` walks the addresses one at a time, so a black-holed
/// IPv6 route can stall a direct tunnel for the whole connect timeout before IPv4 is tried.
/// Returns `(timed_out, detail)` so the caller can distinguish 504 from 502.
pub(super) async fn connect_host_staggered(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, (bool, String)> {
    let started = tokio::time::Instant::now();
    // The system resolver runs in tokio's blocking pool; a stuck lookup must not
    // outlive the caller's connect deadline.
    let resolved = match tokio::time::timeout(timeout, tokio::net::lookup_host((host, port))).await
    {
        Ok(Ok(resolved)) => resolved,
        Ok(Err(error)) => {
            return Err((false, format!("resolving {host}:{port} failed: {error}")));
        }
        Err(_) => {
            return Err((true, format!("resolving {host}:{port} timed out")));
        }
    };
    let mut addresses: Vec<SocketAddr> = Vec::new();
    for address in resolved {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err((false, format!("no address found for {host}")));
    }
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err((true, format!("resolving {host}:{port} timed out")));
    }
    race_tcp_addresses(addresses, remaining).await
}

/// Connect the first address that answers, in rolling staggered batches. Every attempt
/// shares one overall deadline, so a batch of black-holed candidates cannot extend the
/// caller's timeout.
async fn race_tcp_addresses(
    addresses: Vec<SocketAddr>,
    timeout: Duration,
) -> Result<TcpStream, (bool, String)> {
    type ConnectResult = Result<TcpStream, (bool, String)>;

    let deadline = tokio::time::Instant::now() + timeout;
    let mut index = 0usize;
    let mut timed_out = false;
    let mut last_error = String::from("no address available");

    while index < addresses.len() {
        let end = (index + RAW_RACE_SIZE).min(addresses.len());
        let mut pending: FuturesUnordered<Pin<Box<dyn Future<Output = ConnectResult> + Send>>> =
            FuturesUnordered::new();
        for (offset, address) in addresses[index..end].iter().copied().enumerate() {
            pending.push(Box::pin(async move {
                // Give the preferred address a head start; the rest follow together
                // after one stagger instead of a linear ramp.
                if offset > 0 {
                    tokio::time::sleep(RAW_RACE_STAGGER).await;
                }
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err((true, format!("connecting to {address} timed out")));
                }
                match tokio::time::timeout(remaining, TcpStream::connect(address)).await {
                    Ok(Ok(stream)) => {
                        // Same socket tuning as every other upstream path: Nagle adds
                        // latency to interactive tunnels (SSH/WebSocket), and keepalive
                        // lets a dead peer release the tunnel instead of hanging it.
                        let _ = stream.set_nodelay(true);
                        crate::util::apply_tcp_keepalive(&stream);
                        Ok(stream)
                    }
                    Ok(Err(error)) => {
                        Err((false, format!("connecting to {address} failed: {error}")))
                    }
                    Err(_) => Err((true, format!("connecting to {address} timed out"))),
                }
            }));
        }
        while let Some(result) = pending.next().await {
            match result {
                Ok(stream) => return Ok(stream),
                Err((hit_timeout, detail)) => {
                    timed_out |= hit_timeout;
                    last_error = detail;
                }
            }
        }
        index = end;
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    Err((timed_out, last_error))
}

async fn tunnel_to_host(req: &mut Request<Incoming>, host: &str, port: u16) -> Response<ProxyBody> {
    let upstream = match connect_host_staggered(host, port, CONNECT_TIMEOUT).await {
        Ok(stream) => stream,
        Err((timed_out, detail)) => {
            return if timed_out {
                error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Upstream connection timed out",
                    &detail,
                )
            } else {
                error_response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream connection failed",
                    &detail,
                )
            };
        }
    };
    tunnel_connect(req, upstream)
}

fn tunnel_connect(req: &mut Request<Incoming>, mut upstream: TcpStream) -> Response<ProxyBody> {
    let on_upgrade = upgrade::on(req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                if let Err(error) = tokio::io::copy_bidirectional_with_sizes(
                    &mut upgraded,
                    &mut upstream,
                    COPY_BUFFER_SIZE,
                    COPY_BUFFER_SIZE,
                )
                .await
                {
                    tracing::debug!(error = %error, "tunnel closed");
                }
            }
            Err(error) => tracing::debug!(error = %error, "CONNECT upgrade failed"),
        }
    });
    empty_response(StatusCode::OK)
}

fn upstream_failure(
    ctx: &ProxyContext,
    plan: &ConnectPlan,
    reason: crate::strategy::FailureReason,
    detail: String,
) -> Response<ProxyBody> {
    let diagnostics = crate::status::DomainDiagnostics {
        group: Some(plan.group_id.clone()),
        domain: plan.domain.clone(),
        state: crate::status::State::Failed,
        strategy: Some(plan.mode),
        configured_strategy: None,
        ip: Some(plan.ip),
        ip_source: None,
        doh_source: None,
        latency_ms: None,
        last_check: crate::util::now(),
        catalog_version: ctx.config.snapshot().catalog_version,
        cache: crate::strategy::CacheStatus::None,
        error: Some(reason),
        detail: Some(detail),
        attempts: Vec::new(),
        suggestions: vec![reason.suggestion().to_string()],
    };
    ctx.status.record(diagnostics.clone());
    upstream::diagnostics_error_page(&plan.domain, &diagnostics, ctx)
}

pub(crate) fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

pub(crate) fn full_body(data: impl Into<Bytes>) -> ProxyBody {
    Full::new(data.into())
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

fn empty_response(status: StatusCode) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(empty_body())
        .expect("static response")
}

pub(crate) fn text_response(
    status: StatusCode,
    content_type: &str,
    body: impl Into<String>,
) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(full_body(body.into()))
        .expect("text response")
}

pub(crate) fn json_response(value: serde_json::Value) -> Response<ProxyBody> {
    text_response(
        StatusCode::OK,
        "application/json; charset=utf-8",
        value.to_string(),
    )
}

pub(crate) fn error_response(status: StatusCode, title: &str, detail: &str) -> Response<ProxyBody> {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title>{style}</head>\
         <body><main><h1>{title}</h1><p class=\"code\">{status}</p><pre>{detail}</pre></main></body></html>",
        title = escape_html(title),
        status = status.as_u16(),
        detail = escape_html(detail),
        style = upstream::ERROR_STYLE,
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(full_body(body))
        .expect("error response")
}

pub(crate) fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::IpAddr;

    use crate::cache::{CacheManager, LastGoodEntry};
    use crate::catalog::RemoteIpProvider;
    use crate::config::GroupConfig;
    use crate::paths::Paths;
    use crate::resolver::{DohResolution, EchOutcome, IpResolver};
    use crate::strategy::IpSource;
    use crate::util::now;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Loopback throughput microbenchmark for the proxy's bidirectional copy
    /// buffer size. Ignored by default because it moves a large payload.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "loopback throughput benchmark"]
    async fn copy_buffer_size_throughput() {
        async fn run(buffer: usize, total: usize) -> Duration {
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_addr = origin.local_addr().unwrap();
            let origin_task = tokio::spawn(async move {
                let (mut socket, _) = origin.accept().await.unwrap();
                let _ = socket.set_nodelay(true);
                let mut buf = vec![0u8; 64 * 1024];
                let mut read = 0usize;
                while read < total {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    read += n;
                }
                socket.write_all(b"ok").await.unwrap();
            });

            let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let relay_addr = relay.local_addr().unwrap();
            let relay_task = tokio::spawn(async move {
                let (mut client, _) = relay.accept().await.unwrap();
                let _ = client.set_nodelay(true);
                let mut upstream = TcpStream::connect(origin_addr).await.unwrap();
                let _ = upstream.set_nodelay(true);
                let _ = tokio::io::copy_bidirectional_with_sizes(
                    &mut client,
                    &mut upstream,
                    buffer,
                    buffer,
                )
                .await;
            });

            let mut client = TcpStream::connect(relay_addr).await.unwrap();
            let _ = client.set_nodelay(true);
            let chunk = vec![0u8; 64 * 1024];
            let started = Instant::now();
            let mut sent = 0usize;
            while sent < total {
                let n = (total - sent).min(chunk.len());
                client.write_all(&chunk[..n]).await.unwrap();
                sent += n;
            }
            client.shutdown().await.unwrap();
            let mut response = [0u8; 2];
            client.read_exact(&mut response).await.unwrap();
            let elapsed = started.elapsed();
            origin_task.await.unwrap();
            relay_task.await.unwrap();
            elapsed
        }

        const TOTAL: usize = 128 * 1024 * 1024;
        for buffer in [8 * 1024usize, 64 * 1024] {
            let mut samples = Vec::new();
            for _ in 0..3 {
                let elapsed = run(buffer, TOTAL).await;
                let mbps = (TOTAL as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
                println!("buffer={}KiB elapsed={elapsed:?} throughput={mbps:.1} MiB/s", buffer / 1024);
                samples.push(elapsed);
            }
            samples.sort();
            println!("buffer={}KiB median={:?}", buffer / 1024, samples[1]);
        }
    }

    #[test]
    fn html_escape() {
        assert_eq!(escape_html("<a&b>"), "&lt;a&amp;b&gt;");
    }

    struct FakeRemote {
        ips: Vec<IpAddr>,
    }

    impl RemoteIpProvider for FakeRemote {
        fn remote_ips(&self, _domain: &str) -> Option<(String, Vec<IpAddr>)> {
            Some(("upstream.test".into(), self.ips.clone()))
        }

        fn remote_sni(&self, _group_id: &str) -> Option<String> {
            None
        }

        fn has_ip_catalog(&self) -> bool {
            true
        }
    }

    struct FakeResolver;

    #[async_trait::async_trait]
    impl IpResolver for FakeResolver {
        async fn doh_ips(&self, _domain: &str) -> anyhow::Result<DohResolution> {
            Err(anyhow::anyhow!("no doh in this test"))
        }

        async fn doh_ech_config(
            &self,
            _domain: &str,
            _allow_shared: bool,
        ) -> anyhow::Result<EchOutcome> {
            Err(anyhow::anyhow!("no ech in this test"))
        }
    }

    fn engine_for_direct_test(
        dir: &std::path::Path,
        cached_ip: IpAddr,
        remote_ips: Vec<IpAddr>,
    ) -> Arc<DecisionEngine> {
        let paths = Paths::new(dir);
        paths.ensure().unwrap();
        let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
        config
            .upsert_group(GroupConfig {
                id: "test".into(),
                name: "Test".into(),
                domains: vec!["upstream.test".into()],
                strategy: Strategy::Direct,
                enabled: true,
                sni: None,
                experimental: false,
                homepage: None,
                ech_shared: false,
            })
            .unwrap();
        let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
        cache.put_last_good(LastGoodEntry {
            domain: "upstream.test".into(),
            ip: cached_ip,
            strategy: Strategy::Direct,
            source: IpSource::Cache,
            network_id: "test".into(),
            saved_at: now(),
            catalog_version: 0,
        });
        let tls = TlsContext::new().unwrap();
        let status = Arc::new(StatusStore::new());
        DecisionEngine::new(
            config,
            cache,
            Arc::new(FakeRemote { ips: remote_ips }),
            Arc::new(FakeResolver),
            tls,
            status,
        )
    }

    /// The raw CONNECT path must not wait ten seconds for a black-holed first
    /// candidate when another candidate is reachable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_tunnel_races_past_a_blackholed_candidate() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Keep the listener alive for the duration of the test; the winning
        // connect only needs the kernel handshake, not an accept.
        let _listener = listener;

        let dir = tempfile::tempdir().unwrap();
        let engine = engine_for_direct_test(
            dir.path(),
            "192.0.2.1".parse().unwrap(),
            vec!["127.0.0.1".parse().unwrap()],
        );
        let mut cursor = match engine.route("upstream.test", port, true) {
            Route::Group(cursor) => cursor,
            _ => panic!("expected a group route"),
        };

        // Baseline: the previous implementation tried candidates one at a time.
        let serial_started = Instant::now();
        let _ = connect_tcp_upstream(
            "192.0.2.1".parse().unwrap(),
            443,
            Duration::from_secs(1),
        )
        .await;
        let _ = connect_tcp_upstream("127.0.0.1".parse().unwrap(), port, Duration::from_secs(1))
            .await;
        let serial_elapsed = serial_started.elapsed();

        let started = Instant::now();
        let result = race_tcp_plans(&mut cursor, Duration::from_secs(1)).await;
        let elapsed = started.elapsed();
        println!("serial fallback took {serial_elapsed:?}; raw candidate race finished in {elapsed:?}");
        let (plan, _stream, _) = result.expect("the reachable candidate must win");
        assert_eq!(plan.ip.to_string(), "127.0.0.1");
        assert!(
            elapsed < Duration::from_millis(800),
            "serial fallback would wait for the black-holed candidate; elapsed={elapsed:?}"
        );
    }

    /// Before the fix this helper used the 10 s system connect timeout even for
    /// accelerated candidates.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_candidate_uses_the_configured_timeout() {
        let started = Instant::now();
        let result = connect_tcp_upstream(
            "192.0.2.1".parse().unwrap(),
            443,
            Duration::from_millis(300),
        )
        .await;
        let elapsed = started.elapsed();
        assert!(result.is_err(), "the TEST-NET candidate must not connect");
        assert!(
            elapsed < Duration::from_secs(2),
            "candidate timeout was not honored: {elapsed:?}"
        );
    }

    /// Bypass tunnels used to call `TcpStream::connect((host, port))`, which walks
    /// resolved addresses serially: a black-holed first address stalled the whole
    /// tunnel even when another address was reachable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tunnel_address_race_beats_a_blackholed_first_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable = listener.local_addr().unwrap();

        // Serial baseline: the black-holed address consumes the whole first timeout.
        let serial_started = Instant::now();
        let _ =
            tokio::time::timeout(Duration::from_secs(1), TcpStream::connect("192.0.2.1:443")).await;
        let serial_elapsed = serial_started.elapsed();

        let started = Instant::now();
        let stream = race_tcp_addresses(
            vec!["192.0.2.1:443".parse().unwrap(), reachable],
            Duration::from_secs(1),
        )
        .await
        .expect("the reachable address must win");
        let elapsed = started.elapsed();
        drop(stream);
        println!("serial first-address wait {serial_elapsed:?}; staggered race {elapsed:?}");
        assert!(
            elapsed < Duration::from_millis(800),
            "the reachable address was blocked behind the black-holed one: {elapsed:?}"
        );
    }

    /// All addresses black-holed: the shared deadline still bounds the attempt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tunnel_address_race_honors_the_deadline() {
        let started = Instant::now();
        let result = race_tcp_addresses(
            vec![
                "192.0.2.1:443".parse().unwrap(),
                "198.51.100.1:443".parse().unwrap(),
            ],
            Duration::from_millis(400),
        )
        .await;
        let elapsed = started.elapsed();
        assert!(result.is_err(), "TEST-NET addresses must not connect");
        assert!(
            elapsed < Duration::from_secs(2),
            "the overall deadline was not honored: {elapsed:?}"
        );
    }
}
