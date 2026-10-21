use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use futures_util::stream::{FuturesUnordered, StreamExt};
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::upgrade;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::decision::{ConnectPlan, Route, RouteCursor};
use crate::domain::{is_ip_literal, normalize_hostname};
use crate::strategy::{FailureReason, Strategy, TlsMode};
use crate::util::parse_authority;

use super::response::{empty_response, error_response};
use super::{upstream, ProxyBody, ProxyContext, COPY_BUFFER_SIZE};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Addresses raced in parallel while a direct tunnel hunts for a reachable path.
const RAW_RACE_SIZE: usize = 8;
const RAW_RACE_STAGGER: Duration = Duration::from_millis(150);

pub(super) async fn handle_connect(
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
    // Normalize once here: the raw tunnel, plan cache and the MITM Host check
    // must all agree on one spelling (trailing root dot, IDNA, case).
    let host = if is_ip_literal(&host) {
        host
    } else {
        normalize_hostname(&host).unwrap_or(host)
    };

    let config = ctx.config.snapshot();
    let matcher = ctx.config.matcher();
    let group_id = if is_ip_literal(&host) {
        None
    } else {
        matcher.match_normalized(&host).map(ToOwned::to_owned)
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
    let candidate_timeout = Duration::from_millis(config.advanced.ip_timeout_ms.clamp(500, 10_000));
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
    // The browser performs the TLS handshake itself on a raw CONNECT tunnel, so only
    // direct plans can be used. Without this, an auto group whose last-good strategy
    // was ECH generates (and awaits DoH for) an ECH plan before every direct
    // candidate, and a fast-failing first address starves the rest of the list.
    cursor.restrict_to_direct();
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
pub(super) async fn race_tcp_plans(
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

pub(super) async fn connect_tcp_upstream(
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
pub(super) async fn race_tcp_addresses(
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

pub(crate) fn upstream_failure(
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
