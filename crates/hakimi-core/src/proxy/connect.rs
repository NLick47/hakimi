use std::borrow::Cow;
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
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::decision::{ConnectPlan, Route, RouteCursor};
use crate::domain::{is_ip_literal, normalize_hostname_cow};
use crate::strategy::{FailureReason, TlsMode};
use crate::util::parse_authority;

use super::response::{empty_response, error_response};
use super::{upstream, ProxyBody, ProxyContext, COPY_BUFFER_SIZE};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Addresses raced in parallel while a direct tunnel hunts for a reachable path.
const RAW_RACE_SIZE: usize = 8;
const RAW_RACE_STAGGER: Duration = Duration::from_millis(150);

/// Short-TTL cache for system resolver answers. Bypass hosts otherwise pay a
/// blocking `getaddrinfo` on every new connection. Cleared on network changes
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_CACHE_MAX: usize = 512;

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addresses: Vec<SocketAddr>,
    fetched_at: Instant,
}

fn dns_cache() -> &'static parking_lot::Mutex<std::collections::HashMap<(String, u16), DnsCacheEntry>>
{
    static CACHE: std::sync::OnceLock<
        parking_lot::Mutex<std::collections::HashMap<(String, u16), DnsCacheEntry>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()))
}

/// Forget every cached resolver answer; called when the network changes
pub(crate) fn clear_dns_cache() {
    dns_cache().lock().clear();
}

/// Cached wrapper over `tokio::net::lookup_host`. Only successful lookups are
/// cached; failures stay uncached so a flapping resolver recovers immediately
pub(super) async fn lookup_host_cached(
    host: &str,
    port: u16,
) -> std::io::Result<Vec<SocketAddr>> {
    let key = (host.to_ascii_lowercase(), port);
    if let Some(entry) = dns_cache().lock().get(&key).cloned() {
        if entry.fetched_at.elapsed() < DNS_CACHE_TTL {
            return Ok(entry.addresses);
        }
    }
    let resolved = tokio::net::lookup_host((host, port)).await?;
    let mut addresses: Vec<SocketAddr> = Vec::new();
    for address in resolved {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if !addresses.is_empty() {
        let mut cache = dns_cache().lock();
        if cache.len() >= DNS_CACHE_MAX {
            let now = Instant::now();
            cache.retain(|_, entry| now.duration_since(entry.fetched_at) < DNS_CACHE_TTL);
            if cache.len() >= DNS_CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert(
            key,
            DnsCacheEntry {
                addresses: addresses.clone(),
                fetched_at: Instant::now(),
            },
        );
    }
    Ok(addresses)
}

/// Context attached to a raw CONNECT tunnel. Raw tunnels bypass the pooled HTTP
/// client, so without this summary a stalled TLS handshake leaves no request-level
/// trace in the logs.
struct TunnelInfo {
    host: String,
    port: u16,
    mode: &'static str,
}

impl TunnelInfo {
    fn new(host: impl Into<String>, port: u16, mode: &'static str) -> Self {
        Self {
            host: host.into(),
            port,
            mode,
        }
    }
}

/// Whether a cached direct plan may be turned into a raw TCP tunnel.
///
/// Only routes that never use MITM may do this. A route that can use ECH or
/// fake SNI has to terminate the browser's TLS locally, and the browser must
/// not see a different certificate on the next connection to the same host:
/// the first CONNECT was intercepted, the next one has to be too.
pub(super) fn may_tunnel_directly(direct_only: bool, plan_mode: TlsMode) -> bool {
    direct_only && plan_mode == TlsMode::Direct
}

pub(super) async fn handle_connect(
    req: &mut Request<Incoming>,
    ctx: Arc<ProxyContext>,
) -> Response<ProxyBody> {
    // Borrow the authority instead of copying it: CONNECT is the entry point for
    // every new browser connection, and `parse_authority` owns the result anyway.
    let authority = match req.uri().authority() {
        Some(authority) => authority.as_str(),
        None => match req.uri().path().strip_prefix("//") {
            Some(value) => value,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid CONNECT target",
                    "The CONNECT request did not contain an authority.",
                )
            }
        },
    };
    let Some((host, port)) = parse_authority(authority, 443) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "Invalid CONNECT target",
            &format!("Could not parse `{authority}`."),
        );
    };
    // Normalize once here: the raw tunnel, plan cache and the MITM Host check
    // must all agree on one spelling (trailing root dot, IDNA, case).
    let is_ip = is_ip_literal(&host);
    let host = if is_ip {
        host
    } else {
        match normalize_hostname_cow(&host) {
            Ok(Cow::Owned(normalized)) => normalized,
            // Borrowed means the parsed host was already canonical; keep the
            // existing allocation instead of making a second identical String.
            Ok(Cow::Borrowed(_)) | Err(_) => host,
        }
    };

    let (config, matcher) = ctx.config.snapshot_and_matcher();
    let matched = if is_ip {
        None
    } else {
        matcher.match_entry_normalized(&host)
    };
    let Some((group_id, rule_index)) = matched else {
        // These branches are terminal, so move the host into the tunnel info
        // instead of cloning it once more.
        return tunnel_to_host(req, host, port).await;
    };
    let Some(group) = config.group(group_id) else {
        return tunnel_to_host(req, host, port).await;
    };
    if !group.enabled || ctx.status.paused() {
        return tunnel_to_host(req, host, port).await;
    }
    // Resolve the per-domain route once from the matcher's rule index. The
    // previous code scanned every rule in the group twice per CONNECT.
    let route = group.route_at(rule_index);

    // Explicitly direct groups never need MITM. When the CA is not trusted we also keep
    // Auto groups on the raw path: a direct origin still works, while an ECH/fake-SNI
    // origin would only produce a browser certificate error anyway.
    //
    // A cached direct route is passed into the same race as the other candidates
    // instead of being awaited by itself. A stale cached address that accepts TCP
    // but never completes the handshake would otherwise hold CONNECT for the full
    // per-candidate timeout before the healthy catalog/DNS route is tried.
    let direct_only = route.is_direct_only();
    let cached_plan = if direct_only {
        ctx.engine
            .cached_plan(&host, port, true)
            .filter(|plan| may_tunnel_directly(direct_only, plan.mode))
    } else {
        None
    };
    if direct_only || !ctx.ca.installed() {
        return tunnel_direct_group(req, &ctx, host, port, cached_plan).await;
    }

    // The browser is about to perform its local TLS handshake. Use that time
    // to resolve the cold DoH/ECH route instead of waiting for the first HTTP
    // request to trigger it.
    ctx.engine.prefetch_cold_route(&host, port, route);

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
    // Build the normalized authority once for the whole tunnel. Every request
    // on this connection (HTTP/2 can multiplex many) only clones an `Arc` and
    // reuses the parsed authority, instead of cloning the host String and
    // formatting/re-parsing an absolute URI per request.
    let target = match upstream::MitmTarget::new(&host, port) {
        Ok(target) => target,
        Err(error) => {
            return error_response(StatusCode::BAD_GATEWAY, "Invalid MITM target", &error)
        }
    };
    let log_host = target.host.clone();
    let on_upgrade = upgrade::on(req);
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
                    let target = target.clone();
                    async move {
                        Ok::<_, Infallible>(upstream::handle_mitm_request(req, ctx, target).await)
                    }
                });
                let io = TokioIo::new(tls);
                if alpn.as_deref() == Some(b"h2") {
                    http2::Builder::new(TokioExecutor::new())
                        .adaptive_window(true)
                        .timer(TokioTimer::new())
                        .serve_connection(io, service)
                        .await
                        .context("serving MITM HTTP/2 connection")
                } else {
                    http1::Builder::new()
                        // The timer arms hyper's header-read timeout for the
                        // browser side of the MITM tunnel as well.
                        .timer(TokioTimer::new())
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                        .context("serving MITM HTTP/1.1 connection")
                }
            }
            .await;
        if let Err(error) = result {
            tracing::debug!(domain = %log_host, error = %error, "MITM connection ended");
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
    host: String,
    port: u16,
    cached_plan: Option<Arc<ConnectPlan>>,
) -> Response<ProxyBody> {
    let mut cursor = match ctx.engine.route_normalized(&host, port, true) {
        Route::Bypass(_) => return tunnel_to_host(req, host, port).await,
        Route::Blocked(outcome) => {
            return upstream::diagnostics_error_page(&host, &outcome.diagnostics, ctx)
        }
        Route::Group(cursor) => cursor,
    };
    // The browser performs the TLS handshake itself on a raw CONNECT tunnel, so only
    // direct plans can be used. Without this, an auto group whose last-good strategy
    // was ECH generates (and awaits DoH for) an ECH plan before every direct
    // candidate, and a fast-failing first address starves the rest of the list.
    cursor.restrict_to_direct();
    if let Some(plan) = cached_plan.as_ref() {
        // The cached route is seeded into the race, not generated again.
        cursor.skip_plan(plan);
    }
    let timeout = Duration::from_millis(
        ctx.config
            .snapshot()
            .advanced
            .ip_timeout_ms
            .clamp(500, 10_000),
    );
    match race_tcp_plans(&mut cursor, cached_plan, timeout).await {
        Some((plan, stream, latency)) => {
            let _ = cursor.note_success(plan, latency);
            tunnel_connect(req, stream, TunnelInfo::new(host, port, "raw-direct"))
        }
        None => {
            let diagnostics = cursor.outcome().map(|outcome| outcome.diagnostics.clone());
            match diagnostics {
                Some(diagnostics) => upstream::diagnostics_error_page(&host, &diagnostics, ctx),
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
    cached_plan: Option<Arc<ConnectPlan>>,
    timeout: Duration,
) -> Option<(Arc<ConnectPlan>, TcpStream, u64)> {
    type RaceResult =
        Result<(Arc<ConnectPlan>, TcpStream, u64), (Arc<ConnectPlan>, FailureReason, String)>;
    enum Event {
        Plan(Option<Arc<ConnectPlan>>),
        Result(RaceResult),
    }

    let mut pending: FuturesUnordered<Pin<Box<dyn Future<Output = RaceResult> + Send>>> =
        FuturesUnordered::new();
    let mut exhausted = false;
    let mut first_start: Option<Instant> = None;
    // As in the pooled race, a failed candidate releases the remaining
    // hedge delay immediately instead of making the fallback wait it out.
    let (failure_tx, failure_rx) = tokio::sync::watch::channel(false);

    // Seed the cached route as the first race member. Generated plans join
    // after the normal stagger, or immediately if this route fails. The old
    // code awaited the cached TCP connect alone and could spend the full
    // per-candidate timeout before even starting the fallback.
    if let Some(plan) = cached_plan {
        let address = SocketAddr::new(plan.ip, plan.port);
        let failed_plan = Arc::clone(&plan);
        pending.push(Box::pin(async move {
            let started = Instant::now();
            match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    crate::util::apply_tcp_keepalive(&stream);
                    Ok((
                        plan,
                        stream,
                        started.elapsed().as_millis() as u64,
                    ))
                }
                Ok(Err(error)) => Err((
                    failed_plan,
                    FailureReason::TcpRefused,
                    format!("connecting to {address} failed: {error}"),
                )),
                Err(_) => Err((
                    failed_plan,
                    FailureReason::TcpTimeout,
                    format!("connecting to {address} timed out"),
                )),
            }
        }));
        first_start = Some(Instant::now());
    }

    loop {
        let event = if !exhausted && pending.len() < RAW_RACE_SIZE {
            tokio::select! {
                plan = cursor.next_plan() => Event::Plan(plan.map(Arc::new)),
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
                let mut failure_rx = failure_rx.clone();
                pending.push(Box::pin(async move {
                    if let Some(delay) = delay {
                        if !*failure_rx.borrow() {
                            tokio::select! {
                                _ = tokio::time::sleep(delay) => {}
                                _ = failure_rx.changed() => {}
                            }
                        }
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
                Ok((plan, stream, latency)) => return Some((plan, stream, latency)),
                Err((plan, reason, detail)) => {
                    cursor.forget_plan(&plan);
                    cursor.note_failure(&plan, reason, detail);
                    // Same rule as the pooled race: once a candidate has
                    // failed, the fallback is no longer speculative and should
                    // not wait for the rest of the initial hedge window.
                    first_start = None;
                    let _ = failure_tx.send(true);
                }
            },
        }
    }
}

#[cfg(test)]
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

/// RFC 8305: 首选地址族保持首位, 两族交替排布
/// 黑洞的 AAAA 不会挡住排在后面的全部 IPv4
pub(super) fn interleave_by_family<T, F>(items: Vec<T>, is_preferred_family: F) -> Vec<T>
where
    F: Fn(&T) -> bool,
{
    if items.len() < 3 {
        return items;
    }
    let preferred_first = is_preferred_family(&items[0]);
    let mut preferred = Vec::new();
    let mut other = Vec::new();
    for item in items {
        if is_preferred_family(&item) == preferred_first {
            preferred.push(item);
        } else {
            other.push(item);
        }
    }
    let mut preferred = preferred.into_iter();
    let mut other = other.into_iter();
    let mut out = Vec::new();
    out.extend(preferred.next());
    loop {
        match other.next() {
            Some(item) => out.push(item),
            None => break,
        }
        match preferred.next() {
            Some(item) => out.push(item),
            None => break,
        }
    }
    out.extend(preferred);
    out.extend(other);
    out
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
    let resolved = match tokio::time::timeout(timeout, lookup_host_cached(host, port)).await {
        Ok(Ok(resolved)) => resolved,
        Ok(Err(error)) => {
            return Err((false, format!("resolving {host}:{port} failed: {error}")));
        }
        Err(_) => {
            return Err((true, format!("resolving {host}:{port} timed out")));
        }
    };
    let addresses = interleave_by_family(resolved, |address| address.is_ipv4());
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
        // Release the hedge sleep as soon as one address fails, so a refused
        // first address does not add 150 ms to a healthy fallback.
        let (failure_tx, failure_rx) = tokio::sync::watch::channel(false);
        for (offset, address) in addresses[index..end].iter().copied().enumerate() {
            let mut failure_rx = failure_rx.clone();
            pending.push(Box::pin(async move {
                // Give the preferred address a head start; the rest follow together
                // after one stagger instead of a linear ramp.
                if offset > 0 && !*failure_rx.borrow() {
                    tokio::select! {
                        _ = tokio::time::sleep(RAW_RACE_STAGGER) => {}
                        _ = failure_rx.changed() => {}
                    }
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
                    let _ = failure_tx.send(true);
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

async fn tunnel_to_host(
    req: &mut Request<Incoming>,
    host: String,
    port: u16,
) -> Response<ProxyBody> {
    let upstream = match connect_host_staggered(&host, port, CONNECT_TIMEOUT).await {
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
    tunnel_connect(req, upstream, TunnelInfo::new(host, port, "bypass"))
}

fn tunnel_connect(
    req: &mut Request<Incoming>,
    mut upstream: TcpStream,
    info: TunnelInfo,
) -> Response<ProxyBody> {
    let on_upgrade = upgrade::on(req);
    tokio::spawn(async move {
        let started = Instant::now();
        match on_upgrade.await {
            Ok(upgraded) => {
                let upstream_addr = upstream.peer_addr().ok();
                let mut upgraded = TokioIo::new(upgraded);
                match tokio::io::copy_bidirectional_with_sizes(
                    &mut upgraded,
                    &mut upstream,
                    COPY_BUFFER_SIZE,
                    COPY_BUFFER_SIZE,
                )
                .await
                {
                    Ok((to_upstream, from_upstream)) => {
                        let elapsed_ms = started.elapsed().as_millis() as u64;
                        // A long-lived WebSocket/SSH tunnel is not a stall. The
                        // actionable case is a client that sent bytes but the
                        // upstream never answered (the raw TLS handshake hung).
                        let stalled = from_upstream == 0 && to_upstream > 0 && elapsed_ms >= 500;
                        if stalled {
                            tracing::warn!(
                                host = %info.host,
                                port = info.port,
                                mode = info.mode,
                                upstream = ?upstream_addr,
                                bytes_to_upstream = to_upstream,
                                bytes_from_upstream = from_upstream,
                                elapsed_ms,
                                "raw tunnel finished without upstream data"
                            );
                        } else {
                            tracing::debug!(
                                host = %info.host,
                                port = info.port,
                                mode = info.mode,
                                upstream = ?upstream_addr,
                                bytes_to_upstream = to_upstream,
                                bytes_from_upstream = from_upstream,
                                elapsed_ms,
                                "raw tunnel finished"
                            );
                        }
                    }
                    Err(error) => {
                        let elapsed_ms = started.elapsed().as_millis() as u64;
                        let upstream_addr = upstream.peer_addr().ok();
                        tracing::debug!(
                            host = %info.host,
                            port = info.port,
                            mode = info.mode,
                            upstream = ?upstream_addr,
                            elapsed_ms,
                            error = %error,
                            "raw tunnel failed"
                        );
                    }
                }
            }
            Err(error) => tracing::debug!(
                host = %info.host,
                port = info.port,
                mode = info.mode,
                error = %error,
                "CONNECT upgrade failed"
            ),
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
        configured_modes: Vec::new(),
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
