use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::uri::{Authority, PathAndQuery, Scheme, Uri};
use http::{header, HeaderMap, HeaderName, Method, Request, Response, StatusCode};
use http_body_util::{Either, Full};
use hyper::body::Incoming;
use hyper::upgrade::{self, OnUpgrade};
use hyper_util::rt::TokioIo;

use super::pool::{UpstreamBody, UpstreamResponseBody};
use super::{escape_html, full_body, ProxyBody, ProxyContext, COPY_BUFFER_SIZE};
use crate::domain::{is_ip_literal, normalize_hostname, normalize_hostname_cow};
use crate::status::{AttemptRecord, DomainDiagnostics, State};
use crate::strategy::FailureReason;
use crate::util::{host_header_name, parse_authority};

pub(crate) const ERROR_STYLE: &str = r#"<style>
:root{color-scheme:light dark}body{margin:0;background:#0f1115;color:#e7e9ee;font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:860px;margin:48px auto;padding:0 24px}h1{font-size:22px;margin:0 0 4px}p.code{color:#8b93a7;margin:0 0 20px}
pre{white-space:pre-wrap;word-break:break-word;background:#171a21;border:1px solid #262b36;border-radius:8px;padding:14px;overflow:auto}
table{border-collapse:collapse;width:100%;margin:12px 0}th,td{text-align:left;border-bottom:1px solid #262b36;padding:7px 8px;font-size:13px;vertical-align:top}
code{background:#171a21;padding:1px 5px;border-radius:4px}ul{padding-left:20px}.warn{color:#ffcc66}.bad{color:#ff7a7a}.good{color:#7ee2a8}
</style>"#;

/// Both halves of a WebSocket upgrade must be awaited concurrently and bounded:
/// a client that stalls after asking for an upgrade must not leave a spawned
/// task holding the upstream `OnUpgrade` forever.
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) async fn handle_forward(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext>,
) -> Response<ProxyBody> {
    let target = match target_of(&req) {
        Ok(target) => target,
        Err(error) => {
            return super::error_response(
                StatusCode::BAD_REQUEST,
                "Invalid proxy request",
                &format!("{error:#}"),
            )
        }
    };
    let Target {
        normalized_host,
        port,
        https,
        path_and_query,
        upstream_uri,
    } = target;

    // Borrow the host for the error path. A canonical absolute-form request
    // keeps it inside the reused URI, so the common case allocates nothing;
    // a rebuilt request owns the normalized copy.
    let host_uri = upstream_uri.clone();
    let host: &str = target_host(normalized_host.as_deref(), host_uri.as_ref());

    let upgrade_requested = is_upgrade(req.headers());
    let mut req = req;
    let client_upgrade = if upgrade_requested {
        Some(upgrade::on(&mut req))
    } else {
        None
    };

    // Absolute-form proxy requests already carry a parsed URI. Reuse it when
    // the host needed no normalization, which is the normal browser case;
    // otherwise fall back to rebuilding the authority + path.
    let result = match upstream_uri {
        Some(uri) => {
            forward_with_uri(
                &ctx,
                req,
                host,
                port,
                uri,
                upgrade_requested,
                client_upgrade,
            )
            .await
        }
        None => {
            let path_and_query = path_and_query.unwrap_or_else(|| PathAndQuery::from_static("/"));
            forward_with_pool(
                &ctx,
                req,
                host,
                port,
                https,
                &path_and_query,
                upgrade_requested,
                client_upgrade,
            )
            .await
        }
    };
    match result {
        Ok(response) => response,
        Err(detail) => match_forward_error(&ctx, host, port, https, detail),
    }
}

struct Target {
    /// Normalized host, owned only when the request URI had to be rebuilt.
    /// `None` means the host is borrowed from [`Self::upstream_uri`].
    normalized_host: Option<String>,
    port: u16,
    https: bool,
    /// Set only when the absolute-form request URI cannot be reused. Keeping
    /// the parsed `PathAndQuery` avoids copying the path into a new String.
    path_and_query: Option<PathAndQuery>,
    /// Original absolute-form URI when reusing it is byte-for-byte equivalent
    /// to rebuilding the authority (lowercase host, no userinfo, path present).
    upstream_uri: Option<Uri>,
}

/// The normalized host of a target: the owned copy when the request URI had
/// to be rebuilt, otherwise borrowed from the reused upstream URI.
fn target_host<'a>(normalized_host: Option<&'a str>, upstream_uri: Option<&'a Uri>) -> &'a str {
    match normalized_host {
        Some(host) => host,
        None => {
            // An IPv6 literal keeps its brackets in the authority.
            crate::domain::bare_host(upstream_uri.and_then(|uri| uri.host()).unwrap_or(""))
        }
    }
}

/// Immutable authority for one MITM connection. The browser reuses a CONNECT
/// tunnel for many requests (HTTP/2 can multiplex hundreds), so the normalized
/// host and parsed authority are built once and shared by every request.
pub(crate) struct MitmTarget {
    pub(crate) host: Arc<str>,
    pub(crate) port: u16,
    authority: Authority,
}

impl MitmTarget {
    pub(crate) fn new(host: &str, port: u16) -> std::result::Result<Arc<Self>, String> {
        let authority = authority(host, port, true)
            .parse::<Authority>()
            .map_err(|error| format!("invalid MITM authority `{host}:{port}`: {error}"))?;
        Ok(Arc::new(Self {
            host: Arc::from(host),
            port,
            authority,
        }))
    }
}

fn target_of<B>(req: &Request<B>) -> Result<Target> {
    let uri = req.uri();
    if let (Some(scheme), Some(host)) = (uri.scheme_str(), uri.host()) {
        // The brackets of an IPv6 literal belong to the authority, not to the
        // host.  Keeping them would make the host look like a domain name and
        // the request would bypass every group.
        let host = crate::domain::bare_host(host);
        let https = match scheme {
            "https" => true,
            "http" => false,
            other => bail!("unsupported proxy scheme `{other}`"),
        };
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        // Borrow the normalized host while it is already canonical. The old
        // code always allocated a lowercase copy, even for the common case of
        // a browser sending an already-normalized host.
        let normalized =
            normalize_hostname_cow(host).unwrap_or_else(|_| Cow::Owned(host.to_ascii_lowercase()));
        let default_port = if https { 443 } else { 80 };
        let reusable = normalized.as_ref() == host
            && uri.path_and_query().is_some()
            && uri
                .authority()
                .is_none_or(|authority| !authority.as_str().contains('@'))
            && !matches!(uri.port_u16(), Some(port) if port == default_port);
        if reusable {
            return Ok(Target {
                normalized_host: None,
                port,
                https,
                path_and_query: None,
                upstream_uri: Some(uri.clone()),
            });
        }
        return Ok(Target {
            normalized_host: Some(normalized.into_owned()),
            port,
            https,
            path_and_query: Some(
                uri.path_and_query()
                    .cloned()
                    .unwrap_or_else(|| PathAndQuery::from_static("/")),
            ),
            upstream_uri: None,
        });
    }
    let path_and_query = uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    let host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .context("request has neither absolute URI nor Host header")?;
    let (host, port) = parse_authority(host_header, 80).context("invalid Host header")?;
    Ok(Target {
        normalized_host: Some(host),
        port,
        https: false,
        path_and_query: Some(path_and_query),
        upstream_uri: None,
    })
}

pub(crate) async fn handle_mitm_request(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext>,
    target: Arc<MitmTarget>,
) -> Response<ProxyBody> {
    // The browser almost always repeats the CONNECT host verbatim (possibly
    // with a different case). Compare the header/URI host in place; only the
    // mismatch path needs to normalize and allocate for the error message.
    if !request_host_matches(&req, &target.host) {
        let target_host = request_host(&req).unwrap_or(Cow::Borrowed(""));
        let normalized =
            normalize_hostname(&target_host).unwrap_or_else(|_| target_host.into_owned());
        if normalized != target.host.as_ref() {
            return super::error_response(
                StatusCode::BAD_REQUEST,
                "Unexpected host on MITM connection",
                &format!(
                    "CONNECT was for `{}` but the request targets `{normalized}`.",
                    target.host
                ),
            );
        }
    }

    let port = target.port;
    let path_and_query = req
        .uri()
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    let upstream_uri = match build_mitm_uri(&target, path_and_query) {
        Ok(uri) => uri,
        Err(error) => {
            return super::error_response(
                StatusCode::BAD_REQUEST,
                "Invalid upstream URI",
                &format!(
                    "building upstream URI for {}:{} failed: {error}",
                    target.host, port
                ),
            )
        }
    };
    let upgrade_requested = is_upgrade(req.headers());
    let mut req = req;
    let client_upgrade = if upgrade_requested {
        Some(upgrade::on(&mut req))
    } else {
        None
    };

    match forward_with_uri(
        &ctx,
        req,
        &target.host,
        port,
        upstream_uri,
        upgrade_requested,
        client_upgrade,
    )
    .await
    {
        Ok(response) => response,
        Err(detail) => {
            if let Some(diagnostics) = ctx.status.get(&target.host) {
                if diagnostics.state == State::Failed {
                    return diagnostics_error_page(&target.host, &diagnostics, &ctx);
                }
            }
            if let Some(plan) = ctx.engine.cached_plan(&target.host, port, true) {
                return super::upstream_failure(&ctx, &plan, FailureReason::TlsError, detail);
            }
            super::error_response(
                StatusCode::BAD_GATEWAY,
                "Upstream request failed",
                &format!("{}:{port}: {detail}", target.host),
            )
        }
    }
}

fn match_forward_error(
    ctx: &ProxyContext,
    host: &str,
    port: u16,
    https: bool,
    detail: String,
) -> Response<ProxyBody> {
    if !is_ip_literal(host) {
        if let Some(diagnostics) = ctx.status.get(host) {
            if diagnostics.state == State::Failed {
                return diagnostics_error_page(host, &diagnostics, ctx);
            }
        }
        if https {
            if let Some(plan) = ctx.engine.cached_plan(host, port, true) {
                return super::upstream_failure(ctx, &plan, FailureReason::TlsError, detail);
            }
        }
    }
    super::error_response(
        StatusCode::BAD_GATEWAY,
        "Upstream request failed",
        &format!("{host}:{port}: {detail}"),
    )
}

fn request_host<'a>(req: &'a Request<Incoming>) -> Option<Cow<'a, str>> {
    if let Some(host) = req.uri().host() {
        return Some(Cow::Borrowed(host));
    }
    req.headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_authority(value, 443))
        .map(|(host, _)| Cow::Owned(host))
}

/// Compare the request's host with the CONNECT target without allocating.
/// HTTP/1.1 MITM requests use the origin-form (`GET / HTTP/1.1` + `Host`), so
/// this is the common path for every request on an h1 tunnel.
fn request_host_matches(req: &Request<Incoming>, expected: &str) -> bool {
    if let Some(host) = req.uri().host() {
        return same_host(host, expected);
    }
    req.headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(host_header_name)
        .is_some_and(|host| same_host(host, expected))
}

/// Host equality without allocating on the hot path. Browsers may preserve a
/// trailing root dot or vary ASCII case; anything else is normalized only when
/// we are about to reject the request.
fn same_host(candidate: &str, expected: &str) -> bool {
    let candidate = candidate.strip_suffix('.').unwrap_or(candidate);
    candidate.eq_ignore_ascii_case(expected)
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        && headers
            .get(header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            // Compare the comma separated tokens instead of searching for a
            // substring: `Connection: x-upgrade` is not an upgrade request.
            .map(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(true)
}

#[allow(clippy::too_many_arguments)]
async fn forward_with_pool(
    ctx: &ProxyContext,
    req: Request<Incoming>,
    host: &str,
    port: u16,
    https: bool,
    path_and_query: &PathAndQuery,
    upgrade_requested: bool,
    client_upgrade: Option<OnUpgrade>,
) -> std::result::Result<Response<ProxyBody>, String> {
    let upstream_uri = build_upstream_uri(host, port, https, path_and_query)
        .map_err(|error| format!("building upstream URI for {host}:{port} failed: {error}"))?;
    forward_with_uri(
        ctx,
        req,
        host,
        port,
        upstream_uri,
        upgrade_requested,
        client_upgrade,
    )
    .await
}

/// Send an already-built absolute upstream URI. MITM requests use this path so
/// a request only clones the connection's pre-parsed `Authority` and the
/// request's `PathAndQuery` instead of formatting and re-parsing a URI string.
#[allow(clippy::too_many_arguments)]
async fn forward_with_uri(
    ctx: &ProxyContext,
    req: Request<Incoming>,
    host: &str,
    port: u16,
    upstream_uri: Uri,
    upgrade_requested: bool,
    client_upgrade: Option<OnUpgrade>,
) -> std::result::Result<Response<ProxyBody>, String> {
    let is_get = req.method() == Method::GET;
    let has_range = req.headers().contains_key(header::RANGE);
    let rule_uri = upstream_uri;
    let (mut parts, body) = req.into_parts();
    sanitize_request_headers(&mut parts.headers, upgrade_requested);
    // One lazy snapshot, shared by both lookups; other requests never take it.
    let mut config = None;
    let plan = if super::download::mirror_candidate(&rule_uri) {
        let config = config.get_or_insert_with(|| ctx.config.snapshot());
        super::download::mirror_origins(
            &config.advanced.download,
            &ctx.download.mirrors,
            &parts.method,
            &rule_uri,
        )
    } else {
        None
    };
    let mirrored = plan.is_some();
    // Image relays replace the whole request, so they are resolved after the
    // browser headers are cleaned up and before anything is built for the
    // origin.
    let relay = if parts.method == Method::GET || parts.method == Method::HEAD {
        let config = config.get_or_insert_with(|| ctx.config.snapshot());
        if config.advanced.image_relays.iter().any(|rule| rule.enabled) {
            super::relay::plan(
                config,
                &parts.method,
                &parts.headers,
                &rule_uri,
                &ctx.relay_health,
            )
        } else {
            None
        }
    } else {
        None
    };
    let relayed = relay.is_some();
    // Keep the browser's headers for the direct retry and for the range
    // requests of a direct download: a private codeload archive needs its
    // cookies on every chunk. A mirror never sees them.
    let (direct_headers, mirror_headers) = if mirrored {
        let direct_headers = parts.headers.clone();
        super::third_party::strip_request_credentials(&mut parts.headers);
        // The mirrored path never reads `parts.headers` again, so the mirror
        // copy moves instead of cloning the whole map a second time.
        (direct_headers, std::mem::take(&mut parts.headers))
    } else if relayed {
        // The relay keeps its own copy of the headers; the direct fallback
        // replays the browser's request unchanged.
        (parts.headers.clone(), HeaderMap::new())
    } else {
        // No mirror runs on this request, and the direct retry below is only
        // reachable from the mirrored branch. The segment base needs just the
        // handful of credential headers, so keep that small subset instead of
        // deep-cloning the whole browser HeaderMap on every request.
        (
            super::download::credential_headers(&parts.headers),
            HeaderMap::new(),
        )
    };

    let response_uri;
    let mut response;
    let mut served_by_mirror = false;
    let mut served_by_third_party = false;
    let mut relay_trace: Option<super::relay::BodyTrace> = None;
    let mut mirror_prefix: Option<String> = None;
    let method = parts.method.clone();
    // Kept for the range-probe failover: the next candidate needs a rewrite.
    let mut mirror_plan: Option<super::download::MirrorPlan> = None;
    if let Some(plan) = plan {
        mirror_plan = Some(plan);
        match try_mirrors(
            ctx,
            &mirror_plan.as_ref().unwrap(),
            &method,
            &mirror_headers,
            upgrade_requested,
        )
        .await
        {
            Some((mirrored_response, uri, prefix)) => {
                tracing::debug!(mirror = %prefix, path = %rule_uri.path(), "served through a mirror");
                response = mirrored_response;
                response_uri = uri;
                served_by_mirror = true;
                served_by_third_party = true;
                mirror_prefix = Some(prefix);
            }
            None => {
                tracing::info!(
                    path = %rule_uri.path(),
                    "every mirror failed, serving direct"
                );
                response =
                    send_once(ctx, &method, &direct_headers, &rule_uri, upgrade_requested).await?;
                response_uri = rule_uri.clone();
            }
        }
    } else if let Some(relay) = relay {
        if relay.parked {
            return Err(format!("image relay `{}` is cooling down", relay.id));
        }
        let method = parts.method.clone();
        // The budget covers the header wait only: once the relay starts
        // streaming, the body belongs to the browser and is never cut off.
        let attempt = tokio::time::timeout(
            relay.timeout,
            send_once(ctx, &method, &relay.headers, &relay.uri, upgrade_requested),
        )
        .await;
        match attempt {
            Ok(Ok(served)) => {
                let failed = super::relay::should_fallback(served.status());
                if failed {
                    ctx.relay_health.note_failure(&relay.id);
                } else {
                    ctx.relay_health.note_success(&relay.id);
                }
                if failed && relay.fallback_direct {
                    tracing::info!(
                        relay = %relay.id,
                        status = %served.status(),
                        "image relay refused the request; serving the origin"
                    );
                    response =
                        send_once(ctx, &method, &direct_headers, &rule_uri, upgrade_requested)
                            .await?;
                    response_uri = rule_uri.clone();
                } else {
                    // A cache HIT and a cache MISS read the same in the pool
                    // log once the headers are in, which makes "the relay is
                    // slow" impossible to rule out from logs alone.
                    tracing::debug!(
                        relay = %relay.id,
                        status = %served.status(),
                        cache = header_text(served.headers(), "cf-cache-status"),
                        age = header_text(served.headers(), "age"),
                        length = header_text(served.headers(), header::CONTENT_LENGTH.as_str()),
                        "image relay answered"
                    );
                    response_uri = relay.uri;
                    response = served;
                    served_by_third_party = true;
                    relay_trace = Some(super::relay::BodyTrace::new(&relay.id));
                }
            }
            Ok(Err(error)) => {
                ctx.relay_health.note_failure(&relay.id);
                if !relay.fallback_direct {
                    return Err(format!("image relay `{}` failed: {error}", relay.id));
                }
                tracing::info!(relay = %relay.id, error = %error, "image relay failed; serving the origin");
                response =
                    send_once(ctx, &method, &direct_headers, &rule_uri, upgrade_requested).await?;
                response_uri = rule_uri.clone();
            }
            Err(_) => {
                // A parked relay must never make the page slower than the
                // origin would have been.
                ctx.relay_health.note_failure(&relay.id);
                if !relay.fallback_direct {
                    return Err(format!(
                        "image relay `{}` did not answer within {:?}",
                        relay.id, relay.timeout
                    ));
                }
                tracing::info!(
                    relay = %relay.id,
                    budget_ms = relay.timeout.as_millis() as u64,
                    "image relay did not answer in time; serving the origin"
                );
                response =
                    send_once(ctx, &method, &direct_headers, &rule_uri, upgrade_requested).await?;
                response_uri = rule_uri.clone();
            }
        }
    } else {
        parts.uri = rule_uri.clone();
        // Keep a cheap `Uri` handle for the response body's error logger. Cloning
        // the parsed URI shares its `Bytes`; allocating a fresh host String per
        // response is not necessary on this hot path.
        response_uri = rule_uri.clone();
        parts.version = http::Version::HTTP_11;
        let upstream_request = Request::from_parts(parts, Either::Left(body) as UpstreamBody);
        response = ctx
            .upstream
            .send_with_uri(upstream_request, upgrade_requested, &response_uri)
            .await
            .map_err(|error| format!("upstream request to {host}:{port} failed: {error}"))?;
    }

    if served_by_third_party {
        super::third_party::strip_response_cookies(response.headers_mut());
    }

    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            let server_upgrade = upgrade::on(&mut response);
            tokio::spawn(async move {
                // A tuple `(a.await, b.await)` polls `a` to completion before
                // even touching `b`, so a half-open client would strand the
                // upstream upgrade future. `try_join!` drives both at once and
                // the timeout bounds how long the task can live.
                let paired = tokio::time::timeout(UPGRADE_TIMEOUT, async {
                    tokio::try_join!(client_upgrade, server_upgrade)
                })
                .await;
                match paired {
                    Ok(Ok((client, server))) => {
                        let mut client = TokioIo::new(client);
                        let mut server = TokioIo::new(server);
                        if let Err(error) = tokio::io::copy_bidirectional_with_sizes(
                            &mut client,
                            &mut server,
                            COPY_BUFFER_SIZE,
                            COPY_BUFFER_SIZE,
                        )
                        .await
                        {
                            tracing::debug!(error = %error, "websocket tunnel closed");
                        }
                    }
                    Ok(Err(error)) => tracing::debug!(
                        error = %error,
                        "websocket upgrade failed"
                    ),
                    Err(_) => tracing::debug!("websocket upgrade timed out"),
                }
            });
        }
        return Ok(into_proxy_response(response, response_uri, ctx, relay_trace));
    }

    // Segmentation dials the origin URI directly, so it would quietly bypass a
    // relay that is already carrying the bytes.
    if !relayed && super::download::segment_eligible(ctx, &rule_uri, is_get, has_range, &response) {
        let base_headers = if served_by_mirror {
            &mirror_headers
        } else {
            &direct_headers
        };
        // The serving mirror gets one range probe (3s, remembered for 10
        // minutes). When it fails, the remaining candidates are tried with a
        // full mirror request each; only when none qualifies does the already
        // streaming response serve as a single stream.
        if served_by_mirror && !mirror_prefix.as_deref().unwrap_or_default().is_empty() {
            let range_ok = super::download::mirror_range_ok(
                ctx,
                &response_uri,
                &super::download::probe_headers(base_headers, &response),
                &response,
                mirror_prefix.as_deref().unwrap_or_default(),
            )
            .await;
            if !range_ok {
                let tail = super::download::mirrors_after(
                    mirror_prefix.as_deref(),
                    ctx.download.mirrors.available(),
                );
                // Every candidate below gets its own send and probe budget, so
                // a long list could stall the browser far past
                // MIRROR_TOTAL_BUDGET (it was only enforced inside
                // `try_mirrors`). One shared deadline restores the invariant.
                let deadline = tokio::time::Instant::now() + MIRROR_TOTAL_BUDGET;
                for prefix in tail {
                    let Some(uri) = mirror_plan.as_ref().and_then(|plan| plan.rewrite(&prefix))
                    else {
                        continue;
                    };
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        tracing::info!(
                            path = %rule_uri.path(),
                            "mirror failover budget spent; serving the origin response"
                        );
                        break;
                    }
                    let attempt = tokio::time::timeout(
                        MIRROR_BUDGET.min(remaining),
                        send_once(ctx, &method, &mirror_headers, &uri, upgrade_requested),
                    )
                    .await;
                    let response = match attempt {
                        Ok(Ok(response)) if !mirror_failed(response.status()) => {
                            ctx.download.mirrors.note_success(&prefix);
                            response
                        }
                        Ok(Ok(response)) => {
                            if mirror_blame(response.status()) {
                                ctx.download.mirrors.cool_down(&prefix);
                            }
                            tracing::info!(
                                status = %response.status(),
                                mirror = %prefix,
                                "mirror refused the download"
                            );
                            continue;
                        }
                        Ok(Err(error)) => {
                            ctx.download.mirrors.cool_down(&prefix);
                            tracing::info!(error = %error, mirror = %prefix, "mirror request failed");
                            continue;
                        }
                        Err(_) => {
                            ctx.download.mirrors.cool_down(&prefix);
                            tracing::info!(mirror = %prefix, "mirror did not answer in time");
                            continue;
                        }
                    };
                    // This candidate replaces a response that did pass
                    // `segment_eligible`, so it has to pass the same header
                    // gate: a redirect, an encoded body or a missing
                    // Content-Length would reach `segment()` with nothing to
                    // slice — an empty file plus a merger that waits forever
                    // for chunks that can never arrive.
                    if super::download::response_eligible(&response).is_none() {
                        tracing::info!(
                            status = %response.status(),
                            mirror = %prefix,
                            "mirror response cannot be segmented, trying the next mirror"
                        );
                        continue;
                    }
                    if deadline.saturating_duration_since(tokio::time::Instant::now())
                        < super::download::RANGE_PROBE_TIMEOUT
                    {
                        // Not enough budget left to prove the candidate honours
                        // ranges; keep the browser moving instead.
                        break;
                    }
                    if super::download::mirror_range_ok(
                        ctx,
                        &uri,
                        &super::download::probe_headers(base_headers, &response),
                        &response,
                        &prefix,
                    )
                    .await
                    {
                        tracing::info!(mirror = %prefix, "mirror takes over the segmented download");
                        let mut response = response;
                        super::third_party::strip_response_cookies(response.headers_mut());
                        return Ok(super::download::segment(
                            ctx,
                            uri,
                            response,
                            true,
                            base_headers,
                            Some(&prefix),
                        )
                        .await);
                    }
                }
                tracing::info!(
                    path = %rule_uri.path(),
                    "no mirror supports ranges, serving the first response as a single stream"
                );
            }
        }
        return Ok(super::download::segment(
            ctx,
            response_uri,
            response,
            served_by_mirror,
            base_headers,
            mirror_prefix.as_deref(),
        )
        .await);
    }

    Ok(into_proxy_response(response, response_uri, ctx, relay_trace))
}

/// First-byte budget for one mirror. A hung mirror must not hold the download
/// for the global header timeout.
const MIRROR_BUDGET: Duration = Duration::from_secs(8);
/// A list with many dead mirrors must not stall the browser for minutes.
const MIRROR_TOTAL_BUDGET: Duration = Duration::from_secs(10);

/// Walks the candidate prefixes in order. A failing mirror is cooled down and the
/// next one is tried; `None` means none of them worked.
async fn try_mirrors(
    ctx: &ProxyContext,
    plan: &super::download::MirrorPlan,
    method: &Method,
    headers: &HeaderMap,
    upgrade_requested: bool,
) -> Option<(Response<UpstreamResponseBody>, Uri, String)> {
    let deadline = Instant::now() + MIRROR_TOTAL_BUDGET;
    for prefix in &plan.candidates {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            tracing::info!("mirror budget exhausted, serving direct");
            break;
        }
        let Some(uri) = plan.rewrite(prefix) else {
            continue;
        };
        let attempt = tokio::time::timeout(
            MIRROR_BUDGET.min(remaining),
            send_once(ctx, method, headers, &uri, upgrade_requested),
        )
        .await;
        match attempt {
            Ok(Ok(response)) if !mirror_failed(response.status()) => {
                ctx.download.mirrors.note_success(prefix);
                return Some((response, uri, prefix.clone()));
            }
            Ok(Ok(response)) => {
                if mirror_blame(response.status()) {
                    ctx.download.mirrors.cool_down(prefix);
                }
                tracing::info!(
                    status = %response.status(),
                    mirror = %prefix,
                    "mirror refused the download"
                );
            }
            Ok(Err(error)) => {
                ctx.download.mirrors.cool_down(prefix);
                tracing::info!(error = %error, mirror = %prefix, "mirror request failed");
            }
            Err(_) => {
                ctx.download.mirrors.cool_down(prefix);
                tracing::info!(mirror = %prefix, "mirror did not answer in time");
            }
        }
    }
    None
}

fn mirror_failed(status: StatusCode) -> bool {
    status.is_client_error() || status.is_server_error()
}

/// Whether the mirror itself is at fault. A 404 or 410 on a valid release URL
/// means the file is gone, so cooling the mirror would punish it for a dead link
/// and, over a few of them, switch the whole list off.
fn mirror_blame(status: StatusCode) -> bool {
    status != StatusCode::NOT_FOUND && status != StatusCode::GONE
}

/// Sends a bodyless request to `uri`; mirror attempts and the direct retry are
/// both bodyless, so nothing has to be buffered.
async fn send_once(
    ctx: &ProxyContext,
    method: &Method,
    headers: &HeaderMap,
    uri: &Uri,
    upgrade_requested: bool,
) -> std::result::Result<Response<UpstreamResponseBody>, String> {
    let mut request = Request::new(Either::Right(Full::new(Bytes::new())) as UpstreamBody);
    *request.method_mut() = method.clone();
    *request.uri_mut() = uri.clone();
    *request.headers_mut() = headers.clone();
    *request.version_mut() = http::Version::HTTP_11;
    ctx.upstream
        .send_with_uri(request, upgrade_requested, uri)
        .await
        .map_err(|error| format!("request to {} failed: {error}", uri.path()))
}

fn into_proxy_response(
    mut response: Response<UpstreamResponseBody>,
    uri: http::Uri,
    ctx: &ProxyContext,
    relay: Option<super::relay::BodyTrace>,
) -> Response<ProxyBody> {
    let status = response.status();
    let upgrade = status == StatusCode::SWITCHING_PROTOCOLS;
    sanitize_response_headers(response.headers_mut(), upgrade);
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        ProxyBody::upstream(body, uri, status, ctx.upstream.clone(), relay),
    )
}

/// Header value for a log field; `-` when absent or not UTF-8.
fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
}

/// `HeaderName::from_static` does not allocate, while removing a header by
/// `&str` builds a new name on every call.
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

const HOP_CONNECTION: u16 = 1 << 0;
const HOP_PROXY_AUTHENTICATE: u16 = 1 << 1;
const HOP_PROXY_AUTHORIZATION: u16 = 1 << 2;
const HOP_TE: u16 = 1 << 3;
const HOP_TRAILER: u16 = 1 << 4;
const HOP_TRANSFER_ENCODING: u16 = 1 << 5;
const HOP_UPGRADE: u16 = 1 << 6;
const HOP_HOST: u16 = 1 << 7;
const HOP_KEEP_ALIVE: u16 = 1 << 8;
const HOP_PROXY_CONNECTION: u16 = 1 << 9;

/// Remove hop-by-hop headers in one pass over the existing names. The old
/// implementation issued ten hash lookups per request even when none of these
/// headers were present, which is the normal browser case.
/// Tokens in a `Connection` value that only ever name a header the fixed
/// removals below already handle (`close` names no header at all). Skipping
/// them keeps the ubiquitous `Connection: keep-alive` allocation-free.
fn is_standard_hop_token(token: &str) -> bool {
    const STANDARD: [&str; 10] = [
        "connection",
        "keep-alive",
        "proxy-connection",
        "close",
        "upgrade",
        "te",
        "trailer",
        "transfer-encoding",
        "proxy-authenticate",
        "proxy-authorization",
    ];
    STANDARD.iter().any(|name| token.eq_ignore_ascii_case(name))
}

fn sanitize_hop_by_hop(headers: &mut HeaderMap, upgrade: bool, remove_host: bool) {
    let mut present = 0u16;
    for name in headers.keys() {
        present |= match name.as_str() {
            "connection" => HOP_CONNECTION,
            "proxy-authenticate" => HOP_PROXY_AUTHENTICATE,
            "proxy-authorization" => HOP_PROXY_AUTHORIZATION,
            "te" => HOP_TE,
            "trailer" => HOP_TRAILER,
            "transfer-encoding" => HOP_TRANSFER_ENCODING,
            "upgrade" => HOP_UPGRADE,
            "host" => HOP_HOST,
            "keep-alive" => HOP_KEEP_ALIVE,
            "proxy-connection" => HOP_PROXY_CONNECTION,
            _ => 0,
        };
    }
    if present & HOP_CONNECTION != 0 {
        // RFC 7230 §6.1: a header field named in Connection is hop-by-hop too
        // and must not be forwarded. The value is read before Connection is
        // dropped below; the standard tokens are already covered by the fixed
        // removals, so the usual `Connection: keep-alive` costs no allocation.
        let mut listed: Option<Vec<HeaderName>> = None;
        for value in headers.get_all(header::CONNECTION) {
            let Ok(value) = value.to_str() else {
                continue;
            };
            for token in value.split(',') {
                let token = token.trim();
                if token.is_empty() || is_standard_hop_token(token) {
                    continue;
                }
                let Ok(name) = HeaderName::from_bytes(token.to_ascii_lowercase().as_bytes()) else {
                    continue;
                };
                listed.get_or_insert_with(Vec::new).push(name);
            }
        }
        if let Some(listed) = listed {
            for name in listed {
                headers.remove(&name);
            }
        }
        if !upgrade {
            headers.remove(header::CONNECTION);
        }
    }
    if present & HOP_PROXY_AUTHENTICATE != 0 {
        headers.remove(header::PROXY_AUTHENTICATE);
    }
    if present & HOP_PROXY_AUTHORIZATION != 0 {
        headers.remove(header::PROXY_AUTHORIZATION);
    }
    if present & HOP_TE != 0 {
        headers.remove(header::TE);
    }
    if present & HOP_TRAILER != 0 {
        headers.remove(header::TRAILER);
    }
    if present & HOP_TRANSFER_ENCODING != 0 {
        headers.remove(header::TRANSFER_ENCODING);
    }
    if present & HOP_UPGRADE != 0 && !upgrade {
        headers.remove(header::UPGRADE);
    }
    if remove_host && present & HOP_HOST != 0 {
        headers.remove(header::HOST);
    }
    if present & HOP_KEEP_ALIVE != 0 {
        headers.remove(&KEEP_ALIVE);
    }
    if present & HOP_PROXY_CONNECTION != 0 {
        headers.remove(&PROXY_CONNECTION);
    }
}

fn sanitize_request_headers(headers: &mut HeaderMap, upgrade: bool) {
    sanitize_hop_by_hop(headers, upgrade, true);
}

pub(super) fn sanitize_response_headers(headers: &mut HeaderMap, upgrade: bool) {
    sanitize_hop_by_hop(headers, upgrade, false);
}

fn authority(host: &str, port: u16, https: bool) -> Cow<'_, str> {
    let default = if https { 443 } else { 80 };
    if host.contains(':') {
        // IPv6 literals must stay bracketed in an authority, even when the
        // port is implicit. An unbracketed literal is not a valid URI host.
        if port == default {
            Cow::Owned(format!("[{host}]"))
        } else {
            Cow::Owned(format!("[{host}]:{port}"))
        }
    } else if port == default {
        Cow::Borrowed(host)
    } else {
        Cow::Owned(format!("{host}:{port}"))
    }
}

/// Build the absolute upstream URI directly instead of formatting a string and
/// parsing it back. Same result, one allocation less and no re-parse.
fn build_upstream_uri(
    host: &str,
    port: u16,
    https: bool,
    path_and_query: &PathAndQuery,
) -> std::result::Result<Uri, http::Error> {
    Uri::builder()
        .scheme(if https { Scheme::HTTPS } else { Scheme::HTTP })
        .authority(authority(host, port, https).as_ref())
        .path_and_query(path_and_query.clone())
        .build()
}

/// MITM requests reuse the connection's parsed authority; assembling the
/// `Uri` from parts skips re-validating the host on every request.
fn build_mitm_uri(
    target: &MitmTarget,
    path_and_query: PathAndQuery,
) -> std::result::Result<Uri, http::uri::InvalidUriParts> {
    let mut parts = http::uri::Parts::default();
    parts.scheme = Some(Scheme::HTTPS);
    parts.authority = Some(target.authority.clone());
    parts.path_and_query = Some(path_and_query);
    Uri::from_parts(parts)
}

pub(crate) fn diagnostics_error_page(
    domain: &str,
    diagnostics: &DomainDiagnostics,
    ctx: &ProxyContext,
) -> Response<ProxyBody> {
    let ca = ctx.ca.status_cached();
    let mut attempts = String::new();
    if !diagnostics.attempts.is_empty() {
        attempts.push_str("<h2>Attempts</h2><table><tr><th>Strategy</th><th>IP</th><th>Source</th><th>SNI</th><th>Error</th><th>Detail</th></tr>");
        for attempt in &diagnostics.attempts {
            attempts.push_str(&attempt_row(attempt));
        }
        attempts.push_str("</table>");
    }
    let mut suggestions = String::new();
    if !diagnostics.suggestions.is_empty() {
        suggestions.push_str("<h2>Suggestions</h2><ul>");
        for suggestion in &diagnostics.suggestions {
            suggestions.push_str(&format!("<li>{}</li>", escape_html(suggestion)));
        }
        suggestions.push_str("</ul>");
    }
    let health = ctx.resolver.health_snapshot();
    let mut doh_health = String::new();
    if !health.is_empty() {
        doh_health.push_str("<h2>DoH health</h2><table><tr><th>Endpoint</th><th>Source</th><th>Healthy</th><th>Latency</th><th>Last error</th></tr>");
        for item in &health {
            doh_health.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&item.name),
                item.source,
                if item.healthy { "yes" } else { "no" },
                item.latency_ms
                    .map(|ms| format!("{ms} ms"))
                    .unwrap_or_else(|| "-".into()),
                escape_html(item.last_error.as_deref().unwrap_or("")),
            ));
        }
        doh_health.push_str("</table>");
    }
    let ca_note = if !ca.installed {
        format!(
            "<p class=\"warn\">The local CA is not installed (or trust could not be verified), so a \
             MITM strategy would show a certificate error. {}",
            escape_html(ca.note.as_deref().unwrap_or(""))
        )
    } else {
        String::new()
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>hakimi: {domain}</title>{style}</head>\
         <body><main><h1>hakimi 无法连接到 {domain_h}</h1>\
         <p class=\"code\">state={state:?} · strategy={strategy} · ipSource={ip_source} · dohSource={doh_source} · cache={cache} · catalogVersion={version}</p>\
         <p class=\"bad\"><strong>{error}</strong></p>\
         <pre>{detail}</pre>{ca_note}{attempts}{doh_health}{suggestions}\
         <p>Open the hakimi app for group/domain status and diagnostics.</p>\
         </main></body></html>",
        domain = escape_html(domain),
        domain_h = escape_html(domain),
        style = ERROR_STYLE,
        state = diagnostics.state,
        strategy = diagnostics
            .strategy
            .map(|strategy| strategy.to_string())
            .unwrap_or_else(|| "none".into()),
        ip_source = diagnostics
            .ip_source
            .map(|source| source.to_string())
            .unwrap_or_else(|| "none".into()),
        doh_source = diagnostics
            .doh_source
            .map(|source| source.to_string())
            .unwrap_or_else(|| "none".into()),
        cache = diagnostics.cache,
        version = diagnostics.catalog_version,
        error = escape_html(
            diagnostics
                .error
                .map(|error| error.as_str())
                .unwrap_or("unknown_error")
        ),
        detail = escape_html(diagnostics.detail.as_deref().unwrap_or("")),
        ca_note = ca_note,
        attempts = attempts,
        doh_health = doh_health,
        suggestions = suggestions,
    );
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(full_body(body))
        .expect("diagnostics response")
}

fn attempt_row(attempt: &AttemptRecord) -> String {
    format!(
        "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
        attempt.strategy,
        escape_html(&attempt.ip.to_string()),
        attempt.source,
        escape_html(attempt.sni.as_deref().unwrap_or("(none)")),
        escape_html(attempt.error.map(|error| error.as_str()).unwrap_or("")),
        escape_html(attempt.detail.as_deref().unwrap_or("")),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        authority, build_mitm_uri, build_upstream_uri, host_header_name, is_upgrade, same_host,
        sanitize_request_headers, sanitize_response_headers, target_host, target_of, MitmTarget, Target,
    };
    use http::uri::{PathAndQuery, Scheme};
    use http::{header, HeaderMap, Request, Uri};

    fn host_of(target: &Target) -> &str {
        target_host(
            target.normalized_host.as_deref(),
            target.upstream_uri.as_ref(),
        )
    }

    #[test]
    fn mitm_host_match_ignores_ascii_case_and_root_dot() {
        assert!(same_host("EXAMPLE.com", "example.com"));
        assert!(same_host("example.com.", "example.com"));
        assert!(!same_host("evil.example", "example.com"));
        assert!(!same_host("example.com.evil", "example.com"));
    }

    #[test]
    fn host_header_parsing_borrows_host_and_port() {
        assert_eq!(host_header_name("example.com:8443"), "example.com");
        assert_eq!(host_header_name("example.com"), "example.com");
        assert_eq!(host_header_name("[2001:db8::1]:8443"), "2001:db8::1");
        assert_eq!(host_header_name("example.com."), "example.com.");
        // A bare IPv6 literal must survive intact, not be truncated to
        // `2001:db8:` by the host:port split.
        assert_eq!(host_header_name("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn sanitize_keeps_only_the_headers_needed_for_an_upgrade() {
        let mut headers = HeaderMap::new();
        for name in [
            "connection",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "host",
            "keep-alive",
            "proxy-connection",
            "content-type",
        ] {
            headers.insert(name, "x".parse().unwrap());
        }
        sanitize_request_headers(&mut headers, false);
        for name in [
            "connection",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "host",
            "keep-alive",
            "proxy-connection",
        ] {
            assert!(!headers.contains_key(name), "{name} must be removed");
        }
        assert_eq!(headers.get("content-type").unwrap(), "x");

        let mut headers = HeaderMap::new();
        for name in [
            "connection",
            "upgrade",
            "host",
            "keep-alive",
            "proxy-connection",
        ] {
            headers.insert(name, "x".parse().unwrap());
        }
        sanitize_request_headers(&mut headers, true);
        assert!(headers.contains_key("connection"));
        assert!(headers.contains_key("upgrade"));
        assert!(!headers.contains_key("host"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("proxy-connection"));

        let mut response = HeaderMap::new();
        response.insert("host", "origin.example".parse().unwrap());
        response.insert("connection", "close".parse().unwrap());
        sanitize_response_headers(&mut response, false);
        assert!(!response.contains_key("connection"));
        assert_eq!(response.get("host").unwrap(), "origin.example");

        let mut response = HeaderMap::new();
        response.insert("connection", "upgrade".parse().unwrap());
        response.insert("upgrade", "websocket".parse().unwrap());
        sanitize_response_headers(&mut response, true);
        assert!(response.contains_key("connection"));
        assert!(response.contains_key("upgrade"));
    }

    #[test]
    fn headers_named_in_connection_are_hop_by_hop_too() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            "keep-alive, X-Smuggled".parse().unwrap(),
        );
        headers.insert("x-smuggled", "leak".parse().unwrap());
        headers.insert("x-end-to-end", "kept".parse().unwrap());
        sanitize_request_headers(&mut headers, false);
        assert!(
            !headers.contains_key("x-smuggled"),
            "a header named in Connection must not be forwarded"
        );
        assert!(headers.contains_key("x-end-to-end"));
        assert!(!headers.contains_key(header::CONNECTION));

        // An upgrade keeps Connection/Upgrade for the handshake, but a custom
        // header listed next to them is still hop-by-hop.
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, "Upgrade, X-Smuggled".parse().unwrap());
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers.insert("x-smuggled", "leak".parse().unwrap());
        sanitize_request_headers(&mut headers, true);
        assert!(headers.contains_key(header::CONNECTION));
        assert!(headers.contains_key(header::UPGRADE));
        assert!(!headers.contains_key("x-smuggled"));

        // The response direction strips them too.
        let mut response = HeaderMap::new();
        response.insert(header::CONNECTION, "close, X-Trace".parse().unwrap());
        response.insert("x-trace", "internal".parse().unwrap());
        sanitize_response_headers(&mut response, false);
        assert!(!response.contains_key("x-trace"));
        assert!(!response.contains_key(header::CONNECTION));
    }

    #[test]
    fn mitm_target_reuses_a_valid_authority() {
        let target = MitmTarget::new("example.com", 443).unwrap();
        assert_eq!(target.authority.as_str(), "example.com");
        let target = MitmTarget::new("example.com", 8443).unwrap();
        assert_eq!(target.authority.as_str(), "example.com:8443");
    }

    #[test]
    #[ignore = "micro benchmark"]
    fn bench_mitm_uri_build() {
        let target = MitmTarget::new("example.com", 443).unwrap();
        let path = PathAndQuery::from_static("/a/b?q=1");
        crate::bench::measure("mitm.uri.from_parts", 500_000, || {
            let _ = build_mitm_uri(&target, path.clone()).unwrap();
        });
        crate::bench::measure("mitm.uri.builder", 500_000, || {
            let _ = Uri::builder()
                .scheme(Scheme::HTTPS)
                .authority(target.authority.clone())
                .path_and_query(path.clone())
                .build()
                .unwrap();
        });
    }

    #[test]
    fn mitm_uri_from_parts_matches_the_builder() {
        let target = MitmTarget::new("example.com", 8443).unwrap();
        let path = PathAndQuery::from_static("/a/b?q=1");
        let built = build_mitm_uri(&target, path.clone()).unwrap();
        let expected = Uri::builder()
            .scheme(Scheme::HTTPS)
            .authority("example.com:8443")
            .path_and_query(path)
            .build()
            .unwrap();
        assert_eq!(built, expected);
        assert_eq!(built.scheme_str(), Some("https"));
        assert_eq!(
            built.authority().map(|value| value.as_str()),
            Some("example.com:8443")
        );
    }

    fn headers(upgrade: bool, connection: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if upgrade {
            headers.insert("upgrade", "websocket".parse().unwrap());
        }
        if let Some(connection) = connection {
            headers.insert("connection", connection.parse().unwrap());
        }
        headers
    }

    #[test]
    fn upgrade_detection_needs_the_exact_token() {
        assert!(is_upgrade(&headers(true, Some("Upgrade"))));
        assert!(is_upgrade(&headers(true, Some("upgrade"))));
        assert!(is_upgrade(&headers(true, Some("keep-alive, Upgrade"))));
        assert!(is_upgrade(&headers(true, Some("UPGRADE"))));
        // A missing Connection header still means "upgrade".
        assert!(is_upgrade(&headers(true, None)));
        // Not the upgrade token.
        assert!(!is_upgrade(&headers(true, Some("x-upgrade"))));
        assert!(!is_upgrade(&headers(true, Some("keep-alive"))));
        // No Upgrade header at all.
        assert!(!is_upgrade(&headers(false, Some("Upgrade"))));
    }

    #[test]
    fn authority_brackets_ipv6_literals() {
        assert_eq!(authority("2001:db8::1", 443, true), "[2001:db8::1]");
        assert_eq!(authority("2001:db8::1", 8443, true), "[2001:db8::1]:8443");
        assert_eq!(authority("example.com", 443, true), "example.com");
        assert_eq!(authority("example.com", 8443, true), "example.com:8443");
    }

    #[test]
    fn built_upstream_uri_matches_the_former_string_form() {
        for (host, port, https, path) in [
            ("example.com", 443u16, true, "/a/b?c=1"),
            ("example.com", 8080, false, "/"),
            ("example.com", 8443, true, "/index.html"),
            ("2001:db8::1", 443, true, "/"),
            ("2001:db8::1", 8443, true, "/x"),
        ] {
            let authority = authority(host, port, https);
            let expected: Uri = format!(
                "{}://{}{path}",
                if https { "https" } else { "http" },
                authority
            )
            .parse()
            .unwrap();
            let path_and_query = PathAndQuery::try_from(path).unwrap();
            let built = build_upstream_uri(host, port, https, &path_and_query).unwrap();
            assert_eq!(built, expected, "host={host} port={port}");
            assert_eq!(built.to_string(), expected.to_string());
        }
    }

    #[test]
    fn absolute_form_uri_is_reused_only_when_equivalent() {
        let req = Request::builder()
            .uri("https://example.com/path?q=1")
            .body(())
            .unwrap();
        let target = target_of(&req).unwrap();
        assert!(target.upstream_uri.is_some());
        assert!(target.path_and_query.is_none());
        assert!(
            target.normalized_host.is_none(),
            "a canonical absolute-form request keeps no owned host copy"
        );
        assert_eq!(host_of(&target), "example.com");

        let req = Request::builder()
            .uri("https://EXAMPLE.com/path")
            .body(())
            .unwrap();
        let target = target_of(&req).unwrap();
        assert_eq!(host_of(&target), "example.com");
        assert!(target.upstream_uri.is_none());
        assert_eq!(
            target.path_and_query.as_ref().map(|value| value.as_str()),
            Some("/path")
        );

        let req = Request::builder()
            .uri("https://example.com:443/path")
            .body(())
            .unwrap();
        let target = target_of(&req).unwrap();
        assert!(
            target.upstream_uri.is_none(),
            "an explicit default port is rebuilt to the previous authority"
        );
    }

    #[test]
    fn absolute_form_edge_cases() {
        // Userinfo must not be forwarded: the request is rebuilt without it.
        let req = Request::builder()
            .uri("http://user:pass@example.com/path")
            .body(())
            .unwrap();
        let target = target_of(&req).unwrap();
        assert!(target.upstream_uri.is_none(), "userinfo forces a rebuild");
        assert_eq!(host_of(&target), "example.com");

        // An IPv6 literal is a host, not a domain name: the brackets belong
        // to the authority.
        let req = Request::builder()
            .uri("http://[2001:db8::1]/path")
            .body(())
            .unwrap();
        let target = target_of(&req).unwrap();
        assert_eq!(host_of(&target), "2001:db8::1");

        // A URL without a path still has one.  The reusable form keeps it in
        // the URI, the rebuilt form in `path_and_query`.
        let req = Request::builder()
            .uri("http://example.com")
            .body(())
            .unwrap();
        let target = target_of(&req).unwrap();
        assert_eq!(host_of(&target), "example.com");
        let path = target
            .upstream_uri
            .as_ref()
            .map(|uri| uri.path().to_string())
            .or_else(|| {
                target
                    .path_and_query
                    .as_ref()
                    .map(|value| value.as_str().to_string())
            });
        assert_eq!(path.as_deref(), Some("/"));

        // A query without a path is impossible, but an empty path is.
        let req = Request::builder()
            .uri("http://example.com?a=1")
            .body(())
            .unwrap();
        let target = target_of(&req).unwrap();
        let path = target
            .upstream_uri
            .as_ref()
            .map(|uri| uri.path_and_query().map(|value| value.as_str().to_string()))
            .flatten()
            .or_else(|| {
                target
                    .path_and_query
                    .as_ref()
                    .map(|value| value.as_str().to_string())
            });
        // The URI keeps its empty path, the query is what matters.
        assert_eq!(path.as_deref(), Some("?a=1"));
    }

    #[test]
    fn odd_absolute_uris_do_not_panic() {
        for uri in [
            "http://",
            "http://[",
            "http://[::1",
            "http://host:",
            "http://host:0",
            "http://host:99999",
            "http://host:65536",
            "http://user@host",
            "http://host/%",
            "http://host/%zz",
            "http://host/a%2",
            "http://host/#frag",
            "http://host?a=%",
            "https://[::1]:8443/x",
            "http://[::1]:99999/x",
            "http://xn--bcher-kva.example/x",
            "http://HOST.example/x",
            "http://.example/x",
            "http://example../x",
        ] {
            let Ok(req) = Request::builder().uri(uri).body(()) else {
                continue;
            };
            // A malformed URI must be rejected, never panic.
            let _ = target_of(&req);
        }
    }

    #[test]
    fn origin_form_without_host_header_is_rejected() {
        let req = Request::builder().uri("/path").body(()).unwrap();
        assert!(target_of(&req).is_err());
    }

    #[test]
    fn origin_form_uses_host_header() {
        let req = Request::builder()
            .uri("/path")
            .header(http::header::HOST, "example.com:8080")
            .body(())
            .unwrap();
        let target = target_of(&req).unwrap();
        assert_eq!(host_of(&target), "example.com");
        assert_eq!(target.port, 8080);
        assert!(target.upstream_uri.is_none());
        assert_eq!(
            target.path_and_query.as_ref().map(|value| value.as_str()),
            Some("/path")
        );
    }

    /// The CPU cost of preparing one forwarded request, without the network.
    ///
    /// The header clone is part of the measurement: a real request brings its
    /// own header map, and the numbers only compare builds of the same
    /// measurement.
    #[test]
    #[ignore = "micro benchmark"]
    fn bench_request_preparation() {
        let request = Request::builder()
            .method("GET")
            .uri("https://example.com/assets/app.js?v=2")
            .header("user-agent", "Mozilla/5.0")
            .header("accept", "*/*")
            .header("accept-encoding", "gzip, deflate, br")
            .header("cookie", "session=0123456789abcdef")
            .header("referer", "https://example.com/")
            .header("connection", "keep-alive")
            .header("proxy-connection", "keep-alive")
            .body(())
            .unwrap();
        crate::bench::measure("proxy.request_prepare", 50_000, || {
            let target = target_of(&request).unwrap();
            let upgrade = is_upgrade(request.headers());
            let mut headers = request.headers().clone();
            sanitize_request_headers(&mut headers, upgrade);
            let path = target
                .path_and_query
                .clone()
                .unwrap_or_else(|| PathAndQuery::from_static("/"));
            let _ = build_upstream_uri(host_of(&target), target.port, target.https, &path).unwrap();
        });
    }
}
