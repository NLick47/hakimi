use std::sync::Arc;

use anyhow::{bail, Context, Result};
use http::{header, HeaderMap, Request, Response, StatusCode};
use http_body_util::BodyExt;
use http_body_util::Either;
use hyper::body::Incoming;
use hyper::upgrade::{self, OnUpgrade};
use hyper_util::rt::TokioIo;

use super::pool::{UpstreamBody, UpstreamResponseBody};
use super::{escape_html, full_body, ProxyBody, ProxyContext, COPY_BUFFER_SIZE};
use crate::domain::{is_ip_literal, normalize_hostname};
use crate::status::{AttemptRecord, DomainDiagnostics, State};
use crate::strategy::FailureReason;
use crate::util::parse_authority;

pub(crate) const ERROR_STYLE: &str = r#"<style>
:root{color-scheme:light dark}body{margin:0;background:#0f1115;color:#e7e9ee;font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:860px;margin:48px auto;padding:0 24px}h1{font-size:22px;margin:0 0 4px}p.code{color:#8b93a7;margin:0 0 20px}
pre{white-space:pre-wrap;word-break:break-word;background:#171a21;border:1px solid #262b36;border-radius:8px;padding:14px;overflow:auto}
table{border-collapse:collapse;width:100%;margin:12px 0}th,td{text-align:left;border-bottom:1px solid #262b36;padding:7px 8px;font-size:13px;vertical-align:top}
code{background:#171a21;padding:1px 5px;border-radius:4px}ul{padding-left:20px}.warn{color:#ffcc66}.bad{color:#ff7a7a}.good{color:#7ee2a8}
</style>"#;

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
        host,
        port,
        https,
        path_and_query,
    } = target;

    let upgrade_requested = is_upgrade(&req);
    let mut req = req;
    let client_upgrade = if upgrade_requested {
        Some(upgrade::on(&mut req))
    } else {
        None
    };

    match forward_with_pool(
        &ctx,
        req,
        &host,
        port,
        https,
        &path_and_query,
        upgrade_requested,
        client_upgrade,
    )
    .await
    {
        Ok(response) => response,
        Err(detail) => match_forward_error(&ctx, &host, port, https, detail),
    }
}

struct Target {
    host: String,
    port: u16,
    https: bool,
    path_and_query: String,
}

fn target_of(req: &Request<Incoming>) -> Result<Target> {
    let uri = req.uri();
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    if let (Some(scheme), Some(host)) = (uri.scheme_str(), uri.host()) {
        let https = match scheme {
            "https" => true,
            "http" => false,
            other => bail!("unsupported proxy scheme `{other}`"),
        };
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        return Ok(Target {
            host: normalize_hostname(host).unwrap_or_else(|_| host.to_ascii_lowercase()),
            port,
            https,
            path_and_query,
        });
    }
    let host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .context("request has neither absolute URI nor Host header")?;
    let (host, port) = parse_authority(host_header, 80).context("invalid Host header")?;
    Ok(Target {
        host,
        port,
        https: false,
        path_and_query,
    })
}

pub(crate) async fn handle_mitm_request(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext>,
    connect_host: String,
) -> Response<ProxyBody> {
    let target_host = request_host(&req).unwrap_or_default();
    let normalized = normalize_hostname(&target_host).unwrap_or(target_host);
    if normalized != connect_host {
        return super::error_response(
            StatusCode::BAD_REQUEST,
            "Unexpected host on MITM connection",
            &format!("CONNECT was for `{connect_host}` but the request targets `{normalized}`."),
        );
    }

    let port = req
        .uri()
        .port_u16()
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| parse_authority(value, 443))
                .map(|(_, port)| port)
        })
        .unwrap_or(443);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let upgrade_requested = is_upgrade(&req);
    let mut req = req;
    let client_upgrade = if upgrade_requested {
        Some(upgrade::on(&mut req))
    } else {
        None
    };

    match forward_with_pool(
        &ctx,
        req,
        &normalized,
        port,
        true,
        &path_and_query,
        upgrade_requested,
        client_upgrade,
    )
    .await
    {
        Ok(response) => response,
        Err(detail) => {
            if let Some(diagnostics) = ctx.status.get(&normalized) {
                if diagnostics.state == State::Failed {
                    return diagnostics_error_page(&normalized, &diagnostics, &ctx);
                }
            }
            if let Some(plan) = ctx.engine.cached_plan(&normalized, port, true) {
                return super::upstream_failure(&ctx, &plan, FailureReason::TlsError, detail);
            }
            super::error_response(
                StatusCode::BAD_GATEWAY,
                "Upstream request failed",
                &format!("{normalized}:{port}: {detail}"),
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

fn request_host(req: &Request<Incoming>) -> Option<String> {
    req.uri().host().map(ToOwned::to_owned).or_else(|| {
        req.headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| parse_authority(value, 443))
            .map(|(host, _)| host)
    })
}

fn is_upgrade(req: &Request<Incoming>) -> bool {
    req.headers().contains_key(header::UPGRADE)
        && req
            .headers()
            .get(header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(true)
}

#[allow(clippy::too_many_arguments)]
async fn forward_with_pool(
    ctx: &ProxyContext,
    req: Request<Incoming>,
    host: &str,
    port: u16,
    https: bool,
    path_and_query: &str,
    upgrade_requested: bool,
    client_upgrade: Option<OnUpgrade>,
) -> std::result::Result<Response<ProxyBody>, String> {
    let authority = authority(host, port, https);
    let absolute = format!(
        "{}://{}{}",
        if https { "https" } else { "http" },
        authority,
        path_and_query
    );
    let (mut parts, body) = req.into_parts();
    sanitize_request_headers(&mut parts.headers, upgrade_requested);
    parts.uri = absolute
        .parse()
        .map_err(|error| format!("building upstream URI for {host}:{port} failed: {error}"))?;
    parts.version = http::Version::HTTP_11;
    let upstream_request = Request::from_parts(parts, Either::Left(body) as UpstreamBody);

    let mut response = ctx
        .upstream
        .send(upstream_request, upgrade_requested)
        .await
        .map_err(|error| format!("upstream request to {host}:{port} failed: {error}"))?;

    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            let server_upgrade = upgrade::on(&mut response);
            tokio::spawn(async move {
                match (client_upgrade.await, server_upgrade.await) {
                    (Ok(client), Ok(server)) => {
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
                    (client, server) => tracing::debug!(
                        client_ok = client.is_ok(),
                        server_ok = server.is_ok(),
                        "websocket upgrade failed"
                    ),
                }
            });
        }
    }

    Ok(into_proxy_response(response, host))
}

fn into_proxy_response(
    mut response: Response<UpstreamResponseBody>,
    host: &str,
) -> Response<ProxyBody> {
    let upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    let status = response.status();
    sanitize_response_headers(response.headers_mut(), upgrade);
    let (parts, body) = response.into_parts();
    let host = host.to_string();
    let body = body
        .map_err(move |error| -> super::BoxError {
            tracing::warn!(host = %host, status = status.as_u16(), error = %error, "upstream response body failed");
            Box::new(error)
        })
        .boxed_unsync();
    Response::from_parts(parts, body)
}

fn sanitize_request_headers(headers: &mut HeaderMap, upgrade: bool) {
    for name in [
        header::CONNECTION,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
        header::HOST,
    ] {
        if !(upgrade && (name == header::CONNECTION || name == header::UPGRADE)) {
            headers.remove(name);
        }
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

fn sanitize_response_headers(headers: &mut HeaderMap, upgrade: bool) {
    for name in [
        header::CONNECTION,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        if !(upgrade && (name == header::CONNECTION || name == header::UPGRADE)) {
            headers.remove(name);
        }
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

fn authority(host: &str, port: u16, https: bool) -> String {
    let default = if https { 443 } else { 80 };
    if port == default {
        host.to_string()
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn diagnostics_error_page(
    domain: &str,
    diagnostics: &DomainDiagnostics,
    ctx: &ProxyContext,
) -> Response<ProxyBody> {
    let ca = ctx.ca.status();
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
