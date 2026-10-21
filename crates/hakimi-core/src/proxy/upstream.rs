use std::borrow::Cow;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use http::uri::{Authority, PathAndQuery, Scheme, Uri};
use http::{header, HeaderMap, HeaderName, Request, Response, StatusCode};
use http_body_util::BodyExt;
use http_body_util::Either;
use hyper::body::Incoming;
use hyper::upgrade::{self, OnUpgrade};
use hyper_util::rt::TokioIo;

use super::pool::{UpstreamBody, UpstreamResponseBody};
use super::{escape_html, full_body, ProxyBody, ProxyContext, COPY_BUFFER_SIZE};
use crate::domain::{is_ip_literal, normalize_hostname, normalize_hostname_cow};
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
            let path_and_query =
                path_and_query.unwrap_or_else(|| PathAndQuery::from_static("/"));
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
    let upstream_uri = match Uri::builder()
        .scheme(Scheme::HTTPS)
        .authority(target.authority.clone())
        .path_and_query(path_and_query)
        .build()
    {
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

/// Host portion of a `Host` header, borrowing the original string.
fn host_header_name(value: &str) -> &str {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => value,
    }
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
    let (mut parts, body) = req.into_parts();
    sanitize_request_headers(&mut parts.headers, upgrade_requested);
    parts.uri = upstream_uri;
    // Keep a cheap `Uri` handle for the response body's error logger. Cloning the
    // parsed URI shares its `Bytes`; allocating a fresh host String per response is
    // not necessary on this hot path.
    let response_uri = parts.uri.clone();
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

    Ok(into_proxy_response(response, response_uri))
}

fn into_proxy_response(
    mut response: Response<UpstreamResponseBody>,
    uri: http::Uri,
) -> Response<ProxyBody> {
    let upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    let status = response.status();
    sanitize_response_headers(response.headers_mut(), upgrade);
    let (parts, body) = response.into_parts();
    let body = body
        .map_err(move |error| -> super::BoxError {
            tracing::warn!(
                host = uri.host().unwrap_or(""),
                status = status.as_u16(),
                error = %error,
                "upstream response body failed"
            );
            Box::new(error)
        })
        .boxed_unsync();
    Response::from_parts(parts, body)
}

/// `HeaderName::from_static` does not allocate, while removing a header by
/// `&str` builds a new name on every call.
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

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
    headers.remove(&KEEP_ALIVE);
    headers.remove(&PROXY_CONNECTION);
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
    headers.remove(&KEEP_ALIVE);
    headers.remove(&PROXY_CONNECTION);
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

#[cfg(test)]
mod tests {
    use super::{
        authority, build_upstream_uri, host_header_name, is_upgrade, same_host, target_host,
        target_of, MitmTarget, Target,
    };
    use http::uri::PathAndQuery;
    use http::{HeaderMap, Request, Uri};

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
    }

    #[test]
    fn mitm_target_reuses_a_valid_authority() {
        let target = MitmTarget::new("example.com", 443).unwrap();
        assert_eq!(target.authority.as_str(), "example.com");
        let target = MitmTarget::new("example.com", 8443).unwrap();
        assert_eq!(target.authority.as_str(), "example.com:8443");
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
    fn authority_brackets_ipv6_literals() {        assert_eq!(authority("2001:db8::1", 443, true), "[2001:db8::1]");
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
        let req = Request::builder().uri("http://example.com").body(()).unwrap();
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
}
