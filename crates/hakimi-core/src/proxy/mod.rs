mod pool;
mod upstream;

pub use pool::UpstreamPool;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
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
use crate::decision::{ConnectPlan, DecisionEngine, Route};
use crate::domain::is_ip_literal;
use crate::ip_tester::TlsContext;
use crate::resolver::Resolver;
use crate::status::StatusStore;
use crate::strategy::{Strategy, TlsMode};
use crate::util::parse_authority;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
            _ => {}
        }
    }
    if req.method() == Method::CONNECT {
        return handle_connect(&mut req, ctx).await;
    }
    upstream::handle_forward(req, ctx).await
}

fn is_local_request(req: &Request<Incoming>, ctx: &ProxyContext) -> bool {
    let host = req.uri().host().map(ToOwned::to_owned).or_else(|| {
        req.headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| parse_authority(value, 80))
            .map(|(host, _)| host)
    });
    let Some(host) = host else {
        return false;
    };
    let host = host.trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == ctx.proxy_addr().ip().to_string()
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
    let Some(group) = config.group(&group_id).cloned() else {
        return tunnel_to_host(req, &host, port).await;
    };
    if !group.enabled || ctx.status.paused() {
        return tunnel_to_host(req, &host, port).await;
    }

    // Fast path: a previously successful direct route turns CONNECT into a raw TCP tunnel,
    // with no probe, no local certificate and no extra TLS handshake.
    let mut stale_plan = None;
    if let Some(plan) = ctx.engine.cached_plan(&host, port, true) {
        if plan.mode == TlsMode::Direct {
            let started = std::time::Instant::now();
            match connect_tcp_upstream(plan.ip, plan.port).await {
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
    loop {
        let Some(plan) = cursor.next_plan().await else {
            let diagnostics = cursor.outcome().map(|outcome| outcome.diagnostics.clone());
            return match diagnostics {
                Some(diagnostics) => upstream::diagnostics_error_page(host, &diagnostics, ctx),
                None => error_response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream connection failed",
                    &format!("no candidate route succeeded for {host}:{port}"),
                ),
            };
        };
        if plan.mode != TlsMode::Direct {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "Direct routing failed",
                &format!(
                    "the direct strategy was exhausted for {host}:{port}; install the local CA trust                      anchor to enable ECH/fake-SNI through the MITM proxy"
                ),
            );
        }
        let started = std::time::Instant::now();
        match connect_tcp_upstream(plan.ip, plan.port).await {
            Ok(stream) => {
                let latency = started.elapsed().as_millis() as u64;
                let _ = cursor.note_success(&plan, latency);
                return tunnel_connect(req, stream);
            }
            Err((reason, detail)) => cursor.note_failure(&plan, reason, detail),
        }
    }
}

async fn connect_tcp_upstream(
    ip: std::net::IpAddr,
    port: u16,
) -> Result<TcpStream, (crate::strategy::FailureReason, String)> {
    let address = SocketAddr::new(ip, port);
    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            Ok(stream)
        }
        Ok(Err(error)) => Err((
            crate::strategy::FailureReason::TcpRefused,
            format!("connecting to {address} failed: {error}"),
        )),
        Err(_) => Err((
            crate::strategy::FailureReason::TcpTimeout,
            format!("connecting to {address} timed out"),
        )),
    }
}

async fn tunnel_to_host(req: &mut Request<Incoming>, host: &str, port: u16) -> Response<ProxyBody> {
    let upstream =
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream connection failed",
                    &format!("{host}:{port}: {error}"),
                );
            }
            Err(_) => {
                return error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Upstream connection timed out",
                    &format!("{host}:{port}"),
                );
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
                if let Err(error) =
                    tokio::io::copy_bidirectional(&mut upgraded, &mut upstream).await
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

    #[test]
    fn html_escape() {
        assert_eq!(escape_html("<a&b>"), "&lt;a&amp;b&gt;");
    }
}
