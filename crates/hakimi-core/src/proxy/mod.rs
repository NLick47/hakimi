mod connect;
mod pool;
mod response;
mod upstream;

#[cfg(test)]
mod tests;

pub(crate) use connect::{clear_dns_cache, upstream_failure};
pub use pool::UpstreamPool;
pub(crate) use response::{error_response, escape_html, full_body, json_response, text_response};

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::ca::CertificateAuthority;
use crate::cache::CacheManager;
use crate::catalog::CatalogManager;
use crate::config::ConfigManager;
use crate::decision::DecisionEngine;
use crate::ip_tester::TlsContext;
use crate::resolver::Resolver;
use crate::status::StatusStore;
use crate::util::host_header_name;

use self::connect::handle_connect;
use self::pool::UpstreamResponseBody;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Response body returned by the proxy.
///
/// Keeping the three shapes in an enum avoids the per-response boxed body that
/// the previous `UnsyncBoxBody` alias needed. Upstream bodies still stream
/// directly and keep their per-host semaphore permit alive.
pub struct ProxyBody {
    kind: ProxyBodyKind,
}

enum ProxyBodyKind {
    Upstream {
        body: UpstreamResponseBody,
        uri: http::Uri,
        status: StatusCode,
    },
    Full(Full<Bytes>),
    Empty,
}

impl ProxyBody {
    pub(crate) fn empty() -> Self {
        Self {
            kind: ProxyBodyKind::Empty,
        }
    }

    pub(crate) fn full(data: impl Into<Bytes>) -> Self {
        Self {
            kind: ProxyBodyKind::Full(Full::new(data.into())),
        }
    }

    pub(crate) fn upstream(body: UpstreamResponseBody, uri: http::Uri, status: StatusCode) -> Self {
        Self {
            kind: ProxyBodyKind::Upstream { body, uri, status },
        }
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut self.get_mut().kind {
            ProxyBodyKind::Upstream { body, uri, status } => match Pin::new(body).poll_frame(cx) {
                Poll::Ready(Some(Err(error))) => {
                    tracing::warn!(
                        host = uri.host().unwrap_or(""),
                        status = status.as_u16(),
                        error = %error,
                        "upstream response body failed"
                    );
                    Poll::Ready(Some(Err(Box::new(error))))
                }
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            ProxyBodyKind::Full(body) => match Pin::new(body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
                Poll::Ready(Some(Err(never))) => match never {},
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            ProxyBodyKind::Empty => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.kind {
            ProxyBodyKind::Upstream { body, .. } => body.is_end_stream(),
            ProxyBodyKind::Full(body) => body.is_end_stream(),
            ProxyBodyKind::Empty => true,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.kind {
            ProxyBodyKind::Upstream { body, .. } => body.size_hint(),
            ProxyBodyKind::Full(body) => body.size_hint(),
            ProxyBodyKind::Empty => SizeHint::with_exact(0),
        }
    }
}

/// Per-direction buffer for upgraded/TCP tunnels. 64 KiB moves large responses
/// with far fewer read/write syscalls than tokio's 8 KiB default while keeping
/// per-connection memory reasonable.
pub(crate) const COPY_BUFFER_SIZE: usize = 64 * 1024;

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
    /// The status snapshot. The flag asks for every known domain instead of
    /// the ones the groups show; the polled view is the small one.
    pub status_json: Arc<dyn Fn(bool) -> serde_json::Value + Send + Sync>,
    /// Raised by `/hakimi/stop`. Only the owner of the runtime knows what a
    /// shutdown involves, so the endpoint signals instead of shutting down.
    pub on_stop: Arc<dyn Fn() + Send + Sync>,
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
        status_json: Arc<dyn Fn(bool) -> serde_json::Value + Send + Sync>,
        on_stop: Arc<dyn Fn() + Send + Sync>,
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
            on_stop,
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
        // Use one config snapshot for both the rules and the fallback address;
        // `proxy_addr()` would otherwise take the config lock a second time.
        let config = self.config.snapshot();
        let addr = self
            .proxy_addr
            .get()
            .copied()
            .unwrap_or_else(|| SocketAddr::new(config.proxy.bind, config.proxy.port));
        crate::pac::generate(&config, addr, self.status.paused())
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
                            // A browser or tunnel client can disappear without a
                            // FIN (Wi-Fi drop, killed app). TCP keepalive lets the
                            // tunnel task release the upstream socket instead of
                            // waiting for the OS default, which can be hours.
                            crate::util::apply_tcp_keepalive(&stream);
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
        // Hyper's default 30 s header-read timeout is only armed when a timer
        // is installed. Without it a local slowloris client can pin a task and
        // an accepted socket forever before ever sending a complete request.
        .timer(TokioTimer::new())
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .context("serving proxy HTTP/1.1 connection")
}

async fn handle_request(mut req: Request<Incoming>, ctx: Arc<ProxyContext>) -> Response<ProxyBody> {
    // Local endpoints are a tiny minority of proxy traffic, but
    // `is_local_request` has to inspect the Host header (and an IP literal).
    // Match the path first so ordinary traffic never pays for that check.
    let local_path = {
        let path = req.uri().path();
        path == "/proxy.pac" || path.starts_with("/hakimi/")
    };
    if local_path && is_local_request(&req, &ctx) {
        match req.uri().path() {
            "/proxy.pac" => {
                return text_response(
                    StatusCode::OK,
                    "application/x-ns-proxy-autoconfig",
                    ctx.pac_script(),
                );
            }
            "/hakimi/status" => {
                // `?all=1` returns every known domain; the plain view only
                // carries the domains the groups show.
                let every = req
                    .uri()
                    .query()
                    .is_some_and(|query| query.split('&').any(|part| part == "all=1"));
                let value = (ctx.status_json)(every);
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
            "/hakimi/stop" if req.method() == Method::POST => {
                // A custom header forces a CORS preflight, so a page in a
                // browser cannot stop the proxy with a drive-by POST.
                if req
                    .headers()
                    .get("x-hakimi-control")
                    .and_then(|value| value.to_str().ok())
                    != Some("1")
                {
                    return text_response(
                        StatusCode::UNAUTHORIZED,
                        "text/plain; charset=utf-8",
                        "missing x-hakimi-control header",
                    );
                }
                (ctx.on_stop)();
                return json_response(serde_json::json!({ "stopping": true }));
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
            // Borrow the host: this runs on every request of a MITM tunnel,
            // and the name is only compared, never kept.
            let Some(parsed) = req
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(host_header_name)
            else {
                return false;
            };
            owned = parsed;
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
