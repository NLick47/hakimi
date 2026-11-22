use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::config::{AppConfig, DohEndpoint};
use crate::strategy::DohSource;
use super::Resolver;
use crate::util::redact_url;



/// reading, not after `Response::bytes()` has already buffered an unbounded
/// chunked response from a broken or hostile DoH endpoint.
pub(super) const MAX_DOH_RESPONSE_BYTES: usize = 65_535;

#[derive(Debug, Clone)]
pub struct EffectiveEndpoint {
    pub name: String,
    pub url: String,
    pub bootstrap_ip: Option<IpAddr>,
    pub source: DohSource,
}

/// Keep a bounded number of reqwest clients, and never evict the built-in
/// primary/fallback while a custom or catalog endpoint is available to drop.
/// The old policy cleared the whole map when a fifth endpoint appeared, which
/// threw away the HTTP/2 connection and TLS session of the hot endpoints on
/// every health check.
pub(super) const MAX_DOH_CLIENTS: usize = 16;

/// How long a DoH connection stays in the pool while it is idle.
///
/// reqwest's default is 90s, which is shorter than the gap between two
/// resolution bursts in normal browsing. The DoH connection is reused for
/// every query to that endpoint, so dropping it costs a TCP+TLS handshake
/// (two round trips and a certificate verification) on the critical path of
/// the next cold domain.
const DOH_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Idle connections kept per DoH endpoint.
const DOH_POOL_MAX_IDLE: usize = 4;

/// HTTP/2 keep-alive ping for the DoH connection.
///
/// The upstream pool already pings its HTTP/2 connections; without the same
/// treatment a DoH connection can be reaped by the middlebox between two
/// bursts and the next query fails on a socket that looked healthy.
const DOH_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const DOH_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct CachedDohClient {
    pub(super) client: reqwest::Client,
    pub(super) source: DohSource,
    pub(super) created_at: Instant,
}

pub(super) async fn read_limited_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_DOH_RESPONSE_BYTES as u64)
    {
        bail!("DoH response is larger than {MAX_DOH_RESPONSE_BYTES} bytes");
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(MAX_DOH_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| anyhow::anyhow!("reading DoH response: {}", error.without_url()))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_DOH_RESPONSE_BYTES {
            bail!("DoH response is larger than {MAX_DOH_RESPONSE_BYTES} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl Resolver {
    /// The configured endpoints in race order.
    ///
    /// This list only changes when the config or the remote DoH catalog
    /// changes, so a DoH cache miss reuses the previous allocation instead of
    /// re-cloning every URL and custom endpoint.
    pub fn effective_endpoints(&self) -> Arc<Vec<EffectiveEndpoint>> {
        let (config, config_revision) = self.config.snapshot_with_revision();
        // Read the catalog revision before taking the catalog snapshot: a
        // concurrent refresh can then only cache a newer list under an older
        // revision, which the next call refreshes again. The reverse order
        // could pin stale endpoints under the new revision indefinitely.
        let catalog_revision = self.catalogs.revision();
        if let Some((cached_config, cached_catalog, endpoints)) =
            self.endpoint_cache.read().as_ref()
        {
            if *cached_config == config_revision && *cached_catalog == catalog_revision {
                return endpoints.clone();
            }
        }
        let endpoints = Arc::new(Self::build_endpoints(
            &config,
            self.catalogs.remote_doh_endpoints(),
        ));
        *self.endpoint_cache.write() = Some((config_revision, catalog_revision, endpoints.clone()));
        endpoints
    }

    pub(super) fn build_endpoints(config: &AppConfig, remote: Vec<DohEndpoint>) -> Vec<EffectiveEndpoint> {
        let mut endpoints = Vec::new();
        let push = |endpoint: DohEndpoint, source: DohSource, out: &mut Vec<EffectiveEndpoint>| {
            let url = endpoint.url.trim().to_string();
            if url.is_empty() {
                return;
            }
            if let Some(existing) = out.iter_mut().find(|existing| existing.url == url) {
                // A user custom entry that reuses a built-in URL may override its
                // bootstrap/name, but the built-in keeps its primary/fallback position.
                if source == DohSource::Custom && existing.source != DohSource::Custom {
                    existing.bootstrap_ip = endpoint.bootstrap_ip;
                    existing.name = endpoint.display_name();
                }
                return;
            }
            out.push(EffectiveEndpoint {
                name: endpoint.display_name(),
                url,
                bootstrap_ip: endpoint.bootstrap_ip,
                source,
            });
        };
        push(
            DohEndpoint {
                name: "primary".into(),
                url: config.doh.primary.clone(),
                bootstrap_ip: None,
                enabled: true,
            },
            DohSource::Primary,
            &mut endpoints,
        );
        push(
            DohEndpoint {
                name: "fallback".into(),
                url: config.doh.fallback.clone(),
                bootstrap_ip: None,
                enabled: true,
            },
            DohSource::Fallback,
            &mut endpoints,
        );
        for endpoint in config.doh.custom.iter().filter(|endpoint| endpoint.enabled) {
            push(endpoint.clone(), DohSource::Custom, &mut endpoints);
        }
        for endpoint in remote {
            push(endpoint, DohSource::Catalog, &mut endpoints);
        }
        endpoints
    }


    pub(super) fn client_for(
        &self,
        endpoint: &EffectiveEndpoint,
        timeout: Duration,
    ) -> Result<reqwest::Client> {
        let key = format!(
            "{}|{}|{}",
            endpoint.url,
            endpoint
                .bootstrap_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            timeout.as_secs()
        );
        if let Some(entry) = self.clients.read().get(&key) {
            return Ok(entry.client.clone());
        }
        crate::util::install_crypto_provider();
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .tcp_nodelay(true)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            // DoH must bypass the OS proxy: otherwise it could recurse into our own listener.
            .no_proxy()
            // Keep the pooled connection between resolution bursts. reqwest
            // defaults to 90s, and a proxy resolves a handful of names every
            // few minutes: with the default every burst started from an empty
            // pool and paid one or two fresh TCP+TLS handshakes to the DoH
            // endpoint before the first query could even be sent. That is two
            // round trips plus a WebPKI verification on the critical path of
            // the first byte.
            .pool_idle_timeout(DOH_POOL_IDLE_TIMEOUT)
            .pool_max_idle_per_host(DOH_POOL_MAX_IDLE)
            // A half-open HTTP/2 connection can sit in the pool until the
            // next query fails on it. The upstream client already solves this
            // with a keep-alive ping; the DoH client needs the same.
            .http2_keep_alive_interval(DOH_KEEPALIVE_INTERVAL)
            .http2_keep_alive_timeout(DOH_KEEPALIVE_TIMEOUT)
            .http2_keep_alive_while_idle(true)
            .user_agent(format!("hakimi/{}", env!("CARGO_PKG_VERSION")));
        // Test hook: extra roots for a local harness (off by default).
        for root in crate::hooks::extra_roots() {
            if let Ok(certificate) = reqwest::Certificate::from_der(root.as_ref()) {
                builder = builder.add_root_certificate(certificate);
            }
        }
        if let Some(ip) = endpoint.bootstrap_ip {
            let parsed = url::Url::parse(&endpoint.url)
                .with_context(|| format!("invalid DoH URL {}", redact_url(&endpoint.url)))?;
            let host = parsed
                .host_str()
                .context("DoH URL has no host for bootstrap")?;
            let port = parsed.port_or_known_default().unwrap_or(443);
            builder = builder.resolve(host, SocketAddr::new(ip, port));
        }
        let client = builder.build().context("building DoH client")?;
        let mut clients = self.clients.write();
        if !clients.contains_key(&key) && clients.len() >= MAX_DOH_CLIENTS {
            // Prefer evicting a catalog/custom client over the primary or
            // fallback, whose connections are used on every cache miss.
            let evict = clients
                .iter()
                .filter(|(_, entry)| {
                    !matches!(
                        entry.source,
                        DohSource::Primary | DohSource::Fallback
                    )
                })
                .min_by_key(|(_, entry)| entry.created_at)
                .or_else(|| clients.iter().min_by_key(|(_, entry)| entry.created_at))
                .map(|(key, _)| key.clone());
            if let Some(key) = evict {
                clients.remove(&key);
            }
        }
        clients.insert(
            key,
            CachedDohClient {
                client: client.clone(),
                source: endpoint.source,
                created_at: Instant::now(),
            },
        );
        Ok(client)
    }

}
