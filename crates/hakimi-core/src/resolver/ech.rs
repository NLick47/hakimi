use std::time::Instant;

use anyhow::{bail, Result};

use crate::cache::CachedEch;
use crate::dns::TYPE_HTTPS;
use crate::domain::normalize_hostname_cow;
use crate::strategy::DohSource;
use super::{EffectiveEndpoint, Resolver};
use super::lookup::{MIN_CACHE_TTL_SECS, STALE_REFRESH_BACKOFF, STALE_REFRESH_BACKOFF_MAX, STALE_WHILE_REVALIDATE_SECS};
use crate::util::now;



pub(super) const SHARED_ECH_DOMAIN: &str = "cloudflare-ech.com";
const SHARED_ECH_TTL_SECS: u32 = 30 * 60;

#[derive(Debug, Clone)]
pub struct EchOutcome {
    pub config: Vec<u8>,
    pub source: DohSource,
    pub endpoint: Option<String>,
    pub stale: bool,
}

impl Resolver {
    pub(super) fn fresh_ech(&self, domain: &str) -> Result<Option<EchOutcome>> {
        if let Some(cached) = self.cache.ech(domain, true) {
            return Ok(Some(EchOutcome {
                config: cached.ech_config,
                source: DohSource::Cache,
                endpoint: None,
                stale: false,
            }));
        }
        Ok(None)
    }

    /// An expired ECH config inside the stale-while-revalidate window. Serving
    /// it keeps an expired config off the handshake's critical path while DoH
    /// refreshes it in the background. `None` means no usable stale entry.
    pub(super) fn stale_ech(&self, domain: &str) -> Option<EchOutcome> {
        // An authoritative NODATA proves the config is gone; serving a stale
        // one here would defeat that, so fall through to the live query path
        // that already refuses to resurrect it.
        if self.cache.doh_negative_authoritative(domain, TYPE_HTTPS) {
            return None;
        }
        let cached = self.cache.ech(domain, false)?;
        let at = now();
        if cached.is_fresh(at) || cached.ttl_secs == 0 {
            return None;
        }
        let age = at.signed_duration_since(cached.fetched_at).num_seconds();
        if age > cached.ttl_secs as i64 + STALE_WHILE_REVALIDATE_SECS {
            return None;
        }
        Some(EchOutcome {
            config: cached.ech_config,
            source: DohSource::Cache,
            endpoint: None,
            stale: true,
        })
    }

    /// Refresh an expired ECH config off the handshake path. Shares the
    /// per-domain single-flight lock with foreground queries and a backoff map
    /// so a burst of stale hits cannot spawn a DoH attempt each.
    pub(super) fn spawn_ech_refresh(&self, domain: String, allow_shared: bool) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Ok(domain) = normalize_hostname_cow(&domain) else {
            return;
        };
        let domain = domain.into_owned();
        let key = format!("ech|{domain}");
        {
            let at = Instant::now();
            let mut refresh_after = self.stale_refresh_after.lock();
            if refresh_after.get(&key).is_some_and(|until| *until > at) {
                return;
            }
            if refresh_after.len() >= STALE_REFRESH_BACKOFF_MAX {
                refresh_after.retain(|_, until| *until > at);
                if refresh_after.len() >= STALE_REFRESH_BACKOFF_MAX {
                    refresh_after.clear();
                }
            }
            refresh_after.insert(key.clone(), at + STALE_REFRESH_BACKOFF);
        }
        let resolver = self.clone();
        handle.spawn(async move {
            let Some(_guard) = resolver.try_query_lock(key) else {
                return;
            };
            if resolver.fresh_ech(&domain).ok().flatten().is_some() {
                return;
            }
            if let Err(error) = resolver.fetch_ech_live(&domain, allow_shared).await {
                tracing::debug!(
                    domain = %domain,
                    error = %error,
                    "background ECH refresh failed; keeping the stale config"
                );
            }
        });
    }


    /// Fetch the ECHConfigList from the domain's HTTPS RR. A fresh cached config wins; on a
    /// live failure an expired config is used as a last resort.
    ///
    /// When `allow_shared` is set and the domain publishes no ECHConfig, fall back to
    /// Cloudflare's shared `cloudflare-ech.com` config (the approach used by the Piku
    /// project for Pixiv). This only works for Cloudflare-fronted hostnames.
    pub async fn ech_config(&self, domain: &str, allow_shared: bool) -> Result<EchOutcome> {
        let domain = normalize_hostname_cow(domain)?;
        if let Some(outcome) = self.fresh_ech(&domain)? {
            return Ok(outcome);
        }
        // An expired-but-usable config is served immediately while DoH
        // refreshes it in the background. This keeps an expiry off the
        // handshake's critical path instead of blocking on a live query.
        if let Some(outcome) = self.stale_ech(&domain) {
            self.spawn_ech_refresh(domain.to_string(), allow_shared);
            return Ok(outcome);
        }
        let _guard = self.query_lock(format!("ech|{domain}")).await;
        if let Some(outcome) = self.fresh_ech(&domain)? {
            return Ok(outcome);
        }
        self.fetch_ech_live(&domain, allow_shared).await
    }

    async fn fetch_ech_live(&self, domain: &str, allow_shared: bool) -> Result<EchOutcome> {
        let mut live_error: Option<anyhow::Error> = None;
        let mut live_failed = false;
        // A remembered authoritative NODATA proves the HTTPS RR and its ECH
        // config are gone. Skipping the live query is fine; resurrecting the
        // stale config is not. A mere failure entry must keep falling through
        // to query_one_type so the stale config stays available as a last
        // resort.
        if self.cache.doh_negative_authoritative(&domain, TYPE_HTTPS) {
            bail!("HTTPS RR for `{domain}` does not contain an ECH config");
        }
        match self.query_one_type(&domain, TYPE_HTTPS).await {
            Ok(query) => {
                // A successful NODATA answer is authoritative when every
                // endpoint agreed. If another endpoint failed or was cut off
                // before answering, keep the stale config as a last resort,
                // matching the documented policy.
                live_failed |= !query.authoritative;
                if let Some(ech) = query.answer.ech {
                    self.cache.put_ech(CachedEch {
                        domain: domain.to_string(),
                        ech_config: ech.clone(),
                        // Same floor as the address cache: a zero-TTL HTTPS
                        // RR must not turn every handshake into a live race
                        // (RFC 8767).
                        ttl_secs: query.answer.ttl.max(MIN_CACHE_TTL_SECS),
                        fetched_at: now(),
                    });
                    return Ok(EchOutcome {
                        config: ech,
                        source: query.source,
                        endpoint: Some(query.endpoint),
                        stale: false,
                    });
                }
            }
            Err(error) => {
                live_failed = true;
                live_error = Some(error);
            }
        }

        if allow_shared && domain != SHARED_ECH_DOMAIN {
            match self.shared_cloudflare_ech().await {
                Ok(outcome) => {
                    // Cache the shared config under the requesting host too, so subsequent
                    // decisions for this host skip the (always empty) HTTPS RR query.
                    self.cache.put_ech(CachedEch {
                        domain: domain.to_string(),
                        ech_config: outcome.config.clone(),
                        ttl_secs: SHARED_ECH_TTL_SECS,
                        fetched_at: now(),
                    });
                    return Ok(outcome);
                }
                Err(error) => {
                    tracing::debug!(
                        domain = %domain,
                        error = %error,
                        "shared Cloudflare ECH config is unavailable"
                    );
                }
            }
        }

        // Do not override an authoritative live NODATA answer with a stale
        // config. The domain may have removed ECH; offering the old config can
        // turn every connection into a handshake failure. Stale is only a
        // last resort when the live query (or one endpoint in the pair) failed.
        if live_failed {
            if let Some(cached) = self.cache.ech(&domain, false) {
                let config = cached.ech_config;
                tracing::warn!(
                    domain = %domain,
                    error = ?live_error,
                    "using stale ECH config after DoH failure"
                );
                return Ok(EchOutcome {
                    config,
                    source: DohSource::Cache,
                    endpoint: None,
                    stale: true,
                });
            }
        }

        if let Some(error) = live_error {
            return Err(error);
        }
        bail!("HTTPS RR for `{domain}` does not contain an ECH config")
    }

    /// Cloudflare's shared ECH config used for `www.pixiv.net` and other CF-fronted sites.
    /// Piku pins AliDNS; we first try the configured DoH pool (CleanBrowsing serves it too)
    /// and then AliDNS as a fallback.
    pub(super) async fn shared_cloudflare_ech(&self) -> Result<EchOutcome> {
        // Join the resolver's per-key single-flight instead of using a
        // second, ad-hoc global mutex. `ech_config("cloudflare-ech.com")`
        // queries this very name under `ech|{SHARED_ECH_DOMAIN}`; the two
        // paths guarded the same query through unrelated locks, so they
        // could race duplicate live lookups for it. Waiter semantics are
        // unchanged: the first caller queries, everyone else joins the same
        // queue and re-checks the cache afterwards.
        let _guard = self
            .query_lock(format!("ech|{}", SHARED_ECH_DOMAIN))
            .await;
        if let Some(cached) = self.cache.ech(SHARED_ECH_DOMAIN, true) {
            let config = cached.ech_config;
            return Ok(EchOutcome {
                config,
                source: DohSource::Cache,
                endpoint: None,
                stale: false,
            });
        }

        let mut live_failed = false;
        match self.query_one_type(SHARED_ECH_DOMAIN, TYPE_HTTPS).await {
            Ok(query) => {
                live_failed |= !query.authoritative;
                if let Some(ech) = query.answer.ech {
                    self.cache.put_ech(CachedEch {
                        domain: SHARED_ECH_DOMAIN.to_string(),
                        ech_config: ech.clone(),
                        ttl_secs: query.answer.ttl.max(SHARED_ECH_TTL_SECS),
                        fetched_at: now(),
                    });
                    tracing::info!(
                        endpoint = %query.endpoint,
                        "using shared Cloudflare ECH config"
                    );
                    return Ok(EchOutcome {
                        config: ech,
                        source: query.source,
                        endpoint: Some(query.endpoint),
                        stale: false,
                    });
                }
            }
            Err(_) => live_failed = true,
        }

        let alidns = EffectiveEndpoint {
            name: "AliDNS".to_string(),
            url: "https://dns.alidns.com/dns-query".to_string(),
            bootstrap_ip: None,
            source: DohSource::Custom,
        };
        match self
            .query_endpoint(&alidns, SHARED_ECH_DOMAIN, TYPE_HTTPS)
            .await
        {
            Ok(answer) => {
                if let Some(ech) = answer.ech {
                    self.cache.put_ech(CachedEch {
                        domain: SHARED_ECH_DOMAIN.to_string(),
                        ech_config: ech.clone(),
                        ttl_secs: answer.ttl.max(SHARED_ECH_TTL_SECS),
                        fetched_at: now(),
                    });
                    tracing::info!("using shared Cloudflare ECH config from AliDNS");
                    return Ok(EchOutcome {
                        config: ech,
                        source: DohSource::Custom,
                        endpoint: Some("AliDNS".to_string()),
                        stale: false,
                    });
                }
            }
            Err(_) => live_failed = true,
        }

        if live_failed {
            if let Some(cached) = self.cache.ech(SHARED_ECH_DOMAIN, false) {
                return Ok(EchOutcome {
                    config: cached.ech_config,
                    source: DohSource::Cache,
                    endpoint: None,
                    stale: true,
                });
            }
        }

        bail!("unable to fetch the shared Cloudflare ECH config")
    }

}
