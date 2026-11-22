use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use serde::Serialize;

use crate::dns::TYPE_A;
use crate::strategy::DohSource;
use super::{EffectiveEndpoint, Resolver};
use crate::util::{now, redact_url};



/// Consecutive failures before an endpoint is skipped for a while. One failure
/// already triggers the hedge, but a single bad round trip must not demote the
/// endpoint the user configured first.
const ENDPOINT_FAILURE_THRESHOLD: u32 = 3;
const ENDPOINT_COOLDOWN_BASE: Duration = Duration::from_secs(30);
const ENDPOINT_COOLDOWN_MAX: Duration = Duration::from_secs(10 * 60);

/// Upper bound for one health probe, regardless of how the client timeouts are
/// configured. A probe that outlives this is recorded as a failure: without the
/// bound, one hung endpoint would delay the whole `join_all` pass — and, at
/// boot, the warm-up behind it — by up to the configured `timeoutSecs` (60 s).
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DohHealth {
    pub name: String,
    pub url: String,
    pub source: DohSource,
    pub healthy: bool,
    pub latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub checked_at: chrono::DateTime<chrono::Utc>,
    /// True when this entry came from a real probe or query. A synthesized
    /// entry (the endpoint is configured but nothing has observed it yet)
    /// shows as "未检测" instead of pretending the endpoint is broken.
    pub observed: bool,
    /// Consecutive failures. Drives the endpoint order; reset by a success.
    #[serde(skip)]
    pub(super) failures: u32,
    /// While this is in the future the endpoint is skipped by new queries.
    /// Kept out of the serialized snapshot: the UI shows the last observation,
    /// not the policy timer.
    #[serde(skip)]
    pub(super) cooldown_until: Option<Instant>,
}

impl DohHealth {
    pub(super) fn cooling(&self, now: Instant) -> bool {
        self.cooldown_until.is_some_and(|until| until > now)
    }

    fn new(
        endpoint: &EffectiveEndpoint,
        healthy: bool,
        latency_ms: Option<u64>,
        last_error: Option<String>,
        failures: u32,
        cooldown_until: Option<Instant>,
    ) -> Self {
        Self {
            name: endpoint.name.clone(),
            url: endpoint.url.clone(),
            source: endpoint.source,
            healthy,
            latency_ms,
            last_error,
            checked_at: now(),
            observed: true,
            failures,
            cooldown_until,
        }
    }
}

/// Per-endpoint counters since process start. Atomics so a query outcome can
/// be recorded without holding any lock the query path contends on.
#[derive(Debug, Default)]
pub(super) struct DohEndpointStats {
    answered: AtomicU64,
    failed: AtomicU64,
    cooldowns: AtomicU64,
}

/// Serializable per-endpoint counters for the status JSON and the diagnostics
/// page. Not surfaced by `doh health`: the CLI runs its own short-lived
/// process, so its counters would always read zero.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DohStatsSnapshot {
    pub url: String,
    pub answered: u64,
    pub failed: u64,
    pub cooldowns: u64,
}

impl Resolver {
    pub fn health_snapshot(&self) -> Vec<DohHealth> {
        // Health entries are keyed by endpoint URL and outlive a config edit.
        // Drop entries for endpoints that are no longer configured so status
        // and the UI do not keep showing a removed primary/fallback/custom DoH.
        let endpoints = self.effective_endpoints();
        let live: HashSet<&str> = endpoints
            .iter()
            .map(|endpoint| endpoint.url.as_str())
            .collect();
        let mut health = self.health.write();
        health.retain(|url, _| live.contains(url.as_str()));
        let mut values: Vec<DohHealth> = health.values().cloned().collect();
        drop(health);
        // Every configured endpoint gets an entry: one without an observation
        // is an explicit "未检测", not a missing row. Whatever writes health
        // entries out of order then cannot bring the UI back to a stuck
        // "checking" state — the display invariant holds by construction.
        let observed: HashSet<String> = values.iter().map(|entry| entry.url.clone()).collect();
        for endpoint in endpoints.iter() {
            if !observed.contains(endpoint.url.as_str()) {
                values.push(DohHealth {
                    name: endpoint.name.clone(),
                    url: endpoint.url.clone(),
                    source: endpoint.source,
                    healthy: false,
                    latency_ms: None,
                    last_error: None,
                    checked_at: now(),
                    observed: false,
                    failures: 0,
                    cooldown_until: None,
                });
            }
        }
        values.sort_by(|a, b| a.url.cmp(&b.url));
        values
    }

    /// Per-endpoint counters, sorted by URL. Entries for endpoints that are no
    /// longer configured are dropped here, mirroring [`Self::health_snapshot`]:
    /// without the prune, a config that churns endpoint URLs would grow the
    /// counter map without bound.
    pub fn stats_snapshot(&self) -> Vec<DohStatsSnapshot> {
        let endpoints = self.effective_endpoints();
        let live: HashSet<&str> = endpoints
            .iter()
            .map(|endpoint| endpoint.url.as_str())
            .collect();
        let mut stats = self.stats.lock();
        stats.retain(|url, _| live.contains(url.as_str()));
        let mut out: Vec<DohStatsSnapshot> = stats
            .iter()
            .map(|(url, entry)| DohStatsSnapshot {
                url: url.clone(),
                answered: entry.answered.load(Ordering::Relaxed),
                failed: entry.failed.load(Ordering::Relaxed),
                cooldowns: entry.cooldowns.load(Ordering::Relaxed),
            })
            .collect();
        out.sort_by(|a, b| a.url.cmp(&b.url));
        out
    }

    fn record_stats(&self, url: &str, answered: bool, entered_cooldown: bool) {
        let mut stats = self.stats.lock();
        let entry = stats.entry(url.to_string()).or_default();
        if answered {
            entry.answered.fetch_add(1, Ordering::Relaxed);
        } else {
            entry.failed.fetch_add(1, Ordering::Relaxed);
        }
        if entered_cooldown {
            entry.cooldowns.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Health check used at startup, after network changes, and manually. It always performs a
    /// real query (never the cache) and updates [`DohHealth`] for the UI.
    pub async fn health_check(&self) -> Vec<DohHealth> {
        // The endpoints are independent; probing them in parallel turns the
        // worst case from the sum of their timeouts into the slowest one. This
        // runs on network changes before the warm-up sweep, so it is directly
        // visible as recovery latency.
        let endpoints = self.effective_endpoints();
        let checks = endpoints.iter().map(|endpoint| async move {
            let started = Instant::now();
            let result = match tokio::time::timeout(
                HEALTH_PROBE_TIMEOUT,
                self.query_endpoint(endpoint, "example.com", TYPE_A),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(anyhow!(
                    "health probe timed out after {}s",
                    HEALTH_PROBE_TIMEOUT.as_secs()
                )),
            };
            // A health probe is an observation, not a routing decision: keep
            // the policy counters a real query produced instead of resetting
            // them (or counting the probe itself) here.
            let previous = self
                .health
                .read()
                .get(&endpoint.url)
                .map(|entry| (entry.failures, entry.cooldown_until))
                .unwrap_or((0, None));
            let health = DohHealth::new(
                endpoint,
                result.is_ok(),
                Some(started.elapsed().as_millis() as u64),
                result.as_ref().err().map(|error| format!("{error:#}")),
                previous.0,
                previous.1,
            );
            (health, result.is_err())
        });
        let results = futures_util::future::join_all(checks).await;
        let mut out = Vec::with_capacity(results.len());
        for (health, failed) in results {
            if failed {
                tracing::warn!(
                    endpoint = %redact_url(&health.url),
                    error = %health.last_error.as_deref().unwrap_or(""),
                    "DoH health check failed"
                );
            }
            self.health
                .write()
                .insert(health.url.clone(), health.clone());
            self.record_stats(&health.url, !failed, false);
            out.push(health);
        }
        out
    }


    pub(super) fn record_health(
        &self,
        endpoint: &EffectiveEndpoint,
        healthy: bool,
        elapsed: Duration,
        error: Option<String>,
    ) {
        let now = Instant::now();
        let (previous, entered_cooldown, failures, cooldown_until) = {
            let mut health = self.health.write();
            let previous = health.get(&endpoint.url).map(|entry| {
                (
                    entry.healthy,
                    entry.failures,
                    entry.cooldown_until,
                )
            });
            let was_cooling = previous
                .and_then(|entry| entry.2)
                .is_some_and(|until| until > now);
            let (previous_healthy, failures, cooldown_until) = match (healthy, previous) {
                (true, previous) => (previous.map(|entry| entry.0), 0, None),
                (false, Some((previous_healthy, failures, cooldown_until))) => {
                    let failures = failures.saturating_add(1);
                    let cooldown_until = if failures >= ENDPOINT_FAILURE_THRESHOLD {
                        Some(now + cooldown_delay(failures))
                    } else {
                        cooldown_until
                    };
                    (Some(previous_healthy), failures, cooldown_until)
                }
                (false, None) => (None, 1, None),
            };
            health.insert(
                endpoint.url.clone(),
                DohHealth::new(
                    endpoint,
                    healthy,
                    Some(elapsed.as_millis() as u64),
                    error.clone(),
                    failures,
                    cooldown_until,
                ),
            );
            (
                previous_healthy,
                !was_cooling && cooldown_until.is_some(),
                failures,
                cooldown_until,
            )
        };
        self.record_stats(&endpoint.url, healthy, entered_cooldown);
        if entered_cooldown {
            tracing::warn!(
                endpoint = %endpoint.name,
                url = %redact_url(&endpoint.url),
                failures,
                cooldown_secs = cooldown_until
                    .map(|until| until.saturating_duration_since(now).as_secs())
                    .unwrap_or(0),
                "doh endpoint cooling down; skipping it for a while"
            );
        }
        // Only transitions are logged: a healthy endpoint answers every query,
        // and one line per query would drown the interesting failures.
        if previous != Some(healthy) {
            if healthy {
                tracing::info!(
                    endpoint = %endpoint.name,
                    url = %redact_url(&endpoint.url),
                    source = %endpoint.source,
                    latency_ms = elapsed.as_millis() as u64,
                    "doh endpoint is reachable"
                );
            } else {
                tracing::warn!(
                    endpoint = %endpoint.name,
                    url = %redact_url(&endpoint.url),
                    source = %endpoint.source,
                    latency_ms = elapsed.as_millis() as u64,
                    failures,
                    cooling_secs = cooldown_until
                        .map(|until| until.saturating_duration_since(now).as_secs())
                        .unwrap_or(0),
                    error = error.as_deref().unwrap_or("unknown"),
                    "doh endpoint is unreachable"
                );
            }
        }
    }

    /// Endpoints in policy order: healthy ones first (the configured order is
    /// kept among equals), cooling ones last, soonest-to-expire first. A pool
    /// where every entry is cooling still yields the least-bad endpoint.
    pub(super) fn endpoint_order(&self, endpoints: &[EffectiveEndpoint]) -> Vec<usize> {
        let now = Instant::now();
        let health = self.health.read();
        let mut order: Vec<usize> = (0..endpoints.len()).collect();
        order.sort_by_key(|&index| {
            match health.get(&endpoints[index].url) {
                Some(entry) => match entry.cooldown_until {
                    Some(until) if entry.cooling(now) => (1u8, until, index),
                    _ => (0u8, now, index),
                },
                None => (0u8, now, index),
            }
        });
        order
    }
}


/// Cooldown for a consecutive-failure count: 30 s after the third failure,
/// doubling up to ten minutes.
pub(super) fn cooldown_delay(failures: u32) -> Duration {
    let steps = failures
        .saturating_sub(ENDPOINT_FAILURE_THRESHOLD)
        .min(5);
    (ENDPOINT_COOLDOWN_BASE * 2u32.pow(steps)).min(ENDPOINT_COOLDOWN_MAX)
}
