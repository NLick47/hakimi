use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cache::CachedAnswer;
use crate::dns::{TYPE_A, TYPE_AAAA};
use crate::domain::normalize_hostname_cow;
use crate::strategy::DohSource;
use super::{DohResolution, Resolver};
use crate::util::now;



/// After a DoH TTL expires, serve the still-usable answer for this short grace
/// period while a background query refreshes it. Without the grace, every
/// expired entry paid the full DoH timeout before the page could connect.
pub(super) const STALE_WHILE_REVALIDATE_SECS: i64 = 60;
/// A stale answer is returned immediately while DoH refreshes it in the
/// background. If DoH is down, one attempt per stale request would multiply
/// the failure traffic; keep one attempt per domain per window instead.
pub(super) const STALE_REFRESH_BACKOFF: Duration = Duration::from_secs(5);
pub(super) const STALE_REFRESH_BACKOFF_MAX: usize = 1024;

/// RFC 8767: a zero-TTL answer gets a small minimum cache time, or every new
/// connection pays a full endpoint race for the same domain.
pub(super) const MIN_CACHE_TTL_SECS: u32 = 5;

/// How long an AAAA query may hold a resolution that already has IPv4
/// addresses. A slow IPv6 answer is additive, not the only route, so it keeps
/// running in the background instead of delaying the first connection.
pub(super) const FAMILY_GRACE: Duration = Duration::from_secs(1);

/// Background AAAA lookups that may run at once. A page full of IPv4-only
/// names must not spawn one query each while their IPv4 answers come back.
pub(super) const FAMILY_REFRESH_SLOTS: usize = 8;


/// One family's cached answer, reduced to what the merge tiers need. All
/// freshness fields are evaluated against one `now`, so the fresh, stale and
/// expired checks cannot disagree with each other.
pub(super) struct CachedFamily {
    now: chrono::DateTime<chrono::Utc>,
    ips: Vec<std::net::IpAddr>,
    fresh: bool,
    remaining_ttl: u32,
    ttl_secs: u32,
    fetched_at: chrono::DateTime<chrono::Utc>,
}

impl Resolver {
    /// Read both families' cached answers once. The merge tiers used to call
    /// `doh_answer` up to six times per resolution, deep-cloning the
    /// addresses on every probe; every tier now works on this snapshot.
    pub(super) fn cached_families(
        &self,
        domain: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> [Option<CachedFamily>; 2] {
        let mut families = [None, None];
        for (slot, qtype) in families.iter_mut().zip([TYPE_A, TYPE_AAAA]) {
            let Some(answer) = self.cache.doh_answer(domain, qtype) else {
                continue;
            };
            let fresh = answer.is_fresh(now);
            let remaining_ttl = remaining_ttl(&answer, now);
            *slot = Some(CachedFamily {
                now,
                ips: answer.ips,
                fresh,
                remaining_ttl,
                ttl_secs: answer.ttl_secs,
                fetched_at: answer.fetched_at,
            });
        }
        families
    }

    /// Serve the cached answer for `domain`, merging both address families and
    /// renewing anything that is stale or expired in the background.
    pub(super) fn cached_resolution(
        &self,
        domain: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<DohResolution> {
        let families = self.cached_families(domain, at);
        let fresh = fresh_resolution_from(&families);
        let stale = stale_resolution_from(&families, Some(STALE_WHILE_REVALIDATE_SECS));
        let resolution = merge_cached_resolutions(fresh, stale)?;
        if resolution.stale || any_family_expired(&families) {
            self.spawn_ip_refresh(domain.to_owned());
        }
        Some(resolution)
    }

    /// True when the background IP refresh still has work to do.
    ///
    /// A fresh answer from one family is not enough: the other family's TTL
    /// may have expired while the first one is still valid. Stopping at the
    /// first fresh family here would leave the expired one unqueried until the
    /// fresh family expires as well.
    pub(super) fn ip_cache_needs_refresh(&self, domain: &str, at: chrono::DateTime<chrono::Utc>) -> bool {
        let families = self.cached_families(domain, at);
        fresh_resolution_from(&families).is_none() || any_family_expired(&families)
    }


    pub(super) async fn query_lock(&self, key: String) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.query_locks.lock();
            if locks.len() > 1024 {
                locks.retain(|_, lock| Arc::strong_count(lock) > 1);
            }
            locks
                .entry(key)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    pub(super) fn try_query_lock(&self, key: String) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let lock = {
            let mut locks = self.query_locks.lock();
            if locks.len() > 1024 {
                locks.retain(|_, lock| Arc::strong_count(lock) > 1);
            }
            locks
                .entry(key)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        lock.try_lock_owned().ok()
    }

    /// Refresh an expired answer without making the request wait for DoH.
    /// `try_query_lock` deliberately skips spawning another refresh when a
    /// foreground resolve already owns this domain's single-flight lock.
    pub(super) fn spawn_ip_refresh(&self, domain: String) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Ok(domain) = normalize_hostname_cow(&domain) else {
            return;
        };
        let domain = domain.into_owned();
        // A burst of asset connections can all hit the same stale answer.
        // Without a per-domain gate, each request would spawn another full
        // DoH attempt after the previous one failed, amplifying an outage.
        {
            let now = Instant::now();
            let mut refresh_after = self.stale_refresh_after.lock();
            if refresh_after.get(&domain).is_some_and(|until| *until > now) {
                return;
            }
            if refresh_after.len() >= STALE_REFRESH_BACKOFF_MAX {
                refresh_after.retain(|_, until| *until > now);
                if refresh_after.len() >= STALE_REFRESH_BACKOFF_MAX {
                    refresh_after.clear();
                }
            }
            refresh_after.insert(domain.clone(), now + STALE_REFRESH_BACKOFF);
        }
        let resolver = self.clone();
        handle.spawn(async move {
            let Some(_guard) = resolver.try_query_lock(format!("ip|{domain}")) else {
                return;
            };
            if !resolver.ip_cache_needs_refresh(&domain, now()) {
                return;
            }
            if let Err(error) = resolver.resolve_live_ips(&domain).await {
                tracing::debug!(
                    domain = %domain,
                    error = %error,
                    "background DoH refresh failed; keeping the stale answer"
                );
            }
        });
    }


    /// Finish an AAAA lookup the IPv4 answer did not wait for. The result lands
    /// in the cache, so the next resolution (and later connections) see the
    /// IPv6 candidates. Bounded by a semaphore: one slow IPv6 path must not
    /// turn a page full of IPv4-only names into a query burst.
    pub(super) fn spawn_family_refresh(&self, domain: &str, qtype: u16) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Ok(permit) = self.family_refresh_slots.clone().try_acquire_owned() else {
            tracing::debug!(
                domain = %domain,
                "background AAAA refresh skipped; the slots are busy"
            );
            return;
        };
        let resolver = self.clone();
        let domain = domain.to_string();
        handle.spawn(async move {
            let _permit = permit;
            let _ = resolver.query_one_type(&domain, qtype).await;
        });
    }

}


/// Merge every fresh cached A/AAAA answer into one resolution.
///
/// The two record types have independent TTLs. Returning the first family
/// that happened to be fresh dropped the other one: a dual-stack host lost
/// its IPv6 candidate for the whole A TTL, and once the shorter-lived A
/// answer expired the resolver served the still-fresh AAAA alone without
/// ever re-querying A.
pub(super) fn fresh_resolution_from(families: &[Option<CachedFamily>; 2]) -> Option<DohResolution> {
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for family in families.iter().flatten() {
        if !family.fresh || family.ips.is_empty() {
            continue;
        }
        ttl = ttl.min(family.remaining_ttl);
        for ip in &family.ips {
            if !ips.contains(ip) {
                ips.push(*ip);
            }
        }
    }
    if ips.is_empty() {
        return None;
    }
    Some(DohResolution {
        ips,
        source: DohSource::Cache,
        endpoint: "cache".to_string(),
        stale: false,
        ttl: if ttl == u32::MAX { 0 } else { ttl },
        fallback_used: false,
    })
}

/// Select cached IP answers without waiting for DoH. `extra_secs` bounds how
/// far past the DNS TTL the answers may be served in the background refresh
/// path; `None` is the last-resort fallback used after a live failure. Both
/// address families are merged for the same reason as in
/// [`fresh_resolution_from`].
pub(super) fn stale_resolution_from(
    families: &[Option<CachedFamily>; 2],
    extra_secs: Option<i64>,
) -> Option<DohResolution> {
    let mut ips = Vec::new();
    for family in families.iter().flatten() {
        if family.ips.is_empty() || family.fresh {
            continue;
        }
        if let Some(extra) = extra_secs {
            if family.ttl_secs == 0 {
                continue;
            }
            let age = family
                .now
                .signed_duration_since(family.fetched_at)
                .num_seconds();
            if age > family.ttl_secs as i64 + extra {
                continue;
            }
        }
        for ip in &family.ips {
            if !ips.contains(ip) {
                ips.push(*ip);
            }
        }
    }
    if ips.is_empty() {
        return None;
    }
    Some(DohResolution {
        ips,
        source: DohSource::Cache,
        endpoint: "stale-cache".to_string(),
        stale: true,
        ttl: 0,
        fallback_used: false,
    })
}

/// True when one of the cached A/AAAA answers has expired.
///
/// A fresh answer from one family must not keep the other family's expired
/// answer out of the refresh path: the two TTLs are independent, so
/// returning early on the fresh one would leave the expired family
/// unqueried for up to the longer TTL. Only an entry that actually had
/// addresses counts, so an IPv4-only domain (which never caches AAAA) does
/// not trigger a background lookup every few seconds.
pub(super) fn any_family_expired(families: &[Option<CachedFamily>; 2]) -> bool {
    families
        .iter()
        .flatten()
        .any(|family| !family.ips.is_empty() && !family.fresh)
}

/// Combine a fresh cached answer with a just-expired one. The fresh answer
/// (if any) keeps its TTL and ordering; the stale addresses are appended as
/// fallback candidates and the result is marked stale.
fn merge_cached_resolutions(
    fresh: Option<DohResolution>,
    stale: Option<DohResolution>,
) -> Option<DohResolution> {
    match (fresh, stale) {
        (None, None) => None,
        (Some(fresh), None) => Some(fresh),
        (None, Some(stale)) => Some(stale),
        (Some(mut fresh), Some(stale)) => {
            // Keep the documented IPv4-first order while placing the fresh
            // addresses of each family before its stale fallback.
            let mut v4 = Vec::new();
            let mut v6 = Vec::new();
            for ips in [&fresh.ips, &stale.ips] {
                for ip in ips {
                    let target = if ip.is_ipv4() { &mut v4 } else { &mut v6 };
                    if !target.contains(ip) {
                        target.push(*ip);
                    }
                }
            }
            v4.extend(v6);
            fresh.ips = v4;
            fresh.stale = true;
            Some(fresh)
        }
    }
}

fn remaining_ttl(answer: &CachedAnswer, now: chrono::DateTime<chrono::Utc>) -> u32 {
    let age = now
        .signed_duration_since(answer.fetched_at)
        .num_seconds()
        .max(0) as u32;
    answer.ttl_secs.saturating_sub(age)
}

/// Compact rendering of a list of addresses for the log.
///
/// The debug rendering contains spaces, which makes the line impossible to
/// read field by field - and the answer set is the whole point of the line.
pub(super) fn format_ips(ips: &[std::net::IpAddr]) -> String {
    if ips.is_empty() {
        return "none".to_string();
    }
    ips.iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",")
}
