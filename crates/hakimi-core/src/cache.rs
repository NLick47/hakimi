use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::strategy::IpSource;
use crate::util::{atomic_write, atomic_write_json, now, read_json};

const MAX_STALE_AGE_DAYS: i64 = 7;
const MAX_SNI_AGE_DAYS: i64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastGoodEntry {
    pub domain: String,
    pub ip: IpAddr,
    pub source: IpSource,
    pub network_id: String,
    pub saved_at: DateTime<Utc>,
    pub catalog_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedAnswer {
    pub domain: String,
    pub qtype: u16,
    #[serde(default)]
    pub ips: Vec<IpAddr>,
    #[serde(default)]
    pub hints: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech_config: Option<String>,
    pub ttl_secs: u32,
    pub fetched_at: DateTime<Utc>,
}

impl CachedAnswer {
    pub fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        if self.ttl_secs == 0 {
            return false;
        }
        let age = now.signed_duration_since(self.fetched_at).num_seconds();
        age >= 0 && age < self.ttl_secs as i64
    }

    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        let age = now.signed_duration_since(self.fetched_at);
        age <= Duration::days(MAX_STALE_AGE_DAYS)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedEch {
    pub domain: String,
    pub ech_config: String,
    pub ttl_secs: u32,
    pub fetched_at: DateTime<Utc>,
}

impl CachedEch {
    pub fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        if self.ttl_secs == 0 {
            return false;
        }
        let age = now.signed_duration_since(self.fetched_at).num_seconds();
        age >= 0 && age < self.ttl_secs as i64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedSni {
    pub group: String,
    pub domain: String,
    pub network_id: String,
    /// `None` means the empty SNI candidate worked.
    pub sni: Option<String>,
    pub saved_at: DateTime<Utc>,
}

/// Measured quality of one (domain, ip) pair. Persisted so a restart keeps the
/// knowledge that an IP was blocked or slow on this network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpScoreEntry {
    pub ewma_ms: f64,
    pub successes: u32,
    pub failures: u32,
    pub updated_at: DateTime<Utc>,
}

/// One IP quality sample to persist.
#[derive(Debug, Clone, Copy)]
pub struct IpScoreUpdate<'a> {
    pub domain: &'a str,
    pub ip: IpAddr,
    pub ewma_ms: f64,
    pub successes: u32,
    pub failures: u32,
}

/// How many (domain, ip) quality entries to keep at most. The active set of a
/// heavy user stays well below this.
const MAX_IP_SCORES: usize = 1024;
/// Evict in bulk down to this size when the cap is crossed. Pruning back to
/// exactly the cap would make every subsequent insert sort the whole map.
const IP_SCORE_PRUNE_TO: usize = MAX_IP_SCORES * 3 / 4;
/// Entries older than the widest freshness window can never be used again.
const MAX_IP_SCORE_AGE_DAYS: i64 = 30;
/// Same cap and age window for remembered routes; the pre-warm loop takes the
/// newest 20, and 30 days is the widest freshness setting any config can use.
const MAX_LAST_GOOD: usize = 512;
/// Leave headroom after a prune so a page's asset burst does not rank-and-sort
/// the remembered-route map on every new host.
const LAST_GOOD_PRUNE_TO: usize = MAX_LAST_GOOD * 3 / 4;
const MAX_LAST_GOOD_AGE_DAYS: i64 = 30;
/// Resolved addresses, one A and one AAAA entry per domain.  These maps grow
/// with every visited domain, so without a cap the cache and the JSON written
/// from it would grow without bound: 5000 domains already meant 2.4 MB and an
/// 83 ms flush.  The cache is a hint, an evicted answer is looked up again.
const MAX_DOH_ANSWERS: usize = 1024;
const DOH_PRUNE_TO: usize = MAX_DOH_ANSWERS * 3 / 4;
/// ECH configurations.  One per domain, and only for the groups that use ECH.
const MAX_ECH_CONFIGS: usize = 256;
const ECH_PRUNE_TO: usize = MAX_ECH_CONFIGS * 3 / 4;
/// Remembered fake SNI names, one per group, domain and network.
const MAX_FAKE_SNI: usize = 256;
const SNI_PRUNE_TO: usize = MAX_FAKE_SNI * 3 / 4;
/// Domains waiting for a re-plan after a catalog update.  A huge catalog
/// update can name thousands of domains; the flags are consumed by the next
/// connection to each domain.
const MAX_SKIP_ONCE: usize = 4096;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct CacheData {
    last_good: HashMap<String, LastGoodEntry>,
    #[serde(default)]
    ip_scores: HashMap<String, IpScoreEntry>,
    skip_once: HashSet<String>,
    doh: HashMap<String, CachedAnswer>,
    ech: HashMap<String, CachedEch>,
    sni: HashMap<String, CachedSni>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CacheStats {
    pub last_good: usize,
    pub skip_once: usize,
    pub doh_answers: usize,
    pub ech_configs: usize,
    pub fake_sni: usize,
}

/// Persistent local cache: last-good IPs, DoH answers, ECH configs and fake SNI. All writes
/// are atomic, so a crash never leaves a half-written cache behind.
pub struct CacheManager {
    path: PathBuf,
    data: RwLock<CacheData>,
    dirty: AtomicBool,
    /// Stop handle for the one background flusher. Keeping it here makes
    /// `start_auto_flush` idempotent and lets the runtime cancel the task on
    /// stop instead of leaving a flusher behind for a stopped runtime.
    auto_flush_stop: Mutex<Option<tokio::sync::watch::Sender<()>>>,
}

impl CacheManager {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut data = match read_json::<CacheData>(&path) {
            Ok(data) => data,
            Err(error) if path.exists() => {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "cache is unreadable; starting with an empty cache"
                );
                let _ = std::fs::rename(&path, path.with_extension("corrupt.json"));
                CacheData::default()
            }
            Err(_) => CacheData::default(),
        };
        Self::expire(&mut data, now());
        Ok(Self {
            path,
            data: RwLock::new(data),
            dirty: AtomicBool::new(false),
            auto_flush_stop: Mutex::new(None),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self) -> Result<()> {
        let data = self.data.read();
        atomic_write_json(&self.path, &*data)
    }

    /// Record a cache mutation.
    ///
    /// The cache holds hints (remembered routes, measured quality), so the
    /// write is always deferred: the request path only flips a flag, the
    /// background flusher writes the file, and the runtime flushes once more
    /// when it shuts down.  Nothing in the request path waits on the disk.
    fn mark_dirty(&self, _data: &CacheData) {
        self.dirty.store(true, Ordering::SeqCst);
    }

    /// Write once if anything changed since the last flush. The JSON is encoded
    /// under a read lock and written outside every lock, so a slow disk never
    /// blocks lookups and nothing deep-clones the whole cache on the way out.
    pub fn flush_if_dirty(&self) -> bool {
        if !self.dirty.swap(false, Ordering::SeqCst) {
            return false;
        }
        // Expire under the write lock, then encode under the read lock: the
        // encoding must not block the lookups of the request path.
        {
            let mut data = self.data.write();
            Self::expire(&mut data, now());
        }
        let json = {
            let data = self.data.read();
            serde_json::to_string(&*data)
        };
        match json {
            Ok(json) => {
                if let Err(error) = atomic_write(&self.path, json.as_bytes()) {
                    tracing::warn!(error = %error, "failed to persist cache");
                    // Keep the flag: the next tick retries the write instead of
                    // dropping the change on the floor.
                    self.dirty.store(true, Ordering::SeqCst);
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "failed to encode cache");
                self.dirty.store(true, Ordering::SeqCst);
            }
        }
        true
    }

    /// Start the background flusher. Cache writes are hints, so a few seconds of latency is
    /// fine while the fsyncs move off the request path entirely.
    ///
    /// Starting twice is a no-op: the runtime may start, stop and start again,
    /// and each cache must never accumulate a second flusher.
    pub fn start_auto_flush(self: &Arc<Self>, interval: StdDuration) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::debug!("no tokio runtime available; the cache is written on shutdown");
            return;
        };
        let mut stop = self.auto_flush_stop.lock();
        if stop.is_some() {
            return;
        }
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(());
        *stop = Some(stop_tx);
        drop(stop);

        let manager = self.clone();
        handle.spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    _ = tokio::time::sleep(interval) => {
                        // Serializing the cache and fsyncing it are blocking operations.
                        // Keep them off the async workers so a slow disk cannot stall
                        // proxy request handling.
                        let manager = manager.clone();
                        let _ = tokio::task::spawn_blocking(move || manager.flush_if_dirty()).await;
                    }
                }
            }
        });
    }

    /// Stop the background flusher, if one is running. Safe to call repeatedly
    /// and from `HakimiRuntime::stop`/`Drop`.
    pub fn stop_auto_flush(&self) {
        if let Some(stop) = self.auto_flush_stop.lock().take() {
            let _ = stop.send(());
        }
    }

    fn expire(data: &mut CacheData, now: DateTime<Utc>) {
        data.doh.retain(|_, answer| answer.is_usable(now));
        data.ech.retain(|_, ech| {
            now.signed_duration_since(ech.fetched_at) <= Duration::days(MAX_STALE_AGE_DAYS)
        });
        data.sni.retain(|_, sni| {
            now.signed_duration_since(sni.saved_at) <= Duration::days(MAX_SNI_AGE_DAYS)
        });
    }

    /// Drop the oldest entries until the map is back under its cap.
    ///
    /// The maps that grow with the number of visited domains need this: the
    /// cache is a hint, so an evicted entry only costs one more lookup.
    fn prune_by_age<V>(
        map: &mut HashMap<String, V>,
        max: usize,
        to: usize,
        at: impl Fn(&V) -> DateTime<Utc>,
    ) {
        if map.len() <= max {
            return;
        }
        let mut by_age: Vec<(String, DateTime<Utc>)> = map
            .iter()
            .map(|(key, value)| (key.clone(), at(value)))
            .collect();
        by_age.sort_by_key(|(_, at)| *at);
        let overflow = map.len() - to;
        for (key, _) in by_age.into_iter().take(overflow) {
            map.remove(&key);
        }
    }

    // ---- last-good -------------------------------------------------------

    pub fn last_good(&self, domain: &str, max_age_days: i64) -> Option<LastGoodEntry> {
        let now = now();
        let entry = self.data.read().last_good.get(domain).cloned()?;
        if now.signed_duration_since(entry.saved_at) <= Duration::days(max_age_days) {
            Some(entry)
        } else {
            None
        }
    }

    /// Route-relevant fields of a remembered entry. The decision cursor only
    /// needs the IP and strategy; avoid cloning the domain/network strings.
    pub fn last_good_route(&self, domain: &str, max_age_days: i64) -> Option<IpAddr> {
        let now = now();
        let data = self.data.read();
        let entry = data.last_good.get(domain)?;
        (now.signed_duration_since(entry.saved_at) <= Duration::days(max_age_days))
            .then_some(entry.ip)
    }

    /// One read-lock acquisition for the two pieces of route state a new cursor
    /// needs. `skip_once` is only consumed by the caller when it is present, so
    /// the common empty-set path never takes the write lock.
    pub fn route_hints(&self, domain: &str, max_age_days: i64) -> (bool, Option<IpAddr>) {
        let now = now();
        let data = self.data.read();
        let skip_once = data.skip_once.contains(domain);
        let last_good = data.last_good.get(domain).and_then(|entry| {
            (now.signed_duration_since(entry.saved_at) <= Duration::days(max_age_days))
                .then_some(entry.ip)
        });
        (skip_once, last_good)
    }

    /// Persisted quality entries, for seeding the decision engine on startup.
    /// Entries beyond the widest freshness window are dropped on the way in.
    pub fn ip_scores(&self) -> Vec<(String, IpAddr, IpScoreEntry)> {
        let now = now();
        let data = self.data.read();
        data.ip_scores
            .iter()
            .filter_map(|(key, entry)| {
                if now.signed_duration_since(entry.updated_at)
                    > Duration::days(MAX_IP_SCORE_AGE_DAYS)
                {
                    return None;
                }
                let (domain, ip) = key.split_once('|')?;
                let ip = ip.parse().ok()?;
                Some((domain.to_string(), ip, entry.clone()))
            })
            .collect()
    }

    /// Persist one connection outcome: the remembered route and the IP quality
    /// sample. One write lock covers both.
    pub fn record_outcome(
        &self,
        last_good: Option<LastGoodEntry>,
        score: Option<IpScoreUpdate<'_>>,
    ) {
        // Format the map key before taking the cache write lock; this runs on
        // every successful connection and does not need the lock to allocate.
        let score_key = score.map(|score| format!("{}|{}", score.domain, score.ip));
        let mut data = self.data.write();
        let timestamp = now();
        let mut changed = false;
        if let Some(entry) = last_good {
            let fresh = data.last_good.get(&entry.domain).is_some_and(|existing| {
                existing.ip == entry.ip
                    && existing.source == entry.source
                    && timestamp.signed_duration_since(existing.saved_at) < Duration::seconds(60)
            });
            if !fresh {
                data.last_good.insert(entry.domain.clone(), entry);
                if data.last_good.len() > MAX_LAST_GOOD {
                    self.prune_last_good(&mut data);
                }
                changed = true;
            }
        }
        if let (Some(score), Some(key)) = (score, score_key) {
            data.ip_scores.insert(
                key,
                IpScoreEntry {
                    ewma_ms: score.ewma_ms,
                    successes: score.successes,
                    failures: score.failures,
                    updated_at: timestamp,
                },
            );
            // Prune lazily: a full scan on every write (record_ip runs on every
            // connection outcome) is wasted work; the map is bounded and the
            // periodic flush already drops aged entries via `expire`.
            if data.ip_scores.len() > MAX_IP_SCORES {
                let mut by_age: Vec<(String, DateTime<Utc>)> = data
                    .ip_scores
                    .iter()
                    .map(|(key, entry)| (key.clone(), entry.updated_at))
                    .collect();
                by_age.sort_by_key(|(_, at)| *at);
                let overflow = data.ip_scores.len() - IP_SCORE_PRUNE_TO;
                for (key, _) in by_age.into_iter().take(overflow) {
                    data.ip_scores.remove(&key);
                }
            }
            changed = true;
        }
        if changed {
            self.mark_dirty(&data);
        }
    }

    /// Upsert one quality entry. Keeps the map bounded: entries past the widest
    /// freshness window are dropped, then the oldest beyond the cap.
    pub fn put_ip_score(
        &self,
        domain: &str,
        ip: IpAddr,
        ewma_ms: f64,
        successes: u32,
        failures: u32,
    ) {
        self.record_outcome(
            None,
            Some(IpScoreUpdate {
                domain,
                ip,
                ewma_ms,
                successes,
                failures,
            }),
        );
    }

    /// Discard all persisted quality samples. The decision engine calls this
    /// after a network change: scores describe the old path and would otherwise
    /// survive a restart and rank candidates for a network they never saw.
    pub fn clear_ip_scores(&self) {
        let mut data = self.data.write();
        if data.ip_scores.is_empty() {
            return;
        }
        data.ip_scores.clear();
        self.mark_dirty(&data);
    }

    /// Drop remembered routes that no freshness setting can use anymore, and cap
    /// the map so months of browsing do not grow state.json forever.
    fn prune_last_good(&self, data: &mut CacheData) {
        let now = now();
        let stale: Vec<String> = data
            .last_good
            .iter()
            .filter(|(_, entry)| {
                now.signed_duration_since(entry.saved_at) > Duration::days(MAX_LAST_GOOD_AGE_DAYS)
            })
            .map(|(domain, _)| domain.clone())
            .collect();
        for domain in stale {
            data.last_good.remove(&domain);
        }
        if data.last_good.len() > MAX_LAST_GOOD {
            let mut by_age: Vec<(String, DateTime<Utc>)> = data
                .last_good
                .iter()
                .map(|(domain, entry)| (domain.clone(), entry.saved_at))
                .collect();
            by_age.sort_by_key(|(_, at)| *at);
            let overflow = data.last_good.len() - LAST_GOOD_PRUNE_TO;
            for (domain, _) in by_age.into_iter().take(overflow) {
                data.last_good.remove(&domain);
            }
        }
    }

    /// Domains with a remembered route, most recently used first. The desktop app
    /// re-warms these after a restart so an active host does not pay a cold dial.
    pub fn last_good_hosts(&self) -> Vec<String> {
        let now = now();
        let data = self.data.read();
        let mut hosts: Vec<(chrono::DateTime<chrono::Utc>, String)> = data
            .last_good
            .iter()
            .filter(|(_, entry)| {
                now.signed_duration_since(entry.saved_at) <= Duration::days(MAX_LAST_GOOD_AGE_DAYS)
            })
            .map(|(domain, entry)| (entry.saved_at, domain.clone()))
            .collect();
        hosts.sort_by(|a, b| b.0.cmp(&a.0));
        hosts.into_iter().map(|(_, host)| host).collect()
    }

    pub fn put_last_good(&self, entry: LastGoodEntry) {
        self.record_outcome(Some(entry), None);
    }

    pub fn remove_last_good(&self, domain: &str) {
        let mut data = self.data.write();
        if data.last_good.remove(domain).is_some() {
            self.mark_dirty(&data);
        }
    }

    pub fn last_good_domains(&self) -> Vec<String> {
        self.data.read().last_good.keys().cloned().collect()
    }

    // ---- skipOnce --------------------------------------------------------

    pub fn mark_skip_once<I, S>(&self, domains: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut data = self.data.write();
        let mut changed = false;
        for domain in domains {
            if data.skip_once.insert(domain.into()) {
                changed = true;
            }
        }
        // A huge catalog update can name more domains than the flags are
        // worth; the set is a hint that the old route should be re-planned.
        if data.skip_once.len() > MAX_SKIP_ONCE {
            data.skip_once.clear();
            changed = true;
        }
        if changed {
            self.mark_dirty(&data);
        }
    }

    /// Consume the one-shot skip flag for a domain.
    pub fn take_skip_once(&self, domain: &str) -> bool {
        // This runs once per new route cursor. The set is empty for almost all
        // connections, so do not take the cache's global write lock just to
        // discover that. A concurrent catalog refresh can insert between the
        // two locks; that only means this connection does not consume the new
        // flag, which is the same race the previous single-lock version had.
        if !self.data.read().skip_once.contains(domain) {
            return false;
        }
        let mut data = self.data.write();
        let removed = data.skip_once.remove(domain);
        if removed {
            self.mark_dirty(&data);
        }
        removed
    }

    pub fn has_skip_once(&self, domain: &str) -> bool {
        self.data.read().skip_once.contains(domain)
    }

    // ---- DoH -------------------------------------------------------------

    pub fn doh_answer(&self, domain: &str, qtype: u16) -> Option<CachedAnswer> {
        let now = now();
        let answer = self.data.read().doh.get(&doh_key(domain, qtype)).cloned()?;
        answer.is_usable(now).then_some(answer)
    }

    pub fn put_doh_answer(&self, answer: CachedAnswer) {
        let mut data = self.data.write();
        data.doh
            .insert(doh_key(&answer.domain, answer.qtype), answer);
        Self::prune_by_age(&mut data.doh, MAX_DOH_ANSWERS, DOH_PRUNE_TO, |answer| {
            answer.fetched_at
        });
        self.mark_dirty(&data);
    }

    // ---- ECH -------------------------------------------------------------

    pub fn ech(&self, domain: &str, only_fresh: bool) -> Option<CachedEch> {
        let now = now();
        let entry = self.data.read().ech.get(domain).cloned()?;
        if now.signed_duration_since(entry.fetched_at) > Duration::days(MAX_STALE_AGE_DAYS) {
            return None;
        }
        if only_fresh && !entry.is_fresh(now) {
            return None;
        }
        Some(entry)
    }

    pub fn put_ech(&self, entry: CachedEch) {
        let mut data = self.data.write();
        data.ech.insert(entry.domain.clone(), entry);
        Self::prune_by_age(&mut data.ech, MAX_ECH_CONFIGS, ECH_PRUNE_TO, |entry| {
            entry.fetched_at
        });
        self.mark_dirty(&data);
    }

    // ---- fake SNI --------------------------------------------------------

    pub fn sni(&self, group: &str, domain: &str, network_id: &str) -> Option<CachedSni> {
        let now = now();
        let entry = self
            .data
            .read()
            .sni
            .get(&sni_key(group, domain, network_id))
            .cloned()?;
        (now.signed_duration_since(entry.saved_at) <= Duration::days(MAX_SNI_AGE_DAYS))
            .then_some(entry)
    }

    pub fn put_sni(&self, entry: CachedSni) {
        let mut data = self.data.write();
        let key = sni_key(&entry.group, &entry.domain, &entry.network_id);
        if let Some(existing) = data.sni.get(&key) {
            if existing.sni == entry.sni
                && now().signed_duration_since(existing.saved_at) < Duration::seconds(60)
            {
                return;
            }
        }
        data.sni.insert(key, entry);
        Self::prune_by_age(&mut data.sni, MAX_FAKE_SNI, SNI_PRUNE_TO, |entry| {
            entry.saved_at
        });
        self.mark_dirty(&data);
    }

    pub fn remove_sni(&self, group: &str, domain: &str, network_id: &str) {
        let mut data = self.data.write();
        if data
            .sni
            .remove(&sni_key(group, domain, network_id))
            .is_some()
        {
            self.mark_dirty(&data);
        }
    }

    pub fn stats(&self) -> CacheStats {
        let data = self.data.read();
        CacheStats {
            last_good: data.last_good.len(),
            skip_once: data.skip_once.len(),
            doh_answers: data.doh.len(),
            ech_configs: data.ech.len(),
            fake_sni: data.sni.len(),
        }
    }

    pub fn clear(&self) -> Result<()> {
        let mut data = self.data.write();
        *data = CacheData::default();
        self.mark_dirty(&data);
        Ok(())
    }
}

fn doh_key(domain: &str, qtype: u16) -> String {
    format!("{domain}|{qtype}")
}

fn sni_key(group: &str, domain: &str, network_id: &str) -> String {
    format!("{group}\u{1f}{domain}\u{1f}{network_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::network_id;

    fn manager() -> (tempfile::TempDir, CacheManager) {
        let dir = tempfile::tempdir().unwrap();
        let manager = CacheManager::load(dir.path().join("state.json")).unwrap();
        (dir, manager)
    }

    #[tokio::test]
    async fn auto_flush_can_be_started_idempotently_and_stopped() {
        let (_dir, cache) = manager();
        let cache = Arc::new(cache);
        let interval = StdDuration::from_secs(3600);

        cache.start_auto_flush(interval);
        assert!(cache.auto_flush_stop.lock().is_some());
        cache.start_auto_flush(interval);
        assert!(
            cache.auto_flush_stop.lock().is_some(),
            "a second start must not replace the existing flusher"
        );

        cache.stop_auto_flush();
        assert!(cache.auto_flush_stop.lock().is_none());

        cache.start_auto_flush(interval);
        assert!(
            cache.auto_flush_stop.lock().is_some(),
            "a stopped runtime must be able to start a fresh flusher"
        );
        cache.stop_auto_flush();
    }

    #[test]
    fn clearing_ip_scores_removes_and_persists_the_cleared_state() {
        let (_dir, cache) = manager();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        cache.put_ip_score("example.com", ip, 120.0, 2, 0);
        assert_eq!(cache.ip_scores().len(), 1);

        cache.clear_ip_scores();
        assert!(cache.ip_scores().is_empty());
        cache.flush_if_dirty();

        let reloaded = CacheManager::load(cache.path()).unwrap();
        assert!(
            reloaded.ip_scores().is_empty(),
            "cleared scores must not return after a restart"
        );
    }

    #[test]
    fn last_good_roundtrip_and_expiry() {
        let (_dir, cache) = manager();
        cache.put_last_good(LastGoodEntry {
            domain: "github.com".into(),
            ip: "20.205.243.166".parse().unwrap(),
            source: IpSource::Remote,
            network_id: network_id(),
            saved_at: now() - Duration::days(8),
            catalog_version: 3,
        });
        assert!(cache.last_good("github.com", 7).is_none());
        cache.put_last_good(LastGoodEntry {
            domain: "github.com".into(),
            ip: "20.205.243.166".parse().unwrap(),
            source: IpSource::Remote,
            network_id: network_id(),
            saved_at: now() - Duration::days(2),
            catalog_version: 3,
        });
        let entry = cache.last_good("github.com", 7).unwrap();
        assert_eq!(entry.ip.to_string(), "20.205.243.166");
    }

    #[test]
    fn record_outcome_writes_both_parts_and_keeps_the_freshness_rule() {
        let (_dir, cache) = manager();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let entry = sample_entry("example.com", "203.0.113.5");
        let saved_at = entry.saved_at;

        cache.record_outcome(
            Some(entry),
            Some(IpScoreUpdate {
                domain: "example.com",
                ip,
                ewma_ms: 120.0,
                successes: 2,
                failures: 0,
            }),
        );
        // Both parts are in the cache.
        let stored = cache.last_good("example.com", 7).unwrap();
        assert_eq!(stored.ip, ip);
        assert_eq!(stored.saved_at, saved_at);
        let scores = cache.ip_scores();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].2.successes, 2);

        // The same route within 60 seconds keeps the original timestamp, but
        // the quality sample is still updated.
        let mut again = sample_entry("example.com", "203.0.113.5");
        again.saved_at = now();
        cache.record_outcome(
            Some(again),
            Some(IpScoreUpdate {
                domain: "example.com",
                ip,
                ewma_ms: 90.0,
                successes: 3,
                failures: 0,
            }),
        );
        let stored = cache.last_good("example.com", 7).unwrap();
        assert_eq!(
            stored.saved_at, saved_at,
            "a fresh repeat must not restart the freshness window"
        );
        let scores = cache.ip_scores();
        assert_eq!(scores[0].2.successes, 3);
        assert_eq!(scores[0].2.ewma_ms, 90.0);
    }

    /// The maps that grow with the number of visited domains need a cap:
    /// 5000 resolved domains meant 2.4 MB of cache and an 83 ms flush.
    #[test]
    fn the_growing_maps_stay_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheManager::load(dir.path().join("state.json")).unwrap();
        for index in 0..5000u32 {
            let domain = format!("host{index}.example.com");
            cache.put_doh_answer(CachedAnswer {
                domain: domain.clone(),
                qtype: 1,
                ips: vec!["93.184.216.34".parse().unwrap()],
                hints: Vec::new(),
                ech_config: None,
                ttl_secs: 300,
                fetched_at: now(),
            });
            cache.put_ech(CachedEch {
                domain: domain.clone(),
                ech_config: "config".into(),
                ttl_secs: 300,
                fetched_at: now(),
            });
            cache.put_sni(CachedSni {
                group: "g".into(),
                domain,
                network_id: "net".into(),
                sni: None,
                saved_at: now(),
            });
        }
        cache.mark_skip_once((0..5000u32).map(|index| format!("host{index}.example.com")));
        cache.flush_if_dirty();
        let size = std::fs::metadata(cache.path())
            .map(|meta| meta.len())
            .unwrap_or(0);
        assert!(
            size < 900_000,
            "the cache file must stay small, got {size} bytes"
        );
        // The newest entries survive, the oldest are dropped.
        assert!(cache.doh_answer("host4999.example.com", 1).is_some());
        assert!(cache.doh_answer("host0.example.com", 1).is_none());
        assert!(cache.ech("host4999.example.com", false).is_some());
        assert!(cache.sni("g", "host4999.example.com", "net").is_some());
    }

    /// A write that fails must stay scheduled: the change may not be lost
    /// because the disk was busy for a moment.
    #[test]
    fn a_failed_write_is_retried_on_the_next_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let cache = CacheManager::load(&path).unwrap();
        // A directory in place of the state file makes every write fail.
        std::fs::create_dir_all(&path).unwrap();
        cache.mark_skip_once(["example.com"]);
        assert!(cache.flush_if_dirty(), "the first flush attempts the write");
        assert!(
            cache.flush_if_dirty(),
            "a failed write has to stay scheduled for the next flush"
        );
    }

    #[tokio::test]
    async fn record_outcome_without_changes_does_not_schedule_a_flush() {
        let dir = tempfile::tempdir().unwrap();
        let cache = std::sync::Arc::new(CacheManager::load(dir.path().join("state.json")).unwrap());
        // The background flusher has to be running, otherwise every write is
        // persisted eagerly and the dirty flag never shows up.
        cache.start_auto_flush(StdDuration::from_secs(3600));
        let ip: IpAddr = "203.0.113.6".parse().unwrap();
        let entry = sample_entry("example.com", "203.0.113.6");
        cache.record_outcome(
            Some(entry.clone()),
            Some(IpScoreUpdate {
                domain: "example.com",
                ip,
                ewma_ms: 100.0,
                successes: 1,
                failures: 0,
            }),
        );
        assert!(cache.flush_if_dirty(), "the first outcome is a change");

        // The same route within the freshness window changes nothing.
        cache.record_outcome(Some(entry), None);
        assert!(
            !cache.flush_if_dirty(),
            "an unchanged route must not schedule a write"
        );
    }

    #[test]
    fn skip_once_is_consumed() {
        let (_dir, cache) = manager();
        cache.mark_skip_once(["github.com", "api.github.com"]);
        assert!(cache.has_skip_once("github.com"));
        assert!(cache.take_skip_once("github.com"));
        assert!(!cache.take_skip_once("github.com"));
        assert!(cache.has_skip_once("api.github.com"));
    }

    #[test]
    fn route_hints_do_not_consume_the_skip_marker() {
        let (_dir, cache) = manager();
        cache.mark_skip_once(["github.com"]);
        let (skip, last_good) = cache.route_hints("github.com", 7);
        assert!(skip);
        assert!(last_good.is_none());
        assert!(cache.has_skip_once("github.com"));
        assert!(cache.take_skip_once("github.com"));
    }

    #[test]
    fn doh_fresh_and_stale() {
        let (_dir, cache) = manager();
        cache.put_doh_answer(CachedAnswer {
            domain: "example.com".into(),
            qtype: 1,
            ips: vec!["1.1.1.1".parse().unwrap()],
            hints: vec![],
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now(),
        });
        let answer = cache.doh_answer("example.com", 1).unwrap();
        assert!(answer.is_fresh(now()));
        cache.put_doh_answer(CachedAnswer {
            domain: "example.com".into(),
            qtype: 1,
            ips: vec!["1.1.1.1".parse().unwrap()],
            hints: vec![],
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now() - Duration::hours(1),
        });
        let answer = cache.doh_answer("example.com", 1).unwrap();
        assert!(!answer.is_fresh(now()));
        assert!(answer.is_usable(now()));
    }

    #[test]
    fn ip_scores_survive_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        {
            let cache = CacheManager::load(&path).unwrap();
            cache.put_ip_score("example.com", "203.0.113.10".parse().unwrap(), 120.0, 3, 1);
            cache.put_ip_score("example.com", "203.0.113.11".parse().unwrap(), 90.0, 5, 0);
            cache.flush_if_dirty();
        }
        let reloaded = CacheManager::load(&path).unwrap();
        let mut scores = reloaded.ip_scores();
        scores.sort_by(|a, b| (a.0.clone(), a.1).cmp(&(b.0.clone(), b.1)));
        assert_eq!(scores.len(), 2);
        assert_eq!(scores[0].0, "example.com");
        assert_eq!(scores[0].1.to_string(), "203.0.113.10");
        assert_eq!((scores[0].2.successes, scores[0].2.failures), (3, 1));
        assert_eq!(scores[1].2.ewma_ms, 90.0);
    }

    #[test]
    fn ip_scores_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheManager::load(dir.path().join("state.json")).unwrap();
        for i in 0..1100u32 {
            let ip = format!("10.0.{}.{}", i / 250, i % 250);
            cache.put_ip_score("example.com", ip.parse().unwrap(), 100.0, 1, 0);
        }
        assert!(cache.ip_scores().len() <= 1024, "cap must hold");
    }

    #[test]
    fn last_good_is_pruned_by_age_and_count() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheManager::load(dir.path().join("state.json")).unwrap();

        // An entry older than the widest freshness window cannot be used by any
        // config (last_good_days caps at 30): it must not survive the next write.
        let mut ancient = sample_entry("old.example.com", "203.0.113.1");
        ancient.saved_at = now() - chrono::Duration::days(40);
        cache.put_last_good(ancient);
        assert!(cache.last_good("old.example.com", 30).is_none());

        for i in 0..520u32 {
            let domain = format!("site{i}.example.com");
            let ip = format!("10.0.{}.{}", i / 250, i % 250);
            cache.put_last_good(sample_entry(&domain, &ip));
        }
        assert!(cache.last_good_hosts().len() <= 512, "count cap must hold");
        assert!(
            cache.last_good("old.example.com", 30).is_none(),
            "ancient entry pruned"
        );
    }

    fn sample_entry(domain: &str, ip: &str) -> LastGoodEntry {
        LastGoodEntry {
            domain: domain.into(),
            ip: ip.parse().unwrap(),
            source: IpSource::Remote,
            network_id: "ip:test".into(),
            saved_at: now(),
            catalog_version: 1,
        }
    }

    #[test]
    fn persistence_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        {
            let cache = CacheManager::load(&path).unwrap();
            cache.mark_skip_once(["example.com"]);
            cache.put_sni(CachedSni {
                group: "g".into(),
                domain: "example.com".into(),
                network_id: "net".into(),
                sni: Some("www.baidu.com".into()),
                saved_at: now(),
            });
            // Writes are deferred; flush them like the runtime does on exit.
            cache.flush_if_dirty();
        }
        let cache = CacheManager::load(&path).unwrap();
        assert!(cache.has_skip_once("example.com"));
        assert_eq!(
            cache.sni("g", "example.com", "net").unwrap().sni.as_deref(),
            Some("www.baidu.com")
        );
    }

    /// The two writes a successful connection does to the cache.
    #[tokio::test]
    #[ignore = "micro benchmark"]
    async fn bench_cache_writes() {
        let (_dir, cache) = manager();
        let cache = Arc::new(cache);
        // The runtime writes the cache in the background; without the flusher
        // every write would serialize and fsync the whole file.
        cache.start_auto_flush(std::time::Duration::from_secs(5));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        crate::bench::measure("cache.record_outcome", 20_000, || {
            cache.record_outcome(
                Some(sample_entry("example.com", "203.0.113.7")),
                Some(IpScoreUpdate {
                    domain: "example.com",
                    ip,
                    ewma_ms: 100.0,
                    successes: 1,
                    failures: 0,
                }),
            );
        });
    }

    /// The same writes without a background flusher, which is how the one-shot
    /// commands run.  The write must still not touch the disk.
    #[test]
    #[ignore = "micro benchmark"]
    fn bench_cache_writes_without_flusher() {
        let (_dir, cache) = manager();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        crate::bench::measure("cache.write (no flusher)", 20_000, || {
            cache.record_outcome(
                Some(sample_entry("example.com", "203.0.113.7")),
                Some(IpScoreUpdate {
                    domain: "example.com",
                    ip,
                    ewma_ms: 100.0,
                    successes: 1,
                    failures: 0,
                }),
            );
        });
    }
}
