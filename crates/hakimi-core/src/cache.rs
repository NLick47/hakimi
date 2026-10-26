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
use crate::util::{atomic_write_private, now, read_json};

const MAX_STALE_AGE_DAYS: i64 = 7;
const MAX_SNI_AGE_DAYS: i64 = 30;
/// Bump when the shape or meaning of the routes file changes. Unknown versions
/// are discarded instead of being guessed at: the file only holds hints.
const ROUTES_SCHEMA_VERSION: u32 = 1;
/// Fake-SNI choices live in their own file: losing them costs a full SNI sweep
/// per group, domain and network after every restart.
const FAKE_SNI_FILE: &str = "fake-sni.json";
const SNI_SCHEMA_VERSION: u32 = 1;
/// The routes file is a cold-start hint, not a history of every visited host.
/// 128 recent entries keep it small while still covering the active set.
const MAX_LAST_GOOD: usize = 128;
const LAST_GOOD_PRUNE_TO: usize = MAX_LAST_GOOD * 3 / 4;
const MAX_LAST_GOOD_AGE_DAYS: i64 = 30;

/// How often a dirty routes file is checkpointed while the process is running.
/// The final write still happens on shutdown; this only bounds what a crash can
/// lose. The file is tiny, so a five-minute cadence is cheap and avoids the old
/// five-second full-cache fsync cycle.
pub const CHECKPOINT_INTERVAL: StdDuration = StdDuration::from_secs(5 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastGoodEntry {
    pub domain: String,
    pub ip: IpAddr,
    pub source: IpSource,
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
    pub ech_config: Vec<u8>,
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

/// Resolved addresses, one A and one AAAA entry per domain. These maps grow
/// with every visited domain, so they stay bounded and in memory. An evicted
/// answer is simply looked up again; none of it is part of the routes file.
const MAX_DOH_ANSWERS: usize = 1024;
const DOH_PRUNE_TO: usize = MAX_DOH_ANSWERS * 3 / 4;
/// Negative DoH results: NODATA answers and total endpoint failures. Runtime
/// only; a domain that starts answering is re-queried after the TTL anyway.
const MAX_DOH_NEGATIVE: usize = 512;
const DOH_NEGATIVE_PRUNE_TO: usize = MAX_DOH_NEGATIVE * 3 / 4;
/// ECH configurations. One per domain, and only for the groups that use ECH.
const MAX_ECH_CONFIGS: usize = 256;
const ECH_PRUNE_TO: usize = MAX_ECH_CONFIGS * 3 / 4;
/// Remembered fake SNI names, one per group, domain and network.
const MAX_FAKE_SNI: usize = 256;
const SNI_PRUNE_TO: usize = MAX_FAKE_SNI * 3 / 4;
/// Domains waiting for a re-plan after a catalog update. A huge catalog
/// update can name thousands of domains; the flags are consumed by the next
/// connection to each domain.
const MAX_SKIP_ONCE: usize = 4096;

#[derive(Debug, Default)]
struct CacheData {
    last_good: HashMap<String, LastGoodEntry>,
    skip_once: HashSet<String>,
    doh: HashMap<String, CachedAnswer>,
    doh_negative: HashMap<String, CachedNegative>,
    ech: HashMap<String, CachedEch>,
    sni: HashMap<String, CachedSni>,
}

/// A remembered "this query has no useful answer". NODATA entries trust the
/// DNS TTL; total endpoint failures only back off for a short window.
#[derive(Debug, Clone)]
struct CachedNegative {
    ttl_secs: u32,
    fetched_at: DateTime<Utc>,
}

impl CachedNegative {
    fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        if self.ttl_secs == 0 {
            return false;
        }
        let age = now.signed_duration_since(self.fetched_at).num_seconds();
        age >= 0 && age < self.ttl_secs as i64
    }
}

/// The only data that survives a restart: a small set of last working routes.
/// The key is the domain, so the entry itself does not repeat it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedLastGood {
    ip: IpAddr,
    source: IpSource,
    saved_at: DateTime<Utc>,
    catalog_version: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedRoutes {
    schema_version: u32,
    saved_at: DateTime<Utc>,
    #[serde(default)]
    last_good: HashMap<String, PersistedLastGood>,
}

/// Fake-SNI choices, kept apart from the routes file so a broken copy cannot
/// cost the remembered routes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedSni {
    schema_version: u32,
    saved_at: DateTime<Utc>,
    #[serde(default)]
    entries: Vec<CachedSni>,
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

/// Runtime hint cache plus two tiny persisted files.
///
/// DoH answers, ECH configs and one-shot flags live only for this process.
/// The routes file holds `last_good` (128 rows), the fake-SNI file holds the
/// SNI choices, and both are written on shutdown plus a five-minute dirty
/// checkpoint.
pub struct CacheManager {
    path: PathBuf,
    sni_path: PathBuf,
    data: RwLock<CacheData>,
    /// True only when `last_good` changed. Runtime-only caches never set it.
    routes_dirty: AtomicBool,
    /// True only when a fake-SNI choice changed, which is far rarer.
    sni_dirty: AtomicBool,
    /// Serializes the snapshot/write cycle. The background checkpoint and the
    /// shutdown flush can overlap; without this, an older snapshot could rename
    /// itself over a newer one.
    flush_lock: Mutex<()>,
    /// Stop handle for the one background checkpoint task. Keeping it here
    /// makes `start_auto_flush` idempotent and lets the runtime cancel the task
    /// on stop instead of leaving a flusher behind for a stopped runtime.
    auto_flush_stop: Mutex<Option<tokio::sync::watch::Sender<()>>>,
}

impl CacheManager {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let sni_path = path.with_file_name(FAKE_SNI_FILE);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut data = match read_json::<PersistedRoutes>(&path) {
            Ok(routes) if routes.schema_version == ROUTES_SCHEMA_VERSION => {
                tracing::debug!(
                    path = %path.display(),
                    saved_at = %routes.saved_at,
                    entries = routes.last_good.len(),
                    "loaded remembered routes"
                );
                Self::from_persisted(routes)
            }
            Ok(routes) => {
                tracing::warn!(
                    path = %path.display(),
                    schema = routes.schema_version,
                    expected = ROUTES_SCHEMA_VERSION,
                    "routes file has an unknown schema; starting empty"
                );
                Self::quarantine(&path);
                CacheData::default()
            }
            Err(error) if path.exists() => {
                tracing::warn!(
                    path = %path.display(),
                    error = %format!("{error:#}"),
                    "routes file is unreadable; starting empty"
                );
                Self::quarantine(&path);
                CacheData::default()
            }
            Err(_) => CacheData::default(),
        };
        data.sni = Self::load_sni(&sni_path);
        let now = now();
        Self::expire(&mut data, now);
        Self::prune_last_good(&mut data);
        Ok(Self {
            path,
            sni_path,
            data: RwLock::new(data),
            routes_dirty: AtomicBool::new(false),
            sni_dirty: AtomicBool::new(false),
            flush_lock: Mutex::new(()),
            auto_flush_stop: Mutex::new(None),
        })
    }

    fn from_persisted(routes: PersistedRoutes) -> CacheData {
        CacheData {
            last_good: routes
                .last_good
                .into_iter()
                .filter(|(domain, _)| !domain.is_empty())
                .map(|(domain, entry)| {
                    (
                        domain.clone(),
                        LastGoodEntry {
                            domain,
                            ip: entry.ip,
                            source: entry.source,
                            saved_at: entry.saved_at,
                            catalog_version: entry.catalog_version,
                        },
                    )
                })
                .collect(),
            ..CacheData::default()
        }
    }

    /// Fake-SNI choices are optional: a broken copy only costs a new sweep, so
    /// this never fails the load and never touches the routes file.
    fn load_sni(path: &Path) -> HashMap<String, CachedSni> {
        let entries = match read_json::<PersistedSni>(path) {
            Ok(sni) if sni.schema_version == SNI_SCHEMA_VERSION => sni.entries,
            Ok(sni) => {
                tracing::warn!(
                    path = %path.display(),
                    schema = sni.schema_version,
                    expected = SNI_SCHEMA_VERSION,
                    "fake-sni file has an unknown schema; starting empty"
                );
                Self::quarantine(path);
                return HashMap::new();
            }
            Err(error) if path.exists() => {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "fake-sni file is unreadable; starting empty"
                );
                Self::quarantine(path);
                return HashMap::new();
            }
            Err(_) => return HashMap::new(),
        };
        let mut loaded: HashMap<String, CachedSni> = entries
            .into_iter()
            .filter(|entry| !entry.domain.is_empty())
            .map(|entry| {
                (
                    sni_key(&entry.group, &entry.domain, &entry.network_id),
                    entry,
                )
            })
            .collect();
        // A hand-edited or old file may hold more rows than the runtime allows.
        Self::prune_by_age(&mut loaded, MAX_FAKE_SNI, SNI_PRUNE_TO, |entry| {
            entry.saved_at
        });
        loaded
    }

    /// Keep a broken routes file for diagnosis but never let it block startup.
    fn quarantine(path: &Path) {
        let corrupt = path.with_extension("corrupt.json");
        let _ = std::fs::remove_file(&corrupt);
        if let Err(error) = std::fs::rename(path, &corrupt) {
            tracing::warn!(
                path = %path.display(),
                error = %format!("{error:#}"),
                "failed to quarantine an unreadable routes file"
            );
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write both files immediately. The dirty flags are left alone: a
    /// mutation may have happened after the snapshot and must still reach the
    /// next checkpoint.
    pub fn save(&self) -> Result<()> {
        let _guard = self.flush_lock.lock();
        self.write_snapshot()?;
        self.write_sni_snapshot()
    }

    /// The request path only flips a flag. A checkpoint every
    /// [`CHECKPOINT_INTERVAL`] and the final shutdown flush do the disk work.
    fn mark_routes_dirty(&self) {
        self.routes_dirty.store(true, Ordering::SeqCst);
    }

    fn mark_sni_dirty(&self) {
        self.sni_dirty.store(true, Ordering::SeqCst);
    }

    /// Encode and write the last-good routes. The snapshot is taken under a
    /// read lock, then encoded and written outside every data lock so a slow
    /// disk never blocks lookups.
    fn write_snapshot(&self) -> Result<()> {
        let snapshot = {
            let data = self.data.read();
            PersistedRoutes {
                schema_version: ROUTES_SCHEMA_VERSION,
                saved_at: now(),
                last_good: data
                    .last_good
                    .iter()
                    .map(|(domain, entry)| {
                        (
                            domain.clone(),
                            PersistedLastGood {
                                ip: entry.ip,
                                source: entry.source,
                                saved_at: entry.saved_at,
                                catalog_version: entry.catalog_version,
                            },
                        )
                    })
                    .collect(),
            }
        };
        let bytes = serde_json::to_vec(&snapshot)?;
        atomic_write_private(&self.path, &bytes)
    }

    /// Fake-SNI choices are tiny and change rarely, but losing them costs a
    /// fresh sweep of TLS handshakes per domain after a restart.
    fn write_sni_snapshot(&self) -> Result<()> {
        let snapshot = {
            let data = self.data.read();
            PersistedSni {
                schema_version: SNI_SCHEMA_VERSION,
                saved_at: now(),
                entries: data.sni.values().cloned().collect(),
            }
        };
        let bytes = serde_json::to_vec(&snapshot)?;
        atomic_write_private(&self.sni_path, &bytes)
    }

    /// Write whichever files changed since the last flush.
    ///
    /// Returns true when a write was attempted, including a failed one: the
    /// dirty flag stays set so the next checkpoint retries.
    ///
    /// The flush lock covers the snapshot and the rename, so the background
    /// checkpoint and the shutdown flush can never write out of order.
    pub fn flush_if_dirty(&self) -> bool {
        let _guard = self.flush_lock.lock();
        let routes = self.routes_dirty.swap(false, Ordering::SeqCst);
        let sni = self.sni_dirty.swap(false, Ordering::SeqCst);
        if !routes && !sni {
            return false;
        }
        // Expire under the write lock, then encode under the read lock.
        {
            let mut data = self.data.write();
            Self::expire(&mut data, now());
            Self::prune_last_good(&mut data);
        }
        if routes {
            if let Err(error) = self.write_snapshot() {
                tracing::warn!(error = %error, "failed to persist remembered routes");
                // Keep the flag: the next checkpoint retries instead of
                // dropping the change on the floor.
                self.routes_dirty.store(true, Ordering::SeqCst);
            }
        }
        if sni {
            if let Err(error) = self.write_sni_snapshot() {
                tracing::warn!(error = %error, "failed to persist fake-sni choices");
                self.sni_dirty.store(true, Ordering::SeqCst);
            }
        }
        true
    }

    /// Start the background checkpoint. The file holds only a small routes
    /// list, and writes happen only when it changed, so a five-minute cadence
    /// is enough to bound crash loss without touching the request path.
    ///
    /// Starting twice is a no-op: the runtime may start, stop and start again,
    /// and each cache must never accumulate a second checkpoint task.
    pub fn start_auto_flush(self: &Arc<Self>, interval: StdDuration) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::debug!("no tokio runtime available; routes are written on shutdown");
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
                        // Serializing and fsyncing must stay off the async workers.
                        let manager = manager.clone();
                        let _ = tokio::task::spawn_blocking(move || manager.flush_if_dirty()).await;
                    }
                }
            }
        });
    }

    /// Stop the background checkpoint, if one is running. Safe to call
    /// repeatedly and from `HakimiRuntime::stop`/`Drop`. The caller still does
    /// a final `flush_if_dirty`; `flush_lock` waits for any in-flight write.
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
        // The routes and SNI maps reach disk; the rest are runtime hints, so
        // aged entries are dropped here to keep a long session bounded.
        data.last_good.retain(|_, entry| {
            now.signed_duration_since(entry.saved_at) <= Duration::days(MAX_LAST_GOOD_AGE_DAYS)
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
    /// needs the IP and strategy; avoid cloning the domain string.
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

    /// Update the remembered route and schedule a checkpoint.
    pub fn put_last_good(&self, entry: LastGoodEntry) {
        // The steady state is the same route on every connection; settle that
        // under a read lock so concurrent dials do not queue on the writer.
        if Self::route_is_fresh(&self.data.read(), &entry, now()) {
            return;
        }
        let mut data = self.data.write();
        let timestamp = now();
        if Self::route_is_fresh(&data, &entry, timestamp) {
            return;
        }
        data.last_good.insert(entry.domain.clone(), entry);
        if data.last_good.len() > MAX_LAST_GOOD {
            Self::prune_last_good(&mut data);
        }
        self.mark_routes_dirty();
    }

    fn route_is_fresh(data: &CacheData, entry: &LastGoodEntry, timestamp: DateTime<Utc>) -> bool {
        data.last_good.get(&entry.domain).is_some_and(|existing| {
            existing.ip == entry.ip
                && existing.source == entry.source
                && existing.catalog_version == entry.catalog_version
                && timestamp.signed_duration_since(existing.saved_at) < Duration::seconds(60)
        })
    }

    /// Drop remembered routes that no freshness setting can use anymore, and cap
    /// the map so a long session cannot grow the routes file forever.
    fn prune_last_good(data: &mut CacheData) {
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

    pub fn remove_last_good(&self, domain: &str) {
        let mut data = self.data.write();
        if data.last_good.remove(domain).is_some() {
            self.mark_routes_dirty();
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
        for domain in domains {
            data.skip_once.insert(domain.into());
        }
        // A huge catalog update can name more domains than the flags are
        // worth; the set is a hint that the old route should be re-planned.
        if data.skip_once.len() > MAX_SKIP_ONCE {
            data.skip_once.clear();
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
        data.skip_once.remove(domain)
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
    }

    /// True while a fresh negative result for this domain/qtype exists.
    pub fn doh_negative(&self, domain: &str, qtype: u16) -> bool {
        let now = now();
        self.data
            .read()
            .doh_negative
            .get(&doh_key(domain, qtype))
            .is_some_and(|entry| entry.is_fresh(now))
    }

    pub fn put_doh_negative(&self, domain: &str, qtype: u16, ttl_secs: u32) {
        if ttl_secs == 0 {
            return;
        }
        let mut data = self.data.write();
        data.doh_negative.insert(
            doh_key(domain, qtype),
            CachedNegative {
                ttl_secs,
                fetched_at: now(),
            },
        );
        Self::prune_by_age(
            &mut data.doh_negative,
            MAX_DOH_NEGATIVE,
            DOH_NEGATIVE_PRUNE_TO,
            |entry| entry.fetched_at,
        );
    }

    pub fn clear_doh_negative(&self, domain: &str, qtype: u16) {
        self.data.write().doh_negative.remove(&doh_key(domain, qtype));
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
        self.mark_sni_dirty();
    }

    pub fn remove_sni(&self, group: &str, domain: &str, network_id: &str) {
        let mut data = self.data.write();
        if data
            .sni
            .remove(&sni_key(group, domain, network_id))
            .is_some()
        {
            self.mark_sni_dirty();
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
        self.mark_routes_dirty();
        self.mark_sni_dirty();
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
    fn last_good_roundtrip_and_expiry() {
        let (_dir, cache) = manager();
        cache.put_last_good(LastGoodEntry {
            domain: "github.com".into(),
            ip: "20.205.243.166".parse().unwrap(),
            source: IpSource::Remote,
            saved_at: now() - Duration::days(8),
            catalog_version: 3,
        });
        assert!(cache.last_good("github.com", 7).is_none());
        cache.put_last_good(LastGoodEntry {
            domain: "github.com".into(),
            ip: "20.205.243.166".parse().unwrap(),
            source: IpSource::Remote,
            saved_at: now() - Duration::days(2),
            catalog_version: 3,
        });
        let entry = cache.last_good("github.com", 7).unwrap();
        assert_eq!(entry.ip.to_string(), "20.205.243.166");
    }

    #[test]
    fn put_last_good_keeps_the_freshness_rule() {
        let (_dir, cache) = manager();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let entry = sample_entry("example.com", "203.0.113.5");
        let saved_at = entry.saved_at;

        cache.put_last_good(entry);
        let stored = cache.last_good("example.com", 7).unwrap();
        assert_eq!(stored.ip, ip);
        assert_eq!(stored.saved_at, saved_at);

        // The same route within 60 seconds keeps the original timestamp so a
        // busy domain does not churn the file.
        let mut again = sample_entry("example.com", "203.0.113.5");
        again.saved_at = now();
        cache.put_last_good(again);
        let stored = cache.last_good("example.com", 7).unwrap();
        assert_eq!(
            stored.saved_at, saved_at,
            "a fresh repeat must not restart the freshness window"
        );
    }

    /// The maps that grow with the number of visited domains stay bounded, and
    /// none of them may reach the routes file. 5000 resolved domains used to
    /// mean 2.4 MB of cache and an 83 ms flush.
    #[test]
    fn runtime_only_maps_stay_bounded_and_off_disk() {
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
        }
        cache.mark_skip_once((0..5000u32).map(|index| format!("host{index}.example.com")));
        cache.put_last_good(sample_entry("github.com", "20.205.243.166"));
        assert!(cache.flush_if_dirty());

        let bytes = std::fs::read(cache.path()).unwrap();
        let routes: PersistedRoutes = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            routes.last_good.len(),
            1,
            "only remembered routes belong in the file"
        );
        assert!(routes.last_good.contains_key("github.com"));
        assert!(
            bytes.len() < 4096,
            "the routes file must stay tiny, got {} bytes",
            bytes.len()
        );
        assert!(
            !cache.sni_path.exists(),
            "DoH and ECH traffic must not create a fake-sni file"
        );

        // The newest entries survive, the oldest are dropped.
        assert!(cache.doh_answer("host4999.example.com", 1).is_some());
        assert!(cache.doh_answer("host0.example.com", 1).is_none());
        assert!(cache.ech("host4999.example.com", false).is_some());
    }

    /// Fake-SNI choices have their own dirty flag and file: a learned SNI is
    /// written without a route change, and the file stays bounded.
    #[test]
    fn fake_sni_choices_survive_a_reload_and_stay_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        {
            let cache = CacheManager::load(&path).unwrap();
            for index in 0..5000u32 {
                cache.put_sni(CachedSni {
                    group: "g".into(),
                    domain: format!("host{index}.example.com"),
                    network_id: "net".into(),
                    sni: Some("www.baidu.com".into()),
                    saved_at: now(),
                });
            }
            assert!(cache.flush_if_dirty(), "a learned SNI is a change");
            assert!(
                !path.exists(),
                "a fake-SNI flush must not create the routes file"
            );
            assert!(cache.sni_path.metadata().unwrap().len() < 64 * 1024);
        }

        let cache = CacheManager::load(&path).unwrap();
        let newest = cache.sni("g", "host4999.example.com", "net").unwrap();
        assert_eq!(newest.sni.as_deref(), Some("www.baidu.com"));
        assert!(cache.sni("g", "host0.example.com", "net").is_none());
    }

    /// An aged choice cannot be used: the freshness window is the same on load
    /// as it is in memory, so a stale sweep result is not replayed forever.
    #[test]
    fn aged_fake_sni_choices_are_dropped_on_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        {
            let cache = CacheManager::load(&path).unwrap();
            cache.put_sni(CachedSni {
                group: "g".into(),
                domain: "example.com".into(),
                network_id: "net".into(),
                sni: Some("www.baidu.com".into()),
                saved_at: now() - Duration::days(MAX_SNI_AGE_DAYS + 1),
            });
            assert!(cache.flush_if_dirty());
        }
        let cache = CacheManager::load(&path).unwrap();
        assert!(cache.sni("g", "example.com", "net").is_none());
    }

    /// The fake-SNI file is optional: a broken copy must not cost the routes.
    #[test]
    fn a_broken_fake_sni_file_only_costs_the_sni_choices() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        {
            let cache = CacheManager::load(&path).unwrap();
            cache.put_last_good(sample_entry("github.com", "20.205.243.166"));
            cache.put_sni(CachedSni {
                group: "g".into(),
                domain: "github.com".into(),
                network_id: "net".into(),
                sni: Some("www.baidu.com".into()),
                saved_at: now(),
            });
            assert!(cache.flush_if_dirty());
        }
        std::fs::write(dir.path().join(FAKE_SNI_FILE), b"{not json").unwrap();

        let cache = CacheManager::load(&path).unwrap();
        assert!(cache.last_good("github.com", 30).is_some());
        assert!(cache.sni("g", "github.com", "net").is_none());
        assert!(dir.path().join("fake-sni.corrupt.json").exists());
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
        cache.put_last_good(sample_entry("example.com", "203.0.113.9"));
        assert!(cache.flush_if_dirty(), "the first flush attempts the write");
        assert!(
            cache.flush_if_dirty(),
            "a failed write has to stay scheduled for the next flush"
        );
    }

    #[tokio::test]
    async fn an_unchanged_route_does_not_schedule_a_flush() {
        let dir = tempfile::tempdir().unwrap();
        let cache = std::sync::Arc::new(CacheManager::load(dir.path().join("state.json")).unwrap());
        // The background flusher has to be running, otherwise every write is
        // persisted eagerly and the dirty flag never shows up.
        cache.start_auto_flush(StdDuration::from_secs(3600));
        let entry = sample_entry("example.com", "203.0.113.6");
        cache.put_last_good(entry.clone());
        assert!(cache.flush_if_dirty(), "the first outcome is a change");

        // The same route within the freshness window changes nothing.
        cache.put_last_good(entry);
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
    fn last_good_is_pruned_by_age_and_count() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheManager::load(dir.path().join("state.json")).unwrap();

        // An entry older than the widest freshness window cannot be used by any
        // config (last_good_days caps at 30): it must not survive the next write.
        let mut ancient = sample_entry("old.example.com", "203.0.113.1");
        ancient.saved_at = now() - chrono::Duration::days(40);
        cache.put_last_good(ancient);
        assert!(cache.last_good("old.example.com", 30).is_none());

        for i in 0..(MAX_LAST_GOOD as u32 + 20) {
            let domain = format!("site{i}.example.com");
            let ip = format!("10.0.{}.{}", i / 250, i % 250);
            cache.put_last_good(sample_entry(&domain, &ip));
        }
        assert!(
            cache.last_good_hosts().len() <= MAX_LAST_GOOD,
            "count cap must hold"
        );
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
            saved_at: now(),
            catalog_version: 1,
        }
    }

    /// A restart costs a DoH lookup and one ECH fetch; routes and fake-SNI
    /// choices are kept, one-shot flags are not.
    #[test]
    fn routes_survive_a_reload_but_one_shot_flags_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        {
            let cache = CacheManager::load(&path).unwrap();
            cache.mark_skip_once(["example.com"]);
            cache.put_doh_answer(CachedAnswer {
                domain: "example.com".into(),
                qtype: 1,
                ips: vec!["1.1.1.1".parse().unwrap()],
                hints: vec![],
                ech_config: None,
                ttl_secs: 300,
                fetched_at: now(),
            });
            cache.put_last_good(sample_entry("github.com", "20.205.243.166"));
            // Writes are deferred; flush them like the runtime does on exit.
            assert!(cache.flush_if_dirty());
        }
        let cache = CacheManager::load(&path).unwrap();
        let entry = cache.last_good("github.com", 30).unwrap();
        assert_eq!(entry.ip.to_string(), "20.205.243.166");
        assert!(!cache.has_skip_once("example.com"));
        assert!(cache.doh_answer("example.com", 1).is_none());
    }

    /// A file written by an older build holds a different shape. It must be
    /// moved aside instead of being half-read into the new maps.
    #[test]
    fn an_unusable_file_is_quarantined_and_the_cache_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "lastGood": {
                    "github.com": {
                        "ip": "20.205.243.166",
                        "source": "remote",
                        "savedAt": now(),
                        "catalogVersion": 3
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let cache = CacheManager::load(&path).unwrap();
        assert!(cache.last_good("github.com", 30).is_none());
        assert!(!path.exists(), "the old file is moved aside");
        assert!(dir.path().join("state.corrupt.json").exists());

        // A future schema is handled the same way.
        std::fs::write(
            &path,
            serde_json::json!({
                "schemaVersion": ROUTES_SCHEMA_VERSION + 1,
                "savedAt": now(),
                "lastGood": {}
            })
            .to_string(),
        )
        .unwrap();
        let cache = CacheManager::load(&path).unwrap();
        assert!(cache.last_good("github.com", 30).is_none());
        assert!(!path.exists());
    }

    #[test]
    fn expire_drops_aged_routes() {
        let now = now();
        let mut data = CacheData::default();
        let mut old_route = sample_entry("old.example", "203.0.113.1");
        old_route.saved_at = now - chrono::Duration::days(MAX_LAST_GOOD_AGE_DAYS + 1);
        data.last_good.insert(old_route.domain.clone(), old_route);
        data.last_good.insert(
            "fresh.example".into(),
            sample_entry("fresh.example", "203.0.113.2"),
        );

        CacheManager::expire(&mut data, now);

        assert!(!data.last_good.contains_key("old.example"));
        assert!(data.last_good.contains_key("fresh.example"));
    }

    /// A remembered-route write with the runtime checkpoint running.
    #[tokio::test]
    #[ignore = "micro benchmark"]
    async fn bench_cache_writes() {
        let (_dir, cache) = manager();
        let cache = Arc::new(cache);
        cache.start_auto_flush(CHECKPOINT_INTERVAL);
        crate::bench::measure("cache.put_last_good", 20_000, || {
            cache.put_last_good(sample_entry("example.com", "203.0.113.7"));
        });
    }

    /// The same write without a checkpoint, which is how one-shot commands run.
    #[test]
    #[ignore = "micro benchmark"]
    fn bench_cache_writes_without_flusher() {
        let (_dir, cache) = manager();
        crate::bench::measure("cache.put_last_good (no flusher)", 20_000, || {
            cache.put_last_good(sample_entry("example.com", "203.0.113.7"));
        });
    }
}
