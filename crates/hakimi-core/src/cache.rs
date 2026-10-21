use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::strategy::{IpSource, Strategy};
use crate::util::{atomic_write, atomic_write_json, now, read_json};

const MAX_STALE_AGE_DAYS: i64 = 7;
const MAX_SNI_AGE_DAYS: i64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastGoodEntry {
    pub domain: String,
    pub ip: IpAddr,
    pub strategy: Strategy,
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
    auto_flush: AtomicBool,
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
            auto_flush: AtomicBool::new(false),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self) -> Result<()> {
        let data = self.data.read();
        atomic_write_json(&self.path, &*data)
    }

    fn persist_locked(&self, data: &CacheData) {
        if let Err(error) = atomic_write_json(&self.path, data) {
            tracing::warn!(error = %error, "failed to persist cache");
        }
    }

    /// Record a cache mutation. With the background flusher running this only flips a flag,
    /// so request handling never waits on disk; otherwise it keeps the eager write.
    fn mark_dirty(&self, data: &CacheData) {
        if self.auto_flush.load(Ordering::SeqCst) {
            self.dirty.store(true, Ordering::SeqCst);
        } else {
            self.persist_locked(data);
            self.dirty.store(false, Ordering::SeqCst);
        }
    }

    /// Write once if anything changed since the last flush. The JSON is encoded
    /// under a read lock and written outside every lock, so a slow disk never
    /// blocks lookups and nothing deep-clones the whole cache on the way out.
    pub fn flush_if_dirty(&self) -> bool {
        if !self.dirty.swap(false, Ordering::SeqCst) {
            return false;
        }
        let json = {
            let data = self.data.read();
            serde_json::to_string(&*data)
        };
        match json {
            Ok(json) => {
                if let Err(error) = atomic_write(&self.path, json.as_bytes()) {
                    tracing::warn!(error = %error, "failed to persist cache");
                }
            }
            Err(error) => tracing::warn!(error = %error, "failed to encode cache"),
        }
        true
    }

    /// Start the background flusher. Cache writes are hints, so a few seconds of latency is
    /// fine while the fsyncs move off the request path entirely.
    pub fn start_auto_flush(self: &Arc<Self>, interval: StdDuration) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::debug!("no tokio runtime available; cache writes stay synchronous");
            return;
        };
        self.auto_flush.store(true, Ordering::SeqCst);
        let manager = self.clone();
        handle.spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                manager.flush_if_dirty();
            }
        });
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

    /// Persisted quality entries, for seeding the decision engine on startup.
    /// Entries beyond the widest freshness window are dropped on the way in.
    pub fn ip_scores(&self) -> Vec<(String, IpAddr, IpScoreEntry)> {
        let now = now();
        let data = self.data.read();
        data.ip_scores
            .iter()
            .filter_map(|(key, entry)| {
                if now.signed_duration_since(entry.updated_at) > Duration::days(MAX_IP_SCORE_AGE_DAYS)
                {
                    return None;
                }
                let (domain, ip) = key.split_once('|')?;
                let ip = ip.parse().ok()?;
                Some((domain.to_string(), ip, entry.clone()))
            })
            .collect()
    }

    /// Upsert one quality entry. Keeps the map bounded: entries past the widest
    /// freshness window are dropped, then the oldest beyond the cap.
    pub fn put_ip_score(&self, domain: &str, ip: IpAddr, ewma_ms: f64, successes: u32, failures: u32) {
        let mut data = self.data.write();
        let now = now();
        let key = format!("{domain}|{ip}");
        data.ip_scores.insert(
            key,
            IpScoreEntry {
                ewma_ms,
                successes,
                failures,
                updated_at: now,
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
        let mut data = self.data.write();
        let timestamp = now();
        if let Some(existing) = data.last_good.get(&entry.domain) {
            if existing.ip == entry.ip
                && existing.strategy == entry.strategy
                && existing.source == entry.source
                && timestamp.signed_duration_since(existing.saved_at) < Duration::seconds(60)
            {
                return;
            }
        }
        data.last_good.insert(entry.domain.clone(), entry);
        // A read-time age check already ignores stale routes; only pay for the
        // full scan/sort when the map actually needs bounding.
        if data.last_good.len() > MAX_LAST_GOOD {
            self.prune_last_good(&mut data);
        }
        self.mark_dirty(&data);
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
        if changed {
            self.mark_dirty(&data);
        }
    }

    /// Consume the one-shot skip flag for a domain.
    pub fn take_skip_once(&self, domain: &str) -> bool {
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

    #[test]
    fn last_good_roundtrip_and_expiry() {
        let (_dir, cache) = manager();
        cache.put_last_good(LastGoodEntry {
            domain: "github.com".into(),
            ip: "20.205.243.166".parse().unwrap(),
            strategy: Strategy::Direct,
            source: IpSource::Remote,
            network_id: network_id(),
            saved_at: now() - Duration::days(8),
            catalog_version: 3,
        });
        assert!(cache.last_good("github.com", 7).is_none());
        cache.put_last_good(LastGoodEntry {
            domain: "github.com".into(),
            ip: "20.205.243.166".parse().unwrap(),
            strategy: Strategy::Direct,
            source: IpSource::Remote,
            network_id: network_id(),
            saved_at: now() - Duration::days(2),
            catalog_version: 3,
        });
        let entry = cache.last_good("github.com", 7).unwrap();
        assert_eq!(entry.ip.to_string(), "20.205.243.166");
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
            cache.save().unwrap();
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
        assert!(cache.last_good("old.example.com", 30).is_none(), "ancient entry pruned");
    }

    fn sample_entry(domain: &str, ip: &str) -> LastGoodEntry {
        LastGoodEntry {
            domain: domain.into(),
            ip: ip.parse().unwrap(),
            strategy: Strategy::Auto,
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
        }
        let cache = CacheManager::load(&path).unwrap();
        assert!(cache.has_skip_once("example.com"));
        assert_eq!(
            cache.sni("g", "example.com", "net").unwrap().sni.as_deref(),
            Some("www.baidu.com")
        );
    }
}
