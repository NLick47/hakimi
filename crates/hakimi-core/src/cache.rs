use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::strategy::{IpSource, Strategy};
use crate::util::{atomic_write_json, now, read_json};

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

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct CacheData {
    last_good: HashMap<String, LastGoodEntry>,
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
        self.persist_locked(&data);
    }

    pub fn remove_last_good(&self, domain: &str) {
        let mut data = self.data.write();
        if data.last_good.remove(domain).is_some() {
            self.persist_locked(&data);
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
            self.persist_locked(&data);
        }
    }

    /// Consume the one-shot skip flag for a domain.
    pub fn take_skip_once(&self, domain: &str) -> bool {
        let mut data = self.data.write();
        let removed = data.skip_once.remove(domain);
        if removed {
            self.persist_locked(&data);
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
        self.persist_locked(&data);
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
        self.persist_locked(&data);
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
        self.persist_locked(&data);
    }

    pub fn remove_sni(&self, group: &str, domain: &str, network_id: &str) {
        let mut data = self.data.write();
        if data
            .sni
            .remove(&sni_key(group, domain, network_id))
            .is_some()
        {
            self.persist_locked(&data);
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
        self.persist_locked(&data);
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
