//! Download mirror list: the sites come from a remote JSON, only the cache is local.
//!
//! Accelerators die often, so the list expires long before the binary does.
//! Three layers: remote, last good cache, one built-in mirror. A missing list
//! never turns a download into a direct connection.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::util::{atomic_write_json, read_json};

/// Last resort when neither the remote list nor the cache exist, in list order
pub const BUILTIN_MIRRORS: &[&str] = &["https://gh-proxy.com", "https://ghfast.top"];

fn builtin() -> Vec<String> {
    BUILTIN_MIRRORS
        .iter()
        .map(|mirror| (*mirror).to_string())
        .collect()
}

const MAX_MIRRORS: usize = 16;
const MAX_BYTES: usize = 64 * 1024;
/// How long a failing mirror is skipped
const COOLDOWN: Duration = Duration::from_secs(300);

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct MirrorListFile {
    /// The other remote catalogs all spell this `v`; the value is unused
    #[serde(rename = "v")]
    version: u32,
    mirrors: Vec<String>,
}

pub struct MirrorList {
    /// `None` keeps the list in memory only
    cache: Option<PathBuf>,
    mirrors: RwLock<Arc<Vec<String>>>,
    down: RwLock<HashMap<String, MirrorFailure>>,
}

#[derive(Clone, Copy)]
struct MirrorFailure {
    /// Consecutive failures since the last success
    failures: u32,
    /// Skip the mirror until then
    until: Instant,
}

impl MirrorFailure {
    /// Back off further on every repeat: a half-dead mirror that recovers just
    /// long enough to answer once should not cost a timeout every few minutes
    fn backoff(&self) -> Duration {
        match self.failures {
            0 | 1 => COOLDOWN,
            2 => COOLDOWN * 3,
            _ => COOLDOWN * 12,
        }
    }
}

impl MirrorList {
    pub fn load(cache: Option<PathBuf>) -> Self {
        let cached = cache
            .as_deref()
            .and_then(|path| read_json::<MirrorListFile>(path).ok())
            .map(|file| normalize(file.mirrors))
            .unwrap_or_default();
        let mirrors = if cached.is_empty() { builtin() } else { cached };
        Self {
            cache,
            mirrors: RwLock::new(Arc::new(mirrors)),
            down: RwLock::new(HashMap::new()),
        }
    }

    /// Every configured prefix, in list order, including the cooling ones
    pub fn all(&self) -> Vec<String> {
        self.mirrors.read().as_ref().clone()
    }

    /// Usable prefixes in list order, skipping the ones cooling down
    pub fn available(&self) -> Vec<String> {
        let now = Instant::now();
        let down = self.down.read();
        self.mirrors
            .read()
            .iter()
            .filter(|mirror| down.get(*mirror).is_none_or(|state| now >= state.until))
            .cloned()
            .collect()
    }

    /// Records a failure and extends the skip window for that mirror
    pub fn cool_down(&self, mirror: &str) {
        let mut down = self.down.write();
        let failures = down
            .get(mirror)
            .map_or(1, |state| state.failures.saturating_add(1));
        let mut state = MirrorFailure {
            failures,
            until: Instant::now(),
        };
        state.until += state.backoff();
        down.insert(mirror.to_string(), state);
    }

    /// A success wipes the failure count so the next outage starts over
    pub fn note_success(&self, mirror: &str) {
        self.down.write().remove(mirror);
    }

    /// Fetch the remote list and persist it. An empty source means mirrors are off.
    pub async fn refresh(&self, source: &str) -> Result<usize> {
        let source = source.trim();
        if source.is_empty() {
            bail!("no mirror list source configured");
        }
        let client = reqwest::Client::builder()
            .user_agent(format!("hakimi/{}", crate::VERSION))
            // the list must not loop back through our own system proxy
            .no_proxy()
            .build()
            .context("building mirror list HTTP client")?;
        let response = client
            .get(source)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|error| anyhow::anyhow!("fetching mirror list: {}", error.without_url()))?;
        if !response.status().is_success() {
            bail!("mirror list returned HTTP {}", response.status());
        }
        let bytes = crate::catalog::read_limited_body(response, MAX_BYTES, "mirror list").await?;
        let file: MirrorListFile = serde_json::from_slice(&bytes).context("parsing mirror list")?;
        let mirrors = normalize(file.mirrors);
        if mirrors.is_empty() {
            // an empty list counts as a failure so the previous view survives
            bail!("mirror list contains no usable prefix");
        }
        if let Some(path) = &self.cache {
            let file = MirrorListFile {
                version: 1,
                mirrors: mirrors.clone(),
            };
            atomic_write_json(path, &file).context("writing mirror list cache")?;
        }
        let count = mirrors.len();
        *self.mirrors.write() = Arc::new(mirrors);
        self.down.write().clear();
        Ok(count)
    }
}

fn normalize(entries: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for entry in entries {
        let Some(prefix) = normalize_prefix(&entry) else {
            continue;
        };
        if !out.contains(&prefix) {
            out.push(prefix);
        }
        if out.len() == MAX_MIRRORS {
            break;
        }
    }
    out
}

/// A prefix is a bare http(s) origin; a rewrite appends `/{original url}`
fn normalize_prefix(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let url = url::Url::parse(trimmed).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::{normalize, normalize_prefix, MirrorList, BUILTIN_MIRRORS};

    #[test]
    fn prefixes_must_be_absolute_http_urls() {
        assert_eq!(
            normalize_prefix("https://gh-proxy.com/").as_deref(),
            Some("https://gh-proxy.com")
        );
        assert!(normalize_prefix("gh-proxy.com").is_none());
        assert!(normalize_prefix("ftp://gh-proxy.com").is_none());
        assert!(normalize_prefix("  ").is_none());
    }

    #[test]
    fn list_is_deduped_and_order_preserved() {
        let list = normalize(vec![
            "https://a.example".into(),
            "https://a.example/".into(),
            "junk".into(),
            "https://b.example".into(),
        ]);
        assert_eq!(list, vec!["https://a.example", "https://b.example"]);
    }

    #[test]
    fn empty_cache_falls_back_to_builtin_then_cools_down() {
        let mirrors = MirrorList::load(None);
        let available = mirrors.available();
        assert_eq!(available.len(), BUILTIN_MIRRORS.len());
        assert_eq!(available[0], BUILTIN_MIRRORS[0]);
        for mirror in available {
            mirrors.cool_down(&mirror);
        }
        assert!(
            mirrors.available().is_empty(),
            "a mirror cooling down takes no part in rewrites"
        );
    }
}
