use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::strategy::{CacheStatus, DohSource, FailureReason, IpSource, Strategy, TlsMode};
use crate::util::now;

/// Wildcard groups can observe an unbounded set of concrete hosts. Keep the
/// status map bounded so a crawler cannot turn the UI snapshot into a
/// multi-megabyte clone every second.
const MAX_STATUS_DOMAINS: usize = 4096;
/// Evict in bulk so crossing the cap does not sort the map on every insert.
const STATUS_PRUNE_TO: usize = MAX_STATUS_DOMAINS * 3 / 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Disabled,
    Paused,
    Checking,
    Normal,
    Direct,
    Degraded,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptRecord {
    pub strategy: TlsMode,
    pub ip: IpAddr,
    pub source: IpSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<FailureReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

/// Diagnostics record from section 10.3, with the attempt trace used by the local 502 page.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainDiagnostics {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub domain: String,
    pub state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<TlsMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_strategy: Option<Strategy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_source: Option<IpSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doh_source: Option<DohSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub last_check: DateTime<Utc>,
    pub catalog_version: u64,
    pub cache: CacheStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<FailureReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<AttemptRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<String>,
}

impl DomainDiagnostics {
    pub fn checking(
        group: Option<String>,
        domain: impl Into<String>,
        strategy: Option<Strategy>,
        catalog_version: u64,
    ) -> Self {
        Self {
            group,
            domain: domain.into(),
            state: State::Checking,
            strategy: None,
            configured_strategy: strategy,
            ip: None,
            ip_source: None,
            doh_source: None,
            latency_ms: None,
            last_check: now(),
            catalog_version,
            cache: CacheStatus::None,
            error: None,
            detail: None,
            attempts: Vec::new(),
            suggestions: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupStatus {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub experimental: bool,
    pub state: State,
    pub strategy: Strategy,
    pub primary_domain: Option<String>,
    pub primary_state: Option<State>,
    pub tested_domains: usize,
    pub failed_domains: usize,
    pub last_check: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusCounts {
    pub normal: usize,
    pub direct: usize,
    pub failed: usize,
    pub checking: usize,
    pub total: usize,
}

pub struct StatusStore {
    /// Values are shared so snapshots clone only an `Arc`, not every
    /// diagnostics record (including attempts/suggestions vectors).
    domains: RwLock<HashMap<String, Arc<DomainDiagnostics>>>,
    paused: AtomicBool,
    /// Bumped whenever a domain record or the pause flag changes. Pollers
    /// compare it to skip rebuilding a snapshot that cannot have changed.
    revision: AtomicU64,
    started_at: DateTime<Utc>,
}

impl Default for StatusStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusStore {
    pub fn new() -> Self {
        Self {
            domains: RwLock::new(HashMap::new()),
            paused: AtomicBool::new(false),
            revision: AtomicU64::new(0),
            started_at: now(),
        }
    }

    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// Monotonic change counter for the state exposed by [`Self::domains_snapshot`]
    /// and [`Self::paused`].
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    pub fn set_paused(&self, paused: bool) {
        if self.paused.swap(paused, Ordering::SeqCst) != paused {
            self.revision.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    pub fn get(&self, domain: &str) -> Option<Arc<DomainDiagnostics>> {
        self.domains.read().get(domain).cloned()
    }

    pub fn record(&self, diagnostics: DomainDiagnostics) {
        self.record_arc(Arc::new(diagnostics));
    }

    /// Record an already-shared diagnostics value. The decision engine returns
    /// the same allocation in its outcome, so storing it here does not require
    /// a deep clone of attempts/suggestions.
    pub(crate) fn record_arc(&self, diagnostics: Arc<DomainDiagnostics>) {
        let mut map = self.domains.write();
        let mut unchanged_checking = false;
        if let Some(existing) = map.get_mut(&diagnostics.domain) {
            // Never let a slower, older probe overwrite a newer result.
            if existing.last_check > diagnostics.last_check
                && existing.state != State::Checking
                && diagnostics.state == State::Checking
            {
                return;
            }
            // Re-marking an already-checking domain is the common cold-connect
            // path. It changes no visible state, so do not wake every UI poller.
            unchanged_checking =
                existing.state == State::Checking && diagnostics.state == State::Checking;
            // A state flip is the single most useful troubleshooting signal:
            // it tells whether a site just broke or just recovered, and when.
            // `Checking` is a transient marker, not a real transition — logging
            // it buries the Failed<->Normal lines that actually matter.
            if existing.state != diagnostics.state
                && existing.state != State::Checking
                && diagnostics.state != State::Checking
            {
                tracing::info!(
                    domain = %diagnostics.domain,
                    from = ?existing.state,
                    to = ?diagnostics.state,
                    latency_ms = diagnostics.latency_ms,
                    error = ?diagnostics.error,
                    "domain state changed"
                );
            }
            // Reuse the existing key: the common path is an update of a known
            // domain, so there is no reason to clone its name for the map.
            *existing = diagnostics;
        } else {
            map.insert(diagnostics.domain.clone(), diagnostics);
            if map.len() > MAX_STATUS_DOMAINS {
                prune_status_domains(&mut map);
            }
        }
        // The record is in the map now: publish the change to pollers. Doing
        // it after the write (and after the early return above) means a
        // revision bump always corresponds to a visible change. Re-marking an
        // already-checking domain is not a visible change.
        if !unchanged_checking {
            self.revision.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn mark_checking(
        &self,
        group: Option<&str>,
        domain: &str,
        strategy: Option<Strategy>,
        catalog_version: u64,
    ) {
        // A connection that succeeds and is followed immediately by another
        // connection (image hosts with HTTP/1.1, or a page's asset burst)
        // would otherwise flip Normal -> Checking -> Normal for every dial,
        // allocating a diagnostics record and waking every UI poller twice.
        // Keep a fresh real result visible instead of a transient marker.
        {
            let now = now();
            let domains = self.domains.read();
            if let Some(existing) = domains.get(domain) {
                let age = now.signed_duration_since(existing.last_check);
                if age < chrono::Duration::seconds(1)
                    && matches!(
                        existing.state,
                        State::Normal | State::Direct | State::Checking
                    )
                {
                    return;
                }
            }
        }
        self.record(DomainDiagnostics::checking(
            group.map(str::to_owned),
            domain,
            strategy,
            catalog_version,
        ));
    }

    pub fn domains_snapshot(&self) -> Vec<Arc<DomainDiagnostics>> {
        let mut values: Vec<Arc<DomainDiagnostics>> =
            self.domains.read().values().cloned().collect();
        values.sort_by(|a, b| a.domain.cmp(&b.domain));
        values
    }

    /// One pass for the two values the status JSON always needs together.
    /// Avoids a second read lock and a second full scan of the domain map.
    pub fn domains_snapshot_with_counts(&self) -> (Vec<Arc<DomainDiagnostics>>, StatusCounts) {
        let map = self.domains.read();
        let mut counts = StatusCounts {
            normal: 0,
            direct: 0,
            failed: 0,
            checking: 0,
            total: map.len(),
        };
        let mut values = Vec::with_capacity(map.len());
        for entry in map.values() {
            match entry.state {
                State::Normal => counts.normal += 1,
                State::Direct => counts.direct += 1,
                State::Failed => counts.failed += 1,
                State::Checking => counts.checking += 1,
                _ => {}
            }
            values.push(entry.clone());
        }
        values.sort_by(|a, b| a.domain.cmp(&b.domain));
        (values, counts)
    }

    /// The records of the given domains, sorted by name.
    ///
    /// The polled snapshot only needs the domains of the configured groups.
    /// Looking them up directly avoids copying and sorting every known
    /// domain, which dominated the poll once a session had seen thousands.
    pub fn domains_for(&self, wanted: &HashSet<&str>) -> Vec<Arc<DomainDiagnostics>> {
        let map = self.domains.read();
        let mut values: Vec<Arc<DomainDiagnostics>> = wanted
            .iter()
            .filter_map(|domain| map.get(*domain).cloned())
            .collect();
        values.sort_by(|a, b| a.domain.cmp(&b.domain));
        values
    }

    pub fn counts(&self) -> StatusCounts {
        let map = self.domains.read();
        let mut counts = StatusCounts {
            normal: 0,
            direct: 0,
            failed: 0,
            checking: 0,
            total: map.len(),
        };
        for entry in map.values() {
            match entry.state {
                State::Normal => counts.normal += 1,
                State::Direct => counts.direct += 1,
                State::Failed => counts.failed += 1,
                State::Checking => counts.checking += 1,
                _ => {}
            }
        }
        counts
    }

    pub fn groups_snapshot(&self, config: &AppConfig) -> Vec<GroupStatus> {
        let domains = self.domains.read();
        let paused = self.paused();
        config
            .groups
            .iter()
            .map(|group| {
                let primary = group.primary_domain().map(ToOwned::to_owned);
                let primary_state = primary
                    .as_ref()
                    .and_then(|domain| domains.get(domain))
                    .map(|entry| entry.state);
                let entries: Vec<&DomainDiagnostics> = group
                    .exact_domains()
                    .filter_map(|domain| domains.get(domain).map(Arc::as_ref))
                    .collect();
                let tested = entries
                    .iter()
                    .filter(|entry| {
                        !matches!(
                            entry.state,
                            State::Checking | State::Disabled | State::Paused
                        )
                    })
                    .count();
                let failed = entries
                    .iter()
                    .filter(|entry| entry.state == State::Failed)
                    .count();
                let last_check = entries.iter().map(|entry| entry.last_check).max();

                let state = if !group.enabled {
                    State::Disabled
                } else if paused {
                    State::Paused
                } else if matches!(primary_state, Some(State::Failed)) {
                    State::Failed
                } else if matches!(primary_state, None | Some(State::Checking)) {
                    State::Checking
                } else if failed > 0 {
                    State::Degraded
                } else {
                    State::Normal
                };
                GroupStatus {
                    id: group.id.clone(),
                    name: group.name.clone(),
                    enabled: group.enabled,
                    experimental: group.experimental,
                    state,
                    strategy: group.strategy,
                    primary_domain: primary,
                    primary_state,
                    tested_domains: tested,
                    failed_domains: failed,
                    last_check,
                }
            })
            .collect()
    }

    pub fn clear(&self) {
        self.domains.write().clear();
    }
}

/// Keep failure evidence longer than ordinary success records. If every entry
/// is failed/degraded, the oldest failures are evicted as a last resort.
fn prune_status_domains(map: &mut HashMap<String, Arc<DomainDiagnostics>>) {
    let mut candidates: Vec<(String, DateTime<Utc>, bool)> = map
        .iter()
        .map(|(domain, entry)| {
            (
                domain.clone(),
                entry.last_check,
                matches!(entry.state, State::Failed | State::Degraded),
            )
        })
        .collect();
    candidates.sort_by_key(|(_, last_check, protected)| (*protected, *last_check));
    let excess = map.len().saturating_sub(STATUS_PRUNE_TO);
    for (domain, _, _) in candidates.into_iter().take(excess) {
        map.remove(&domain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    fn report(domain: &str, state: State) -> DomainDiagnostics {
        DomainDiagnostics {
            group: Some("github".into()),
            domain: domain.into(),
            state,
            strategy: Some(TlsMode::Direct),
            configured_strategy: Some(Strategy::Auto),
            ip: None,
            ip_source: None,
            doh_source: None,
            latency_ms: None,
            last_check: now(),
            catalog_version: 1,
            cache: CacheStatus::Fresh,
            error: None,
            detail: None,
            attempts: Vec::new(),
            suggestions: Vec::new(),
        }
    }

    #[test]
    fn repeated_checking_does_not_bump_revision() {
        let store = StatusStore::new();
        store.record(report("example.com", State::Normal));
        store.mark_checking(Some("github"), "example.com", Some(Strategy::Auto), 1);
        let revision = store.revision();
        store.mark_checking(Some("github"), "example.com", Some(Strategy::Auto), 1);
        assert_eq!(
            store.revision(),
            revision,
            "a cold connect that is already marked Checking must not force a UI snapshot rebuild"
        );
    }

    #[test]
    fn a_cold_burst_reuses_one_checking_record() {
        let store = StatusStore::new();
        store.mark_checking(Some("github"), "example.com", Some(Strategy::Auto), 1);
        let first = store.get("example.com").unwrap().last_check;
        std::thread::sleep(std::time::Duration::from_millis(10));
        store.mark_checking(Some("github"), "example.com", Some(Strategy::Auto), 1);
        assert_eq!(
            store.get("example.com").unwrap().last_check,
            first,
            "concurrent cold connections must not replace the shared Checking record"
        );
    }

    #[test]
    fn fresh_success_absorbs_the_next_checking_marker() {
        let store = StatusStore::new();
        store.record(report("example.com", State::Normal));

        store.mark_checking(Some("github"), "example.com", Some(Strategy::Auto), 1);
        assert_eq!(store.get("example.com").unwrap().state, State::Normal);

        // A stale result is re-marked so the UI still shows progress.
        let mut stale = report("stale.example", State::Normal);
        stale.last_check = now() - chrono::Duration::seconds(2);
        store.record(stale);
        store.mark_checking(Some("github"), "stale.example", Some(Strategy::Auto), 1);
        assert_eq!(store.get("stale.example").unwrap().state, State::Checking);
    }

    #[test]
    fn aggregates_group_state() {
        let store = StatusStore::new();
        let config = AppConfig::default();
        let statuses = store.groups_snapshot(&config);
        let github = statuses.iter().find(|g| g.id == "github").unwrap();
        assert_eq!(github.state, State::Checking);

        store.record(report("github.com", State::Normal));
        let github = store
            .groups_snapshot(&config)
            .into_iter()
            .find(|g| g.id == "github")
            .unwrap();
        assert_eq!(github.state, State::Normal);

        store.record(report("api.github.com", State::Failed));
        let github = store
            .groups_snapshot(&config)
            .into_iter()
            .find(|g| g.id == "github")
            .unwrap();
        assert_eq!(github.state, State::Degraded);
        assert_eq!(github.failed_domains, 1);

        store.record(report("github.com", State::Failed));
        let github = store
            .groups_snapshot(&config)
            .into_iter()
            .find(|g| g.id == "github")
            .unwrap();
        assert_eq!(github.state, State::Failed);
    }

    #[test]
    fn disabled_and_paused_win() {
        let store = StatusStore::new();
        let config = AppConfig::default();
        let eh = store
            .groups_snapshot(&config)
            .into_iter()
            .find(|g| g.id == "eh")
            .unwrap();
        assert_eq!(eh.state, State::Disabled);
        store.set_paused(true);
        let github = store
            .groups_snapshot(&config)
            .into_iter()
            .find(|g| g.id == "github")
            .unwrap();
        assert_eq!(github.state, State::Paused);
    }

    #[test]
    fn revision_moves_only_when_the_published_state_changes() {
        let store = StatusStore::new();
        let start = store.revision();

        store.set_paused(true);
        let paused = store.revision();
        assert!(paused > start, "a pause flip must publish");

        // Setting the same value again is not a change.
        store.set_paused(true);
        assert_eq!(store.revision(), paused);

        store.record(report("github.com", State::Normal));
        assert!(store.revision() > paused, "a domain record must publish");
    }

    #[test]
    fn wildcard_host_growth_is_bounded() {
        let store = StatusStore::new();
        for index in 0..=MAX_STATUS_DOMAINS {
            store.record(report(
                &format!("host{index}.wildcard.example"),
                State::Normal,
            ));
        }
        let snapshot = store.domains_snapshot();
        assert!(snapshot.len() <= MAX_STATUS_DOMAINS);
        assert!(
            snapshot.len() < MAX_STATUS_DOMAINS,
            "the bulk prune should leave headroom below the cap"
        );
    }

    /// The snapshot the UI polls: a clone of every domain record plus the counts.
    #[test]
    #[ignore = "micro benchmark"]
    fn bench_status_snapshot() {
        let store = StatusStore::new();
        for index in 0..256 {
            store.record(report(&format!("host{index}.example.com"), State::Normal));
        }
        crate::bench::measure("status.snapshot", 2_000, || {
            let _ = store.domains_snapshot_with_counts();
        });
    }
}
