use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::strategy::{CacheStatus, DohSource, FailureReason, IpSource, TlsMode};
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
    /// Ordered modes of the matched domain rule, for diagnostics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configured_modes: Vec<TlsMode>,
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
        configured_modes: Vec<TlsMode>,
        catalog_version: u64,
    ) -> Self {
        Self {
            group,
            domain: domain.into(),
            state: State::Checking,
            strategy: None,
            configured_modes,
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
    pub state: State,
    pub primary_domain: Option<String>,
    pub primary_state: Option<State>,
    pub tested_domains: usize,
    pub failed_domains: usize,
    pub last_check: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusCounts {
    pub normal: usize,
    pub direct: usize,
    pub failed: usize,
    pub checking: usize,
    pub total: usize,
}

impl StatusCounts {
    fn add(&mut self, state: State) {
        match state {
            State::Normal => self.normal += 1,
            State::Direct => self.direct += 1,
            State::Failed => self.failed += 1,
            State::Checking => self.checking += 1,
            _ => {}
        }
    }

    fn remove(&mut self, state: State) {
        match state {
            State::Normal => self.normal = self.normal.saturating_sub(1),
            State::Direct => self.direct = self.direct.saturating_sub(1),
            State::Failed => self.failed = self.failed.saturating_sub(1),
            State::Checking => self.checking = self.checking.saturating_sub(1),
            _ => {}
        }
    }
}

pub struct StatusStore {
    /// Values are shared so snapshots clone only an `Arc`, not every
    /// diagnostics record (including attempts/suggestions vectors).
    domains: RwLock<HashMap<String, Arc<DomainDiagnostics>>>,
    /// Maintained together with `domains` under its write lock. Keeping the
    /// counters separate lets pollers read them without scanning all domains.
    counts: RwLock<StatusCounts>,
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
            counts: RwLock::new(StatusCounts::default()),
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
        let mut state_change: Option<(State, State)> = None;
        // Keep the log payload out of the map write guard. `tracing` may block
        // on the log writer, and status readers must not wait for it.
        let mut transition_log: Option<(State, State, Arc<DomainDiagnostics>)> = None;
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
            if existing.state != diagnostics.state {
                state_change = Some((existing.state, diagnostics.state));
                if existing.state != State::Checking && diagnostics.state != State::Checking {
                    transition_log =
                        Some((existing.state, diagnostics.state, diagnostics.clone()));
                }
            }
            // Reuse the existing key: the common path is an update of a known
            // domain, so there is no reason to clone its name for the map.
            *existing = diagnostics;
        } else {
            let state = diagnostics.state;
            map.insert(diagnostics.domain.clone(), diagnostics);
            if map.len() > MAX_STATUS_DOMAINS {
                prune_status_domains(&mut map);
                // The prune removes a bulk of domains at once; recomputing is
                // cheaper than trying to maintain every removal individually.
                *self.counts.write() = counts_for(&map);
            } else {
                let mut counts = self.counts.write();
                counts.total += 1;
                counts.add(state);
            }
        }
        if let Some((old, new)) = state_change {
            let mut counts = self.counts.write();
            counts.remove(old);
            counts.add(new);
        }
        // The record is in the map now: publish the change to pollers. Doing
        // it after the write (and after the early return above) means a
        // revision bump always corresponds to a visible change. Re-marking an
        // already-checking domain is not a visible change.
        if !unchanged_checking {
            self.revision.fetch_add(1, Ordering::SeqCst);
        }
        drop(map);
        if let Some((from, to, diagnostics)) = transition_log {
            tracing::info!(
                domain = %diagnostics.domain,
                from = ?from,
                to = ?to,
                latency_ms = diagnostics.latency_ms,
                error = ?diagnostics.error,
                "domain state changed"
            );
        }
    }

    /// Warmup failures are recorded as Checking so a first attempt that is
    /// immediately retried does not flash Failed. Once warmup finishes, turn
    /// any probe still sitting in Checking with a recorded failure into a real
    /// Failed state exactly once.
    pub fn settle_provisional(&self, domains: &[String]) {
        let mut map = self.domains.write();
        let mut counts = self.counts.write();
        let mut changed = false;
        let mut transitions: Vec<(String, Option<FailureReason>)> = Vec::new();
        for domain in domains {
            let Some(entry) = map.get_mut(domain) else {
                continue;
            };
            if entry.state != State::Checking || entry.error.is_none() {
                continue;
            }
            let mut updated = (**entry).clone();
            updated.state = State::Failed;
            transitions.push((domain.clone(), updated.error));
            counts.remove(State::Checking);
            counts.add(State::Failed);
            *entry = Arc::new(updated);
            changed = true;
        }
        if changed {
            self.revision.fetch_add(1, Ordering::SeqCst);
        }
        drop(counts);
        drop(map);
        for (domain, error) in transitions {
            tracing::info!(
                domain = %domain,
                from = ?State::Checking,
                to = ?State::Failed,
                error = ?error,
                "domain state changed"
            );
        }
    }

    pub fn mark_checking(
        &self,
        group: Option<&str>,
        domain: &str,
        configured_modes: Vec<TlsMode>,
        catalog_version: u64,
    ) {
        self.mark_checking_lazy(group, domain, || configured_modes, catalog_version);
    }

    /// [`Self::mark_checking`] with the configured-mode list built lazily.
    ///
    /// A cold page asset burst often reconnects to the same domain within the
    /// one-second debounce below. Building `configured_modes` (a rule scan and
    /// a `Vec` allocation for groups with many domains) before that check
    /// wasted that work on every connection. The closure runs only when a new
    /// Checking record is actually published.
    pub(crate) fn mark_checking_lazy<F>(
        &self,
        group: Option<&str>,
        domain: &str,
        configured_modes: F,
        catalog_version: u64,
    ) where
        F: FnOnce() -> Vec<TlsMode>,
    {
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
            configured_modes(),
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
    /// The counts are maintained incrementally, so this only clones the
    /// shared records and sorts them; it does not rescan the whole map.
    pub fn domains_snapshot_with_counts(&self) -> (Vec<Arc<DomainDiagnostics>>, StatusCounts) {
        let map = self.domains.read();
        let counts = *self.counts.read();
        let mut values: Vec<Arc<DomainDiagnostics>> = map.values().cloned().collect();
        values.sort_by(|a, b| a.domain.cmp(&b.domain));
        (values, counts)
    }

    /// The records of `wanted`, which must already be sorted by domain name.
    ///
    /// The polled snapshot only needs the domains of the configured groups.
    /// Looking them up directly avoids copying and sorting every known
    /// domain, which dominated the poll once a session had seen thousands.
    pub fn domains_for(&self, wanted: &[String]) -> Vec<Arc<DomainDiagnostics>> {
        let map = self.domains.read();
        wanted
            .iter()
            .filter_map(|domain| map.get(domain).cloned())
            .collect()
    }

    /// The same lookup as [`Self::domains_for`], plus the cached counts.
    /// Both locks are taken in the same order as the writer (domains, then
    /// counts), so a reader never observes a record/count mismatch.
    pub fn domains_for_with_counts(
        &self,
        wanted: &[String],
    ) -> (Vec<Arc<DomainDiagnostics>>, StatusCounts) {
        let map = self.domains.read();
        let values: Vec<Arc<DomainDiagnostics>> = wanted
            .iter()
            .filter_map(|domain| map.get(domain).cloned())
            .collect();
        let counts = *self.counts.read();
        (values, counts)
    }

    pub fn counts(&self) -> StatusCounts {
        *self.counts.read()
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
                // Count the group's records in one pass. Collecting them into
                // an intermediate Vec and scanning it three times allocated
                // (and kept the read lock held) for no reason.
                let mut tested = 0;
                let mut failed = 0;
                let mut last_check = None;
                for domain in group.exact_domains() {
                    let Some(entry) = domains.get(domain) else {
                        continue;
                    };
                    if !matches!(
                        entry.state,
                        State::Checking | State::Disabled | State::Paused
                    ) {
                        tested += 1;
                    }
                    if entry.state == State::Failed {
                        failed += 1;
                    }
                    if last_check.is_none_or(|at| entry.last_check > at) {
                        last_check = Some(entry.last_check);
                    }
                }

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
                    state,
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
        let mut map = self.domains.write();
        map.clear();
        *self.counts.write() = StatusCounts::default();
    }
}

fn counts_for(map: &HashMap<String, Arc<DomainDiagnostics>>) -> StatusCounts {
    let mut counts = StatusCounts {
        total: map.len(),
        ..StatusCounts::default()
    };
    for entry in map.values() {
        counts.add(entry.state);
    }
    counts
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
            configured_modes: vec![TlsMode::Direct],
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
        store.mark_checking(Some("github"), "example.com", vec![TlsMode::Direct], 1);
        let revision = store.revision();
        store.mark_checking(Some("github"), "example.com", vec![TlsMode::Direct], 1);
        assert_eq!(
            store.revision(),
            revision,
            "a cold connect that is already marked Checking must not force a UI snapshot rebuild"
        );
    }

    #[test]
    fn the_checking_debounce_skips_the_mode_list_entirely() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let store = StatusStore::new();
        let builds = AtomicUsize::new(0);
        store.mark_checking_lazy(
            Some("github"),
            "example.com",
            || {
                builds.fetch_add(1, Ordering::SeqCst);
                vec![TlsMode::Direct]
            },
            1,
        );
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        // The record is fresh and Checking, so the debounce returns before
        // touching the configured modes. A page asset burst must not scan the
        // group's rule list or allocate a Vec for every reconnect.
        store.mark_checking_lazy(
            Some("github"),
            "example.com",
            || {
                builds.fetch_add(1, Ordering::SeqCst);
                vec![TlsMode::FakeSni]
            },
            1,
        );
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(
            store.get("example.com").unwrap().configured_modes,
            vec![TlsMode::Direct]
        );
    }

    #[test]
    fn a_cold_burst_reuses_one_checking_record() {
        let store = StatusStore::new();
        store.mark_checking(Some("github"), "example.com", vec![TlsMode::Direct], 1);
        let first = store.get("example.com").unwrap().last_check;
        std::thread::sleep(std::time::Duration::from_millis(10));
        store.mark_checking(Some("github"), "example.com", vec![TlsMode::Direct], 1);
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

        store.mark_checking(Some("github"), "example.com", vec![TlsMode::Direct], 1);
        assert_eq!(store.get("example.com").unwrap().state, State::Normal);

        // A stale result is re-marked so the UI still shows progress.
        let mut stale = report("stale.example", State::Normal);
        stale.last_check = now() - chrono::Duration::seconds(2);
        store.record(stale);
        store.mark_checking(Some("github"), "stale.example", vec![TlsMode::Direct], 1);
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
        let mut config = AppConfig::default();
        config
            .groups
            .iter_mut()
            .find(|group| group.id == "eh")
            .unwrap()
            .enabled = false;
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
    fn counts_follow_transitions_and_clear() {
        let store = StatusStore::new();
        assert_eq!(store.counts().total, 0);

        store.record(report("a.example", State::Normal));
        store.record(report("b.example", State::Direct));
        store.record(report("c.example", State::Failed));
        store.record(report("d.example", State::Checking));
        store.record(report("e.example", State::Paused));
        store.record(report("f.example", State::Degraded));
        let counts = store.counts();
        assert_eq!(
            counts,
            StatusCounts {
                normal: 1,
                direct: 1,
                failed: 1,
                checking: 1,
                total: 6,
            }
        );

        // A state transition adjusts the old and new buckets, without
        // changing the total.
        store.record(report("a.example", State::Failed));
        let counts = store.counts();
        assert_eq!(
            counts,
            StatusCounts {
                normal: 0,
                direct: 1,
                failed: 2,
                checking: 1,
                total: 6,
            }
        );

        // Re-recording the same state is not a count change.
        store.record(report("b.example", State::Direct));
        assert_eq!(store.counts(), counts);

        // The combined snapshot returns the same counters as the cheap read.
        let (domains, snapshot_counts) = store.domains_snapshot_with_counts();
        assert_eq!(snapshot_counts, counts);
        assert_eq!(domains.len(), counts.total);

        store.clear();
        assert_eq!(store.counts(), StatusCounts::default());
    }

    #[test]
    fn settling_provisional_failures_publishes_one_failure() {
        let store = StatusStore::new();
        let mut diagnostic = DomainDiagnostics::checking(
            Some("test".into()),
            "a.example",
            Vec::new(),
            0,
        );
        diagnostic.error = Some(FailureReason::TcpTimeout);
        store.record(diagnostic);
        assert_eq!(store.get("a.example").unwrap().state, State::Checking);

        let revision = store.revision();
        store.settle_provisional(&["a.example".to_string()]);
        assert_eq!(store.get("a.example").unwrap().state, State::Failed);
        assert!(store.revision() > revision);
        assert_eq!(store.counts().failed, 1);
        assert_eq!(store.counts().checking, 0);

        // Settling again is a no-op.
        let revision = store.revision();
        store.settle_provisional(&["a.example".to_string()]);
        assert_eq!(store.revision(), revision);
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
        let counts = store.counts();
        assert_eq!(counts.total, snapshot.len());
        assert_eq!(counts.normal, snapshot.len());
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
