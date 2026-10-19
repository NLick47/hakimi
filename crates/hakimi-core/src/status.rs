use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::strategy::{CacheStatus, DohSource, FailureReason, IpSource, Strategy, TlsMode};
use crate::util::now;

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
    domains: RwLock<HashMap<String, DomainDiagnostics>>,
    paused: AtomicBool,
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
            started_at: now(),
        }
    }

    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
    }

    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    pub fn get(&self, domain: &str) -> Option<DomainDiagnostics> {
        self.domains.read().get(domain).cloned()
    }

    pub fn record(&self, diagnostics: DomainDiagnostics) {
        let mut map = self.domains.write();
        if let Some(existing) = map.get(&diagnostics.domain) {
            // Never let a slower, older probe overwrite a newer result.
            if existing.last_check > diagnostics.last_check
                && existing.state != State::Checking
                && diagnostics.state == State::Checking
            {
                return;
            }
        }
        map.insert(diagnostics.domain.clone(), diagnostics);
    }

    pub fn mark_checking(
        &self,
        group: Option<String>,
        domain: &str,
        strategy: Option<Strategy>,
        catalog_version: u64,
    ) {
        self.record(DomainDiagnostics::checking(
            group,
            domain,
            strategy,
            catalog_version,
        ));
    }

    pub fn domains_snapshot(&self) -> Vec<DomainDiagnostics> {
        let mut values: Vec<DomainDiagnostics> = self.domains.read().values().cloned().collect();
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
                    .filter_map(|domain| domains.get(domain))
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
                } else if self.paused() {
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
}
