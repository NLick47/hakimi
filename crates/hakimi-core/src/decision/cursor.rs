use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::{AppConfig, GroupConfig};
use crate::resolver::EchOutcome;
use crate::status::AttemptRecord;
use crate::strategy::{FailureReason, IpSource, Strategy, TlsMode};
use crate::util::{network_id, now};

use super::engine::DecisionEngine;
use super::plan::{mode_for_strategy, ConnectPlan, DecisionOutcome};
use super::types::{Candidate, DohExpansion, EARLY_DOH_AFTER};

/// Result of matching a host against the configured groups.
pub enum Route {
    /// No interception: the caller should connect directly.
    Bypass(DecisionOutcome),
    /// The host belongs to a group but cannot be routed (invalid config, CA-independent error).
    Blocked(DecisionOutcome),
    /// The host belongs to an enabled group. Plans are produced lazily and without probing:
    /// the real upstream TLS handshake is the probe, so the hot path never pays for two
    /// handshakes per connection.
    Group(Box<RouteCursor>),
}

/// Lazy, probe-free route generator. The design's candidate order (cache/remote ->
/// DoH -> stale DoH) is unchanged, but in `auto` mode the TLS routes no longer run as
/// strict priority blocks: the generator walks rounds over the candidate list, pairing
/// one IP with every configured route (direct, ECH, fake SNI). The connection race then
/// compares routes instead of stopping at the first route that merely works — a slow
/// direct connection loses to a faster accelerated one, and `last_good` remembers which
/// route won. Only DoH and ECH resolution stay lazy.
///
/// The caller attempts each returned plan for real and reports the outcome with
/// [`RouteCursor::note_failure`] / [`RouteCursor::note_success`]. Because the real
/// connection performs the same TCP + TLS + certificate validation a probe would, this
/// removes the duplicate handshake from the proxy hot path without weakening validation.
pub struct RouteCursor {
    engine: Arc<DecisionEngine>,
    domain: String,
    port: u16,
    tls: bool,
    /// Index into the immutable `config` snapshot. Keeping only the index avoids
    /// cloning the group (including all of its domain strings) per connection.
    group_index: usize,
    config: Arc<AppConfig>,
    max: usize,
    candidates: Vec<Candidate>,
    seen: HashSet<IpAddr>,
    candidate_index: usize,
    doh_loaded: bool,
    doh: DohExpansion,
    skip_once: bool,
    remote_available: bool,
    modes: Vec<TlsMode>,
    mode_index: usize,
    current: Option<Candidate>,
    ech_config: Option<Vec<u8>>,
    ech_checked: bool,
    ech_error: Option<String>,
    sni_candidates: Vec<Option<String>>,
    sni_index: usize,
    attempts: Vec<AttemptRecord>,
    last_reason: Option<FailureReason>,
    last_detail: Option<String>,
    skipped: HashSet<String>,
    finished: bool,
    failure: Option<DecisionOutcome>,
}

impl RouteCursor {
    pub(super) fn new(
        engine: Arc<DecisionEngine>,
        domain: String,
        port: u16,
        tls: bool,
        group_index: usize,
        config: Arc<AppConfig>,
    ) -> Self {
        let group = &config.groups[group_index];
        let max = config.advanced.max_candidates_per_domain;
        let (skip_hint, last_good) =
            engine
                .cache
                .route_hints(&domain, config.advanced.last_good_days);
        // The common case is an empty set. Only take the write lock (and
        // re-check) when the read-only hint saw a marker.
        let skip_once = skip_hint && engine.cache.take_skip_once(&domain);
        // One catalog snapshot for both the IPs and the "catalog loaded" flag.
        let (remote, remote_available) = engine.remote.remote_ips_with_catalog(&domain);

        let mut candidates: Vec<Candidate> = Vec::new();
        let mut seen = HashSet::new();
        let add_remote = |candidates: &mut Vec<Candidate>, seen: &mut HashSet<IpAddr>| {
            if let Some((_, ips)) = &remote {
                for ip in ips {
                    if candidates.len() >= max {
                        break;
                    }
                    if seen.insert(*ip) {
                        candidates.push(Candidate {
                            ip: *ip,
                            source: IpSource::Remote,
                        });
                    }
                }
            }
        };
        let add_cache = |candidates: &mut Vec<Candidate>, seen: &mut HashSet<IpAddr>| {
            if let Some((ip, _)) = last_good {
                if candidates.len() < max && seen.insert(ip) {
                    candidates.push(Candidate {
                        ip,
                        source: IpSource::Cache,
                    });
                }
            }
        };
        // 8.1 / 8.2: after a catalog update the new remote IPs are attempted before the
        // last-good cache; otherwise the cache is tried first.
        if skip_once {
            add_remote(&mut candidates, &mut seen);
            add_cache(&mut candidates, &mut seen);
        } else {
            add_cache(&mut candidates, &mut seen);
            add_remote(&mut candidates, &mut seen);
        }

        // Order by measured quality on this network: proven fast IPs lead, failures sink.
        // Unknown addresses keep the catalog order, so a fresh start is still deterministic.
        // Score each candidate once instead of taking the score lock on every comparison.
        let mut ranked: Vec<(f64, Candidate)> = candidates
            .into_iter()
            .map(|candidate| {
                let score = if skip_once && candidate.source == IpSource::Remote {
                    0.0
                } else {
                    engine.score_ip(&domain, candidate.ip)
                };
                (score, candidate)
            })
            .collect();
        ranked.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let candidates: Vec<Candidate> =
            ranked.into_iter().map(|(_, candidate)| candidate).collect();

        let mut modes = if tls {
            group.strategy.attempts().to_vec()
        } else {
            vec![TlsMode::Direct]
        };
        // Use the last-known-good strategy as the first attempt. Without this, a site that
        // only works with fake SNI pays a failed direct/ECH pass on every process start
        // (and every catalog-triggered re-plan), which is especially visible for image
        // hosts. `auto` still falls back to the normal order on failure.
        if tls && group.strategy == Strategy::Auto {
            if let Some(preferred) = last_good.map(|(_, strategy)| mode_for_strategy(strategy)) {
                if modes.contains(&preferred) && modes.first() != Some(&preferred) {
                    modes.retain(|mode| *mode != preferred);
                    modes.insert(0, preferred);
                }
            }
        }
        let sni_candidates = if tls && modes.contains(&TlsMode::FakeSni) {
            // Only fake-SNI routes need the current network identity. Most
            // connections never touch the OS network cache.
            let network = network_id();
            engine.sni_candidates(&config, group, &domain, &network)
        } else {
            Vec::new()
        };

        Self {
            engine,
            domain,
            port,
            tls,
            group_index,
            config,
            max,
            candidates,
            seen,
            candidate_index: 0,
            doh_loaded: false,
            doh: DohExpansion::default(),
            skip_once,
            remote_available,
            modes,
            mode_index: 0,
            current: None,
            ech_config: None,
            ech_checked: false,
            ech_error: None,
            sni_candidates,
            sni_index: 0,
            attempts: Vec::new(),
            last_reason: None,
            last_detail: None,
            skipped: HashSet::new(),
            finished: false,
            failure: None,
        }
    }

    fn group(&self) -> &GroupConfig {
        &self.config.groups[self.group_index]
    }

    pub fn group_id(&self) -> &str {
        self.group().id.as_str()
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// True when a catalog update asked this domain to try its new remote IPs before
    /// any cached route.
    pub fn skip_once(&self) -> bool {
        self.skip_once
    }

    /// Restrict this cursor to raw direct tunnels.
    ///
    /// A raw tunnel forwards bytes to the origin and lets the browser perform the TLS
    /// handshake itself, so only `Direct` plans are usable. Restricting the mode list
    /// avoids generating (and, for ECH, awaiting a DoH lookup for) plans the caller
    /// would immediately discard. That lookup used to sit between direct candidates,
    /// which could keep a later address from ever being tried when the first one failed
    /// quickly.
    ///
    /// Locked ECH/fake-SNI groups have no direct mode; their cursor is left untouched so
    /// the usual failure diagnostics still apply. Must be called before the first plan.
    pub fn restrict_to_direct(&mut self) -> bool {
        if !self.modes.contains(&TlsMode::Direct) {
            return false;
        }
        self.modes.retain(|mode| *mode == TlsMode::Direct);
        self.mode_index = 0;
        self.sni_candidates.clear();
        self.sni_index = 0;
        // Nothing can request ECH after the mode was removed.
        self.ech_checked = true;
        true
    }

    /// Skip an already-attempted plan (for example one taken from the plan cache).
    pub fn skip_plan(&mut self, plan: &ConnectPlan) {
        self.skipped.insert(plan.identity());
    }

    pub fn outcome(&self) -> Option<&DecisionOutcome> {
        self.failure.as_ref()
    }

    /// Produce the next plan in round-robin order. Each round pairs one candidate IP
    /// with every configured TLS route, so the connection race compares routes instead
    /// of stopping at the first route that merely works. `None` means every strategy
    /// and candidate was exhausted; a failure diagnostic has been recorded in that case.
    pub async fn next_plan(&mut self) -> Option<ConnectPlan> {
        if self.finished {
            return None;
        }
        loop {
            if self.finished {
                return None;
            }
            if self.modes.is_empty() {
                self.finish_failure();
                return None;
            }
            // Advance to the next candidate when the round is done (or not started).
            if self.current.is_none() || self.mode_index >= self.modes.len() {
                match self.next_candidate().await {
                    Some(candidate) => {
                        self.current = Some(candidate);
                        self.mode_index = 0;
                        // The SNI list is swept per candidate. Without this reset the
                        // second IP starts at the end of the list and never gets a
                        // fake-SNI attempt at all.
                        self.sni_index = 0;
                    }
                    None => {
                        self.finish_failure();
                        return None;
                    }
                }
            }
            let mode = self.modes[self.mode_index];

            if mode == TlsMode::Ech && !self.ech_checked {
                match self
                    .engine
                    .resolver
                    .doh_ech_config(&self.domain, self.group().ech_shared)
                    .await
                {
                    Ok(EchOutcome {
                        config,
                        source,
                        stale,
                        ..
                    }) => {
                        self.ech_config = Some(config);
                        if self.doh.source.is_none() {
                            self.doh.source = Some(source);
                        }
                        self.doh.stale |= stale;
                    }
                    Err(error) => {
                        self.ech_error = Some(format!("{error:#}"));
                    }
                }
                // Mark the attempt only after the await: if the race that
                // requested this plan is cancelled mid-query, the next plan
                // request retries instead of silently dropping the ECH route.
                self.ech_checked = true;
                if self.ech_config.is_none() {
                    if self.group().strategy == Strategy::Ech {
                        self.last_reason = Some(FailureReason::EchUnavailable);
                        self.last_detail = self
                            .ech_error
                            .clone()
                            .or_else(|| Some("no ECHConfig available".into()));
                        self.finish_failure();
                        return None;
                    }
                    // Drop the ECH route for every round; the mode index now points
                    // at the next mode, so do not advance again.
                    self.modes.retain(|m| *m != TlsMode::Ech);
                    continue;
                }
            }

            let Some(candidate) = self.current.clone() else {
                self.finish_failure();
                return None;
            };

            if mode == TlsMode::FakeSni {
                if self.sni_index >= self.sni_candidates.len() {
                    // The SNI list is exhausted for this candidate, but another
                    // candidate may still work with the same hosts. Move past the
                    // fake-SNI route for this round; the mode stays in the list so
                    // the next candidate sweeps the full SNI list again.
                    self.mode_index += 1;
                    continue;
                }
                // Stay on this mode until the whole SNI list has been paired with
                // the current candidate, mirroring the old SNI-major sweep.
                let sni = self.sni_candidates[self.sni_index].clone();
                self.sni_index += 1;
                let plan = self.build_plan(candidate, mode, sni, None);
                if self.take_skipped(&plan) {
                    continue;
                }
                return Some(plan);
            }

            self.mode_index += 1;
            let ech = if mode == TlsMode::Ech {
                self.ech_config.clone()
            } else {
                None
            };
            let plan = self.build_plan(candidate, mode, None, ech);
            if self.take_skipped(&plan) {
                continue;
            }
            return Some(plan);
        }
    }

    fn build_plan(
        &self,
        candidate: Candidate,
        mode: TlsMode,
        sni: Option<String>,
        ech: Option<Vec<u8>>,
    ) -> ConnectPlan {
        ConnectPlan {
            domain: self.domain.clone(),
            group_id: self.group().id.clone(),
            ip: candidate.ip,
            port: self.port,
            mode,
            sni,
            ech_config: ech,
            tls: self.tls,
            source: candidate.source,
        }
    }

    fn take_skipped(&mut self, plan: &ConnectPlan) -> bool {
        // The common case has no skip set at all (only a failed cached plan
        // populates it); avoid hashing and formatting a plan identity for
        // every candidate in the race.
        if self.skipped.is_empty() {
            return false;
        }
        self.skipped.remove(&plan.identity())
    }

    async fn next_candidate(&mut self) -> Option<Candidate> {
        loop {
            if self.candidate_index < self.candidates.len() {
                let candidate = self.candidates[self.candidate_index].clone();
                self.candidate_index += 1;
                return Some(candidate);
            }
            // Expand with DoH once a few initial candidates have been consumed instead of
            // only at full exhaustion: a stale or poisoned catalog would otherwise pay its
            // whole serial timeout before DoH is ever consulted.
            if !self.doh_loaded
                && self.candidates.len() < self.max
                && self.candidate_index >= EARLY_DOH_AFTER.min(self.candidates.len())
            {
                let engine = self.engine.clone();
                let expansion = engine
                    .expand_doh(&self.domain, &mut self.candidates, &mut self.seen, self.max)
                    .await;
                // Set the flag only after the await: a cancelled race must not
                // permanently skip the DoH expansion for this route cursor.
                self.doh_loaded = true;
                merge_expansion(&mut self.doh, expansion);
                if self.candidate_index < self.candidates.len() {
                    continue;
                }
            }
            return None;
        }
    }

    /// Record a failed real connection attempt. The caller then asks for the next plan.
    pub fn note_failure(&mut self, plan: &ConnectPlan, reason: FailureReason, detail: String) {
        tracing::debug!(
            domain = %plan.domain,
            ip = %plan.ip,
            mode = %plan.mode,
            reason = %reason,
            detail = %detail,
            "upstream candidate failed"
        );
        self.last_reason = Some(reason);
        self.last_detail = Some(detail.clone());
        self.attempts.push(AttemptRecord {
            strategy: plan.mode,
            ip: plan.ip,
            source: plan.source,
            sni: plan.sni.clone(),
            error: Some(reason),
            detail: Some(detail),
            latency_ms: None,
        });
        self.engine.record_ip(&plan.domain, plan.ip, None, true);
    }

    /// Record a successful real connection (TLS + certificate validation already passed).
    ///
    /// The plan is taken by value: the caller usually owns the only copy, and
    /// the plan cache and the outcome can share it instead of deep-copying
    /// the domain, group and SNI strings.
    pub fn note_success(&mut self, plan: Arc<ConnectPlan>, latency_ms: u64) -> DecisionOutcome {
        let diagnostics = self.engine.record_success(
            &plan,
            latency_ms,
            std::mem::take(&mut self.attempts),
            &self.doh,
            &self.config,
        );
        if plan.mode == TlsMode::FakeSni {
            self.engine.cache.put_sni(crate::cache::CachedSni {
                group: self.group().id.clone(),
                domain: self.domain.clone(),
                network_id: network_id(),
                sni: plan.sni.clone(),
                saved_at: now(),
            });
        }
        self.finished = true;
        DecisionOutcome {
            plan: Some(plan),
            diagnostics,
        }
    }

    fn finish_failure(&mut self) {
        if self.failure.is_some() {
            return;
        }
        self.finished = true;
        let reason = if let Some(reason) = self.last_reason {
            reason
        } else if self.group().strategy == Strategy::Ech && self.ech_config.is_none() {
            FailureReason::EchUnavailable
        } else if self.doh.error.is_some() {
            FailureReason::DohFailed
        } else if !self.remote_available {
            FailureReason::RemoteCatalogUnavailable
        } else {
            FailureReason::NoCandidate
        };
        let mut detail = Vec::new();
        if let Some(error) = &self.doh.error {
            detail.push(format!("DoH: {error}"));
        }
        if let Some(error) = &self.ech_error {
            detail.push(format!("ECH: {error}"));
        }
        if let Some(error) = &self.last_detail {
            detail.push(error.clone());
        }
        if !self.remote_available {
            detail.push("remote IP catalog is not loaded".into());
        }
        if self.skip_once {
            detail.push("last-good cache was skipped once after a catalog update".into());
        }
        let attempts = std::mem::take(&mut self.attempts);
        let diagnostics = self.engine.failure_diagnostics(
            self.group(),
            &self.domain,
            &self.config,
            reason,
            attempts,
            &self.doh,
            if detail.is_empty() {
                None
            } else {
                Some(detail.join("; "))
            },
        );
        self.failure = Some(DecisionOutcome {
            plan: None,
            diagnostics,
        });
    }
}

fn merge_expansion(target: &mut DohExpansion, expansion: DohExpansion) {
    if target.source.is_none() {
        target.source = expansion.source;
    }
    if target.error.is_none() {
        target.error = expansion.error;
    }
    target.stale |= expansion.stale;
}
