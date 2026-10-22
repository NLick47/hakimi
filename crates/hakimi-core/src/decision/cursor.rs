use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::{AppConfig, EchSource, GroupConfig, RouteAttempt, RoutePolicy};
use crate::resolver::EchOutcome;
use crate::status::AttemptRecord;
use crate::strategy::{FailureReason, IpSource, TlsMode};
use crate::util::{network_id, now};

use super::engine::DecisionEngine;
use super::plan::{ConnectPlan, DecisionOutcome};
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
    /// Index of the matched `DomainRule` inside the group.
    rule_index: usize,
    config: Arc<AppConfig>,
    max: usize,
    candidates: Vec<Candidate>,
    candidate_index: usize,
    doh_loaded: bool,
    doh: DohExpansion,
    skip_once: bool,
    remote_available: bool,
    /// Ordered attempts of the matched domain rule.
    route_attempts: Vec<RouteAttempt>,
    attempt_index: usize,
    current: Option<Candidate>,
    /// ECHConfigList cache per source (own / shared).
    ech_configs: [Option<Vec<u8>>; 2],
    ech_checked: [bool; 2],
    ech_errors: [Option<String>; 2],
    /// Fake SNI candidates for the current SNI attempt.
    sni_candidates: Vec<Option<String>>,
    sni_attempt: Option<usize>,
    sni_index: usize,
    network: String,
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
        rule_index: usize,
        config: Arc<AppConfig>,
        hedge_cold_ech: bool,
    ) -> Self {
        let group = &config.groups[group_index];
        let max = config.advanced.max_candidates_per_domain;
        let (skip_hint, last_good) = engine
            .cache
            .route_hints(&domain, config.advanced.last_good_days);
        // The common case is an empty set. Only take the write lock (and
        // re-check) when the read-only hint saw a marker.
        let skip_once = skip_hint && engine.cache.take_skip_once(&domain);
        // One catalog snapshot for both the IPs and the "catalog loaded" flag.
        let (remote, remote_available) = engine.remote.remote_ips_with_catalog(&domain);

        let mut candidates: Vec<Candidate> = Vec::new();
        // The candidate list is capped at eight entries, so a linear scan is
        // cheaper than allocating a hash set for every new connection.
        let contains_ip = |candidates: &[Candidate], ip: IpAddr| {
            candidates.iter().any(|candidate| candidate.ip == ip)
        };
        let add_remote = |candidates: &mut Vec<Candidate>| {
            if let Some(ips) = &remote {
                for ip in ips {
                    if candidates.len() >= max {
                        break;
                    }
                    if !contains_ip(candidates, *ip) && !engine.ip_rejected(&domain, *ip) {
                        candidates.push(Candidate {
                            ip: *ip,
                            source: IpSource::Remote,
                        });
                    }
                }
            }
        };
        let add_cache = |candidates: &mut Vec<Candidate>| {
            if let Some(ip) = last_good {
                if candidates.len() < max
                    && !contains_ip(candidates, ip)
                    && !engine.ip_rejected(&domain, ip)
                {
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
            add_remote(&mut candidates);
            add_cache(&mut candidates);
        } else {
            add_cache(&mut candidates);
            add_remote(&mut candidates);
        }

        // Order by measured quality on this network: proven fast IPs lead, failures sink.
        // Unknown addresses keep the catalog order, so a fresh start is still deterministic.
        // Score the whole candidate list under one read lock. The previous
        // per-candidate lookups took the same lock up to `max` times for every
        // cold connection.
        let scores = engine.score_candidates(&domain, &candidates);
        let mut ranked: Vec<(f64, Candidate)> = candidates
            .into_iter()
            .zip(scores)
            .map(|(candidate, score)| {
                let score = if skip_once && candidate.source == IpSource::Remote {
                    0.0
                } else {
                    score
                };
                (score, candidate)
            })
            .collect();
        ranked.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let candidates: Vec<Candidate> =
            ranked.into_iter().map(|(_, candidate)| candidate).collect();

        let route = group
            .domains
            .get(rule_index)
            .and_then(|rule| rule.route.as_ref())
            .unwrap_or(&group.default_route);
        let mut route_attempts = if tls {
            route.attempts.clone()
        } else {
            vec![RouteAttempt::Direct]
        };
        // A cold ECH-first route used to block the whole cursor on the HTTPS RR
        // lookup even when the route explicitly allows Direct fallback. In the
        // connection race, move that fallback ahead of the lookup so the first
        // TCP connection can open immediately; the ECH plan is still generated
        // (and raced) on the next `next_plan` call once the lookup has a value.
        // Diagnostic probes keep the configured priority, and a fresh cached
        // config keeps ECH in its configured first position.
        if tls && hedge_cold_ech {
            let cold_ech = route_attempts
                .iter()
                .position(|attempt| attempt.ech_source().is_some());
            let direct = route_attempts
                .iter()
                .position(|attempt| matches!(attempt, RouteAttempt::Direct));
            if let (Some(cold_ech), Some(direct)) = (cold_ech, direct) {
                if direct > cold_ech && engine.cache.ech(&domain, true).is_none() {
                    let direct = route_attempts.remove(direct);
                    route_attempts.insert(cold_ech, direct);
                }
            }
        }

        Self {
            engine,
            domain,
            port,
            tls,
            group_index,
            rule_index,
            config,
            max,
            candidates,
            candidate_index: 0,
            doh_loaded: false,
            doh: DohExpansion::default(),
            skip_once,
            remote_available,
            route_attempts,
            attempt_index: 0,
            current: None,
            ech_configs: [None, None],
            ech_checked: [false, false],
            ech_errors: [None, None],
            sni_candidates: Vec::new(),
            sni_attempt: None,
            sni_index: 0,
            network: network_id(),
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
        if !self
            .route_attempts
            .iter()
            .any(|attempt| attempt.mode() == TlsMode::Direct)
        {
            return false;
        }
        self.route_attempts
            .retain(|attempt| matches!(attempt, RouteAttempt::Direct));
        self.attempt_index = 0;
        self.sni_candidates.clear();
        self.sni_attempt = None;
        self.sni_index = 0;
        true
    }

    fn configured_route(&self) -> &RoutePolicy {
        let group = self.group();
        group
            .domains
            .get(self.rule_index)
            .and_then(|rule| rule.route.as_ref())
            .unwrap_or(&group.default_route)
    }

    /// Ordered modes of the matched route, used by status diagnostics.
    pub fn configured_modes(&self) -> Vec<TlsMode> {
        self.configured_route()
            .attempts
            .iter()
            .map(RouteAttempt::mode)
            .collect()
    }

    fn sni_candidates_for(&self, hosts: &[String]) -> Vec<Option<String>> {
        let mut out: Vec<Option<String>> = Vec::new();
        let mut push = |candidate: Option<String>| {
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        };
        if let Some(cached) = self
            .engine
            .cache
            .sni(&self.group().id, &self.domain, &self.network)
        {
            let allowed = hosts.is_empty()
                || cached.sni.as_deref().is_some_and(|cached| {
                    hosts.iter().any(|host| host.eq_ignore_ascii_case(cached))
                });
            if allowed {
                push(cached.sni);
            }
        }
        if hosts.is_empty() {
            for candidate in &self.config.advanced.fake_sni_candidates {
                push(normalize_sni(candidate));
            }
        } else {
            for candidate in hosts {
                push(normalize_sni(candidate));
            }
        }
        if out.is_empty() {
            out.push(None);
        }
        // A `None` entry sends no SNI and is effectively a duplicate of Direct.
        out.sort_by_key(|entry| entry.is_none());
        out
    }

    /// Skip an already-attempted plan (for example one taken from the plan cache).
    pub fn skip_plan(&mut self, plan: &ConnectPlan) {
        self.skipped.insert(plan.identity());
    }

    /// Drop a failed plan so the next cold connection re-races instead of
    /// pinning the same address again.
    pub fn forget_plan(&self, plan: &ConnectPlan) {
        self.engine.forget_plan(&plan.domain, plan.port, plan.tls);
    }

    pub fn outcome(&self) -> Option<&DecisionOutcome> {
        self.failure.as_ref()
    }

    /// Produce the next plan in round-robin order. Each round pairs one candidate IP
    /// with every configured attempt, so the connection race compares attempts instead
    /// of stopping at the first one that merely connects. `None` means every attempt
    /// and candidate was exhausted; a failure diagnostic has been recorded in that case.
    pub async fn next_plan(&mut self) -> Option<ConnectPlan> {
        if self.finished {
            return None;
        }
        loop {
            if self.finished {
                return None;
            }
            if self.route_attempts.is_empty() {
                self.finish_failure();
                return None;
            }
            // Advance to the next candidate when the round is done (or not started).
            if self.current.is_none() || self.attempt_index >= self.route_attempts.len() {
                match self.next_candidate().await {
                    Some(candidate) => {
                        self.current = Some(candidate);
                        self.attempt_index = 0;
                        self.sni_attempt = None;
                        self.sni_index = 0;
                    }
                    None => {
                        self.finish_failure();
                        return None;
                    }
                }
            }
            let attempt = self.route_attempts[self.attempt_index].clone();
            if self.engine.route_rejected(&self.domain, attempt.mode()) {
                self.attempt_index += 1;
                continue;
            }
            let Some(candidate) = self.current.clone() else {
                self.finish_failure();
                return None;
            };

            match attempt {
                RouteAttempt::Direct => {
                    self.attempt_index += 1;
                    let plan = self.build_plan(candidate, TlsMode::Direct, None, None);
                    if self.take_skipped(&plan) {
                        continue;
                    }
                    return Some(plan);
                }
                RouteAttempt::Ech { ech } => {
                    let slot = ech_slot(ech);
                    if !self.ech_checked[slot] {
                        match self
                            .engine
                            .resolver
                            .doh_ech_config(&self.domain, ech == EchSource::Shared)
                            .await
                        {
                            Ok(EchOutcome {
                                config,
                                source,
                                stale,
                                ..
                            }) => {
                                self.ech_configs[slot] = Some(config);
                                if self.doh.source.is_none() {
                                    self.doh.source = Some(source);
                                }
                                self.doh.stale |= stale;
                            }
                            Err(error) => {
                                self.ech_errors[slot] = Some(format!("{error:#}"));
                            }
                        }
                        // Mark the attempt only after the await: if the race that
                        // requested this plan is cancelled mid-query, the next plan
                        // request retries instead of permanently dropping ECH.
                        self.ech_checked[slot] = true;
                    }
                    self.attempt_index += 1;
                    let Some(config) = self.ech_configs[slot].clone() else {
                        self.last_reason = Some(FailureReason::EchUnavailable);
                        self.last_detail = self.ech_errors[slot].clone().or_else(|| {
                            Some(format!(
                                "no ECHConfig available ({})",
                                if ech == EchSource::Shared {
                                    "own + shared"
                                } else {
                                    "own"
                                }
                            ))
                        });
                        continue;
                    };
                    let plan = self.build_plan(candidate, TlsMode::Ech, None, Some(config));
                    if self.take_skipped(&plan) {
                        continue;
                    }
                    return Some(plan);
                }
                RouteAttempt::Sni { sni: hosts } => {
                    if self.sni_attempt != Some(self.attempt_index) {
                        self.sni_candidates = self.sni_candidates_for(&hosts);
                        self.sni_attempt = Some(self.attempt_index);
                        self.sni_index = 0;
                    }
                    if self.sni_index >= self.sni_candidates.len() {
                        // The SNI list is exhausted for this candidate; the next
                        // candidate sweeps the same list again.
                        self.attempt_index += 1;
                        continue;
                    }
                    let sni = self.sni_candidates[self.sni_index].clone();
                    self.sni_index += 1;
                    let plan = self.build_plan(candidate, TlsMode::FakeSni, sni, None);
                    if self.take_skipped(&plan) {
                        continue;
                    }
                    return Some(plan);
                }
            }
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
                    .expand_doh(&self.domain, &mut self.candidates, self.max)
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
                network_id: self.network.clone(),
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
        } else if self.configured_route().contains_mode(TlsMode::Ech)
            && self.ech_configs.iter().all(Option::is_none)
        {
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
        for error in self.ech_errors.iter().flatten() {
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

fn normalize_sni(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_ascii_lowercase())
    }
}

fn ech_slot(source: EchSource) -> usize {
    match source {
        EchSource::Own => 0,
        EchSource::Shared => 1,
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
