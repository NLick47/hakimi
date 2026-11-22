use std::net::IpAddr;
use std::time::{Duration, Instant};

use base64::Engine;
use rand::Rng;

use anyhow::{bail, Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use serde::Serialize;

use crate::cache::{CachedAnswer, CachedEch};
use crate::dns::{self, ResolvedAnswer, TYPE_A, TYPE_AAAA, TYPE_HTTPS};
use crate::strategy::DohSource;
use super::{EffectiveEndpoint, Resolver};
use super::endpoints::read_limited_body;
use super::lookup::{format_ips, MIN_CACHE_TTL_SECS};
use crate::util::{now, redact_url};



/// Negative-answer TTLs. These are deliberately short: a resolver that filters
/// a domain answers NODATA, and caching that for a full DNS window kept the
/// domain unroutable long after another endpoint would have answered. A total
/// endpoint failure only backs off briefly so a flapping endpoint recovers on
/// the next attempt.
pub(super) const NEGATIVE_NODATA_SECS: u32 = 20;
pub(super) const NEGATIVE_HTTPS_NODATA_SECS: u32 = 60;
pub(super) const NEGATIVE_FAILURE_SECS: u32 = 10;

/// Lanes and budget for the endpoints after the first two. The remote catalog
/// decides how many there are (up to 64), and one timeout each would let a
/// silent list stretch every cold lookup to minutes. Two lanes avoid queueing
/// behind one dead endpoint; the budget is two client timeouts so the second
/// wave can still find an answer behind a stalled first.
const FALLBACK_LANES: usize = 2;
const FALLBACK_WAVES: u32 = 2;

/// How long every dialled endpoint gets to answer before the query gives up
/// on it. DoH providers abroad often need a few seconds; a shorter window
/// discarded their answers. Capped by `catalogs.timeoutSecs`.
const ENDPOINT_WINDOW: Duration = Duration::from_secs(4);

/// How long the first endpoint gets before the second is dialled as well. The
/// second is a hedge, not a second racer: a healthy endpoint answers in a few
/// hundred milliseconds, and racing both from t=0 sent every queried name to
/// two providers on every cache miss.
const PRIMARY_HEDGE: Duration = Duration::from_millis(250);

/// Distinct addresses an A/AAAA answer must carry before the query stops
/// collecting. One address is a single point of failure — and exactly what a
/// filtering resolver hands back — so a thin answer is widened with the next
/// ranked endpoint instead of being accepted as-is.
const MIN_ADDRESS_CANDIDATES: usize = 2;
/// Endpoints that contributed data to one query before collection stops. A
/// failure is not a contribution, so a dead endpoint still lets the walk reach
/// the next one.
const MAX_ANSWER_SOURCES: usize = 3;
/// Independent empty answers needed before a query concludes that the record
/// does not exist. One endpoint saying "no records" can be a filter; two are
/// not. Without this, every IPv4-only host walked the whole catalog for its
/// (always empty) AAAA query — a query storm on the most common case.
const EMPTY_CONFIRMATIONS: usize = 2;

/// The upper bound of one live `doh_ips` call, excluding the single-flight
/// queue wait: one endpoint window plus the serial fallback waves. Callers
/// that await a lookup inside a larger budget — the raw connect race sizes
/// its whole wall-clock budget with this — use it instead of re-deriving the
/// constants.
pub(crate) fn doh_lookup_budget(catalog_timeout_secs: u64) -> Duration {
    let request = Duration::from_secs(catalog_timeout_secs.max(1));
    ENDPOINT_WINDOW.min(request) + request * FALLBACK_WAVES
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DohAttemptError {
    pub endpoint: String,
    pub source: DohSource,
    pub error: String,
}

pub struct TypeQuery {
    pub(super) answer: ResolvedAnswer,
    pub(super) source: DohSource,
    pub(super) endpoint: String,
    pub(super) attempts: Vec<DohAttemptError>,
    pub(super) fallback_used: bool,
    /// Whether the answer may be trusted without further confirmation. A
    /// useful answer always is; an empty (NODATA) answer only when every
    /// endpoint consulted for the query actually answered — a raced endpoint
    /// cancelled by the grace window never confirmed the silence, so it must
    /// not be cached as authoritative NODATA.
    pub(super) authoritative: bool,
}

/// Union of the answers one query collected from several endpoints.
///
/// The proxy wants a wide candidate set, not the first reply: a filtering
/// resolver answers with a subset (or NODATA), and discarding what another
/// endpoint returned threw away exactly the address that would have worked.
struct MergedAnswers {
    address_query: bool,
    ips: Vec<IpAddr>,
    ech: Option<Vec<u8>>,
    ttl: u32,
    cname: Option<String>,
    https_present: bool,
    /// First answer that carried nothing, kept so a total NODATA still has a
    /// precise `TypeQuery` to return.
    empty: Option<(usize, ResolvedAnswer)>,
    /// Endpoints that gave a conclusive answer (data or NODATA).
    answered: usize,
    /// Endpoints that contributed data. This is the collection cap; failures
    /// do not count, so a dead endpoint still lets the walk reach the next one.
    sources: usize,
    /// Endpoints that answered with data but added no new address.
    redundant: usize,
    /// First endpoint that contributed data, for source attribution.
    first_source: Option<usize>,
}

impl MergedAnswers {
    fn new(address_query: bool) -> Self {
        Self {
            address_query,
            ips: Vec::new(),
            ech: None,
            ttl: u32::MAX,
            cname: None,
            https_present: false,
            empty: None,
            answered: 0,
            sources: 0,
            redundant: 0,
            first_source: None,
        }
    }

    fn absorb(&mut self, index: usize, answer: ResolvedAnswer) {
        self.answered += 1;
        let before = self.ips.len();
        let useful = if self.address_query {
            !answer.ips.is_empty()
        } else {
            answer.ech.is_some()
        };
        if useful {
            self.sources += 1;
            self.first_source.get_or_insert(index);
        }
        if answer.ips.is_empty() && answer.ech.is_none() && self.empty.is_none() {
            self.empty = Some((index, answer.clone()));
        }
        if answer.ttl != 0 {
            self.ttl = self.ttl.min(answer.ttl);
        }
        self.https_present |= answer.https_present;
        if self.cname.is_none() {
            self.cname = answer.cname.clone();
        }
        for ip in answer.ips {
            if !self.ips.contains(&ip) {
                self.ips.push(ip);
            }
        }
        if self.address_query && useful && self.ips.len() == before {
            self.redundant += 1;
        }
        if self.ech.is_none() {
            self.ech = answer.ech;
        }
    }

    /// Whether this query has collected enough to stop.
    fn complete(&self) -> bool {
        // An empty answer needs as many confirmations as an ECH lookup: the
        // first NODATA may be a filter, the second makes it a conclusion.
        let confirmed_empty = self.ips.is_empty() && self.answered >= EMPTY_CONFIRMATIONS;
        if self.address_query {
            // Two addresses give the engine a real choice; one is a single
            // point of failure. A peer repeating that one address has nothing
            // left to add, so the walk stops instead of querying the catalog.
            self.ips.len() >= MIN_ADDRESS_CANDIDATES
                || self.redundant > 0
                || self.sources >= MAX_ANSWER_SOURCES
                || confirmed_empty
        } else {
            // ECH is a single domain-level value: the first copy is the whole
            // answer. Without it, a second independent NODATA is required.
            self.ech.is_some() || self.answered >= EMPTY_CONFIRMATIONS
        }
    }

    fn has_data(&self) -> bool {
        !self.ips.is_empty() || self.ech.is_some()
    }

    fn into_answer(self) -> ResolvedAnswer {
        ResolvedAnswer {
            ips: self.ips,
            ech: self.ech,
            ttl: if self.ttl == u32::MAX { 0 } else { self.ttl },
            cname: self.cname,
            https_present: self.https_present,
        }
    }
}

impl Resolver {
    pub(super) async fn query_one_type(&self, domain: &str, qtype: u16) -> Result<TypeQuery> {
        let endpoints = self.effective_endpoints();
        if endpoints.is_empty() {
            bail!("no DoH endpoint is configured");
        }
        // A remembered NODATA or total failure skips the full endpoint race for
        // this window. Stale answers are still served by the callers above.
        if self.cache.doh_negative(domain, qtype) {
            bail!("cached negative answer for `{domain}` qtype {qtype}");
        }
        let address_query = matches!(qtype, TYPE_A | TYPE_AAAA);
        let timeout = Duration::from_secs(self.config.snapshot().catalogs.timeout_secs.max(1));
        let endpoint_deadline = tokio::time::Instant::now() + ENDPOINT_WINDOW.min(timeout);
        // Policy order: a cooling endpoint drops behind the healthy ones; the
        // user's configured order is kept among equals.
        let order = self.endpoint_order(&endpoints);
        let primary = order[0];
        let mut merged = MergedAnswers::new(address_query);
        let mut attempts: Vec<DohAttemptError> = Vec::new();
        // Per-endpoint outcome of this query: None until the endpoint produced
        // a result. The authoritative-NODATA decision reads it.
        let mut outcome: Vec<Option<bool>> = vec![None; endpoints.len()];
        // Endpoints actually contacted, in launch order.
        let mut asked: Vec<usize> = Vec::new();

        // The first two ranked endpoints. The second is a hedge: it joins when
        // the first fails, answers without enough data, or stalls past
        // PRIMARY_HEDGE. Racing both from t=0 sent every queried name to two
        // providers even when the first was healthy.
        let mut pending: FuturesUnordered<
            futures_util::future::BoxFuture<'_, (usize, Instant, Result<ResolvedAnswer>)>,
        > = FuturesUnordered::new();
        let mut cursor = 1usize;
        let mut second_started = order.len() < 2;
        asked.push(primary);
        {
            let endpoint = &endpoints[primary];
            pending.push(Box::pin(async move {
                let queued = Instant::now();
                (
                    primary,
                    queued,
                    self.query_endpoint(endpoint, domain, qtype).await,
                )
            }));
        }
        let mut hedge_at = if second_started {
            None
        } else {
            Some(tokio::time::Instant::now() + PRIMARY_HEDGE)
        };
        let stage_deadline = endpoint_deadline;
        enum StageEvent {
            Item(Option<(usize, Instant, Result<ResolvedAnswer>)>),
            Hedge,
            Deadline,
        }
        loop {
            if pending.is_empty() {
                break;
            }
            let deadline = stage_deadline;
            let event = match hedge_at {
                Some(at) if at < deadline => tokio::select! {
                    item = pending.next() => StageEvent::Item(item),
                    _ = tokio::time::sleep_until(at) => StageEvent::Hedge,
                },
                _ => match tokio::time::timeout_at(deadline, pending.next()).await {
                    Ok(item) => StageEvent::Item(item),
                    Err(_) => StageEvent::Deadline,
                },
            };
            match event {
                StageEvent::Deadline | StageEvent::Item(None) => break,
                StageEvent::Hedge => {
                    hedge_at = None;
                    if !second_started {
                        second_started = true;
                        let index = order[cursor];
                        cursor += 1;
                        asked.push(index);
                        tracing::debug!(
                            domain = %domain,
                            qtype,
                            waited_ms = PRIMARY_HEDGE.as_millis() as u64,
                            next = %endpoints[index].name,
                            "doh endpoint is slow; running the next one in parallel"
                        );
                        let endpoint = &endpoints[index];
                        pending.push(Box::pin(async move {
                            let queued = Instant::now();
                            (
                                index,
                                queued,
                                self.query_endpoint(endpoint, domain, qtype).await,
                            )
                        }));
                    }
                }
                StageEvent::Item(Some((index, queued, result))) => {
                    hedge_at = None;
                    let endpoint = &endpoints[index];
                    match result {
                        Ok(answer) => {
                            outcome[index] = Some(true);
                            self.record_health(endpoint, true, queued.elapsed(), None);
                            merged.absorb(index, answer);
                            if merged.complete() {
                                return self.finish_query(
                                    domain, qtype, &endpoints, primary, merged, attempts, &asked,
                                    &outcome,
                                );
                            }
                            // A conclusive but insufficient answer means the
                            // peer still has time to improve on it.
                            tracing::debug!(
                                domain = %domain,
                                qtype,
                                addresses = merged.ips.len(),
                                answered = merged.answered,
                                "doh answer is not enough yet; widening"
                            );
                        }
                        Err(error) => {
                            outcome[index] = Some(false);
                            self.record_health(
                                endpoint,
                                false,
                                queued.elapsed(),
                                Some(format!("{error:#}")),
                            );
                            tracing::debug!(
                                endpoint = %redact_url(&endpoint.url),
                                domain = %domain,
                                qtype,
                                error = %error,
                                "DoH query failed"
                            );
                            attempts.push(DohAttemptError {
                                endpoint: endpoint.name.clone(),
                                source: endpoint.source,
                                error: format!("{error:#}"),
                            });
                        }
                    }
                    // A failure or a thin answer makes the next ranked
                    // endpoint cheaper than waiting out the hedge window.
                    if !second_started && cursor < order.len() {
                        second_started = true;
                        let index = order[cursor];
                        cursor += 1;
                        asked.push(index);
                        let endpoint = &endpoints[index];
                        pending.push(Box::pin(async move {
                            let queued = Instant::now();
                            (
                                index,
                                queued,
                                self.query_endpoint(endpoint, domain, qtype).await,
                            )
                        }));
                    }
                }
            }
        }
        // Anything still in flight at the endpoint deadline is dropped
        // silently instead of being remembered as a failure.
        let mut tail_deadline = Some(endpoint_deadline);
        // The rest of the ranked list, two lanes at a time under one budget.
        // The catalog can be long; the budget bounds it.
        let budget = tokio::time::Instant::now() + timeout * FALLBACK_WAVES;
        loop {
            if tail_deadline.is_none() {
                while pending.len() < FALLBACK_LANES && cursor < order.len() {
                    let index = order[cursor];
                    cursor += 1;
                    if asked.contains(&index) {
                        continue;
                    }
                    asked.push(index);
                    let endpoint = &endpoints[index];
                    pending.push(Box::pin(async move {
                        let queued = Instant::now();
                        (
                            index,
                            queued,
                            self.query_endpoint(endpoint, domain, qtype).await,
                        )
                    }));
                }
            }
            let deadline = tail_deadline.unwrap_or(budget).min(budget);
            let next = match tokio::time::timeout_at(deadline, pending.next()).await {
                Ok(next) => next,
                Err(_) if tail_deadline.is_some() => {
                    pending = FuturesUnordered::new();
                    tail_deadline = None;
                    continue;
                }
                // The shared budget is spent. Queries still in flight are
                // dropped and keep no health record this round.
                Err(_) => break,
            };
            let Some((index, queued, result)) = next else {
                if tail_deadline.is_some() {
                    tail_deadline = None;
                    continue;
                }
                break;
            };
            let endpoint = &endpoints[index];
            match result {
                Ok(answer) => {
                    outcome[index] = Some(true);
                    self.record_health(endpoint, true, queued.elapsed(), None);
                    merged.absorb(index, answer);
                    if merged.complete() {
                        return self.finish_query(
                            domain, qtype, &endpoints, primary, merged, attempts, &asked, &outcome,
                        );
                    }
                }
                Err(error) => {
                    outcome[index] = Some(false);
                    self.record_health(
                        endpoint,
                        false,
                        queued.elapsed(),
                        Some(format!("{error:#}")),
                    );
                    tracing::debug!(
                        endpoint = %redact_url(&endpoint.url),
                        domain = %domain,
                        qtype,
                        error = %error,
                        "DoH query failed"
                    );
                    attempts.push(DohAttemptError {
                        endpoint: endpoint.name.clone(),
                        source: endpoint.source,
                        error: format!("{error:#}"),
                    });
                }
            }
        }
        self.finish_query(
            domain, qtype, &endpoints, primary, merged, attempts, &asked, &outcome,
        )
    }

    /// Turn the collected answers into a `TypeQuery`: the union when there is
    /// data, an authoritative-NODATA decision when every asked endpoint
    /// answered, and a precise failure otherwise.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_query(
        &self,
        domain: &str,
        qtype: u16,
        endpoints: &[EffectiveEndpoint],
        primary: usize,
        merged: MergedAnswers,
        attempts: Vec<DohAttemptError>,
        asked: &[usize],
        outcome: &[Option<bool>],
    ) -> Result<TypeQuery> {
        // `fallback_used` now means what it says: a second endpoint was
        // involved (as a source or as a failed attempt).
        let fallback_used =
            merged.sources > 1 || merged.first_source != Some(primary) || !attempts.is_empty();
        if merged.has_data() {
            let first = merged.first_source.unwrap_or(primary);
            let answer = merged.into_answer();
            self.store_answer(domain, qtype, &answer);
            let endpoint = &endpoints[first];
            return Ok(TypeQuery {
                answer,
                source: endpoint.source,
                endpoint: endpoint.name.clone(),
                fallback_used,
                attempts,
                authoritative: true,
            });
        }
        let Some((index, answer)) = merged.empty else {
            let detail = attempts
                .iter()
                .map(|attempt| format!("{}: {}", attempt.endpoint, attempt.error))
                .collect::<Vec<_>>()
                .join("; ");
            if attempts.is_empty() {
                // Nothing failed: the deadline cancelled every query while it
                // was still in flight. Caching that as a hard failure
                // black-holed the domain for NEGATIVE_FAILURE_SECS even though
                // a healthy-but-slow endpoint would answer the next attempt.
                bail!("all DoH endpoints silent: race deadline exceeded before any answered");
            }
            self.cache
                .put_doh_negative(domain, qtype, NEGATIVE_FAILURE_SECS, false);
            bail!("all DoH endpoints failed: {detail}");
        };
        // A NODATA answer repeats for every cold connection, so remember it —
        // but only as authoritative when every endpoint we asked actually
        // answered. A peer cut off by the deadline never confirmed the
        // silence, and caching that would hide a working endpoint.
        let authoritative =
            !asked.is_empty() && asked.iter().all(|&asked| outcome[asked] == Some(true));
        let ttl = if authoritative && qtype == TYPE_HTTPS {
            NEGATIVE_HTTPS_NODATA_SECS
        } else if authoritative {
            NEGATIVE_NODATA_SECS
        } else {
            NEGATIVE_FAILURE_SECS
        };
        self.cache
            .put_doh_negative(domain, qtype, ttl, authoritative);
        let endpoint = &endpoints[index];
        Ok(TypeQuery {
            answer,
            source: endpoint.source,
            endpoint: endpoint.name.clone(),
            fallback_used,
            attempts,
            authoritative,
        })
    }

    /// Persist a successful resolution into the answer/ECH caches.
    pub(super) fn store_answer(&self, domain: &str, qtype: u16, answer: &ResolvedAnswer) {
        // A real answer supersedes any remembered negative result
        self.cache.clear_doh_negative(domain, qtype);
        if qtype == TYPE_A || qtype == TYPE_AAAA {
            self.cache.put_doh_answer(CachedAnswer {
                domain: domain.to_string(),
                qtype,
                ips: answer.ips.clone(),
                ech_config: answer
                    .ech
                    .as_ref()
                    .map(|ech| base64::engine::general_purpose::STANDARD.encode(ech)),
                ttl_secs: answer.ttl.max(MIN_CACHE_TTL_SECS),
                fetched_at: now(),
            });
        } else if qtype == TYPE_HTTPS {
            // HTTPS RRs only feed the ECH cache. A `CachedAnswer` with an
            // empty IP list is never read (fresh/stale resolution only looks
            // at A/AAAA) and used to occupy the bounded answer cache, evicting
            // real addresses. It also encoded the ECHConfigList a second time.
            if let Some(ech) = &answer.ech {
                self.cache.put_ech(CachedEch {
                    domain: domain.to_string(),
                    ech_config: ech.clone(),
                    // Same floor as the A/AAAA path above: a zero-TTL HTTPS
                    // RR would otherwise never count as fresh and re-query
                    // the endpoints on every cold handshake.
                    ttl_secs: answer.ttl.max(MIN_CACHE_TTL_SECS),
                    fetched_at: now(),
                });
            }
        }
    }

    pub(super) async fn query_endpoint(
        &self,
        endpoint: &EffectiveEndpoint,
        domain: &str,
        qtype: u16,
    ) -> Result<ResolvedAnswer> {
        let started = Instant::now();
        let result = self.query_endpoint_inner(endpoint, domain, qtype).await;
        match &result {
            Ok(_) => {}
            Err(error) => {
                // A DoH failure is one of the two classic reasons why a site
                // becomes unroutable, so it must be visible at the default log
                // level and must name the endpoint that failed.
                tracing::warn!(
                    endpoint = %endpoint.name,
                    url = %redact_url(&endpoint.url),
                    source = %endpoint.source,
                    domain = %domain,
                    qtype,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    error = %format!("{error:#}"),
                    "doh query failed"
                );
            }
        }
        result
    }

    async fn query_endpoint_inner(
        &self,
        endpoint: &EffectiveEndpoint,
        domain: &str,
        qtype: u16,
    ) -> Result<ResolvedAnswer> {
        let config = self.config.snapshot();
        let timeout = Duration::from_secs(config.catalogs.timeout_secs.max(1));
        let client = self.client_for(endpoint, timeout)?;
        let id: u16 = rand::rng().random();
        let query = dns::build_query(domain, qtype, id)?;
        let started = Instant::now();
        let response = client
            .post(&endpoint.url)
            .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
            .header(reqwest::header::ACCEPT, "application/dns-message")
            .body(query)
            .send()
            .await
            .map_err(|error| {
                // reqwest's Display repeats the request URL, including a token
                // in the path. Keep only our already-redacted endpoint in the
                // error that is stored in health/status and shown in exports.
                anyhow::anyhow!(
                    "POST {} failed: {}",
                    redact_url(&endpoint.url),
                    error.without_url()
                )
            })?;
        let status = response.status();
        if !status.is_success() {
            bail!("DoH endpoint returned HTTP {status}");
        }
        let body = read_limited_body(response).await?;
        let parsed = dns::parse_response(&body).context("parsing DoH response")?;
        if parsed.id != id {
            bail!(
                "DoH response id mismatch (expected {id}, got {})",
                parsed.id
            );
        }
        if let Some(question) = parsed.questions.first() {
            if question.name != domain.trim_end_matches('.') || question.qtype != qtype {
                bail!(
                    "DoH response question mismatch ({} type {})",
                    question.name,
                    question.qtype
                );
            }
        }
        if parsed.rcode != 0 {
            bail!("DoH response code {}", parsed.rcode_text());
        }
        let answer = dns::extract_answer(&parsed, domain, qtype);
        // The answer set is the whole point of a DoH lookup: without it a log
        // reader cannot tell "DoH is unreachable" apart from "DoH answered but
        // the answer was empty", and those two need very different fixes.
        tracing::info!(
            endpoint = %endpoint.name,
            url = %redact_url(&endpoint.url),
            source = %endpoint.source,
            domain = %domain,
            qtype,
            elapsed_ms = started.elapsed().as_millis() as u64,
            ips = %format_ips(&answer.ips),
            // An HTTPS answer carries no addresses; whether it carried the
            // ECHConfig is the fact that decides the route.
            ech = answer.ech.is_some(),
            ttl_secs = answer.ttl,
            "doh query answered"
        );
        Ok(answer)
    }

}
