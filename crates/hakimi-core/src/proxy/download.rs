//! Large downloads: a chunk queue plus in-order assembly.
//!
//! The first upstream stream (the response to the browser's own request) fills
//! chunks from the head of the file; segment connections claim chunks from the
//! tail. They meet in the middle. Chunks are reordered before delivery, so the
//! bytes and the content-length match a single connection exactly.

use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::Full;
use hyper::body::{Frame, Incoming, SizeHint};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use super::pool::UpstreamResponse;
use super::upstream::strip_mirror_cookies;
use super::ProxyBody;
use crate::config::AppConfig;
use http_body_util::BodyExt;

const MIB: u64 = 1024 * 1024;
/// Cap on finished-but-undelivered chunks; segment connections pause above it
const BACKLOG_CHUNKS: usize = 8;
/// Per-chunk attempt cap; a re-dial can pick a different IP
const MAX_ATTEMPTS: u32 = 3;
/// A range probe must not hold the browser's first byte for long
pub(crate) const RANGE_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// The streaming worker owns this chunk: its bytes start at file offset 0.
const STREAM_CHUNK: u64 = 0;
/// The shared counter starts after [`STREAM_CHUNK`] so no other worker can
/// claim the streaming chunk out from under the stream.
const NEXT_AFTER_STREAM_CHUNK: u64 = STREAM_CHUNK + 1;

pub struct DownloadManager {
    slots: Arc<Semaphore>,
    active: Arc<AtomicUsize>,
    finished: Arc<AtomicU64>,
    pub(crate) mirrors: Arc<crate::mirror::MirrorList>,
}

impl DownloadManager {
    pub(crate) fn new(config: &AppConfig, mirrors: Arc<crate::mirror::MirrorList>) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(config.advanced.download.max_conns.max(4))),
            active: Arc::new(AtomicUsize::new(0)),
            finished: Arc::new(AtomicU64::new(0)),
            mirrors,
        }
    }

    pub(crate) fn stats(&self) -> (usize, u64) {
        (
            self.active.load(Ordering::Relaxed),
            self.finished.load(Ordering::Relaxed),
        )
    }
}

/// Header-only gate: status, size floor, range support. Returns the body
/// length when the response can be sliced into byte ranges.
///
/// `min_size` is the caller's floor, not a suggestion: image CDNs qualify at a
/// few hundred KiB, and clamping it up to [`MIB`] here silently disabled that
/// path while every unit test that used the archive floor still passed.
fn headers_eligible(
    status: StatusCode,
    content_length: Option<&str>,
    accept_ranges: Option<&str>,
    min_size: u64,
) -> Option<u64> {
    if status != StatusCode::OK {
        return None;
    }
    let len: u64 = content_length?.trim().parse().ok()?;
    if len < min_size {
        return None;
    }
    accept_ranges?
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("bytes"))
        .then_some(len)
}

/// Response-header gate shared by [`segment_eligible`] and the mirror
/// failover: a body can only be sliced when it is a plain 200 with a usable
/// Content-Length, advertised byte ranges and no content encoding. Returns
/// the body length when the response qualifies.
pub(crate) fn response_eligible<B>(response: &http::Response<B>) -> Option<u64> {
    response_eligible_from(response, MIB)
}

/// Same gate with a caller-chosen size floor. Image CDNs qualify far below the
/// archive floor, so the shared helper cannot bake in one MiB.
pub(crate) fn response_eligible_from<B>(response: &http::Response<B>, min_size: u64) -> Option<u64> {
    let headers = response.headers();
    if content_encoded(headers) {
        return None;
    }
    headers_eligible(
        response.status(),
        headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        headers
            .get(header::ACCEPT_RANGES)
            .and_then(|value| value.to_str().ok()),
        min_size,
    )
}

/// A response that carries a content encoding cannot be sliced by byte offset:
/// range requests are normally answered with the identity representation, so
/// the offsets would refer to different bytes.
fn content_encoded(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
}

/// `bytes START-END/TOTAL`; the total may be `*`.
fn parse_content_range(value: &str) -> Option<(u64, u64, Option<u64>)> {
    let rest = value.trim().strip_prefix("bytes")?.trim_start();
    let (range, total) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.trim().parse().ok()?;
    let end = end.trim().parse().ok()?;
    if start > end {
        return None;
    }
    let total = match total.trim() {
        "*" => None,
        total => Some(total.parse().ok()?),
    };
    Some((start, end, total))
}

/// The small subset of browser headers a range request needs. A segmented
/// download re-sends these on every chunk, so keeping only them avoids
/// carrying (and deep-cloning) the whole `HeaderMap` on the hot path.
pub(crate) fn credential_headers(base: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for name in [
        header::USER_AGENT,
        header::REFERER,
        header::COOKIE,
        header::AUTHORIZATION,
    ] {
        if let Some(value) = base.get(&name) {
            headers.insert(name, value.clone());
        }
    }
    headers
}

/// Headers for the range requests that fill the later chunks. The base is the
/// browser's request with credentials already stripped when the response came
/// from a mirror, so a third party never sees the GitHub session.
fn range_request_headers(base: &HeaderMap, response: &HeaderMap) -> HeaderMap {
    let mut headers = credential_headers(base);
    headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    // If the file changed between the first response and a segment request,
    // the server answers 200 instead of 206 and the worker stops instead of
    // splicing two versions together.
    if let Some(validator) = response
        .get(header::ETAG)
        .or_else(|| response.get(header::LAST_MODIFIED))
    {
        headers.insert(header::IF_RANGE, validator.clone());
    }
    headers
}

/// The `Host` header for a request sent on hyper's raw `client::conn` API.
///
/// That API never synthesizes `Host` ("req must have a Host header", hyper's
/// own docs); only `hyper_util`'s legacy client adds it, which the main pool
/// uses and the segment/probe paths bypass. An HTTP/1.1 origin must answer
/// 400 without one (nginx does by default), so every range request would fail.
fn host_header(uri: &Uri) -> Option<HeaderValue> {
    let host = uri.host()?;
    let default = if uri.scheme_str() == Some("https") {
        443
    } else {
        80
    };
    let value = match uri.port_u16() {
        Some(port) if port != default => format!("{host}:{port}"),
        _ => host.to_string(),
    };
    HeaderValue::from_str(&value).ok()
}

/// Built-in download host rules (hardcoded in v1)
fn candidate_uri(uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    let host = crate::domain::bare_host(host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "codeload.github.com" {
        return true;
    }
    if host == "github.com" {
        let path = uri.path();
        return path.contains("/releases/download/") || path.contains("/releases/latest/download/");
    }
    host.ends_with(".githubusercontent.com")
}

/// The narrow subset that may go through a mirror: release assets and source
/// archives. Avatars, raw files and other page resources stay direct.
///
/// Unsigned entry points only. GitHub 302s an asset to a signed storage host;
/// handing that URL to a third party both leaks the credential and fails after
/// the host swap, so matching stops at github.com.
pub(crate) fn mirror_candidate(uri: &Uri) -> bool {
    // runs on every request, so no allocation here
    let Some(host) = uri.host() else {
        return false;
    };
    let host = crate::domain::bare_host(host).trim_end_matches('.');
    if host.eq_ignore_ascii_case("codeload.github.com") {
        return true;
    }
    if !host.eq_ignore_ascii_case("github.com") {
        return false;
    }
    // /{owner}/{repo}/releases/download/… or /{owner}/{repo}/archive/…
    // matching on segments, not substrings: a blob path such as
    // /owner/repo/blob/main/archive/x.md is a web page and must stay direct
    let mut segments = uri.path().split('/').filter(|segment| !segment.is_empty());
    let (Some(_owner), Some(_repo), Some(kind)) =
        (segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    match kind {
        // releases/latest/download is the shorthand form of the same asset
        "releases" => matches!(segments.next(), Some("download" | "latest")),
        "archive" => true,
        _ => false,
    }
}

/// Signed URLs are never rewritten: the signature is the credential, and it
/// stops working under a different host
pub(crate) fn signed_url(uri: &Uri) -> bool {
    let Some(query) = uri.query() else {
        return false;
    };
    query.split('&').any(|pair| {
        let key = pair
            .split('=')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        matches!(
            key.as_str(),
            "sig"
                | "signature"
                | "policy"
                | "key-pair-id"
                | "token"
                | "access_token"
                | "jwt"
                | "api_key"
                | "apikey"
                | "auth"
                | "code"
                | "credential"
                | "password"
        ) || key.starts_with("x-amz-")
            || key.starts_with("x-goog-")
    })
}

/// Rewrites a matching download to `{prefix}/{original url}`. The browser does
/// not notice, and the segment engine works against the mirror directly.
///
/// The candidates come back in list order and the caller walks them one by one:
/// a mirror that fails is cooled down and the next one is tried before giving
/// up on speed-up altogether.
pub(crate) struct MirrorPlan {
    origin: String,
    pub(crate) candidates: Vec<String>,
}

impl MirrorPlan {
    pub(crate) fn rewrite(&self, prefix: &str) -> Option<Uri> {
        format!("{prefix}/{}", self.origin).parse().ok()
    }
}

pub(crate) fn mirror_origins(
    download: &crate::config::DownloadConfig,
    mirrors: &crate::mirror::MirrorList,
    method: &Method,
    uri: &Uri,
) -> Option<MirrorPlan> {
    // a retry has to resend an empty body, so only bodyless methods qualify
    if *method != Method::GET && *method != Method::HEAD {
        return None;
    }
    // `enabled` only gates segmentation; the mirror has its own switch, the
    // source URL, so a user can keep one and drop the other
    if download.mirror_source.trim().is_empty() || !mirror_candidate(uri) || signed_url(uri) {
        return None;
    }
    let candidates = mirrors.available();
    if candidates.is_empty() {
        return None;
    }
    let origin = format!(
        "{}://{}{}",
        uri.scheme_str()?,
        uri.authority()?.as_str(),
        uri.path_and_query()?
    );
    Some(MirrorPlan { origin, candidates })
}

pub(crate) fn segment_eligible(
    ctx: &super::ProxyContext,
    rule_uri: &Uri,
    is_get: bool,
    has_range: bool,
    response: &UpstreamResponse,
) -> bool {
    if !is_get || has_range {
        return false;
    }
    // a 1 MiB hard floor rejects most traffic before the config snapshot is paid for
    let Some(len) = response_eligible(response) else {
        return false;
    };
    let config = &ctx.config.snapshot().advanced.download;
    if !config.enabled || ctx.status.paused() {
        return false;
    }
    if len < config.min_size_bytes {
        return false;
    }
    candidate_uri(rule_uri)
}

/// Single cursor: every segment claims the next chunk near the consumer, so N
/// connections fill the window in front of the browser in parallel. An earlier
/// two-cursor design (streaming head, dialled tail) always serialized the head
/// behind one connection while the bandwidth piled up at the end.
fn claim(next: &AtomicU64, chunks_total: u64) -> Option<u64> {
    let index = next.fetch_add(1, Ordering::Relaxed);
    (index < chunks_total).then_some(index)
}

fn expected_chunk_len(index: u64, chunks_total: u64, chunk_len: u64, total_len: u64) -> usize {
    if index + 1 == chunks_total {
        (total_len - index * chunk_len) as usize
    } else {
        chunk_len as usize
    }
}

struct Shared {
    uri: Uri,
    pool: Arc<super::UpstreamPool>,
    slots: Arc<Semaphore>,
    /// Base headers for segment requests (never the mirror's credentials)
    headers: HeaderMap,
    chunks_total: u64,
    chunk_len: u64,
    total_len: u64,
    stall: Duration,
    header_wait: Duration,
    backlog: Arc<Semaphore>,
    order_tx: mpsc::Sender<(u64, Bytes)>,
    next: AtomicU64,
    fatal_tx: watch::Sender<bool>,
    fatal_rx: watch::Receiver<bool>,
    reason: Mutex<Option<String>>,
    /// Bytes actually handed to the browser for this download
    delivered: AtomicU64,
    /// Process-wide total, kept for the status endpoint
    finished: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
    started: Instant,
    host: String,
}

impl Shared {
    fn set_fatal(&self, reason: &str) {
        {
            let mut slot = self.reason.lock().unwrap();
            if slot.is_none() {
                *slot = Some(reason.to_string());
            }
        }
        let _ = self.fatal_tx.send(true);
        // Log the path but not the query: direct storage URLs carry signatures
        // in `sig`/`jwt`/`X-Amz-*`, and this file is a local log.
        let url = uri_without_query(&self.uri);
        tracing::warn!(
            host = %self.host,
            url = %truncate(&url, 300),
            reason,
            "segmented download failed"
        );
    }
}

fn uri_without_query(uri: &Uri) -> String {
    match (uri.scheme_str(), uri.authority()) {
        (Some(scheme), Some(authority)) => format!("{scheme}://{authority}{}", uri.path()),
        _ => uri.path().to_string(),
    }
}

fn truncate(value: &str, max: usize) -> &str {
    match value.char_indices().nth(max) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

/// Read the body of a non-206 reply; a mirror explains itself there.
/// The timeout matters: a server that sends headers and then stalls the body
/// must not wedge a segment worker forever.
async fn error_body_text(body: Incoming, timeout: Duration) -> String {
    let limited = http_body_util::Limited::new(body, 256);
    match tokio::time::timeout(timeout, limited.collect()).await {
        Ok(Ok(collected)) => String::from_utf8_lossy(&collected.to_bytes())
            .trim()
            .to_string(),
        _ => String::new(),
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        tracing::info!(
            host = %self.host,
            bytes = self.delivered.load(Ordering::Relaxed),
            elapsed_ms = self.started.elapsed().as_millis() as u64,
            "segmented download ended"
        );
    }
}

enum Source {
    Stream(Incoming),
    Dialed(DialedConnection),
    None,
}

struct DialedConnection {
    tx: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    _conn: JoinHandle<()>,
    _slot: OwnedSemaphorePermit,
}

enum ReadOutcome {
    Complete,
    SourceDead(String),
}

struct Worker {
    shared: Arc<Shared>,
    source: Source,
    carry: Option<Bytes>,
    /// A pooled response can carry an image-host concurrency permit, held until
    /// the streaming segment exits
    _upstream_permit: Option<OwnedSemaphorePermit>,
}

impl Worker {
    /// Reserve one slot in the "downloaded but not yet delivered" window.
    ///
    /// The permit is intentionally forgotten instead of dropped: it represents
    /// a chunk the merger has not handed to the browser yet, so `run_merger` is
    /// the single place that returns it (`add_permits(1)` when a chunk is
    /// delivered). Dropping it here would return the permit as soon as the chunk
    /// is *downloaded* rather than *delivered*, and two returns per chunk would
    /// make the semaphore grow without bound so `wait_backlog` never blocks.
    async fn wait_backlog(&self) -> bool {
        loop {
            if *self.shared.fatal_rx.borrow() {
                return false;
            }
            let mut fatal_rx = self.shared.fatal_rx.clone();
            tokio::select! {
                changed = fatal_rx.changed() => {
                    if changed.is_err() {
                        return false;
                    }
                }
                permit = self.shared.backlog.clone().acquire_owned() => {
                    return match permit {
                        Ok(permit) => {
                            permit.forget();
                            true
                        }
                        Err(_) => false,
                    };
                }
            }
        }
    }

    async fn dial(&self) -> Result<Source, String> {
        let slot = self
            .shared
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "download slots closed".to_string())?;
        let io = self.shared.pool.dial_http1(self.shared.uri.clone()).await?;
        let (tx, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|error| format!("h1 handshake failed: {error}"))?;
        let handle = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(Source::Dialed(DialedConnection {
            tx,
            _conn: handle,
            _slot: slot,
        }))
    }

    async fn run(mut self) {
        loop {
            if *self.shared.fatal_rx.borrow() {
                return;
            }
            if !self.wait_backlog().await {
                return;
            }
            // The response stream starts at file offset 0, so its worker owns
            // chunk 0 no matter when the runtime schedules it. Letting it race
            // for the shared counter let a tail worker claim chunk 0 first and
            // the stream then filed file-head bytes under a later index —
            // reassembly is ordered by index, so the corruption was silent.
            let streaming = matches!(self.source, Source::Stream(_));
            let index = if streaming {
                STREAM_CHUNK
            } else {
                let Some(index) = claim(&self.shared.next, self.shared.chunks_total) else {
                    // No chunk was claimed, so the reserved delivery slot is
                    // unused. `wait_backlog` forgot its permit (the merger is
                    // the single return point for delivered chunks), so put it
                    // back to keep the semaphore balanced.
                    self.shared.backlog.add_permits(1);
                    return;
                };
                index
            };
            if let Err(reason) = self.fill_chunk(index).await {
                // The chunk will never be delivered, so release its reserved
                // slot before aborting the whole download.
                self.shared.backlog.add_permits(1);
                self.shared.set_fatal(&reason);
                return;
            }
            if streaming {
                // drop the stream once the first chunk is done: one connection
                // caps the speed the browser sees. Later chunks come from dialled
                // connections in parallel. Any carry read past the chunk boundary
                // is discarded and re-fetched by a range request.
                if let Some(carry) = self.carry.take() {
                    tracing::debug!(
                        host = %self.shared.host,
                        dropped = carry.len(),
                        "discarded carry bytes after the stream chunk"
                    );
                }
                self.source = Source::None;
            }
        }
    }

    async fn fill_chunk(&mut self, index: u64) -> Result<(), String> {
        let start = index * self.shared.chunk_len;
        let end = ((index + 1) * self.shared.chunk_len).min(self.shared.total_len);
        let expected = (end - start) as usize;
        let mut got = 0usize;
        let mut attempts = 0u32;
        loop {
            if *self.shared.fatal_rx.borrow() {
                return Err("download cancelled".into());
            }
            if matches!(self.source, Source::None) {
                match self.dial().await {
                    Ok(source) => self.source = source,
                    Err(reason) => {
                        attempts += 1;
                        if attempts >= MAX_ATTEMPTS {
                            return Err(format!(
                                "chunk {index} failed after {attempts} attempts: {reason}"
                            ));
                        }
                        continue;
                    }
                }
            }
            let outcome = match &mut self.source {
                Source::Stream(body) => {
                    read_stream(
                        &self.shared,
                        body,
                        &mut self.carry,
                        index,
                        expected,
                        &mut got,
                    )
                    .await
                }
                Source::Dialed(conn) => {
                    read_dialed(
                        &self.shared,
                        conn,
                        index,
                        start + got as u64,
                        end - 1,
                        expected,
                        &mut got,
                    )
                    .await
                }
                Source::None => unreachable!("source established above"),
            };
            match outcome {
                ReadOutcome::Complete => {
                    self.shared
                        .finished
                        .fetch_add(expected as u64, Ordering::Relaxed);
                    return Ok(());
                }
                ReadOutcome::SourceDead(reason) => {
                    self.source = Source::None;
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(format!(
                            "chunk {index} failed after {attempts} attempts: {reason}"
                        ));
                    }
                    tracing::debug!(host = %self.shared.host, index, attempts, %reason, "retrying download chunk");
                }
            }
        }
    }
}

/// Slice bytes on chunk boundaries and enqueue them, returning the remainder
/// that belongs to the next chunk. A missing aggregator sets fatal, which the
/// caller notices on its next check.
async fn push_bytes(
    shared: &Shared,
    index: u64,
    data: Bytes,
    expected: usize,
    got: &mut usize,
) -> Bytes {
    let need = expected - *got;
    let (head, leftover) = if data.len() <= need {
        *got += data.len();
        (data, Bytes::new())
    } else {
        *got += need;
        (data.slice(..need), data.slice(need..))
    };
    if shared.order_tx.send((index, head)).await.is_err() {
        shared.set_fatal("aggregator went away");
    }
    leftover
}

async fn read_stream(
    shared: &Shared,
    body: &mut Incoming,
    carry: &mut Option<Bytes>,
    index: u64,
    expected: usize,
    got: &mut usize,
) -> ReadOutcome {
    if let Some(pending) = carry.take() {
        let leftover = push_bytes(shared, index, pending, expected, got).await;
        if !leftover.is_empty() {
            *carry = Some(leftover);
            return ReadOutcome::Complete;
        }
    }
    loop {
        if *got == expected {
            return ReadOutcome::Complete;
        }
        if *shared.fatal_rx.borrow() {
            return ReadOutcome::SourceDead("download cancelled".into());
        }
        let frame = match tokio::time::timeout(shared.stall, body.frame()).await {
            Err(_) => return ReadOutcome::SourceDead("upstream stream stalled".into()),
            Ok(Some(Err(error))) => {
                return ReadOutcome::SourceDead(format!("upstream stream error: {error}"))
            }
            Ok(None) => {
                return ReadOutcome::SourceDead(format!(
                    "upstream stream ended {} bytes early",
                    expected - *got
                ))
            }
            Ok(Some(Ok(frame))) => frame,
        };
        let Some(data) = frame.data_ref() else {
            continue;
        };
        let leftover = push_bytes(shared, index, data.clone(), expected, got).await;
        if !leftover.is_empty() {
            *carry = Some(leftover);
            return ReadOutcome::Complete;
        }
    }
}

async fn read_dialed(
    shared: &Shared,
    conn: &mut DialedConnection,
    index: u64,
    range_start: u64,
    range_end: u64,
    expected: usize,
    got: &mut usize,
) -> ReadOutcome {
    if conn.tx.is_closed() {
        return ReadOutcome::SourceDead("connection closed".into());
    }
    let Ok(range) = HeaderValue::from_bytes(format!("bytes={range_start}-{range_end}").as_bytes())
    else {
        return ReadOutcome::SourceDead("range header build failed".into());
    };
    let mut headers = shared.headers.clone();
    headers.insert(header::RANGE, range);
    if let Some(host) = host_header(&shared.uri) {
        headers.insert(header::HOST, host);
    }
    let mut request = match Request::builder()
        .method(Method::GET)
        .uri(shared.uri.clone())
        .body(Full::new(Bytes::new()))
    {
        Ok(request) => request,
        Err(error) => {
            return ReadOutcome::SourceDead(format!("range request build failed: {error}"))
        }
    };
    *request.headers_mut() = headers;
    let response = match tokio::time::timeout(shared.header_wait, conn.tx.send_request(request))
        .await
    {
        Err(_) => return ReadOutcome::SourceDead("range request header timeout".into()),
        Ok(Err(error)) => return ReadOutcome::SourceDead(format!("range request failed: {error}")),
        Ok(Ok(response)) => response,
    };
    let status = response.status();
    if status != StatusCode::PARTIAL_CONTENT {
        let body_text = error_body_text(
            response.into_body(),
            shared.stall.min(Duration::from_secs(3)),
        )
        .await;
        let detail = if body_text.is_empty() {
            String::new()
        } else {
            format!(": {}", truncate(&body_text, 200))
        };
        return ReadOutcome::SourceDead(format!("range request returned {}{}", status, detail));
    }
    let content_range = response
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_content_range);
    let Some((start, end, total)) = content_range else {
        return ReadOutcome::SourceDead("range response has no valid Content-Range".into());
    };
    if start != range_start || end != range_end {
        return ReadOutcome::SourceDead(format!(
            "range response covers {start}-{end}, expected {range_start}-{range_end}"
        ));
    }
    if let Some(total) = total {
        if total != shared.total_len {
            return ReadOutcome::SourceDead(format!(
                "range total changed from {} to {total}",
                shared.total_len
            ));
        }
    }
    if content_encoded(response.headers()) {
        return ReadOutcome::SourceDead("range response is encoded".into());
    }
    if let Some(len) = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        // The request already asked for the remaining span
        // (`range_start..=range_end`, shrunk by the bytes `got`), so a resumed
        // chunk expects the shorter length the server correctly answers with.
        // Comparing against the full chunk rejected every resume and, after
        // three attempts, aborted the whole download.
        let wanted = range_end - range_start + 1;
        if len != wanted {
            return ReadOutcome::SourceDead(format!(
                "range response length {len}, expected {wanted}"
            ));
        }
    }
    let mut body = response.into_body();
    while *got < expected {
        if *shared.fatal_rx.borrow() {
            return ReadOutcome::SourceDead("download cancelled".into());
        }
        let frame = match tokio::time::timeout(shared.stall, body.frame()).await {
            Err(_) => return ReadOutcome::SourceDead("range body stalled".into()),
            Ok(Some(Err(error))) => {
                return ReadOutcome::SourceDead(format!("range body error: {error}"))
            }
            Ok(None) => return ReadOutcome::SourceDead("range body ended early".into()),
            Ok(Some(Ok(frame))) => frame,
        };
        let Some(data) = frame.data_ref() else {
            continue;
        };
        // a range body never runs past the end; if it does, drop the extra bytes
        // and the connection is re-dialled
        let _ = push_bytes(shared, index, data.clone(), expected, got).await;
    }
    ReadOutcome::Complete
}

async fn send_merge_error(shared: &Shared, out_tx: &mpsc::Sender<Result<Bytes, String>>) {
    let reason = shared
        .reason
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| "download interrupted".into());
    let _ = out_tx.send(Err(reason)).await;
}

async fn run_merger(
    shared: Arc<Shared>,
    mut order_rx: mpsc::Receiver<(u64, Bytes)>,
    out_tx: mpsc::Sender<Result<Bytes, String>>,
) {
    // The Shared sender keeps the order channel open, so a closed receiver is
    // not how a failed worker reaches us; watch the fatal flag instead.
    let mut fatal_rx = shared.fatal_rx.clone();
    let mut pending: BTreeMap<u64, (VecDeque<Bytes>, usize)> = BTreeMap::new();
    let mut next = 0u64;
    loop {
        if *fatal_rx.borrow() {
            send_merge_error(&shared, &out_tx).await;
            return;
        }
        // keep draining while the next chunk has fragments; recv only when the
        // chunk is complete or a gap appears
        while let Some(entry) = pending.get_mut(&next) {
            let Some(fragment) = entry.0.pop_front() else {
                break;
            };
            let len = fragment.len();
            if out_tx.send(Ok(fragment)).await.is_err() {
                shared.set_fatal("browser went away");
                return;
            }
            shared.delivered.fetch_add(len as u64, Ordering::Relaxed);
            if entry.0.is_empty()
                && entry.1
                    == expected_chunk_len(
                        next,
                        shared.chunks_total,
                        shared.chunk_len,
                        shared.total_len,
                    )
            {
                pending.remove(&next);
                next += 1;
                shared.backlog.add_permits(1);
            }
        }
        if next >= shared.chunks_total {
            return;
        }
        tokio::select! {
            item = order_rx.recv() => match item {
                Some((index, bytes)) => {
                    let entry = pending.entry(index).or_default();
                    entry.1 += bytes.len();
                    entry.0.push_back(bytes);
                }
                None => {
                    send_merge_error(&shared, &out_tx).await;
                    return;
                }
            },
            changed = fatal_rx.changed() => {
                // A closed watch sender cannot happen while Shared holds the
                // sender; either way the download can no longer finish cleanly.
                let _ = changed;
                send_merge_error(&shared, &out_tx).await;
                return;
            }
        }
    }
}

/// An advertised range support is not a real one (gh-proxy answers some range
/// requests with 400). Probe with `bytes=0-0` first; on failure the download
/// falls back to a single connection and still completes, just without speed-up.
async fn probe_range(
    pool: &super::UpstreamPool,
    uri: &Uri,
    headers: &HeaderMap,
    total_len: u64,
    timeout: Duration,
) -> Result<(), String> {
    let io = pool
        .dial_http1(uri.clone())
        .await
        .map_err(|error| format!("dial failed: {error}"))?;
    let (mut tx, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|error| format!("handshake failed: {error}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .body(Full::new(Bytes::new()))
        .map_err(|error| format!("request build failed: {error}"))?;
    *request.headers_mut() = headers.clone();
    if let Some(host) = host_header(uri) {
        request.headers_mut().entry(header::HOST).or_insert(host);
    }
    request
        .headers_mut()
        .insert(header::RANGE, HeaderValue::from_static("bytes=0-0"));
    let response = match tokio::time::timeout(timeout, tx.send_request(request)).await {
        Err(_) => return Err("timed out".into()),
        Ok(Err(error)) => return Err(format!("request failed: {error}")),
        Ok(Ok(response)) => response,
    };
    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Err(format!("returned {}", response.status()));
    }
    let (start, end, total) = response
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_content_range)
        .ok_or_else(|| "returned no valid Content-Range".to_string())?;
    if start != 0 || end != 0 {
        return Err(format!("returned range {start}-{end}, expected 0-0"));
    }
    if let Some(total) = total {
        if total != total_len {
            return Err(format!("returned total {total}, expected {total_len}"));
        }
    }
    if content_encoded(response.headers()) {
        return Err("returned an encoded body".into());
    }
    Ok(())
}

/// Whether the origin honours byte ranges, probed with `bytes=0-0`.
///
/// `mirror` is the prefix the verdict is remembered under. `None` is a direct
/// origin: its answer is not reused, because the next download may land on a
/// different edge of the same host.
async fn probe_range_support(
    ctx: &super::ProxyContext,
    uri: &Uri,
    range_headers: &HeaderMap,
    response: &UpstreamResponse,
    mirror: Option<&str>,
) -> bool {
    let total_len = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let host = uri.host().unwrap_or("").to_string();
    let started = Instant::now();
    let result = match tokio::time::timeout(
        RANGE_PROBE_TIMEOUT,
        probe_range(
            &ctx.upstream,
            uri,
            range_headers,
            total_len,
            RANGE_PROBE_TIMEOUT,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err("timed out".to_string()),
    };
    let elapsed = started.elapsed().as_millis() as u64;
    if let Some(prefix) = mirror {
        ctx.download.mirrors.note_range(prefix, result.is_ok());
    }
    match result {
        Ok(()) => true,
        Err(reason) => {
            tracing::info!(
                host = %host,
                mirror = mirror.unwrap_or("direct"),
                elapsed_ms = elapsed,
                reason = %reason,
                "range probe failed"
            );
            false
        }
    }
}

/// Whether `prefix` honours byte ranges, probing and remembering it when the
/// answer is not cached. The probe result is shared through the mirror list,
/// so one download pays for it and the rest reuse the judgement.
pub(crate) async fn mirror_range_ok(
    ctx: &super::ProxyContext,
    uri: &Uri,
    range_headers: &HeaderMap,
    response: &UpstreamResponse,
    prefix: &str,
) -> bool {
    if let Some(supported) = ctx.download.mirrors.range_supported(prefix) {
        return supported;
    }
    probe_range_support(ctx, uri, range_headers, response, Some(prefix)).await
}

/// The mirror candidates to try when the serving mirror does not honour byte
/// ranges: everything after it in list order that is not cooling down. A
/// direct download (no mirror) returns an empty list — the original response
/// already streams from the origin.
pub(crate) fn mirrors_after(serving: Option<&str>, candidates: Vec<String>) -> Vec<String> {
    let Some(prefix) = serving else {
        return Vec::new();
    };
    match candidates.iter().position(|entry| entry == prefix) {
        Some(index) => candidates[index + 1..].to_vec(),
        None => candidates
            .into_iter()
            .filter(|entry| entry != prefix)
            .collect(),
    }
}

/// Headers for the range probe of a fresh mirror response.
pub(crate) fn probe_headers(base: &HeaderMap, response: &UpstreamResponse) -> HeaderMap {
    range_request_headers(base, response.headers())
}

pub(crate) async fn segment(
    ctx: &super::ProxyContext,
    uri: Uri,
    mut response: UpstreamResponse,
    mirrored: bool,
    base_headers: &HeaderMap,
    mirror_prefix: Option<&str>,
) -> Response<ProxyBody> {
    let config = ctx.config.snapshot();
    let download = &config.advanced.download;
    let total_len = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let range_headers = range_request_headers(base_headers, response.headers());

    if mirrored {
        // A mirror response must never plant cookies on the origin the browser
        // thinks it is talking to. Both the single-stream fallback below and
        // the segmented path go through here; the failover path in upstream.rs
        // hands us a raw mirror response that was never stripped.
        strip_mirror_cookies(response.headers_mut());
    }

    // The sliced path needs a body it can actually cut into byte ranges.
    // Without a known, non-zero length the chunk math collapses (one empty
    // chunk, no tail workers): the stream worker completes its zero-length
    // chunk without emitting anything, the merger then waits forever for
    // chunks that can never arrive — pinning `download.active` — while the
    // browser is handed an empty body. Anything unsuitable for slicing is
    // served as the single stream it already is.
    let prefix = mirror_prefix.unwrap_or_default();
    let sliceable = total_len > 0
        && response.status() == StatusCode::OK
        && !content_encoded(response.headers());
    let ranges_ok = sliceable
        && if mirrored {
            !prefix.is_empty()
                && mirror_range_ok(ctx, &uri, &range_headers, &response, prefix).await
        } else {
            // `Accept-Ranges` is only an advertisement: a server (or a proxy
            // in front of it) can answer a range request with the whole body,
            // and the first such reply aborted the download after chunk 0 was
            // already on the wire. Probe while the original response is still
            // unread; a failure falls back to that response as a single stream
            // below instead of killing it.
            //
            // Images pay this probe too. It costs one handshake, but a false
            // positive would fail the whole image once the segmented path
            // started, and a broken image is worse than a slow one.
            probe_range_support(ctx, &uri, &range_headers, &response, None).await
        };
    if !ranges_ok {
        tracing::info!(
            host = uri.host().unwrap_or(""),
            reason = if mirrored {
                "mirror does not support ranges or the body is not sliceable"
            } else {
                "the body is not sliceable or the origin did not honour a range probe"
            },
            "falling back to a single stream"
        );
        let (mut parts, body) = response.into_parts();
        super::upstream::sanitize_response_headers(&mut parts.headers, false);
        return Response::from_parts(parts, ProxyBody::upstream(body, uri, StatusCode::OK));
    }

    let chunk_len = download.chunk_bytes.max(64 * 1024);
    let chunks_total = total_len.div_ceil(chunk_len).max(1);
    let segments = download.segments.clamp(2, 8).min(chunks_total as usize);

    let (mut parts, body) = response.into_parts();
    super::upstream::sanitize_response_headers(&mut parts.headers, false);

    let (order_tx, order_rx) = mpsc::channel(512);
    let (out_tx, out_rx) = mpsc::channel::<Result<Bytes, String>>(8);
    let (fatal_tx, fatal_rx) = watch::channel(false);
    let backlog = Arc::new(Semaphore::new((segments * 2).max(BACKLOG_CHUNKS)));
    ctx.download.active.fetch_add(1, Ordering::Relaxed);

    let host = uri.host().unwrap_or("").to_string();
    tracing::info!(
        host = %host,
        size_bytes = total_len,
        segments,
        chunk_bytes = chunk_len,
        "segmented download started"
    );

    let shared = Arc::new(Shared {
        uri: uri.clone(),
        pool: ctx.upstream.clone(),
        slots: ctx.download.slots.clone(),
        headers: range_headers,
        next: AtomicU64::new(NEXT_AFTER_STREAM_CHUNK),
        chunks_total,
        chunk_len,
        total_len,
        stall: Duration::from_secs(download.stall_timeout_secs.max(2)),
        header_wait: Duration::from_secs(config.advanced.upstream_header_timeout_secs.max(5)),
        backlog,
        order_tx,
        fatal_tx,
        fatal_rx: fatal_rx.clone(),
        reason: Mutex::new(None),
        delivered: AtomicU64::new(0),
        finished: ctx.download.finished.clone(),
        active: ctx.download.active.clone(),
        started: Instant::now(),
        host,
    });

    let (incoming, upstream_permit) = body.into_incoming();
    tokio::spawn(
        Worker {
            shared: shared.clone(),
            source: Source::Stream(incoming),
            carry: None,
            _upstream_permit: upstream_permit,
        }
        .run(),
    );
    // the remaining segments start from chunk 1 in parallel; once the window is
    // full the browser consumes the aggregated bandwidth
    let tail = segments
        .saturating_sub(1)
        .min(chunks_total.saturating_sub(1) as usize);
    for _ in 0..tail {
        tokio::spawn(
            Worker {
                shared: shared.clone(),
                source: Source::None,
                carry: None,
                _upstream_permit: None,
            }
            .run(),
        );
    }
    tokio::spawn(run_merger(shared, order_rx, out_tx));

    Response::from_parts(
        parts,
        ProxyBody::download(SegmentedBody {
            rx: out_rx,
            remaining: total_len,
        }),
    )
}

pub(crate) struct SegmentedBody {
    rx: mpsc::Receiver<Result<Bytes, String>>,
    remaining: u64,
}

impl hyper::body::Body for SegmentedBody {
    type Data = Bytes;
    type Error = String;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let poll = this.rx.poll_recv(cx);
        match poll {
            Poll::Ready(Some(Ok(bytes))) => {
                this.remaining = this.remaining.saturating_sub(bytes.len() as u64);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Some(Err(reason))) => Poll::Ready(Some(Err(reason))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::default();
        hint.set_exact(self.remaining);
        hint
    }
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_uri, claim, content_encoded, credential_headers, expected_chunk_len,
        headers_eligible, host_header, mirror_candidate, mirror_origins, parse_content_range,
        range_request_headers, response_eligible, response_eligible_from, run_merger, signed_url,
        Shared, Source, Worker, MIB, NEXT_AFTER_STREAM_CHUNK,
    };
    use crate::cache::{CacheManager, LastGoodEntry};
    use crate::catalog::RemoteIpProvider;
    use crate::config::{ConfigManager, DomainRule, DownloadConfig, GroupConfig, RoutePolicy};
    use crate::decision::DecisionEngine;
    use crate::ip_tester::TlsContext;
    use crate::mirror::{MirrorList, BUILTIN_MIRRORS};
    use crate::paths::Paths;
    use crate::resolver::{DohResolution, EchOutcome, IpResolver};
    use crate::status::StatusStore;
    use crate::strategy::IpSource;
    use crate::util::now;
    use bytes::Bytes;
    use http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper_util::rt::TokioIo;
    use std::future::Future;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, watch, Semaphore};

    fn builtin_mirrors() -> MirrorList {
        MirrorList::load(None)
    }

    fn release() -> Uri {
        "https://github.com/o/r/releases/download/v1/a.zip"
            .parse()
            .unwrap()
    }

    #[test]
    fn the_plan_embeds_the_origin_url_behind_every_prefix() {
        let config = DownloadConfig::default();
        let mirrors = builtin_mirrors();
        let plan = mirror_origins(&config, &mirrors, &Method::GET, &release()).unwrap();
        assert_eq!(plan.candidates, BUILTIN_MIRRORS.to_vec());

        let rewritten = plan.rewrite(&plan.candidates[0]).unwrap();
        assert_eq!(rewritten.host(), Some("gh-proxy.com"));
        let path = rewritten.path().to_string();
        assert!(
            path.starts_with("/https://github.com/o/r/releases/download/v1/a.zip"),
            "mirror path must embed the origin url: {path}"
        );
        assert_eq!(rewritten.scheme_str(), Some("https"));

        let avatar: Uri = "https://avatars.githubusercontent.com/u/1".parse().unwrap();
        assert!(mirror_origins(&config, &mirrors, &Method::GET, &avatar).is_none());
        let raw: Uri = "https://raw.githubusercontent.com/o/r/main/x"
            .parse()
            .unwrap();
        assert!(mirror_origins(&config, &mirrors, &Method::GET, &raw).is_none());
        let page: Uri = "https://github.com/owner/repo".parse().unwrap();
        assert!(mirror_origins(&config, &mirrors, &Method::GET, &page).is_none());
    }

    /// The shared header gate defaults to one MiB. If the image branch used it,
    /// every artwork would be rejected before the lower image floor was even
    /// consulted — which is exactly what happened on the first attempt.
    #[test]
    fn the_header_gate_accepts_an_artwork_sized_body() {
        let build = |len: &str| {
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = StatusCode::OK;
            response
                .headers_mut()
                .insert(header::CONTENT_LENGTH, len.parse().unwrap());
            response
                .headers_mut()
                .insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
            response
        };
        let artwork = 441_990u64;
        assert!(
            response_eligible(&build(&artwork.to_string())).is_none(),
            "the archive floor must still reject a 442 KiB body"
        );
        assert_eq!(
            response_eligible_from(&build(&artwork.to_string()), 256 * 1024),
            Some(artwork),
            "the image floor must let the same body through"
        );
    }

    #[test]
    fn only_bodyless_methods_get_a_plan() {
        let config = DownloadConfig::default();
        let mirrors = builtin_mirrors();
        assert!(mirror_origins(&config, &mirrors, &Method::GET, &release()).is_some());
        assert!(mirror_origins(&config, &mirrors, &Method::HEAD, &release()).is_some());
        assert!(
            mirror_origins(&config, &mirrors, &Method::POST, &release()).is_none(),
            "a request with a body cannot be re-sent, so it never reaches a mirror"
        );
    }

    #[test]
    fn signed_urls_never_reach_a_third_party_mirror() {
        let config = DownloadConfig::default();
        let mirrors = builtin_mirrors();
        // this is where GitHub 302s to the signed storage host
        let signed: Uri = "https://github.com/o/r/releases/download/v1/a.zip?se=1&sig=abc"
            .parse()
            .unwrap();
        assert!(mirror_candidate(&signed));
        assert!(signed_url(&signed));
        assert!(mirror_origins(&config, &mirrors, &Method::GET, &signed).is_none());

        let hf: Uri = "https://cdn-lfs.huggingface.co/x?X-Amz-Signature=1"
            .parse()
            .unwrap();
        assert!(signed_url(&hf));
        let cloudfront: Uri = "https://cas-bridge.xethub.hf.co/x?Policy=p&Key-Pair-Id=k"
            .parse()
            .unwrap();
        assert!(signed_url(&cloudfront));
        assert!(!signed_url(&release()));

        // GitHub's private entry points use these instead of `sig`.
        for key in ["token", "access_token", "jwt", "code"] {
            let uri: Uri = format!("https://github.com/o/r/archive/main.zip?{key}=secret")
                .parse()
                .unwrap();
            assert!(
                signed_url(&uri),
                "a `{key}` query must never be embedded in a mirror URL"
            );
        }
    }

    #[test]
    fn content_range_must_match_the_requested_chunk() {
        assert_eq!(
            parse_content_range("bytes 0-0/100"),
            Some((0, 0, Some(100)))
        );
        assert_eq!(
            parse_content_range("bytes 100-199/*"),
            Some((100, 199, None))
        );
        assert_eq!(parse_content_range("bytes 100-99/200"), None);
        assert_eq!(parse_content_range("bytes 100-199"), None);
        assert_eq!(parse_content_range("items 0-0/1"), None);
    }

    #[test]
    fn encoded_responses_are_never_segmented() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(content_encoded(&headers));
        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        assert!(!content_encoded(&headers));
        assert!(!content_encoded(&HeaderMap::new()));
    }

    #[test]
    fn a_reduced_credential_base_yields_the_same_range_headers() {
        // `segment()` receives only the small credential subset from the
        // direct path. Range requests must be identical to those built from
        // the full browser HeaderMap, or the copy-depth optimisation would
        // silently change what the upstream sees.
        let mut full = HeaderMap::new();
        full.insert(header::USER_AGENT, HeaderValue::from_static("browser"));
        full.insert(header::REFERER, HeaderValue::from_static("https://ref/"));
        full.insert(header::COOKIE, HeaderValue::from_static("session=1"));
        full.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        full.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        full.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("en"));
        let mut response = HeaderMap::new();
        response.insert(header::ETAG, HeaderValue::from_static("\"v1\""));

        let from_full = range_request_headers(&full, &response);
        let reduced = credential_headers(&full);
        // The reduced base must carry none of the irrelevant headers.
        assert!(reduced.get(header::CACHE_CONTROL).is_none());
        assert_eq!(reduced.len(), 4);
        let from_reduced = range_request_headers(&reduced, &response);
        assert_eq!(from_full, from_reduced);
    }

    #[test]
    fn range_headers_drop_mirror_credentials_and_pin_the_validator() {
        let mut base = HeaderMap::new();
        base.insert(header::USER_AGENT, HeaderValue::from_static("browser"));
        base.insert(header::COOKIE, HeaderValue::from_static("session=1"));
        base.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        let mut response = HeaderMap::new();
        response.insert(header::ETAG, HeaderValue::from_static("\"v1\""));

        let headers = range_request_headers(&base, &response);
        assert_eq!(headers.get(header::USER_AGENT).unwrap(), "browser");
        assert_eq!(headers.get(header::COOKIE).unwrap(), "session=1");
        assert_eq!(headers.get(header::ACCEPT_ENCODING).unwrap(), "identity");
        assert_eq!(headers.get(header::IF_RANGE).unwrap(), "\"v1\"");
        assert!(headers.get(header::RANGE).is_none());

        // A mirrored response's base had its credentials removed upstream.
        let stripped = HeaderMap::new();
        let headers = range_request_headers(&stripped, &response);
        assert!(headers.get(header::COOKIE).is_none());
        assert!(headers.get(header::AUTHORIZATION).is_none());
    }

    #[test]
    fn an_empty_source_disables_the_mirror_entirely() {
        let mirrors = builtin_mirrors();
        let off = DownloadConfig {
            mirror_source: String::new(),
            ..DownloadConfig::default()
        };
        assert!(mirror_origins(&off, &mirrors, &Method::GET, &release()).is_none());

        // turning segmentation off must not turn the mirror off with it
        let no_segments = DownloadConfig {
            enabled: false,
            ..DownloadConfig::default()
        };
        assert!(mirror_origins(&no_segments, &mirrors, &Method::GET, &release()).is_some());
    }

    #[test]
    fn the_failover_tail_skips_the_serving_mirror() {
        use super::mirrors_after;
        let list = vec![
            "https://a.example".to_string(),
            "https://b.example".to_string(),
            "https://c.example".to_string(),
        ];
        // The serving mirror is the first candidate: the tail is the rest.
        assert_eq!(
            mirrors_after(Some("https://a.example"), list.clone()),
            vec!["https://b.example", "https://c.example"]
        );
        // A serving mirror that dropped out of the list still excludes itself,
        // and an unknown mirror leaves every other candidate reachable.
        assert_eq!(mirrors_after(Some("https://z.example"), list.clone()), list);
        // A direct download has no mirror to fail over to.
        assert_eq!(mirrors_after(None, list), Vec::<String>::new());
    }

    #[test]
    fn a_failing_mirror_falls_through_to_the_next_one() {
        let config = DownloadConfig::default();
        let mirrors = builtin_mirrors();
        mirrors.cool_down(BUILTIN_MIRRORS[0]);
        let plan = mirror_origins(&config, &mirrors, &Method::GET, &release()).unwrap();
        assert_eq!(
            plan.candidates[0], BUILTIN_MIRRORS[1],
            "the next mirror takes over"
        );
        let rewritten = plan.rewrite(&plan.candidates[0]).unwrap();
        assert_eq!(
            rewritten.host(),
            Some("ghfast.top"),
            "the rewrite must point at the second mirror"
        );

        for mirror in BUILTIN_MIRRORS {
            mirrors.cool_down(mirror);
        }
        assert!(
            mirror_origins(&config, &mirrors, &Method::GET, &release()).is_none(),
            "with every mirror cooling down the request stays direct"
        );
    }

    #[test]
    fn mirror_candidate_is_narrower_than_segment_rules() {
        let codeload: Uri = "https://codeload.github.com/o/r/zip/1".parse().unwrap();
        let dl: Uri = "https://github.com/o/r/releases/download/v1/x"
            .parse()
            .unwrap();
        let latest: Uri = "https://github.com/o/r/releases/latest/download/x"
            .parse()
            .unwrap();
        let archive: Uri = "https://github.com/o/r/archive/refs/tags/v1.zip"
            .parse()
            .unwrap();
        assert!(mirror_candidate(&codeload));
        assert!(mirror_candidate(&dl));
        assert!(mirror_candidate(&latest));
        assert!(mirror_candidate(&archive));

        // a web page whose path happens to contain the same words stays direct
        let blob: Uri = "https://github.com/o/r/blob/main/archive/notes.md"
            .parse()
            .unwrap();
        assert!(!mirror_candidate(&blob), "a blob page is not a download");
        let nested: Uri = "https://github.com/o/r/blob/main/docs/releases/download/x.md"
            .parse()
            .unwrap();
        assert!(!mirror_candidate(&nested));
        let repo_page: Uri = "https://github.com/o/r".parse().unwrap();
        assert!(!mirror_candidate(&repo_page));

        let avatar: Uri = "https://avatars.githubusercontent.com/u/1".parse().unwrap();
        assert!(!mirror_candidate(&avatar));
        assert!(
            candidate_uri(&avatar),
            "segment rules stay wide for direct mode"
        );
    }

    #[test]
    fn headers_gate_blocks_wrong_status_size_and_missing_ranges() {
        assert_eq!(
            headers_eligible(StatusCode::OK, Some("1048576"), Some("bytes"), MIB),
            Some(1048576)
        );
        assert!(headers_eligible(
            StatusCode::PARTIAL_CONTENT,
            Some("1048576"),
            Some("bytes"),
            MIB
        )
        .is_none());
        assert!(headers_eligible(StatusCode::OK, None, Some("bytes"), MIB).is_none());
        assert!(headers_eligible(StatusCode::OK, Some("1024"), Some("bytes"), MIB).is_none());
        assert!(headers_eligible(StatusCode::OK, Some("1048576"), Some("none"), MIB).is_none());
        assert!(headers_eligible(StatusCode::OK, Some("abc"), Some("bytes"), MIB).is_none());
        // below the configured threshold but above the 1 MiB floor: the caller
        // applies the config on top
        assert!(headers_eligible(StatusCode::OK, Some("2097152"), Some("bytes"), 4 * MIB).is_none());
    }

    /// The mirror failover hands its candidate straight to `segment()`; a
    /// response that cannot be sliced must be rejected there, or the download
    /// would end up empty while the merger waits for chunks that never come.
    #[test]
    fn response_eligible_requires_a_sliceable_body() {
        let build = |status: StatusCode, len: Option<&str>, ranges: Option<&str>, encoding: &str| {
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = status;
            if let Some(len) = len {
                response
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, len.parse().unwrap());
            }
            if let Some(ranges) = ranges {
                response
                    .headers_mut()
                    .insert(header::ACCEPT_RANGES, ranges.parse().unwrap());
            }
            if !encoding.is_empty() {
                response
                    .headers_mut()
                    .insert(header::CONTENT_ENCODING, encoding.parse().unwrap());
            }
            response
        };
        let ok = build(StatusCode::OK, Some("1048576"), Some("bytes"), "");
        assert_eq!(response_eligible(&ok), Some(1048576));
        // A mirror that answers without Content-Length (or with a redirect or
        // a content encoding) must never reach the segmented path.
        assert_eq!(
            response_eligible(&build(StatusCode::OK, None, Some("bytes"), "")),
            None
        );
        assert_eq!(
            response_eligible(&build(StatusCode::MOVED_PERMANENTLY, Some("1048576"), Some("bytes"), "")),
            None
        );
        assert_eq!(
            response_eligible(&build(StatusCode::OK, Some("1048576"), Some("bytes"), "gzip")),
            None
        );
    }

    #[test]
    fn download_rules_cover_github_assets_only() {
        let uri: Uri = "https://objects.githubusercontent.com/x/y?sig=1"
            .parse()
            .unwrap();
        assert!(candidate_uri(&uri));
        let uri: Uri = "https://release-assets.githubusercontent.com/a/b"
            .parse()
            .unwrap();
        assert!(candidate_uri(&uri));
        let uri: Uri = "https://github.com/owner/repo/releases/download/v1/x.zip"
            .parse()
            .unwrap();
        assert!(candidate_uri(&uri));
        let uri: Uri = "https://github.com/owner/repo/releases/latest/download/x.zip"
            .parse()
            .unwrap();
        assert!(
            candidate_uri(&uri),
            "the latest shorthand is a download too"
        );
        let uri: Uri = "https://codeload.github.com/owner/repo/zip/refs/tags/v1"
            .parse()
            .unwrap();
        assert!(candidate_uri(&uri));
        let uri: Uri = "https://github.com/owner/repo".parse().unwrap();
        assert!(!candidate_uri(&uri));
        let uri: Uri = "https://github.com/owner/repo/blob/main/x.zip"
            .parse()
            .unwrap();
        assert!(!candidate_uri(&uri));
        let uri: Uri = "https://evil-githubusercontent.com/x".parse().unwrap();
        assert!(!candidate_uri(&uri));
        let uri: Uri = "https://pixiv.net/x".parse().unwrap();
        assert!(!candidate_uri(&uri));
    }

    #[test]
    fn cursor_hands_out_each_chunk_once() {
        let next = AtomicU64::new(0);
        assert_eq!(claim(&next, 5).unwrap(), 0);
        assert_eq!(claim(&next, 5).unwrap(), 1);
        assert_eq!(claim(&next, 5).unwrap(), 2);
        assert_eq!(claim(&next, 5).unwrap(), 3);
        assert_eq!(claim(&next, 5).unwrap(), 4);
        assert!(claim(&next, 5).is_none());
        assert!(claim(&next, 5).is_none());
    }

    #[test]
    fn chunk_lengths_cover_the_exactly_and_the_tail() {
        let chunks_total = 5u64;
        let chunk_len = 2u64;
        let total = 9u64;
        let sum: u64 = (0..chunks_total)
            .map(|index| expected_chunk_len(index, chunks_total, chunk_len, total) as u64)
            .sum();
        assert_eq!(sum, total);
        assert_eq!(expected_chunk_len(4, chunks_total, chunk_len, total), 1);
        assert_eq!(expected_chunk_len(0, chunks_total, chunk_len, total), 2);
    }

    #[test]
    fn the_shared_counter_skips_the_streaming_chunk() {
        let next = AtomicU64::new(NEXT_AFTER_STREAM_CHUNK);
        assert_eq!(claim(&next, 4).unwrap(), 1);
        assert_eq!(claim(&next, 4).unwrap(), 2);
        assert_eq!(claim(&next, 4).unwrap(), 3);
        assert!(claim(&next, 4).is_none());
    }

    /// The `backlog` semaphore caps chunks that are downloaded but not yet
    /// handed to the browser: a worker reserves one permit before filling a
    /// chunk and the merger returns it once that chunk is delivered. The old
    /// code returned the permit both when the worker's `OwnedSemaphorePermit`
    /// was dropped at the end of the loop iteration and in `run_merger`'s
    /// `add_permits(1)`, so every delivered chunk left one extra permit behind
    /// and `wait_backlog()` stopped blocking entirely.
    #[tokio::test]
    async fn delivering_a_chunk_does_not_leak_a_backlog_permit() {
        let dir = tempfile::tempdir().unwrap();
        let chunk_len = 4096u64;
        let chunks_total = 2u64;
        let backlog = Arc::new(Semaphore::new(4));
        let (order_tx, order_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel::<Result<Bytes, String>>(8);
        let (fatal_tx, fatal_rx) = watch::channel(false);
        let shared = Arc::new(Shared {
            uri: "http://upstream.test/chunked".parse().unwrap(),
            pool: segment_pool(dir.path()),
            slots: Arc::new(Semaphore::new(8)),
            headers: HeaderMap::new(),
            chunks_total,
            chunk_len,
            total_len: chunk_len * chunks_total,
            stall: Duration::from_secs(5),
            header_wait: Duration::from_secs(60),
            backlog: backlog.clone(),
            order_tx,
            next: AtomicU64::new(NEXT_AFTER_STREAM_CHUNK),
            fatal_tx,
            fatal_rx: fatal_rx.clone(),
            reason: Mutex::new(None),
            delivered: AtomicU64::new(0),
            finished: Arc::new(AtomicU64::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            started: Instant::now(),
            host: "upstream.test".into(),
        });

        // A worker that will never dial: only its wait_backlog() is driven.
        let worker = Worker {
            shared: shared.clone(),
            source: Source::None,
            carry: None,
            _upstream_permit: None,
        };
        let merger = tokio::spawn(run_merger(shared.clone(), order_rx, out_tx));

        assert!(worker.wait_backlog().await, "a permit must be available");
        assert_eq!(
            backlog.available_permits(),
            3,
            "reserving a chunk must consume exactly one permit"
        );
        // Deliver chunk 0 to the browser. `wait_backlog` forgets its permit, so
        // the merger's add_permits(1) is the only thing returning it.
        shared
            .order_tx
            .send((0, Bytes::from(vec![7u8; chunk_len as usize])))
            .await
            .unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("the merger must deliver the chunk")
            .expect("the output channel must stay open")
            .expect("the chunk must not be an error");
        assert_eq!(frame.len(), chunk_len as usize);

        // One permit reserved, one chunk delivered: back to the starting
        // balance. The double-return bug left 5 here instead of 4.
        assert_eq!(
            backlog.available_permits(),
            4,
            "each delivered chunk must release exactly one backlog permit"
        );

        // Finish the download so the merger exits cleanly.
        assert!(worker.wait_backlog().await, "a permit must be available");
        shared
            .order_tx
            .send((1, Bytes::from(vec![8u8; chunk_len as usize])))
            .await
            .unwrap();
        while out_rx.recv().await.is_some() {}
        let _ = merger.await;
        // The whole download delivered exactly as many chunks as permits it
        // reserved: the semaphore ends at its starting balance.
        assert_eq!(backlog.available_permits(), 4);
    }

    /// With the double-return fixed, a full delivery window must actually stop
    /// the workers. The old bug let every delivered chunk add a permit, so this
    /// `wait_backlog` returned immediately instead of waiting for a delivery.
    #[tokio::test]
    async fn a_full_delivery_window_blocks_the_next_worker() {
        let dir = tempfile::tempdir().unwrap();
        let chunk_len = 4096u64;
        let chunks_total = 4u64;
        let backlog = Arc::new(Semaphore::new(2));
        let (order_tx, order_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel::<Result<Bytes, String>>(8);
        let (fatal_tx, fatal_rx) = watch::channel(false);
        let shared = Arc::new(Shared {
            uri: "http://upstream.test/chunked".parse().unwrap(),
            pool: segment_pool(dir.path()),
            slots: Arc::new(Semaphore::new(8)),
            headers: HeaderMap::new(),
            chunks_total,
            chunk_len,
            total_len: chunk_len * chunks_total,
            stall: Duration::from_secs(5),
            header_wait: Duration::from_secs(60),
            backlog: backlog.clone(),
            order_tx,
            next: AtomicU64::new(0),
            fatal_tx,
            fatal_rx: fatal_rx.clone(),
            reason: Mutex::new(None),
            delivered: AtomicU64::new(0),
            finished: Arc::new(AtomicU64::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            started: Instant::now(),
            host: "upstream.test".into(),
        });
        let worker = Worker {
            shared: shared.clone(),
            source: Source::None,
            carry: None,
            _upstream_permit: None,
        };
        let merger = tokio::spawn(run_merger(shared.clone(), order_rx, out_tx));

        // Reserve the whole window without delivering anything.
        assert!(worker.wait_backlog().await);
        assert!(worker.wait_backlog().await);
        assert_eq!(backlog.available_permits(), 0);

        // A third reserve must not succeed while the window is full.
        let blocked = tokio::time::timeout(Duration::from_millis(100), worker.wait_backlog()).await;
        assert!(
            blocked.is_err(),
            "wait_backlog must block until a chunk is delivered to the browser"
        );

        // Delivering chunk 0 releases one slot and unblocks the waiter.
        shared
            .order_tx
            .send((0, Bytes::from(vec![1u8; chunk_len as usize])))
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("chunk 0 must be delivered");
        let acquired = tokio::time::timeout(Duration::from_secs(5), worker.wait_backlog()).await;
        assert!(matches!(acquired, Ok(true)), "a delivered slot must free a worker");
        assert_eq!(backlog.available_permits(), 0);

        shared.set_fatal("stop test merger");
        let _ = merger.await;
    }

    #[test]
    fn host_header_matches_the_legacy_client() {
        let uri: Uri = "http://example.com/x".parse().unwrap();
        assert_eq!(host_header(&uri).unwrap(), "example.com");
        let uri: Uri = "http://example.com:8080/x".parse().unwrap();
        assert_eq!(host_header(&uri).unwrap(), "example.com:8080");
        // The default port stays implicit, like hyper_util's `set_host`.
        let uri: Uri = "https://example.com:443/x".parse().unwrap();
        assert_eq!(host_header(&uri).unwrap(), "example.com");
        let uri: Uri = "https://example.com:8443/x".parse().unwrap();
        assert_eq!(host_header(&uri).unwrap(), "example.com:8443");
    }

    struct NoDoh;

    #[async_trait::async_trait]
    impl IpResolver for NoDoh {
        async fn doh_ips(&self, _domain: &str) -> anyhow::Result<DohResolution> {
            Err(anyhow::anyhow!("no DoH in this test"))
        }

        async fn doh_ech_config(
            &self,
            _domain: &str,
            _allow_shared: bool,
        ) -> anyhow::Result<EchOutcome> {
            Err(anyhow::anyhow!("no ECH in this test"))
        }
    }

    struct NoRemote;

    impl RemoteIpProvider for NoRemote {
        fn remote_ips(&self, _domain: &str) -> Option<Arc<[IpAddr]>> {
            None
        }

        fn has_ip_catalog(&self) -> bool {
            false
        }
    }

    /// A pool whose `upstream.test` route points at loopback, so a segment
    /// worker's dial goes somewhere the test controls.
    fn segment_pool(dir: &std::path::Path) -> Arc<crate::proxy::UpstreamPool> {
        let paths = Paths::new(dir);
        paths.ensure().unwrap();
        let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
        config
            .upsert_group(GroupConfig {
                id: "test".into(),
                name: "Test".into(),
                domains: vec![DomainRule::new("upstream.test")],
                enabled: true,
                homepage: None,
                default_route: RoutePolicy::direct(),
            })
            .unwrap();
        let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
        cache.put_last_good(LastGoodEntry {
            domain: "upstream.test".into(),
            ip: "127.0.0.1".parse().unwrap(),
            source: IpSource::Cache,
            saved_at: now(),
            catalog_version: 0,
        });
        let tls = TlsContext::new().unwrap();
        let status = Arc::new(StatusStore::new());
        let engine = DecisionEngine::new(
            config.clone(),
            cache,
            Arc::new(NoRemote),
            Arc::new(NoDoh),
            tls.clone(),
            status,
        );
        crate::proxy::UpstreamPool::new(engine, tls, &config.snapshot())
    }

    /// A local origin that answers exactly once with the full body, giving the
    /// test a real `hyper::body::Incoming` for the streaming worker.
    async fn stream_incoming(payload: &[u8]) -> Incoming {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = payload.to_vec();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..read]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(&payload).await.unwrap();
        });
        let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
        let (mut tx, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        tx.ready().await.unwrap();
        let request = Request::builder()
            .uri("http://stream.test/chunked")
            .body(Full::new(Bytes::new()))
            .unwrap();
        tx.send_request(request).await.unwrap().into_body()
    }

    /// Reproduces the claim race deterministically: `run()` lets every worker
    /// claim any chunk from one shared counter, so a tail worker polled first
    /// takes chunk 0 and the streaming worker (whose bytes start at file
    /// offset 0) labels file-head data with a later chunk index. The merger
    /// reorders strictly by index, so the wrong bytes are spliced at the right
    /// length — silent corruption.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_stream_worker_fills_chunk_zero_even_when_a_tail_claims_first() {
        let chunk_len = 4096u64;
        let chunks_total = 4u64;
        let payload: Vec<u8> = (0..(chunk_len * chunks_total) as usize)
            .map(|index| (index % 251) as u8)
            .collect();
        let incoming = stream_incoming(&payload).await;

        // Completes the TCP handshake but never answers: the tail worker
        // claims its chunk and then parks on the range response.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        let _dead = dead;

        let dir = tempfile::tempdir().unwrap();
        let pool = segment_pool(dir.path());
        let (order_tx, mut order_rx) = mpsc::channel(16);
        let (fatal_tx, fatal_rx) = watch::channel(false);
        let shared = Arc::new(Shared {
            uri: format!("http://upstream.test:{}/chunked", dead_addr.port())
                .parse::<Uri>()
                .unwrap(),
            pool,
            slots: Arc::new(Semaphore::new(8)),
            headers: HeaderMap::new(),
            chunks_total,
            chunk_len,
            total_len: chunk_len * chunks_total,
            stall: Duration::from_secs(5),
            header_wait: Duration::from_secs(60),
            backlog: Arc::new(Semaphore::new(8)),
            order_tx,
            next: AtomicU64::new(0),
            fatal_tx,
            fatal_rx,
            reason: Mutex::new(None),
            delivered: AtomicU64::new(0),
            finished: Arc::new(AtomicU64::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            started: Instant::now(),
            host: "upstream.test".into(),
        });

        // The tail worker runs first — exactly like a spawner thread that is
        // preempted right after `tokio::spawn`.
        let mut tail = Box::pin(
            Worker {
                shared: shared.clone(),
                source: Source::None,
                carry: None,
                _upstream_permit: None,
            }
            .run(),
        );
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            matches!(tail.as_mut().poll(&mut cx), Poll::Pending),
            "the tail worker parks on the unanswered range request"
        );

        tokio::spawn(
            Worker {
                shared: shared.clone(),
                source: Source::Stream(incoming),
                carry: None,
                _upstream_permit: None,
            }
            .run(),
        );

        let (index, head) = tokio::time::timeout(Duration::from_secs(10), order_rx.recv())
            .await
            .expect("the stream worker must publish a chunk")
            .expect("the order channel must stay open");
        assert_eq!(
            index, 0,
            "the streaming connection starts at file offset 0, so it must fill chunk 0"
        );
        assert_eq!(&head[..], &payload[..chunk_len as usize]);
    }
}
