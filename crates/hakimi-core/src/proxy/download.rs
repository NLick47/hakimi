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
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::Full;
use hyper::body::{Frame, Incoming, SizeHint};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use super::pool::UpstreamResponse;
use super::ProxyBody;
use crate::config::AppConfig;
use http_body_util::BodyExt;

const MIB: u64 = 1024 * 1024;
/// Cap on finished-but-undelivered chunks; segment connections pause above it
const BACKLOG_CHUNKS: usize = 8;
/// Per-chunk attempt cap; a re-dial can pick a different IP
const MAX_ATTEMPTS: u32 = 3;

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

/// Header-only gate: status, size floor, range support
fn headers_eligible(
    status: StatusCode,
    content_length: Option<&str>,
    accept_ranges: Option<&str>,
    min_size: u64,
) -> bool {
    if status != StatusCode::OK {
        return false;
    }
    let Some(len) = content_length.and_then(|value| value.trim().parse::<u64>().ok()) else {
        return false;
    };
    if len < min_size.max(MIB) {
        return false;
    }
    accept_ranges.is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("bytes"))
    })
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
        return uri.path().contains("/releases/download/");
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
        let key = pair.split('=').next().unwrap_or_default().to_ascii_lowercase();
        matches!(key.as_str(), "sig" | "signature" | "policy" | "key-pair-id")
            || key.starts_with("x-amz-")
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
    Some(MirrorPlan {
        origin,
        candidates,
    })
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
    let headers = response.headers();
    let len = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    let ranges = headers
        .get(header::ACCEPT_RANGES)
        .and_then(|value| value.to_str().ok());
    // a 1 MiB hard floor rejects most traffic before the config snapshot is paid for
    if !headers_eligible(response.status(), len.map(|len| len.to_string()).as_deref(), ranges, MIB)
    {
        return false;
    }
    let config = &ctx.config.snapshot().advanced.download;
    if !config.enabled || ctx.status.paused() {
        return false;
    }
    if len.is_none_or(|len| len < config.min_size_bytes) {
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
        // log the full URL with the reason: a mirror 400 is only diagnosable from
        // the error body
        let url = self.uri.to_string();
        tracing::warn!(
            host = %self.host,
            url = %truncate(&url, 300),
            reason,
            "segmented download failed"
        );
    }
}

fn truncate(value: &str, max: usize) -> &str {
    match value.char_indices().nth(max) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

/// Read the body of a non-206 reply; a mirror explains itself there
async fn error_body_text(body: Incoming) -> String {
    let mut limited = http_body_util::Limited::new(body, 256);
    match limited.collect().await {
        Ok(collected) => String::from_utf8_lossy(&collected.to_bytes())
            .trim()
            .to_string(),
        Err(_) => String::new(),
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        tracing::info!(
            host = %self.host,
            bytes = self.finished.load(Ordering::Relaxed),
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
    async fn wait_backlog(&self) -> Option<OwnedSemaphorePermit> {
        loop {
            if *self.shared.fatal_rx.borrow() {
                return None;
            }
            let mut fatal_rx = self.shared.fatal_rx.clone();
            tokio::select! {
                changed = fatal_rx.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                }
                permit = self.shared.backlog.clone().acquire_owned() => {
                    return permit.ok();
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
            let Some(_backlog) = self.wait_backlog().await else {
                return;
            };
            let Some(index) = claim(&self.shared.next, self.shared.chunks_total) else {
                return;
            };
            let streaming = matches!(self.source, Source::Stream(_));
            if let Err(reason) = self.fill_chunk(index).await {
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
        if let Some(carry) = self.carry.take() {
            let leftover = push_bytes(&self.shared, index, carry, expected, &mut got).await;
            if !leftover.is_empty() {
                self.carry = Some(leftover);
                self.shared
                    .finished
                    .fetch_add(expected as u64, Ordering::Relaxed);
                return Ok(());
            }
        }
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
                    read_stream(&self.shared, body, &mut self.carry, index, expected, &mut got).await
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
    let request = match Request::builder()
        .method(Method::GET)
        .uri(shared.uri.clone())
        .header(header::RANGE, format!("bytes={range_start}-{range_end}"))
        .header(header::ACCEPT, "*/*")
        .body(Full::new(Bytes::new()))
    {
        Ok(request) => request,
        Err(error) => {
            return ReadOutcome::SourceDead(format!("range request build failed: {error}"))
        }
    };
    let response =
        match tokio::time::timeout(shared.header_wait, conn.tx.send_request(request)).await {
            Err(_) => return ReadOutcome::SourceDead("range request header timeout".into()),
            Ok(Err(error)) => return ReadOutcome::SourceDead(format!("range request failed: {error}")),
            Ok(Ok(response)) => response,
        };
    let status = response.status();
    if status != StatusCode::PARTIAL_CONTENT {
        let body_text = error_body_text(response.into_body()).await;
        let detail = if body_text.is_empty() {
            String::new()
        } else {
            format!(": {}", truncate(&body_text, 200))
        };
        return ReadOutcome::SourceDead(format!(
            "range request returned {}{}",
            status, detail
        ));
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

async fn run_merger(
    shared: Arc<Shared>,
    mut order_rx: mpsc::Receiver<(u64, Bytes)>,
    out_tx: mpsc::Sender<Result<Bytes, String>>,
) {
    let mut pending: BTreeMap<u64, (VecDeque<Bytes>, usize)> = BTreeMap::new();
    let mut next = 0u64;
    loop {
        // keep draining while the next chunk has fragments; recv only when the
        // chunk is complete or a gap appears
        while let Some(entry) = pending.get_mut(&next) {
            let Some(fragment) = entry.0.pop_front() else {
                break;
            };
            if out_tx.send(Ok(fragment)).await.is_err() {
                shared.set_fatal("browser went away");
                return;
            }
            if entry.0.is_empty()
                && entry.1 == expected_chunk_len(next, shared.chunks_total, shared.chunk_len, shared.total_len)
            {
                pending.remove(&next);
                next += 1;
                shared.backlog.add_permits(1);
            }
        }
        if next >= shared.chunks_total {
            return;
        }
        match order_rx.recv().await {
            Some((index, bytes)) => {
                let entry = pending.entry(index).or_default();
                entry.1 += bytes.len();
                entry.0.push_back(bytes);
            }
            None => {
                let reason = shared
                    .reason
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| "download interrupted".into());
                let _ = out_tx.send(Err(reason)).await;
                return;
            }
        }
    }
}

/// An advertised range support is not a real one (gh-proxy answers some range
/// requests with 400). Probe with `bytes=0-0` first; on failure the download
/// falls back to a single connection and still completes, just without speed-up.
async fn probe_range(pool: &super::UpstreamPool, uri: &Uri, timeout: Duration) -> bool {
    let Ok(io) = pool.dial_http1(uri.clone()).await else {
        return false;
    };
    let Ok((mut tx, conn)) = hyper::client::conn::http1::handshake(io).await else {
        return false;
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = match Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .header(header::RANGE, "bytes=0-0")
        .header(header::ACCEPT, "*/*")
        .body(Full::new(Bytes::new()))
    {
        Ok(request) => request,
        Err(_) => return false,
    };
    let Ok(Ok(response)) = tokio::time::timeout(timeout, tx.send_request(request)).await else {
        return false;
    };
    response.status() == StatusCode::PARTIAL_CONTENT
        && response
            .headers()
            .contains_key(header::CONTENT_RANGE)
}

pub(crate) async fn segment(
    ctx: &super::ProxyContext,
    uri: Uri,
    response: UpstreamResponse,
    mirrored: bool,
) -> Response<ProxyBody> {
    let config = ctx.config.snapshot();
    let download = &config.advanced.download;
    let total_len = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);

    if mirrored {
        let probe_timeout = Duration::from_secs(download.stall_timeout_secs.max(2));
        let host = uri.host().unwrap_or("").to_string();
        if !probe_range(&ctx.upstream, &uri, probe_timeout).await {
            tracing::info!(
                host = %host,
                "mirror range probe failed, falling back to single stream"
            );
            let (mut parts, body) = response.into_parts();
            super::upstream::sanitize_response_headers(&mut parts.headers, false);
            return Response::from_parts(
                parts,
                ProxyBody::upstream(body, uri, StatusCode::OK),
            );
        }
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
        next: AtomicU64::new(0),
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
        candidate_uri, claim, expected_chunk_len, headers_eligible, mirror_candidate,
        mirror_origins, signed_url, MIB,
    };
    use crate::config::DownloadConfig;
    use crate::mirror::{MirrorList, BUILTIN_MIRRORS};
    use std::sync::atomic::AtomicU64;
    use http::{Method, StatusCode, Uri};

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
        let raw: Uri = "https://raw.githubusercontent.com/o/r/main/x".parse().unwrap();
        assert!(mirror_origins(&config, &mirrors, &Method::GET, &raw).is_none());
        let page: Uri = "https://github.com/owner/repo".parse().unwrap();
        assert!(mirror_origins(&config, &mirrors, &Method::GET, &page).is_none());
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
    fn a_failing_mirror_falls_through_to_the_next_one() {
        let config = DownloadConfig::default();
        let mirrors = builtin_mirrors();
        mirrors.cool_down(BUILTIN_MIRRORS[0]);
        let plan = mirror_origins(&config, &mirrors, &Method::GET, &release()).unwrap();
        assert_eq!(plan.candidates[0], BUILTIN_MIRRORS[1], "the next mirror takes over");
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
        let dl: Uri = "https://github.com/o/r/releases/download/v1/x".parse().unwrap();
        let latest: Uri = "https://github.com/o/r/releases/latest/download/x".parse().unwrap();
        let archive: Uri = "https://github.com/o/r/archive/refs/tags/v1.zip".parse().unwrap();
        assert!(mirror_candidate(&codeload));
        assert!(mirror_candidate(&dl));
        assert!(mirror_candidate(&latest));
        assert!(mirror_candidate(&archive));

        // a web page whose path happens to contain the same words stays direct
        let blob: Uri = "https://github.com/o/r/blob/main/archive/notes.md".parse().unwrap();
        assert!(!mirror_candidate(&blob), "a blob page is not a download");
        let nested: Uri =
            "https://github.com/o/r/blob/main/docs/releases/download/x.md"
                .parse()
                .unwrap();
        assert!(!mirror_candidate(&nested));
        let repo_page: Uri = "https://github.com/o/r".parse().unwrap();
        assert!(!mirror_candidate(&repo_page));

        let avatar: Uri = "https://avatars.githubusercontent.com/u/1".parse().unwrap();
        assert!(!mirror_candidate(&avatar));
        assert!(candidate_uri(&avatar), "segment rules stay wide for direct mode");
    }

    #[test]
    fn headers_gate_blocks_wrong_status_size_and_missing_ranges() {
        assert!(headers_eligible(StatusCode::OK, Some("1048576"), Some("bytes"), MIB));
        assert!(!headers_eligible(
            StatusCode::PARTIAL_CONTENT,
            Some("1048576"),
            Some("bytes"),
            MIB
        ));
        assert!(!headers_eligible(StatusCode::OK, None, Some("bytes"), MIB));
        assert!(!headers_eligible(StatusCode::OK, Some("1024"), Some("bytes"), MIB));
        assert!(!headers_eligible(StatusCode::OK, Some("1048576"), Some("none"), MIB));
        assert!(!headers_eligible(StatusCode::OK, Some("abc"), Some("bytes"), MIB));
        // below the configured threshold but above the 1 MiB floor: the caller
        // applies the config on top
        assert!(!headers_eligible(
            StatusCode::OK,
            Some("2097152"),
            Some("bytes"),
            4 * MIB
        ));
    }

    #[test]
    fn download_rules_cover_github_assets_only() {
        let uri: Uri = "https://objects.githubusercontent.com/x/y?sig=1".parse().unwrap();
        assert!(candidate_uri(&uri));
        let uri: Uri = "https://release-assets.githubusercontent.com/a/b"
            .parse()
            .unwrap();
        assert!(candidate_uri(&uri));
        let uri: Uri = "https://github.com/owner/repo/releases/download/v1/x.zip"
            .parse()
            .unwrap();
        assert!(candidate_uri(&uri));
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
}
