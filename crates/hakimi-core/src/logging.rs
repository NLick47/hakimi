use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::json;
use tracing_subscriber::fmt::MakeWriter;

use crate::config::LogFormat;
use crate::paths::Paths;
use crate::util::{atomic_write_json, now, redact_ip, redact_url};

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const MAX_LOG_BACKUPS: usize = 5;
const DIAGNOSTIC_LOG_LINES: usize = 300;
/// Bounded queue between request workers and the log writer. A page-load burst
/// can produce thousands of events; keeping the queue finite means a stalled
/// disk can never turn logging into unbounded memory growth.
const LOG_QUEUE_CAPACITY: usize = 2048;

/// Events that were dropped because the writer could not keep up.
static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Set once a subscriber is installed, so a host that owns its own logging
/// (the CLI) can install it first and keep the runtime from doing it again.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// How many log events were dropped because the queue was full.
pub fn dropped_events() -> u64 {
    DROPPED_EVENTS.load(Ordering::Relaxed)
}

/// Whether a log subscriber has already been installed.
pub fn initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

/// Optional behaviour for [`init_with`].
#[derive(Clone, Copy, Debug, Default)]
pub struct LoggingOptions {
    /// Write the same events to stderr as well, for a foreground process
    /// whose service manager collects stdout/stderr.
    pub stderr: bool,
    /// The `level` argument wins over `RUST_LOG` instead of being the fallback.
    pub explicit_level: bool,
}

/// Initialize local-only logging. Logs never leave the machine; catalog/DoH URLs are redacted
/// before they are written by callers.
pub fn init(paths: &Paths, level: &str, format: LogFormat) -> Result<()> {
    init_with(paths, level, format, LoggingOptions::default())
}

/// [`init`] with an explicit sink policy.
pub fn init_with(
    paths: &Paths,
    level: &str,
    format: LogFormat,
    options: LoggingOptions,
) -> Result<()> {
    paths.ensure()?;
    let log_path = paths.log_file();
    if let Ok(metadata) = fs::metadata(&log_path) {
        if metadata.len() > MAX_LOG_BYTES {
            rotate_logs(&log_path);
        }
    }
    let file = open_log_file(&log_path);
    match spawn_log_writer(file, log_path.clone()) {
        Ok(sink) => {
            let writer = NonBlockingMakeWriter::new(sink);
            let _ = if options.stderr {
                install(TeeMakeWriter { file: writer }, level, format, options)
            } else {
                install(writer, level, format, options)
            };
        }
        Err(error) => {
            // Thread creation is the only fallible part; if it fails, keep the
            // previous synchronous behavior rather than losing logging entirely.
            eprintln!(
                "hakimi: could not start asynchronous log writer ({error}); using synchronous writes"
            );
            let writer = std::sync::Mutex::new(open_log_file(&log_path));
            let _ = if options.stderr {
                install(TeeMakeWriter { file: writer }, level, format, options)
            } else {
                install(writer, level, format, options)
            };
        }
    }
    Ok(())
}

/// Append-only file handle. O_APPEND keeps lines from concurrent processes
/// intact; opening once avoids a metadata syscall per event.
fn open_log_file(path: &Path) -> File {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|_| {
            OpenOptions::new()
                .write(true)
                .open(if cfg!(windows) { "NUL" } else { "/dev/null" })
                .expect("null device")
        })
}

/// Desktop keeps `RUST_LOG`-style filtering; the regex machinery behind
/// `EnvFilter` is too large for the Android binary.
#[cfg(not(target_os = "android"))]
fn install<W>(writer: W, level: &str, format: LogFormat, options: LoggingOptions) -> bool
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let filter = if options.explicit_level {
        tracing_subscriber::EnvFilter::new(level.to_ascii_lowercase())
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level.to_ascii_lowercase()))
    };
    let installed = match format {
        LogFormat::Text => {
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(writer)
                .with_ansi(false)
                .with_target(true);
            subscriber.try_init().is_ok()
        }
        LogFormat::Json => {
            // JSONL is append-only and self-describing, which makes it suitable
            // for local analysis (jq/SQLite/ClickHouse) without a text parser.
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(writer)
                .with_ansi(false)
                .with_target(true)
                .json()
                .flatten_event(true)
                .with_current_span(false)
                .with_span_list(false);
            subscriber.try_init().is_ok()
        }
    };
    if installed {
        INITIALIZED.store(true, Ordering::Relaxed);
    }
    installed
}

#[cfg(target_os = "android")]
fn install<W>(writer: W, level: &str, format: LogFormat, _options: LoggingOptions) -> bool
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let filter: tracing::level_filters::LevelFilter = level
        .trim()
        .parse()
        .unwrap_or(tracing::level_filters::LevelFilter::INFO);
    let installed = match format {
        LogFormat::Text => {
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(filter)
                .with_writer(writer)
                .with_ansi(false)
                .with_target(true);
            subscriber.try_init().is_ok()
        }
        LogFormat::Json => {
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(filter)
                .with_writer(writer)
                .with_ansi(false)
                .with_target(true)
                .json()
                .flatten_event(true)
                .with_current_span(false)
                .with_span_list(false);
            subscriber.try_init().is_ok()
        }
    };
    if installed {
        INITIALIZED.store(true, Ordering::Relaxed);
    }
    installed
}

#[derive(Clone)]
struct LogSink {
    tx: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
}

/// Writer factory for one tracing event. Formatting happens on the caller's
/// thread (tracing requires that), but the completed line is handed to a
/// bounded channel and written by one dedicated thread. No file lock or disk
/// syscall runs on a Tokio worker.
#[derive(Clone)]
struct NonBlockingMakeWriter {
    sink: LogSink,
}

impl NonBlockingMakeWriter {
    fn new(sink: LogSink) -> Self {
        Self { sink }
    }
}

impl<'a> MakeWriter<'a> for NonBlockingMakeWriter {
    type Writer = NonBlockingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        NonBlockingWriter {
            sink: self.sink.clone(),
            buffer: Vec::with_capacity(256),
        }
    }
}

struct NonBlockingWriter {
    sink: LogSink,
    buffer: Vec<u8>,
}

impl Write for NonBlockingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for NonBlockingWriter {
    fn drop(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        // try_send keeps a slow/stalled disk from applying backpressure to
        // request handling. If the queue is full, this event is dropped and
        // counted rather than blocking the proxy.
        if self
            .sink
            .tx
            .try_send(std::mem::take(&mut self.buffer))
            .is_err()
        {
            self.sink.dropped.fetch_add(1, Ordering::Relaxed);
            DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Copies every log line to stderr as well as to the file sink, for a
/// foreground process whose service manager collects stderr.
struct TeeMakeWriter<A> {
    file: A,
}

impl<'a, A> MakeWriter<'a> for TeeMakeWriter<A>
where
    A: MakeWriter<'a>,
{
    type Writer = TeeWriter<A::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        TeeWriter {
            file: self.file.make_writer(),
            stderr: io::stderr(),
        }
    }
}

struct TeeWriter<W> {
    file: W,
    stderr: io::Stderr,
}

impl<W: Write> Write for TeeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write_all(buf)?;
        // stderr is best effort: a closed console must not break logging.
        let _ = self.stderr.write_all(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        let _ = self.stderr.flush();
        Ok(())
    }
}

fn spawn_log_writer(mut file: File, path: PathBuf) -> io::Result<LogSink> {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(LOG_QUEUE_CAPACITY);
    let sink = LogSink {
        tx,
        dropped: Arc::new(AtomicU64::new(0)),
    };
    std::thread::Builder::new()
        .name("hakimi-log".to_string())
        .spawn(move || {
            let mut written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
            for bytes in rx {
                if file.write_all(&bytes).is_err() {
                    break;
                }
                written = written.saturating_add(bytes.len() as u64);
                // Rotate while the process runs, not only at the next launch:
                // per-connection INFO lines can fill the cap during one session.
                if written > MAX_LOG_BYTES {
                    let _ = file.flush();
                    drop(file);
                    rotate_logs(&path);
                    file = open_log_file(&path);
                    written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
                }
            }
            let _ = file.flush();
        })?;
    Ok(sink)
}

/// Rotate to `hakimi.1.log` ... `hakimi.5.log`. Text logs are cheap to keep,
/// but JSON/debug logs grow quickly; a single 5 MB backup loses the history
/// needed to compare a regression with the previous day.
fn rotate_logs(log_path: &Path) {
    let Some(dir) = log_path.parent() else {
        return;
    };
    let _ = fs::remove_file(dir.join(format!("hakimi.{MAX_LOG_BACKUPS}.log")));
    for index in (1..MAX_LOG_BACKUPS).rev() {
        let from = dir.join(format!("hakimi.{index}.log"));
        let to = dir.join(format!("hakimi.{}.log", index + 1));
        if from.exists() {
            let _ = fs::rename(from, to);
        }
    }
    let _ = fs::rename(log_path, dir.join("hakimi.1.log"));
}

pub fn log_file_tail(path: &Path, max_lines: usize) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut lines: VecDeque<String> = VecDeque::with_capacity(max_lines);
    for line in text.lines() {
        if lines.len() == max_lines {
            lines.pop_front();
        }
        lines.push_back(line.to_string());
    }
    lines.into_iter().collect()
}

/// Build the diagnostics export written by the CLI/desktop shell.
pub fn export_diagnostics(paths: &Paths, status: serde_json::Value) -> Result<PathBuf> {
    let log_tail: Vec<String> = log_file_tail(&paths.log_file(), DIAGNOSTIC_LOG_LINES)
        .into_iter()
        .map(|line| redact_log_line(&line))
        .collect();
    let exported_at = now();
    let value = json!({
        "app": "hakimi",
        "version": env!("CARGO_PKG_VERSION"),
        "exportedAt": exported_at,
        "status": status,
        "logTail": log_tail,
    });
    let path = paths.root().join(format!(
        "diagnostics-{}.json",
        exported_at.format("%Y%m%d-%H%M%S")
    ));
    atomic_write_json(&path, &value)?;
    Ok(path)
}

/// Redact credentials, paths and query strings from user-configurable URLs before exporting config.
pub fn redact_config_value(mut value: serde_json::Value) -> serde_json::Value {
    fn walk(value: &mut serde_json::Value, key: Option<&str>) {
        match value {
            serde_json::Value::Object(map) => {
                for (name, child) in map.iter_mut() {
                    walk(child, Some(name));
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    walk(child, key);
                }
            }
            serde_json::Value::String(text)
                if matches!(
                    key,
                    Some("url")
                        | Some("primary")
                        | Some("fallback")
                        | Some("ip")
                        | Some("doh")
                        | Some("signatureUrl")
                        // Catalog status and config expose the source/mirror
                        // URLs outside a `url` key. They can carry a token in
                        // the path just like a DoH endpoint.
                        | Some("source")
                        | Some("ipSource")
                        | Some("dohSource")
                        | Some("ipMirrors")
                        | Some("dohMirrors")
                ) && text.starts_with("http") =>
            {
                *text = redact_url(text);
            }
            serde_json::Value::String(_) => {}
            _ => {}
        }
    }
    walk(&mut value, None);
    value
}

pub fn append_manual_line(path: &Path, line: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Mask IP addresses and URL query strings in exported log lines.
pub fn redact_log_line(line: &str) -> String {
    line.split(' ')
        .map(|token| {
            let (prefix, value) = token.split_once('=').unwrap_or(("", token));
            let trimmed = value.trim_matches(|c: char| {
                matches!(
                    c,
                    ',' | ';' | '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>'
                )
            });
            let replacement = if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
                Some(redact_ip(ip))
            } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                Some(redact_url(trimmed))
            } else {
                None
            };
            match replacement {
                Some(value) if prefix.is_empty() => value,
                Some(value) => format!("{prefix}={value}"),
                None => token.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::fmt::MakeWriter;

    #[test]
    fn nonblocking_writer_buffers_one_event_until_drop() {
        let (tx, rx) = mpsc::sync_channel(4);
        let sink = LogSink {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        let make = NonBlockingMakeWriter::new(sink);
        {
            let mut writer = make.make_writer();
            writer.write_all(b"hello").unwrap();
            writer.write_all(b" world\n").unwrap();
            assert!(rx.try_recv().is_err(), "must not write while formatting");
        }
        assert_eq!(rx.recv().unwrap(), b"hello world\n");
    }

    #[test]
    fn dropped_events_are_counted() {
        let before = dropped_events();
        let (tx, rx) = mpsc::sync_channel(1);
        let sink = LogSink {
            tx: tx.clone(),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        tx.send(b"first\n".to_vec()).unwrap();
        let make = NonBlockingMakeWriter::new(sink);
        {
            let mut writer = make.make_writer();
            writer.write_all(b"second\n").unwrap();
        }
        // Another test may drop an event at the same time, so only the
        // direction of the change is pinned here.
        assert!(dropped_events() > before);
        assert_eq!(rx.recv().unwrap(), b"first\n");
    }

    #[test]
    fn full_log_queue_drops_instead_of_blocking() {
        let (tx, rx) = mpsc::sync_channel(1);
        let dropped = Arc::new(AtomicU64::new(0));
        let sink = LogSink {
            tx: tx.clone(),
            dropped: dropped.clone(),
        };
        tx.send(b"first\n".to_vec()).unwrap();
        let make = NonBlockingMakeWriter::new(sink);
        {
            let mut writer = make.make_writer();
            writer.write_all(b"second\n").unwrap();
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert_eq!(rx.recv().unwrap(), b"first\n");
    }

    #[test]
    fn tail_reads_last_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hakimi.log");
        std::fs::write(&path, "a\nb\nc\nd\n").unwrap();
        assert_eq!(log_file_tail(&path, 2), vec!["c", "d"]);
    }

    #[test]
    fn redacts_url_path_tokens() {
        // NextDNS-style DoH URLs (and catalog mirrors) carry the credential in
        // the path; clearing only the query would export it verbatim.
        assert_eq!(
            crate::util::redact_url("https://doh.example/dns-query/secret-token?x=1"),
            "https://doh.example/redacted"
        );
        assert_eq!(
            crate::util::redact_url("https://doh.example"),
            "https://doh.example/"
        );
    }

    #[test]
    fn redacts_ip_and_urls_in_log_lines() {
        let line = "resolved ip=20.205.243.166 url=https://doh.example/q?token=secret";
        let redacted = redact_log_line(line);
        assert!(redacted.contains("ip=20.205.243.x"));
        assert!(redacted.contains("url=https://doh.example/redacted"));
        assert!(!redacted.contains("secret"));
    }

    #[test]
    fn redacts_urls_in_config() {
        let value = serde_json::json!({
            "doh": {"primary": "https://user:pass@doh.example/query?token=secret"},
            "url": "https://example.com/path?key=value",
            "catalogs": {
                "ipMirrors": ["https://mirror.example/ips/secret-token?key=value"],
                "dohMirrors": ["https://mirror.example/doh/token"]
            },
            "ipSource": "https://catalog.example/ips/secret-token",
            "dohSource": "https://catalog.example/doh/token",
            "name": "https://example.com/untouched"
        });
        let redacted = redact_config_value(value);
        assert_eq!(redacted["doh"]["primary"], "https://doh.example/redacted");
        assert_eq!(redacted["url"], "https://example.com/redacted");
        assert_eq!(
            redacted["catalogs"]["ipMirrors"][0],
            "https://mirror.example/redacted"
        );
        assert_eq!(
            redacted["catalogs"]["dohMirrors"][0],
            "https://mirror.example/redacted"
        );
        assert_eq!(redacted["ipSource"], "https://catalog.example/redacted");
        assert_eq!(redacted["dohSource"], "https://catalog.example/redacted");
        assert_eq!(redacted["name"], "https://example.com/untouched");
    }
}
