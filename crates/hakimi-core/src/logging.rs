use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;
use tracing_subscriber::EnvFilter;

use crate::paths::Paths;
use crate::util::{atomic_write_json, now, redact_ip, redact_url};

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const DIAGNOSTIC_LOG_LINES: usize = 300;

/// Initialize local-only logging. Logs never leave the machine; catalog/DoH URLs are redacted
/// before they are written by callers.
pub fn init(paths: &Paths, level: &str) -> Result<()> {
    paths.ensure()?;
    let log_path = paths.log_file();
    if let Ok(metadata) = std::fs::metadata(&log_path) {
        if metadata.len() > MAX_LOG_BYTES {
            let rotated = paths.logs_dir().join("hakimi.1.log");
            let _ = std::fs::rename(&log_path, rotated);
        }
    }
    // Keep the append-only handle open for the lifetime of the subscriber. Opening and
    // closing the file for every event costs a pair of metadata syscalls, which is
    // noticeable during a page-load burst of connection logs. O_APPEND keeps lines from
    // concurrent processes intact.
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .unwrap_or_else(|_| {
            OpenOptions::new()
                .write(true)
                .open(if cfg!(windows) { "NUL" } else { "/dev/null" })
                .expect("null device")
        });
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.to_ascii_lowercase()));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .with_target(true);
    let _ = subscriber.try_init();
    Ok(())
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

/// Redact credentials/query strings from user-configurable URLs before exporting config.
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

    #[test]
    fn tail_reads_last_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hakimi.log");
        std::fs::write(&path, "a\nb\nc\nd\n").unwrap();
        assert_eq!(log_file_tail(&path, 2), vec!["c", "d"]);
    }

    #[test]
    fn redacts_ip_and_urls_in_log_lines() {
        let line = "resolved ip=20.205.243.166 url=https://doh.example/q?token=secret";
        let redacted = redact_log_line(line);
        assert!(redacted.contains("ip=20.205.243.x"));
        assert!(redacted.contains("url=https://doh.example/q"));
        assert!(!redacted.contains("secret"));
    }

    #[test]
    fn redacts_urls_in_config() {
        let value = serde_json::json!({
            "doh": {"primary": "https://user:pass@doh.example/query?token=secret"},
            "url": "https://example.com/path?key=value",
            "name": "https://example.com/untouched"
        });
        let redacted = redact_config_value(value);
        assert_eq!(redacted["doh"]["primary"], "https://doh.example/query");
        assert_eq!(redacted["url"], "https://example.com/path");
        assert_eq!(redacted["name"], "https://example.com/untouched");
    }
}
