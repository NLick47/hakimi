//! Update checks against the project's release manifest.
//!
//! The manifest is a small JSON asset attached to every GitHub Release. It
//! contains one entry per client, so a desktop-only release cannot make the
//! Android app think it has an update (and vice versa). The app never
//! downloads or installs anything itself: the UI opens the release page in the
//! browser, so a tampered manifest can at worst open a GitHub URL.

use std::cmp::Ordering;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

pub const PROJECT: &str = "NLick47/hakimi";
pub const RELEASES_URL: &str = "https://github.com/NLick47/hakimi/releases";

fn manifest_url() -> String {
    format!("https://github.com/{PROJECT}/releases/latest/download/latest.json")
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    UpToDate,
    Available(Release),
}

/// Reads the manifest attached to the newest published release.
pub async fn check() -> Result<CheckOutcome> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(6))
        .timeout(Duration::from_secs(12))
        .user_agent(format!("hakimi/{}", current_version()))
        .build()
        .context("building the update client")?;
    let response = client
        .get(manifest_url())
        .header("Accept", "application/json")
        .send()
        .await
        .context("requesting the update manifest")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        // No release has been published yet; that is not an error.
        return Ok(CheckOutcome::UpToDate);
    }
    let status = response.status();
    if !status.is_success() {
        bail!("GitHub returned HTTP {}", status.as_u16());
    }
    let text = response
        .text()
        .await
        .context("reading the update manifest")?;
    let body: Value =
        serde_json::from_str(&text).context("decoding the update manifest")?;
    parse_manifest(&body, current_version())
}

/// Separated from the request so version handling is testable without a network.
pub fn parse_manifest(body: &Value, current: &str) -> Result<CheckOutcome> {
    let schema = body.get("schema").and_then(Value::as_u64);
    if schema != Some(1) {
        bail!("unsupported update manifest schema");
    }

    let Some(desktop) = body.get("desktop").and_then(Value::as_object) else {
        // The first releases may not contain a desktop build yet.
        return Ok(CheckOutcome::UpToDate);
    };
    let version = desktop
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let version = version.strip_prefix('v').unwrap_or(version).trim();
    if version.is_empty() || parse_version(version).is_none() {
        bail!("the update manifest has no usable desktop version");
    }
    if !is_newer(version, current) {
        return Ok(CheckOutcome::UpToDate);
    }

    let release = body
        .get("release")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let fallback = if safe_tag(release) {
        format!("{RELEASES_URL}/tag/{release}")
    } else {
        RELEASES_URL.to_string()
    };
    let url = desktop
        .get("url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|url| safe_release_url(url))
        .map(str::to_string)
        .unwrap_or(fallback);
    Ok(CheckOutcome::Available(Release {
        version: version.to_string(),
        url,
    }))
}

fn safe_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

/// The manifest is untrusted input. Only the project's own release pages may
/// be opened, so a modified manifest cannot redirect the user elsewhere.
fn safe_release_url(url: &str) -> bool {
    url.starts_with("https://github.com/NLick47/hakimi/releases/")
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    compare_versions(candidate, current) == Ordering::Greater
}

/// Compares two versions tolerantly: a leading `v` and build metadata are
/// ignored, missing components count as zero (`0.3` equals `0.3.0`), and
/// prereleases sort before the matching release.
pub fn compare_versions(left: &str, right: &str) -> Ordering {
    let (Some(left), Some(right)) = (parse_version(left), parse_version(right)) else {
        // An unparseable version must never be reported as an update.
        return Ordering::Equal;
    };
    let length = left.core.len().max(right.core.len());
    for index in 0..length {
        let a = left.core.get(index).copied().unwrap_or(0);
        let b = right.core.get(index).copied().unwrap_or(0);
        match a.cmp(&b) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match (left.pre.is_empty(), right.pre.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => compare_prerelease(&left.pre, &right.pre),
    }
}

fn compare_prerelease(left: &[&str], right: &[&str]) -> Ordering {
    for (a, b) in left.iter().zip(right) {
        let order = match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(a), Ok(b)) => a.cmp(&b),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => a.cmp(b),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

#[derive(Debug)]
struct ParsedVersion<'a> {
    core: Vec<u64>,
    pre: Vec<&'a str>,
}

fn parse_version(value: &str) -> Option<ParsedVersion<'_>> {
    let value = value.trim();
    let value = value.strip_prefix('v').unwrap_or(value);
    let value = value.split('+').next()?.trim();
    let (core, pre) = match value.split_once('-') {
        Some((core, pre)) => (core, pre.split('.').collect()),
        None => (value, Vec::new()),
    };
    let mut parts = Vec::new();
    for part in core.split('.') {
        if part.is_empty() {
            return None;
        }
        parts.push(part.parse::<u64>().ok()?);
    }
    if parts.is_empty() {
        return None;
    }
    Some(ParsedVersion { core: parts, pre })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions_compare_by_core() {
        assert_eq!(compare_versions("0.1.0", "v0.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.3", "0.3.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.2.0", "0.1.9"), Ordering::Greater);
        assert_eq!(compare_versions("0.1.10", "0.1.9"), Ordering::Greater);
        assert!(is_newer("1.0.0+build.7", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
    }

    #[test]
    fn prereleases_sort_before_the_release() {
        assert!(is_newer("0.2.0", "0.2.0-beta.2"));
        assert!(is_newer("0.2.0-beta.2", "0.2.0-beta.1"));
        assert!(is_newer("0.2.0-beta", "0.2.0-alpha"));
        assert!(!is_newer("0.2.0-beta", "0.2.0"));
        assert_eq!(compare_versions("garbage", "0.1.0"), Ordering::Equal);
    }

    #[test]
    fn current_release_is_not_an_update() {
        let body = json!({
            "schema": 1,
            "release": "release-2026.10.23",
            "desktop": {
                "version": "0.1.0",
                "url": "https://github.com/NLick47/hakimi/releases/tag/release-2026.10.23"
            }
        });
        assert_eq!(
            parse_manifest(&body, "0.1.0").unwrap(),
            CheckOutcome::UpToDate
        );
    }

    #[test]
    fn desktop_entry_is_extracted() {
        let body = json!({
            "schema": 1,
            "release": "release-2026.10.23",
            "desktop": {
                "version": "0.2.0",
                "url": "https://github.com/NLick47/hakimi/releases/tag/release-2026.10.23"
            }
        });
        assert_eq!(
            parse_manifest(&body, "0.1.0").unwrap(),
            CheckOutcome::Available(Release {
                version: "0.2.0".into(),
                url: "https://github.com/NLick47/hakimi/releases/tag/release-2026.10.23".into(),
            })
        );
    }

    #[test]
    fn android_only_manifest_is_up_to_date() {
        let body = json!({
            "schema": 1,
            "release": "release-2026.10.23",
            "android": {
                "version": "0.2.0",
                "url": "https://github.com/NLick47/hakimi/releases/tag/release-2026.10.23"
            }
        });
        assert_eq!(
            parse_manifest(&body, "0.1.0").unwrap(),
            CheckOutcome::UpToDate
        );
    }

    #[test]
    fn unsafe_or_missing_urls_fall_back_to_the_project_release() {
        let body = json!({
            "schema": 1,
            "release": "release-2026.10.23",
            "desktop": {
                "version": "0.2.0",
                "url": "https://example.com/download"
            }
        });
        let CheckOutcome::Available(release) = parse_manifest(&body, "0.1.0").unwrap() else {
            panic!("expected an update");
        };
        assert_eq!(
            release.url,
            "https://github.com/NLick47/hakimi/releases/tag/release-2026.10.23"
        );
    }

    #[test]
    fn invalid_manifest_is_rejected() {
        assert!(parse_manifest(&json!({}), "0.1.0").is_err());
        assert!(parse_manifest(
            &json!({ "schema": 2, "desktop": { "version": "0.2.0" } }),
            "0.1.0"
        )
        .is_err());
        assert!(parse_manifest(
            &json!({ "schema": 1, "desktop": { "version": "nightly" } }),
            "0.1.0"
        )
        .is_err());
    }
}
