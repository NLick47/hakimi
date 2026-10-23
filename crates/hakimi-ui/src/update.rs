//! Update checks against the project's GitHub releases.
//!
//! A check only reads release metadata. The app never downloads or installs
//! anything itself: the UI opens the release page in the browser, so a
//! tampered response can at worst open a GitHub URL.

use std::cmp::Ordering;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

pub const PROJECT: &str = "NLick47/hakimi";
pub const RELEASES_URL: &str = "https://github.com/NLick47/hakimi/releases";

fn api_url() -> String {
    format!("https://api.github.com/repos/{PROJECT}/releases/latest")
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub notes: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    UpToDate,
    Available(Release),
}

/// Asks GitHub for the newest published (non-prerelease) release.
pub async fn check() -> Result<CheckOutcome> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(6))
        .timeout(Duration::from_secs(12))
        .user_agent(format!("hakimi/{}", current_version()))
        .build()
        .context("building the update client")?;
    let response = client
        .get(api_url())
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .context("requesting the latest release")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        // No release has been published yet; that is not an error.
        return Ok(CheckOutcome::UpToDate);
    }
    let status = response.status();
    if !status.is_success() {
        bail!("GitHub returned HTTP {}", status.as_u16());
    }
    let body: Value = response
        .json()
        .await
        .context("decoding the latest release")?;
    parse_release(&body, current_version())
}

/// Separated from the request so version handling is testable without a network.
pub fn parse_release(body: &Value, current: &str) -> Result<CheckOutcome> {
    let tag = body
        .get("tag_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let version = tag.strip_prefix('v').unwrap_or(tag).trim();
    if version.is_empty() || parse_version(version).is_none() {
        bail!("the latest release has no usable version tag");
    }
    if !is_newer(version, current) {
        return Ok(CheckOutcome::UpToDate);
    }
    let fallback = format!("{RELEASES_URL}/tag/v{version}");
    let url = body
        .get("html_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|url| safe_release_url(url))
        .map(str::to_string)
        .unwrap_or(fallback);
    let notes = body
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .chars()
        .take(8000)
        .collect();
    Ok(CheckOutcome::Available(Release {
        version: version.to_string(),
        url,
        notes,
    }))
}

/// The API payload is untrusted input. Only the project's own release pages
/// may be opened, so a modified response cannot redirect the user elsewhere.
fn safe_release_url(url: &str) -> bool {
    url.starts_with("https://github.com/NLick47/hakimi/")
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
            "tag_name": "v0.1.0",
            "html_url": "https://github.com/NLick47/hakimi/releases/tag/v0.1.0",
            "body": ""
        });
        assert_eq!(
            parse_release(&body, "0.1.0").unwrap(),
            CheckOutcome::UpToDate
        );
    }

    #[test]
    fn release_payload_is_extracted() {
        let body = json!({
            "tag_name": "v0.2.0",
            "html_url": "https://github.com/NLick47/hakimi/releases/tag/v0.2.0",
            "body": "  - 新的更新检查  \n"
        });
        let outcome = parse_release(&body, "0.1.0").unwrap();
        assert_eq!(
            outcome,
            CheckOutcome::Available(Release {
                version: "0.2.0".into(),
                url: "https://github.com/NLick47/hakimi/releases/tag/v0.2.0".into(),
                notes: "- 新的更新检查".into(),
            })
        );
    }

    #[test]
    fn unsafe_or_missing_urls_fall_back_to_the_project_page() {
        let body = json!({
            "tag_name": "v0.2.0",
            "html_url": "https://example.com/download",
        });
        let CheckOutcome::Available(release) = parse_release(&body, "0.1.0").unwrap() else {
            panic!("expected an update");
        };
        assert_eq!(
            release.url,
            "https://github.com/NLick47/hakimi/releases/tag/v0.2.0"
        );
    }

    #[test]
    fn invalid_tags_are_rejected() {
        assert!(parse_release(&json!({ "tag_name": "nightly" }), "0.1.0").is_err());
        assert!(parse_release(&json!({}), "0.1.0").is_err());
    }
}
