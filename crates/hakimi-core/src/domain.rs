use std::borrow::Cow;
use std::collections::HashMap;

use anyhow::{bail, Context, Result};

/// A normalized domain or wildcard pattern.
///
/// Wildcards use the design document's semantics: `*.example.com` matches any subdomain of
/// `example.com`, including multi-level subdomains, but never `example.com` itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainPattern {
    pattern: String,
    wildcard: bool,
}

impl DomainPattern {
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("empty domain pattern");
        }
        if let Some(suffix) = trimmed.strip_prefix("*.") {
            if suffix.contains('*') {
                bail!("wildcard is only allowed as the leading `*.` label");
            }
            let suffix = normalize_hostname(suffix)
                .with_context(|| format!("invalid wildcard suffix in `{input}`"))?;
            if suffix.split('.').count() < 2 {
                bail!("wildcard suffix `{suffix}` must contain at least two labels");
            }
            Ok(Self {
                pattern: format!("*.{suffix}"),
                wildcard: true,
            })
        } else {
            if trimmed.contains('*') {
                bail!("wildcard is only allowed as the leading `*.` label");
            }
            let host = normalize_hostname(trimmed)?;
            Ok(Self {
                pattern: host,
                wildcard: false,
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// Match an already-normalized host.
    pub fn matches_normalized(&self, host: &str) -> bool {
        if self.wildcard {
            let suffix = &self.pattern[2..];
            host.len() > suffix.len()
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        } else {
            host == self.pattern
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        match normalize_hostname(host) {
            Ok(host) => self.matches_normalized(&host),
            Err(_) => false,
        }
    }
}

/// Normalize a DNS host name to lowercase ASCII (IDNA) without a trailing dot.
pub fn normalize_hostname(input: &str) -> Result<String> {
    normalize_hostname_cow(input).map(Cow::into_owned)
}

/// Normalize a host name, borrowing the input when it is already canonical.
///
/// The fast path is deliberately strict and validates labels before returning
/// a borrow, so it accepts exactly the inputs the owned path would accept
/// unchanged. Uppercase, IDNA, trailing-dot, and empty/colon inputs fall
/// through to the existing slow path.
pub fn normalize_hostname_cow(input: &str) -> Result<Cow<'_, str>> {
    let trimmed = input.trim();
    if is_canonical_ascii_hostname(trimmed) {
        return Ok(Cow::Borrowed(trimmed));
    }

    let mut host = trimmed.to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    if host.is_empty() {
        bail!("empty host name");
    }
    if host.contains(':') {
        bail!("`{input}` is not a domain name");
    }
    // An ASCII host needs no IDNA processing. The label checks below reject
    // the same invalid characters, and this runs on every request twice.
    let ascii = if host.is_ascii() {
        host
    } else {
        idna::domain_to_ascii(&host)
            .map_err(|err| anyhow::anyhow!("invalid internationalized domain `{input}`: {err:?}"))?
    };
    validate_ascii_hostname(&ascii)?;
    Ok(Cow::Owned(ascii))
}

/// True when `host` is already a lowercase ASCII DNS name that passes the
/// same label checks as [`validate_ascii_hostname`].
///
/// One pass over the bytes replaces the previous ascii/trailing-dot/colon/
/// uppercase scans plus the per-label validation walk. Anything unusual
/// (uppercase, IDNA, trailing dot, colon, invalid label) falls through to the
/// existing slow path so its error messages and normalization stay unchanged.
fn is_canonical_ascii_hostname(host: &str) -> bool {
    let bytes = host.as_bytes();
    if bytes.is_empty() || bytes.len() > 253 {
        return false;
    }
    let mut label_start = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' | b'-' => {}
            b'.' => {
                let len = index - label_start;
                if len == 0 || len > 63 || bytes[label_start] == b'-' || bytes[index - 1] == b'-' {
                    return false;
                }
                label_start = index + 1;
            }
            _ => return false,
        }
    }
    let len = bytes.len() - label_start;
    len > 0 && len <= 63 && bytes[label_start] != b'-' && bytes[bytes.len() - 1] != b'-'
}

fn validate_ascii_hostname(ascii: &str) -> Result<()> {
    if ascii.len() > 253 {
        bail!("domain name is longer than 253 characters");
    }
    for label in ascii.split('.') {
        if label.is_empty() {
            bail!("domain name contains an empty label");
        }
        if label.len() > 63 {
            bail!("domain label is longer than 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("domain label `{label}` starts or ends with a hyphen");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("domain label `{label}` contains unsupported characters");
        }
    }
    Ok(())
}

/// Host of a pasted URL: `https://user@www.example.com:443/path?q#f` yields
/// `www.example.com`. `None` when the input isn't URL-shaped at all.
pub fn host_from_url(input: &str) -> Option<&str> {
    let (scheme, rest) = input.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    // The authority ends at the first path, query or fragment delimiter.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or(rest, |(host, _)| host),
        None => host.split_once(':').map_or(host, |(host, _)| host),
    };
    let host = host.trim();
    (!host.is_empty()).then_some(host)
}

pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// The host of an authority without the brackets of an IPv6 literal.
///
/// The brackets belong to the authority, not to the host: keeping them makes
/// the host look like a name, so it matches no group and cannot be resolved.
pub fn bare_host(host: &str) -> &str {
    match host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inner) => inner,
        None => host,
    }
}

/// Maps hosts to group ids with the documented precedence:
/// exact match first, then the longest wildcard suffix.
#[derive(Clone, Debug, Default)]
pub struct DomainMatcher {
    exact: HashMap<String, MatchEntry>,
    wildcards: HashMap<String, MatchEntry>,
}

#[derive(Clone, Debug)]
struct MatchEntry {
    group: String,
    rule: usize,
}

impl DomainMatcher {
    pub fn from_patterns<I, S>(entries: I) -> Result<Self>
    where
        I: IntoIterator<Item = (S, S)>,
        S: AsRef<str>,
    {
        let mut exact = HashMap::new();
        let mut wildcards = HashMap::new();
        for (group_id, pattern) in entries {
            let group_id = group_id.as_ref().to_string();
            if group_id.is_empty() {
                bail!("empty group id");
            }
            let pattern = DomainPattern::parse(pattern.as_ref())?;
            let entry = MatchEntry {
                group: group_id,
                rule: 0,
            };
            if pattern.wildcard {
                // `or_insert` keeps the first declaration for a shared wildcard, matching
                // exact-match precedence.
                wildcards
                    .entry(pattern.pattern[2..].to_string())
                    .or_insert(entry);
            } else {
                exact.entry(pattern.pattern).or_insert(entry);
            }
        }
        Ok(Self { exact, wildcards })
    }

    pub fn from_groups(groups: &[crate::config::GroupConfig]) -> Result<Self> {
        let mut exact = HashMap::new();
        let mut wildcards = HashMap::new();
        for group in groups {
            for (rule_index, rule) in group.domains.iter().enumerate() {
                let pattern = DomainPattern::parse(&rule.pattern)?;
                let entry = MatchEntry {
                    group: group.id.clone(),
                    rule: rule_index,
                };
                if pattern.wildcard {
                    wildcards
                        .entry(pattern.pattern[2..].to_string())
                        .or_insert(entry);
                } else {
                    exact.entry(pattern.pattern).or_insert(entry);
                }
            }
        }
        Ok(Self { exact, wildcards })
    }

    pub fn match_host(&self, host: &str) -> Option<&str> {
        let host = normalize_hostname(host).ok()?;
        self.match_normalized(&host)
    }

    pub fn match_normalized(&self, host: &str) -> Option<&str> {
        self.match_entry_normalized(host).map(|entry| entry.0)
    }

    /// Group id plus the matched domain-rule index. Callers that resolve a
    /// per-domain route need the rule index; other callers keep using
    /// [`Self::match_normalized`].
    pub fn match_entry_normalized(&self, host: &str) -> Option<(&str, usize)> {
        if let Some(entry) = self.exact.get(host) {
            return Some((entry.group.as_str(), entry.rule));
        }
        self.wildcard_entry(host)
            .map(|entry| (entry.group.as_str(), entry.rule))
    }

    /// Longest wildcard suffix wins. Scanning label boundaries from left to right
    /// visits the longest suffix first and costs O(labels) map lookups instead of
    /// an O(number of wildcards) scan per request.
    fn wildcard_entry(&self, host: &str) -> Option<&MatchEntry> {
        if self.wildcards.is_empty() {
            return None;
        }
        for (index, byte) in host.bytes().enumerate() {
            if byte == b'.' {
                if let Some(entry) = self.wildcards.get(&host[index + 1..]) {
                    return Some(entry);
                }
            }
        }
        None
    }

    fn wildcard_match(&self, host: &str) -> Option<&str> {
        self.wildcard_entry(host).map(|entry| entry.group.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcards.is_empty()
    }

    pub fn pattern_count(&self) -> usize {
        self.exact.len() + self.wildcards.len()
    }

    /// Exact patterns, used for group/probe logic.
    pub fn exact_patterns(&self) -> impl Iterator<Item = &String> {
        self.exact.keys()
    }

    /// True when every host matching `pattern` also belongs to this matcher.
    ///
    /// Used to decide whether a remote `ips` entry is covered by a group.
    pub fn covers_pattern(&self, pattern: &DomainPattern) -> bool {
        if !pattern.wildcard {
            return self.match_normalized(&pattern.pattern).is_some();
        }
        let suffix = &pattern.pattern[2..];
        self.wildcards.contains_key(suffix) || self.wildcard_match(suffix).is_some()
    }
}

/// Best match in a domain -> value map that may contain exact and wildcard keys.
pub fn lookup_domain_map<'a, V>(
    map: &'a HashMap<String, V>,
    host: &str,
) -> Option<(&'a String, &'a V)> {
    let host = normalize_hostname(host).ok()?;
    if let Some((key, value)) = map.get_key_value(&host) {
        return Some((key, value));
    }
    let mut best: Option<(&String, &V, usize)> = None;
    for (key, value) in map {
        if let Some(suffix) = key.strip_prefix("*.") {
            if host.len() > suffix.len()
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            {
                let labels = suffix.split('.').count();
                if best.map(|(_, _, n)| labels > n).unwrap_or(true) {
                    best = Some((key, value, labels));
                }
            }
        }
    }
    best.map(|(key, value, _)| (key, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DomainRule, GroupConfig};

    fn group(id: &str, domains: &[&str]) -> GroupConfig {
        GroupConfig {
            id: id.into(),
            name: id.into(),
            domains: domains
                .iter()
                .map(|domain| DomainRule::new(*domain))
                .collect(),
            enabled: true,
            homepage: None,
            default_route: crate::config::RoutePolicy::direct(),
        }
    }

    #[test]
    fn exact_beats_wildcard() {
        let matcher = DomainMatcher::from_groups(&[
            group("github", &["github.com", "*.github.com"]),
            group("assets", &["*.github.com"]),
        ])
        .unwrap();
        assert_eq!(matcher.match_host("github.com"), Some("github"));
        assert_eq!(matcher.match_host("api.github.com"), Some("github"));
    }

    #[test]
    fn wildcard_does_not_match_root() {
        let pattern = DomainPattern::parse("*.example.com").unwrap();
        assert!(pattern.matches("a.example.com"));
        assert!(pattern.matches("a.b.example.com"));
        assert!(!pattern.matches("example.com"));
        assert!(!pattern.matches("notexample.com"));
    }

    #[test]
    fn longest_wildcard_wins() {
        let matcher = DomainMatcher::from_groups(&[
            group("broad", &["*.example.com"]),
            group("narrow", &["*.cdn.example.com"]),
        ])
        .unwrap();
        assert_eq!(matcher.match_host("a.cdn.example.com"), Some("narrow"));
        assert_eq!(matcher.match_host("a.example.com"), Some("broad"));
    }

    #[test]
    fn ipv6_literals_lose_their_brackets() {
        assert_eq!(bare_host("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(bare_host("[::1]"), "::1");
        assert_eq!(bare_host("example.com"), "example.com");
        assert_eq!(bare_host("1.2.3.4"), "1.2.3.4");
        // A missing closing bracket is not an IPv6 literal.
        assert_eq!(bare_host("[2001:db8::1"), "[2001:db8::1");
    }

    #[test]
    fn normalization() {
        assert_eq!(normalize_hostname(" GitHub.COM. ").unwrap(), "github.com");
        assert!(DomainPattern::parse("*.example.com")
            .unwrap()
            .matches("A.Example.COM"));
        assert!(DomainPattern::parse("bad*pattern.com").is_err());
    }

    /// The behaviour of `normalize_hostname` before the borrowing fast path
    /// existed.  The fast path must not change any decision, only the
    /// allocation behaviour.
    fn reference_normalize(input: &str) -> Result<String> {
        let mut host = input.trim().to_ascii_lowercase();
        if host.ends_with('.') {
            host.pop();
        }
        if host.is_empty() {
            bail!("empty host name");
        }
        if host.contains(':') {
            bail!("`{input}` is not a domain name");
        }
        let ascii = if host.is_ascii() {
            host
        } else {
            idna::domain_to_ascii(&host).map_err(|err| {
                anyhow::anyhow!("invalid internationalized domain `{input}`: {err:?}")
            })?
        };
        if ascii.len() > 253 {
            bail!("domain name is longer than 253 characters");
        }
        for label in ascii.split('.') {
            if label.is_empty() {
                bail!("domain name contains an empty label");
            }
            if label.len() > 63 {
                bail!("domain label is longer than 63 characters");
            }
            if label.starts_with('-') || label.ends_with('-') {
                bail!("domain label `{label}` starts or ends with a hyphen");
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                bail!("domain label `{label}` contains unsupported characters");
            }
        }
        Ok(ascii)
    }

    #[test]
    fn cow_normalization_matches_the_previous_behaviour() {
        let long_label = "a".repeat(64);
        let long_host = std::iter::repeat("a".repeat(63) + ".")
            .take(4)
            .collect::<String>()
            + "com";
        let cases = [
            "",
            " ",
            ".",
            "..",
            "a.",
            "a..b",
            "A.COM",
            "a.com.",
            " a.com. ",
            "example.com",
            "xn--bcher-kva.example",
            "bücher.example",
            "2001:db8::1",
            "host:443",
            "a.com/path",
            "a.com:80",
            "1.2.3.4",
            "0.0.0.0",
            "under_score.com",
            "-lead.com",
            "trail-.com",
            "a b.com",
            "a.com\n",
            "\ta.com",
            long_label.as_str(),
            long_host.as_str(),
        ];
        for input in cases {
            let expected = reference_normalize(input);
            let actual = normalize_hostname_cow(input);
            match (&expected, &actual) {
                (Ok(expected), Ok(actual)) => assert_eq!(
                    expected.as_str(),
                    actual.as_ref(),
                    "different result for {input:?}"
                ),
                (Err(_), Err(_)) => {}
                (expected, actual) => {
                    panic!("different outcome for {input:?}: old={expected:?} new={actual:?}")
                }
            }
        }
    }

    #[test]
    fn cow_normalization_borrows_canonical_hosts_only() {
        assert!(matches!(
            normalize_hostname_cow("example.com"),
            Ok(Cow::Borrowed("example.com"))
        ));
        assert!(matches!(
            normalize_hostname_cow(" example.com "),
            Ok(Cow::Borrowed("example.com"))
        ));
        assert!(matches!(
            normalize_hostname_cow("Example.com"),
            Ok(Cow::Owned(host)) if host == "example.com"
        ));
        assert!(matches!(
            normalize_hostname_cow("example.com."),
            Ok(Cow::Owned(host)) if host == "example.com"
        ));
        assert!(matches!(
            normalize_hostname_cow("bücher.example"),
            Ok(Cow::Owned(host)) if host == "xn--bcher-kva.example"
        ));
        assert!(normalize_hostname_cow("bad domain.example").is_err());
    }

    #[test]
    fn canonical_fast_path_accepts_exactly_the_old_fast_path() {
        let mut cases: Vec<String> = [
            "example.com",
            "a",
            "a-b.c",
            "a.b-c",
            "a..b",
            "-a.com",
            "a-.com",
            "a_b.com",
            "a b.com",
            "A.com",
            "a.com.",
            "a:b",
            "",
            "127.0.0.1",
            "example.test",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        cases.push("a".repeat(63));
        cases.push("a".repeat(64));
        cases.push(format!("{}.com", "a".repeat(63)));
        cases.push(format!("{}.com", "a".repeat(64)));
        for host in &cases {
            let old_fast_path = !host.is_empty()
                && host.is_ascii()
                && !host.ends_with('.')
                && !host.contains(':')
                && !host.bytes().any(|byte| byte.is_ascii_uppercase())
                && validate_ascii_hostname(host).is_ok();
            assert_eq!(
                is_canonical_ascii_hostname(host),
                old_fast_path,
                "fast path changed for {host:?}"
            );
        }
    }

    #[test]
    fn urls_reduce_to_their_host() {
        assert_eq!(
            host_from_url("https://www.example.com").unwrap(),
            "www.example.com"
        );
        assert_eq!(
            host_from_url("HTTPS://user:pw@www.example.com:8443/en/?q=1#top").unwrap(),
            "www.example.com"
        );
        assert_eq!(host_from_url("http://example.com/").unwrap(), "example.com");
        assert_eq!(
            host_from_url("ftp://*.example.com").unwrap(),
            "*.example.com"
        );
        assert!(host_from_url("www.example.com").is_none());
        assert!(host_from_url("https://").is_none());
        assert!(host_from_url("https:// ").is_none());
    }

    #[test]
    fn domain_map_lookup() {
        let mut map = HashMap::new();
        map.insert("github.com".to_string(), vec![1]);
        map.insert("*.github.com".to_string(), vec![2]);
        assert_eq!(lookup_domain_map(&map, "github.com").unwrap().1, &vec![1]);
        assert_eq!(
            lookup_domain_map(&map, "api.github.com").unwrap().1,
            &vec![2]
        );
    }
}
