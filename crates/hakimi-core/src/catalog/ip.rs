use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{
    validate_group_id, AppConfig, MAX_DOMAINS_PER_GROUP, MAX_GROUPS, MAX_TOTAL_DOMAINS,
};
use crate::domain::{normalize_hostname, DomainMatcher, DomainPattern};
use crate::util::is_public_ip;

pub const IP_CATALOG_SCHEMA: u32 = 1;
pub const MAX_IPS_PER_DOMAIN: usize = 8;
pub const MAX_IPS_ENTRIES: usize = 4096;

/// JSON shape from section 7.1 of the design document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpCatalogRaw {
    pub v: u32,
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub ips: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct IpCatalog {
    pub schema_version: u32,
    /// Raw group definitions, for UI display.
    pub groups: BTreeMap<String, Vec<String>>,
    /// Normalized domain or wildcard -> ordered candidate IPs.
    pub ips: HashMap<String, Vec<IpAddr>>,
    pub warnings: Vec<String>,
    /// Sum of every domain's IP list. Status polling reads this while holding
    /// the catalog lock; recomputing it there scanned the whole catalog.
    ip_count: usize,
    matcher: DomainMatcher,
    /// `suffix -> full wildcard key` for every `*.` entry. Matching walks the
    /// host's label boundaries, so a cold connection does not scan unrelated
    /// wildcard entries.
    wildcards: HashMap<String, String>,
}

impl IpCatalog {
    pub fn lookup_ips(&self, domain: &str) -> Option<(&String, &Vec<IpAddr>)> {
        let host = normalize_hostname(domain).ok()?;
        self.lookup_ips_normalized(&host)
    }

    /// Lookup for callers that already normalized the host (the route cursor
    /// does this once per connection).
    pub fn lookup_ips_normalized(&self, host: &str) -> Option<(&String, &Vec<IpAddr>)> {
        if let Some((key, ips)) = self.ips.get_key_value(host) {
            return Some((key, ips));
        }
        if self.wildcards.is_empty() {
            return None;
        }
        for (index, byte) in host.bytes().enumerate() {
            if byte == b'.' {
                if let Some(key) = self.wildcards.get(&host[index + 1..]) {
                    return self.ips.get_key_value(key);
                }
            }
        }
        None
    }

    pub fn match_group(&self, host: &str) -> Option<&str> {
        self.matcher.match_host(host)
    }

    pub fn group_ids(&self) -> impl Iterator<Item = &String> {
        self.groups.keys()
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.groups.is_empty()
    }

    pub fn domain_count(&self) -> usize {
        self.ips.len()
    }

    pub fn ip_count(&self) -> usize {
        self.ip_count
    }

    /// All configured exact domains that are affected by this catalog's wildcard entries.
    pub fn exact_domains_matching_wildcards(&self, config: &AppConfig) -> Vec<String> {
        let wildcard_suffixes: Vec<&str> = self
            .ips
            .keys()
            .filter_map(|key| key.strip_prefix("*."))
            .collect();
        if wildcard_suffixes.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for group in &config.groups {
            for rule in group
                .domains
                .iter()
                .filter(|rule| !rule.pattern.starts_with("*."))
            {
                let domain = rule.pattern.as_str();
                if wildcard_suffixes.iter().any(|suffix| {
                    domain.len() > suffix.len()
                        && domain.ends_with(suffix)
                        && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
                }) {
                    out.push(domain.to_string());
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

/// Validate and normalize a remote IP catalog.
///
/// A malformed schema, a bad domain, or an entry with too many IPs rejects the whole catalog
/// (the old cache stays in place). Individual non-public IPs are dropped with a warning, since
/// they can never be safely tested; an entry with no public IPs is dropped too.
pub fn validate(raw: IpCatalogRaw, config: &AppConfig) -> Result<IpCatalog> {
    if raw.v != IP_CATALOG_SCHEMA {
        bail!(
            "unsupported IP catalog schema version {} (expected {IP_CATALOG_SCHEMA})",
            raw.v
        );
    }
    if raw.groups.len() > MAX_GROUPS {
        bail!("IP catalog has more than {MAX_GROUPS} groups");
    }
    if raw.ips.len() > MAX_IPS_ENTRIES {
        bail!("IP catalog has more than {MAX_IPS_ENTRIES} IP entries");
    }

    let mut warnings = Vec::new();
    let mut groups = BTreeMap::new();
    let mut total_domains = 0usize;
    let mut catalog_group_patterns: Vec<(String, String)> = Vec::new();

    for (group_id, domains) in &raw.groups {
        validate_group_id(group_id).with_context(|| format!("IP catalog group `{group_id}`"))?;
        if domains.len() > MAX_DOMAINS_PER_GROUP {
            bail!("IP catalog group `{group_id}` has more than {MAX_DOMAINS_PER_GROUP} domains");
        }
        let mut seen = HashSet::new();
        let mut normalized = Vec::with_capacity(domains.len());
        for domain in domains {
            let pattern = DomainPattern::parse(domain)
                .with_context(|| format!("IP catalog group `{group_id}`"))?;
            if !seen.insert(pattern.as_str().to_string()) {
                warnings.push(format!(
                    "group `{group_id}` has duplicate domain `{domain}`; ignored"
                ));
                continue;
            }
            catalog_group_patterns.push((group_id.clone(), pattern.as_str().to_string()));
            normalized.push(pattern.as_str().to_string());
        }
        total_domains += normalized.len();
        groups.insert(group_id.clone(), normalized);
    }
    if total_domains > MAX_TOTAL_DOMAINS {
        bail!("IP catalog defines more than {MAX_TOTAL_DOMAINS} domains");
    }

    // Coverage may come from the catalog's own group list or from user-configured groups.
    let mut coverage_entries = catalog_group_patterns.clone();
    for group in &config.groups {
        for rule in &group.domains {
            coverage_entries.push((group.id.clone(), rule.pattern.clone()));
        }
    }
    let coverage = DomainMatcher::from_patterns(coverage_entries)?;

    let mut ips: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for (raw_domain, raw_ips) in raw.ips {
        let pattern = DomainPattern::parse(&raw_domain)
            .with_context(|| format!("IP catalog entry `{raw_domain}`"))?;
        if !coverage.covers_pattern(&pattern) {
            warnings.push(format!(
                "IP catalog entry `{raw_domain}` is not covered by any group; ignored"
            ));
            continue;
        }
        if raw_ips.len() > MAX_IPS_PER_DOMAIN {
            bail!(
                "IP catalog entry `{raw_domain}` has {} IPs (maximum {MAX_IPS_PER_DOMAIN})",
                raw_ips.len()
            );
        }
        let mut parsed = Vec::with_capacity(raw_ips.len());
        for raw_ip in &raw_ips {
            let ip: IpAddr = raw_ip
                .trim()
                .parse()
                .with_context(|| format!("IP catalog entry `{raw_domain}` contains `{raw_ip}`"))?;
            // A harness points the catalog at its own loopback origins.
            if !is_public_ip(ip) && !crate::hooks::allow_private_catalog_ips() {
                warnings.push(format!(
                    "IP catalog entry `{raw_domain}` contains non-public IP `{ip}`; ignored"
                ));
                continue;
            }
            if !parsed.contains(&ip) {
                parsed.push(ip);
            }
        }
        if parsed.is_empty() {
            warnings.push(format!(
                "IP catalog entry `{raw_domain}` has no usable public IPs; ignored"
            ));
            continue;
        }
        if ips.insert(pattern.as_str().to_string(), parsed).is_some() {
            warnings.push(format!(
                "IP catalog contains duplicate entry `{raw_domain}`; last one wins"
            ));
        }
    }

    let matcher = DomainMatcher::from_patterns(groups.iter().flat_map(|(id, domains)| {
        domains
            .iter()
            .map(move |domain| (id.clone(), domain.clone()))
    }))?;

    let wildcards: HashMap<String, String> = ips
        .keys()
        .filter_map(|key| {
            key.strip_prefix("*.")
                .map(|suffix| (suffix.to_string(), key.clone()))
        })
        .collect();
    let ip_count = ips.values().map(Vec::len).sum();

    Ok(IpCatalog {
        schema_version: raw.v,
        groups,
        ips,
        warnings,
        ip_count,
        matcher,
        wildcards,
    })
}

/// Domains whose cached IP should be skipped once after a catalog update.
pub fn affected_domains(
    old: Option<&IpCatalog>,
    new: &IpCatalog,
    config: &AppConfig,
    cached_domains: &[String],
) -> HashSet<String> {
    let mut affected = HashSet::new();
    let mut changed_wildcards: Vec<String> = Vec::new();

    let old_ips = old.map(|catalog| &catalog.ips);
    let mut all_keys: HashSet<&String> = new.ips.keys().collect();
    if let Some(old) = old_ips {
        all_keys.extend(old.keys());
    }
    for key in all_keys {
        let old_value = old_ips.and_then(|map| map.get(key));
        let new_value = new.ips.get(key);
        if old_value == new_value {
            continue;
        }
        if let Some(suffix) = key.strip_prefix("*.") {
            changed_wildcards.push(suffix.to_string());
        } else {
            affected.insert(key.clone());
        }
    }

    if !changed_wildcards.is_empty() {
        for group in &config.groups {
            for rule in group
                .domains
                .iter()
                .filter(|rule| !rule.pattern.starts_with("*."))
            {
                if matches_any_suffix(&rule.pattern, &changed_wildcards) {
                    affected.insert(rule.pattern.clone());
                }
            }
        }
        for domain in cached_domains {
            if matches_any_suffix(domain, &changed_wildcards) {
                affected.insert(domain.clone());
            }
        }
    }

    // New exact entries always deserve one fresh probe, even on the first catalog load.
    if old.is_none() {
        affected.extend(new.ips.keys().filter(|key| !key.starts_with("*.")).cloned());
        affected.extend(new.exact_domains_matching_wildcards(config));
    }
    affected
}

fn matches_any_suffix(domain: &str, suffixes: &[String]) -> bool {
    suffixes.iter().any(|suffix| {
        domain.len() > suffix.len()
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(json: &str) -> IpCatalogRaw {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn validates_document_example_shape() {
        let catalog = validate(
            raw(r#"{
                    "v": 1,
                    "groups": {
                        "github": ["github.com", "api.github.com", "*.githubusercontent.com"],
                        "pixiv": ["pixiv.net", "*.pximg.net"]
                    },
                    "ips": {
                        "github.com": ["20.205.243.166", "140.82.121.4"],
                        "api.github.com": ["20.205.243.168"],
                        "raw.githubusercontent.com": ["185.199.108.133"],
                        "pixiv.net": ["210.140.139.155", "210.140.139.161"],
                        "uncovered.example": ["1.1.1.1"]
                    }
                }"#),
            &AppConfig::default(),
        )
        .unwrap();
        assert_eq!(catalog.ips.len(), 4);
        assert_eq!(catalog.domain_count(), 4);
        assert_eq!(catalog.ip_count(), 6);
        assert_eq!(
            catalog
                .lookup_ips("raw.githubusercontent.com")
                .unwrap()
                .1
                .len(),
            1
        );
        assert!(catalog
            .warnings
            .iter()
            .any(|w| w.contains("uncovered.example")));
    }

    #[test]
    fn wildcard_precedence() {
        let catalog = validate(
            raw(r#"{
                    "v": 1,
                    "groups": {"g": ["*.example.com"]},
                    "ips": {
                        "*.example.com": ["1.1.1.1"],
                        "cdn.example.com": ["8.8.8.8"]
                    }
                }"#),
            &AppConfig::default(),
        )
        .unwrap();
        assert_eq!(
            catalog.lookup_ips("cdn.example.com").unwrap().1[0].to_string(),
            "8.8.8.8"
        );
        assert_eq!(
            catalog.lookup_ips("other.example.com").unwrap().1[0].to_string(),
            "1.1.1.1"
        );
    }

    #[test]
    fn drops_private_ips_and_rejects_too_many() {
        let catalog = validate(
            raw(r#"{
                    "v": 1,
                    "groups": {"g": ["example.com"]},
                    "ips": {"example.com": ["10.0.0.1", "1.1.1.1"]}
                }"#),
            &AppConfig::default(),
        )
        .unwrap();
        assert_eq!(catalog.lookup_ips("example.com").unwrap().1.len(), 1);

        let too_many = format!(
            r#"{{"v":1,"groups":{{"g":["example.com"]}},"ips":{{"example.com":[{}]}}}}"#,
            (0..9)
                .map(|i| format!("\"1.1.1.{}\"", i + 1))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(validate(raw(&too_many), &AppConfig::default()).is_err());
    }

    #[test]
    fn indexed_lookup_matches_the_linear_reference() {
        let catalog = validate(
            raw(r#"{
                    "v": 1,
                    "groups": {"g": ["example.com", "*.example.com"]},
                    "ips": {
                        "example.com": ["8.8.8.8"],
                        "api.example.com": ["8.8.4.4"],
                        "*.example.com": ["1.1.1.1"],
                        "*.cdn.example.com": ["9.9.9.9"]
                    }
                }"#),
            &AppConfig::default(),
        )
        .unwrap();
        for host in [
            "example.com",
            "api.example.com",
            "www.example.com",
            "a.cdn.example.com",
            "other.example.net",
        ] {
            let expected =
                crate::domain::lookup_domain_map(&catalog.ips, host).map(|(key, _)| key.clone());
            let actual = catalog.lookup_ips(host).map(|(key, _)| key.clone());
            assert_eq!(actual, expected, "lookup for {host}");
        }
    }

    #[test]
    fn wildcard_catalog_entry_serves_a_subdomain() {
        let catalog = validate(
            raw(r#"{
                    "v": 1,
                    "groups": {"g": ["*.mitm.test"]},
                    "ips": {"*.mitm.test": ["1.1.1.1"]}
                }"#),
            &AppConfig::default(),
        )
        .unwrap();
        let found = catalog.lookup_ips("a.mitm.test");
        assert!(
            found.is_some(),
            "the wildcard entry must serve the subdomain"
        );
        assert_eq!(found.unwrap().1.len(), 1);
    }

    #[test]
    fn rejects_bad_schema_version() {
        assert!(validate(
            raw(r#"{"v": 2, "groups": {}, "ips": {}}"#),
            &AppConfig::default()
        )
        .is_err());
    }

    #[test]
    fn computes_affected_domains() {
        let old = validate(
            raw(r#"{"v":1,"groups":{"g":["github.com","*.github.com"]},
                    "ips":{"github.com":["1.1.1.1"],"*.github.com":["8.8.8.8"]}}"#),
            &AppConfig::default(),
        )
        .unwrap();
        let new = validate(
            raw(r#"{"v":1,"groups":{"g":["github.com","*.github.com"]},
                    "ips":{"github.com":["1.1.1.2"],"*.github.com":["8.8.4.4"]}}"#),
            &AppConfig::default(),
        )
        .unwrap();
        let affected = affected_domains(
            Some(&old),
            &new,
            &AppConfig::default(),
            &["api.github.com".to_string(), "pixiv.net".to_string()],
        );
        assert!(affected.contains("github.com"));
        assert!(affected.contains("api.github.com"));
        assert!(!affected.contains("pixiv.net"));
    }
}
