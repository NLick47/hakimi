use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{validate_doh_url, DohEndpoint};

pub const DOH_CATALOG_SCHEMA: u32 = 1;
pub const MAX_REMOTE_DOH: usize = 64;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawDohCatalog {
    Wrapped {
        v: u32,
        #[serde(default)]
        doh: Vec<RawDohEntry>,
        #[serde(default)]
        endpoints: Vec<RawDohEntry>,
    },
    List(Vec<RawDohEntry>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawDohEntry {
    Url(String),
    Object {
        #[serde(default)]
        name: String,
        url: String,
        #[serde(default, rename = "bootstrapIp", alias = "bootstrap_ip")]
        bootstrap_ip: Option<std::net::IpAddr>,
        #[serde(default = "default_true")]
        enabled: bool,
    },
}

fn default_true() -> bool {
    true
}

/// Validate a remote DoH catalog. Entries never change the user's primary/fallback settings;
/// they are only appended to the effective endpoint list.
pub fn validate(bytes: &[u8]) -> Result<Vec<DohEndpoint>> {
    let raw: RawDohCatalog = serde_json::from_slice(bytes).context("parsing DoH catalog")?;
    let (schema, entries) = match raw {
        RawDohCatalog::Wrapped {
            v,
            mut doh,
            endpoints,
        } => {
            doh.extend(endpoints);
            (v, doh)
        }
        RawDohCatalog::List(entries) => (DOH_CATALOG_SCHEMA, entries),
    };
    if schema != DOH_CATALOG_SCHEMA {
        bail!("unsupported DoH catalog schema version {schema} (expected {DOH_CATALOG_SCHEMA})");
    }
    if entries.len() > MAX_REMOTE_DOH {
        bail!("DoH catalog has more than {MAX_REMOTE_DOH} entries");
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        let (name, url, bootstrap_ip, enabled) = match entry {
            RawDohEntry::Url(url) => (String::new(), url, None, true),
            RawDohEntry::Object {
                name,
                url,
                bootstrap_ip,
                enabled,
            } => (name, url, bootstrap_ip, enabled),
        };
        validate_doh_url(&url, "remote DoH entry")?;
        let url = url.trim().to_string();
        if !seen.insert(url.clone()) {
            continue;
        }
        let mut name = name.trim().to_string();
        if name.is_empty() {
            name = url::Url::parse(&url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| url.clone());
        }
        out.push(DohEndpoint {
            name,
            url,
            bootstrap_ip,
            enabled,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DohCatalogSummary {
    pub schema_version: u32,
    pub endpoints: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_wrapped_and_list_forms() {
        let wrapped = validate(
            br#"{"v":1,"doh":[{"name":"a","url":"https://doh.example/query"},
                               "https://doh2.example/dns-query"]}"#,
        )
        .unwrap();
        assert_eq!(wrapped.len(), 2);

        let list = validate(br#"["https://doh.example/query"]"#).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn rejects_http_and_duplicates_are_dropped() {
        assert!(validate(br#"["http://doh.example/query"]"#).is_err());
        let list =
            validate(br#"["https://doh.example/query","https://doh.example/query"]"#).unwrap();
        assert_eq!(list.len(), 1);
    }
}
