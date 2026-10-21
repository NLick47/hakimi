pub mod doh;
pub mod ip;
pub mod signature;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::cache::CacheManager;
use crate::config::{AppConfig, ConfigManager, DohEndpoint};
use crate::paths::Paths;
use crate::util::{atomic_write, atomic_write_json, now, read_json, redact_url, sha256_hex};

use self::ip::{IpCatalog, IpCatalogRaw};
use self::signature::CatalogSignature;

const MAX_CATALOG_BYTES: usize = 2 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogMeta {
    pub source: String,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    pub fetched_at: DateTime<Utc>,
    pub sha256: String,
    pub catalog_version: u64,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshReport {
    pub kind: String,
    pub updated: bool,
    pub up_to_date: bool,
    pub source: Option<String>,
    pub version: u64,
    pub affected_domains: Vec<String>,
    pub warnings: Vec<String>,
    pub message: Option<String>,
}

impl RefreshReport {
    fn up_to_date(kind: &str, source: String, version: u64, message: &str) -> Self {
        Self {
            kind: kind.to_string(),
            updated: false,
            up_to_date: true,
            source: Some(source),
            version,
            affected_domains: Vec::new(),
            warnings: Vec::new(),
            message: Some(message.to_string()),
        }
    }

    fn skipped(kind: &str, message: &str) -> Self {
        Self {
            kind: kind.to_string(),
            updated: false,
            up_to_date: false,
            source: None,
            version: 0,
            affected_domains: Vec::new(),
            warnings: Vec::new(),
            message: Some(message.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogStatus {
    pub ip_loaded: bool,
    pub ip_version: u64,
    pub ip_source: Option<String>,
    pub ip_fetched_at: Option<DateTime<Utc>>,
    pub ip_domains: usize,
    pub ip_ips: usize,
    pub ip_warnings: Vec<String>,
    pub doh_loaded: bool,
    pub doh_count: usize,
    pub doh_source: Option<String>,
    pub doh_fetched_at: Option<DateTime<Utc>>,
    pub doh_warnings: Vec<String>,
}

/// Owns the remote IP and DoH catalogs. Refresh is explicit (the runtime schedules it); the
/// manager never blocks startup and always keeps the previous catalog when validation fails.
pub struct CatalogManager {
    paths: Paths,
    config: Arc<ConfigManager>,
    cache: Arc<CacheManager>,
    client: reqwest::Client,
    ip_catalog: RwLock<Option<IpCatalog>>,
    ip_meta: RwLock<Option<CatalogMeta>>,
    doh_catalog: RwLock<Option<Vec<DohEndpoint>>>,
    doh_meta: RwLock<Option<CatalogMeta>>,
    refresh_lock: tokio::sync::Mutex<()>,
}

/// Read-only catalog surface used by the decision engine. It can be mocked in tests.
pub trait RemoteIpProvider: Send + Sync {
    fn remote_ips(&self, domain: &str) -> Option<(String, Vec<std::net::IpAddr>)>;
    fn remote_sni(&self, group_id: &str) -> Option<String>;
    fn has_ip_catalog(&self) -> bool;

    /// Remote IPs for a domain plus the "an IP catalog is loaded" flag.
    ///
    /// The decision cursor needs both for every new connection. The default
    /// keeps existing providers working; implementations that can answer both
    /// from one snapshot should override it.
    fn remote_ips_with_catalog(
        &self,
        domain: &str,
    ) -> (Option<(String, Vec<std::net::IpAddr>)>, bool) {
        (self.remote_ips(domain), self.has_ip_catalog())
    }
}

impl RemoteIpProvider for CatalogManager {
    fn remote_ips(&self, domain: &str) -> Option<(String, Vec<std::net::IpAddr>)> {
        CatalogManager::remote_ips(self, domain)
    }

    fn remote_sni(&self, group_id: &str) -> Option<String> {
        CatalogManager::remote_sni(self, group_id)
    }

    fn has_ip_catalog(&self) -> bool {
        CatalogManager::has_ip_catalog(self)
    }

    fn remote_ips_with_catalog(
        &self,
        domain: &str,
    ) -> (Option<(String, Vec<std::net::IpAddr>)>, bool) {
        CatalogManager::remote_ips_with_catalog(self, domain)
    }
}

impl CatalogManager {
    pub fn load(
        paths: &Paths,
        config: Arc<ConfigManager>,
        cache: Arc<CacheManager>,
    ) -> Result<Arc<Self>> {
        let client = reqwest::Client::builder()
            .user_agent(format!("hakimi/{}", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::limited(5))
            // Catalog fetches must not loop back through our own system-proxy takeover.
            .no_proxy()
            .build()
            .context("building catalog HTTP client")?;

        let ip_meta: Option<CatalogMeta> = read_json(&paths.catalog_ip_meta_file()).ok();
        let ip_catalog = match std::fs::read(paths.catalog_ip_file()) {
            Ok(bytes) => match serde_json::from_slice::<IpCatalogRaw>(&bytes)
                .map_err(anyhow::Error::from)
                .and_then(|raw| ip::validate(raw, &config.snapshot()))
            {
                Ok(catalog) => Some(catalog),
                Err(error) => {
                    tracing::warn!(error = %error, "cached IP catalog is invalid; ignoring it");
                    None
                }
            },
            Err(_) => None,
        };

        let doh_meta: Option<CatalogMeta> = read_json(&paths.catalog_doh_meta_file()).ok();
        let doh_catalog = match std::fs::read(paths.catalog_doh_file()) {
            Ok(bytes) => match doh::validate(&bytes) {
                Ok(catalog) => Some(catalog),
                Err(error) => {
                    tracing::warn!(error = %error, "cached DoH catalog is invalid; ignoring it");
                    None
                }
            },
            Err(_) => None,
        };

        if let Some(meta) = &ip_meta {
            let current = config.snapshot().catalog_version;
            if meta.catalog_version > current {
                config.set_catalog_version(meta.catalog_version)?;
            }
        }

        Ok(Arc::new(Self {
            paths: paths.clone(),
            config,
            cache,
            client,
            ip_catalog: RwLock::new(ip_catalog),
            ip_meta: RwLock::new(ip_meta),
            doh_catalog: RwLock::new(doh_catalog),
            doh_meta: RwLock::new(doh_meta),
            refresh_lock: tokio::sync::Mutex::new(()),
        }))
    }

    pub fn ip_catalog(&self) -> Option<IpCatalog> {
        self.ip_catalog.read().clone()
    }

    pub fn has_ip_catalog(&self) -> bool {
        self.ip_catalog.read().is_some()
    }

    pub fn remote_ips(&self, domain: &str) -> Option<(String, Vec<std::net::IpAddr>)> {
        self.ip_catalog
            .read()
            .as_ref()
            .and_then(|catalog| catalog.lookup_ips_normalized(domain))
            .map(|(pattern, ips)| (pattern.clone(), ips.clone()))
    }

    /// One read-lock acquisition for the domain's IPs and the catalog flag.
    /// The decision cursor asks for both on every new connection.
    pub fn remote_ips_with_catalog(
        &self,
        domain: &str,
    ) -> (Option<(String, Vec<std::net::IpAddr>)>, bool) {
        let catalog = self.ip_catalog.read();
        let available = catalog.is_some();
        let ips = catalog
            .as_ref()
            .and_then(|catalog| catalog.lookup_ips_normalized(domain))
            .map(|(pattern, ips)| (pattern.clone(), ips.clone()));
        (ips, available)
    }

    pub fn remote_sni(&self, group_id: &str) -> Option<String> {
        self.ip_catalog
            .read()
            .as_ref()
            .and_then(|catalog| catalog.sni.get(group_id).cloned())
    }

    pub fn remote_doh_endpoints(&self) -> Vec<DohEndpoint> {
        self.doh_catalog
            .read()
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|endpoint| endpoint.enabled)
            .collect()
    }

    pub fn status(&self) -> CatalogStatus {
        let ip = self.ip_catalog.read();
        let ip_meta = self.ip_meta.read();
        let doh = self.doh_catalog.read();
        let doh_meta = self.doh_meta.read();
        CatalogStatus {
            ip_loaded: ip.is_some(),
            ip_version: ip_meta
                .as_ref()
                .map(|meta| meta.catalog_version)
                .unwrap_or(0),
            ip_source: ip_meta.as_ref().map(|meta| meta.source.clone()),
            ip_fetched_at: ip_meta.as_ref().map(|meta| meta.fetched_at),
            ip_domains: ip.as_ref().map(IpCatalog::domain_count).unwrap_or(0),
            ip_ips: ip.as_ref().map(IpCatalog::ip_count).unwrap_or(0),
            ip_warnings: ip_meta
                .as_ref()
                .map(|meta| meta.warnings.clone())
                .unwrap_or_default(),
            doh_loaded: doh.is_some(),
            doh_count: doh.as_ref().map(Vec::len).unwrap_or(0),
            doh_source: doh_meta.as_ref().map(|meta| meta.source.clone()),
            doh_fetched_at: doh_meta.as_ref().map(|meta| meta.fetched_at),
            doh_warnings: doh_meta
                .as_ref()
                .map(|meta| meta.warnings.clone())
                .unwrap_or_default(),
        }
    }

    pub async fn refresh_ip(&self, force: bool) -> Result<RefreshReport> {
        let _guard = self.refresh_lock.lock().await;
        let config = self.config.snapshot();
        let sources = catalog_sources(&config.catalogs.ip, &config.catalogs.ip_mirrors);
        if sources.is_empty() {
            return Ok(RefreshReport::skipped(
                "ip",
                "no remote IP catalog source is configured",
            ));
        }
        let timeout = Duration::from_secs(config.catalogs.timeout_secs);
        let signature = match &config.catalogs.signature_public_key {
            Some(key) => Some(Arc::new(
                CatalogSignature::new(key).context("invalid catalog signature public key")?,
            )),
            None => None,
        };

        let mut errors = Vec::new();
        for source in sources {
            let previous_meta = self.ip_meta.read().clone();
            let conditional = previous_meta
                .as_ref()
                .filter(|meta| meta.source == source)
                .map(|meta| (meta.etag.clone(), meta.last_modified.clone()));
            match self
                .fetch_catalog(
                    &source,
                    timeout,
                    force,
                    conditional,
                    signature.as_deref(),
                    &config,
                )
                .await
            {
                Ok(FetchOutcome::NotModified) => {
                    if self.ip_catalog.read().is_some() {
                        if let Some(meta) = self.ip_meta.write().as_mut() {
                            meta.fetched_at = now();
                        }
                        self.persist_ip_meta();
                        let version = self
                            .ip_meta
                            .read()
                            .as_ref()
                            .map(|meta| meta.catalog_version)
                            .unwrap_or(0);
                        return Ok(RefreshReport::up_to_date(
                            "ip",
                            source,
                            version,
                            "remote catalog is unchanged",
                        ));
                    }
                    errors.push(format!(
                        "{}: not modified but no cached catalog",
                        redact_url(&source)
                    ));
                }
                Ok(FetchOutcome::Body {
                    bytes,
                    etag,
                    last_modified,
                }) => {
                    let hash = sha256_hex(&bytes);
                    if previous_meta
                        .as_ref()
                        .map(|meta| meta.sha256 == hash)
                        .unwrap_or(false)
                        && self.ip_catalog.read().is_some()
                    {
                        if let Some(meta) = self.ip_meta.write().as_mut() {
                            meta.source = source.clone();
                            meta.fetched_at = now();
                            meta.etag = etag.or_else(|| meta.etag.clone());
                            meta.last_modified =
                                last_modified.or_else(|| meta.last_modified.clone());
                        }
                        self.persist_ip_meta();
                        let version = self
                            .ip_meta
                            .read()
                            .as_ref()
                            .map(|meta| meta.catalog_version)
                            .unwrap_or(0);
                        return Ok(RefreshReport::up_to_date(
                            "ip",
                            source,
                            version,
                            "remote catalog content is unchanged",
                        ));
                    }

                    let validated = match serde_json::from_slice::<IpCatalogRaw>(&bytes)
                        .context("parsing remote IP catalog")
                        .and_then(|raw| ip::validate(raw, &config))
                    {
                        Ok(validated) => validated,
                        Err(error) => {
                            errors.push(format!("{}: {error:#}", redact_url(&source)));
                            continue;
                        }
                    };
                    let old = self.ip_catalog.read().clone();
                    let cached_domains = self.cache.last_good_domains();
                    let affected =
                        ip::affected_domains(old.as_ref(), &validated, &config, &cached_domains);
                    let version = config.catalog_version.saturating_add(1);
                    let warnings = validated.warnings.clone();

                    atomic_write(&self.paths.catalog_ip_file(), &bytes)?;
                    let meta = CatalogMeta {
                        source: source.clone(),
                        etag,
                        last_modified,
                        fetched_at: now(),
                        sha256: hash,
                        catalog_version: version,
                        warnings: warnings.clone(),
                    };
                    atomic_write_json(&self.paths.catalog_ip_meta_file(), &meta)?;
                    *self.ip_meta.write() = Some(meta);
                    *self.ip_catalog.write() = Some(validated);
                    if let Err(error) = self.config.set_catalog_version(version) {
                        tracing::warn!(error = %error, "failed to persist catalog version");
                    }
                    self.cache.mark_skip_once(affected.iter().cloned());
                    tracing::info!(
                        source = %redact_url(&source),
                        version,
                        domains = affected.len(),
                        "remote IP catalog updated"
                    );
                    let mut sorted: Vec<String> = affected.into_iter().collect();
                    sorted.sort();
                    return Ok(RefreshReport {
                        kind: "ip".to_string(),
                        updated: true,
                        up_to_date: false,
                        source: Some(source),
                        version,
                        affected_domains: sorted,
                        warnings,
                        message: None,
                    });
                }
                Err(error) => {
                    errors.push(format!("{}: {error:#}", redact_url(&source)));
                }
            }
        }
        bail!("all IP catalog sources failed: {}", errors.join("; "))
    }

    pub async fn refresh_doh(&self, force: bool) -> Result<RefreshReport> {
        let _guard = self.refresh_lock.lock().await;
        let config = self.config.snapshot();
        let sources = catalog_sources(&config.catalogs.doh, &config.catalogs.doh_mirrors);
        if sources.is_empty() {
            return Ok(RefreshReport::skipped(
                "doh",
                "no remote DoH catalog source is configured",
            ));
        }
        let timeout = Duration::from_secs(config.catalogs.timeout_secs);
        let signature = match &config.catalogs.signature_public_key {
            Some(key) => Some(Arc::new(
                CatalogSignature::new(key).context("invalid catalog signature public key")?,
            )),
            None => None,
        };
        let mut errors = Vec::new();
        for source in sources {
            let previous_meta = self.doh_meta.read().clone();
            let conditional = previous_meta
                .as_ref()
                .filter(|meta| meta.source == source)
                .map(|meta| (meta.etag.clone(), meta.last_modified.clone()));
            match self
                .fetch_catalog(
                    &source,
                    timeout,
                    force,
                    conditional,
                    signature.as_deref(),
                    &config,
                )
                .await
            {
                Ok(FetchOutcome::NotModified) => {
                    if self.doh_catalog.read().is_some() {
                        if let Some(meta) = self.doh_meta.write().as_mut() {
                            meta.fetched_at = now();
                        }
                        self.persist_doh_meta();
                        let version = self
                            .doh_meta
                            .read()
                            .as_ref()
                            .map(|meta| meta.catalog_version)
                            .unwrap_or(0);
                        return Ok(RefreshReport::up_to_date(
                            "doh",
                            source,
                            version,
                            "remote DoH catalog is unchanged",
                        ));
                    }
                    errors.push(format!(
                        "{}: not modified but no cached catalog",
                        redact_url(&source)
                    ));
                }
                Ok(FetchOutcome::Body {
                    bytes,
                    etag,
                    last_modified,
                }) => {
                    let hash = sha256_hex(&bytes);
                    if previous_meta
                        .as_ref()
                        .map(|meta| meta.sha256 == hash)
                        .unwrap_or(false)
                        && self.doh_catalog.read().is_some()
                    {
                        if let Some(meta) = self.doh_meta.write().as_mut() {
                            meta.source = source.clone();
                            meta.fetched_at = now();
                            meta.etag = etag.or_else(|| meta.etag.clone());
                            meta.last_modified =
                                last_modified.or_else(|| meta.last_modified.clone());
                        }
                        self.persist_doh_meta();
                        let version = self
                            .doh_meta
                            .read()
                            .as_ref()
                            .map(|meta| meta.catalog_version)
                            .unwrap_or(0);
                        return Ok(RefreshReport::up_to_date(
                            "doh",
                            source,
                            version,
                            "remote DoH catalog content is unchanged",
                        ));
                    }
                    let endpoints = match doh::validate(&bytes) {
                        Ok(endpoints) => endpoints,
                        Err(error) => {
                            errors.push(format!("{}: {error:#}", redact_url(&source)));
                            continue;
                        }
                    };
                    let count = endpoints.len();
                    let version = previous_meta
                        .as_ref()
                        .map(|meta| meta.catalog_version.saturating_add(1))
                        .unwrap_or(1);
                    atomic_write(&self.paths.catalog_doh_file(), &bytes)?;
                    let meta = CatalogMeta {
                        source: source.clone(),
                        etag,
                        last_modified,
                        fetched_at: now(),
                        sha256: hash,
                        catalog_version: version,
                        warnings: Vec::new(),
                    };
                    atomic_write_json(&self.paths.catalog_doh_meta_file(), &meta)?;
                    *self.doh_meta.write() = Some(meta);
                    *self.doh_catalog.write() = Some(endpoints);
                    tracing::info!(
                        source = %redact_url(&source),
                        version,
                        count,
                        "remote DoH catalog updated"
                    );
                    return Ok(RefreshReport {
                        kind: "doh".to_string(),
                        updated: true,
                        up_to_date: false,
                        source: Some(source),
                        version,
                        affected_domains: Vec::new(),
                        warnings: Vec::new(),
                        message: None,
                    });
                }
                Err(error) => errors.push(format!("{}: {error:#}", redact_url(&source))),
            }
        }
        bail!("all DoH catalog sources failed: {}", errors.join("; "))
    }

    async fn fetch_catalog(
        &self,
        url: &str,
        timeout: Duration,
        force: bool,
        conditional: Option<(Option<String>, Option<String>)>,
        signature: Option<&CatalogSignature>,
        config: &AppConfig,
    ) -> Result<FetchOutcome> {
        let mut request = self.client.get(url).timeout(timeout);
        if let Some((etag, last_modified)) = conditional {
            if !force {
                if let Some(etag) = etag {
                    request = request.header(reqwest::header::IF_NONE_MATCH, etag);
                }
                if let Some(last_modified) = last_modified {
                    request = request.header(reqwest::header::IF_MODIFIED_SINCE, last_modified);
                }
            }
        }
        let response = request.send().await.context("fetching catalog")?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(FetchOutcome::NotModified);
        }
        if !response.status().is_success() {
            bail!("catalog source returned HTTP {}", response.status());
        }
        if response
            .content_length()
            .map(|len| len as usize > MAX_CATALOG_BYTES)
            .unwrap_or(false)
        {
            bail!("catalog is larger than {MAX_CATALOG_BYTES} bytes");
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let last_modified = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let bytes = response.bytes().await.context("reading catalog body")?;
        if bytes.len() > MAX_CATALOG_BYTES {
            bail!("catalog is larger than {MAX_CATALOG_BYTES} bytes");
        }

        if let Some(verifier) = signature {
            let signature_url = config
                .catalogs
                .signature_url
                .clone()
                .unwrap_or_else(|| default_signature_url(url));
            let signature_bytes = self
                .fetch_signature(&signature_url, timeout)
                .await
                .with_context(|| format!("fetching signature {}", redact_url(&signature_url)))?;
            verifier
                .verify(&bytes, &signature_bytes)
                .context("catalog signature check failed")?;
        }

        Ok(FetchOutcome::Body {
            bytes: bytes.to_vec(),
            etag,
            last_modified,
        })
    }

    async fn fetch_signature(&self, url: &str, timeout: Duration) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(url)
            .timeout(timeout)
            .send()
            .await
            .context("fetching signature")?;
        if !response.status().is_success() {
            bail!("signature source returned HTTP {}", response.status());
        }
        if response
            .content_length()
            .map(|len| len as usize > MAX_SIGNATURE_BYTES)
            .unwrap_or(false)
        {
            bail!("signature is larger than {MAX_SIGNATURE_BYTES} bytes");
        }
        let bytes = response.bytes().await.context("reading signature body")?;
        if bytes.len() > MAX_SIGNATURE_BYTES {
            bail!("signature is larger than {MAX_SIGNATURE_BYTES} bytes");
        }
        Ok(bytes.to_vec())
    }

    fn persist_ip_meta(&self) {
        if let Some(meta) = self.ip_meta.read().as_ref() {
            if let Err(error) = atomic_write_json(&self.paths.catalog_ip_meta_file(), meta) {
                tracing::warn!(error = %error, "failed to persist IP catalog metadata");
            }
        }
    }

    fn persist_doh_meta(&self) {
        if let Some(meta) = self.doh_meta.read().as_ref() {
            if let Err(error) = atomic_write_json(&self.paths.catalog_doh_meta_file(), meta) {
                tracing::warn!(error = %error, "failed to persist DoH catalog metadata");
            }
        }
    }
}

enum FetchOutcome {
    NotModified,
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

fn catalog_sources(primary: &str, mirrors: &[String]) -> Vec<String> {
    let mut sources = Vec::new();
    if !primary.trim().is_empty() {
        sources.push(primary.trim().to_string());
    }
    for mirror in mirrors {
        let mirror = mirror.trim();
        if !mirror.is_empty() && !sources.iter().any(|existing| existing == mirror) {
            sources.push(mirror.to_string());
        }
    }
    sources
}

fn default_signature_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            let path = format!("{}.sig", parsed.path().trim_end_matches('/'));
            parsed.set_path(&path);
            parsed.to_string()
        }
        Err(_) => format!("{url}.sig"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ordering_and_dedupe() {
        let sources = catalog_sources(
            "https://a.example/ips.json",
            &[
                "https://b.example/ips.json".to_string(),
                "https://a.example/ips.json".to_string(),
                " ".to_string(),
            ],
        );
        assert_eq!(
            sources,
            vec![
                "https://a.example/ips.json".to_string(),
                "https://b.example/ips.json".to_string()
            ]
        );
    }

    #[test]
    fn signature_url_appends_suffix() {
        assert_eq!(
            default_signature_url("https://example.com/catalog/ips.json"),
            "https://example.com/catalog/ips.json.sig"
        );
    }
}
