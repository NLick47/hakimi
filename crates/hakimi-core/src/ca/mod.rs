//! Local certificate authority used for MITM of enabled groups.
//!
//! The lifecycle and trust-cache state machine stays here. Key/certificate
//! material and platform trust-store commands live in submodules so each can be
//! tested and audited on its own.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use rustls::ServerConfig;
use serde::Serialize;
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::paths::Paths;

use self::material::{build_leaf_config, generate_and_save, load_material, CaMaterial};
use self::trust::{install_cert, trust_note, trust_status, trust_supported, uninstall_by_sha1};

mod material;
mod trust;

#[cfg(test)]
mod tests;

pub use material::pem_to_der;

const CA_COMMON_NAME: &str = "hakimi Local CA";
const LEAF_ROTATE_HOURS: i64 = 24;
/// Wildcard groups can expose an unbounded set of concrete hosts, so the
/// per-domain leaf cache must not grow forever. Certificate generation is
/// cheap enough to repeat; 512 covers the active set of a normal browser.
const LEAF_CACHE_MAX: usize = 512;
const LEAF_CACHE_PRUNE_TO: usize = LEAF_CACHE_MAX * 3 / 4;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaStatus {
    pub present: bool,
    pub supported: bool,
    pub installed: bool,
    pub subject: Option<String>,
    pub fingerprint_sha1: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub cert_path: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub error: Option<String>,
    pub note: Option<String>,
}

struct LeafEntry {
    config: Arc<ServerConfig>,
    created_at: OffsetDateTime,
}

/// Local CA used only for enabled-group domains. Leaf certificates are generated on demand,
/// cached for a day, and always carry the real domain in SAN; certificate verification is never
/// disabled.
pub struct CertificateAuthority {
    paths: Paths,
    provider: Arc<rustls::crypto::CryptoProvider>,
    material: RwLock<Arc<CaMaterial>>,
    leaves: RwLock<HashMap<String, Arc<LeafEntry>>>,
    // Trust status costs a `security find-certificate` subprocess on macOS;
    // it only changes when the user (de)installs, so cache it briefly.
    status_cache: Mutex<Option<(Instant, CaStatus)>>,
    // A subprocess must never run under `status_cache` (that would block every
    // CONNECT and UI probe behind Keychain). Concurrent callers reuse the last
    // snapshot instead of piling up more `security` processes; operations that
    // need an authoritative pre/post state wait for this lock instead.
    probe_lock: Mutex<()>,
    // `security add-trusted-cert` imports the certificate before asking for
    // authorization. Probing the store while an operation is in flight would
    // see that half-applied state and report "trusted" while the password
    // dialog is still on screen.
    busy: AtomicBool,
}

impl CertificateAuthority {
    pub fn load_or_create(paths: &Paths) -> Result<Arc<Self>> {
        paths.ensure()?;
        std::fs::create_dir_all(paths.ca_dir())?;
        let cert_path = paths.ca_cert_file();
        let key_path = paths.ca_key_file();
        let material = if cert_path.exists() && key_path.exists() {
            load_material(&cert_path, &key_path)?
        } else {
            if cert_path.exists() || key_path.exists() {
                tracing::warn!("incomplete CA files found; generating a new local CA");
            }
            generate_and_save(paths)?
        };
        Ok(Arc::new(Self {
            paths: paths.clone(),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            material: RwLock::new(Arc::new(material)),
            leaves: RwLock::new(HashMap::new()),
            status_cache: Mutex::new(None),
            probe_lock: Mutex::new(()),
            busy: AtomicBool::new(false),
        }))
    }

    pub fn ca_pem(&self) -> String {
        self.material.read().pem.clone()
    }

    pub fn ca_der(&self) -> Vec<u8> {
        self.material.read().der.clone()
    }

    pub fn fingerprint_sha1(&self) -> String {
        self.material.read().fingerprint_sha1.clone()
    }

    pub fn ca_path(&self) -> PathBuf {
        self.paths.ca_cert_file()
    }

    /// Build (or reuse) a rustls server config with a locally signed leaf certificate.
    pub fn server_config(&self, domain: &str) -> Result<Arc<ServerConfig>> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if let Some(entry) = self.leaves.read().get(&domain).cloned() {
            if OffsetDateTime::now_utc() - entry.created_at < TimeDuration::hours(LEAF_ROTATE_HOURS)
            {
                return Ok(entry.config.clone());
            }
        }

        // Hold the CA material while building and inserting the leaf. Otherwise
        // `regenerate` could swap the CA and clear the cache between those two
        // steps, leaving a leaf signed by the retired CA in the fresh cache.
        let material = self.material.read();
        let config = build_leaf_config(&domain, &material, self.provider.clone())?;
        let mut leaves = self.leaves.write();
        leaves.insert(
            domain,
            Arc::new(LeafEntry {
                config: config.clone(),
                created_at: OffsetDateTime::now_utc(),
            }),
        );
        if leaves.len() > LEAF_CACHE_MAX {
            prune_leaves(&mut leaves, LEAF_CACHE_PRUNE_TO);
        }
        Ok(config)
    }

    pub fn status(&self) -> CaStatus {
        const STATUS_TTL: Duration = Duration::from_secs(10);
        // Read the snapshot and release the lock before doing anything slow. In
        // particular, never hold it while `security(1)` runs: every CONNECT and
        // every UI tick would otherwise queue behind a Keychain subprocess.
        let cached = {
            let cache = self.status_cache.lock();
            if self.busy.load(Ordering::SeqCst) {
                // The store is mid-change: answer with the state from before the
                // operation instead of the half-applied one.
                if let Some((_, status)) = cache.as_ref() {
                    tracing::debug!(
                        installed = status.installed,
                        "ca status asked during an operation; using the previous state"
                    );
                    return status.clone();
                }
                return self.unprobed_status(false);
            }
            match cache.as_ref() {
                Some((at, status)) if at.elapsed() < STATUS_TTL => {
                    tracing::debug!(
                        age_ms = at.elapsed().as_millis() as u64,
                        installed = status.installed,
                        "ca status served from cache"
                    );
                    return status.clone();
                }
                Some((_, status)) => Some(status.clone()),
                None => None,
            }
        };

        // One probe at a time. A second caller gets the previous snapshot
        // immediately rather than waiting for the Keychain or spawning another
        // `security` process.
        let Some(_probe) = self.probe_lock.try_lock() else {
            return cached.unwrap_or_else(|| self.unprobed_status(false));
        };
        self.probe_and_cache(cached)
    }

    /// Authoritative status for CA operations and their result reporting. Waits
    /// for any concurrent background probe, then performs a fresh one.
    fn status_now(&self) -> CaStatus {
        let _probe = self.probe_lock.lock();
        let cached = self
            .status_cache
            .lock()
            .as_ref()
            .map(|(_, status)| status.clone());
        self.probe_and_cache(cached)
    }

    /// Probe the trust store and update the snapshot. Callers must hold
    /// `probe_lock`; `cached` is the previous snapshot used only for logging.
    fn probe_and_cache(&self, cached: Option<CaStatus>) -> CaStatus {
        let (fingerprint_sha1, fingerprint_sha256, not_before, not_after) = {
            let material = self.material.read();
            (
                material.fingerprint_sha1.clone(),
                material.fingerprint_sha256.clone(),
                material.not_before.clone(),
                material.not_after.clone(),
            )
        };
        let fingerprint = short_fingerprint(&fingerprint_sha1);
        let (supported, installed, error) =
            match trust_status(&fingerprint_sha1, &self.paths.ca_cert_file()) {
                Ok(outcome) => outcome,
                Err(error) => {
                    tracing::warn!(
                        fingerprint,
                        error = %format!("{error:#}"),
                        "ca trust probe failed; reporting untrusted"
                    );
                    (trust_supported(), false, Some(format!("{error:#}")))
                }
            };
        // The UI probes every second; only a change is worth an INFO line.
        let previous = cached
            .as_ref()
            .map(|status| (status.supported, status.installed, status.error.clone()));
        let signature = (supported, installed, error.clone());
        if previous.as_ref() == Some(&signature) {
            tracing::debug!(fingerprint, installed, "ca status unchanged");
        } else {
            tracing::info!(
                fingerprint,
                supported,
                installed,
                error = error.as_deref().unwrap_or(""),
                "ca status changed"
            );
        }
        let status = CaStatus {
            present: true,
            supported,
            installed,
            subject: Some(format!("CN={CA_COMMON_NAME}")),
            fingerprint_sha1: Some(fingerprint_sha1),
            fingerprint_sha256: Some(fingerprint_sha256),
            cert_path: Some(self.paths.ca_cert_file().display().to_string()),
            not_before: Some(not_before),
            not_after: Some(not_after),
            error,
            note: trust_note(),
        };
        *self.status_cache.lock() = Some((Instant::now(), status.clone()));
        status
    }

    /// Status without touching the store, for the rare case where one is asked
    /// for mid-operation and no previous answer is cached.
    fn unprobed_status(&self, installed: bool) -> CaStatus {
        let material = self.material.read();
        CaStatus {
            present: true,
            supported: trust_supported(),
            installed,
            subject: Some(format!("CN={CA_COMMON_NAME}")),
            fingerprint_sha1: Some(material.fingerprint_sha1.clone()),
            fingerprint_sha256: Some(material.fingerprint_sha256.clone()),
            cert_path: Some(self.paths.ca_cert_file().display().to_string()),
            not_before: Some(material.not_before.clone()),
            not_after: Some(material.not_after.clone()),
            error: None,
            note: trust_note(),
        }
    }

    /// Marks the trust store as being modified for as long as the guard lives.
    fn begin_operation(&self) -> OperationGuard<'_> {
        self.busy.store(true, Ordering::SeqCst);
        OperationGuard { busy: &self.busy }
    }

    /// Install the CA into the current user's trust store.
    pub fn install(&self) -> Result<CaStatus> {
        *self.status_cache.lock() = None;
        let was_installed = self.status_now().installed;
        self.install_with_rollback(was_installed)
    }

    /// Install the CA. `was_installed` is the trust state before the whole
    /// action (for [`Self::repair`] that means before its uninstall step).
    ///
    /// `security add-trusted-cert` imports the certificate *before* it asks for
    /// authorization, and trust settings survive `delete-certificate`; so a
    /// cancelled dialog can leave a previously-trusted certificate trusted
    /// again. When the CA was not trusted before the action, a failed install
    /// rolls the import back instead of silently reporting success.
    fn install_with_rollback(&self, was_installed: bool) -> Result<CaStatus> {
        let (der, fingerprint, fingerprint_sha1) = {
            let material = self.material.read();
            (
                material.der.clone(),
                short_fingerprint(&material.fingerprint_sha1),
                material.fingerprint_sha1.clone(),
            )
        };
        tracing::info!(fingerprint, was_installed, "ca install starting");
        let result = {
            let _guard = self.begin_operation();
            install_cert(&der, &self.paths.ca_cert_file())
        };
        // The pre-operation cache is stale now; the next status re-reads the
        // store. A failed or cancelled install must never be reported through
        // a leftover "installed" entry.
        *self.status_cache.lock() = None;
        match &result {
            Ok(()) => tracing::info!(fingerprint, "ca install command succeeded"),
            Err(error) => {
                tracing::warn!(fingerprint, error = %format!("{error:#}"), "ca install failed")
            }
        }
        let mut status = self.status_now();
        if should_roll_back(was_installed, result.is_err()) {
            // A cancelled dialog still imports the certificate, so undo the
            // import whether or not the trust setting landed.
            tracing::info!(
                fingerprint,
                "install did not complete; removing the imported certificate"
            );
            // Silent: the user just cancelled a dialog, do not ask again.
            let rollback = {
                let _guard = self.begin_operation();
                uninstall_by_sha1(&fingerprint_sha1, false)
            };
            match rollback {
                Ok(()) => tracing::info!(fingerprint, "imported certificate rolled back"),
                Err(error) => tracing::debug!(
                    fingerprint,
                    error = %format!("{error:#}"),
                    "nothing to roll back"
                ),
            }
            *self.status_cache.lock() = None;
            status = self.status_now();
        }
        tracing::info!(
            fingerprint,
            installed = status.installed,
            error = status.error.as_deref().unwrap_or(""),
            ok = result.is_ok(),
            "ca install finished"
        );
        result?;
        Ok(status)
    }

    pub fn uninstall(&self) -> Result<CaStatus> {
        let sha1 = self.material.read().fingerprint_sha1.clone();
        let fingerprint = short_fingerprint(&sha1);
        tracing::info!(fingerprint, "ca uninstall starting");
        *self.status_cache.lock() = None;
        // Fill the cache with the pre-operation state for mid-flight queries.
        let _ = self.status_now();
        let result = {
            let _guard = self.begin_operation();
            // Explicit removal should drop the trust settings as well.
            uninstall_by_sha1(&sha1, true)
        };
        *self.status_cache.lock() = None;
        match &result {
            Ok(()) => tracing::info!(fingerprint, "ca uninstall command succeeded"),
            Err(error) => {
                tracing::warn!(fingerprint, error = %format!("{error:#}"), "ca uninstall failed")
            }
        }
        let status = self.status_now();
        tracing::info!(
            fingerprint,
            installed = status.installed,
            ok = result.is_ok(),
            "ca uninstall finished"
        );
        result?;
        Ok(status)
    }

    pub fn repair(&self) -> Result<CaStatus> {
        let sha1 = self.material.read().fingerprint_sha1.clone();
        tracing::info!(fingerprint = short_fingerprint(&sha1), "ca repair starting");
        *self.status_cache.lock() = None;
        // A repair that gets cancelled should end where it started: if the CA
        // was trusted before, the re-imported copy may stay trusted.
        let was_installed = self.status_now().installed;
        let removed = {
            let _guard = self.begin_operation();
            // The following install re-adds trust; no need for a second prompt.
            uninstall_by_sha1(&sha1, false)
        };
        if let Err(error) = removed {
            // Not fatal: a repair on a never-installed CA lands here.
            tracing::info!(
                fingerprint = short_fingerprint(&sha1),
                error = %format!("{error:#}"),
                "ca repair could not remove the old certificate; installing anyway"
            );
        }
        self.install_with_rollback(was_installed)
    }

    /// Create a new CA, replacing the current files (old files are kept as `.bak`). The CA must
    /// be reinstalled afterwards; callers should surface that in the UI.
    pub fn regenerate(&self) -> Result<CaStatus> {
        let cert_path = self.paths.ca_cert_file();
        let key_path = self.paths.ca_key_file();
        for path in [&cert_path, &key_path] {
            if path.exists() {
                let _ = std::fs::rename(path, path.with_extension("bak"));
            }
        }
        let material = generate_and_save(&self.paths)?;
        *self.material.write() = Arc::new(material);
        self.leaves.write().clear();
        // The cached trust snapshot describes the old certificate; the new one
        // has not been imported anywhere yet.
        *self.status_cache.lock() = None;
        Ok(self.status_now())
    }
}

/// Bound the leaf cache: drop expired certificates first, then the oldest
/// entries until `target` remain.
fn prune_leaves(leaves: &mut HashMap<String, Arc<LeafEntry>>, target: usize) {
    let now = OffsetDateTime::now_utc();
    let rotate = TimeDuration::hours(LEAF_ROTATE_HOURS);
    leaves.retain(|_, entry| now - entry.created_at < rotate);
    if leaves.len() <= target {
        return;
    }
    let mut ages: Vec<(String, OffsetDateTime)> = leaves
        .iter()
        .map(|(domain, entry)| (domain.clone(), entry.created_at))
        .collect();
    ages.sort_by_key(|(_, created_at)| *created_at);
    let excess = leaves.len() - target;
    for (domain, _) in ages.into_iter().take(excess) {
        leaves.remove(&domain);
    }
}

/// Clears [`CertificateAuthority::busy`] however the operation ends.
struct OperationGuard<'a> {
    busy: &'a AtomicBool,
}

impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        self.busy.store(false, Ordering::SeqCst);
    }
}

/// First 12 hex chars of a SHA-1, enough to tell certificates apart in logs
/// without dumping a full fingerprint on every line.
fn short_fingerprint(sha1: &str) -> String {
    sha1.chars()
        .take(12)
        .collect::<String>()
        .to_ascii_uppercase()
}

/// A failed install may still have imported (and re-trusted) the certificate.
/// Rolling back is only correct when the CA was not trusted beforehand; during a
/// repair it was, so leaving it trusted restores the starting point.
fn should_roll_back(was_installed: bool, failed: bool) -> bool {
    failed && !was_installed
}
