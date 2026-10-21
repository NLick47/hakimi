use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use parking_lot::{Mutex, RwLock};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use serde::Serialize;
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::paths::Paths;
use crate::util::{atomic_write, atomic_write_private, sha1_hex, sha256_hex};

const CA_COMMON_NAME: &str = "hakimi Local CA";
const LEAF_VALIDITY_DAYS: i64 = 7;
const LEAF_ROTATE_HOURS: i64 = 24;

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

struct CaMaterial {
    issuer: Certificate,
    key: KeyPair,
    der: Vec<u8>,
    pem: String,
    fingerprint_sha1: String,
    fingerprint_sha256: String,
    not_before: String,
    not_after: String,
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

        let material = Arc::clone(&self.material.read());
        let config = build_leaf_config(&domain, &material, self.provider.clone())?;
        self.leaves.write().insert(
            domain,
            Arc::new(LeafEntry {
                config: config.clone(),
                created_at: OffsetDateTime::now_utc(),
            }),
        );
        Ok(config)
    }

    pub fn status(&self) -> CaStatus {
        const STATUS_TTL: Duration = Duration::from_secs(3);
        let mut cache = self.status_cache.lock();
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
        if let Some((at, status)) = cache.as_ref() {
            if at.elapsed() < STATUS_TTL {
                tracing::debug!(
                    age_ms = at.elapsed().as_millis() as u64,
                    installed = status.installed,
                    "ca status served from cache"
                );
                return status.clone();
            }
        }
        let previous = cache
            .as_ref()
            .map(|(_, status)| (status.supported, status.installed, status.error.clone()));
        let material = self.material.read();
        let fingerprint = short_fingerprint(&material.fingerprint_sha1);
        let (supported, installed, error) =
            match trust_status(&material.fingerprint_sha1, &self.paths.ca_cert_file()) {
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
            fingerprint_sha1: Some(material.fingerprint_sha1.clone()),
            fingerprint_sha256: Some(material.fingerprint_sha256.clone()),
            cert_path: Some(self.paths.ca_cert_file().display().to_string()),
            not_before: Some(material.not_before.clone()),
            not_after: Some(material.not_after.clone()),
            error,
            note: trust_note(),
        };
        *cache = Some((Instant::now(), status.clone()));
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
        let was_installed = self.status().installed;
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
        let mut status = self.status();
        if should_roll_back(was_installed, result.is_err()) {
            // A cancelled dialog still imports the certificate, so undo the
            // import whether or not the trust setting landed.
            tracing::info!(fingerprint, "install did not complete; removing the imported certificate");
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
            status = self.status();
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
        let _ = self.status();
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
        let status = self.status();
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
        let was_installed = self.status().installed;
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
        Ok(self.status())
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
    sha1.chars().take(12).collect::<String>().to_ascii_uppercase()
}

/// A failed install may still have imported (and re-trusted) the certificate.
/// Rolling back is only correct when the CA was not trusted beforehand; during a
/// repair it was, so leaving it trusted restores the starting point.
fn should_roll_back(was_installed: bool, failed: bool) -> bool {
    failed && !was_installed
}

/// Cap command output before it lands in the log.
fn truncate_for_log(text: &str, max: usize) -> String {
    let one_line = text.trim().replace('\n', " ");
    if one_line.chars().count() <= max {
        return one_line;
    }
    let head: String = one_line.chars().take(max).collect();
    format!("{head}…")
}

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
enum SecurityOutcome {
    Ok,
    Cancelled,
    Failed,
}

/// `security` may exit 0 after the user dismisses the authorization dialog, so
/// the output decides first and the exit status only breaks the tie.
#[cfg(target_os = "macos")]
fn classify_security_output(success: bool, stderr: &str) -> SecurityOutcome {
    if stderr.to_ascii_lowercase().contains("cancel") {
        SecurityOutcome::Cancelled
    } else if success {
        SecurityOutcome::Ok
    } else {
        SecurityOutcome::Failed
    }
}

fn build_leaf_config(
    domain: &str,
    material: &CaMaterial,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<ServerConfig>> {
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .with_context(|| format!("building leaf parameters for `{domain}`"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, domain);
    let now = OffsetDateTime::now_utc();
    params.not_before = now - TimeDuration::hours(1);
    params.not_after = now + TimeDuration::days(LEAF_VALIDITY_DAYS);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;

    let leaf_key = KeyPair::generate().context("generating leaf key")?;
    let leaf = params
        .signed_by(&leaf_key, &material.issuer, &material.key)
        .context("signing leaf certificate")?;

    let chain = vec![
        leaf.der().clone(),
        CertificateDer::from(material.der.clone()),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("building rustls server config")?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("installing local leaf certificate")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn generate_and_save(paths: &Paths) -> Result<CaMaterial> {
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = now - TimeDuration::days(1);
    params.not_after = now + TimeDuration::days(3650);
    params.use_authority_key_identifier_extension = true;
    let key = KeyPair::generate().context("generating CA key")?;
    let cert = params.self_signed(&key).context("self-signing local CA")?;

    let material = material_from_parts(cert, key);
    persist_material(paths, &material)?;
    Ok(material)
}

fn load_material(cert_path: &std::path::Path, key_path: &std::path::Path) -> Result<CaMaterial> {
    let pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?;
    let key_bytes =
        std::fs::read(key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let key_pem = decode_key_file(&key_bytes)?;
    let key = KeyPair::from_pem(&key_pem)
        .with_context(|| format!("parsing CA key {}", key_path.display()))?;
    let params = CertificateParams::from_ca_cert_pem(&pem)
        .with_context(|| format!("parsing CA certificate {}", cert_path.display()))?;
    let not_before = params.not_before.to_string();
    let not_after = params.not_after.to_string();
    // `signed_by` needs a Certificate for issuer parameters. Re-signing with the same key and
    // loaded parameters reproduces the issuer DN / key identifier used by the installed CA.
    let issuer = params
        .self_signed(&key)
        .context("reconstructing CA issuer parameters")?;
    let original_der = pem_to_der(&pem)?;
    Ok(CaMaterial {
        issuer,
        key,
        fingerprint_sha1: sha1_hex(&original_der),
        fingerprint_sha256: sha256_hex(&original_der),
        der: original_der,
        pem,
        not_before,
        not_after,
    })
}

fn material_from_parts(issuer: Certificate, key: KeyPair) -> CaMaterial {
    let der = issuer.der().to_vec();
    let pem = issuer.pem();
    let not_before = issuer.params().not_before.to_string();
    let not_after = issuer.params().not_after.to_string();
    CaMaterial {
        fingerprint_sha1: sha1_hex(&der),
        fingerprint_sha256: sha256_hex(&der),
        der,
        pem,
        not_before,
        not_after,
        issuer,
        key,
    }
}

fn persist_material(paths: &Paths, material: &CaMaterial) -> Result<()> {
    atomic_write(&paths.ca_cert_file(), material.pem.as_bytes())?;
    let key_bytes = encode_key_file(material.key.serialize_pem().as_bytes())?;
    atomic_write_private(&paths.ca_key_file(), &key_bytes)?;
    Ok(())
}

const DPAPI_MAGIC: &[u8] = b"HAKIMI-DPAPI";

fn encode_key_file(pem: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        match dpapi_protect(pem) {
            Ok(protected) => {
                let mut out = Vec::with_capacity(DPAPI_MAGIC.len() + protected.len());
                out.extend_from_slice(DPAPI_MAGIC);
                out.extend_from_slice(&protected);
                return Ok(out);
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "DPAPI key protection failed; storing the CA key as a 0600-equivalent PEM instead"
                );
            }
        }
    }
    Ok(pem.to_vec())
}

fn decode_key_file(bytes: &[u8]) -> Result<String> {
    #[cfg(windows)]
    {
        if let Some(protected) = bytes.strip_prefix(DPAPI_MAGIC) {
            let plain = dpapi_unprotect(protected).context("unprotecting the CA key with DPAPI")?;
            return String::from_utf8(plain).context("CA key is not UTF-8 after DPAPI");
        }
    }
    String::from_utf8(bytes.to_vec()).context("CA key file is not valid UTF-8")
}

#[cfg(windows)]
fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        );
        if ok == 0 {
            bail!("CryptProtectData failed");
        }
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as *mut c_void);
        Ok(bytes)
    }
}

#[cfg(windows)]
fn dpapi_unprotect(protected: &[u8]) -> Result<Vec<u8>> {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: protected.len() as u32,
            pbData: protected.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        );
        if ok == 0 {
            bail!("CryptUnprotectData failed");
        }
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as *mut c_void);
        Ok(bytes)
    }
}

pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut in_cert = false;
    let mut base64_text = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
        } else if line == "-----END CERTIFICATE-----" {
            break;
        } else if in_cert {
            base64_text.push_str(line);
        }
    }
    if base64_text.is_empty() {
        bail!("PEM does not contain a certificate");
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(base64_text)
        .context("decoding PEM certificate")
}

// ---------------------------------------------------------------------------
// Trust store integration
// ---------------------------------------------------------------------------

fn trust_supported() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

fn trust_note() -> Option<String> {
    #[cfg(windows)]
    {
        Some(
            "Installed into the current user's Root store; Chromium/Edge/Windows use it, Firefox may use its own store."
                .to_string(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        Some(
            "Installed into the login keychain; browsers using the system trust store honor it."
                .to_string(),
        )
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Some("Automatic CA installation is only implemented on Windows and macOS.".to_string())
    }
}

#[cfg(windows)]
fn trust_status(sha1_hex: &str, _cert_path: &Path) -> Result<(bool, bool, Option<String>)> {
    let hash = hex::decode(sha1_hex).context("decoding SHA-1 fingerprint")?;
    let found = unsafe { win_store_find(&hash)? };
    Ok((true, found, None))
}

#[cfg(windows)]
unsafe fn win_store_find(hash: &[u8]) -> Result<bool> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertOpenStore,
        CERT_FIND_HASH, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    #[repr(C)]
    struct CryptHashBlob {
        cb_data: u32,
        pb_data: *const u8,
    }

    let store_name: Vec<u16> = "ROOT\0".encode_utf16().collect();
    let store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        store_name.as_ptr() as *const c_void,
    );
    if store.is_null() {
        bail!("unable to open the current user's Root certificate store");
    }
    let blob = CryptHashBlob {
        cb_data: hash.len() as u32,
        pb_data: hash.as_ptr(),
    };
    let context = CertFindCertificateInStore(
        store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        &blob as *const _ as *const c_void,
        std::ptr::null(),
    );
    if !context.is_null() {
        CertFreeCertificateContext(context);
    }
    CertCloseStore(store, 0);
    Ok(!context.is_null())
}

#[cfg(windows)]
fn install_cert(der: &[u8], _pem_path: &Path) -> Result<()> {
    unsafe { win_store_add(der) }
}

#[cfg(windows)]
unsafe fn win_store_add(der: &[u8]) -> Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Cryptography::{
        CertAddEncodedCertificateToStore, CertCloseStore, CertOpenStore,
        CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
        X509_ASN_ENCODING,
    };
    let store_name: Vec<u16> = "ROOT\0".encode_utf16().collect();
    let store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        store_name.as_ptr() as *const c_void,
    );
    if store.is_null() {
        bail!("unable to open the current user's Root certificate store");
    }
    let added = CertAddEncodedCertificateToStore(
        store,
        X509_ASN_ENCODING,
        der.as_ptr(),
        der.len() as u32,
        CERT_STORE_ADD_REPLACE_EXISTING,
        std::ptr::null_mut(),
    );
    CertCloseStore(store, 0);
    if added == 0 {
        bail!("Windows refused to add the CA certificate to the Root store");
    }
    Ok(())
}

#[cfg(windows)]
fn uninstall_by_sha1(sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    let hash = hex::decode(sha1_hex).context("decoding SHA-1 fingerprint")?;
    unsafe { win_store_delete(&hash) }
}

#[cfg(windows)]
unsafe fn win_store_delete(hash: &[u8]) -> Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertDeleteCertificateFromStore, CertFindCertificateInStore, CertOpenStore,
        CERT_FIND_HASH, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    #[repr(C)]
    struct CryptHashBlob {
        cb_data: u32,
        pb_data: *const u8,
    }

    let store_name: Vec<u16> = "ROOT\0".encode_utf16().collect();
    let store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        store_name.as_ptr() as *const c_void,
    );
    if store.is_null() {
        bail!("unable to open the current user's Root certificate store");
    }
    let blob = CryptHashBlob {
        cb_data: hash.len() as u32,
        pb_data: hash.as_ptr(),
    };
    let context = CertFindCertificateInStore(
        store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        &blob as *const _ as *const c_void,
        std::ptr::null(),
    );
    if context.is_null() {
        CertCloseStore(store, 0);
        bail!("CA certificate is not installed");
    }
    let deleted = CertDeleteCertificateFromStore(context);
    CertCloseStore(store, 0);
    if deleted == 0 {
        bail!("Windows refused to remove the CA certificate");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
fn keychain_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{home}/Library/Keychains/login.keychain-db")
}

#[cfg(target_os = "macos")]
fn trust_status(sha1_hex: &str, cert_path: &Path) -> Result<(bool, bool, Option<String>)> {
    let keychain = keychain_path();
    let output = Command::new("security")
        .args([
            "find-certificate",
            "-a",
            "-Z",
            "-c",
            CA_COMMON_NAME,
            &keychain,
        ])
        .output()
        .context("running security find-certificate")?;
    let text = String::from_utf8_lossy(&output.stdout).to_uppercase();
    let needle = sha1_hex.to_uppercase();
    let present = text.contains(&needle);
    let listed = text.matches("SHA-1 HASH:").count();
    tracing::debug!(
        keychain = %keychain,
        exit = output.status.code().unwrap_or(-1),
        certificates_with_our_cn = listed,
        present,
        "ca keychain lookup"
    );
    if !output.status.success() {
        tracing::warn!(
            keychain = %keychain,
            stderr = %truncate_for_log(&String::from_utf8_lossy(&output.stderr), 300),
            "security find-certificate failed; treating the CA as not installed"
        );
    }
    if !present {
        return Ok((true, false, None));
    }
    // The certificate being in the keychain is not trust: a cancelled trust
    // dialog leaves it imported but untrusted. Verify what the system actually
    // believes before reporting "installed and trusted".
    let verify = Command::new("security")
        .args(["verify-cert", "-c", &cert_path.display().to_string(), "-p", "ssl"])
        .output()
        .context("running security verify-cert")?;
    if verify.status.success() {
        tracing::debug!("ca verify-cert passed; reporting trusted");
        Ok((true, true, None))
    } else {
        tracing::info!(
            exit = verify.status.code().unwrap_or(-1),
            stderr = %truncate_for_log(&String::from_utf8_lossy(&verify.stderr), 300),
            "ca is imported but not trusted"
        );
        // Keep it short: the UI only shows one status line here.
        Ok((true, false, Some("已导入，但尚未受信任".into())))
    }
}

#[cfg(target_os = "macos")]
fn install_cert(_der: &[u8], pem_path: &Path) -> Result<()> {
    let keychain = keychain_path();
    let pem = pem_path.display().to_string();
    let output = Command::new("security")
        .args(["add-trusted-cert", "-r", "trustRoot", "-k", &keychain, &pem])
        .output()
        .context("running security add-trusted-cert")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let outcome = classify_security_output(output.status.success(), &stderr);
    tracing::info!(
        exit = output.status.code().unwrap_or(-1),
        outcome = ?outcome,
        stderr = %truncate_for_log(&stderr, 400),
        "security add-trusted-cert finished"
    );
    // `security` can exit 0 after the user dismisses the authorization dialog,
    // and an already-trusted copy would still verify — so a cancellation has to
    // be detected from the output, not from the exit status alone.
    match outcome {
        SecurityOutcome::Ok => {}
        SecurityOutcome::Cancelled => bail!("user canceled the authorization dialog"),
        SecurityOutcome::Failed => {
            bail!("security add-trusted-cert failed: {}", stderr.trim())
        }
    }
    // The trust dialog can be cancelled: the certificate imports but the trust
    // setting never lands. Only report success when the system really trusts it.
    // Trust settings can take a moment to propagate, so retry briefly instead
    // of rolling back an install that actually worked.
    const VERIFY_ATTEMPTS: u32 = 5;
    let mut stderr = String::new();
    for attempt in 1..=VERIFY_ATTEMPTS {
        let verify = Command::new("security")
            .args(["verify-cert", "-c", &pem, "-p", "ssl"])
            .output()
            .context("running security verify-cert")?;
        stderr = String::from_utf8_lossy(&verify.stderr).to_string();
        if verify.status.success() {
            tracing::info!(attempt, "security verify-cert after install: trusted");
            return Ok(());
        }
        tracing::debug!(
            attempt,
            stderr = %truncate_for_log(&stderr, 200),
            "security verify-cert after install: not trusted yet"
        );
        if attempt < VERIFY_ATTEMPTS {
            std::thread::sleep(Duration::from_millis(150));
        }
    }
    tracing::info!(
        stderr = %truncate_for_log(&stderr, 300),
        "security verify-cert after install: still untrusted"
    );
    bail!("the certificate was imported but the trust dialog was not confirmed; run install again")
}

#[cfg(target_os = "macos")]
fn uninstall_by_sha1(sha1_hex: &str, remove_trust: bool) -> Result<()> {
    let keychain = keychain_path();
    let thumbprint = sha1_hex.to_uppercase();
    // `-t` also drops the user trust settings, but macOS asks for authorization
    // again — fine for an explicit "remove", wrong for a silent rollback after
    // the user already cancelled one dialog.
    let mut args = vec!["delete-certificate"];
    if remove_trust {
        args.push("-t");
    }
    args.extend(["-Z", thumbprint.as_str(), keychain.as_str()]);
    let output = Command::new("security")
        .args(&args)
        .output()
        .context("running security delete-certificate")?;
    tracing::info!(
        thumbprint = %thumbprint,
        exit = output.status.code().unwrap_or(-1),
        stderr = %truncate_for_log(&String::from_utf8_lossy(&output.stderr), 300),
        "security delete-certificate finished"
    );
    if !output.status.success() {
        bail!(
            "security delete-certificate failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn trust_status(_sha1_hex: &str, _cert_path: &Path) -> Result<(bool, bool, Option<String>)> {
    Ok((
        false,
        false,
        Some("automatic CA trust is not supported on this platform".into()),
    ))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn install_cert(_der: &[u8], _pem_path: &Path) -> Result<()> {
    bail!("automatic CA installation is only implemented on Windows and macOS")
}

#[cfg(not(any(windows, target_os = "macos")))]
fn uninstall_by_sha1(_sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    bail!("automatic CA removal is only implemented on Windows and macOS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_reloads_ca() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let ca = CertificateAuthority::load_or_create(&paths).unwrap();
        let first = ca.fingerprint_sha1();
        assert!(paths.ca_cert_file().exists());
        assert!(paths.ca_key_file().exists());
        drop(ca);

        let ca = CertificateAuthority::load_or_create(&paths).unwrap();
        assert_eq!(ca.fingerprint_sha1(), first);
        let status = ca.status();
        assert!(status.present);
        assert_eq!(status.fingerprint_sha1.as_deref(), Some(first.as_str()));
    }

    #[test]
    fn leaf_config_covers_real_domain() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let ca = CertificateAuthority::load_or_create(&paths).unwrap();
        let config = ca.server_config("github.com").unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // Cached leaf is reused.
        let config2 = ca.server_config("github.com").unwrap();
        assert!(Arc::ptr_eq(&config, &config2));
    }

    #[test]
    fn status_reports_the_pre_operation_state_while_busy() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let ca = CertificateAuthority::load_or_create(&paths).unwrap();

        // Pretend the CA was trusted before the operation. A real probe on this
        // temp CA would say "not installed", so seeing `true` proves the store
        // was not queried mid-operation.
        let mut cached = ca.status();
        cached.installed = true;
        *ca.status_cache.lock() = Some((Instant::now(), cached));

        {
            let _guard = ca.begin_operation();
            assert!(ca.status().installed);
        }

        // Without a cache it still refuses to probe and reports untrusted.
        *ca.status_cache.lock() = None;
        {
            let _guard = ca.begin_operation();
            assert!(!ca.status().installed);
        }
    }

    #[test]
    fn a_failed_install_only_rolls_back_a_new_certificate() {
        // The dialog may have imported it, trusted or not: remove it.
        assert!(should_roll_back(false, true));
        // A repair starts from "trusted": removing would be worse than leaving.
        assert!(!should_roll_back(true, true));
        // Successful installs stay.
        assert!(!should_roll_back(false, false));
    }

    #[test]
    fn fingerprints_are_shortened_for_logs() {
        assert_eq!(
            short_fingerprint("17655f91461cb5436e520be1a76b9b5eff83c83f"),
            "17655F91461C"
        );
        assert_eq!(short_fingerprint("abc"), "ABC");
    }

    #[test]
    fn long_output_is_truncated_for_logs() {
        assert_eq!(truncate_for_log("  a\nb  ", 10), "a b");
        let truncated = truncate_for_log("0123456789abcdef", 8);
        assert_eq!(truncated, "01234567…");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cancellation_is_detected_even_when_security_exits_zero() {
        use SecurityOutcome::*;
        assert_eq!(
            classify_security_output(true, "User canceled the operation."),
            Cancelled
        );
        assert_eq!(
            classify_security_output(false, "security: authorization was cancelled"),
            Cancelled
        );
        assert_eq!(classify_security_output(false, "boom"), Failed);
        assert_eq!(classify_security_output(true, ""), Ok);
    }

    #[test]
    fn pem_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let ca = CertificateAuthority::load_or_create(&paths).unwrap();
        let der = ca.ca_der();
        let pem = ca.ca_pem();
        assert_eq!(pem_to_der(&pem).unwrap(), der);
    }
}
