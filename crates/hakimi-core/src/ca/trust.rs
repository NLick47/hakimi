use std::path::Path;

use anyhow::{bail, Context, Result};

#[cfg(target_os = "macos")]
use super::CA_COMMON_NAME;
#[cfg(target_os = "macos")]
use std::time::Duration;

/// Cap command output before it lands in the log.
#[cfg(any(target_os = "macos", test))]
pub(super) fn truncate_for_log(text: &str, max: usize) -> String {
    let one_line = text.trim().replace('\n', " ");
    if one_line.chars().count() <= max {
        return one_line;
    }
    let head: String = one_line.chars().take(max).collect();
    format!("{head}…")
}

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SecurityOutcome {
    Ok,
    Cancelled,
    Failed,
}

/// `security` may exit 0 after the user dismisses the authorization dialog, so
/// the output decides first and the exit status only breaks the tie.
#[cfg(target_os = "macos")]
pub(super) fn classify_security_output(success: bool, stderr: &str) -> SecurityOutcome {
    if stderr.to_ascii_lowercase().contains("cancel") {
        SecurityOutcome::Cancelled
    } else if success {
        SecurityOutcome::Ok
    } else {
        SecurityOutcome::Failed
    }
}

// ---------------------------------------------------------------------------
// Trust store integration
// ---------------------------------------------------------------------------

pub(super) fn trust_supported() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

pub(super) fn trust_note() -> Option<String> {
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
pub(super) fn trust_status(
    sha1_hex: &str,
    _cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
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
pub(super) fn install_cert(der: &[u8], _pem_path: &Path) -> Result<()> {
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
pub(super) fn uninstall_by_sha1(sha1_hex: &str, _remove_trust: bool) -> Result<()> {
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
pub(super) fn trust_status(
    sha1_hex: &str,
    cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
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
        .args([
            "verify-cert",
            "-c",
            &cert_path.display().to_string(),
            "-p",
            "ssl",
        ])
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
pub(super) fn install_cert(_der: &[u8], pem_path: &Path) -> Result<()> {
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
pub(super) fn uninstall_by_sha1(sha1_hex: &str, remove_trust: bool) -> Result<()> {
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
pub(super) fn trust_status(
    _sha1_hex: &str,
    _cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    Ok((
        false,
        false,
        Some("automatic CA trust is not supported on this platform".into()),
    ))
}

#[cfg(not(any(windows, target_os = "macos")))]
pub(super) fn install_cert(_der: &[u8], _pem_path: &Path) -> Result<()> {
    bail!("automatic CA installation is only implemented on Windows and macOS")
}

#[cfg(not(any(windows, target_os = "macos")))]
pub(super) fn uninstall_by_sha1(_sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    bail!("automatic CA removal is only implemented on Windows and macOS")
}
