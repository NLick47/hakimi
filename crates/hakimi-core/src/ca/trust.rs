use std::path::Path;

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
use anyhow::Context;
use anyhow::{bail, Result};

#[cfg(target_os = "macos")]
use super::CA_COMMON_NAME;
#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "macos")]
use std::time::Duration;

/// Android cannot install or probe the user CA store from Rust: the user must
/// install the certificate through Settings, and the JNI shell reports the
/// result back with [`set_android_ca_trusted`]. Chrome and WebView read
/// `AndroidCAStore` directly and trust user CAs; most other apps do not.
#[cfg(target_os = "android")]
static ANDROID_CA_TRUSTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "android")]
pub fn set_android_ca_trusted(trusted: bool) {
    ANDROID_CA_TRUSTED.store(trusted, Ordering::SeqCst);
}

/// The JNI shell is part of the workspace and must also compile for the host,
/// where there is no Android user CA store to update.
#[cfg(not(target_os = "android"))]
pub fn set_android_ca_trusted(_trusted: bool) {}

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
    cfg!(any(
        windows,
        target_os = "macos",
        target_os = "android",
        target_os = "linux"
    ))
}

pub(super) fn trust_note() -> Option<String> {
    #[cfg(windows)]
    {
        Some(
            "已安装到当前用户的根证书存储；Chromium/Edge 会使用它，Firefox 可能用自己的证书库。"
                .to_string(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        Some("已安装到登录钥匙串；使用系统信任库的浏览器会生效。".to_string())
    }
    #[cfg(target_os = "android")]
    {
        Some(
            "已作为用户证书安装；Chrome/WebView 及 Chromium 系浏览器会信任它，多数原生应用不会。"
                .to_string(),
        )
    }
    #[cfg(target_os = "linux")]
    {
        Some(
            "已通过发行版的工具安装到系统信任库；Firefox 等使用 NSS 的程序需要单独导入。"
                .to_string(),
        )
    }
    #[cfg(not(any(
        windows,
        target_os = "macos",
        target_os = "android",
        target_os = "linux"
    )))]
    {
        Some("该平台不支持自动安装 CA。".to_string())
    }
}

/// The file `install` writes and the command that rebuilds the bundle, so a
/// caller can show the exact change before making it. Platforms that install
/// through an OS API have nothing to show.
#[cfg(not(target_os = "linux"))]
pub(super) fn install_target() -> Option<(String, String)> {
    None
}

#[cfg(windows)]
pub(super) fn trust_status(
    sha1_hex: &str,
    _cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    let hash = hex::decode(sha1_hex).context("解析 SHA-1 指纹")?;
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
        bail!("无法打开当前用户的根证书存储");
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
        bail!("无法打开当前用户的根证书存储");
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
        bail!("Windows 拒绝把 CA 证书写入根证书存储");
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn uninstall_by_sha1(sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    let hash = hex::decode(sha1_hex).context("解析 SHA-1 指纹")?;
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
        bail!("无法打开当前用户的根证书存储");
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
        // Already gone: uninstall is a no-op, not a failure.
        CertCloseStore(store, 0);
        return Ok(());
    }
    let deleted = CertDeleteCertificateFromStore(context);
    CertCloseStore(store, 0);
    if deleted == 0 {
        bail!("Windows 拒绝删除 CA 证书");
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

/// Finds our CA in the login keychain. Returns whether the fingerprint is
/// present and how many certificates carry the CA common name, which tells
/// "not imported at all" from "imported but never trusted".
#[cfg(target_os = "macos")]
fn keychain_lookup(sha1_hex: &str) -> Result<(bool, usize)> {
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
        .context("执行 security find-certificate")?;
    let text = String::from_utf8_lossy(&output.stdout).to_uppercase();
    let present = text.contains(&sha1_hex.to_uppercase());
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
    Ok((present, listed))
}

#[cfg(target_os = "macos")]
pub(super) fn trust_status(
    sha1_hex: &str,
    cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    let (present, _) = keychain_lookup(sha1_hex)?;
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
        .context("执行 security verify-cert")?;
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
        .context("执行 security add-trusted-cert")?;
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
        SecurityOutcome::Cancelled => bail!("用户取消了授权对话框"),
        SecurityOutcome::Failed => {
            bail!("security add-trusted-cert 执行失败：{}", stderr.trim())
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
            .context("执行 security verify-cert")?;
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
    bail!("证书已导入，但授权对话框没有确认；请重新执行一次安装")
}

#[cfg(target_os = "macos")]
pub(super) fn uninstall_by_sha1(sha1_hex: &str, remove_trust: bool) -> Result<()> {
    let keychain = keychain_path();
    let thumbprint = sha1_hex.to_uppercase();
    // Nothing to delete is a no-op: `security delete-certificate` would exit
    // non-zero and turn an idempotent `ca uninstall` (and the uninstall step of
    // `ca repair`) into a failure.
    if !keychain_lookup(sha1_hex)?.0 {
        tracing::info!(
            thumbprint = %thumbprint,
            "no matching certificate in the keychain; nothing to remove"
        );
        return Ok(());
    }
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
        .context("执行 security delete-certificate")?;
    tracing::info!(
        thumbprint = %thumbprint,
        exit = output.status.code().unwrap_or(-1),
        stderr = %truncate_for_log(&String::from_utf8_lossy(&output.stderr), 300),
        "security delete-certificate finished"
    );
    if !output.status.success() {
        bail!(
            "security delete-certificate 执行失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "android")]
pub(super) fn trust_status(
    _sha1_hex: &str,
    _cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    Ok((true, ANDROID_CA_TRUSTED.load(Ordering::SeqCst), None))
}

#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "android",
    target_os = "linux"
)))]
pub(super) fn trust_status(
    _sha1_hex: &str,
    _cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    Ok((
        false,
        false,
        Some("该平台不支持自动检查 CA 信任状态".into()),
    ))
}

#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "android",
    target_os = "linux"
)))]
pub(super) fn install_cert(_der: &[u8], _pem_path: &Path) -> Result<()> {
    bail!("该平台不支持自动安装 CA；请用 `hakimi ca export` 导出后手动信任")
}

#[cfg(target_os = "android")]
pub(super) fn install_cert(_der: &[u8], _pem_path: &Path) -> Result<()> {
    bail!("请在 Android 设置中手动安装导出的 CA（用户证书）")
}

#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "android",
    target_os = "linux"
)))]
pub(super) fn uninstall_by_sha1(_sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    bail!("该平台不支持自动移除 CA")
}

#[cfg(target_os = "android")]
pub(super) fn uninstall_by_sha1(_sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    bail!("请在 Android 设置中手动移除该 CA")
}

// ---------------------------------------------------------------------------
// Linux: distribution trust anchors
// ---------------------------------------------------------------------------

/// Where a distribution keeps local anchors and how it rebuilds the bundle.
/// Kept as data so path selection and PEM matching are testable on any host;
/// the functions below only add the file and process calls.
#[cfg(any(test, target_os = "linux"))]
mod distro {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    #[cfg(target_os = "linux")]
    use std::path::Path;

    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    pub struct Layout {
        /// Where the distribution expects local anchors.
        pub anchor: &'static str,
        /// The extracted bundle TLS clients read.
        pub bundle: &'static str,
        /// Command that rebuilds the bundle from the anchors.
        pub update: &'static [&'static str],
    }

    /// Debian, Ubuntu and derivatives.
    const DEBIAN: Layout = Layout {
        anchor: "/usr/local/share/ca-certificates/hakimi.crt",
        bundle: "/etc/ssl/certs/ca-certificates.crt",
        update: &["update-ca-certificates"],
    };

    /// Fedora, RHEL and openSUSE.
    const RPM: Layout = Layout {
        anchor: "/etc/pki/ca-trust/source/anchors/hakimi.pem",
        bundle: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        update: &["update-ca-trust", "extract"],
    };

    /// Arch and anything else on p11-kit: `trust` writes the same
    /// `ca-certificates.crt` that OpenSSL reads.
    const P11KIT: Layout = Layout {
        anchor: "/etc/ca-certificates/trust-source/anchors/hakimi.pem",
        bundle: "/etc/ssl/certs/ca-certificates.crt",
        update: &["trust", "extract-compat"],
    };

    pub fn detect(exists: impl Fn(&str) -> bool) -> Option<&'static Layout> {
        if exists("/usr/local/share/ca-certificates") {
            Some(&DEBIAN)
        } else if exists("/etc/pki/ca-trust/source/anchors") {
            Some(&RPM)
        } else if exists("/etc/ca-certificates/trust-source/anchors") {
            Some(&P11KIT)
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    pub fn exists(path: &str) -> bool {
        Path::new(path).exists()
    }

    /// DER of the first certificate in a PEM file.
    pub fn pem_to_der(pem: &[u8]) -> Option<Vec<u8>> {
        let text = String::from_utf8_lossy(pem);
        let start = text.find(BEGIN)?;
        let body = &text[start + BEGIN.len()..];
        let end = body.find(END)?;
        let encoded: String = body[..end].split_whitespace().collect();
        STANDARD.decode(encoded).ok()
    }

    pub fn der_to_pem(der: &[u8]) -> Vec<u8> {
        let encoded = STANDARD.encode(der);
        let mut pem = String::from(BEGIN);
        pem.push('\n');
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        pem.push_str(END);
        pem.push('\n');
        pem.into_bytes()
    }

    /// Whether the extracted bundle already carries this certificate. Line
    /// wrapping differs between distributions, so each block is decoded rather
    /// than matched as text.
    pub fn bundle_contains(bundle: &[u8], der: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bundle);
        let mut rest = text.as_ref();
        while let Some(start) = rest.find(BEGIN) {
            let body = &rest[start + BEGIN.len()..];
            let Some(end) = body.find(END) else {
                return false;
            };
            let encoded: String = body[..end].split_whitespace().collect();
            if STANDARD.decode(encoded).is_ok_and(|decoded| decoded == der) {
                return true;
            }
            rest = &body[end + END.len()..];
        }
        false
    }
}

#[cfg(target_os = "linux")]
pub(super) fn install_target() -> Option<(String, String)> {
    distro::detect(distro::exists)
        .map(|layout| (layout.anchor.to_string(), layout.update.join(" ")))
}

#[cfg(target_os = "linux")]
pub(super) fn trust_status(
    _sha1_hex: &str,
    cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    let Some(layout) = distro::detect(distro::exists) else {
        return Ok((
            false,
            false,
            Some("未找到受支持的 CA 信任库；请用 `hakimi ca export` 导出后手动信任".into()),
        ));
    };
    let pem = match std::fs::read(cert_path) {
        Ok(pem) => pem,
        Err(error) => {
            return Ok((
                true,
                false,
                Some(format!("读取 {} 失败：{error}", cert_path.display())),
            ));
        }
    };
    let Some(der) = distro::pem_to_der(&pem) else {
        return Ok((true, false, Some("本地 CA 文件不是有效的 PEM".into())));
    };
    let bundle = std::fs::read(layout.bundle).unwrap_or_default();
    Ok((true, distro::bundle_contains(&bundle, &der), None))
}

#[cfg(target_os = "linux")]
pub(super) fn install_cert(der: &[u8], pem_path: &Path) -> Result<()> {
    let Some(layout) = distro::detect(distro::exists) else {
        bail!(
            "未找到受支持的 CA 信任库；该发行版可能用声明式方式管理信任（例如 NixOS）。\
             请用 `hakimi ca export` 导出证书，再按系统的配置方式加入"
        )
    };
    let pem = std::fs::read(pem_path).unwrap_or_else(|_| distro::der_to_pem(der));
    write_anchor(layout.anchor, &pem)?;
    run_update(layout)?;
    // The update tool can exit 0 and still skip the file (wrong suffix, a stale
    // lock), so success is only reported once the bundle lists the certificate.
    let bundle = std::fs::read(layout.bundle).unwrap_or_default();
    if !distro::bundle_contains(&bundle, der) {
        bail!(
            "已写入 {}，但 {} 中还没有这张证书；请手动执行 `{}` 并检查输出",
            layout.anchor,
            layout.bundle,
            layout.update.join(" ")
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn uninstall_by_sha1(_sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    let Some(layout) = distro::detect(distro::exists) else {
        return Ok(());
    };
    match std::fs::remove_file(layout.anchor) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(anyhow::Error::new(super::NeedsRoot {
                path: layout.anchor.to_string(),
            }))
        }
        Err(error) => return Err(error).with_context(|| format!("删除 {} 失败", layout.anchor)),
    }
    run_update(layout)
}

#[cfg(target_os = "linux")]
fn write_anchor(path: &str, pem: &[u8]) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建 {} 失败", parent.display()))?;
    }
    match std::fs::write(path, pem) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(anyhow::Error::new(super::NeedsRoot {
                path: path.to_string(),
            }))
        }
        Err(error) => Err(error).with_context(|| format!("写入 {path} 失败")),
    }
}

#[cfg(target_os = "linux")]
fn run_update(layout: &distro::Layout) -> Result<()> {
    let Some((program, args)) = layout.update.split_first() else {
        bail!("信任库配置缺少重建命令");
    };
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("执行 {program} 失败"))?;
    if !output.status.success() {
        bail!(
            "{program} 执行失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod trust_tests {
    use super::distro;

    fn sample_der() -> Vec<u8> {
        (0u8..=255).collect()
    }

    #[test]
    fn pem_roundtrip_keeps_the_der() {
        let der = sample_der();
        assert_eq!(distro::pem_to_der(&distro::der_to_pem(&der)), Some(der));
    }

    #[test]
    fn bundle_match_ignores_line_wrapping() {
        let der = sample_der();
        let mut bundle = b"# system bundle\n".to_vec();
        bundle.extend(distro::der_to_pem(&der));
        assert!(distro::bundle_contains(&bundle, &der));
        assert!(!distro::bundle_contains(
            &bundle,
            b"a different certificate"
        ));
        // A truncated block must not panic or match.
        assert!(!distro::bundle_contains(
            b"-----BEGIN CERTIFICATE-----\n",
            &der
        ));
    }

    #[test]
    fn layout_names_a_hakimi_anchor_and_the_family_update_command() {
        let debian = distro::detect(|path| path == "/usr/local/share/ca-certificates").unwrap();
        assert!(debian.anchor.ends_with("hakimi.crt"));
        assert!(debian.bundle.starts_with("/etc/ssl/"));
        assert_eq!(debian.update, ["update-ca-certificates"]);

        let rpm = distro::detect(|path| path == "/etc/pki/ca-trust/source/anchors").unwrap();
        assert!(rpm.anchor.ends_with("hakimi.pem"));
        assert!(rpm.bundle.contains("ca-trust"));
        assert_eq!(rpm.update, ["update-ca-trust", "extract"]);

        let p11kit =
            distro::detect(|path| path == "/etc/ca-certificates/trust-source/anchors").unwrap();
        assert!(p11kit.anchor.contains("trust-source"));
        assert_eq!(p11kit.update, ["trust", "extract-compat"]);

        assert!(distro::detect(|_| false).is_none());
    }
}
