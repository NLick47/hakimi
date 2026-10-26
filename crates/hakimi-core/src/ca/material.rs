use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::paths::Paths;
use crate::util::{atomic_write, atomic_write_private, sha1_hex, sha256_hex};

use super::CA_COMMON_NAME;

const LEAF_VALIDITY_DAYS: i64 = 7;

pub(super) struct CaMaterial {
    pub(super) issuer: Certificate,
    pub(super) key: KeyPair,
    pub(super) der: Vec<u8>,
    pub(super) pem: String,
    pub(super) subject: String,
    pub(super) fingerprint_sha1: String,
    pub(super) fingerprint_sha256: String,
    pub(super) not_before: String,
    pub(super) not_after: String,
}

/// Subject from the actual certificate, not a hardcoded preset: the Android
/// probe ships a pre-generated CA whose CN differs from the desktop default.
fn parse_subject(der: &[u8]) -> Result<String> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|error| anyhow::anyhow!("parsing CA subject: {error}"))?;
    Ok(certificate.subject().to_string())
}

pub(super) fn build_leaf_config(
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
    // TLS 1.3 session tickets.  rustls can also resume statefully, but a
    // ticket keeps no session state in the server.  One ticketer per leaf,
    // so a ticket never crosses hosts.
    if let Ok(ticketer) = rustls::crypto::aws_lc_rs::Ticketer::new() {
        config.ticketer = ticketer;
    }
    Ok(Arc::new(config))
}

pub(super) fn generate_and_save(paths: &Paths) -> Result<CaMaterial> {
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

pub(super) fn load_material(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<CaMaterial> {
    let pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?;
    let key_bytes =
        std::fs::read(key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let key_pem = decode_key_file(&key_bytes)?;
    let key = KeyPair::from_pem(&key_pem)
        .with_context(|| format!("parsing CA key {}", key_path.display()))?;
    let original_der = pem_to_der(&pem)?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&original_der)
        .map_err(|error| anyhow::anyhow!("parsing CA certificate: {error}"))?;
    let subject = parse_subject(&original_der)?;
    let params = issuer_params_from(&certificate)?;
    // `self_signed` 用同一把 CA 私钥重签解析出的参数，得到签名 leaf 时的 issuer 模板
    let issuer = params
        .self_signed(&key)
        .context("reconstructing CA issuer parameters")?;
    let not_before = certificate.validity().not_before.to_datetime().to_string();
    let not_after = certificate.validity().not_after.to_datetime().to_string();
    Ok(CaMaterial {
        issuer,
        key,
        fingerprint_sha1: sha1_hex(&original_der),
        fingerprint_sha256: sha256_hex(&original_der),
        der: original_der,
        pem,
        subject,
        not_before,
        not_after,
    })
}

/// 从解析出的 CA 证书重建自签参数
/// hakimi 签发的 CA 只含 CN，重建时同样只取 CN，有效期沿用原证书
fn issuer_params_from(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<CertificateParams> {
    let mut params = CertificateParams::default();
    let mut cn_count = 0;
    for attr in certificate.subject().iter_common_name() {
        let value = attr
            .attr_value()
            .as_str()
            .context("CA subject CN is not a string")?;
        params.distinguished_name.push(DnType::CommonName, value);
        cn_count += 1;
    }
    if cn_count == 0 {
        bail!("CA certificate has no common name");
    }
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.use_authority_key_identifier_extension = true;
    params.not_before = certificate.validity().not_before.to_datetime();
    params.not_after = certificate.validity().not_after.to_datetime();
    Ok(params)
}

fn material_from_parts(issuer: Certificate, key: KeyPair) -> CaMaterial {
    let der = issuer.der().to_vec();
    let pem = issuer.pem();
    let subject = parse_subject(&der).unwrap_or_else(|_| format!("CN={CA_COMMON_NAME}"));
    let not_before = issuer.params().not_before.to_string();
    let not_after = issuer.params().not_after.to_string();
    CaMaterial {
        fingerprint_sha1: sha1_hex(&der),
        fingerprint_sha256: sha256_hex(&der),
        der,
        pem,
        subject,
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

#[cfg(windows)]
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
