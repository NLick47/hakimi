//! Test hooks for a local harness.
//!
//! The proxy normally trusts only the compiled-in Mozilla roots. A test
//! harness needs to talk to servers whose certificates it generated itself
//! (a fake DoH endpoint, a fake origin), so `HAKIMI_EXTRA_ROOT_CA` may point
//! at a PEM file with additional roots.
//!
//! The hook is opt-in and off by default: without the environment variable the
//! trust store is exactly the one from before.

use std::path::PathBuf;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;

/// Path of the optional extra root bundle.
const EXTRA_ROOT_ENV: &str = "HAKIMI_EXTRA_ROOT_CA";

/// Allow catalog entries with non-public addresses (loopback, private ranges).
const ALLOW_PRIVATE_IPS_ENV: &str = "HAKIMI_ALLOW_PRIVATE_CATALOG_IPS";

/// Skip the startup warm-up of the upstream routes.
///
/// The warm-up probes every configured domain, which fills the DoH answer
/// cache and the last-good cache before the first real request arrives. A
/// harness that has to observe a *cold* connection - one that starts with a
/// thin candidate list and has to wait for DoH - needs the warm-up out of the
/// way.
const SKIP_WARMUP_ENV: &str = "HAKIMI_SKIP_WARMUP";

/// Whether the startup warm-up should be skipped.
pub fn skip_warmup() -> bool {
    matches!(
        std::env::var(SKIP_WARMUP_ENV).ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Pretend the local CA is trusted by the operating system.
///
/// The MITM path refuses to run without a trusted CA, and installing one
/// needs a user prompt.  A harness sets this to exercise the MITM path.
const ASSUME_CA_INSTALLED_ENV: &str = "HAKIMI_ASSUME_CA_INSTALLED";

/// Whether the trust check should be skipped.
pub fn assume_ca_installed() -> bool {
    matches!(
        std::env::var(ASSUME_CA_INSTALLED_ENV).ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Whether the catalog may contain addresses that are not globally routable.
///
/// A harness needs it: its fake origins live on 127.0.0.1.  Off by default.
pub fn allow_private_catalog_ips() -> bool {
    matches!(
        std::env::var(ALLOW_PRIVATE_IPS_ENV).ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// The configured extra root bundle, if any.
pub fn extra_root_path() -> Option<PathBuf> {
    let raw = std::env::var(EXTRA_ROOT_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
}

/// Load the extra roots from `HAKIMI_EXTRA_ROOT_CA`.
///
/// An unreadable or malformed file is reported once and then ignored: a broken
/// test fixture must not take the proxy down.
pub fn extra_roots() -> Vec<CertificateDer<'static>> {
    let Some(path) = extra_root_path() else {
        return Vec::new();
    };
    let iter = match CertificateDer::pem_file_iter(&path) {
        Ok(iter) => iter,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "ignoring the extra root bundle"
            );
            return Vec::new();
        }
    };
    let mut roots = Vec::new();
    for certificate in iter {
        match certificate {
            Ok(certificate) => roots.push(certificate),
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "skipping a malformed certificate in the extra root bundle"
                );
            }
        }
    }
    roots
}
