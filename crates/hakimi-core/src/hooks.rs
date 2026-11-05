//! Test hooks for a local harness.
//!
//! The proxy normally trusts only the compiled-in Mozilla roots. A test
//! harness needs to talk to servers whose certificates it generated itself
//! (a fake DoH endpoint, a fake origin), so `HAKIMI_EXTRA_ROOT_CA` may point
//! at a PEM file with additional roots.
//!
//! These hooks can weaken the trust chain (skip the CA trust check, inject an
//! extra root, allow private catalog IPs), so they are compiled only into
//! debug builds. The scenario harness and integration tests build
//! `target/debug/hakimi`, where `debug_assertions` is on; release binaries
//! keep the full trust checks and ignore every `HAKIMI_*` hook entirely.

use std::path::PathBuf;

use rustls_pki_types::CertificateDer;

#[cfg(debug_assertions)]
use rustls_pki_types::pem::PemObject;

/// Path of the optional extra root bundle.
#[cfg(debug_assertions)]
const EXTRA_ROOT_ENV: &str = "HAKIMI_EXTRA_ROOT_CA";

/// Allow catalog entries with non-public addresses (loopback, private ranges).
#[cfg(debug_assertions)]
const ALLOW_PRIVATE_IPS_ENV: &str = "HAKIMI_ALLOW_PRIVATE_CATALOG_IPS";

/// Skip the startup warm-up of the upstream routes.
///
/// The warm-up probes every configured domain, which fills the DoH answer
/// cache and the last-good cache before the first real request arrives. A
/// harness that has to observe a *cold* connection - one that starts with a
/// thin candidate list and has to wait for DoH - needs the warm-up out of the
/// way.
#[cfg(debug_assertions)]
const SKIP_WARMUP_ENV: &str = "HAKIMI_SKIP_WARMUP";

/// Whether the startup warm-up should be skipped.
pub fn skip_warmup() -> bool {
    #[cfg(debug_assertions)]
    {
        matches!(
            std::env::var(SKIP_WARMUP_ENV).ok().as_deref(),
            Some("1") | Some("true") | Some("yes")
        )
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// Pretend the local CA is trusted by the operating system.
///
/// The MITM path refuses to run without a trusted CA, and installing one
/// needs a user prompt.  A harness sets this to exercise the MITM path.
#[cfg(debug_assertions)]
const ASSUME_CA_INSTALLED_ENV: &str = "HAKIMI_ASSUME_CA_INSTALLED";

/// Whether the trust check should be skipped.
pub fn assume_ca_installed() -> bool {
    #[cfg(debug_assertions)]
    {
        matches!(
            std::env::var(ASSUME_CA_INSTALLED_ENV).ok().as_deref(),
            Some("1") | Some("true") | Some("yes")
        )
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// Whether the catalog may contain addresses that are not globally routable.
///
/// A harness needs it: its fake origins live on 127.0.0.1.  Off by default.
pub fn allow_private_catalog_ips() -> bool {
    #[cfg(debug_assertions)]
    {
        matches!(
            std::env::var(ALLOW_PRIVATE_IPS_ENV).ok().as_deref(),
            Some("1") | Some("true") | Some("yes")
        )
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// The configured extra root bundle, if any.
pub fn extra_root_path() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    {
        let raw = std::env::var(EXTRA_ROOT_ENV).ok()?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(PathBuf::from(trimmed))
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

/// Load the extra roots from `HAKIMI_EXTRA_ROOT_CA`.
///
/// An unreadable or malformed file is reported once and then ignored: a broken
/// test fixture must not take the proxy down.
pub fn extra_roots() -> Vec<CertificateDer<'static>> {
    #[cfg(not(debug_assertions))]
    {
        Vec::new()
    }
    #[cfg(debug_assertions)]
    {
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
}
