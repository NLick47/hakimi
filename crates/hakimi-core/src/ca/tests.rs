use std::sync::Arc;
use std::time::{Duration, Instant};

use time::{Duration as TimeDuration, OffsetDateTime};

use crate::paths::Paths;

use super::trust::truncate_for_log;
#[cfg(target_os = "macos")]
use super::trust::{classify_security_output, SecurityOutcome};
use super::*;
use super::{prune_leaves, short_fingerprint, should_roll_back, LeafEntry};

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
    // A ticketer is required for TLS 1.3 session tickets, without them a
    // repeat CONNECT repeats the full local handshake.
    assert!(config.ticketer.enabled());
}

#[test]
fn leaf_cache_prunes_oldest_entries_without_touching_the_newest() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let base = OffsetDateTime::now_utc() - TimeDuration::minutes(10);
    for i in 0..6 {
        let domain = format!("h{i}.test");
        let config = ca.server_config(&domain).unwrap();
        ca.leaves.write().insert(
            domain,
            Arc::new(LeafEntry {
                config,
                created_at: base + TimeDuration::seconds(i),
            }),
        );
    }

    prune_leaves(&mut ca.leaves.write(), 4);
    let leaves = ca.leaves.read();
    assert_eq!(leaves.len(), 4);
    assert!(!leaves.contains_key("h0.test"));
    assert!(!leaves.contains_key("h1.test"));
    assert!(leaves.contains_key("h5.test"));
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
fn stale_status_is_reused_while_another_probe_is_running() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let mut cached = ca.status();
    cached.installed = true;
    *ca.status_cache.lock() = Some((Instant::now() - Duration::from_secs(60), cached));
    let _probe = ca.probe_lock.lock();

    let status = ca.status();
    assert!(
        status.installed,
        "a concurrent probe must not make callers wait or lose the snapshot"
    );
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
