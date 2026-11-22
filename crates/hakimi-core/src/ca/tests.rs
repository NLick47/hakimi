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
fn invalidating_status_clears_the_fast_installed_flag() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    ca.store_status(Some(CaStatus {
        present: true,
        supported: true,
        installed: true,
        subject: None,
        fingerprint_sha1: None,
        fingerprint_sha256: None,
        cert_path: None,
        not_before: None,
        not_after: None,
        error: None,
        note: None,
    }));
    assert!(ca.installed_flag.load(Ordering::Relaxed));

    // Android calls this after the user removes the user-CA trust flag. The
    // CONNECT hot path reads the mirror first, so clearing only the snapshot
    // would keep reporting the old state as installed.
    ca.invalidate_status();

    assert!(ca.status_cache.lock().is_none());
    assert!(
        !ca.installed_flag.load(Ordering::Relaxed),
        "the fast installed mirror must not outlive the invalidated snapshot"
    );
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

/// A repeat CONNECT must be able to resume the local TLS session.  Without a
/// ticketer rustls only supports stateful TLS 1.2 session ids, so a browser
/// would run a full local handshake for every connection.
#[test]
fn the_local_server_resumes_sessions() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    use rustls::{
        ClientConfig, ClientConnection, HandshakeKind, RootCertStore, ServerConnection, StreamOwned,
    };
    use rustls_pki_types::pem::PemObject;

    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let server_config = ca.server_config("example.test").unwrap();

    let mut roots = RootCertStore::empty();
    let certificate = rustls_pki_types::CertificateDer::from_pem_file(ca.ca_path()).unwrap();
    roots.add(certificate).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_config = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(server_config.clone()).unwrap();
            let mut tls = StreamOwned::new(connection, stream);
            let mut buffer = [0u8; 1];
            tls.read_exact(&mut buffer).unwrap();
            tls.write_all(&buffer).unwrap();
            tls.flush().unwrap();
        }
    });

    let mut resumed = false;
    for attempt in 0..2 {
        let stream = TcpStream::connect(address).unwrap();
        let name = rustls::pki_types::ServerName::try_from("example.test").unwrap();
        let connection = ClientConnection::new(client_config.clone(), name).unwrap();
        let mut tls = StreamOwned::new(connection, stream);
        // The ticket arrives after the handshake; reading lets the client
        // store it for the next connection.
        tls.write_all(b"x").unwrap();
        tls.flush().unwrap();
        let mut buffer = [0u8; 1];
        tls.read_exact(&mut buffer).unwrap();
        if attempt == 1 {
            resumed = tls.conn.handshake_kind() == Some(HandshakeKind::Resumed);
        }
    }
    server.join().unwrap();
    assert!(resumed, "the second local handshake must resume the session");
}

/// A cold CONNECT to a host the leaf cache has never seen pays for key
/// generation and certificate signing before the browser TLS handshake starts.
#[test]
#[ignore = "micro benchmark"]
fn bench_leaf_generation() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    crate::bench::measure("ca.leaf_miss", 100, || {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let index = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = ca
            .server_config(&format!("host{index}.example.test"))
            .unwrap();
    });
    crate::bench::measure("ca.leaf_hit", 100_000, || {
        let _ = ca.server_config("host.example.test").unwrap();
    });
}

/// Fill the snapshot with a marker a real probe can never produce: seeing it in
/// a return value proves that the caller did not run `security(1)` itself.
fn backdate_snapshot(ca: &Arc<CertificateAuthority>, age: Duration) -> CaStatus {
    let mut status = ca.status();
    status.fingerprint_sha1 = Some("stale-marker".into());
    *ca.status_cache.lock() = Some((Instant::now() - age, status.clone()));
    status
}

/// Age the existing snapshot without touching the trust store, so a benchmark
/// measures the read under test and not the setup.
fn age_snapshot(ca: &Arc<CertificateAuthority>, age: Duration) {
    let mut cache = ca.status_cache.lock();
    match cache.as_mut() {
        Some((at, _)) => *at = Instant::now() - age,
        None => panic!("the snapshot must be filled before it can be aged"),
    }
}

/// Wait (bounded) for the background probe to replace the marked snapshot.
fn wait_for_background_refresh(ca: &Arc<CertificateAuthority>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let refreshed = ca.status_cache.lock().as_ref().is_some_and(|(at, status)| {
            at.elapsed() < CA_STATUS_TTL
                && status.fingerprint_sha1.as_deref() != Some("stale-marker")
        });
        if refreshed {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the background trust probe never refreshed the snapshot"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn stale_trust_status_is_answered_without_a_probe_on_the_caller() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let stale = backdate_snapshot(&ca, CA_STATUS_TTL + Duration::from_secs(5));

    let started = Instant::now();
    let seen = ca.status_cached();
    let elapsed = started.elapsed();

    assert_eq!(
        seen.fingerprint_sha1.as_deref(),
        Some("stale-marker"),
        "a stale read must be answered from the snapshot: a synchronous probe \
         would have replaced the marker with the real fingerprint"
    );
    assert_eq!(seen.installed, stale.installed);
    assert!(
        elapsed < Duration::from_millis(50),
        "the polled status must not wait for `security(1)`; took {elapsed:?}"
    );

    // The refresh still happens — just not on the caller's thread.
    wait_for_background_refresh(&ca);
    assert_ne!(
        ca.status_cached().fingerprint_sha1.as_deref(),
        Some("stale-marker"),
        "the refreshed snapshot must be what the next read sees"
    );
}

#[test]
fn the_first_trust_read_still_probes_synchronously() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    assert!(ca.status_cache.lock().is_none());

    // Nothing to serve stale: showing "unknown" would be wrong for the first
    // caller, so this one read still waits for the real probe.
    let status = ca.status_cached();
    assert!(status.present);
    assert!(
        ca.status_cache.lock().is_some(),
        "the first read must fill the snapshot"
    );
}

#[test]
fn installed_reads_a_stale_snapshot_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    // A temp CA is never trusted, so the fast path stays off and the snapshot
    // is what the CONNECT path reads.
    assert!(!ca.installed_flag.load(Ordering::Relaxed));
    backdate_snapshot(&ca, CA_STATUS_TTL + Duration::from_secs(5));

    assert!(
        !ca.installed(),
        "the stale snapshot is what the CONNECT path must see"
    );
    assert_eq!(
        ca.status_cache
            .lock()
            .as_ref()
            .and_then(|(_, status)| status.fingerprint_sha1.clone()),
        Some("stale-marker".to_string()),
        "the CONNECT path must not run security(1) itself"
    );
    wait_for_background_refresh(&ca);

    // With no snapshot at all the answer must be authoritative instead.
    *ca.status_cache.lock() = None;
    assert!(!ca.installed());
    assert!(
        ca.status_cache.lock().is_some(),
        "an authoritative read still probes synchronously"
    );
}

/// The stale read the UI poll and the CONNECT path used to pay for: a Keychain
/// subprocess on the caller's thread every `CA_STATUS_TTL`.
#[test]
#[ignore = "micro benchmark"]
fn bench_trust_status_when_stale() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let _ = ca.status();
    let stale = CA_STATUS_TTL + Duration::from_secs(5);

    crate::bench::measure("ca.status_stale_sync", 20, || {
        age_snapshot(&ca, stale);
        let _ = ca.status();
    });
    crate::bench::measure("ca.status_cached_stale", 20, || {
        age_snapshot(&ca, stale);
        let _ = ca.status_cached();
    });
}

#[test]
fn a_skipped_background_probe_does_not_disable_later_refreshes() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    backdate_snapshot(&ca, CA_STATUS_TTL + Duration::from_secs(5));

    // The probe lock is held by a synchronous reader, so the queued background
    // probe has to give up. Releasing the "queued" flag must not depend on the
    // probe having actually run: a stuck flag would stop every later refresh
    // and freeze the CA state for the rest of the process.
    let held = ca.probe_lock.lock();
    let seen = ca.status_cached();
    assert_eq!(seen.fingerprint_sha1.as_deref(), Some("stale-marker"));

    let deadline = Instant::now() + Duration::from_secs(5);
    while ca.probe_pending.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        !ca.probe_pending.load(Ordering::Acquire),
        "a probe that could not run must still release the queued flag"
    );
    drop(held);

    // The next stale read must be able to queue a probe again.
    assert_eq!(
        ca.status_cached().fingerprint_sha1.as_deref(),
        Some("stale-marker")
    );
    wait_for_background_refresh(&ca);
}

#[test]
fn an_operation_in_flight_never_triggers_a_background_probe() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let ca = CertificateAuthority::load_or_create(&paths).unwrap();
    let stale = backdate_snapshot(&ca, CA_STATUS_TTL + Duration::from_secs(5));

    let _guard = ca.begin_operation();
    let runs = ca.probe_runs.load(Ordering::Relaxed);

    let seen = ca.status_cached();
    assert_eq!(
        seen.fingerprint_sha1.as_deref(),
        Some("stale-marker"),
        "during an operation callers must keep seeing the pre-operation state"
    );
    assert!(!ca.installed(), "the same holds for the CONNECT path");
    assert!(
        !ca.probe_pending.load(Ordering::Acquire),
        "a probe queued mid-install could store a half-applied trust state"
    );
    assert_eq!(ca.probe_runs.load(Ordering::Relaxed), runs);

    drop(_guard);
    assert!(!stale.installed, "a temp CA is never trusted");
}

#[cfg(test)]
mod minider_crosscheck {
    use super::*;

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    use time::{Date, Month, Time};
    use x509_parser::der_parser::asn1_rs::{FromDer, GeneralizedTime, UtcTime};
    use x509_parser::parse_x509_certificate;

    fn utc_date(year: i32, month: u8, day: u8) -> OffsetDateTime {
        Date::from_calendar_date(year, Month::try_from(month).unwrap(), day)
            .unwrap()
            .with_time(Time::MIDNIGHT)
            .assume_utc()
    }

    fn rcgen_ca(
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        dn: impl FnOnce(&mut CertificateParams),
    ) -> String {
        let mut params = CertificateParams::default();
        dn(&mut params);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.use_authority_key_identifier_extension = true;
        params.not_before = not_before;
        params.not_after = not_after;
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    /// Both parsers must agree on every field hakimi consumes.
    fn crosscheck(pem: &str) {
        let der = material::pem_to_der(pem).unwrap();
        let (_, cert) = parse_x509_certificate(&der).unwrap();
        let fields = minider::parse_ca_fields(&der).unwrap();

        assert_eq!(fields.subject, cert.subject().to_string(), "subject display");

        let old_ski = cert
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(key_id) => {
                    Some(key_id.0.to_vec())
                }
                _ => None,
            });
        assert_eq!(fields.ski, old_ski, "subject key identifier");

        let old_cns: Vec<String> = cert
            .subject()
            .iter_common_name()
            .map(|attr| attr.attr_value().as_str().unwrap().to_string())
            .collect();
        let new_cns: Vec<String> = fields
            .subject_attrs
            .iter()
            .filter(|attr| attr.oid == minider::OID_COMMON_NAME)
            .map(|attr| minider::utf8_string(attr.tag, &attr.value).unwrap().to_string())
            .collect();
        assert_eq!(new_cns, old_cns, "common names");

        assert_eq!(fields.not_before, cert.validity().not_before.to_datetime());
        assert_eq!(fields.not_after, cert.validity().not_after.to_datetime());
    }

    #[test]
    fn shipped_android_probe_ca_matches_x509_parser() {
        let pem = include_str!("../../../../android/probe/assets/ca/ca.pem");
        let fields = minider::parse_ca_fields(&material::pem_to_der(pem).unwrap()).unwrap();
        assert_eq!(fields.subject, "CN=Hakimi Android Probe CA");
        assert_eq!(
            fields.ski.unwrap(),
            [
                0xE4, 0x0C, 0x9D, 0x4D, 0xA9, 0x35, 0xD1, 0x15, 0x67, 0xD7, 0x14, 0xED, 0xF8,
                0xA7, 0x31, 0xA8, 0x47, 0x92, 0x70, 0x49
            ]
        );
        crosscheck(pem);
    }

    #[test]
    fn rcgen_generated_ca_matches_x509_parser() {
        let pem = rcgen_ca(utc_date(2026, 1, 1), utc_date(2036, 1, 1), |params| {
            params
                .distinguished_name
                .push(DnType::CommonName, "Hakimi Cross Check CA");
        });
        crosscheck(&pem);
    }

    #[test]
    fn multi_rdn_subject_matches_x509_parser() {
        let pem = rcgen_ca(utc_date(2026, 1, 1), utc_date(2036, 1, 1), |params| {
            params.distinguished_name.push(DnType::CountryName, "US");
            params
                .distinguished_name
                .push(DnType::OrganizationName, "Hakimi Test Org");
            params
                .distinguished_name
                .push(DnType::OrganizationalUnitName, "QA");
            params
                .distinguished_name
                .push(DnType::CommonName, "Cross Check CA");
        });
        crosscheck(&pem);
    }

    #[test]
    fn validity_across_2050_boundary_matches_x509_parser() {
        // not_before lands in UTCTime range, not_after past 2050 in
        // GeneralizedTime: one certificate exercises both encodings.
        let pem = rcgen_ca(utc_date(2049, 12, 31), utc_date(2051, 1, 1), |params| {
            params
                .distinguished_name
                .push(DnType::CommonName, "Boundary CA");
        });
        let fields =
            minider::parse_ca_fields(&material::pem_to_der(&pem).unwrap()).unwrap();
        assert_eq!(fields.not_before.year(), 2049);
        assert_eq!(fields.not_after.year(), 2051);
        crosscheck(&pem);
    }

    fn tlv_bytes(tag: u8, content: &str) -> Vec<u8> {
        let mut bytes = vec![tag, content.len() as u8];
        bytes.extend_from_slice(content.as_bytes());
        bytes
    }

    #[test]
    fn time_shapes_match_asn1_rs() {
        let cases: Vec<(u8, &str)> = vec![
            (0x17, "260102030405Z"),
            (0x17, "490101000000Z"),
            (0x17, "500101000000Z"),
            (0x17, "2601010000Z"),
            (0x17, "260101000000+0530"),
            (0x17, "260101000000-0530"),
            (0x18, "20501231235959Z"),
            (0x18, "20510101000000Z"),
            (0x18, "20510101000000.500Z"),
            (0x18, "20510101000000,5Z"),
            (0x18, "205101010000Z"),
        ];
        for (tag, content) in cases {
            let bytes = tlv_bytes(tag, content);
            let parsed = minider::parse_time(tag, content.as_bytes());
            let reference = match tag {
                0x17 => UtcTime::from_der(&bytes)
                    .map(|(_, t)| t.utc_adjusted_datetime()),
                _ => GeneralizedTime::from_der(&bytes)
                    .map(|(_, t)| t.utc_datetime()),
            };
            match reference {
                Ok(Ok(expected)) => assert_eq!(parsed.unwrap(), expected, "shape {content}"),
                _ => assert!(parsed.is_err(), "shape {content} must also be rejected"),
            }
        }
    }

    #[test]
    fn malformed_times_error_like_the_old_parser() {
        let cases: Vec<(u8, &str)> = vec![
            (0x17, "260101000"),
            (0x17, "2601010000"),
            (0x17, "260101000000"),
            (0x17, "2601010000+0530"),
            (0x17, "261301000000Z"),
            (0x17, "260132000000Z"),
            (0x18, "20510101000000.500"),
            (0x18, "20510101000000,5Z"),
            (0x18, "20a101000000Z"),
            (0x13, "260101000000Z"),
        ];
        for (tag, content) in cases {
            assert!(
                minider::parse_time(tag, content.as_bytes()).is_err(),
                "expected {content:?} to be rejected"
            );
        }
    }

    #[test]
    fn garbage_certificates_are_rejected() {
        let der = material::pem_to_der(include_str!(
            "../../../../android/probe/assets/ca/ca.pem"
        ))
        .unwrap();
        for cut in [0, 1, 4, 16, der.len() / 2, der.len() - 1] {
            assert!(
                minider::parse_ca_fields(&der[..cut]).is_err(),
                "truncation at {cut} must be rejected"
            );
        }
        assert!(minider::parse_ca_fields(&[0x02, 0x01, 0x00]).is_err());
        assert!(minider::parse_ca_fields(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_err());
    }
}
