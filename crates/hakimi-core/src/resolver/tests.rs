use crate::cache::{CachedAnswer, CachedEch};
use crate::dns::{ResolvedAnswer, TYPE_HTTPS};
use super::endpoints::{read_limited_body, MAX_DOH_CLIENTS};
use super::ech::SHARED_ECH_DOMAIN;
use super::lookup::{any_family_expired, STALE_WHILE_REVALIDATE_SECS};
use std::net::SocketAddr;
use std::time::Duration;
    use super::*;

    use crate::cache::CacheManager;
    use crate::catalog::CatalogManager;
    use crate::config::ConfigManager;
    use crate::paths::Paths;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn resolver(dir: &std::path::Path) -> (Arc<ConfigManager>, Arc<CacheManager>, Arc<Resolver>) {
        let paths = Paths::new(dir);
        paths.ensure().unwrap();
        let config = Arc::new(ConfigManager::load_or_create(&paths).unwrap());
        let cache = Arc::new(CacheManager::load(paths.state_file()).unwrap());
        let catalogs = CatalogManager::load(&paths, config.clone(), cache.clone()).unwrap();
        let resolver = Resolver::new(cache.clone(), config.clone(), catalogs);
        (config, cache, resolver)
    }

    #[test]
    fn endpoint_cache_reuses_the_list_until_the_config_changes() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _, resolver) = resolver(dir.path());
        let first = resolver.effective_endpoints();
        let same = resolver.effective_endpoints();
        assert!(
            Arc::ptr_eq(&first, &same),
            "an unchanged config must reuse the cached endpoint list"
        );

        config
            .mutate(|config| {
                config.doh.custom.push(crate::config::DohEndpoint {
                    name: "added".into(),
                    url: "https://added.example/dns-query".into(),
                    bootstrap_ip: None,
                    enabled: true,
                });
                Ok(())
            })
            .unwrap();
        let changed = resolver.effective_endpoints();
        assert_eq!(changed.len(), first.len() + 1);
        assert!(!Arc::ptr_eq(&first, &changed));
    }

    #[test]
    fn endpoint_order_and_dedupe() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _, resolver) = resolver(dir.path());
        config
            .mutate(|config| {
                config.doh.fallback = config.doh.primary.clone();
                config.doh.custom.push(crate::config::DohEndpoint {
                    name: "custom".into(),
                    url: "https://custom.example/dns-query".into(),
                    bootstrap_ip: None,
                    enabled: true,
                });
                Ok(())
            })
            .unwrap();
        let endpoints = resolver.effective_endpoints();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].source, DohSource::Primary);
        assert_eq!(endpoints[1].source, DohSource::Custom);
    }

    #[test]
    fn catalog_endpoints_are_named_as_catalog_not_custom() {
        // The remote catalog's endpoints must be distinguishable from the
        // ones the user typed in, and they must not be able to override a
        // custom endpoint's name or bootstrap.
        let dir = tempfile::tempdir().unwrap();
        let (config, _, _) = resolver(dir.path());
        let url = "https://from-catalog.example/dns-query";
        let endpoints = Resolver::build_endpoints(
            &config.snapshot(),
            vec![crate::config::DohEndpoint {
                name: "catalog entry".into(),
                url: url.into(),
                bootstrap_ip: Some("1.1.1.1".parse().unwrap()),
                enabled: true,
            }],
        );
        let entry = endpoints
            .iter()
            .find(|endpoint| endpoint.url == url)
            .expect("the catalog endpoint is appended");
        assert_eq!(entry.source, DohSource::Catalog);

        // A user custom entry reusing the same URL keeps its Custom source;
        // the catalog entry adds nothing.
        config
            .mutate(|config| {
                config.doh.custom.push(crate::config::DohEndpoint {
                    name: "mine".into(),
                    url: url.into(),
                    bootstrap_ip: Some("9.9.9.9".parse().unwrap()),
                    enabled: true,
                });
                Ok(())
            })
            .unwrap();
        let merged = Resolver::build_endpoints(
            &config.snapshot(),
            vec![crate::config::DohEndpoint {
                name: "catalog entry".into(),
                url: url.into(),
                bootstrap_ip: Some("1.1.1.1".parse().unwrap()),
                enabled: true,
            }],
        );
        let entries: Vec<_> = merged.iter().filter(|e| e.url == url).collect();
        assert_eq!(entries.len(), 1, "the catalog entry dedupes into the custom one");
        assert_eq!(entries[0].source, DohSource::Custom);
        assert_eq!(entries[0].name, "mine");
    }

    #[test]
    fn doh_client_cache_keeps_the_hot_endpoints_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, resolver) = resolver(dir.path());
        let endpoints = resolver.effective_endpoints();
        for endpoint in endpoints.iter() {
            resolver
                .client_for(endpoint, Duration::from_secs(3))
                .unwrap();
        }
        for index in 0..(MAX_DOH_CLIENTS + 8) {
            let endpoint = EffectiveEndpoint {
                name: format!("custom{index}"),
                url: format!("https://custom{index}.example/dns-query"),
                bootstrap_ip: None,
                source: DohSource::Custom,
            };
            resolver
                .client_for(&endpoint, Duration::from_secs(3))
                .unwrap();
        }
        let clients = resolver.clients.read();
        assert!(
            clients.len() <= MAX_DOH_CLIENTS,
            "the client cache must stay bounded ({} entries)",
            clients.len()
        );
        assert_eq!(
            clients
                .values()
                .filter(|entry| entry.source == DohSource::Primary)
                .count(),
            1,
            "the primary client must survive custom-endpoint churn"
        );
        assert_eq!(
            clients
                .values()
                .filter(|entry| entry.source == DohSource::Fallback)
                .count(),
            1,
            "the fallback client must survive custom-endpoint churn"
        );
    }

    #[tokio::test]
    async fn fresh_cache_is_used_first() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_A,
            ips: vec!["20.205.243.166".parse().unwrap()],
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now(),
        });
        let resolution = resolver.resolve_ips("github.com").await.unwrap();
        assert_eq!(resolution.source, DohSource::Cache);
        assert_eq!(resolution.ips.len(), 1);
    }

    /// A cached answer must not drop one address family just because the
    /// other family happens to be cached too. The live query always merges
    /// A and AAAA; the cache path used to return the first fresh family and
    /// silently lose the IPv6 candidates for the rest of the A TTL.
    #[tokio::test]
    async fn cached_answers_from_both_address_families_are_merged() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        let v4: IpAddr = "20.205.243.166".parse().unwrap();
        let v6: IpAddr = "2606:50c0:8000::153".parse().unwrap();
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_A,
            ips: vec![v4],
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now(),
        });
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_AAAA,
            ips: vec![v6],
            ech_config: None,
            ttl_secs: 300,
            fetched_at: now(),
        });

        let resolution = resolver.resolve_ips("github.com").await.unwrap();
        assert_eq!(resolution.source, DohSource::Cache);
        assert_eq!(
            resolution.ips,
            vec![v4, v6],
            "a fresh AAAA answer must not be dropped because A is cached"
        );
        assert_eq!(resolution.ttl, 60, "the earliest expiry wins");
    }

    /// A and AAAA have independent TTLs. When the shorter-lived A answer
    /// expires while AAAA is still fresh, the old code returned the IPv6
    /// answer alone and never re-queried A until AAAA expired too. The stale
    /// IPv4 fallback must stay in the candidate list and a refresh must be
    /// started.
    #[tokio::test]
    async fn an_expired_family_is_kept_beside_a_fresh_one() {
        let dir = tempfile::tempdir().unwrap();
        let (config, cache, resolver) = resolver(dir.path());
        config
            .mutate(|config| {
                // Keep the background refresh offline and deterministic.
                config.doh.primary = "https://127.0.0.1:1/dns-query".into();
                config.doh.fallback = config.doh.primary.clone();
                config.doh.custom.clear();
                Ok(())
            })
            .unwrap();
        let v4: IpAddr = "20.205.243.166".parse().unwrap();
        let v6: IpAddr = "2606:50c0:8000::153".parse().unwrap();
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_A,
            ips: vec![v4],
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now() - chrono::Duration::seconds(90),
        });
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_AAAA,
            ips: vec![v6],
            ech_config: None,
            ttl_secs: 300,
            fetched_at: now(),
        });

        let resolution = resolver.resolve_ips("github.com").await.unwrap();
        assert!(resolution.stale, "the merged answer carries a stale entry");
        assert_eq!(
            resolution.ips,
            vec![v4, v6],
            "the expired IPv4 fallback must survive while AAAA is fresh"
        );
        let families = resolver.cached_families("github.com", now());
        assert!(
            any_family_expired(&families),
            "the expired family has to be refreshed in the background"
        );
        // Let the background refresh observe the closed endpoint and exit.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    /// The refresh worker used to stop as soon as *any* family was fresh, so
    /// an expired family behind a fresh one was never re-queried. The check
    /// must consider every cached family, but not invent work for a domain
    /// that only ever had one family.
    #[test]
    fn a_fresh_family_does_not_stop_refreshing_an_expired_one() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        let at = now();
        let v4: IpAddr = "20.205.243.166".parse().unwrap();
        let v6: IpAddr = "2606:50c0:8000::153".parse().unwrap();
        let answer = |domain: &str, qtype: u16, ip: IpAddr, fetched_at| CachedAnswer {
            domain: domain.into(),
            qtype,
            ips: vec![ip],
            ech_config: None,
            ttl_secs: 60,
            fetched_at,
        };

        // A is fresh while AAAA has expired.
        cache.put_doh_answer(answer("dual.example", TYPE_A, v4, at));
        cache.put_doh_answer(answer(
            "dual.example",
            TYPE_AAAA,
            v6,
            at - chrono::Duration::seconds(90),
        ));
        assert!(
            resolver.ip_cache_needs_refresh("dual.example", at),
            "the expired AAAA family must still be refreshed"
        );

        // An IPv4-only domain has no AAAA entry to fetch.
        cache.put_doh_answer(answer("v4.example", TYPE_A, v4, at));
        assert!(!resolver.ip_cache_needs_refresh("v4.example", at));

        // Both families fresh: nothing to do.
        cache.put_doh_answer(answer("fresh.example", TYPE_A, v4, at));
        cache.put_doh_answer(answer("fresh.example", TYPE_AAAA, v6, at));
        assert!(!resolver.ip_cache_needs_refresh("fresh.example", at));

        // A cold domain still needs a live lookup.
        assert!(resolver.ip_cache_needs_refresh("cold.example", at));
    }

    #[tokio::test]
    async fn expired_answers_are_served_without_waiting_for_doh() {
        let dir = tempfile::tempdir().unwrap();
        let (config, cache, resolver) = resolver(dir.path());
        config
            .mutate(|config| {
                // Keep the background refresh offline and deterministic.
                config.doh.primary = "https://127.0.0.1:1/dns-query".into();
                config.doh.fallback = "https://127.0.0.1:1/dns-query".into();
                config.doh.custom.clear();
                Ok(())
            })
            .unwrap();
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_A,
            ips: vec!["20.205.243.166".parse().unwrap()],
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now() - chrono::Duration::seconds(90),
        });

        let started = Instant::now();
        let resolution = resolver.resolve_ips("github.com").await.unwrap();
        assert!(resolution.stale);
        assert_eq!(resolution.source, DohSource::Cache);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "an expired-but-usable answer should not wait for DoH: {:?}",
            started.elapsed()
        );
        // Let the background refresh observe the empty endpoint list and exit.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn doh_errors_do_not_leak_endpoint_path_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _, resolver) = resolver(dir.path());
        config
            .mutate(|config| {
                // Port 1 is closed, so reqwest reports a request error. Its
                // Display includes the full URL; the status/health record must
                // not carry the credential from the path.
                config.doh.primary = "https://127.0.0.1:1/dns-query/secret-token".into();
                config.doh.fallback = config.doh.primary.clone();
                config.doh.custom.clear();
                Ok(())
            })
            .unwrap();

        let health = resolver.health_check().await;
        let errors: Vec<&str> = health
            .iter()
            .filter_map(|entry| entry.last_error.as_deref())
            .collect();
        let text = errors.join("\n");
        assert!(
            !text.contains("secret-token"),
            "DoH health must not expose a token from the endpoint path: {text}"
        );
        assert!(
            text.contains("redacted"),
            "the error should name the endpoint with its path redacted: {text}"
        );
    }

    #[tokio::test]
    async fn oversized_chunked_doh_body_is_rejected_while_streaming() {
        crate::util::install_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/dns-message\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .unwrap();
            let chunk = vec![b'x'; 4096];
            for _ in 0..20 {
                let header = format!("{:x}\r\n", chunk.len());
                if socket.write_all(header.as_bytes()).await.is_err() {
                    return;
                }
                if socket.write_all(&chunk).await.is_err() {
                    return;
                }
                if socket.write_all(b"\r\n").await.is_err() {
                    return;
                }
            }
            let _ = socket.write_all(b"0\r\n\r\n").await;
        });

        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        let error = read_limited_body(response).await.unwrap_err();
        assert!(
            error.to_string().contains("larger"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn expired_answers_are_available_for_the_revalidate_grace_window() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        cache.put_doh_answer(CachedAnswer {
            domain: "github.com".into(),
            qtype: TYPE_A,
            ips: vec!["20.205.243.166".parse().unwrap()],
            ech_config: None,
            ttl_secs: 60,
            fetched_at: now() - chrono::Duration::seconds(90),
        });

        let at = now();
        let families = resolver.cached_families("github.com", at);
        let stale = stale_resolution_from(&families, Some(STALE_WHILE_REVALIDATE_SECS))
            .expect("an expired answer within the grace window must be usable");
        assert!(stale.stale);
        assert_eq!(stale.ips.len(), 1);

        let beyond_grace = now() + chrono::Duration::seconds(90);
        let families = resolver.cached_families("github.com", beyond_grace);
        assert!(
            stale_resolution_from(&families, Some(60)).is_none(),
            "the stale-while-revalidate path must not serve arbitrarily old answers"
        );
        assert!(
            stale_resolution_from(&families, None).is_some(),
            "the last-resort path may still use the usable answer"
        );
    }

    #[test]
    fn https_answers_use_only_the_ech_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        let answer = ResolvedAnswer {
            ips: Vec::new(),
            ech: Some(vec![1, 2, 3, 4]),
            ttl: 60,
            cname: None,
            https_present: true,
        };
        resolver.store_answer("pixiv.net", TYPE_HTTPS, &answer);
        assert_eq!(
            cache.stats().doh_answers,
            0,
            "an HTTPS RR has no addresses; caching it only evicts real A/AAAA answers"
        );
        assert_eq!(cache.stats().ech_configs, 1);
    }

    /// `CachedEch` stores the raw ECHConfigList. The stale shared-config
    /// fallback used to base64-decode it, which either fails on the binary
    /// version byte or silently returns different bytes. When DoH is down the
    /// last-resort shared config must be handed to rustls verbatim.
    #[tokio::test]
    async fn stale_shared_ech_config_is_returned_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let (config, cache, resolver) = resolver(dir.path());
        config
            .mutate(|config| {
                // Both raced endpoints are offline, so the live lookup fails
                // immediately instead of waiting for a timeout.
                config.doh.primary = "https://127.0.0.1:1/dns-query".into();
                config.doh.fallback = config.doh.primary.clone();
                config.doh.custom.clear();
                Ok(())
            })
            .unwrap();

        // `shared_cloudflare_ech` tries AliDNS directly after the configured
        // endpoints. Pin that client to a closed local port so the test never
        // depends on the real network.
        let timeout = Duration::from_secs(config.snapshot().catalogs.timeout_secs.max(1));
        let key = format!("https://dns.alidns.com/dns-query||{}", timeout.as_secs());
        let alidns = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .resolve("dns.alidns.com", SocketAddr::from(([127, 0, 0, 1], 1)))
            .build()
            .unwrap();
        resolver.clients.write().insert(
            key,
            CachedDohClient {
                client: alidns,
                source: DohSource::Custom,
                created_at: Instant::now(),
            },
        );

        let ech_config = vec![0xfe, 0x0d, 0x00, 0x01, 0x00, 0x00];
        cache.put_ech(CachedEch {
            domain: SHARED_ECH_DOMAIN.into(),
            ech_config: ech_config.clone(),
            ttl_secs: 60,
            fetched_at: now() - chrono::Duration::seconds(120),
        });

        let shared = resolver
            .shared_cloudflare_ech()
            .await
            .expect("a stale shared config is the last resort when DoH is down");
        assert_eq!(
            shared.config, ech_config,
            "the raw ECHConfigList must not be base64-decoded"
        );
        assert!(shared.stale);

        // The public ECH path must use the same stale fallback for the
        // requesting host instead of surfacing the DoH failure.
        let outcome = resolver
            .ech_config("pixiv.net", true)
            .await
            .expect("the stale shared config must reach the requesting host");
        assert_eq!(outcome.config, ech_config);
        assert!(outcome.stale);
    }

    /// The endpoint order is the policy that keeps a blocked primary off the
    /// hot path. Two failures must not demote it (a single bad round trip is
    /// noise), the third cools it, a success restores it, and an expired
    /// cooldown restores it without any traffic.
    #[test]
    fn a_failing_endpoint_is_demoted_only_after_the_threshold_and_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, resolver) = resolver(dir.path());
        let endpoints = resolver.effective_endpoints();
        assert!(endpoints.len() >= 2, "the default config has a pair");
        let first = endpoints[0].clone();

        let fail = || {
            resolver.record_health(
                &first,
                false,
                Duration::from_millis(1),
                Some("blocked".into()),
            )
        };
        assert_eq!(resolver.endpoint_order(&endpoints)[0], 0);
        fail();
        fail();
        assert_eq!(
            resolver.endpoint_order(&endpoints)[0],
            0,
            "two failures are noise, not a verdict"
        );
        fail();
        let order = resolver.endpoint_order(&endpoints);
        assert_eq!(order[0], 1, "the healthy endpoint takes the first slot");
        assert_eq!(*order.last().unwrap(), 0, "the cooled endpoint sinks");

        // An expired cooldown restores the position without new traffic.
        {
            let mut health = resolver.health.write();
            let entry = health.get_mut(&first.url).unwrap();
            entry.cooldown_until = Some(Instant::now() - Duration::from_millis(1));
        }
        assert_eq!(resolver.endpoint_order(&endpoints)[0], 0);

        // A success resets the failure count and leaves it first even while a
        // new cooldown is armed.
        {
            let mut health = resolver.health.write();
            health.get_mut(&first.url).unwrap().cooldown_until =
                Some(Instant::now() + Duration::from_secs(60));
        }
        resolver.record_health(&first, true, Duration::from_millis(1), None);
        let entry = resolver.health.read().get(&first.url).cloned().unwrap();
        assert_eq!(entry.failures, 0);
        assert!(entry.cooldown_until.is_none());
        assert_eq!(resolver.endpoint_order(&endpoints)[0], 0);
    }

    #[test]
    fn stale_ech_serves_the_grace_window_but_not_fresh_or_nodata() {
        let dir = tempfile::tempdir().unwrap();
        let (_, cache, resolver) = resolver(dir.path());
        let config = vec![0xfe, 0x0d, 0x00, 0x01];
        let put = |age: i64, ttl: u32| {
            cache.put_ech(CachedEch {
                domain: "example.test".into(),
                ech_config: config.clone(),
                ttl_secs: ttl,
                fetched_at: now() - chrono::Duration::seconds(age),
            });
        };

        put(0, 300);
        assert!(resolver.stale_ech("example.test").is_none(), "fresh is not stale");

        put(310, 300);
        let served = resolver.stale_ech("example.test").expect("expired within grace");
        assert!(served.stale);
        assert_eq!(served.config, config);

        // Past TTL + STALE_WHILE_REVALIDATE_SECS the grace is over: the live
        // path (with its own failure fallback) must decide instead.
        put(400, 300);
        assert!(resolver.stale_ech("example.test").is_none(), "grace window expired");

        // An authoritative NODATA proves the config is gone; never resurrect
        // a cached one even inside the grace window.
        put(310, 300);
        cache.put_doh_negative("example.test", TYPE_HTTPS, 300, true);
        assert!(
            resolver.stale_ech("example.test").is_none(),
            "authoritative NODATA must suppress stale ECH"
        );
    }
