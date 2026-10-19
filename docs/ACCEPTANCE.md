# Acceptance checklist (design §17)

This is a code-level map for the acceptance criteria in `ACCELERATION_DESIGN.md`.

| Criterion | Implementation | Verification |
|---|---|---|
| Default groups reachable where the network allows | `config::default_groups`, `decision::DecisionEngine`, `proxy::handle_connect` | `doctor` against a live network; group state in `status` |
| Remote IP catalog pull/validate/cache; new IP first after update | `catalog::CatalogManager::refresh_ip`, `catalog::ip::validate`, `decision::RouteCursor` (`skipOnce`), `DecisionEngine::cached_plan` | `tests/catalog_refresh.rs`, `decision::tests::catalog_update_bypasses_cached_plan_once` |
| Global DoH primary/fallback switch and fallback | `resolver::Resolver::effective_endpoints`, `query_one_type`, `cache` | `resolver::tests`, live `doctor` |
| last-good 7 days; cache first; remote → DoH fallback | `cache::CacheManager::last_good`, `decision::RouteCursor`, `DecisionEngine::record_success` | `cache::tests`, `decision::tests` |
| Primary at startup, all exact domains warmed, wildcards lazy | `runtime::warm_groups`, `proxy::UpstreamPool::warm`, cached route plans | live startup status; `proxy::pool::tests` |
| Group aggregation and per-domain diagnostics | `status::StatusStore`, `DecisionEngine::record_success/failure_diagnostics`, `RouteCursor` | `status::tests`, `decision::tests` |
| No fragmentation / site DoH / manual IP / built-in IP | codebase contains none of these paths | grep / module review |
| Upstream HTTP/2 multiplexing and HTTP/1.1 keep-alive | `proxy::pool::UpstreamPool`, `RouteConnector`, `PooledIo` | `proxy::pool::tests::http1_connections_are_reused`; live `upstream` counters |
| No probe+request double handshake on the hot path | `decision::RouteCursor`, `proxy::pool::RouteConnector::connect_group` | `decision::tests::route_cursor_needs_no_probe_and_caches_the_plan` |
| No VPS/domain/Cloudflare required | direct local proxy + public DoH + catalogs | runtime smoke test |
| CA install/repair/remove; browser works | `ca::CertificateAuthority` | `ca::tests`; manual `hakimi ca install` |
| HTTP/HTTPS catalogs; invalid data keeps old cache | `catalog::fetch_catalog`, atomic writes | `tests/catalog_refresh.rs` |
| No telemetry; local logs/cache | `logging`, `cache`, `catalog` | source review |

## Manual verification

1. `hakimi serve --no-takeover` and open `http://127.0.0.1:8443/proxy.pac`; it should list only
   enabled groups.
2. `hakimi ca install`, then `hakimi ca status` should report `installed: true`.
3. With a configured catalog:
   ```bash
   hakimi catalog refresh --kind ip --force
   hakimi status --json
   ```
   The status should show the new catalog version and affected domains.
4. `hakimi doctor github.com --json` returns attempts in candidate order and a final
   `state`/`error`.
5. After startup, `hakimi status --json` should show `upstream.warmSuccess` for exact domains
   and `connectionsH2`/`connectionsH1`. Repeating or parallelizing requests should increase
   `upstream.requests` without increasing `upstream.connectionsOpened`.
6. `hakimi export` writes a JSON bundle with redacted URLs/IPs in the log tail.

## Intentional gaps

- Desktop autostart/tray and the UI are shell responsibilities.
- Android VpnService/JNI is reserved only.
- RFC 8441 (WebSocket over HTTP/2) is not implemented; WebSocket upgrades are forwarded over
  HTTP/1.1. CONNECT tunnels and direct traffic are unaffected.
- Firefox may need a manual CA import even after system-store installation.
