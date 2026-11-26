use super::*;
use crate::model::{SITE_ICONS, TONE_BROKEN, TONE_DEGRADED, TONE_NEUTRAL, TONE_OK};
use crate::ui_state::{BAD_COLOR, IDLE_COLOR, OK_COLOR, SLOW_COLOR};
use hakimi_core::config::{DomainRule, GroupConfig, RouteAttempt, RoutePolicy, VerifyMode};
use hakimi_core::mirror::MirrorStatus;
use hakimi_core::resolver::EffectiveEndpoint;
use hakimi_core::strategy::DohSource;

fn domains(patterns: &[&str]) -> serde_json::Value {
    serde_json::Value::Array(
        patterns
            .iter()
            .map(|pattern| serde_json::json!({ "pattern": pattern }))
            .collect(),
    )
}

fn row(pattern: &str, preset: i32) -> DomainDraft {
    DomainDraft {
        pattern: pattern.into(),
        preset,
        sni: String::new(),
        custom: String::new(),
    }
}

fn row_with_sni(pattern: &str, sni: &str) -> DomainDraft {
    DomainDraft {
        pattern: pattern.into(),
        preset: 3,
        sni: sni.into(),
        custom: String::new(),
    }
}

fn draft(rows: Vec<DomainDraft>, preset: i32) -> SiteDraft {
    SiteDraft {
        id: String::new(),
        is_new: true,
        name: String::new(),
        domains: rows,
        homepage: String::new(),
        default_preset: preset,
        default_custom: String::new(),
        default_sni: String::new(),
        verify: 0,
    }
}

#[test]
fn new_site_gets_a_config_safe_id() {
    let config = AppConfig::default();
    let group = build_group(&config, &draft(vec![row("www.example.com", 0)], 0)).unwrap();
    assert_eq!(group.id, "www-example-com");
    assert_eq!(group.name, "www.example.com");
    assert!(group.enabled);
    assert_eq!(group.default_route, RoutePolicy::auto());
    assert_eq!(group.domains.len(), 1);
    assert_eq!(group.domains[0].pattern, "www.example.com");
    assert!(group.domains[0].route.is_none());
}

#[test]
fn default_sni_hosts_round_trip_through_the_editor() {
    let config = AppConfig::default();
    let mut site = draft(vec![row("www.example.com", 0)], 3);
    site.default_sni = "g.cn".into();
    let group = build_group(&config, &site).unwrap();
    assert_eq!(
        group.default_route,
        RoutePolicy::sni(vec!["g.cn".to_string()])
    );
    assert_eq!(route_preset_index(&group.default_route), 3);
}

#[test]
fn the_site_verify_mode_is_stored_on_the_group() {
    let config = AppConfig::default();
    let mut site = draft(
        vec![row("www.example.com", 0), row("*.cdn.example.com", 3)],
        0,
    );
    site.verify = 1;
    let group = build_group(&config, &site).unwrap();
    assert_eq!(group.verify, VerifyMode::Sni);
}

#[test]
fn editing_a_site_keeps_its_verify_mode() {
    let mut config = AppConfig::default();
    config.groups.push(GroupConfig {
        id: "kept".into(),
        name: "Kept".into(),
        domains: vec![DomainRule::new("a.example")],
        enabled: true,
        homepage: None,
        default_route: RoutePolicy::auto(),
        verify: VerifyMode::Off,
    });
    let mut site = draft_with("kept", false, vec![row("a.example", 0)], 0);
    site.verify = 2;
    let group = build_group(&config, &site).unwrap();
    assert_eq!(group.verify, VerifyMode::Off);
}

#[test]
fn domain_rows_can_override_ech_and_sni() {
    let config = AppConfig::default();
    let group = build_group(
        &config,
        &draft(
            vec![
                row("www.example.com", 2),
                row_with_sni("*.cdn.example.com", "www.baidu.com"),
                row("example.com", 0),
            ],
            0,
        ),
    )
    .unwrap();
    assert_eq!(group.domains[0].pattern, "www.example.com");
    assert_eq!(
        group.domains[0].route.as_ref().unwrap().attempts[0].mode(),
        hakimi_core::strategy::TlsMode::Ech
    );
    assert_eq!(
        group.domains[1].route.as_ref().unwrap().attempts[0].mode(),
        hakimi_core::strategy::TlsMode::FakeSni
    );
    assert!(group.domains[2].route.is_none());
}

#[test]
fn default_route_presets_and_custom_specs_round_trip() {
    let config = AppConfig::default();
    let group = build_group(&config, &draft(vec![row("example.com", 0)], 2)).unwrap();
    assert_eq!(group.default_route, RoutePolicy::ech_shared());

    let mut custom = draft(vec![row("example.com", 0)], 4);
    custom.default_custom = "sni:WWW.Baidu.COM+direct".into();
    let group = build_group(&config, &custom).unwrap();
    assert_eq!(
        group.default_route,
        RoutePolicy::sni(vec!["www.baidu.com".into()])
    );
}

#[test]
fn rejects_domains_without_an_exact_entry() {
    let config = AppConfig::default();
    assert!(build_group(&config, &draft(vec![row("*.example.com", 0)], 0)).is_err());
}

#[test]
fn rejects_domains_owned_by_another_group() {
    let config = AppConfig::default();
    let error = build_group(&config, &draft(vec![row("github.com", 0)], 0)).unwrap_err();
    assert!(format!("{error:#}").contains("GitHub"));
}

#[test]
fn rejects_malformed_domains() {
    let config = AppConfig::default();
    assert!(build_group(&config, &draft(vec![row("example..com", 0)], 0)).is_err());
}

#[test]
fn ca_actions_are_judged_by_the_resulting_trust_state() {
    // A cancelled dialog must never read as success.
    let cancelled = anyhow::anyhow!("user canceled the authorization dialog");
    assert_eq!(ca_outcome(Err(cancelled), true), CaOutcome::Cancelled);

    // `security` can exit 0 while nothing got trusted: the store decides.
    assert_eq!(ca_outcome(Ok(false), true), CaOutcome::Failed);
    assert_eq!(ca_outcome(Ok(true), false), CaOutcome::Failed);
    assert_eq!(ca_outcome(Ok(true), true), CaOutcome::Done);
    assert_eq!(ca_outcome(Ok(false), false), CaOutcome::Done);

    let failed = anyhow::anyhow!("security add-trusted-cert failed: boom");
    assert_eq!(ca_outcome(Err(failed), true), CaOutcome::Failed);

    assert_eq!(CaOutcome::Cancelled.message(), Some("已取消，未做更改"));
    assert_eq!(CaOutcome::Failed.message(), Some("未成功，请重试"));
    assert_eq!(CaOutcome::Done.message(), None);
}

#[test]
fn probe_sweep_phases_drive_the_display() {
    let config = serde_json::json!({
        "groups": [
            { "id": "flip", "name": "Flip", "enabled": true, "domains": domains(&["flip.example"]) }
        ]
    });

    // While the sweep runs, every active site holds 测速中.
    let status_bad = serde_json::json!({
        "domains": [{ "domain": "flip.example", "state": "failed" }]
    });
    let (sites, _) = build_snapshot(
        &status_bad,
        &config,
        &HashSet::new(),
        true,
        false,
        Some(ui_state::SettlePhase::Sweeping),
    );
    assert_eq!(sites[0].summary, "1 个域名 · 测速中");

    // When the sweep finishes the fresh results commit at once.
    let status_slow = serde_json::json!({
        "domains": [{ "domain": "flip.example", "state": "normal", "latencyMs": 200 }]
    });
    let (sites, _) = build_snapshot(
        &status_slow,
        &config,
        &HashSet::new(),
        true,
        false,
        Some(ui_state::SettlePhase::Commit),
    );
    assert_eq!(sites[0].summary, "1 个域名 · 全部较慢");

    // Afterwards background tracking keeps a brief flip from showing.
    let (sites, _) = build_snapshot(
        &status_bad,
        &config,
        &HashSet::new(),
        true,
        false,
        Some(ui_state::SettlePhase::Tracking),
    );
    assert_eq!(sites[0].summary, "1 个域名 · 全部较慢");
}

#[test]
fn icon_keys_match_whole_ids_and_slugs_only() {
    assert_eq!(icon_key_for("eh"), "eh");
    assert_eq!(icon_key_for("ao3"), "ao3");
    // A site added from pixiv.net gets the slug `pixiv-net`.
    assert_eq!(icon_key_for("pixiv-net"), "pixiv");
    // Must not hand the E-Hentai logo to a slug that merely contains "eh".
    assert_eq!(icon_key_for("mehta-com"), "");
    // Sites that ship their own logo match by id.
    assert_eq!(icon_key_for("google"), "google");
    assert_eq!(icon_key_for("hanime"), "hanime");
    assert_eq!(icon_key_for("nhentai"), "nhentai");
    // The catalog id and the homepage slug must reach the same logo.
    assert_eq!(icon_key_for("hf"), "hf");
    assert_eq!(icon_key_for("huggingface-co"), "huggingface");
}

/// A logo that ships as an asset but no group id can reach it is dead weight;
/// one that groups can reach but has no asset leaves a letter tile behind.
#[test]
fn bundled_logos_and_group_lookups_stay_in_sync() {
    let assets: std::collections::HashSet<&str> = crate::assets::logo_keys().into_iter().collect();
    for key in SITE_ICONS {
        assert!(assets.contains(key), "{key} is matched but not embedded");
    }
    for key in &assets {
        assert_eq!(
            icon_key_for(key),
            *key,
            "{key} is embedded but never matched"
        );
    }
}

/// Decoding happens at startup and failures are silent, so a broken PNG would
/// quietly turn every tile of that site back into a letter.
#[test]
fn every_bundled_logo_decodes() {
    assert!(
        crate::assets::every_logo_decodes(),
        "a bundled logo did not decode"
    );
}

/// The Android shell keeps its own copy of every logo. Both trees have drifted
/// before (a fully transparent booth.png sat on each side), so an asset has to
/// land in both places. Skipped when only the desktop crate is checked out.
#[test]
fn android_drawables_match_the_desktop_assets() {
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    let android = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../android/probe/res/drawable-nodpi");
    if !android.is_dir() {
        return;
    }
    for entry in std::fs::read_dir(&assets).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        // Window and tray icons belong to the app shell, not to a site.
        if !name.ends_with(".png") || name == "app-icon.png" || name == "tray.png" {
            continue;
        }
        let mirror = android.join(format!("site_{name}"));
        let other = std::fs::read(&mirror)
            .unwrap_or_else(|_| panic!("{name} has no Android copy at {}", mirror.display()));
        let here = std::fs::read(assets.join(&name)).unwrap();
        assert_eq!(here, other, "{name} differs between desktop and Android");
    }
}

fn draft_with(id: &str, is_new: bool, rows: Vec<DomainDraft>, preset: i32) -> SiteDraft {
    SiteDraft {
        id: id.into(),
        is_new,
        name: String::new(),
        domains: rows,
        homepage: String::new(),
        default_preset: preset,
        default_custom: String::new(),
        default_sni: String::new(),
        verify: 0,
    }
}

#[test]
fn new_site_homepage_is_normalized_and_optional() {
    let config = AppConfig::default();
    let mut site = draft(vec![row("www.example.com", 0)], 0);

    // Blank means "use the first exact domain" at render time.
    assert_eq!(build_group(&config, &site).unwrap().homepage, None);

    site.homepage = "example.com".into();
    assert_eq!(
        build_group(&config, &site).unwrap().homepage.as_deref(),
        Some("https://example.com")
    );

    site.homepage = "https://www.example.com/path".into();
    assert_eq!(
        build_group(&config, &site).unwrap().homepage.as_deref(),
        Some("https://www.example.com/path")
    );

    site.homepage = "file:///etc/passwd".into();
    assert!(build_group(&config, &site).is_err());
}

#[test]
fn editing_a_site_keeps_its_id_and_per_domain_routes() {
    let config = AppConfig::default();

    let group = build_group(
        &config,
        &draft_with(
            "pixiv",
            false,
            vec![
                row("pixiv.net", 2),
                row("www.pixiv.net", 2),
                row_with_sni("*.pximg.net", "www.baidu.com"),
            ],
            0,
        ),
    )
    .unwrap();

    assert_eq!(group.id, "pixiv");
    assert_eq!(group.default_route, RoutePolicy::auto());
    assert_eq!(group.domains.len(), 3);
    assert_eq!(
        group.domains[2].route.as_ref().unwrap().attempts[0].mode(),
        hakimi_core::strategy::TlsMode::FakeSni
    );
}

#[test]
fn generated_ids_avoid_existing_groups() {
    let mut config = AppConfig::default();
    let mut taken = config.group("pixiv").unwrap().clone();
    taken.id = "example-com".into();
    taken.domains = vec![DomainRule::new("other.example")];
    config.groups.push(taken);

    let group = build_group(&config, &draft(vec![row("example.com", 0)], 0)).unwrap();
    assert_eq!(group.id, "example-com-2");
}

#[test]
fn domain_rows_are_lowercased_and_deduped() {
    let config = AppConfig::default();
    let group = build_group(
        &config,
        &draft(vec![row("Example.COM", 0), row("example.com", 0)], 0),
    )
    .unwrap();
    assert_eq!(group.domains.len(), 1);
    assert_eq!(group.domains[0].pattern, "example.com");
    assert_eq!(
        group.name, "example.com",
        "name falls back to the first domain"
    );
}

#[test]
fn sni_hostnames_are_normalized() {
    let config = AppConfig::default();
    let group = build_group(
        &config,
        &draft(vec![row_with_sni("example.com", "WWW.Baidu.COM")], 0),
    )
    .unwrap();
    let route = group.domains[0].route.as_ref().unwrap();
    assert_eq!(
        route.attempts[0],
        RouteAttempt::Sni {
            sni: vec!["www.baidu.com".into()]
        }
    );
}

#[test]
fn rejects_malformed_sni() {
    let config = AppConfig::default();
    assert!(build_group(
        &config,
        &draft(vec![row_with_sni("example.com", "not a host")], 0)
    )
    .is_err());
}

#[test]
fn pasted_urls_contribute_their_host() {
    let config = AppConfig::default();
    let group = build_group(
        &config,
        &draft(
            vec![
                row("https://www.example.com/en/", 0),
                row("HTTPS://cdn.example.net:8443/x?q=1", 0),
            ],
            0,
        ),
    )
    .unwrap();
    assert_eq!(
        group
            .domains
            .iter()
            .map(|rule| rule.pattern.as_str())
            .collect::<Vec<_>>(),
        vec!["www.example.com", "cdn.example.net"]
    );
    assert_eq!(group.name, "www.example.com");
}

#[test]
fn urls_without_a_usable_host_are_rejected() {
    let config = AppConfig::default();
    for input in ["https://", "https:///path", "://example.com"] {
        let error = build_group(&config, &draft(vec![row(input, 0)], 0)).unwrap_err();
        assert!(
            format!("{error:#}").contains("网址"),
            "{input} should read as a URL problem: {error:#}"
        );
    }
}

#[test]
fn rejects_an_empty_domain_list() {
    let config = AppConfig::default();
    assert!(build_group(&config, &draft(Vec::new(), 0)).is_err());
    assert!(build_group(&config, &draft(vec![row("  ", 0)], 0)).is_err());
}

#[test]
fn route_presets_round_trip_through_the_editor() {
    for preset in 0..=3 {
        let route = route_from_preset(preset).unwrap();
        assert_eq!(route_preset_index(&route), preset);
        assert_eq!(parse_route(&format_route(&route)).unwrap(), route);
    }
    let custom = parse_route("ech:own+sni:www.baidu.com+direct").unwrap();
    assert_eq!(route_preset_index(&custom), 4);
    assert_eq!(parse_route(&format_route(&custom)).unwrap(), custom);
}

fn snapshot() -> (Vec<SiteData>, String) {
    let config = serde_json::json!({
        "groups": [
            { "id": "ok", "name": "OK", "enabled": true,
              "domains": domains(&["a.example", "b.example"]) },
            { "id": "slow", "name": "Slow", "enabled": true,
              "domains": domains(&["c.example"]) },
            { "id": "bad", "name": "Bad", "enabled": true,
              "domains": domains(&["d.example"]) },
            { "id": "off", "name": "Off", "enabled": false,
              "domains": domains(&["e.example"]) }
        ]
    });
    let status = serde_json::json!({
        "domains": [
            { "domain": "a.example", "state": "normal", "latencyMs": 20 },
            { "domain": "b.example", "state": "normal", "latencyMs": 30 },
            { "domain": "c.example", "state": "normal", "latencyMs": 200 },
            { "domain": "d.example", "state": "failed" },
            { "domain": "e.example", "state": "normal", "latencyMs": 20 }
        ]
    });
    build_snapshot(&status, &config, &HashSet::new(), true, false, None)
}

#[test]
fn visit_urls_use_canonical_homepages() {
    let config = serde_json::json!({
        "groups": [
            { "id": "github", "name": "GitHub", "enabled": true, "domains": domains(&["github.com"]) },
            { "id": "pixiv", "name": "Pixiv", "enabled": true, "domains": domains(&["pixiv.net", "www.pixiv.net"]), "homepage": "https://www.pixiv.net/" },
            { "id": "ao3", "name": "AO3", "enabled": true, "domains": domains(&["archiveofourown.org"]) },
            { "id": "eh", "name": "E-Hentai", "enabled": true, "domains": domains(&["e-hentai.org"]) },
            { "id": "hitomi", "name": "Hitomi", "enabled": true, "domains": domains(&["hitomi.la"]) },
            { "id": "hanime", "name": "Hanime", "enabled": true, "domains": domains(&["hanime.tv"]) },
            { "id": "steam", "name": "Steam", "enabled": true, "domains": domains(&["store.steampowered.com"]) },
            { "id": "poipiku", "name": "Poipiku", "enabled": true, "domains": domains(&["poipiku.com"]) },
            { "id": "custom", "name": "Custom", "enabled": true, "domains": domains(&["custom.example", "*.custom.example"]), "homepage": "https://custom-home.example/" },
            { "id": "fallback", "name": "Fallback", "enabled": true, "domains": domains(&["fallback.example"]) },
            { "id": "wild", "name": "Wild", "enabled": true, "domains": domains(&["*.wild.example"]) }
        ]
    });
    let status = serde_json::json!({ "domains": [] });
    let (sites, _) = build_sites(&status, &config, &HashSet::new());
    let url = |id: &str| {
        sites
            .iter()
            .find(|site| site.id == id)
            .unwrap()
            .url
            .as_str()
    };

    assert_eq!(url("pixiv"), "https://www.pixiv.net/");
    assert_eq!(url("github"), "https://github.com/");
    assert_eq!(url("ao3"), "https://archiveofourown.org/");
    assert_eq!(url("eh"), "https://e-hentai.org/");
    assert_eq!(url("hitomi"), "https://hitomi.la/");
    assert_eq!(url("hanime"), "https://hanime.tv/");
    assert_eq!(url("steam"), "https://store.steampowered.com/");
    assert_eq!(url("poipiku"), "https://poipiku.com/");
    assert_eq!(url("custom"), "https://custom-home.example/");
    assert_eq!(url("fallback"), "https://fallback.example/");
    assert_eq!(url("wild"), "https://wild.example/");
}

#[test]
fn site_summaries_reflect_state_with_matching_colours() {
    let (sites, _) = snapshot();
    let by_id = |id: &str| sites.iter().find(|site| site.id == id).unwrap();

    assert_eq!(by_id("ok").summary, "2 个域名 · 全部正常");
    assert_eq!(by_id("ok").summary_hex, OK_COLOR);

    assert_eq!(by_id("slow").summary, "1 个域名 · 全部较慢");
    assert_eq!(by_id("slow").summary_hex, SLOW_COLOR);

    assert_eq!(by_id("bad").summary, "1 个域名 · 全部超时");
    assert_eq!(by_id("bad").summary_hex, BAD_COLOR);

    assert_eq!(by_id("off").summary, "1 个域名 · 未选择");
    assert_eq!(by_id("off").summary_hex, IDLE_COLOR);
}

#[test]
fn paused_snapshot_still_reports_health() {
    let config = serde_json::json!({
        "groups": [
            { "id": "ok", "name": "OK", "enabled": true, "domains": domains(&["a.example"]) }
        ]
    });
    let status = serde_json::json!({ "domains": [
        { "domain": "a.example", "state": "failed" }
    ]});
    let (sites, subtitle) = build_snapshot(&status, &config, &HashSet::new(), false, false, None);
    assert_eq!(
        sites[0].summary, "1 个域名 · 全部超时",
        "pause is a routing state, not a health result"
    );
    assert_eq!(sites[0].summary_hex, BAD_COLOR);
    assert_eq!(subtitle, "已选择 1 个站点 · 1 个异常 · 加速已暂停");
}

#[test]
fn selected_but_untested_sites_point_to_the_explicit_action() {
    let config = serde_json::json!({
        "groups": [
            { "id": "ok", "name": "OK", "enabled": true, "domains": domains(&["a.example"]) }
        ]
    });
    let status = serde_json::json!({ "domains": [] });
    let (sites, subtitle) = build_snapshot(&status, &config, &HashSet::new(), true, false, None);
    assert_eq!(sites[0].summary, "1 个域名 · 待检测");
    assert_eq!(
        subtitle, "已选择 1 个站点 · 点击检测选中获取健康状态",
        "selection must not imply a test; the subtitle names the explicit action"
    );
}

#[test]
fn a_sweep_is_visible_while_paused() {
    let config = serde_json::json!({
        "groups": [
            { "id": "ok", "name": "OK", "enabled": true, "domains": domains(&["a.example"]) }
        ]
    });
    let status = serde_json::json!({ "domains": [] });
    let (sites, subtitle) = build_snapshot(
        &status,
        &config,
        &HashSet::new(),
        false,
        false,
        Some(SettlePhase::Sweeping),
    );
    assert_eq!(sites[0].summary, "1 个域名 · 测速中");
    assert_eq!(subtitle, "正在检测 1 个域名 · 结果会自动更新");
}

#[test]
fn custom_groups_are_marked_for_deletion() {
    let builtins = builtin_group_ids();
    assert!(builtins.contains("pixiv"), "bundled ids stay undeletable");
    assert!(!builtins.contains("mine"), "user ids are deletable");
}

/// The settings page shows the host list as one comma-separated line, the same
/// shape the fake-SNI field uses.
#[test]
fn the_http1_host_list_round_trips_through_the_settings_field() {
    let mut config = AppConfig::default();
    config.advanced.http1_hosts = vec![
        "i.pximg.net".into(),
        "s.pximg.net".into(),
        "cdn.example.com".into(),
    ];
    let json = serde_json::to_value(&config).unwrap();
    let values = crate::settings_values(&json);
    assert_eq!(
        values.http1_hosts,
        "i.pximg.net, s.pximg.net, cdn.example.com"
    );

    // The editor parses the same shape back: commas, arbitrary spaces, and an
    // empty entry from a trailing comma all collapse to the list.
    assert_eq!(
        split_entries(" i.pximg.net ,, s.pximg.net , "),
        vec!["i.pximg.net", "s.pximg.net"]
    );
}

/// An empty list is a legitimate choice, not an error: it turns the feature off
/// for every host.
#[test]
fn an_empty_http1_host_list_is_accepted() {
    let mut config = AppConfig::default();
    config.advanced.http1_hosts = Vec::new();
    let json = serde_json::to_value(&config).unwrap();
    assert_eq!(crate::settings_values(&json).http1_hosts, "");
    assert!(config.validate().is_ok(), "an empty list must validate");
}

/// A login launch is silent, `--show` overrides every hidden source, and a
/// saved "start hidden" preference only applies to launches without `--show`.
#[test]
fn the_initial_window_follows_the_launch_flags() {
    let hidden = |autostart, hide, show, config_hidden| {
        crate::starts_hidden(
            crate::LaunchOptions {
                autostart,
                hidden: hide,
                show,
            },
            config_hidden,
        )
    };
    assert!(
        hidden(true, false, false, false),
        "a login launch is silent"
    );
    assert!(hidden(false, true, false, false), "--hidden is one-shot");
    assert!(hidden(false, false, false, true), "the saved preference");
    assert!(!hidden(false, false, false, false));
    assert!(!hidden(true, false, true, true), "--show wins");
    assert!(!hidden(false, true, true, true), "--show wins");
}

#[test]
fn launch_flags_are_parsed_from_the_command_line() {
    let args: Vec<String> = ["--autostart", "--hidden", "--show"]
        .iter()
        .map(|value| value.to_string())
        .collect();
    let options = crate::launch_options(&args);
    assert!(options.autostart && options.hidden && options.show);
    let empty = crate::launch_options(&[]);
    assert!(!empty.autostart && !empty.hidden && !empty.show);
}

/// The startup switches read from the nested `advanced.startup` section; a
/// config written before the section existed must read as all-off instead of
/// failing to load.
#[test]
fn startup_switches_default_to_off_and_follow_the_config() {
    let values = crate::settings_values(&serde_json::json!({ "advanced": {} }));
    assert!(!values.auto_start && !values.start_hidden && !values.auto_connect);

    let mut config = AppConfig::default();
    config.advanced.startup.auto_start = true;
    config.advanced.startup.start_hidden = true;
    config.advanced.startup.auto_connect = true;
    let json = serde_json::to_value(&config).unwrap();
    let values = crate::settings_values(&json);
    assert!(values.auto_start && values.start_hidden && values.auto_connect);
}

/// The download card must show the shipped concurrency ceiling even though a
/// file whose `advanced.download` still matches the defaults omits the whole
/// section.
#[test]
fn download_controls_show_defaults_and_follow_the_config() {
    let values = crate::settings_values(&serde_json::json!({ "advanced": {} }));
    assert!(values.download_enabled);
    assert_eq!(values.download_segments, "12");

    let mut config = AppConfig::default();
    config.advanced.download.enabled = false;
    config.advanced.download.segments = 8;
    let json = serde_json::to_value(&config).unwrap();
    let values = crate::settings_values(&json);
    assert!(!values.download_enabled);
    assert_eq!(values.download_segments, "8");

    // The runtime clamps to 2..=12; the picker must show the effective value.
    config.advanced.download.segments = 1;
    let json = serde_json::to_value(&config).unwrap();
    assert_eq!(crate::settings_values(&json).download_segments, "2");
}

/// The caption must name only the scenarios where the engine lands below the
/// chosen ceiling: below 6 the pill already says everything, and a wrong merge
/// condition would either lie or leak an empty line.
#[test]
fn the_concurrency_caption_names_only_truncated_scenarios() {
    use crate::view::settings::concurrency_caption;

    for value in [2, 3, 4, 5, 6] {
        assert!(concurrency_caption(value).is_empty(), "{value} must stay silent");
    }
    assert_eq!(concurrency_caption(7), "镜像 6");
    assert_eq!(concurrency_caption(8), "镜像 6");
    assert_eq!(concurrency_caption(12), "小文件 8 · 镜像 6");
    assert_eq!(concurrency_caption(64), "大文件 12 · 小文件 8 · 镜像 6");
}

/// The card must render the shipped relay without the user typing anything:
/// the values come from the config snapshot, which carries the defaults.
#[test]
fn the_settings_card_shows_the_shipped_image_relay() {
    let config = serde_json::to_value(hakimi_core::config::AppConfig::default()).unwrap();
    let settings = settings_values(&config);
    assert!(settings.image_relay_enabled);
    assert_eq!(settings.image_relay_base, "https://pic-relay.cyou/pximg");
    assert_eq!(settings.image_relay_hosts, "i.pximg.net");
    assert_eq!(settings.image_relay_paths, "/img-original/, /img-master/");
    assert_eq!(settings.image_relay_user_agent, "Piku/3.7.0");
    assert!(settings.image_relay_fallback);
}

/// The hosts and paths fields are comma separated. A Chinese input method
/// emits `，`, and an unsplit entry made the host list invalid and the path
/// list match nothing at all.
#[test]
fn comma_separated_fields_split_on_both_commas() {
    assert_eq!(
        split_entries("/img-original/, /img-master/"),
        ["/img-original/", "/img-master/"]
    );
    assert_eq!(
        split_entries("/img-original/，/img-master/"),
        ["/img-original/", "/img-master/"]
    );
    assert_eq!(
        split_entries(" i.pximg.net ， s.pximg.net ,,"),
        ["i.pximg.net", "s.pximg.net"]
    );
    assert!(split_entries("   ").is_empty());
    assert_eq!(
        parse_sni_hosts("a.example.com，B.Example.com ").unwrap(),
        ["a.example.com", "b.example.com"]
    );
}

/// The status card counts, it does not judge: an endpoint nobody has observed
/// yet is neutral, never a failure — otherwise the panel flashes red every
/// time the window opens.
#[test]
fn doh_summary_separates_unprobed_from_failed() {
    assert_eq!(doh_summary(2, 0, 0), ("未检测".to_string(), TONE_NEUTRAL));
    assert_eq!(doh_summary(2, 2, 2), ("2/2 可用".to_string(), TONE_OK));
    assert_eq!(
        doh_summary(4, 4, 3),
        ("3/4 可用".to_string(), TONE_DEGRADED)
    );
    assert_eq!(doh_summary(4, 4, 0), ("0/4 可用".to_string(), TONE_BROKEN));
    // Half probed and healthy so far: still counting, no verdict yet — and a
    // lone failure while the rest are in flight must not read as 0/4 broken.
    assert_eq!(doh_summary(4, 2, 2), ("2/4 可用".to_string(), TONE_NEUTRAL));
    assert_eq!(doh_summary(4, 1, 0), ("0/4 可用".to_string(), TONE_NEUTRAL));
    assert_eq!(doh_summary(0, 0, 0), ("未配置".to_string(), TONE_BROKEN));
}

/// The source doubles as the switch, so an empty one reads as off rather than
/// as a mirror list that failed to load.
#[test]
fn mirror_summary_treats_an_empty_source_as_off() {
    assert_eq!(
        mirror_summary(false, 5, 5),
        ("已关闭".to_string(), TONE_NEUTRAL)
    );
    assert_eq!(
        mirror_summary(true, 0, 0),
        ("更新中".to_string(), TONE_NEUTRAL)
    );
    assert_eq!(
        mirror_summary(true, 2, 2),
        ("2/2 可用".to_string(), TONE_OK)
    );
    assert_eq!(
        mirror_summary(true, 3, 2),
        ("2/3 可用".to_string(), TONE_DEGRADED)
    );
    assert_eq!(
        mirror_summary(true, 3, 0),
        ("0/3 可用".to_string(), TONE_BROKEN)
    );
}

fn doh_endpoint(name: &str, url: &str) -> EffectiveEndpoint {
    EffectiveEndpoint {
        name: name.into(),
        url: url.into(),
        bootstrap_ip: None,
        source: DohSource::Primary,
    }
}

/// A health record is keyed by URL. Matching by name would leave the failed
/// endpoint reading "未检测" forever, which is exactly what a half-configured
/// fallback looks like in the panel. A synthesized entry (observed=false)
/// reads the same neutral "未检测" as a missing one.
#[test]
fn doh_rows_keep_unprobed_neutral_and_show_the_failure_detail() {
    let endpoints = vec![
        doh_endpoint(
            "cleanbrowsing",
            "https://doh.cleanbrowsing.org/doh/security-filter",
        ),
        doh_endpoint("fallback", "https://doh.example/query"),
    ];

    let unprobed = doh_entries(&endpoints, &[]);
    assert_eq!(unprobed.len(), 2);
    assert_eq!(
        (unprobed[0].value.as_str(), unprobed[0].tone),
        ("未检测", TONE_NEUTRAL)
    );
    assert_eq!(unprobed[0].detail, "doh.cleanbrowsing.org");

    let observed = vec![DohObservation {
        url: endpoints[1].url.clone(),
        healthy: false,
        observed: true,
        latency_ms: None,
        last_error: Some("TCP 超时".into()),
    }];
    let rows = doh_entries(&endpoints, &observed);
    assert_eq!(
        (rows[0].value.as_str(), rows[0].tone),
        ("未检测", TONE_NEUTRAL)
    );
    assert_eq!(
        (rows[1].value.as_str(), rows[1].tone),
        ("失败", TONE_BROKEN)
    );
    assert_eq!(rows[1].detail, "TCP 超时");
}

#[test]
fn doh_rows_format_latency_and_explain_an_empty_config() {
    let endpoints = vec![doh_endpoint(
        "cleanbrowsing",
        "https://doh.cleanbrowsing.org",
    )];
    let observed = vec![DohObservation {
        url: endpoints[0].url.clone(),
        healthy: true,
        observed: true,
        latency_ms: Some(28),
        last_error: None,
    }];
    let rows = doh_entries(&endpoints, &observed);
    assert_eq!((rows[0].value.as_str(), rows[0].tone), ("28 ms", TONE_OK));
    assert_eq!(rows[0].detail, "doh.cleanbrowsing.org");

    let none = doh_entries(&[], &[]);
    assert_eq!(none.len(), 1);
    assert_eq!(none[0].label, "未配置 DoH");
}

/// An empty source is off, not a broken mirror list. A cooling prefix must read
/// as degraded with its retry time, and a repeatedly failing one as broken.
#[test]
fn mirror_rows_separate_off_updating_and_cooldown() {
    let off = mirror_entries(false, &[]);
    assert_eq!(off.len(), 1);
    assert_eq!(
        (off[0].value.as_str(), off[0].tone),
        ("已关闭", TONE_NEUTRAL)
    );
    assert_eq!(mirror_entries(true, &[])[0].value, "更新中");

    let status = vec![
        MirrorStatus {
            prefix: "https://gh-proxy.com".into(),
            cooldown_secs: 0,
            failures: 0,
        },
        MirrorStatus {
            prefix: "https://ghfast.top/".into(),
            cooldown_secs: 292,
            failures: 2,
        },
        MirrorStatus {
            prefix: "https://dead.example".into(),
            cooldown_secs: 900,
            failures: 3,
        },
    ];
    let rows = mirror_entries(true, &status);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].label, "gh-proxy.com");
    assert_eq!((rows[0].value.as_str(), rows[0].tone), ("可用", TONE_OK));
    assert_eq!(rows[1].value, "冷却 4:52");
    assert_eq!(rows[1].tone, TONE_DEGRADED);
    assert_eq!(rows[2].tone, TONE_BROKEN);
}

#[test]
fn adding_a_domain_keeps_the_existing_rows_alive() {
    let mut rows = crate::app_state::with_editor_rows(|| {
        (0..2)
            .map(|i| crate::EditorRowState::new(i, "a.com", 0, "", ""))
            .collect::<Vec<_>>()
    });
    let first_pattern = rows[0].pattern;

    let index = rows.len();
    crate::app_state::with_new_editor_row(|| {
        rows.push(crate::EditorRowState::new(index, "", 0, "", ""));
    });

    // The row that was already mounted still reads: rotating the generation
    // here would have disposed this slot.
    assert_eq!(first_pattern.get(), "a.com");
    assert!(rows[2].pattern.is_alive());
}

#[test]
fn repeated_editor_opens_reach_a_steady_state() {
    let build = || {
        crate::app_state::with_editor_rows(|| {
            (0..5)
                .map(|i| crate::EditorRowState::new(i, "a.com", 0, "", ""))
                .collect::<Vec<_>>()
        })
    };
    // Warm up to the steady state: two generations are live by design.
    for _ in 0..4 {
        std::hint::black_box(build());
    }
    let settled = windui::signal::stats().live;
    for _ in 0..20 {
        std::hint::black_box(build());
    }
    let after = windui::signal::stats().live;
    assert_eq!(
        after, settled,
        "live signal count kept growing across editor opens ({settled} -> {after}); \
         the per-generation reclaim is not running"
    );
}

#[test]
fn the_mirror_source_falls_back_to_the_default_only_when_absent() {
    let base = serde_json::to_value(AppConfig::default()).unwrap();

    let mut omitted = base.clone();
    omitted.as_object_mut().unwrap().remove("advanced");
    assert_eq!(
        settings_values(&omitted).mirror_source,
        hakimi_core::config::DownloadConfig::default().mirror_source,
        "a missing `advanced` section must not blank the mirror list"
    );

    let mut switched_off = base.clone();
    switched_off["advanced"]["download"]["mirrorSource"] = serde_json::json!("");
    assert_eq!(
        settings_values(&switched_off).mirror_source,
        "",
        "an explicit empty string is the user switching it off"
    );

    let mut custom = base;
    custom["advanced"]["download"]["mirrorSource"] =
        serde_json::json!("https://example.test/mirrors.json");
    assert_eq!(
        settings_values(&custom).mirror_source,
        "https://example.test/mirrors.json"
    );
}

#[test]
fn the_catalog_urls_fall_back_to_the_default_only_when_absent() {
    let base = serde_json::to_value(AppConfig::default()).unwrap();
    let defaults = hakimi_core::config::CatalogSources::default();

    let mut omitted = base.clone();
    omitted.as_object_mut().unwrap().remove("catalogs");
    let values = settings_values(&omitted);
    assert_eq!(values.catalog_ip, defaults.ip);
    assert_eq!(values.catalog_doh, defaults.doh);

    let mut cleared = base;
    cleared["catalogs"]["ip"] = serde_json::json!("");
    cleared["catalogs"]["doh"] = serde_json::json!("");
    let values = settings_values(&cleared);
    assert_eq!(
        values.catalog_ip, "",
        "an explicit empty string means disabled"
    );
    assert_eq!(values.catalog_doh, "");
}

#[test]
fn footer_buttons_are_hittable_next_to_a_flex_spacer() {
    use windui::core::Tree;
    use windui::text::NullTextEngine;

    // Same shape as the fix-page footer: [text_button][flex_spacer][button].
    let mut tree = Tree::new();
    let row = Element::row()
        .width(520)
        .height(30)
        .child(
            Element::row()
                .height(30)
                .min_width(44)
                .clickable()
                .on_click(|_| {})
                .child(Element::label("暂不处理").font_size(12.5)),
        )
        .child(Element::flex_spacer())
        .child(Element::button("完成").min_width(96).height(30))
        .build(&mut tree);
    tree.root = Some(row);
    tree.layout_root(Size::new(560, 40), &mut NullTextEngine);

    let kids = tree.get(row).unwrap().children.clone();
    assert_eq!(kids.len(), 3, "footer row must have three children");
    let (first, spacer, second) = (kids[0], kids[1], kids[2]);
    let center = |id| {
        let b = tree.abs_bounds(id);
        windui::geometry::Point::new(b.x + b.w / 2, b.y + b.h / 2)
    };
    let hit_first = tree.hit_test(center(first));
    let hit_second = tree.hit_test(center(second));
    let in_subtree = |hit, root| {
        let mut cur = Some(hit);
        while let Some(id) = cur {
            if id == root {
                return true;
            }
            cur = tree.get(id).and_then(|n| n.parent);
        }
        false
    };
    assert!(
        hit_first.is_some_and(|h| in_subtree(h, first)),
        "first button center must resolve inside it, got {:?}",
        hit_first
    );
    assert!(
        hit_second.is_some_and(|h| in_subtree(h, second)),
        "second button center must resolve inside it, got {:?}",
        hit_second
    );
    // The spacer itself must never swallow a click aimed at either button.
    assert!(
        hit_first != Some(spacer) && hit_second != Some(spacer),
        "the flex spacer must not be the hit target"
    );
}
