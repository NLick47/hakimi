use super::*;
use crate::ui_state::{BAD_COLOR, IDLE_COLOR, OK_COLOR, SLOW_COLOR};

fn draft(domains: &str, strategy: Strategy, sni: &str) -> SiteDraft {
    SiteDraft {
        id: String::new(),
        is_new: true,
        name: String::new(),
        domains: domains.into(),
        homepage: String::new(),
        strategy,
        sni: sni.into(),
    }
}

#[test]
fn new_site_gets_a_config_safe_id() {
    let config = AppConfig::default();
    let group = build_group(&config, &draft("www.example.com", Strategy::Auto, "")).unwrap();
    assert_eq!(group.id, "www-example-com");
    assert_eq!(group.name, "www.example.com");
    assert!(group.enabled);
    assert_eq!(group.sni, None);
}

#[test]
fn empty_sni_is_preserved_for_fake_sni() {
    let config = AppConfig::default();
    let group = build_group(&config, &draft("example.com", Strategy::FakeSni, " ")).unwrap();
    assert_eq!(group.sni.as_deref(), Some(""));
}

#[test]
fn sni_is_dropped_for_other_strategies() {
    let config = AppConfig::default();
    let group = build_group(&config, &draft("example.com", Strategy::Ech, "")).unwrap();
    assert_eq!(group.sni, None);
}

#[test]
fn rejects_domains_without_an_exact_entry() {
    let config = AppConfig::default();
    assert!(build_group(&config, &draft("*.example.com", Strategy::Auto, "")).is_err());
}

#[test]
fn rejects_domains_owned_by_another_group() {
    let config = AppConfig::default();
    let error = build_group(&config, &draft("github.com", Strategy::Auto, "")).unwrap_err();
    assert!(format!("{error:#}").contains("GitHub"));
}

#[test]
fn rejects_malformed_domains() {
    let config = AppConfig::default();
    assert!(build_group(&config, &draft("example..com", Strategy::Auto, "")).is_err());
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
            { "id": "flip", "name": "Flip", "enabled": true, "domains": ["flip.example"] }
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
    assert_eq!(icon_key_for("nhentai"), "nhentai");
    assert_eq!(icon_key_for("hanime"), "hanime");
}

fn draft_with(id: &str, is_new: bool, domains: &str, strategy: Strategy, sni: &str) -> SiteDraft {
    SiteDraft {
        id: id.into(),
        is_new,
        name: String::new(),
        domains: domains.into(),
        homepage: String::new(),
        strategy,
        sni: sni.into(),
    }
}

#[test]
fn new_site_homepage_is_normalized_and_optional() {
    let config = AppConfig::default();
    let mut site = draft("www.example.com", Strategy::Auto, "");

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
fn editing_a_site_keeps_its_id_and_shared_flags() {
    let mut config = AppConfig::default();
    let mut existing = config.group("pixiv").unwrap().clone();
    existing.ech_shared = true;
    existing.experimental = true;
    config.groups = vec![existing];

    let group = build_group(
        &config,
        &draft_with(
            "pixiv",
            false,
            "pixiv.net\nwww.pixiv.net",
            Strategy::FakeSni,
            "",
        ),
    )
    .unwrap();

    assert_eq!(group.id, "pixiv");
    assert!(group.ech_shared, "editing must not drop echShared");
    assert!(group.experimental, "editing must not drop experimental");
    assert_eq!(group.domains, vec!["pixiv.net", "www.pixiv.net"]);
}

#[test]
fn generated_ids_avoid_existing_groups() {
    let mut config = AppConfig::default();
    let mut taken = config.group("pixiv").unwrap().clone();
    taken.id = "example-com".into();
    taken.domains = vec!["other.example".into()];
    config.groups.push(taken);

    let group = build_group(&config, &draft("example.com", Strategy::Auto, "")).unwrap();
    assert_eq!(group.id, "example-com-2");
}

#[test]
fn domains_accept_commas_and_whitespace() {
    let config = AppConfig::default();
    let group = build_group(
        &config,
        &draft(
            "a.example, b.example，c.example\nd.example",
            Strategy::Auto,
            "",
        ),
    )
    .unwrap();
    assert_eq!(
        group.domains,
        vec!["a.example", "b.example", "c.example", "d.example"]
    );
}

#[test]
fn domains_are_lowercased_and_deduped() {
    let config = AppConfig::default();
    let group = build_group(
        &config,
        &draft("Example.COM example.com", Strategy::Auto, ""),
    )
    .unwrap();
    assert_eq!(group.domains, vec!["example.com"]);
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
        &draft("example.com", Strategy::FakeSni, "  WWW.Baidu.COM "),
    )
    .unwrap();
    assert_eq!(group.sni.as_deref(), Some("www.baidu.com"));
}

#[test]
fn rejects_malformed_sni() {
    let config = AppConfig::default();
    assert!(build_group(
        &config,
        &draft("example.com", Strategy::FakeSni, "not a host")
    )
    .is_err());
}

#[test]
fn pasted_urls_contribute_their_host() {
    let config = AppConfig::default();
    let group = build_group(
        &config,
        &draft(
            "https://www.example.com/en/\nHTTPS://cdn.example.net:8443/x?q=1",
            Strategy::Auto,
            "",
        ),
    )
    .unwrap();
    assert_eq!(group.domains, vec!["www.example.com", "cdn.example.net"]);
    assert_eq!(group.name, "www.example.com");
}

#[test]
fn urls_without_a_usable_host_are_rejected() {
    let config = AppConfig::default();
    for input in ["https://", "https:///path", "://example.com"] {
        let error = build_group(&config, &draft(input, Strategy::Auto, "")).unwrap_err();
        assert!(
            format!("{error:#}").contains("网址"),
            "{input} should read as a URL problem: {error:#}"
        );
    }
}

#[test]
fn rejects_an_empty_domain_list() {
    let config = AppConfig::default();
    assert!(build_group(&config, &draft(" ,  , ", Strategy::Auto, "")).is_err());
}

#[test]
fn strategies_round_trip_through_the_editor() {
    assert_eq!(
        strategy_from_index(editor_strategy_index(Strategy::Auto)),
        Strategy::Auto
    );
    assert_eq!(
        strategy_from_index(editor_strategy_index(Strategy::Ech)),
        Strategy::Ech
    );
    assert_eq!(
        strategy_from_index(editor_strategy_index(Strategy::FakeSni)),
        Strategy::FakeSni
    );
    // Direct is intentionally shown as Auto: auto already tries direct first.
    assert_eq!(editor_strategy_index(Strategy::Direct), 0);
}

fn snapshot() -> (Vec<SiteData>, String) {
    let config = serde_json::json!({
        "groups": [
            { "id": "ok", "name": "OK", "enabled": true,
              "domains": ["a.example", "b.example"] },
            { "id": "slow", "name": "Slow", "enabled": true,
              "domains": ["c.example"] },
            { "id": "bad", "name": "Bad", "enabled": true,
              "domains": ["d.example"] },
            { "id": "off", "name": "Off", "enabled": false,
              "domains": ["e.example"] }
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
            { "id": "github", "name": "GitHub", "enabled": true, "domains": ["github.com"] },
            { "id": "pixiv", "name": "Pixiv", "enabled": true, "domains": ["pixiv.net", "www.pixiv.net"], "homepage": "https://www.pixiv.net/" },
            { "id": "ao3", "name": "AO3", "enabled": true, "domains": ["archiveofourown.org"] },
            { "id": "eh", "name": "E-Hentai", "enabled": true, "domains": ["e-hentai.org"] },
            { "id": "hitomi", "name": "Hitomi", "enabled": true, "domains": ["hitomi.la"] },
            { "id": "nhentai", "name": "nhentai", "enabled": true, "domains": ["nhentai.net"] },
            { "id": "hanime", "name": "Hanime", "enabled": true, "domains": ["hanime.tv"] },
            { "id": "steam", "name": "Steam", "enabled": true, "domains": ["store.steampowered.com"] },
            { "id": "poipiku", "name": "Poipiku", "enabled": true, "domains": ["poipiku.com"] },
            { "id": "custom", "name": "Custom", "enabled": true, "domains": ["custom.example", "*.custom.example"], "homepage": "https://custom-home.example/" },
            { "id": "fallback", "name": "Fallback", "enabled": true, "domains": ["fallback.example"] },
            { "id": "wild", "name": "Wild", "enabled": true, "domains": ["*.wild.example"] }
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
    assert_eq!(url("nhentai"), "https://nhentai.net/");
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
            { "id": "ok", "name": "OK", "enabled": true, "domains": ["a.example"] }
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
            { "id": "ok", "name": "OK", "enabled": true, "domains": ["a.example"] }
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
            { "id": "ok", "name": "OK", "enabled": true, "domains": ["a.example"] }
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
    let config = serde_json::json!({
        "groups": [
            { "id": "pixiv", "name": "Pixiv", "enabled": true, "domains": ["pixiv.net"] },
            { "id": "mine", "name": "Mine", "enabled": true, "domains": ["mine.example"] }
        ]
    });
    let (sites, _) = build_snapshot(
        &serde_json::json!({}),
        &config,
        &HashSet::new(),
        true,
        false,
        None,
    );
    assert!(!sites.iter().find(|s| s.id == "pixiv").unwrap().custom);
    assert!(sites.iter().find(|s| s.id == "mine").unwrap().custom);
}
