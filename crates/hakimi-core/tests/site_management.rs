//! Site management round-trips: what the editor writes must survive a reload,
//! and edits must replace rather than duplicate.

use hakimi_core::config::{ConfigManager, GroupConfig};
use hakimi_core::paths::Paths;
use hakimi_core::strategy::Strategy;

fn group(id: &str, name: &str, domains: &[&str]) -> GroupConfig {
    GroupConfig {
        id: id.into(),
        name: name.into(),
        domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
        strategy: Strategy::Auto,
        enabled: true,
        ..Default::default()
    }
}

#[test]
fn added_sites_survive_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());

    {
        let config = ConfigManager::load_or_create(&paths).unwrap();
        let mut site = group("custom", "Custom", &["custom.example", "*.custom.example"]);
        site.strategy = Strategy::FakeSni;
        site.sni = Some("www.baidu.com".into());
        config.upsert_group(site).unwrap();
    }

    let reloaded = ConfigManager::load_or_create(&paths).unwrap();
    let site = reloaded.snapshot().group("custom").cloned().unwrap();
    assert_eq!(site.name, "Custom");
    assert_eq!(site.domains, vec!["custom.example", "*.custom.example"]);
    assert_eq!(site.strategy, Strategy::FakeSni);
    assert_eq!(site.sni.as_deref(), Some("www.baidu.com"));
}

#[test]
fn editing_a_site_replaces_it_instead_of_duplicating() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let config = ConfigManager::load_or_create(&paths).unwrap();

    let mut site = group("custom", "Custom", &["custom.example"]);
    config.upsert_group(site.clone()).unwrap();

    site.domains = vec!["custom.example".into(), "cdn.custom.example".into()];
    site.name = "Renamed".into();
    config.upsert_group(site).unwrap();

    let snapshot = config.snapshot();
    let matches: Vec<_> = snapshot
        .groups
        .iter()
        .filter(|group| group.id == "custom")
        .collect();
    assert_eq!(matches.len(), 1, "editing must not append a second group");
    assert_eq!(matches[0].name, "Renamed");
    assert_eq!(matches[0].domains.len(), 2);
}

#[test]
fn removed_sites_disappear_and_stay_gone() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let config = ConfigManager::load_or_create(&paths).unwrap();

    config
        .upsert_group(group("custom", "Custom", &["custom.example"]))
        .unwrap();
    config.remove_group("custom").unwrap();
    assert!(config.snapshot().group("custom").is_none());

    let reloaded = ConfigManager::load_or_create(&paths).unwrap();
    assert!(reloaded.snapshot().group("custom").is_none());
}

#[test]
fn removing_an_unknown_site_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path());
    let config = ConfigManager::load_or_create(&paths).unwrap();
    assert!(config.remove_group("does-not-exist").is_err());
}
