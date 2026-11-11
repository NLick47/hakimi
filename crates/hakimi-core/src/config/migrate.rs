//! Configuration migrations: one static entry per historical shape change.
//!
//! Field renames live in serde (`alias`), not here — migrations only upgrade
//! shapes. Every `apply` is idempotent and leaves user-customized values alone.

use super::{AdvancedConfig, AppConfig, GroupConfig, ImageRelayRule, RoutePolicy};

/// Shape version this build writes. Bump when adding a migration; files
/// without the field deserialize as 0 and catch up in one load.
pub const SCHEMA_VERSION: u32 = 4;

type MigrationFn = fn(&mut AppConfig) -> bool;

struct Migration {
    /// Version that introduced the shape change, for logs only.
    version: &'static str,
    describe: &'static str,
    /// Run only for files whose schema_version is below this value. `None`
    /// means the migration is safe to run at any version.
    applies_below: Option<u32>,
    apply: MigrationFn,
}

static MIGRATIONS: &[Migration] = &[
    Migration {
        version: "0.1.2",
        describe: "legacy http1Hosts adopt the current defaults",
        applies_below: Some(2),
        apply: migrate_http1_hosts,
    },
    Migration {
        version: "0.1.2",
        describe: "poipiku auto route folds to direct",
        applies_below: Some(2),
        apply: migrate_poipiku_auto,
    },
    Migration {
        version: "0.1.3",
        describe: "poipiku apex adopts the no-SNI attempt",
        applies_below: Some(2),
        apply: migrate_poipiku_apex,
    },
    Migration {
        version: "0.1.8",
        describe: "http1Hosts gain the Pixiv asset CDN",
        applies_below: Some(3),
        apply: migrate_http1_hosts_asset_cdn,
    },
    Migration {
        version: "0.1.9",
        describe: "a half-created pixiv relay adopts the shipped address",
        applies_below: Some(4),
        apply: migrate_pixiv_relay,
    },
];

/// Run every applicable migration in order, then stamp the schema version.
/// Returns descriptions of the entries that changed the configuration.
pub(crate) fn run_migrations(config: &mut AppConfig) -> Vec<&'static str> {
    let mut applied = Vec::new();
    for migration in MIGRATIONS {
        if migration
            .applies_below
            .is_some_and(|limit| config.schema_version >= limit)
        {
            continue;
        }
        if (migration.apply)(config) {
            tracing::info!(
                version = migration.version,
                what = migration.describe,
                "config migration applied"
            );
            applied.push(migration.describe);
        }
    }
    config.schema_version = SCHEMA_VERSION;
    applied
}

/// Fold a field that still equals an old default onto the current one. A
/// user-pinned value that merely looks old folds too, which is why migrations
/// built on this stop running once the schema version catches up.
fn fold_default<T: PartialEq + Clone>(field: &mut T, old_default: &T, current_default: &T) -> bool {
    if *field == *old_default {
        *field = current_default.clone();
        true
    } else {
        false
    }
}

/// Give the rule matching `pattern` a route unless it already has one.
fn adopt_route(group: &mut GroupConfig, pattern: &str, route: RoutePolicy) -> bool {
    group
        .domains
        .iter_mut()
        .find(|rule| rule.pattern == pattern)
        .is_some_and(|rule| {
            if rule.route.is_none() {
                rule.route = Some(route);
                true
            } else {
                false
            }
        })
}

fn migrate_http1_hosts(config: &mut AppConfig) -> bool {
    let old = vec![
        "*.pximg.net".to_string(),
        "img.poipiku.com".to_string(),
        "cdn.poipiku.com".to_string(),
    ];
    let current = AdvancedConfig::default().http1_hosts;
    fold_default(&mut config.advanced.http1_hosts, &old, &current)
}

/// The v2 default list still named only the image CDNs. A file that still
/// carries it verbatim is a user who never customized the list, so it adopts
/// the current one — which adds the asset CDN. A list with any other content
/// is a deliberate choice and is left alone.
fn migrate_http1_hosts_asset_cdn(config: &mut AppConfig) -> bool {
    let old = vec![
        "i.pximg.net".to_string(),
        "booth.pximg.net".to_string(),
        "img.poipiku.com".to_string(),
        "cdn.poipiku.com".to_string(),
    ];
    let current = AdvancedConfig::default().http1_hosts;
    fold_default(&mut config.advanced.http1_hosts, &old, &current)
}

fn migrate_poipiku_auto(config: &mut AppConfig) -> bool {
    let group = match config.groups.iter_mut().find(|group| group.id == "poipiku") {
        Some(group) => group,
        None => return false,
    };
    fold_default(
        &mut group.default_route,
        &RoutePolicy::auto(),
        &RoutePolicy::direct(),
    )
}

fn migrate_poipiku_apex(config: &mut AppConfig) -> bool {
    let group = match config.groups.iter_mut().find(|group| group.id == "poipiku") {
        Some(group) => group,
        None => return false,
    };
    adopt_route(group, "poipiku.com", RoutePolicy::sni(vec![String::new()]))
}

/// An earlier build created the `pixiv` rule the moment the settings card was
/// touched, before there was a shipped address to fill in. Such a rule has an
/// empty base and no referer/UA — anything else is a value the user chose, so
/// only that signature is upgraded, and the rest of the shipped rule comes
/// with it. Host and path lists the user did edit survive.
fn migrate_pixiv_relay(config: &mut AppConfig) -> bool {
    let shipped = ImageRelayRule::pixiv_default();
    let Some(rule) = config
        .advanced
        .image_relays
        .iter_mut()
        .find(|rule| rule.id == shipped.id)
    else {
        return false;
    };
    if !rule.base.trim().is_empty() || rule.referer.is_some() || rule.user_agent.is_some() {
        return false;
    }
    let hosts = std::mem::take(&mut rule.hosts);
    let paths = std::mem::take(&mut rule.paths);
    *rule = shipped;
    if !hosts.is_empty() {
        rule.hosts = hosts;
    }
    if !paths.is_empty() {
        rule.paths = paths;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.schema_version = 0;
        // 把 v2 默认退回旧形状，让三条迁移都有事可做
        config.advanced.http1_hosts = vec![
            "*.pximg.net".to_string(),
            "img.poipiku.com".to_string(),
            "cdn.poipiku.com".to_string(),
        ];
        let group = config.group_mut("poipiku").unwrap();
        group.default_route = RoutePolicy::auto();
        group.domains.retain(|rule| rule.pattern == "poipiku.com");
        group.domains[0].route = None;
        config
    }

    #[test]
    fn fold_default_folds_only_equal_values() {
        let mut value = vec!["a".to_string()];
        assert!(fold_default(&mut value, &vec!["a".to_string()], &vec!["b".to_string()]));
        assert_eq!(value, vec!["b".to_string()]);
        assert!(!fold_default(&mut value, &vec!["a".to_string()], &vec!["c".to_string()]));
        assert_eq!(value, vec!["b".to_string()]);
    }

    #[test]
    fn adopt_route_leaves_customized_rules_alone() {
        let mut config = legacy_config();
        config
            .group_mut("poipiku")
            .unwrap()
            .domains
            .retain(|rule| rule.pattern == "poipiku.com");
        config.group_mut("poipiku").unwrap().domains[0].route = Some(RoutePolicy::direct());
        assert!(!migrate_poipiku_apex(&mut config));

        config.group_mut("poipiku").unwrap().domains[0].route = None;
        assert!(migrate_poipiku_apex(&mut config));
        assert_eq!(
            config.group("poipiku").unwrap().domains[0].route,
            Some(RoutePolicy::sni(vec![String::new()]))
        );
    }

    #[test]
    fn run_migrations_is_idempotent() {
        let mut config = legacy_config();
        assert!(!run_migrations(&mut config).is_empty());
        assert!(run_migrations(&mut config).is_empty());
        assert_eq!(config.schema_version, SCHEMA_VERSION);
    }

    /// The first version of the settings card created the rule on the first
    /// click, with an empty address. That half-created rule has to pick up the
    /// shipped address instead of staying blank forever.
    #[test]
    fn a_half_created_pixiv_relay_adopts_the_shipped_address() {
        let mut config = AppConfig::default();
        config.schema_version = 3;
        config.advanced.image_relays = vec![ImageRelayRule {
            id: "pixiv".into(),
            enabled: false,
            hosts: vec!["i.pximg.net".into()],
            paths: vec!["/img-original/".into()],
            ..ImageRelayRule::default()
        }];
        run_migrations(&mut config);

        let rule = &config.advanced.image_relays[0];
        let shipped = ImageRelayRule::pixiv_default();
        assert_eq!(rule.base, shipped.base);
        assert_eq!(rule.user_agent, shipped.user_agent);
        assert_eq!(rule.referer, shipped.referer);
        assert!(
            rule.enabled,
            "a rule that was never configured adopts the shipped one, which is on"
        );
    }

    #[test]
    fn a_configured_pixiv_relay_is_left_alone() {
        let mut config = AppConfig::default();
        config.schema_version = 3;
        let mut rule = ImageRelayRule::pixiv_default();
        rule.base = "https://mine.example/pximg".into();
        config.advanced.image_relays = vec![rule];
        assert!(!migrate_pixiv_relay(&mut config));
        assert_eq!(
            config.advanced.image_relays[0].base,
            "https://mine.example/pximg"
        );
    }

    /// A file written by the previous release pins the v2 list verbatim. It is
    /// the default, not a choice, so it must pick up the asset CDN.
    #[test]
    fn v2_http1_hosts_adopt_the_asset_cdn() {        let mut config = AppConfig::default();
        config.schema_version = 2;
        config.advanced.http1_hosts = vec![
            "i.pximg.net".to_string(),
            "booth.pximg.net".to_string(),
            "img.poipiku.com".to_string(),
            "cdn.poipiku.com".to_string(),
        ];

        assert!(!run_migrations(&mut config).is_empty());
        assert!(config
            .advanced
            .http1_hosts
            .iter()
            .any(|pattern| pattern == "s.pximg.net"));
    }

    /// Anything that is not the old default is a deliberate list.
    #[test]
    fn customized_http1_hosts_are_not_rewritten() {
        let mut config = AppConfig::default();
        config.schema_version = 2;
        config.advanced.http1_hosts = vec!["i.pximg.net".to_string()];

        run_migrations(&mut config);
        assert_eq!(config.advanced.http1_hosts, vec!["i.pximg.net".to_string()]);
    }

    #[test]
    fn fresh_defaults_skip_all_migrations() {
        let mut config = AppConfig::default();
        assert!(run_migrations(&mut config).is_empty());
        assert_eq!(config.schema_version, SCHEMA_VERSION);
    }
}
