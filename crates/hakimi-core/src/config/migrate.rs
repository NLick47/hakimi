//! Configuration migrations: one static entry per historical shape change.
//!
//! Field renames live in serde (`alias`), not here — migrations only upgrade
//! shapes. Every `apply` is idempotent and leaves user-customized values alone.

use super::{AdvancedConfig, AppConfig, GroupConfig, RoutePolicy};

/// Shape version this build writes. Bump when adding a migration; files
/// without the field deserialize as 0 and catch up in one load.
pub const SCHEMA_VERSION: u32 = 2;

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

    #[test]
    fn fresh_defaults_skip_all_migrations() {
        let mut config = AppConfig::default();
        assert!(run_migrations(&mut config).is_empty());
        assert_eq!(config.schema_version, SCHEMA_VERSION);
    }
}
