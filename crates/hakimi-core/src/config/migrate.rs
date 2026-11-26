//! Configuration migrations: one static entry per historical shape change.
//!
//! Field renames live in serde (`alias`), not here — migrations only upgrade
//! shapes. Every `apply` is idempotent and leaves user-customized values alone.

use super::{AdvancedConfig, AppConfig, DownloadConfig, GroupConfig, ImageRelayRule, RoutePolicy};

/// Shape version this build writes. Bump when adding a migration; files
/// without the field deserialize as 0 and catch up in one load.
pub const SCHEMA_VERSION: u32 = 7;

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
    Migration {
        version: "0.1.11",
        describe: "download chunks adopt the 512 KiB default",
        applies_below: Some(5),
        apply: migrate_download_chunk_default,
    },
    Migration {
        version: "0.1.12",
        describe: "download segments adopt the tiered-engine default",
        applies_below: Some(6),
        apply: migrate_download_segments_default,
    },
    Migration {
        version: "0.1.13",
        describe: "the download floor adopts the 512 KiB default",
        applies_below: Some(7),
        apply: migrate_download_min_size_default,
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

/// The first chunked-download default was 128 KiB. A file that customized any
/// download field materialized the whole `download` object, old chunk size
/// included, so those installs would keep paying a round trip per 128 KiB even
/// after the default moved to 512 KiB. Anything other than the old default is
/// a deliberate choice and is left alone.
fn migrate_download_chunk_default(config: &mut AppConfig) -> bool {
    let current = DownloadConfig::default().chunk_bytes;
    fold_default(
        &mut config.advanced.download.chunk_bytes,
        &(128 * 1024),
        &current,
    )
}

/// The old default of 6 predates the tiered engine: mirror 6, small direct 8,
/// large direct 12. A file still carrying 6 adopts the new ceiling; any other
/// count is a deliberate choice.
fn migrate_download_segments_default(config: &mut AppConfig) -> bool {
    let current = DownloadConfig::default().segments;
    fold_default(&mut config.advanced.download.segments, &6, &current)
}

/// The old floor of 2 MiB kept sub-two-megabyte assets single-stream even
/// though the route experiment measured them fastest when split. A file still
/// carrying the old default adopts 512 KiB; any other floor is deliberate.
fn migrate_download_min_size_default(config: &mut AppConfig) -> bool {
    let current = DownloadConfig::default().min_size_bytes;
    fold_default(
        &mut config.advanced.download.min_size_bytes,
        &(2 * 1024 * 1024),
        &current,
    )
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
        assert!(fold_default(
            &mut value,
            &vec!["a".to_string()],
            &vec!["b".to_string()]
        ));
        assert_eq!(value, vec!["b".to_string()]);
        assert!(!fold_default(
            &mut value,
            &vec!["a".to_string()],
            &vec!["c".to_string()]
        ));
        assert_eq!(value, vec!["b".to_string()]);
    }

    #[test]
    fn run_migrations_is_idempotent() {
        let mut config = legacy_config();
        assert!(!run_migrations(&mut config).is_empty());
        assert!(run_migrations(&mut config).is_empty());
        assert_eq!(config.schema_version, SCHEMA_VERSION);
    }

    /// A file that materialized the old 128 KiB chunk default — because it
    /// customized another download field — folds onto the new default. A chunk
    /// size the user actually chose survives.
    #[test]
    fn the_old_download_chunk_default_folds_onto_the_new_one() {
        let mut config = AppConfig::default();
        config.schema_version = 4;
        config.advanced.download.chunk_bytes = 128 * 1024;
        assert!(!run_migrations(&mut config).is_empty());
        assert_eq!(
            config.advanced.download.chunk_bytes,
            DownloadConfig::default().chunk_bytes
        );

        let mut custom = AppConfig::default();
        custom.schema_version = 4;
        custom.advanced.download.chunk_bytes = 1024 * 1024;
        run_migrations(&mut custom);
        assert_eq!(custom.advanced.download.chunk_bytes, 1024 * 1024);
    }

    /// The old concurrency default of 6 predates the tiered engine, so a file
    /// still carrying it adopts the new ceiling of 12; any other count is a
    /// deliberate choice and survives.
    #[test]
    fn the_old_download_segments_default_folds_onto_the_new_one() {
        let mut config = AppConfig::default();
        config.schema_version = 5;
        config.advanced.download.segments = 6;
        assert!(!run_migrations(&mut config).is_empty());
        assert_eq!(config.advanced.download.segments, 12);

        let mut custom = AppConfig::default();
        custom.schema_version = 5;
        custom.advanced.download.segments = 4;
        run_migrations(&mut custom);
        assert_eq!(custom.advanced.download.segments, 4);
    }

    /// The old 2 MiB floor kept half-megabyte assets out of the fast path; a
    /// file still carrying it adopts 512 KiB while a raised floor survives.
    #[test]
    fn the_old_download_min_size_default_folds_onto_the_new_one() {
        let mut config = AppConfig::default();
        config.schema_version = 6;
        config.advanced.download.min_size_bytes = 2 * 1024 * 1024;
        assert!(!run_migrations(&mut config).is_empty());
        assert_eq!(config.advanced.download.min_size_bytes, 512 * 1024);

        let mut custom = AppConfig::default();
        custom.schema_version = 6;
        custom.advanced.download.min_size_bytes = 4 * 1024 * 1024;
        run_migrations(&mut custom);
        assert_eq!(custom.advanced.download.min_size_bytes, 4 * 1024 * 1024);
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
    fn v2_http1_hosts_adopt_the_asset_cdn() {
        let mut config = AppConfig::default();
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
