use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use hakimi_core::config::AppConfig;
use hakimi_core::runtime::HakimiRuntime;
use serde_json::Value;

use crate::control;
use crate::output::Output;

#[derive(Args)]
pub struct ConfigArgs {
    /// Defaults to `show`.
    #[command(subcommand)]
    pub command: Option<ConfigCommand>,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Print the effective configuration as JSON.
    Show,
    /// Print the path of the configuration file.
    Path,
    /// Print one value, e.g. `proxy.port`.
    Get {
        /// Dotted path, e.g. `proxy.port` or `groups.0.enabled`.
        path: String,
    },
    /// Set one value, e.g. `proxy.port 9000`.
    Set {
        /// Dotted path, e.g. `proxy.port`.
        path: String,
        /// JSON if it parses as JSON, otherwise a string.
        value: String,
    },
    /// Merge a JSON patch onto the configuration (file or stdin).
    Update {
        /// Read the patch from this file instead of stdin.
        #[arg(long, value_name = "FILE")]
        file: Option<PathBuf>,
    },
}

pub async fn run(runtime: &HakimiRuntime, args: ConfigArgs, out: Output) -> Result<()> {
    match args.command.unwrap_or(ConfigCommand::Show) {
        ConfigCommand::Show => {
            let config = runtime.config().snapshot();
            println!("{}", serde_json::to_string_pretty(&*config)?);
        }
        ConfigCommand::Path => println!("{}", runtime.paths().config_file().display()),
        ConfigCommand::Get { path } => get(runtime, &path, out)?,
        ConfigCommand::Set { path, value } => {
            set(runtime, &path, &value, out)?;
            control::note_live_instance(runtime).await;
        }
        ConfigCommand::Update { file } => {
            update(runtime, file.as_deref())?;
            control::note_live_instance(runtime).await;
        }
    }
    Ok(())
}

fn get(runtime: &HakimiRuntime, path: &str, out: Output) -> Result<()> {
    let root = serde_json::to_value(&*runtime.config().snapshot())?;
    let value = lookup(&root, path).with_context(|| format!("no such setting `{path}`"))?;
    match value {
        // A bare string is what a shell script wants; `--json` keeps the quotes.
        Value::String(text) if !out.is_json() => println!("{text}"),
        other => println!("{}", serde_json::to_string_pretty(other)?),
    }
    Ok(())
}

fn set(runtime: &HakimiRuntime, path: &str, raw: &str, out: Output) -> Result<()> {
    let value = serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()));
    let mut root = serde_json::to_value(&*runtime.config().snapshot())?;
    assign(&mut root, path, value.clone())?;
    let config: AppConfig =
        serde_json::from_value(root).context("invalid configuration after the change")?;
    runtime.update_config(config)?;
    if out.is_json() {
        out.json(&value)?;
    } else {
        match &value {
            Value::String(text) => println!("{path} = {text}"),
            other => println!("{path} = {other}"),
        }
    }
    Ok(())
}

fn update(runtime: &HakimiRuntime, file: Option<&Path>) -> Result<()> {
    let text = match file {
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
        }
        None => {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("reading the patch from stdin")?;
            text
        }
    };
    if text.trim().is_empty() {
        bail!("empty configuration patch");
    }
    let patch: Value = serde_json::from_str(&text).context("parsing the configuration patch")?;
    if !patch.is_object() {
        bail!("the configuration patch must be a JSON object");
    }
    let current = runtime.config().snapshot();
    let mut merged = serde_json::to_value(&*current)?;
    merge(&mut merged, patch);
    let config: AppConfig =
        serde_json::from_value(merged.clone()).context("invalid configuration after merge")?;
    // `AppConfig` uses serde defaults, so a typo in the patch would silently
    // vanish at deserialization and `update` would still report success.
    if let Some(key) = first_unknown_key(&merged, &config)? {
        bail!("unknown setting `{key}` in the configuration patch");
    }
    runtime.update_config(config)?;
    let applied = runtime.config().snapshot();
    println!("{}", serde_json::to_string_pretty(&*applied)?);
    Ok(())
}

fn lookup<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = match current {
            Value::Object(map) => map.get(part)?,
            Value::Array(items) => items.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

/// Writes one value in place. Existing keys only: a typo must fail instead of
/// silently adding a field that the deserializer would then ignore.
fn assign(root: &mut Value, path: &str, value: Value) -> Result<()> {
    let parts: Vec<&str> = path.split('.').collect();
    let Some((leaf, parents)) = parts.split_last() else {
        bail!("empty setting path");
    };
    let mut current = root;
    for part in parents {
        current = match current {
            Value::Object(map) => map
                .get_mut(*part)
                .with_context(|| format!("no such setting `{path}`"))?,
            Value::Array(items) => {
                let index: usize = part
                    .parse()
                    .with_context(|| format!("`{part}` is not an array index"))?;
                items
                    .get_mut(index)
                    .with_context(|| format!("`{path}` is out of range"))?
            }
            _ => bail!("`{path}` does not point into an object or an array"),
        };
    }
    match current {
        Value::Object(map) => {
            if !map.contains_key(*leaf) {
                bail!("unknown setting `{path}`");
            }
            map.insert(leaf.to_string(), value);
        }
        Value::Array(items) => {
            let index: usize = leaf
                .parse()
                .with_context(|| format!("`{leaf}` is not an array index"))?;
            let slot = items
                .get_mut(index)
                .with_context(|| format!("`{path}` is out of range"))?;
            *slot = value;
        }
        _ => bail!("`{path}` does not point into an object or an array"),
    }
    Ok(())
}

fn merge(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(base), Value::Object(patch)) => {
            for (key, value) in patch {
                if base.contains_key(&key) {
                    if let Some(slot) = base.get_mut(&key) {
                        merge(slot, value);
                    }
                } else {
                    base.insert(key, value);
                }
            }
        }
        (base, patch) => *base = patch,
    }
}

/// The dotted path of the first key in `merged` that `AppConfig` would ignore.
///
/// `AppConfig` deserializes with `#[serde(default)]` and no
/// `deny_unknown_fields`, so unknown keys are dropped without an error.
/// Serializing the deserialized config back yields exactly the recognised keys,
/// so comparing the two trees detects typos without tightening
/// deserialization for config files, remote catalogs or FFI callers that may
/// carry extra fields.
///
/// Only object-keyed paths are checked: arrays (`groups`, per-group `domains`)
/// are replaced wholesale by `merge`, so their element keys are validated by
/// serde itself and do not need a separate key check. A `null` value carries no
/// nested keys, so it short-circuits here as well.
fn first_unknown_key(merged: &Value, config: &AppConfig) -> Result<Option<String>> {
    let canonical = serde_json::to_value(config)?;
    Ok(find_unknown(merged, &canonical, String::new()))
}

fn find_unknown(value: &Value, schema: &Value, path: String) -> Option<String> {
    // A scalar/null child or an array has no object keys to validate, so there
    // is nothing to flag at this level. Array elements are handled by serde.
    let (Value::Object(map), Value::Object(schema)) = (value, schema) else {
        return None;
    };
    for (key, child) in map {
        let child_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        match schema.get(key) {
            None => return Some(child_path),
            Some(schema_child) => {
                if let Some(found) = find_unknown(child, schema_child, child_path) {
                    return Some(found);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{assign, first_unknown_key, lookup, merge};
    use hakimi_core::config::AppConfig;
    use serde_json::json;

    fn check_unknown(merged: &serde_json::Value) -> Option<String> {
        let config: AppConfig = serde_json::from_value(merged.clone()).unwrap();
        first_unknown_key(merged, &config).unwrap()
    }

    #[test]
    fn an_unknown_key_in_a_patch_is_detected() {
        // `AppConfig` has no deny_unknown_fields, so this typo deserializes
        // fine and the old `update` reported success while changing nothing.
        let mut base = serde_json::to_value(AppConfig::default()).unwrap();
        merge(&mut base, json!({"proxy": {"prt": 9999}}));
        assert_eq!(check_unknown(&base).as_deref(), Some("proxy.prt"));
    }

    #[test]
    fn a_known_optional_field_is_not_flagged() {
        // An Option field is present in the canonical tree (as `null` or a
        // value), so setting it must not be mistaken for an unknown key.
        let mut base = serde_json::to_value(AppConfig::default()).unwrap();
        merge(&mut base, json!({"catalogs": {"signaturePublicKey": "abc"}}));
        assert_eq!(check_unknown(&base), None);
    }

    #[test]
    fn a_valid_patch_has_no_unknown_keys() {
        let mut base = serde_json::to_value(AppConfig::default()).unwrap();
        merge(&mut base, json!({"proxy": {"port": 9000}}));
        assert_eq!(check_unknown(&base), None);
    }

    #[test]
    fn clearing_an_optional_field_with_null_is_not_flagged() {
        // Assigning `null` to clear an Option field is a valid patch. A null
        // child has no nested keys, so it short-circuits instead of being
        // compared against the (equally null) canonical value.
        let mut base = serde_json::to_value(AppConfig::default()).unwrap();
        merge(&mut base, json!({"catalogs": {"signaturePublicKey": null}}));
        assert_eq!(check_unknown(&base), None);
    }

    #[test]
    fn an_unknown_key_beside_a_null_one_is_still_detected() {
        // The null short-circuit must not mask a genuine typo in a sibling key.
        let mut base = serde_json::to_value(AppConfig::default()).unwrap();
        merge(
            &mut base,
            json!({"catalogs": {"signaturePublicKey": null, "sigPublicKeyTypo": "x"}}),
        );
        assert_eq!(
            check_unknown(&base).as_deref(),
            Some("catalogs.sigPublicKeyTypo")
        );
    }

    #[test]
    fn array_valued_patches_have_no_false_positives() {
        // Arrays are replaced wholesale by `merge` and their element keys are
        // validated by serde, so `find_unknown` must not invent index keys.
        let mut base = serde_json::to_value(AppConfig::default()).unwrap();
        merge(&mut base, json!({"groups": [{"id": "g", "name": "G", "domains": [], "enabled": true}]}));
        assert_eq!(check_unknown(&base), None);
    }

    #[test]
    fn untouched_keys_survive_a_patch() {
        let mut base = json!({"proxy": {"port": 8443, "mode": "pac"}, "groups": [1, 2]});
        merge(&mut base, json!({"proxy": {"port": 9000}, "groups": [3]}));
        assert_eq!(base["proxy"]["port"], 9000);
        assert_eq!(base["proxy"]["mode"], "pac");
        // Arrays replace as a whole: a patch cannot edit one element.
        assert_eq!(base["groups"], json!([3]));
    }

    #[test]
    fn new_sections_are_added() {
        let mut base = json!({});
        merge(&mut base, json!({"log": {"level": "debug"}}));
        assert_eq!(base["log"]["level"], "debug");
    }

    #[test]
    fn dotted_paths_read_and_write_nested_values() {
        let mut root = json!({"groups": [{"id": "a", "enabled": true}]});
        assert_eq!(lookup(&root, "groups.0.id"), Some(&json!("a")));
        assign(&mut root, "groups.0.enabled", json!(false)).unwrap();
        assert_eq!(root["groups"][0]["enabled"], false);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let mut root = json!({"proxy": {"port": 8443}});
        // A typo must not silently add a field the deserializer would ignore.
        assert!(assign(&mut root, "proxy.prot", json!(1)).is_err());
        assert!(assign(&mut root, "nope.port", json!(1)).is_err());
    }
}
