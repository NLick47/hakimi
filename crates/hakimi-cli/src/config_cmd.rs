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
        serde_json::from_value(merged).context("invalid configuration after merge")?;
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

#[cfg(test)]
mod tests {
    use super::{assign, lookup, merge};
    use serde_json::json;

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
