use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use hakimi_core::config::{
    validate_group_id, DomainRule, EchSource, GroupConfig, RouteAttempt, RoutePolicy,
};
use hakimi_core::runtime::HakimiRuntime;

use crate::control;
use crate::output::Output;

#[derive(Args)]
pub struct GroupArgs {
    /// Defaults to `list`.
    #[command(subcommand)]
    pub command: Option<GroupCommand>,
}

#[derive(Subcommand)]
pub enum GroupCommand {
    /// List the configured groups.
    List,
    /// Show one group and its domains.
    Show {
        /// Group id.
        id: String,
    },
    /// Change a group's name, state, homepage or default route.
    Set {
        /// Group id.
        id: String,
        /// Enable the group.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable the group.
        #[arg(long)]
        disable: bool,
        /// Display name.
        #[arg(long)]
        name: Option<String>,
        /// Canonical page the UI opens for this group.
        #[arg(long)]
        homepage: Option<String>,
        /// Replace the default route preset.
        #[arg(long, value_enum)]
        route: Option<RoutePreset>,
    },
    /// Add a group.
    Add {
        /// Group id: lowercase letters, digits and dashes.
        id: String,
        /// Display name (defaults to the id).
        #[arg(long)]
        name: Option<String>,
        /// Domain pattern; repeat for more than one.
        #[arg(long = "domain", value_name = "PATTERN")]
        domains: Vec<String>,
        /// Default route preset for the group's domains.
        #[arg(long, value_enum)]
        route: Option<RoutePreset>,
        /// Canonical page the UI opens for this group.
        #[arg(long)]
        homepage: Option<String>,
        /// Add the group in the disabled state.
        #[arg(long)]
        disabled: bool,
    },
    /// Remove a group.
    Rm {
        /// Group id.
        id: String,
    },
    /// Add or remove a domain pattern.
    Domain {
        #[command(subcommand)]
        command: DomainCommand,
    },
}

#[derive(Subcommand)]
pub enum DomainCommand {
    /// Add a domain pattern to a group.
    Add {
        /// Group id.
        id: String,
        /// Domain pattern, e.g. `example.com` or `*.example.com`.
        pattern: String,
        /// Route preset for this pattern only.
        #[arg(long, value_enum)]
        route: Option<RoutePreset>,
    },
    /// Remove a domain pattern from a group.
    Rm {
        /// Group id.
        id: String,
        /// Domain pattern to remove.
        pattern: String,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum RoutePreset {
    /// Direct, then ECH, then fake SNI.
    Auto,
    /// Direct only.
    Direct,
    /// ECH (own record, then Cloudflare's shared config), then direct.
    Ech,
    /// Fake SNI, then direct.
    Sni,
}

impl From<RoutePreset> for RoutePolicy {
    fn from(value: RoutePreset) -> Self {
        match value {
            RoutePreset::Auto => RoutePolicy::auto(),
            RoutePreset::Direct => RoutePolicy::direct(),
            RoutePreset::Ech => RoutePolicy::ech_shared(),
            RoutePreset::Sni => RoutePolicy::sni(Vec::new()),
        }
    }
}

pub async fn run(runtime: &HakimiRuntime, args: GroupArgs, out: Output) -> Result<()> {
    match args.command.unwrap_or(GroupCommand::List) {
        GroupCommand::List => list(runtime, out)?,
        GroupCommand::Show { id } => show(runtime, &id, out)?,
        GroupCommand::Set {
            id,
            enable,
            disable,
            name,
            homepage,
            route,
        } => {
            let enabled = match (enable, disable) {
                (true, _) => Some(true),
                (_, true) => Some(false),
                _ => None,
            };
            set(runtime, &id, enabled, route, name, homepage)?;
            control::note_live_instance(runtime).await;
            show(runtime, &id, out)?;
        }
        GroupCommand::Add {
            id,
            name,
            domains,
            route,
            homepage,
            disabled,
        } => {
            add(runtime, &id, name, domains, route, homepage, disabled)?;
            control::note_live_instance(runtime).await;
            show(runtime, &id, out)?;
        }
        GroupCommand::Rm { id } => {
            remove(runtime, &id)?;
            control::note_live_instance(runtime).await;
        }
        GroupCommand::Domain { command } => {
            let id = match &command {
                DomainCommand::Add { id, pattern, route } => {
                    domain_add(runtime, id, pattern, *route)?;
                    id.clone()
                }
                DomainCommand::Rm { id, pattern } => {
                    domain_remove(runtime, id, pattern)?;
                    id.clone()
                }
            };
            control::note_live_instance(runtime).await;
            show(runtime, &id, out)?;
        }
    }
    Ok(())
}

fn list(runtime: &HakimiRuntime, out: Output) -> Result<()> {
    let config = runtime.config().snapshot();
    if out.is_json() {
        return out.json(&config.groups);
    }
    let rows = config
        .groups
        .iter()
        .map(|group| {
            vec![
                group.id.clone(),
                group.name.clone(),
                if group.enabled { "on" } else { "off" }.to_string(),
                route_label(&group.default_route),
                group.domains.len().to_string(),
            ]
        })
        .collect::<Vec<_>>();
    out.table(
        &["id", "name", "state", "default route", "domains"],
        &rows,
        &[4],
    );
    Ok(())
}

fn show(runtime: &HakimiRuntime, id: &str, out: Output) -> Result<()> {
    let group = existing(runtime, id)?;
    if out.is_json() {
        return out.json(&group);
    }
    print_group(out, &group);
    Ok(())
}

fn print_group(out: Output, group: &GroupConfig) {
    out.field("id", &group.id);
    out.field("name", &group.name);
    out.field("state", if group.enabled { "enabled" } else { "disabled" });
    if let Some(homepage) = &group.homepage {
        out.field("homepage", homepage);
    }
    out.field("route", route_label(&group.default_route));
    out.field("domains", group.domains.len());
    for rule in &group.domains {
        match &rule.route {
            Some(route) => println!("  {}  ({})", rule.pattern, route_label(route)),
            None => println!("  {}", rule.pattern),
        }
    }
}

fn route_label(policy: &RoutePolicy) -> String {
    policy
        .attempts
        .iter()
        .map(|attempt| match attempt {
            RouteAttempt::Direct => "direct".to_string(),
            RouteAttempt::Ech { ech } => match ech {
                EchSource::Own => "ech:own".to_string(),
                EchSource::Shared => "ech:shared".to_string(),
            },
            RouteAttempt::Sni { sni } if sni.is_empty() => "sni".to_string(),
            RouteAttempt::Sni { sni } => format!("sni({})", sni.join(",")),
        })
        .collect::<Vec<_>>()
        .join(">")
}

fn existing(runtime: &HakimiRuntime, id: &str) -> Result<GroupConfig> {
    runtime
        .config()
        .snapshot()
        .group(id)
        .cloned()
        .with_context(|| format!("unknown group `{id}`"))
}

fn set(
    runtime: &HakimiRuntime,
    id: &str,
    enabled: Option<bool>,
    route: Option<RoutePreset>,
    name: Option<String>,
    homepage: Option<String>,
) -> Result<()> {
    let mut group = existing(runtime, id)?;
    if let Some(enabled) = enabled {
        group.enabled = enabled;
    }
    if let Some(route) = route {
        group.default_route = route.into();
    }
    if let Some(name) = name {
        group.name = name;
    }
    if let Some(homepage) = homepage {
        group.homepage = Some(homepage);
    }
    runtime.upsert_group(group)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add(
    runtime: &HakimiRuntime,
    id: &str,
    name: Option<String>,
    domains: Vec<String>,
    route: Option<RoutePreset>,
    homepage: Option<String>,
    disabled: bool,
) -> Result<()> {
    validate_group_id(id)?;
    if runtime.config().snapshot().group(id).is_some() {
        bail!("group `{id}` already exists; use `group set` to change it");
    }
    let group = GroupConfig {
        id: id.to_string(),
        name: name.unwrap_or_else(|| id.to_string()),
        domains: domains
            .iter()
            .map(|domain| DomainRule::new(domain.as_str()))
            .collect(),
        enabled: !disabled,
        homepage,
        default_route: route
            .map(RoutePolicy::from)
            .unwrap_or_else(RoutePolicy::auto),
    };
    runtime.upsert_group(group)?;
    Ok(())
}

fn remove(runtime: &HakimiRuntime, id: &str) -> Result<()> {
    let _ = existing(runtime, id)?;
    runtime.remove_group(id)?;
    println!("removed group `{id}`");
    Ok(())
}

fn domain_add(
    runtime: &HakimiRuntime,
    id: &str,
    pattern: &str,
    route: Option<RoutePreset>,
) -> Result<()> {
    let mut group = existing(runtime, id)?;
    if group.domains.iter().any(|rule| rule.pattern == pattern) {
        bail!("`{pattern}` is already in group `{id}`");
    }
    group.domains.push(match route {
        Some(route) => DomainRule::routed(pattern, route.into()),
        None => DomainRule::new(pattern),
    });
    runtime.upsert_group(group)?;
    Ok(())
}

fn domain_remove(runtime: &HakimiRuntime, id: &str, pattern: &str) -> Result<()> {
    let mut group = existing(runtime, id)?;
    let before = group.domains.len();
    group.domains.retain(|rule| rule.pattern != pattern);
    if group.domains.len() == before {
        bail!("`{pattern}` is not in group `{id}`");
    }
    runtime.upsert_group(group)?;
    Ok(())
}
