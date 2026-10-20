use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use hakimi_core::cache::CacheStats;
use hakimi_core::runtime::HakimiRuntime;
use hakimi_core::strategy::Strategy;
use serde_json::Value;

#[derive(Parser)]
#[command(name = "hakimi", version, about = "hakimi acceleration core")]
struct Cli {
    /// Override the data directory (defaults to the platform data dir).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the local proxy and apply the system proxy/PAC.
    Serve {
        /// Do not change the OS proxy setting.
        #[arg(long)]
        no_takeover: bool,
        /// Start in the paused state (PAC returns DIRECT).
        #[arg(long)]
        paused: bool,
    },
    /// Print runtime status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Diagnose one domain end-to-end.
    Doctor {
        domain: String,
        #[arg(long)]
        json: bool,
    },
    /// Refresh remote catalogs.
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
    /// Local CA management.
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    /// Print the generated PAC script.
    Pac,
    /// List configured groups.
    Groups {
        #[arg(long)]
        json: bool,
    },
    /// Change a group setting.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// Print the effective configuration.
    Config,
    /// Run a manual DoH health check.
    Doh {
        #[command(subcommand)]
        command: DohCommand,
    },
    /// Restore the OS proxy settings saved by a previous `serve` run.
    RestoreProxy,
    /// Export a sanitized diagnostics bundle.
    Export,
}

#[derive(Subcommand)]
enum CatalogCommand {
    Refresh {
        #[arg(long, value_enum, default_value_t = CatalogKind::All)]
        kind: CatalogKind,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CatalogKind {
    Ip,
    Doh,
    All,
}

#[derive(Subcommand)]
enum CaCommand {
    Status,
    Install,
    Uninstall,
    Repair,
    Regenerate,
}

#[derive(Subcommand)]
enum DohCommand {
    Health,
}

#[derive(Subcommand)]
enum GroupCommand {
    Set {
        id: String,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long, value_enum)]
        strategy: Option<StrategyArg>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum StrategyArg {
    Auto,
    Direct,
    Ech,
    Sni,
}

impl From<StrategyArg> for Strategy {
    fn from(value: StrategyArg) -> Self {
        match value {
            StrategyArg::Auto => Strategy::Auto,
            StrategyArg::Direct => Strategy::Direct,
            StrategyArg::Ech => Strategy::Ech,
            StrategyArg::Sni => Strategy::FakeSni,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let runtime = HakimiRuntime::new(cli.data_dir.clone())?;
    match cli.command {
        Command::Serve {
            no_takeover,
            paused,
        } => {
            // Long-running instance: take the single-instance lock for the whole
            // lifetime, so a second serve (or the UI) cannot fight over the port.
            let _instance_lock =
                hakimi_core::instance::InstanceLock::acquire(runtime.paths().root())?;
            if no_takeover {
                runtime.config().mutate(|config| {
                    config.proxy.takeover = false;
                    Ok(())
                })?;
            }
            runtime.start().await?;
            if paused {
                runtime.pause();
            }
            if let Some(url) = runtime.pac_url() {
                println!("proxy listening; PAC: {url}");
            }
            println!("data dir: {}", runtime.paths().root().display());
            println!("press Ctrl+C to stop");
            tokio::signal::ctrl_c()
                .await
                .context("waiting for Ctrl+C")?;
            runtime.stop().await?;
        }
        Command::Status { json } => {
            if let Some(value) = try_live_status(&runtime).await {
                print_status(&value, json)?;
            } else {
                print_status(&runtime.status_json(), json)?;
            }
        }
        Command::Doctor { domain, json } => {
            let diagnostics = runtime.diagnose(&domain).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&diagnostics)?);
            } else {
                println!("domain:        {}", diagnostics.domain);
                println!("state:         {:?}", diagnostics.state);
                println!(
                    "strategy:      {}",
                    diagnostics
                        .strategy
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "none".into())
                );
                println!(
                    "ip:            {}",
                    diagnostics
                        .ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "none".into())
                );
                println!(
                    "ip source:     {}",
                    diagnostics
                        .ip_source
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "none".into())
                );
                println!(
                    "doh source:    {}",
                    diagnostics
                        .doh_source
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "none".into())
                );
                println!(
                    "error:         {}",
                    diagnostics
                        .error
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "none".into())
                );
                if let Some(detail) = &diagnostics.detail {
                    println!("detail:        {detail}");
                }
                for suggestion in &diagnostics.suggestions {
                    println!("suggestion:    {suggestion}");
                }
            }
        }
        Command::Catalog { command } => match command {
            CatalogCommand::Refresh { kind, force } => {
                let results = match kind {
                    CatalogKind::All => runtime.refresh_catalogs(force).await,
                    CatalogKind::Ip => vec![runtime.refresh_catalog("ip", force).await],
                    CatalogKind::Doh => vec![runtime.refresh_catalog("doh", force).await],
                };
                for result in results {
                    match result {
                        Ok(report) => println!("{}", serde_json::to_string_pretty(&report)?),
                        Err(error) => eprintln!("refresh failed: {error:#}"),
                    }
                }
            }
        },
        Command::Ca { command } => match command {
            CaCommand::Status => println!(
                "{}",
                serde_json::to_string_pretty(&runtime.ca_status().await)?
            ),
            CaCommand::Install => {
                println!("{}", serde_json::to_string_pretty(&runtime.ca_install()?)?)
            }
            CaCommand::Uninstall => println!(
                "{}",
                serde_json::to_string_pretty(&runtime.ca_uninstall()?)?
            ),
            CaCommand::Repair => {
                println!("{}", serde_json::to_string_pretty(&runtime.ca_repair()?)?)
            }
            CaCommand::Regenerate => println!(
                "{}",
                serde_json::to_string_pretty(&runtime.ca_regenerate()?)?
            ),
        },
        Command::Pac => {
            let config = runtime.config().snapshot();
            println!(
                "{}",
                hakimi_core::pac::generate(
                    &config,
                    std::net::SocketAddr::new(config.proxy.bind, config.proxy.port),
                    false
                )
            );
        }
        Command::Groups { json } => {
            let config = runtime.config().snapshot();
            if json {
                println!("{}", serde_json::to_string_pretty(&config.groups)?);
            } else {
                for group in &config.groups {
                    println!(
                        "{:<10} {:<20} strategy={:<6} enabled={:<5} experimental={} domains={}",
                        group.id,
                        group.name,
                        group.strategy.as_str(),
                        group.enabled,
                        group.experimental,
                        group.domains.len()
                    );
                }
            }
        }
        Command::Group { command } => match command {
            GroupCommand::Set {
                id,
                enabled,
                strategy,
            } => {
                if let Some(enabled) = enabled {
                    runtime.set_group_enabled(&id, enabled)?;
                }
                if let Some(strategy) = strategy {
                    runtime.set_group_strategy(&id, strategy.into())?;
                }
                let group = runtime
                    .config()
                    .snapshot()
                    .group(&id)
                    .cloned()
                    .with_context(|| format!("unknown group `{id}`"))?;
                println!("{}", serde_json::to_string_pretty(&group)?);
            }
        },
        Command::Config => println!("{}", serde_json::to_string_pretty(&runtime.config_json())?),
        Command::Doh { command } => match command {
            DohCommand::Health => {
                let health = runtime.doh_health().await;
                println!("{}", serde_json::to_string_pretty(&health)?);
            }
        },
        Command::RestoreProxy => {
            let restored = runtime.restore_system_proxy()?;
            if restored {
                println!("system proxy settings restored");
            } else {
                println!("no saved system proxy state found");
            }
        }
        Command::Export => {
            let path = runtime.export_diagnostics()?;
            println!("{}", path.display());
        }
    }
    Ok(())
}

async fn try_live_status(runtime: &HakimiRuntime) -> Option<Value> {
    let config = runtime.config().snapshot();
    let url = format!(
        "http://{}:{}/hakimi/status",
        config.proxy.bind, config.proxy.port
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(600))
        .no_proxy()
        .build()
        .ok()?;
    tokio::time::timeout(Duration::from_millis(800), async {
        client.get(url).send().await.ok()?.json().await.ok()
    })
    .await
    .ok()?
}

fn print_status(value: &Value, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }
    let paused = value["paused"].as_bool().unwrap_or(false);
    println!(
        "hakimi {} — {}",
        value["version"].as_str().unwrap_or("?"),
        if paused { "paused" } else { "running" }
    );
    if let Some(listen) = value["proxy"]["listen"].as_str() {
        println!("proxy: {}", listen);
    }
    if let Some(pac) = value["proxy"]["pacUrl"].as_str() {
        println!("pac:   {}", pac);
    }
    let ca = &value["ca"];
    println!(
        "ca:    trusted={} fingerprint={}",
        ca["installed"].as_bool().unwrap_or(false),
        ca["fingerprintSha1"].as_str().unwrap_or("-")
    );
    if let Some(groups) = value["groups"].as_array() {
        for group in groups {
            println!(
                "{:<10} {:<10} {:<20} tested={} failed={}",
                group["id"].as_str().unwrap_or("?"),
                group["state"].as_str().unwrap_or("?"),
                group["name"].as_str().unwrap_or(""),
                group["testedDomains"].as_u64().unwrap_or(0),
                group["failedDomains"].as_u64().unwrap_or(0),
            );
        }
    }
    let cache: CacheStats = serde_json::from_value(value["cache"].clone()).unwrap_or_default();
    println!(
        "cache: lastGood={} doh={} ech={} sni={}",
        cache.last_good, cache.doh_answers, cache.ech_configs, cache.fake_sni
    );
    Ok(())
}
