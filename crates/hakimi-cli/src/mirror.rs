use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Subcommand};
use hakimi_core::config::DEFAULT_MIRROR_SOURCE;
use hakimi_core::runtime::HakimiRuntime;
use serde_json::json;

use crate::control;
use crate::output::Output;

#[derive(Args)]
pub struct MirrorArgs {
    /// Defaults to `status`.
    #[command(subcommand)]
    pub command: Option<MirrorCommand>,
}

#[derive(Subcommand)]
pub enum MirrorCommand {
    /// Show whether the mirror is on and which sites it would use.
    Status,
    /// Send GitHub downloads through the mirror list.
    On,
    /// Send GitHub downloads direct.
    Off,
    /// Fetch the remote mirror list now.
    Refresh,
}

pub async fn run(runtime: &HakimiRuntime, args: MirrorArgs, out: Output) -> Result<ExitCode> {
    match args.command.unwrap_or(MirrorCommand::Status) {
        MirrorCommand::Status => {
            print_status(runtime, out)?;
            Ok(ExitCode::SUCCESS)
        }
        MirrorCommand::On => {
            set_source(runtime, DEFAULT_MIRROR_SOURCE)?;
            control::note_live_instance(runtime).await;
            print_status(runtime, out)?;
            Ok(ExitCode::SUCCESS)
        }
        MirrorCommand::Off => {
            set_source(runtime, "")?;
            control::note_live_instance(runtime).await;
            print_status(runtime, out)?;
            Ok(ExitCode::SUCCESS)
        }
        MirrorCommand::Refresh => {
            match runtime.refresh_mirrors().await {
                Ok(0) => {
                    if !out.is_json() {
                        println!("mirror is off; nothing to fetch");
                    }
                }
                Ok(count) => {
                    if !out.is_json() {
                        println!("fetched {count} mirrors");
                    }
                }
                Err(error) => {
                    if out.is_json() {
                        out.json(&json!({ "error": format!("{error:#}") }))?;
                    } else {
                        eprintln!("refresh failed: {error:#}");
                    }
                    return Ok(ExitCode::FAILURE);
                }
            }
            print_status(runtime, out)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn set_source(runtime: &HakimiRuntime, source: &str) -> Result<()> {
    runtime.config().mutate(|config| {
        config.advanced.download.mirror_source = source.to_string();
        Ok(())
    })?;
    Ok(())
}

fn print_status(runtime: &HakimiRuntime, out: Output) -> Result<()> {
    let config = runtime.config().snapshot();
    let source = config.advanced.download.mirror_source.clone();
    let enabled = !source.trim().is_empty();
    let all = runtime.mirrors().all();
    let usable = runtime.mirrors().available();

    if out.is_json() {
        out.json(&json!({
            "enabled": enabled,
            "source": source,
            "mirrors": all,
            "usable": usable,
        }))?;
        return Ok(());
    }

    out.field("mirror", if enabled { "on" } else { "off" });
    if enabled {
        out.field("source", &source);
        out.field("sites", all.len());
        for mirror in &all {
            let state = if usable.contains(mirror) {
                ""
            } else {
                "  (cooling down)"
            };
            println!("  {mirror}{state}");
        }
    }
    Ok(())
}
