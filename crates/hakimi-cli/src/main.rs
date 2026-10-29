mod ca;
mod catalog;
mod config_cmd;
mod control;
mod doctor;
mod doh;
mod env;
mod export;
mod group;
mod output;
mod pac;
mod serve;
mod status;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use hakimi_core::runtime::HakimiRuntime;

use crate::output::Output;

#[derive(Parser)]
#[command(
    name = "hakimi",
    version = hakimi_core::VERSION,
    about = "local acceleration proxy for the configured sites"
)]
struct Cli {
    /// Override the data directory (defaults to the platform data dir).
    #[arg(long, global = true, value_name = "DIR", env = "HAKIMI_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Print machine-readable JSON instead of tables.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the local proxy and apply the system proxy/PAC.
    Serve(serve::ServeArgs),
    /// Stop the running instance.
    Stop,
    /// Pause acceleration; the PAC returns DIRECT.
    Pause,
    /// Resume acceleration.
    Resume,
    /// Print the runtime status.
    Status,
    /// Diagnose one domain, or every domain of the enabled groups.
    Doctor(doctor::DoctorArgs),
    /// List or change groups.
    Group(group::GroupArgs),
    /// Print or change the configuration.
    Config(config_cmd::ConfigArgs),
    /// Manage the local CA.
    Ca {
        #[command(subcommand)]
        command: ca::CaArgs,
    },
    /// Refresh the remote catalogs.
    Catalog {
        #[command(subcommand)]
        command: catalog::CatalogCommand,
    },
    /// Check the DoH endpoints.
    Doh {
        #[command(subcommand)]
        command: doh::DohCommand,
    },
    /// Print the proxy environment variables for this shell.
    Env(env::EnvArgs),
    /// Print the PAC script.
    Pac,
    /// Export a sanitized diagnostics bundle.
    Export(export::ExportArgs),
    /// Restore the OS proxy settings saved by a previous `serve` run.
    RestoreProxy,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("hakimi: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let out = Output::new(cli.json);
    // `serve` owns the log sink: its flags decide where the first line goes.
    if let Command::Serve(args) = &cli.command {
        serve::init_logging(cli.data_dir.as_deref(), args)?;
    }
    let runtime = HakimiRuntime::new(cli.data_dir.clone())?;
    match cli.command {
        Command::Serve(args) => serve::run(&runtime, args).await?,
        Command::Stop => control::stop(&runtime).await?,
        Command::Pause => control::set_paused(&runtime, true).await?,
        Command::Resume => control::set_paused(&runtime, false).await?,
        Command::Status => status::run(&runtime, out).await?,
        Command::Doctor(args) => return doctor::run(&runtime, args, out).await,
        Command::Group(args) => group::run(&runtime, args, out).await?,
        Command::Config(args) => config_cmd::run(&runtime, args, out).await?,
        Command::Ca { command } => return ca::run(&runtime, command, out).await,
        Command::Catalog { command } => return catalog::run(&runtime, command, out).await,
        Command::Doh { command } => doh::run(&runtime, command, out).await?,
        Command::Env(args) => env::run(&runtime, args, out)?,
        Command::Pac => pac::run(&runtime).await?,
        Command::Export(args) => export::run(&runtime, args)?,
        Command::RestoreProxy => {
            let restored = runtime.restore_system_proxy()?;
            if restored {
                println!("system proxy settings restored");
            } else {
                println!("no saved system proxy state found");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
