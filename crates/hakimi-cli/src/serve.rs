use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use hakimi_core::config::ConfigManager;
use hakimi_core::instance::InstanceLock;
use hakimi_core::logging::{self, LoggingOptions};
use hakimi_core::paths::Paths;
use hakimi_core::runtime::HakimiRuntime;

use crate::output::Output;

#[derive(Args)]
pub struct ServeArgs {
    /// Do not read or write the OS proxy setting.
    #[arg(long)]
    pub no_takeover: bool,
    /// Start in the paused state (the PAC returns DIRECT).
    #[arg(long)]
    pub paused: bool,
    /// Also write log lines to stderr, for a service manager that collects them.
    #[arg(long)]
    pub log_stdout: bool,
    /// Log level (trace, debug, info, warn, error); wins over RUST_LOG and
    /// config.log.level.
    #[arg(long, value_name = "LEVEL")]
    pub log_level: Option<String>,
}

/// Install the subscriber before the runtime is created, so `--log-level` and
/// `--log-stdout` shape the very first line the process writes.
pub fn init_logging(data_dir: Option<&Path>, args: &ServeArgs) -> Result<()> {
    if logging::initialized() {
        return Ok(());
    }
    let paths = match data_dir {
        Some(path) => Paths::new(path),
        None => Paths::default_location()?,
    };
    let config = ConfigManager::load_or_create(&paths)?;
    let config = config.snapshot();
    let level = args
        .log_level
        .clone()
        .unwrap_or_else(|| config.log.level.clone());
    logging::init_with(
        &paths,
        &level,
        config.log.format,
        LoggingOptions {
            stderr: args.log_stdout,
            explicit_level: args.log_level.is_some(),
        },
    )
}

pub async fn run(runtime: &Arc<HakimiRuntime>, args: ServeArgs) -> Result<()> {
    // Long-running instance: hold the single-instance lock for the whole
    // lifetime, so a second serve (or the UI) cannot fight over the port.
    let _instance_lock = InstanceLock::acquire(runtime.paths().root())?;
    // `--no-takeover` is a per-run choice: it must not be written into the
    // config, and it must not disable a proxy the user configured themselves.
    // Platforms without a system proxy (Linux) never take over: the proxy is
    // the product there and the user decides who points at it.
    let takeover_unsupported = runtime.config().snapshot().proxy.takeover
        && !hakimi_core::system_proxy::takeover_supported();
    if args.no_takeover || takeover_unsupported {
        runtime.start_without_takeover().await?;
    } else {
        runtime.start().await?;
    }
    if args.paused {
        runtime.pause();
    }
    banner(runtime, args.paused);
    notes(runtime, takeover_unsupported);
    let mut shutdown = runtime.shutdown_receiver();
    match shutdown.as_mut() {
        // A stop request from another process (`hakimi stop`) arrives here as
        // a shutdown signal; the cleanup below is the same either way.
        Some(receiver) => {
            tokio::select! {
                _ = stop_signal() => {}
                _ = receiver.changed() => {}
            }
        }
        None => stop_signal().await,
    }
    runtime.stop().await?;
    println!("stopped");
    Ok(())
}

/// Hints for the two steps the CLI deliberately leaves to the user: taking
/// over a system proxy (no such thing on Linux) and trusting the CA, which
/// needs the OS authorization dialog on macOS or root on Linux. A service
/// manager collects stderr into the journal, so this is terminal-only.
fn notes(runtime: &HakimiRuntime, takeover_unsupported: bool) {
    if !std::io::stderr().is_terminal() {
        return;
    }
    if takeover_unsupported {
        if let Some(url) = runtime.proxy_url() {
            eprintln!("提示：本平台没有可接管的系统代理，请自行把工具指向 {url}");
        }
        eprintln!("提示：shell 用 `eval \"$(hakimi env)\"`，浏览器用 `hakimi pac` 生成的脚本");
    }
    let status = runtime.status_json();
    if !status["ca"]["installed"].as_bool().unwrap_or(false) {
        eprintln!("提示：本地 CA 尚未被信任，需要终结 TLS 的路径会失败");
        eprintln!(
            "提示：安装命令：{}",
            crate::ca::privileged_command(runtime, "install")
        );
    }
}

fn banner(runtime: &HakimiRuntime, paused: bool) {
    let out = Output::new(false);
    println!(
        "hakimi {} ({})",
        hakimi_core::VERSION,
        if paused { "paused" } else { "running" }
    );
    match runtime.proxy_url() {
        Some(url) => out.field("proxy", url),
        None => out.field("proxy", "disabled (proxy.mode = off)"),
    }
    if let Some(pac) = runtime.pac_url() {
        out.field("pac", pac);
    }
    out.field("data", runtime.paths().root().display());
    out.field("log", runtime.paths().log_file().display());
    println!("press Ctrl+C to stop");
}

async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).ok();
        // Closing the terminal sends SIGHUP. Exiting through the same path as
        // SIGTERM keeps the cache flush and the OS-proxy restore from being
        // skipped, which is what a killed-by-hangup process used to leave
        // behind.
        let mut hangup = signal(SignalKind::hangup()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = wait(terminate.as_mut()) => {}
            _ = wait(hangup.as_mut()) => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Resolves when the signal arrives, or never when it could not be registered.
#[cfg(unix)]
async fn wait(signal: Option<&mut tokio::signal::unix::Signal>) {
    match signal {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}
