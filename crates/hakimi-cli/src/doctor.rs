use std::collections::HashSet;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{bail, Result};
use clap::Args;
use hakimi_core::runtime::HakimiRuntime;
use hakimi_core::status::{DomainDiagnostics, State};
use tokio::sync::Semaphore;

use crate::output::Output;

/// Probes are network-bound; a handful at a time keeps a sweep quick without
/// turning it into a burst of TLS handshakes.
const SWEEP_CONCURRENCY: usize = 8;

#[derive(Args)]
pub struct DoctorArgs {
    /// Domain to diagnose.
    #[arg(
        value_name = "DOMAIN",
        required_unless_present = "all",
        conflicts_with = "all"
    )]
    pub domain: Option<String>,
    /// Diagnose every exact domain of every enabled group.
    #[arg(long)]
    pub all: bool,
}

pub async fn run(runtime: &Arc<HakimiRuntime>, args: DoctorArgs, out: Output) -> Result<ExitCode> {
    match (args.domain, args.all) {
        (Some(domain), _) => one(runtime, &domain, out).await,
        (None, true) => sweep(runtime, out).await,
        (None, false) => bail!("specify a domain, or --all"),
    }
}

async fn one(runtime: &Arc<HakimiRuntime>, domain: &str, out: Output) -> Result<ExitCode> {
    let diagnostics = runtime.diagnose(domain).await;
    if out.is_json() {
        out.json(&diagnostics)?;
    } else {
        print_one(out, &diagnostics);
    }
    Ok(exit_code(&diagnostics.state))
}

async fn sweep(runtime: &Arc<HakimiRuntime>, out: Output) -> Result<ExitCode> {
    let config = runtime.config().snapshot();
    let mut hosts = Vec::new();
    let mut seen = HashSet::new();
    for group in config.enabled_groups() {
        for host in group.exact_domains() {
            if seen.insert(host.to_string()) {
                hosts.push(host.to_string());
            }
        }
    }
    if hosts.is_empty() {
        println!("no exact domains in the enabled groups");
        return Ok(ExitCode::SUCCESS);
    }
    let total = hosts.len();
    let gate = Arc::new(Semaphore::new(SWEEP_CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for (index, host) in hosts.into_iter().enumerate() {
        let gate = gate.clone();
        let runtime = runtime.clone();
        tasks.spawn(async move {
            let _permit = gate.acquire_owned().await.ok();
            (index, runtime.diagnose(&host).await)
        });
    }
    let mut results = Vec::with_capacity(total);
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(entry) => results.push(entry),
            Err(error) => eprintln!("probe failed: {error}"),
        }
    }
    results.sort_by_key(|(index, _)| *index);
    let diagnostics: Vec<DomainDiagnostics> = results.into_iter().map(|(_, item)| item).collect();

    if out.is_json() {
        out.json(&diagnostics)?;
    } else {
        print_table(out, &diagnostics);
    }
    let failed = diagnostics
        .iter()
        .filter(|item| item.state == State::Failed)
        .count();
    Ok(if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn exit_code(state: &State) -> ExitCode {
    if *state == State::Failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn print_one(out: Output, diagnostics: &DomainDiagnostics) {
    out.field("domain", &diagnostics.domain);
    out.field("state", format!("{:?}", diagnostics.state).to_lowercase());
    out.field(
        "strategy",
        option(diagnostics.strategy.map(|v| v.to_string())),
    );
    out.field("ip", option(diagnostics.ip.map(|v| v.to_string())));
    out.field(
        "ip source",
        option(diagnostics.ip_source.map(|v| v.to_string())),
    );
    out.field(
        "doh source",
        option(diagnostics.doh_source.map(|v| v.to_string())),
    );
    out.field(
        "latency",
        option(diagnostics.latency_ms.map(|v| format!("{v}ms"))),
    );
    out.field("error", option(diagnostics.error.map(|v| v.to_string())));
    if let Some(detail) = &diagnostics.detail {
        out.field("detail", detail);
    }
    for suggestion in &diagnostics.suggestions {
        println!("suggestion:    {suggestion}");
    }
}

fn option(value: Option<String>) -> String {
    value.unwrap_or_else(|| "-".into())
}

fn print_table(out: Output, items: &[DomainDiagnostics]) {
    let rows = items
        .iter()
        .map(|item| {
            vec![
                item.domain.clone(),
                format!("{:?}", item.state).to_lowercase(),
                option(item.strategy.map(|v| v.to_string())),
                option(item.ip.map(|v| v.to_string())),
                option(item.latency_ms.map(|v| v.to_string())),
                item.error
                    .as_ref()
                    .map(|error| error.to_string())
                    .unwrap_or_default(),
            ]
        })
        .collect::<Vec<_>>();
    out.table(
        &["domain", "state", "mode", "ip", "ms", "error"],
        &rows,
        &[4],
    );
    let mut ok = 0;
    let mut degraded = 0;
    let mut failed = 0;
    for item in items {
        match item.state {
            State::Normal | State::Direct => ok += 1,
            State::Degraded => degraded += 1,
            State::Failed => failed += 1,
            _ => {}
        }
    }
    println!(
        "\n{} domains: {} ok, {} degraded, {} failed",
        items.len(),
        ok,
        degraded,
        failed
    );
}
