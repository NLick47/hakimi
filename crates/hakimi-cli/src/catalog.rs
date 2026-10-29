use std::process::ExitCode;

use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use hakimi_core::catalog::RefreshReport;
use hakimi_core::runtime::HakimiRuntime;
use serde_json::json;

use crate::output::Output;

#[derive(Subcommand)]
pub enum CatalogCommand {
    /// Refresh the IP and/or DoH catalog.
    Refresh {
        #[arg(long, value_enum, default_value_t = CatalogKind::All)]
        kind: CatalogKind,
        /// Fetch even when the cached copy looks current.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum CatalogKind {
    Ip,
    Doh,
    All,
}

pub async fn run(runtime: &HakimiRuntime, args: CatalogCommand, out: Output) -> Result<ExitCode> {
    let CatalogCommand::Refresh { kind, force } = args;
    let results = match kind {
        CatalogKind::All => runtime.refresh_catalogs(force).await,
        CatalogKind::Ip => vec![runtime.refresh_catalog("ip", force).await],
        CatalogKind::Doh => vec![runtime.refresh_catalog("doh", force).await],
    };
    let mut failed = false;
    let mut values = Vec::new();
    for result in results {
        match result {
            Ok(report) => {
                if out.is_json() {
                    values.push(serde_json::to_value(&report)?);
                } else {
                    print_report(&report);
                }
            }
            Err(error) => {
                failed = true;
                if out.is_json() {
                    values.push(json!({ "error": format!("{error:#}") }));
                } else {
                    eprintln!("refresh failed: {error:#}");
                }
            }
        }
    }
    if out.is_json() {
        out.json(&values)?;
    } else if values.is_empty() {
        println!("no remote catalog configured (catalogs.ip and catalogs.doh are empty)");
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn print_report(report: &RefreshReport) {
    let state = if report.updated {
        "updated"
    } else if report.up_to_date {
        "up to date"
    } else {
        "unchanged"
    };
    println!(
        "{}: {} (version {}, {} domains)",
        report.kind,
        state,
        report.version,
        report.affected_domains.len()
    );
    if let Some(source) = &report.source {
        println!("  source: {source}");
    }
    if let Some(message) = &report.message {
        println!("  {}", message);
    }
    for warning in &report.warnings {
        println!("  warning: {warning}");
    }
}
