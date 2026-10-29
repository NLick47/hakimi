use anyhow::Result;
use clap::Subcommand;
use hakimi_core::runtime::HakimiRuntime;

use crate::output::Output;

#[derive(Subcommand)]
pub enum DohCommand {
    /// Query every configured endpoint once.
    Health,
}

pub async fn run(runtime: &HakimiRuntime, args: DohCommand, out: Output) -> Result<()> {
    let DohCommand::Health = args;
    let health = runtime.doh_health().await;
    if out.is_json() {
        return out.json(&health);
    }
    let rows = health
        .iter()
        .map(|item| {
            vec![
                item.name.clone(),
                item.source.to_string(),
                if item.healthy { "ok" } else { "failed" }.to_string(),
                item.latency_ms
                    .map(|latency| format!("{latency}ms"))
                    .unwrap_or_else(|| "-".into()),
                item.url.clone(),
            ]
        })
        .collect::<Vec<_>>();
    out.table(
        &["name", "source", "state", "latency", "endpoint"],
        &rows,
        &[3],
    );
    for item in health.iter().filter(|item| item.last_error.is_some()) {
        println!(
            "{}: {}",
            item.name,
            item.last_error.as_deref().unwrap_or_default()
        );
    }
    Ok(())
}
