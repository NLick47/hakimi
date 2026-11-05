use std::process::ExitCode;

use anyhow::Result;
use clap::Subcommand;
use hakimi_core::runtime::HakimiRuntime;

use crate::output::Output;

#[derive(Subcommand)]
pub enum DohCommand {
    /// Query every configured endpoint once.
    Health,
}

pub async fn run(runtime: &HakimiRuntime, args: DohCommand, out: Output) -> Result<ExitCode> {
    let DohCommand::Health = args;
    let health = runtime.doh_health().await;
    if out.is_json() {
        out.json(&health)?;
    } else {
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
    }
    // A health check that finds every endpoint down must fail the command,
    // so scripted `doh health && notify_ok` cannot report a false positive.
    // A single unhealthy endpoint among several is not a failure: the resolver
    // races endpoints, so one timeout does not mean name resolution is down.
    Ok(health_exit_code(health.iter().map(|item| item.healthy)))
}

/// `doh health` fails only when there is at least one endpoint and all of them
/// are down. An empty list means "nothing was checked", which must not be
/// reported as a healthy success either.
fn health_exit_code(states: impl IntoIterator<Item = bool>) -> ExitCode {
    let mut any = false;
    let mut any_healthy = false;
    for healthy in states {
        any = true;
        any_healthy |= healthy;
    }
    // Only an all-down (and non-empty) result fails. An empty check is
    // inconclusive and must not be a green light for `doh health && ...`.
    if !any || !any_healthy {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::health_exit_code;
    use std::process::ExitCode;

    fn ok(code: ExitCode) -> bool {
        code == ExitCode::SUCCESS
    }

    #[test]
    fn one_down_endpoint_among_healthy_ones_still_succeeds() {
        // The old `any(|!healthy)` logic failed the whole command here.
        assert!(ok(health_exit_code([true, false, true])));
        assert!(ok(health_exit_code([false, true])));
    }

    #[test]
    fn every_endpoint_down_fails() {
        assert!(!ok(health_exit_code([false, false])));
        assert!(!ok(health_exit_code([false])));
    }

    #[test]
    fn all_healthy_succeeds() {
        assert!(ok(health_exit_code([true, true])));
    }

    #[test]
    fn an_empty_check_is_not_reported_as_healthy() {
        assert!(!ok(health_exit_code([])));
    }
}
