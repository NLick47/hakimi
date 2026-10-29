use std::time::Duration;

use anyhow::Result;
use hakimi_core::cache::CacheStats;
use hakimi_core::runtime::HakimiRuntime;
use serde_json::Value;

use crate::output::Output;

pub async fn run(runtime: &HakimiRuntime, out: Output) -> Result<()> {
    let local = runtime.status_json();
    let value = match try_live_status(runtime).await {
        Some(live) if same_data_dir(&live, &local) => live,
        Some(_) => {
            // The port alone does not identify an instance: another data
            // directory can point at the same one. The CA lives in the data
            // directory, so its fingerprint tells the two apart.
            eprintln!("note: another instance answers on this port; showing this data dir");
            local
        }
        None => local,
    };
    if out.is_json() {
        return out.json(&value);
    }
    print_human(out, &value);
    Ok(())
}

async fn try_live_status(runtime: &HakimiRuntime) -> Option<Value> {
    let url = crate::control::endpoint(runtime, "/hakimi/status");
    let client = crate::control::client(Duration::from_millis(600)).ok()?;
    let value: Value = tokio::time::timeout(Duration::from_millis(800), async {
        let text = client.get(url).send().await.ok()?.text().await.ok()?;
        serde_json::from_str(&text).ok()
    })
    .await
    .ok()??;
    // Something else may listen on the proxy port. Only a hakimi answer is a
    // status; anything else falls back to this runtime's own snapshot.
    (value["app"].as_str() == Some("hakimi")).then_some(value)
}

fn same_data_dir(live: &Value, local: &Value) -> bool {
    live["ca"]["fingerprintSha1"] == local["ca"]["fingerprintSha1"]
}

fn print_human(out: Output, value: &Value) {
    let running = value["proxy"]["running"].as_bool().unwrap_or(false);
    let paused = value["paused"].as_bool().unwrap_or(false);
    let state = if !running {
        "stopped"
    } else if paused {
        "paused"
    } else {
        "running"
    };
    println!(
        "hakimi {} — {}",
        value["version"].as_str().unwrap_or("?"),
        state
    );
    if let Some(listen) = value["proxy"]["listen"].as_str() {
        out.field("proxy", listen);
    }
    if let Some(pac) = value["proxy"]["pacUrl"].as_str() {
        out.field("pac", pac);
    }
    let ca = &value["ca"];
    out.field(
        "ca",
        format!(
            "{} ({})",
            if ca["installed"].as_bool().unwrap_or(false) {
                "trusted"
            } else {
                "untrusted"
            },
            ca["fingerprintSha1"].as_str().unwrap_or("-")
        ),
    );
    if !running {
        println!("start one with `hakimi serve`");
        print_warnings(value);
        return;
    }
    if let Some(groups) = value["groups"].as_array() {
        let rows = groups
            .iter()
            .map(|group| {
                let state = group["state"].as_str().unwrap_or("?");
                // Nothing has been tested yet: nothing is being checked either.
                let state =
                    if state == "checking" && group["testedDomains"].as_u64().unwrap_or(0) == 0 {
                        "untested"
                    } else {
                        state
                    };
                vec![
                    group["id"].as_str().unwrap_or("?").to_string(),
                    state.to_string(),
                    group["name"].as_str().unwrap_or("").to_string(),
                    group["testedDomains"].as_u64().unwrap_or(0).to_string(),
                    group["failedDomains"].as_u64().unwrap_or(0).to_string(),
                ]
            })
            .collect::<Vec<_>>();
        out.table(
            &["group", "state", "name", "tested", "failed"],
            &rows,
            &[3, 4],
        );
    }
    let cache: CacheStats = serde_json::from_value(value["cache"].clone()).unwrap_or_default();
    out.field(
        "cache",
        format!(
            "lastGood={} doh={} ech={} sni={}",
            cache.last_good, cache.doh_answers, cache.ech_configs, cache.fake_sni
        ),
    );
    print_warnings(value);
}

fn print_warnings(value: &Value) {
    if let Some(warnings) = value["warnings"].as_array() {
        for warning in warnings.iter().filter_map(Value::as_str) {
            // The `ca` line above already states the trust state.
            if warning == "ca_untrusted" {
                continue;
            }
            println!("warning: {warning}");
        }
    }
}
