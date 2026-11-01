use std::net::IpAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use hakimi_core::runtime::HakimiRuntime;
use serde_json::Value;

/// Local control endpoint on the configured proxy address.
pub fn endpoint(runtime: &HakimiRuntime, path: &str) -> String {
    let config = runtime.config().snapshot();
    endpoint_url(config.proxy.bind, config.proxy.port, path)
}

fn endpoint_url(bind: IpAddr, port: u16, path: &str) -> String {
    // A v6 bind needs brackets in the authority: `http://::1:p` parses for
    // no HTTP client. Same dialing rules as `hakimi env`.
    format!("http://{}:{port}{path}", crate::env::dial_host(bind))
}

pub fn client(timeout: Duration) -> Result<reqwest::Client> {
    hakimi_core::util::install_crypto_provider();
    reqwest::Client::builder()
        .timeout(timeout)
        .no_proxy()
        .build()
        .context("building the local HTTP client")
}

async fn post(runtime: &HakimiRuntime, path: &str) -> Result<Value> {
    let url = endpoint(runtime, path);
    let response = client(Duration::from_secs(3))?
        .post(&url)
        .header("x-hakimi-control", "1")
        .send()
        .await
        .with_context(|| {
            format!("no reachable instance at {url}; start one with `hakimi serve`")
        })?;
    let status = response.status();
    let text = response.text().await.context("reading the response")?;
    if !status.is_success() {
        bail!("{path} failed: HTTP {status}: {text}");
    }
    serde_json::from_str(&text).with_context(|| format!("unexpected response from {path}: {text}"))
}

pub async fn set_paused(runtime: &HakimiRuntime, paused: bool) -> Result<()> {
    let path = if paused {
        "/hakimi/pause"
    } else {
        "/hakimi/resume"
    };
    post(runtime, path).await?;
    println!("{}", if paused { "paused" } else { "resumed" });
    Ok(())
}

pub async fn stop(runtime: &HakimiRuntime) -> Result<()> {
    let value = post(runtime, "/hakimi/stop").await?;
    if value["stopping"].as_bool() != Some(true) {
        bail!("the instance did not accept the stop request");
    }
    // The instance flushes the cache and restores the OS proxy before it
    // closes the listener, so wait for the port to stop answering.
    let health = endpoint(runtime, "/hakimi/health");
    let probe = client(Duration::from_millis(400))?;
    for _ in 0..40 {
        if probe.get(&health).send().await.is_err() {
            println!("stopped");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    bail!("stop requested, but the instance still answers on {health}");
}

/// The PAC script the running instance actually serves, which reflects its
/// paused state and its bound address. `None` when nothing is listening.
pub async fn live_pac(runtime: &HakimiRuntime) -> Option<String> {
    let url = endpoint(runtime, "/proxy.pac");
    let response = client(Duration::from_millis(800))
        .ok()?
        .get(url)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let text = response.text().await.ok()?;
    text.contains("FindProxyForURL").then_some(text)
}

/// Configuration edits land on disk; a running instance only reads them on
/// its next start.
pub async fn note_live_instance(runtime: &HakimiRuntime) {
    let url = endpoint(runtime, "/hakimi/health");
    let Ok(probe) = client(Duration::from_millis(250)) else {
        return;
    };
    if probe.get(url).send().await.is_ok() {
        eprintln!("note: the running instance keeps its current config until it restarts");
    }
}

#[cfg(test)]
mod tests {
    use super::endpoint_url;

    #[test]
    fn v6_binds_are_bracketed_in_the_authority() {
        let bind: std::net::IpAddr = "::1".parse().unwrap();
        assert_eq!(
            endpoint_url(bind, 8443, "/hakimi/stop"),
            "http://[::1]:8443/hakimi/stop",
            "`http://::1:8443` would fail to parse in every HTTP client"
        );
        let bind: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(endpoint_url(bind, 8443, "/x"), "http://127.0.0.1:8443/x");
    }
}
