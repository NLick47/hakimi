use std::net::IpAddr;

use anyhow::Result;
use clap::Args;
use hakimi_core::config::ProxyMode;
use hakimi_core::runtime::HakimiRuntime;

use crate::output::Output;

#[derive(Args)]
pub struct EnvArgs {
    /// Print `unset` lines instead of `export`.
    #[arg(long)]
    pub unset: bool,
}

const NO_PROXY: &str = "localhost,127.0.0.1,::1";

pub fn run(runtime: &HakimiRuntime, args: EnvArgs, out: Output) -> Result<()> {
    let config = runtime.config().snapshot();
    if out.is_json() {
        let value = if config.proxy.mode == ProxyMode::Off {
            serde_json::json!({ "mode": "off" })
        } else {
            let proxy = dial_url(config.proxy.bind, config.proxy.port);
            serde_json::json!({
                "httpProxy": proxy,
                "httpsProxy": proxy,
                "allProxy": proxy,
                "noProxy": NO_PROXY,
            })
        };
        return out.json(&value);
    }
    let proxy = dial_url(config.proxy.bind, config.proxy.port);
    for line in shell_lines(config.proxy.mode, &proxy, args.unset) {
        println!("{line}");
    }
    Ok(())
}

/// The lines `hakimi env` prints. An `Off` mode exports nothing: the proxy
/// variables would point every tool at a port nothing listens on.
fn shell_lines(mode: ProxyMode, proxy: &str, unset: bool) -> Vec<String> {
    if mode == ProxyMode::Off || unset {
        return vec!["unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY".to_string()];
    }
    vec![
        format!("export HTTP_PROXY={proxy}"),
        format!("export HTTPS_PROXY={proxy}"),
        format!("export ALL_PROXY={proxy}"),
        format!("export NO_PROXY={NO_PROXY}"),
    ]
}

fn dial_url(bind: IpAddr, port: u16) -> String {
    format!("http://{}:{port}", dial_host(bind))
}

/// A bind address is not necessarily an address a client can dial.
pub(crate) fn dial_host(bind: IpAddr) -> String {
    match bind {
        IpAddr::V4(address) if address.is_unspecified() => "127.0.0.1".to_string(),
        IpAddr::V6(address) if address.is_unspecified() => "[::1]".to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
        IpAddr::V4(address) => address.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{dial_host, shell_lines};
    use hakimi_core::config::ProxyMode;

    #[test]
    fn bind_addresses_become_dial_addresses() {
        assert_eq!(dial_host("0.0.0.0".parse().unwrap()), "127.0.0.1");
        assert_eq!(dial_host("127.0.0.1".parse().unwrap()), "127.0.0.1");
        assert_eq!(dial_host("::".parse().unwrap()), "[::1]");
        assert_eq!(dial_host("::1".parse().unwrap()), "[::1]");
    }

    #[test]
    fn off_mode_exports_nothing() {
        let lines = shell_lines(ProxyMode::Off, "http://127.0.0.1:8443", false);
        assert!(
            lines.iter().all(|line| !line.starts_with("export")),
            "an off proxy would point every tool at a dead port: {lines:?}"
        );
        assert!(lines[0].starts_with("unset"));
    }

    #[test]
    fn a_running_mode_still_exports_the_proxy() {
        let lines = shell_lines(ProxyMode::Pac, "http://[::1]:8443", false);
        assert!(lines.iter().any(|line| line == "export HTTP_PROXY=http://[::1]:8443"));
        assert!(lines.iter().any(|line| line == "export NO_PROXY=localhost,127.0.0.1,::1"));
    }
}
