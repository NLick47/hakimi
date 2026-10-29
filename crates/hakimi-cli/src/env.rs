use std::net::IpAddr;

use anyhow::Result;
use clap::Args;
use hakimi_core::runtime::HakimiRuntime;

use crate::output::Output;

#[derive(Args)]
pub struct EnvArgs {
    /// Print `unset` lines instead of `export`.
    #[arg(long)]
    pub unset: bool,
}

pub fn run(runtime: &HakimiRuntime, args: EnvArgs, out: Output) -> Result<()> {
    let config = runtime.config().snapshot();
    let proxy = format!(
        "http://{}:{}",
        dial_host(config.proxy.bind),
        config.proxy.port
    );
    let no_proxy = "localhost,127.0.0.1,::1";
    if out.is_json() {
        return out.json(&serde_json::json!({
            "httpProxy": proxy,
            "httpsProxy": proxy,
            "allProxy": proxy,
            "noProxy": no_proxy,
        }));
    }
    if args.unset {
        println!("unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY");
        return Ok(());
    }
    println!("export HTTP_PROXY={proxy}");
    println!("export HTTPS_PROXY={proxy}");
    println!("export ALL_PROXY={proxy}");
    println!("export NO_PROXY={no_proxy}");
    Ok(())
}

/// A bind address is not necessarily an address a client can dial.
fn dial_host(bind: IpAddr) -> String {
    match bind {
        IpAddr::V4(address) if address.is_unspecified() => "127.0.0.1".to_string(),
        IpAddr::V6(address) if address.is_unspecified() => "[::1]".to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
        IpAddr::V4(address) => address.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::dial_host;

    #[test]
    fn bind_addresses_become_dial_addresses() {
        assert_eq!(dial_host("0.0.0.0".parse().unwrap()), "127.0.0.1");
        assert_eq!(dial_host("127.0.0.1".parse().unwrap()), "127.0.0.1");
        assert_eq!(dial_host("::".parse().unwrap()), "[::1]");
        assert_eq!(dial_host("::1".parse().unwrap()), "[::1]");
    }
}
