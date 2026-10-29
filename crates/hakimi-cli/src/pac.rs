use std::net::SocketAddr;

use anyhow::Result;
use hakimi_core::runtime::HakimiRuntime;

use crate::control;

pub async fn run(runtime: &HakimiRuntime) -> Result<()> {
    // A running instance serves the PAC that matches its paused state and its
    // actual bound address; that is the script a browser is using right now.
    if let Some(script) = control::live_pac(runtime).await {
        print!("{script}");
        return Ok(());
    }
    let config = runtime.config().snapshot();
    let address = SocketAddr::new(config.proxy.bind, config.proxy.port);
    print!("{}", hakimi_core::pac::generate(&config, address, false));
    Ok(())
}
