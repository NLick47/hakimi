use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use hakimi_core::runtime::HakimiRuntime;

#[derive(Args)]
pub struct ExportArgs {
    /// Copy the bundle here instead of leaving it in the data directory.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

pub fn run(runtime: &HakimiRuntime, args: ExportArgs) -> Result<()> {
    let path = runtime.export_diagnostics()?;
    match args.out {
        Some(out) => {
            std::fs::copy(&path, &out)?;
            println!("{}", out.display());
        }
        None => println!("{}", path.display()),
    }
    Ok(())
}
