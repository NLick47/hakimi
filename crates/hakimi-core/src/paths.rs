use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// All on-disk locations used by the core.
///
/// Layout (under the platform data dir, e.g. `%APPDATA%\hakimi`):
/// ```text
/// config.json
/// ca/ca.pem, ca/key.pem
/// cache/state.json
/// cache/fake-sni.json
/// cache/catalog-ip.json, cache/catalog-ip.meta.json
/// cache/catalog-doh.json, cache/catalog-doh.meta.json
/// state/system-proxy.json
/// logs/hakimi.log (release), logs/hakimi-dev.log (debug)
/// ```
#[derive(Debug, Clone)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[cfg(not(target_os = "android"))]
    pub fn default_location() -> Result<Self> {
        let base = dirs::data_dir()
            .or_else(dirs::home_dir)
            .context("unable to determine a data directory")?;
        Ok(Self::new(base.join("hakimi")))
    }

    /// Android has no `dirs`-style data directory; the JNI shell passes the app files
    /// directory to [`crate::runtime::HakimiRuntime::new`] explicitly.
    #[cfg(target_os = "android")]
    pub fn default_location() -> Result<Self> {
        anyhow::bail!("Android callers must pass the app data directory explicitly")
    }

    pub fn ensure(&self) -> Result<()> {
        for dir in [
            self.root.clone(),
            self.ca_dir(),
            self.cache_dir(),
            self.state_dir(),
            self.logs_dir(),
        ] {
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn ca_dir(&self) -> PathBuf {
        self.root.join("ca")
    }

    pub fn ca_cert_file(&self) -> PathBuf {
        self.ca_dir().join("ca.pem")
    }

    pub fn ca_key_file(&self) -> PathBuf {
        self.ca_dir().join("key.pem")
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }

    pub fn state_file(&self) -> PathBuf {
        self.cache_dir().join("state.json")
    }

    pub fn catalog_ip_file(&self) -> PathBuf {
        self.cache_dir().join("catalog-ip.json")
    }

    pub fn catalog_ip_meta_file(&self) -> PathBuf {
        self.cache_dir().join("catalog-ip.meta.json")
    }

    pub fn catalog_doh_file(&self) -> PathBuf {
        self.cache_dir().join("catalog-doh.json")
    }

    pub fn catalog_doh_meta_file(&self) -> PathBuf {
        self.cache_dir().join("catalog-doh.meta.json")
    }

    pub fn mirror_list_file(&self) -> PathBuf {
        self.cache_dir().join("mirrors.json")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    pub fn system_proxy_state_file(&self) -> PathBuf {
        self.state_dir().join("system-proxy.json")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn log_file(&self) -> PathBuf {
        self.logs_dir().join(log_file_name(cfg!(debug_assertions)))
    }
}

/// Debug builds keep their own log so a development run cannot overwrite the
/// production log a release build is writing.
fn log_file_name(debug: bool) -> &'static str {
    if debug {
        "hakimi-dev.log"
    } else {
        "hakimi.log"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_and_debug_logs_never_share_a_file() {
        assert_eq!(log_file_name(false), "hakimi.log");
        assert_eq!(log_file_name(true), "hakimi-dev.log");
        assert_ne!(log_file_name(true), log_file_name(false));
    }

    #[test]
    fn a_debug_build_points_at_its_own_log() {
        let paths = Paths::new("/tmp/hakimi");
        assert_eq!(
            paths.log_file().file_name().unwrap(),
            log_file_name(cfg!(debug_assertions))
        );
    }
}
