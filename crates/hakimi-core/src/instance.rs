//! Single-instance guard: an exclusive lock file inside the data directory.
//!
//! The OS releases the lock when the holding process dies — including on a
//! crash — so there is no stale-lock recovery to implement. Every long-running
//! entry point (the UI, `hakimi serve`) takes the lock for its lifetime; short
//! CLI commands (`status`, `restore-proxy`, …) stay lock-free so they can
//! operate alongside a running instance.

use std::fs::File;
use std::path::{Path, PathBuf};

/// Held for the whole process lifetime; dropping it releases the lock.
pub struct InstanceLock {
    _file: File,
}

#[derive(Debug)]
pub enum InstanceLockError {
    /// Another long-running instance holds the lock for this data directory.
    AlreadyRunning { path: PathBuf },
    Io(std::io::Error),
}

impl std::fmt::Display for InstanceLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRunning { path } => write!(
                f,
                "another hakimi instance is already running (lock: {})",
                path.display()
            ),
            Self::Io(error) => write!(f, "instance lock: {error}"),
        }
    }
}

impl std::error::Error for InstanceLockError {}

impl InstanceLock {
    pub fn acquire(data_dir: &Path) -> Result<Self, InstanceLockError> {
        std::fs::create_dir_all(data_dir).map_err(InstanceLockError::Io)?;
        let path = data_dir.join("hakimi.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(InstanceLockError::Io)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {
                Err(InstanceLockError::AlreadyRunning { path })
            }
            Err(std::fs::TryLockError::Error(error)) => Err(InstanceLockError::Io(error)),
        }
    }
}
