//! hakimi shared Rust core.
//!
//! The crate is intentionally UI-agnostic. Desktop shells call into [`runtime::HakimiRuntime`]
//! (or the C ABI in `hakimi-ffi`); Android can reuse the same modules through JNI later.
//!
//! Module map follows the design document:
//! - [`config`] global/group/catalog configuration
//! - [`catalog`] remote IP and DoH catalogs (fetch, validate, sign, cache)
//! - [`resolver`] DoH + HTTPS RR + ECH
//! - [`ip_tester`] ordered TCP/TLS/certificate probes
//! - [`strategy`] direct / ECH / fake-SNI / auto
//! - [`decision`] connection decision engine and last-good cache rules
//! - [`proxy`] local HTTP/CONNECT proxy + MITM
//! - [`ca`] local CA and on-demand leaf certificates
//! - [`status`] group/domain state and diagnostics
//! - [`logging`] local logging and redaction

/// Version of the linked core crate, reported separately from the client shell.
///
/// This is the core package version from `crates/hakimi-core/Cargo.toml`, not
/// the client release tag. Release CI only overwrites the workspace version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod bench;
pub mod ca;
pub mod cache;
pub mod catalog;
pub mod config;
pub mod decision;
pub mod dns;
pub mod domain;
pub mod hooks;
pub mod instance;
pub mod ip_tester;
pub mod logging;
pub mod pac;
pub mod paths;
pub mod proxy;
pub mod resolver;
pub mod runtime;
pub mod status;
pub mod strategy;
pub mod system_proxy;
pub mod util;

pub use config::{AppConfig, DomainRule, GroupConfig, RouteAttempt, RoutePolicy};
pub use runtime::HakimiRuntime;
