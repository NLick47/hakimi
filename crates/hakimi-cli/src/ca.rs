use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Subcommand;
use hakimi_core::ca::{CaStatus, NeedsRoot};
use hakimi_core::runtime::HakimiRuntime;

use crate::output::Output;

#[derive(Subcommand)]
pub enum CaArgs {
    /// Show whether the local CA exists and is trusted.
    Status,
    /// Print the local CA as PEM, for trusting it yourself.
    Export {
        /// Copy it here instead of printing it.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
    /// Install and trust the local CA.
    Install,
    /// Remove the local CA and its trust entry.
    Uninstall,
    /// Re-apply trust for the existing CA.
    Repair,
    /// Replace the local CA with a new key pair.
    Regenerate,
}

pub async fn run(runtime: &HakimiRuntime, args: CaArgs, out: Output) -> Result<ExitCode> {
    if let CaArgs::Export { out: path } = args {
        export(runtime, path, out)?;
        return Ok(ExitCode::SUCCESS);
    }
    let (action, status) = match args {
        CaArgs::Status => (None, runtime.ca_status().await),
        CaArgs::Install => {
            show_target(runtime, "将写入");
            (
                Some("installed"),
                root_action(runtime, "install", runtime.ca_install())?,
            )
        }
        CaArgs::Uninstall => {
            // Uninstalling something that was never installed is a no-op, and
            // the headline should say so instead of claiming a removal.
            let installed = runtime.ca_status().await.installed;
            show_target(runtime, "将删除");
            let status = root_action(runtime, "uninstall", runtime.ca_uninstall())?;
            let label = if installed {
                "removed"
            } else {
                "本地 CA 未安装，无需移除"
            };
            (Some(label), status)
        }
        CaArgs::Repair => {
            show_target(runtime, "将写入");
            (
                Some("repaired"),
                root_action(runtime, "repair", runtime.ca_repair())?,
            )
        }
        CaArgs::Regenerate => {
            show_target(runtime, "将写入");
            (
                Some("regenerated"),
                root_action(runtime, "regenerate", runtime.ca_regenerate())?,
            )
        }
        CaArgs::Export { .. } => unreachable!("handled above"),
    };
    if out.is_json() {
        out.json(&status)?;
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(action) = action {
        println!("{action}");
    }
    print_status(out, &status);
    Ok(ExitCode::SUCCESS)
}

/// Says what the next action changes before it happens: on Linux the trust
/// store is a file plus a distro tool, and a silent success leaves people
/// guessing what was touched.
fn show_target(runtime: &HakimiRuntime, verb: &str) {
    if let Some((anchor, command)) = runtime.ca().install_target() {
        eprintln!("{verb} {anchor}");
        eprintln!("随后用 {command} 重建证书库");
    }
}

fn export(runtime: &HakimiRuntime, out_path: Option<PathBuf>, out: Output) -> Result<()> {
    let source = runtime.paths().ca_cert_file();
    let pem = std::fs::read(&source).with_context(|| format!("reading {}", source.display()))?;
    let status = runtime.ca().status_cached();
    let target = match out_path {
        Some(path) => {
            std::fs::write(&path, &pem).with_context(|| format!("writing {}", path.display()))?;
            Some(path)
        }
        None => None,
    };
    if out.is_json() {
        let path = target.clone().unwrap_or_else(|| source.clone());
        return out.json(&serde_json::json!({
            "path": path.display().to_string(),
            "sha1": status.fingerprint_sha1,
            "sha256": status.fingerprint_sha256,
        }));
    }
    match &target {
        Some(path) => println!("{}", path.display()),
        None => print!("{}", String::from_utf8_lossy(&pem)),
    }
    trust_hint(target.as_deref().unwrap_or(&source));
    Ok(())
}

/// The manual steps, kept next to the export so the two stay in sync.
fn trust_hint(path: &Path) {
    let path = path.display().to_string();
    #[cfg(target_os = "linux")]
    {
        eprintln!();
        eprintln!("如需信任，请选择与你系统匹配的方式：");
        eprintln!(
            "  Debian/Ubuntu  sudo cp {path} /usr/local/share/ca-certificates/hakimi.crt && sudo update-ca-certificates"
        );
        eprintln!(
            "  Fedora/RHEL    sudo cp {path} /etc/pki/ca-trust/source/anchors/hakimi.pem && sudo update-ca-trust extract"
        );
        eprintln!("  Arch/p11-kit   sudo trust anchor --store {path}");
        eprintln!("  NixOS          写进 security.pki.certificates");
        eprintln!(
            "  Firefox/NSS    certutil -d sql:$HOME/.pki/nssdb -A -t \"C,,\" -n hakimi -i {path}"
        );
    }
    #[cfg(target_os = "macos")]
    {
        eprintln!();
        eprintln!("如需信任：");
        eprintln!(
            "  security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db {path}"
        );
        eprintln!("也可以把它拖进\"钥匙串访问\"，将证书设为\"始终信任\"。");
    }
    #[cfg(windows)]
    {
        eprintln!();
        eprintln!("如需信任：");
        eprintln!("  certutil -addstore -user Root {path}");
        eprintln!("也可以双击文件，安装到\"受信任的根证书颁发机构\"。");
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
    }
}

/// On Linux the trust store is only writable as root, and `sudo` starts with
/// root's environment: the data directory has to be named explicitly or the
/// command would act on `/root/.local/share/hakimi`.
fn root_action<T>(runtime: &HakimiRuntime, action: &str, result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            if error.chain().any(|cause| cause.is::<NeedsRoot>()) {
                // One message, error first and the fix below it: main prints
                // the whole thing after its `hakimi:` prefix.
                return Err(anyhow::anyhow!(
                    "{error:#}\n提示：sudo 不会继承 HAKIMI_DATA_DIR，请显式指定数据目录：\n  {}",
                    privileged_command(runtime, action)
                ));
            }
            Err(error)
        }
    }
}

/// The command that touches the trust store, with the data directory spelled
/// out: `sudo` does not inherit `HAKIMI_DATA_DIR`, and on Linux the trust store
/// is only writable as root.
pub fn privileged_command(runtime: &HakimiRuntime, action: &str) -> String {
    let binary = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "hakimi".to_string());
    let sudo = if cfg!(target_os = "linux") {
        "sudo "
    } else {
        ""
    };
    format!(
        "{sudo}{binary} --data-dir {} ca {action}",
        runtime.paths().root().display()
    )
}

fn print_status(out: Output, status: &CaStatus) {
    out.field("present", yes_no(status.present));
    out.field("trusted", yes_no(status.installed));
    if !status.supported {
        out.field("automatic", "unsupported on this platform");
    }
    if let Some(subject) = &status.subject {
        out.field("subject", subject);
    }
    if let Some(sha1) = &status.fingerprint_sha1 {
        out.field("sha1", sha1);
    }
    if let Some(sha256) = &status.fingerprint_sha256 {
        out.field("sha256", sha256);
    }
    if let (Some(before), Some(after)) = (&status.not_before, &status.not_after) {
        out.field("valid", format!("{before} → {after}"));
    }
    if let Some(path) = &status.cert_path {
        out.field("certificate", path);
    }
    // The note explains how this platform trusts a CA, so it only makes sense
    // once there is one to trust, or when the platform cannot do it at all.
    if let Some(note) = &status.note {
        if status.installed || !status.supported {
            out.field("note", note);
        }
    }
    if let Some(error) = &status.error {
        out.field("error", error);
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::root_action;
    use anyhow::Result;
    use hakimi_core::ca::NeedsRoot;
    use hakimi_core::runtime::HakimiRuntime;

    /// A permission failure can only happen on Linux, so the message it turns
    /// into is checked here instead of on a build machine that never hits it.
    #[test]
    fn root_errors_carry_the_sudo_hint() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = HakimiRuntime::new(Some(dir.path().to_path_buf())).unwrap();
        let failed: Result<()> = Err(anyhow::Error::new(NeedsRoot {
            path: "/usr/local/share/ca-certificates/hakimi.crt".into(),
        }));
        let message = format!(
            "{:#}",
            root_action(&runtime, "install", failed).unwrap_err()
        );
        assert!(message.contains("需要 root 权限"), "{message}");
        assert!(message.contains("--data-dir"), "{message}");
        assert!(message.contains("ca install"), "{message}");
        assert!(message.lines().count() >= 3, "{message}");
    }

    /// Any other failure keeps its own message and gains no sudo advice.
    #[test]
    fn unrelated_errors_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = HakimiRuntime::new(Some(dir.path().to_path_buf())).unwrap();
        let failed: Result<()> = Err(anyhow::anyhow!("update-ca-certificates 执行失败"));
        let message = format!(
            "{:#}",
            root_action(&runtime, "install", failed).unwrap_err()
        );
        assert_eq!(message, "update-ca-certificates 执行失败");
    }
}
