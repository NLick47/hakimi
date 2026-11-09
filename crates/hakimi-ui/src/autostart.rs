//! Login-item registration for the desktop builds.
//!
//! `config.json` records the user's intent; the OS holds the actual entry.
//! [`apply`] reconciles the two and runs once at launch (a moved executable
//! rewrites its own path) and again whenever the settings switch flips.
//!
//! Every platform write is idempotent: enabling an already-enabled entry just
//! rewrites it, and disabling an absent one is a success, because "not
//! registered" is the state being asked for.

use anyhow::Result;

/// Argument the login entry passes, so a launch at login is distinguishable
/// from a user double-click.
pub const AUTOSTART_ARG: &str = "--autostart";

/// File stem of the Windows shortcut and the Linux desktop entry. Stable
/// across versions so an upgrade overwrites instead of stacking another entry.
/// macOS names its LaunchAgent after the bundle identifier instead.
#[cfg(not(target_os = "macos"))]
const ENTRY_NAME: &str = "hakimi";

/// Whether the login entry is actually in place and active. Windows can
/// disable an entry from its Startup apps settings without deleting the file,
/// so the config alone is not enough to describe reality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginState {
    Present,
    Missing,
    /// The file exists, but the OS startup list has it disabled.
    Disabled,
}

impl LoginState {
    /// Short explanation for the settings page, or `None` when healthy.
    pub fn problem(self) -> Option<&'static str> {
        match self {
            Self::Present => None,
            Self::Missing => Some("启动项缺失，下次启动会自动重建"),
            Self::Disabled => Some("已被系统启动应用设置禁用，请在任务管理器 → 启动应用中重新启用"),
        }
    }
}

#[cfg(windows)]
pub fn apply(enabled: bool) -> Result<()> {
    windows_impl::apply(enabled)
}

#[cfg(target_os = "macos")]
pub fn apply(enabled: bool) -> Result<()> {
    macos_impl::apply(enabled)
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn apply(enabled: bool) -> Result<()> {
    linux_impl::apply(enabled)
}

#[cfg(windows)]
pub fn login_state() -> LoginState {
    windows_impl::state()
}

#[cfg(target_os = "macos")]
pub fn login_state() -> LoginState {
    macos_impl::state()
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn login_state() -> LoginState {
    linux_impl::state()
}

/// The Windows login item is a shortcut in the user's Startup folder. This is
/// the same mechanism Explorer itself uses for "Startup apps", needs no
/// administrator rights, and never writes the registry. The registry is read
/// (not written) only to notice when the OS startup list disabled the entry.
#[cfg(windows)]
mod windows_impl {
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::Once;

    use anyhow::{Context, Result};
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, IPersistFile, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::UI::Shell::{
        FOLDERID_Startup, IShellLinkW, SHGetKnownFolderPath, ShellLink, KF_FLAG_DEFAULT,
    };
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_BINARY,
    };

    /// Where Explorer records the user's enable/disable choice for the
    /// entries in the Startup folder. Read-only here: the app never writes it.
    const STARTUP_APPROVED: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

    thread_local! {
        /// COM is per-thread. The toggle and the launch-time reconcile both
        /// run on the UI thread; the Once only keeps a repeated toggle from
        /// re-initializing. The init is deliberately never undone: it lives as
        /// long as the process, like winit's own OLE initialization.
        static COM_INIT: Once = const { Once::new() };
    }

    fn ensure_com() {
        COM_INIT.with(|init| {
            init.call_once(|| unsafe {
                let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            });
        });
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn wide_str(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\hakimi.lnk`.
    /// The Known Folder API resolves redirected profiles too.
    fn shortcut_path() -> Result<PathBuf> {
        unsafe {
            let raw = SHGetKnownFolderPath(&FOLDERID_Startup, KF_FLAG_DEFAULT, None)
                .context("无法定位启动文件夹")?;
            let folder = raw.to_string().context("启动文件夹路径不是有效的 UTF-16");
            CoTaskMemFree(Some(raw.0 as *const core::ffi::c_void));
            Ok(PathBuf::from(folder?).join(format!("{}.lnk", super::ENTRY_NAME)))
        }
    }

    /// The value is a REG_BINARY record whose first DWORD is the state. The
    /// observed Task Manager values are 2 (enabled) and 3 (disabled, with the
    /// change time in the trailing eight bytes); 7 appears in the same family.
    /// Unknown values are treated as enabled so a format change can never
    /// produce a false "disabled" warning.
    pub(super) fn approved_disabled(data: &[u8]) -> bool {
        data.len() >= 4 && matches!(data[0], 3 | 7)
    }

    fn startup_approved_disabled(file_name: &str) -> bool {
        let mut data = [0u8; 12];
        let mut size = data.len() as u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                wide_str(STARTUP_APPROVED).as_ptr(),
                wide_str(file_name).as_ptr(),
                RRF_RT_REG_BINARY,
                std::ptr::null_mut(),
                data.as_mut_ptr().cast(),
                &mut size,
            )
        };
        status == ERROR_SUCCESS && approved_disabled(&data[..size as usize])
    }

    pub(super) fn state() -> super::LoginState {
        let Ok(path) = shortcut_path() else {
            return super::LoginState::Missing;
        };
        if !path.exists() {
            return super::LoginState::Missing;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return super::LoginState::Present;
        };
        if startup_approved_disabled(name) {
            super::LoginState::Disabled
        } else {
            super::LoginState::Present
        }
    }

    fn same_file(left: &Path, right: &Path) -> bool {
        match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
            (Ok(left), Ok(right)) => left == right,
            // A stale target that cannot be canonicalized is not ours.
            _ => false,
        }
    }

    /// Whether an existing shortcut was written for this executable. Deleting
    /// is scoped to our own entry: another copy of the app shares the file
    /// name, and a hand-edited shortcut is not ours to remove.
    pub(super) fn entry_belongs(target: &str, arguments: &str, exe: &Path) -> bool {
        arguments == super::AUTOSTART_ARG && same_file(Path::new(target), exe)
    }

    pub(super) fn apply(enabled: bool) -> Result<()> {
        let path = shortcut_path()?;
        if !enabled {
            // A missing shortcut already means "off".
            if !path.exists() {
                return Ok(());
            }
            let Ok(exe) = std::env::current_exe() else {
                return Ok(());
            };
            let ours = read_shortcut(&path)
                .map(|(target, arguments)| entry_belongs(&target, &arguments, &exe))
                .unwrap_or(false);
            if !ours {
                return Ok(());
            }
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error).with_context(|| format!("无法删除 {}", path.display())),
            }
        } else {
            let exe = std::env::current_exe().context("无法定位当前可执行文件")?;
            write_shortcut(&exe, &path)
        }
    }

    pub(super) fn write_shortcut(exe: &Path, path: &Path) -> Result<()> {
        ensure_com();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("无法创建 {}", parent.display()))?;
        }
        let target = wide_path(exe);
        let arguments = wide_str(super::AUTOSTART_ARG);
        let description = wide_str("hakimi");
        let working_dir = exe.parent().map(wide_path).unwrap_or_default();
        let link_path = wide_path(path);
        unsafe {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
                .context("无法创建快捷方式对象")?;
            link.SetPath(PCWSTR(target.as_ptr()))
                .context("无法设置快捷方式目标")?;
            link.SetArguments(PCWSTR(arguments.as_ptr()))
                .context("无法设置快捷方式参数")?;
            link.SetDescription(PCWSTR(description.as_ptr()))
                .context("无法设置快捷方式描述")?;
            link.SetIconLocation(PCWSTR(target.as_ptr()), 0)
                .context("无法设置快捷方式图标")?;
            if !working_dir.is_empty() {
                link.SetWorkingDirectory(PCWSTR(working_dir.as_ptr()))
                    .context("无法设置快捷方式工作目录")?;
            }
            let persist: IPersistFile = link.cast().context("快捷方式对象不支持持久化")?;
            persist
                .Save(PCWSTR(link_path.as_ptr()), true)
                .with_context(|| format!("无法写入 {}", path.display()))?;
        }
        Ok(())
    }

    /// Reads back the target and arguments; used by tests and by the
    /// ownership check before deleting an existing entry.
    pub(super) fn read_shortcut(path: &Path) -> Result<(String, String)> {
        use windows::Win32::System::Com::STGM_READ;

        ensure_com();
        let link_path = wide_path(path);
        unsafe {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            let persist: IPersistFile = link.cast()?;
            persist.Load(PCWSTR(link_path.as_ptr()), STGM_READ)?;
            let mut target = [0u16; 1024];
            link.GetPath(&mut target, std::ptr::null_mut(), 0)?;
            let mut arguments = [0u16; 1024];
            link.GetArguments(&mut arguments)?;
            Ok((utf16_string(&target), utf16_string(&arguments)))
        }
    }

    fn utf16_string(buffer: &[u16]) -> String {
        let end = buffer
            .iter()
            .position(|&value| value == 0)
            .unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..end])
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};

    const LABEL: &str = "com.hakimi.app";

    fn plist_path() -> Result<PathBuf> {
        let home = std::env::var_os("HOME").context("HOME 未设置")?;
        Ok(PathBuf::from(home)
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")))
    }

    /// A packaged app must be started through LaunchServices (that is what
    /// gives it its bundle identity); a bare binary is executed directly.
    fn program_arguments(exe: &Path) -> Vec<String> {
        let macos_dir = exe.parent();
        let contents = macos_dir.and_then(Path::parent);
        let bundle = contents.and_then(Path::parent);
        let in_bundle = macos_dir.is_some_and(|dir| dir.ends_with("MacOS"))
            && contents.is_some_and(|dir| dir.ends_with("Contents"))
            && bundle.is_some();
        match bundle {
            Some(bundle) if in_bundle => vec![
                "/usr/bin/open".to_string(),
                "-a".to_string(),
                bundle.display().to_string(),
                "--args".to_string(),
                super::AUTOSTART_ARG.to_string(),
            ],
            _ => vec![exe.display().to_string(), super::AUTOSTART_ARG.to_string()],
        }
    }

    fn xml_escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    fn plist(program: &[String]) -> String {
        let mut args = String::new();
        for arg in program {
            args.push_str(&format!("        <string>{}</string>\n", xml_escape(arg)));
        }
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{args}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
</dict>
</plist>
"#
        )
    }

    /// Writing the file is the whole registration: launchd reads the folder
    /// at login, which is exactly when the entry should fire. Loading it into
    /// the current session with `launchctl` is unnecessary.
    pub(super) fn apply(enabled: bool) -> Result<()> {
        let path = plist_path()?;
        if enabled {
            let exe = std::env::current_exe().context("无法定位当前可执行文件")?;
            let content = plist(&program_arguments(&exe));
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("无法创建 {}", parent.display()))?;
            }
            std::fs::write(&path, content)
                .with_context(|| format!("无法写入 {}", path.display()))?;
            return Ok(());
        }
        // Only remove the plist this executable would have written. Another
        // copy of the app (or a hand-edited launch agent) is left alone.
        let Ok(exe) = std::env::current_exe() else {
            return Ok(());
        };
        let expected = plist(&program_arguments(&exe));
        match std::fs::read_to_string(&path) {
            Ok(content) if content == expected => match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error).with_context(|| format!("无法删除 {}", path.display())),
            },
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("无法读取 {}", path.display())),
        }
    }

    pub(super) fn state() -> super::LoginState {
        match plist_path() {
            Ok(path) if path.exists() => super::LoginState::Present,
            _ => super::LoginState::Missing,
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod linux_impl {
    use std::path::PathBuf;

    use anyhow::{Context, Result};

    fn desktop_path() -> Result<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .context("XDG_CONFIG_HOME 与 HOME 均未设置")?;
        Ok(base
            .join("autostart")
            .join(format!("{}.desktop", super::ENTRY_NAME)))
    }

    /// Desktop Entry string quoting: inside the double quotes the spec
    /// requires escaping the quote, backtick, dollar sign and backslash; `%`
    /// is doubled so it is not read as a field code.
    fn exec_quote(exe: &str) -> String {
        format!(
            "\"{}\"",
            exe.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('`', "\\`")
                .replace('$', "\\$")
                .replace('%', "%%")
        )
    }

    fn desktop_entry(exe: &str) -> String {
        format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=hakimi\n\
             Comment=hakimi local acceleration proxy\n\
             Exec={} {}\n\
             Terminal=false\n\
             X-GNOME-Autostart-enabled=true\n",
            exec_quote(exe),
            super::AUTOSTART_ARG
        )
    }

    /// XDG autostart is file-driven: the session manager reads this folder at
    /// login, so writing or removing the file completes the change.
    pub(super) fn apply(enabled: bool) -> Result<()> {
        let path = desktop_path()?;
        if enabled {
            let exe = std::env::current_exe().context("无法定位当前可执行文件")?;
            let entry = desktop_entry(&exe.display().to_string());
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("无法创建 {}", parent.display()))?;
            }
            std::fs::write(&path, entry).with_context(|| format!("无法写入 {}", path.display()))?;
            return Ok(());
        }
        // Only remove the entry this executable would have written; another
        // copy of the app keeps its own login item.
        let Ok(exe) = std::env::current_exe() else {
            return Ok(());
        };
        let expected = desktop_entry(&exe.display().to_string());
        match std::fs::read_to_string(&path) {
            Ok(content) if content == expected => match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error).with_context(|| format!("无法删除 {}", path.display())),
            },
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("无法读取 {}", path.display())),
        }
    }

    pub(super) fn state() -> super::LoginState {
        match desktop_path() {
            Ok(path) if path.exists() => super::LoginState::Present,
            _ => super::LoginState::Missing,
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// The shortcut is the login entry: it has to point at this executable and
    /// carry the flag that keeps the login launch in the tray.
    #[test]
    fn the_login_shortcut_round_trips() {
        let path = std::env::temp_dir().join(format!(
            "hakimi-autostart-{}-{}.lnk",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let exe = std::env::current_exe().unwrap();
        super::windows_impl::write_shortcut(&exe, &path).unwrap();
        let (target, arguments) = super::windows_impl::read_shortcut(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(PathBuf::from(target), exe);
        assert_eq!(arguments, super::AUTOSTART_ARG);
    }

    /// Only the values Task Manager writes for "disabled" count; an unknown
    /// record must not produce a false warning in the settings page.
    #[test]
    fn approved_records_only_report_documented_disabled_states() {
        use super::windows_impl::approved_disabled;
        assert!(!approved_disabled(&[]));
        assert!(!approved_disabled(&[2, 0, 0, 0]));
        assert!(approved_disabled(&[3, 0, 0, 0]));
        assert!(approved_disabled(&[7, 0, 0, 0]));
        assert!(!approved_disabled(&[1, 0, 0, 0]));
    }

    /// Deleting an existing entry is scoped to our own executable and the
    /// exact login arguments.
    #[test]
    fn the_delete_path_only_claims_matching_entries() {
        let exe = std::env::current_exe().unwrap();
        let target = exe.to_string_lossy();
        assert!(super::windows_impl::entry_belongs(
            &target,
            super::AUTOSTART_ARG,
            &exe
        ));
        assert!(!super::windows_impl::entry_belongs(
            r"C:\Windows\System32\notepad.exe",
            super::AUTOSTART_ARG,
            &exe
        ));
        assert!(!super::windows_impl::entry_belongs(
            &target, "--other", &exe
        ));
    }
}
