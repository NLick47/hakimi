//! C ABI for the desktop shell.
//!
//! The surface is deliberately small: create a runtime, start/stop it, read status, and send
//! JSON commands. Every returned string is owned by the caller and must be released with
//! [`hakimi_free_string`].

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;

use hakimi_core::config::{AppConfig, GroupConfig, RoutePolicy};
use hakimi_core::runtime::HakimiRuntime;
use parking_lot::Mutex;
use serde_json::{json, Value};

pub struct HakimiHandle {
    runtime: Arc<HakimiRuntime>,
    tokio: tokio::runtime::Runtime,
    last_error: Mutex<Option<String>>,
}

static INIT_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_init_error(message: impl Into<String>) {
    *INIT_ERROR.lock() = Some(message.into());
}

fn alloc_string(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(value) => value.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

unsafe fn read_c_string(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    CStr::from_ptr(value).to_str().ok().map(ToOwned::to_owned)
}

impl HakimiHandle {
    fn set_error(&self, message: impl Into<String>) {
        *self.last_error.lock() = Some(message.into());
    }

    fn clear_error(&self) {
        *self.last_error.lock() = None;
    }

    fn error_json(&self, message: impl Into<String>) -> String {
        let message = message.into();
        self.set_error(message.clone());
        json!({"ok": false, "error": message}).to_string()
    }

    fn command(&self, request: &str) -> String {
        let value: Value = match serde_json::from_str(request) {
            Ok(value) => value,
            Err(error) => return self.error_json(format!("invalid command JSON: {error}")),
        };
        let Some(command) = value.get("command").and_then(Value::as_str) else {
            return self.error_json("command JSON needs a string `command` field");
        };
        match command {
            "getStatus" | "status" => json!({
                "ok": true,
                "result": self.runtime.status_json()
            })
            .to_string(),
            "getConfig" | "config" => json!({
                "ok": true,
                "result": self.runtime.config_json()
            })
            .to_string(),
            "pac" => json!({
                "ok": true,
                "result": {
                    "pacUrl": self.runtime.pac_url(),
                    "script": self.runtime.pac_script()
                }
            })
            .to_string(),
            "pause" => {
                self.runtime.pause();
                json!({"ok": true, "result": {"paused": true}}).to_string()
            }
            "resume" => {
                self.runtime.resume();
                json!({"ok": true, "result": {"paused": false}}).to_string()
            }
            "setPaused" => {
                let paused = value
                    .get("paused")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                self.runtime.set_paused(paused);
                json!({"ok": true, "result": {"paused": paused}}).to_string()
            }
            "setGroupEnabled" => {
                let Some(id) = value.get("id").and_then(Value::as_str) else {
                    return self.error_json("setGroupEnabled needs `id`");
                };
                let enabled = value
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                match self.runtime.set_group_enabled(id, enabled) {
                    Ok(config) => json!({"ok": true, "result": config}).to_string(),
                    Err(error) => self.error_json(format!("{error:#}")),
                }
            }
            "setGroupDefaultRoute" => {
                let Some(id) = value.get("id").and_then(Value::as_str) else {
                    return self.error_json("setGroupDefaultRoute needs `id`");
                };
                let Some(route) = value
                    .get("route")
                    .cloned()
                    .and_then(|route| serde_json::from_value::<RoutePolicy>(route).ok())
                else {
                    return self.error_json(
                        "setGroupDefaultRoute needs a `route` with a non-empty attempts array",
                    );
                };
                match self.runtime.set_group_default_route(id, route) {
                    Ok(config) => json!({"ok": true, "result": config}).to_string(),
                    Err(error) => self.error_json(format!("{error:#}")),
                }
            }
            "upsertGroup" => {
                let Some(group) = value.get("group") else {
                    return self.error_json("upsertGroup needs `group`");
                };
                match serde_json::from_value::<GroupConfig>(group.clone()) {
                    Ok(group) => match self.runtime.upsert_group(group) {
                        Ok(config) => json!({"ok": true, "result": config}).to_string(),
                        Err(error) => self.error_json(format!("{error:#}")),
                    },
                    Err(error) => self.error_json(format!("invalid group: {error}")),
                }
            }
            "removeGroup" => {
                let Some(id) = value.get("id").and_then(Value::as_str) else {
                    return self.error_json("removeGroup needs `id`");
                };
                match self.runtime.remove_group(id) {
                    Ok(config) => json!({"ok": true, "result": config}).to_string(),
                    Err(error) => self.error_json(format!("{error:#}")),
                }
            }
            "updateConfig" => {
                let Some(config) = value.get("config") else {
                    return self.error_json("updateConfig needs `config`");
                };
                match serde_json::from_value::<AppConfig>(config.clone()) {
                    Ok(config) => match self.runtime.update_config(config) {
                        Ok(()) => {
                            json!({"ok": true, "result": self.runtime.status_json()}).to_string()
                        }
                        Err(error) => self.error_json(format!("{error:#}")),
                    },
                    Err(error) => self.error_json(format!("invalid config: {error}")),
                }
            }
            "refreshCatalog" => {
                let kind = value.get("kind").and_then(Value::as_str).unwrap_or("ip");
                let force = value.get("force").and_then(Value::as_bool).unwrap_or(false);
                match self
                    .tokio
                    .block_on(self.runtime.refresh_catalog(kind, force))
                {
                    Ok(report) => json!({"ok": true, "result": report}).to_string(),
                    Err(error) => self.error_json(format!("{error:#}")),
                }
            }
            "refreshAllCatalogs" => {
                let force = value.get("force").and_then(Value::as_bool).unwrap_or(false);
                let results = self.tokio.block_on(self.runtime.refresh_catalogs(force));
                let results: Vec<Value> = results
                    .into_iter()
                    .map(|result| match result {
                        Ok(report) => serde_json::to_value(report).unwrap_or(Value::Null),
                        Err(error) => json!({"error": format!("{error:#}")}),
                    })
                    .collect();
                json!({"ok": true, "result": results}).to_string()
            }
            "diagnose" | "probeDomain" => {
                let Some(domain) = value.get("domain").and_then(Value::as_str) else {
                    return self.error_json("diagnose needs `domain`");
                };
                let diagnostics = self.tokio.block_on(self.runtime.diagnose(domain));
                json!({"ok": true, "result": diagnostics}).to_string()
            }
            "caStatus" => json!({
                "ok": true,
                "result": self.tokio.block_on(self.runtime.ca_status())
            })
            .to_string(),
            "dohHealth" => json!({
                "ok": true,
                "result": self.tokio.block_on(self.runtime.doh_health())
            })
            .to_string(),
            "caInstall" => self.ca_result(self.runtime.ca_install()),
            "caUninstall" => self.ca_result(self.runtime.ca_uninstall()),
            "caRepair" => self.ca_result(self.runtime.ca_repair()),
            "caRegenerate" => self.ca_result(self.runtime.ca_regenerate()),
            "applySystemProxy" => match self.runtime.apply_system_proxy() {
                Ok(status) => json!({"ok": true, "result": status}).to_string(),
                Err(error) => self.error_json(format!("{error:#}")),
            },
            "exportDiagnostics" => match self.runtime.export_diagnostics() {
                Ok(path) => json!({"ok": true, "result": {"path": path}}).to_string(),
                Err(error) => self.error_json(format!("{error:#}")),
            },
            other => self.error_json(format!("unknown command `{other}`")),
        }
    }

    fn ca_result(&self, result: anyhow::Result<hakimi_core::ca::CaStatus>) -> String {
        match result {
            Ok(status) => json!({"ok": true, "result": status}).to_string(),
            Err(error) => self.error_json(format!("{error:#}")),
        }
    }
}

/// Create a runtime. `config_dir` may be null to use the platform data directory.
#[no_mangle]
/// # Safety
/// `config_dir` must be null or point to a valid, NUL-terminated UTF-8 string for the
/// duration of the call.
pub unsafe extern "C" fn hakimi_init(config_dir: *const c_char) -> *mut HakimiHandle {
    let result = catch_unwind(AssertUnwindSafe(
        || -> std::result::Result<*mut HakimiHandle, String> {
            let data_dir = unsafe { read_c_string(config_dir) }.map(PathBuf::from);
            let tokio = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("building the tokio runtime failed: {error}"))?;
            let runtime = HakimiRuntime::new(data_dir).map_err(|error| format!("{error:#}"))?;
            Ok(Box::into_raw(Box::new(HakimiHandle {
                runtime,
                tokio,
                last_error: Mutex::new(None),
            })))
        },
    ));
    match result {
        Ok(Ok(handle)) => {
            *INIT_ERROR.lock() = None;
            handle
        }
        Ok(Err(error)) => {
            set_init_error(error);
            ptr::null_mut()
        }
        Err(_) => {
            set_init_error("panic while initializing the hakimi runtime");
            ptr::null_mut()
        }
    }
}

/// Error from the last failed `hakimi_init` (null if none).
#[no_mangle]
pub extern "C" fn hakimi_last_init_error() -> *mut c_char {
    match INIT_ERROR.lock().clone() {
        Some(error) => alloc_string(error),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
/// # Safety
/// `handle` must be a live pointer returned by [`hakimi_init`] and not yet freed.
pub unsafe extern "C" fn hakimi_start(handle: *mut HakimiHandle) -> i32 {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return -1;
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        handle.tokio.block_on(handle.runtime.start())
    }));
    match result {
        Ok(Ok(())) => {
            handle.clear_error();
            0
        }
        Ok(Err(error)) => {
            handle.set_error(format!("{error:#}"));
            -2
        }
        Err(_) => {
            handle.set_error("panic in hakimi_start");
            -3
        }
    }
}

#[no_mangle]
/// # Safety
/// `handle` must be a live pointer returned by [`hakimi_init`] and not yet freed.
pub unsafe extern "C" fn hakimi_stop(handle: *mut HakimiHandle) -> i32 {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return -1;
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        handle.tokio.block_on(handle.runtime.stop())
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            handle.set_error(format!("{error:#}"));
            -2
        }
        Err(_) => {
            handle.set_error("panic in hakimi_stop");
            -3
        }
    }
}

#[no_mangle]
/// # Safety
/// `handle` must be a live pointer returned by [`hakimi_init`]; it must not be used again.
pub unsafe extern "C" fn hakimi_free(handle: *mut HakimiHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let handle = unsafe { Box::from_raw(handle) };
        let _ = handle.tokio.block_on(handle.runtime.stop());
    }));
}

#[no_mangle]
/// # Safety
/// `handle` must be a live pointer returned by [`hakimi_init`] and not yet freed.
pub unsafe extern "C" fn hakimi_status_json(handle: *mut HakimiHandle) -> *mut c_char {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return ptr::null_mut();
    };
    match catch_unwind(AssertUnwindSafe(|| {
        handle.runtime.status_json().to_string()
    })) {
        Ok(value) => alloc_string(value),
        Err(_) => {
            handle.set_error("panic in hakimi_status_json");
            ptr::null_mut()
        }
    }
}

/// Send a JSON command. The result is a JSON object: `{"ok":true,"result":...}` or
/// `{"ok":false,"error":"..."}`.
#[no_mangle]
/// # Safety
/// `handle` must be live, and `command` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn hakimi_command_json(
    handle: *mut HakimiHandle,
    command: *const c_char,
) -> *mut c_char {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return ptr::null_mut();
    };
    let Some(command) = (unsafe { read_c_string(command) }) else {
        return alloc_string(handle.error_json("null or invalid UTF-8 command"));
    };
    match catch_unwind(AssertUnwindSafe(|| handle.command(&command))) {
        Ok(value) => alloc_string(value),
        Err(_) => alloc_string(handle.error_json("panic in hakimi_command_json")),
    }
}

#[no_mangle]
/// # Safety
/// `handle` must be a live pointer returned by [`hakimi_init`] and not yet freed.
pub unsafe extern "C" fn hakimi_last_error(handle: *mut HakimiHandle) -> *mut c_char {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return ptr::null_mut();
    };
    match handle.last_error.lock().clone() {
        Some(error) => alloc_string(error),
        None => ptr::null_mut(),
    }
}

/// Release a string returned by this library. Passing null is a no-op.
#[no_mangle]
/// # Safety
/// `value` must be a pointer returned by this library that has not already been freed, or null.
pub unsafe extern "C" fn hakimi_free_string(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_roundtrip_status_and_command() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = CString::new(dir.path().to_string_lossy().to_string()).unwrap();
        let handle = unsafe { hakimi_init(config_dir.as_ptr()) };
        assert!(!handle.is_null(), "hakimi_init returned null");

        let status = unsafe { hakimi_status_json(handle) };
        assert!(!status.is_null());
        let status_text = unsafe { CStr::from_ptr(status) }
            .to_string_lossy()
            .to_string();
        unsafe { hakimi_free_string(status) };
        assert!(status_text.contains("\"app\":\"hakimi\""), "{status_text}");

        let request = CString::new(r#"{"command":"getStatus"}"#).unwrap();
        let response = unsafe { hakimi_command_json(handle, request.as_ptr()) };
        assert!(!response.is_null());
        let response_text = unsafe { CStr::from_ptr(response) }
            .to_string_lossy()
            .to_string();
        unsafe { hakimi_free_string(response) };
        assert!(response_text.contains("\"ok\":true"), "{response_text}");

        assert_eq!(unsafe { hakimi_stop(handle) }, 0);
        unsafe { hakimi_free(handle) };
    }
}
