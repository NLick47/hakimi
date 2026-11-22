//! Windows: carry the main window's outer frame across tray re-opens.
//!
//! Resident mode destroys the window on close, so without this every open
//! lands on the OS default placement. `remember_current` snapshots the live
//! frame while the close handler still runs (`native_window_handle` is the
//! closing window there); `restore` hands the frame back for the next
//! window request when it still touches any monitor — a frame stranded on an
//! unplugged screen falls back to windui's centering instead.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::Graphics::Gdi::{MonitorFromRect, MONITOR_DEFAULTTONULL};
use windows_sys::Win32::UI::WindowsAndMessaging::GetWindowRect;

static FRAME_LEFT: AtomicI32 = AtomicI32::new(0);
static FRAME_TOP: AtomicI32 = AtomicI32::new(0);
static FRAME_RIGHT: AtomicI32 = AtomicI32::new(0);
static FRAME_BOTTOM: AtomicI32 = AtomicI32::new(0);
static HAS_FRAME: AtomicBool = AtomicBool::new(false);

/// Minimized windows report the classic (-32000, -32000) frame; memorizing it
/// would reopen the window where no screen can show it.
fn plausible(rc: &RECT) -> bool {
    rc.left > -30000 && rc.top > -30000 && rc.right > rc.left && rc.bottom > rc.top
}

/// Snapshot the live window frame. Runs inside event dispatch (the close
/// handler), where `native_window_handle` is this window's HWND.
pub(super) fn remember_current() {
    let Some(handle) = windui::platform::native_window_handle() else {
        tracing::debug!("window frame not remembered: no native window handle");
        return;
    };
    let mut rc = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    if unsafe { GetWindowRect(handle as *mut core::ffi::c_void, &mut rc) } == 0
        || !plausible(&rc)
    {
        tracing::debug!(
            left = rc.left,
            top = rc.top,
            "window frame not remembered (query failed or minimized)"
        );
        return;
    }
    FRAME_LEFT.store(rc.left, Ordering::Relaxed);
    FRAME_TOP.store(rc.top, Ordering::Relaxed);
    FRAME_RIGHT.store(rc.right, Ordering::Relaxed);
    FRAME_BOTTOM.store(rc.bottom, Ordering::Relaxed);
    HAS_FRAME.store(true, Ordering::Relaxed);
    tracing::info!(
        left = rc.left,
        top = rc.top,
        right = rc.right,
        bottom = rc.bottom,
        "DBG window_placement: remembered window frame"
    );
}

/// Outer-frame top-left for the next open: the remembered position while its
/// frame still intersects a monitor, otherwise `None` (the caller centers).
pub(super) fn restore() -> Option<(i32, i32)> {
    if !HAS_FRAME.load(Ordering::Relaxed) {
        tracing::info!("DBG window_placement: no remembered frame, opening centered");
        return None;
    }
    let rc = RECT {
        left: FRAME_LEFT.load(Ordering::Relaxed),
        top: FRAME_TOP.load(Ordering::Relaxed),
        right: FRAME_RIGHT.load(Ordering::Relaxed),
        bottom: FRAME_BOTTOM.load(Ordering::Relaxed),
    };
    let monitor = unsafe { MonitorFromRect(&rc, MONITOR_DEFAULTTONULL) };
    if monitor.is_null() {
        tracing::info!(
            left = rc.left,
            top = rc.top,
            "DBG window_placement: remembered frame is off every monitor, opening centered"
        );
        None
    } else {
        tracing::info!(
            x = rc.left,
            y = rc.top,
            "DBG window_placement: restoring remembered window position"
        );
        Some((rc.left, rc.top))
    }
}
