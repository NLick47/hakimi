//! System tray: keeps the app alive with the window closed and mirrors the
//! window actions. Port of the `TrayRoot` component in the old app.slint.

use std::rc::Rc;

use windui::prelude::*;

use crate::app_state::{self, Action, UiSignals};
use crate::Ui;

/// Build the tray. Menu item titles encode state (`开机自启：开/关`) because
/// windui tray check items would need a Signal that lives as long as the tray;
/// deriving the title from signals keeps the menu honest with no extra state.
///
/// Callbacks call `Ui::handle` directly instead of going through the channel:
/// windui drains channel messages in `drawRect`, and a window hidden to the
/// tray never draws, so a queued menu action (quit above all) would sit there
/// until the window next became visible. Tray callbacks run on the UI thread
/// and are not `Send`, so capturing the `Rc<Ui>` is safe.
pub fn build(
    ui: Rc<Ui>,
    signals: UiSignals,
    running: Signal<bool>,
    auto_start: Signal<bool>,
    start_hidden: Signal<bool>,
    tray_rgba: (u32, u32, Vec<u8>),
) -> Tray {
    let click_ui = ui.clone();
    let double_ui = ui.clone();
    let show_ui_handle = ui.clone();
    let master_ui = ui.clone();
    let auto_ui = ui.clone();
    let hidden_ui = ui.clone();
    let quit_ui = ui;

    let click_signals = signals;
    let double_signals = signals;
    let show_signals = signals;

    let running_for_title = running;
    let auto_for_title = auto_start;
    let hidden_for_title = start_hidden;

    Tray::new()
        .tooltip("hakimi")
        .icon_rgba(tray_rgba.0, tray_rgba.1, &tray_rgba.2)
        .on_left_click(move |ctx| {
            crate::set_dock_visible(true);
            app_state::prepare_show(click_signals);
            click_ui.handle(Action::ShowMain);
            ctx.show_window();
        })
        .on_double_click(move |ctx| {
            crate::set_dock_visible(true);
            app_state::prepare_show(double_signals);
            double_ui.handle(Action::ShowMain);
            ctx.show_window();
        })
        .menu(vec![
            TrayMenuItem::item("显示主窗口", move |ctx| {
                crate::set_dock_visible(true);
                app_state::prepare_show(show_signals);
                show_ui_handle.handle(Action::ShowMain);
                ctx.show_window();
            }),
            TrayMenuItem::separator(),
            TrayMenuItem::item(
                running_for_title.map(|on| if *on { "停止加速" } else { "开启加速" }.to_string()),
                move |_| master_ui.handle(Action::ToggleMaster),
            ),
            TrayMenuItem::separator(),
            TrayMenuItem::item(
                auto_for_title.map(|on| format!("开机自启：{}", if *on { "开" } else { "关" })),
                move |_| auto_ui.handle(Action::ToggleAutoStart),
            ),
            TrayMenuItem::item(
                hidden_for_title.map(|on| format!("静默启动：{}", if *on { "开" } else { "关" })),
                move |_| hidden_ui.handle(Action::ToggleStartHidden),
            ),
            TrayMenuItem::separator(),
            TrayMenuItem::item("退出", move |_| quit_ui.handle(Action::Quit)),
        ])
}
