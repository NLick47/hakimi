//! System tray: keeps the app alive with the window closed and mirrors the
//! window actions. Port of the `TrayRoot` component in the old app.slint.

use windui::prelude::*;

use crate::app_state::Action;

/// Build the tray. Menu item titles encode state (`开机自启：开/关`) because
/// windui tray check items would need a Signal that lives as long as the tray;
/// deriving the title from signals keeps the menu honest with no extra state.
pub fn build(
    tx: Sender<Action>,
    running: Signal<bool>,
    auto_start: Signal<bool>,
    start_hidden: Signal<bool>,
    tray_rgba: (u32, u32, Vec<u8>),
) -> Tray {
    let show_tx = tx.clone();
    let click_tx = tx.clone();
    let double_tx = tx.clone();
    let master_tx = tx.clone();
    let auto_tx = tx.clone();
    let hidden_tx = tx.clone();
    let quit_tx = tx;

    let running_for_title = running;
    let auto_for_title = auto_start;
    let hidden_for_title = start_hidden;

    Tray::new()
        .tooltip("hakimi")
        .icon_rgba(tray_rgba.0, tray_rgba.1, &tray_rgba.2)
        .on_left_click(move |ctx| {
            let _ = click_tx.send(Action::ShowMain);
            ctx.show_window();
        })
        .on_double_click(move |ctx| {
            let _ = double_tx.send(Action::ShowMain);
            ctx.show_window();
        })
        .menu(vec![
            TrayMenuItem::item("显示主窗口", move |ctx| {
                let _ = show_tx.clone().send(Action::ShowMain);
                ctx.show_window();
            }),
            TrayMenuItem::separator(),
            TrayMenuItem::item(
                running_for_title.map(|on| if *on { "停止加速" } else { "开启加速" }.to_string()),
                move |_| {
                    let _ = master_tx.clone().send(Action::ToggleMaster);
                },
            ),
            TrayMenuItem::separator(),
            TrayMenuItem::item(
                auto_for_title.map(|on| format!("开机自启：{}", if *on { "开" } else { "关" })),
                move |_| {
                    let _ = auto_tx.clone().send(Action::ToggleAutoStart);
                },
            ),
            TrayMenuItem::item(
                hidden_for_title.map(|on| format!("静默启动：{}", if *on { "开" } else { "关" })),
                move |_| {
                    let _ = hidden_tx.clone().send(Action::ToggleStartHidden);
                },
            ),
            TrayMenuItem::separator(),
            TrayMenuItem::item("退出", move |_| {
                let _ = quit_tx.clone().send(Action::Quit);
            }),
        ])
}
