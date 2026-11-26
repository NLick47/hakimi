//! View modules: the four pages plus the modal editor, assembled in `view()`.

pub mod common;
pub mod editor;
pub mod fix;
pub mod home;
pub mod settings;

use windui::prelude::*;

use crate::app_state::{Action, UiSignals};

/// Right-click menu for a site row, rebuilt on every right-click.
pub(crate) fn site_menu(
    tx: Sender<Action>,
    id: String,
    builtin: bool,
    hidden: bool,
    enabled: bool,
) -> Vec<MenuItem> {
    let open_tx = tx.clone();
    let open_id = id.clone();
    let mut menu = vec![MenuItem::run(
        if builtin { "查看" } else { "编辑" },
        move |_| {
            let _ = open_tx.send(Action::OpenEditor(open_id.clone()));
        },
        false,
    )];
    if hidden {
        let unhide_tx = tx.clone();
        let unhide_id = id.clone();
        menu.push(MenuItem::run(
            "取消隐藏（不会自动加速）",
            move |_| {
                let _ = unhide_tx.send(Action::UnhideSite(unhide_id.clone()));
            },
            false,
        ));
    } else {
        let hide_tx = tx.clone();
        let hide_id = id.clone();
        menu.push(MenuItem::run(
            if enabled {
                "隐藏并停止加速"
            } else {
                "隐藏"
            },
            move |_| {
                let _ = hide_tx.send(Action::HideSite(hide_id.clone()));
            },
            false,
        ));
    }
    menu
}

/// The full UI tree. `s.root` is written explicitly after every action so the
/// switcher sees the change: a derived signal's version only tracks one source,
/// so a map over window_open/page/show_onboarding would miss page changes.
/// root: 0=Closed, 1=Home, 2=Settings, 3=Fix.
pub fn view(s: UiSignals, tx: Sender<Action>) -> Element {
    let home_tx = tx.clone();
    let settings_tx = tx.clone();
    let fix_tx = tx.clone();
    let editor_tx = tx;

    let pages = Element::switcher(s.root, move |root| {
        let page = match root {
            0 => Element::stack().fill().bg(crate::theme::WINDOW_BG), // Closed
            1 => home::view(s, home_tx.clone()),
            2 => settings::view(s, settings_tx.clone()),
            3 => fix::view(s, fix_tx.clone()),
            _ => Element::stack().fill().bg(crate::theme::WINDOW_BG),
        };
        // The switcher adds a cross-fade to any page without its own presence.
        // Reopening from the tray swaps Closed→Home; a fade there reads as a
        // flash, so switch pages instantly.
        page.transition(Presence::none())
    })
    .fill();

    Element::stack()
        .fill()
        .bg(crate::theme::WINDOW_BG)
        .child(pages)
        .child(editor::view(s, editor_tx))
}
