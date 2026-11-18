//! View modules: the four pages plus the modal editor, assembled in `view()`.

pub mod common;
pub mod editor;
pub mod fix;
pub mod home;
pub mod settings;

use windui::prelude::*;

use crate::app_state::{Action, UiSignals};

/// The full UI tree. `s.root` is written explicitly after every action so the
/// switcher sees the change: a derived signal's version only tracks one source,
/// so a map over window_open/page/show_onboarding would miss page changes.
/// root: 0=Closed, 1=Home, 2=Settings, 3=Fix.
pub fn view(s: UiSignals, tx: Sender<Action>) -> Element {
    let home_tx = tx.clone();
    let settings_tx = tx.clone();
    let fix_tx = tx.clone();
    let editor_tx = tx;

    let pages = Element::switcher(s.root, move |root| match root {
        0 => Element::stack().fill().bg(crate::theme::WINDOW_BG), // Closed
        1 => home::view(s, home_tx.clone()),
        2 => settings::view(s, settings_tx.clone()),
        3 => fix::view(s, fix_tx.clone()),
        _ => Element::stack().fill().bg(crate::theme::WINDOW_BG),
    })
    .fill();

    Element::stack()
        .fill()
        .bg(crate::theme::WINDOW_BG)
        .child(pages)
        .child(editor::view(s, editor_tx))
}
