//! Reusable view helpers shared by the home, fix, settings and editor pages.
//! Faithful ports of the small private components at the top of the old
//! `app.slint`; sizes, colours and copy match it one for one.

use windui::core::EventCtx;
use windui::prelude::*;

use crate::app_state::Action;

use crate::theme;

// -- icons --------------------------------------------------------------------

thread_local! {
    static ICON_CACHE: std::cell::RefCell<
        std::collections::HashMap<usize, Option<Image>>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

fn cached_icon(bytes: &'static [u8]) -> Option<ImageContent> {
    let key = bytes.as_ptr() as usize;
    let image = ICON_CACHE.with(|cache| {
        cache
            .borrow_mut()
            .entry(key)
            .or_insert_with(|| Image::from_png_bytes(bytes).ok())
            .clone()
    });
    image.map(|image| ImageContent::new(Some(image)))
}

pub fn icon(bytes: &'static [u8], size: i32, tint: Color) -> Element {
    match cached_icon(bytes) {
        Some(content) => Element::image_content(content),
        None => Element::image_bytes(bytes),
    }
    .tint(tint)
    .size(size, size)
    .fit(Fit::Contain)
}

pub fn back_icon() -> Element {
    icon(include_bytes!("../../assets/icons/ic-back.png"), 15, theme::TEXT_BODY)
}

pub fn settings_icon() -> Element {
    icon(include_bytes!("../../assets/icons/ic-settings.png"), 17, theme::TEXT_SECONDARY)
}

pub fn chevron_right_icon() -> Element {
    icon(include_bytes!("../../assets/icons/ic-chevron-right.png"), 8, theme::TEXT_DISABLED)
}

pub fn chevron_down_icon() -> Element {
    icon(include_bytes!("../../assets/icons/ic-chevron-down.png"), 8, theme::TEXT_CHEVRON_OPEN)
}

#[allow(dead_code)]
pub fn chevron_menu_icon() -> Element {
    icon(include_bytes!("../../assets/icons/ic-chevron-menu.png"), 10, theme::TEXT_SECONDARY)
}

#[allow(dead_code)]
pub fn check_icon(tint: Color) -> Element {
    icon(include_bytes!("../../assets/icons/ic-check.png"), 10, tint)
}

/// The old `Chevron`: points right when closed, down when open, with the
/// original's 120ms crossfade approximated by an opacity swap.
pub fn chevron(open: Signal<bool>) -> Element {
    let closed = open;
    let opened = open;
    Element::stack()
        .size(8, 8)
        .child(chevron_right_icon().opacity_when(move || if closed.get() { 0.0 } else { 1.0 }))
        .child(chevron_down_icon().opacity_when(move || if opened.get() { 1.0 } else { 0.0 }))
}

// -- buttons ------------------------------------------------------------------

/// The old `ActionButton` (emphasis): Fluent-blue primary, 34px.
#[allow(dead_code)]
pub fn action_button(label: &'static str) -> Element {
    Element::button(label)
        .min_width(92)
        .height(34)
        .corner(5.0)
        .font_size(13.0)
}

/// The old `ActionButton` (plain): white, hairline border, danger-red label.
#[allow(dead_code)]
pub fn action_button_plain(label: &'static str) -> Element {
    Element::button(label)
        .min_width(92)
        .height(34)
        .corner(5.0)
        .font_size(13.0)
        .outline_soft()
        .danger()
        .bg(theme::CARD_BG)
}

/// The old `TextButton`: bare label, light hover fill, blue when accent,
/// transparent with no border at rest. Built from a clickable row so there is
/// no button chrome — the hover tint comes from windui's Clickable feedback.
pub fn text_button(label: &'static str, accent: bool) -> Element {
    Element::row()
        .height(24)
        .min_width(40)
        .padding_xy(8, 0)
        .cross(Align::Center)
        .corner(5.0)
        .clickable()
        .on_click(|_| {})
        .child(
            Element::label(label)
                .font_size(12.5)
                .fg(if accent { theme::ACCENT } else { theme::TEXT_SECONDARY })
                .align(Align::Center),
        )
}

/// The old `PillButton` (tone 0): white pill, blue hairline, blue label.
pub fn pill_button(label: &'static str) -> Element {
    Element::button(label)
        .height(28)
        .min_width(64)
        .corner(5.0)
        .font_size(12.0)
        .outline()
        .bg(theme::CARD_BG)
}

/// A borderless toolbar button: bare label with a light hover fill, for
/// secondary actions that sit next to a filled primary one.
pub fn ghost_button(label: &'static str) -> Element {
    ghost(Element::label(label).font_size(12.5).fg(theme::TEXT_BODY))
}

/// [`ghost_button`] for a label that follows a signal.
pub fn ghost_button_signal(label: Signal<String>) -> Element {
    ghost(Element::label_signal(label).font_size(12.5).fg(theme::TEXT_BODY))
}

fn ghost(label: Element) -> Element {
    Element::row()
        .height(30)
        .min_width(44)
        .padding_xy(12, 0)
        .cross(Align::Center)
        .corner(5.0)
        .clickable()
        .on_click(|_| {})
        .child(label.align(Align::Center))
}

/// The old `PillButton` with `tone == 1`: red-tinted pill.
pub fn pill_button_danger(label: &'static str) -> Element {
    Element::button(label)
        .height(28)
        .min_width(64)
        .corner(5.0)
        .font_size(12.0)
        .outline()
        .danger()
        .bg(theme::CARD_BG)
}

/// The old `ChoicePill`: 28px, filled steel blue with a white label when
/// active; white with a hairline border otherwise. Built from stacked leaves
/// so the fill, border and label colour all follow the active signal.
pub fn choice_pill(label: &'static str, active: Signal<bool>) -> Element {
    let fill = active;
    let ring = active;
    let on = active;
    let off = active;
    Element::stack()
        .height(28)
        .min_width(44)
        .clickable()
        .child(
            Element::leaf()
                .fill()
                .corner(5.0)
                .bg_when(move || {
                    if ring.get() {
                        theme::ACCENT
                    } else {
                        theme::BORDER_SELECT
                    }
                }),
        )
        .child(
            Element::leaf()
                .fill()
                .margin(1)
                .corner(4.0)
                .bg_when(move || {
                    if fill.get() {
                        theme::ACCENT
                    } else {
                        theme::CARD_BG
                    }
                }),
        )
        .child(
            Element::label(label)
                .font_size(12.0)
                .fg(theme::CARD_BG)
                .align(Align::Center)
                .visible_when(move || on.get()),
        )
        .child(
            Element::label(label)
                .font_size(12.0)
                .fg(theme::TEXT_BODY)
                .align(Align::Center)
                .visible_when(move || !off.get()),
        )
}

// -- inputs -------------------------------------------------------------------

/// A light inline input (old `InlineField`, 30px). Commit fires on Enter and
/// on focus loss; the border turns red while this field owns `cfg-error-key`
/// (swapped for a frameless input inside a red shell, because the widget
/// paints its own border from the theme).
pub fn inline_field(
    value: Signal<String>,
    placeholder: &'static str,
    invalid: Signal<bool>,
    commit_tx: Sender<Action>,
    commit_key: &'static str,
) -> Element {
    let swap = invalid;
    let shell = invalid;
    let commit_value = value;
    let tx_a = commit_tx.clone();
    let tx_b = commit_tx;
    let make_commit = move |tx: Sender<Action>| {
        let cv = commit_value;
        let key = commit_key;
        move |_ctx: &mut EventCtx| {
            let current = cv.get();
            let _ = tx.send(Action::SaveString(key.to_string(), current));
        }
    };
    let commit_a = make_commit(tx_a);
    let commit_b = make_commit(tx_b);
    Element::stack()
        .height(30)
        .child(
            Element::text_input(value, placeholder)
                .fill()
                .height(30)
                .font_size(12.5)
                .corner(6.0)
                .on_commit(commit_a)
                .visible_when(move || !swap.get()),
        )
        .child(
            Element::stack()
                .fill()
                .visible_when(move || shell.get())
                .child(Element::leaf().fill().corner(6.0).bg(theme::BORDER_INVALID))
                .child(
                    Element::leaf()
                        .fill()
                        .margin(1)
                        .corner(5.0)
                        .bg(theme::CARD_BG),
                )
                .child(
                    Element::text_input(value, placeholder)
                        .fill()
                        .font_size(12.5)
                        .frameless()
                        .margin_xy(9, 0)
                        .on_commit(commit_b),
                ),
        )
}

/// A settings row (old `FieldRow`): fixed label column with hint underneath,
/// one right-aligned control. `control` is built by the caller so it can carry
/// its own commit closure and invalid-border swap.
pub fn field_row(
    label: &'static str,
    hint: &'static str,
    control: Element,
    label_width: i32,
) -> Element {
    let height = if hint.is_empty() { 52 } else { 58 };
    let hint_present = !hint.is_empty();
    Element::row()
        .width_match()
        .height(height)
        .padding_xy(16, 0)
        .cross(Align::Center)
        .spacing(12)
        .child(
            Element::col()
                .width(label_width)
                .spacing(2)
                .child(Element::label(label).font_size(13.0).fg(theme::TEXT).truncate(Truncate::End))
                .child(
                    Element::label(hint)
                        .font_size(11.0)
                        .fg(theme::TEXT_MUTED)
                                .visible_when(move || hint_present),
                ),
        )
        // No flex_spacer: the control carries weight(1.0) and takes the whole
        // remaining width. A spacer here would split the space and halve it.
        .child(control)
}

/// The old `ToggleRow`: label + optional hint/error on the left, small
/// switch right. `on_switch_change` receives the already-applied new value.
pub fn toggle_row(
    label: &'static str,
    hint: &'static str,
    error: Signal<String>,
    checked: Signal<bool>,
    on_change: impl Fn(&mut EventCtx, bool) + 'static,
) -> Element {
    let hint_present = !hint.is_empty();
    // Fixed-height row with both the copy block and the switch centred on the
    // full row (not on the first line), matching the old Slint ToggleRow.
    Element::row()
        .width_match()
        .height(60)
        .padding_xy(16, 0)
        .cross(Align::Center)
        .spacing(12)
        .child(
            Element::stack()
                .height_match()
                .weight(1.0)
                .child(
                    Element::col()
                        .cross(Align::Start)
                        .spacing(3)
                        .align_xy(Align::Start, Align::Center)
                        .child(Element::label(label).font_size(13.0).fg(theme::TEXT))
                        .child(
                            Element::label(hint)
                                .font_size(11.0)
                                .fg(theme::TEXT_MUTED)
                                        .visible_when(move || hint_present),
                        )
                        .child(
                            Element::label_signal(error)
                                .font_size(11.0)
                                .fg(theme::DANGER)
                                        .visible_signal(error.map(|e| !e.is_empty())),
                        ),
                ),
        )
        .child(Element::switch(checked).small().on_switch_change(on_change))
}

/// The old `RowLine`: 1px separator inset 16px on both sides, with breathing
/// room above and below so it never crowds the row's subtitle.
pub fn row_line() -> Element {
    Element::row()
        .width_match()
        .height(1)
        .margin_xy(0, 7)
        .padding_xy(16, 0)
        .child(Element::leaf().weight(1.0).height(1).bg(theme::BORDER_SOFT))
}

// -- sidebar pieces -----------------------------------------------------------

/// The old `StatRow`: quiet label left, value right, 18px. The value colour
/// arrives as a theme Role so it can follow the state signal.
pub fn stat_row(label: &'static str, value: Signal<String>, value_color: Signal<Role>) -> Element {
    Element::row()
        .width_match()
        .height(18)
        .spacing(8)
        .child(
            Element::label(label)
                .font_size(12.0)
                .fg(theme::TEXT_SECONDARY)
                .weight(1.0),
        )
        .child(
            Element::label_signal(value)
                .font_size(12.0)
                .fg_role_signal(value_color),
        )
}

/// The old `StatusRow`: dot + label + value + chevron, hoverable, 28px.
pub fn status_row(
    label: &'static str,
    value: Signal<String>,
    tone: Signal<i32>,
    open: Signal<bool>,
    on_toggle: impl FnMut(&mut EventCtx) + 'static,
) -> Element {
    let dot = tone;
    Element::row()
        .width_match()
        .height(28)
        .padding_xy(2, 0)
        .spacing(8)
        .cross(Align::Center)
        .clickable()
        .on_click(on_toggle)
        .child(
            Element::leaf()
                .size(5, 5)
                .corner(2.5)
                .bg_when(move || theme::tone_color(dot.get())),
        )
        .child(
            Element::label(label)
                .font_size(12.0)
                .fg(theme::TEXT_BODY)
                .weight(1.0),
        )
        .child(Element::label_signal(value).font_size(12.0).fg(theme::TEXT))
        .child(chevron(open))
}

/// The old `NetRowView`: label + value over a detail line, 36px.
pub fn net_row(label: String, detail: String, value: String, tone: i32) -> Element {
    let dot = theme::tone_color(tone);
    let value_color = if tone == 1 || tone == 0 { theme::TEXT_SOFT } else { dot };
    let flagged = tone >= 2;
    Element::row()
        .width_match()
        .height(36)
        .spacing(8)
        .child(
            Element::col()
                .weight(1.0)
                .padding_xy(0, 5)
                .spacing(1)
                .child(
                    Element::row()
                        .spacing(6)
                        .child(
                            Element::label(label)
                                .font_size(12.0)
                                .fg(theme::TEXT_BODY)
                                                .weight(1.0),
                        )
                        .child(Element::label(value).font_size(11.0).fg(value_color)),
                )
                .child(
                    Element::label(detail)
                        .font_size(11.0)
                        .fg(theme::TEXT_SOFT)
                        .truncate(Truncate::End),
                ),
        )
        .child(
            Element::leaf()
                .size(5, 5)
                .corner(2.5)
                .bg(dot)
                .visible_when(move || flagged),
        )
}

/// The old `SiteBadge` at its default 28px: white tile + hairline border when
/// a logo is bundled, tinted tile + white initial otherwise. The logo inset is
/// 4px so it lands on device pixels at every Windows scale factor.
pub fn site_badge(logo: Option<ImageContent>, initial: Signal<String>, tile: Color) -> Element {
    match logo {
        Some(image) => Element::stack()
            .size(28, 28)
            .corner(6.0)
            .bg(theme::CARD_BG)
            .border(theme::BORDER_TILE, 1)
            .child(
                Element::image_content(image)
                    .size(20, 20)
                    .align(Align::Center)
                    .fit(Fit::Contain),
            ),
        None => Element::stack()
            .size(28, 28)
            .corner(6.0)
            .bg(tile)
            .child(
                Element::label_signal(initial)
                    .font_size(12.0)
                    .fg(theme::CARD_BG)
                    .align(Align::Center),
            ),
    }
}

// -- surfaces -----------------------------------------------------------------

/// A white card with a hairline border (the base of every page).
pub fn card(body: Element) -> Element {
    Element::col()
        .width_match()
        .bg(theme::CARD_BG)
        .corner(6.0)
        .border(theme::BORDER, 1)
        .child(body)
}
