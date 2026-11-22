//! The exact light palette from the old `app.slint`, expressed as windui Colours.
//!
//! The desktop surface is a fixed light Fluent-style window: neutral window,
//! solid surfaces, hairline borders, no gradients. Keeping these as named
//! constants makes the port match the old screenshots pixel for pixel and gives
//! the view modules one place to look for a colour.

use windui::prelude::*;

pub const WINDOW_BG: Color = Color::hex(0xF3F4F5);
pub const TOOLBAR_BG: Color = Color::hex(0xFAFBFC);
pub const CARD_BG: Color = Color::hex(0xFFFFFF);

pub const BORDER: Color = Color::hex(0xE1E4E8);
pub const BORDER_SIDEBAR: Color = Color::hex(0xE5E8EC);
pub const BORDER_SOFT: Color = Color::hex(0xECEEF0);
#[allow(dead_code)]
pub const BORDER_FAINT: Color = Color::hex(0xF4F6F8);
#[allow(dead_code)]
pub const BORDER_ROW: Color = Color::hex(0xF1F3F5);
pub const BORDER_CARD_LINE: Color = Color::hex(0xEFF1F3);
pub const BORDER_INPUT: Color = Color::hex(0xD8DDE3);
pub const BORDER_SELECT: Color = Color::hex(0xD6DBE0);
pub const BORDER_SELECT_HOVER: Color = Color::hex(0xBFC7CF);
pub const BORDER_TILE: Color = Color::hex(0xE4E7EA);
pub const BORDER_FOCUS: Color = Color::hex(0x385D78);
pub const BORDER_INVALID: Color = Color::hex(0xC05B5B);
#[allow(dead_code)]
pub const BORDER_CHECK: Color = Color::hex(0x9AA3AC);

pub const TEXT: Color = Color::hex(0x1B1F24);
/// #3B434C — labels and domain hosts.
pub const TEXT_BODY: Color = Color::hex(0x3B434C);
/// #5C6670 — secondary labels, icons at rest.
pub const TEXT_SECONDARY: Color = Color::hex(0x5C6670);
/// #6B7480 — quiet copy, subtitles.
pub const TEXT_SOFT: Color = Color::hex(0x6B7480);
/// #8A95A2 — hints and zero-value stats.
pub const TEXT_MUTED: Color = Color::hex(0x8A95A2);
/// #4F5963 — settings nav labels and group subheads.
pub const TEXT_NAV: Color = Color::hex(0x4F5963);
/// #7B858F — the "偏好设置" caption.
pub const TEXT_CAPTION: Color = Color::hex(0x7B858F);
/// #263746 — selected settings nav label.
pub const TEXT_NAV_ACTIVE: Color = Color::hex(0x263746);
/// #98A1AB — the 线路 prefix in the route select.
#[allow(dead_code)]
pub const TEXT_PREFIX: Color = Color::hex(0x98A1AB);
/// #A8B0B9 — inline input placeholder.
pub const TEXT_PLACEHOLDER: Color = Color::hex(0xA8B0B9);
pub const TEXT_DISABLED: Color = Color::hex(0xAAB1B9);
/// #7A848F — open chevron.
pub const TEXT_CHEVRON_OPEN: Color = Color::hex(0x7A848F);

/// The old accent blue (steel blue) used for links, switches, checkmarks and
/// active pills. This is not the Windows system blue — primary action buttons
/// use `PRIMARY` below, matching the old Fluent look.
pub const ACCENT: Color = Color::hex(0x385D78);
#[allow(dead_code)]
pub const ACCENT_HOVER_BG: Color = Color::hex(0xF2F4F6);
#[allow(dead_code)]
pub const ACCENT_TINT: Color = Color::hex(0xEDF3FA);
pub const ACCENT_TINT_BG: Color = Color::hex(0xE8EEF4);
#[allow(dead_code)]
pub const ACCENT_BORDER: Color = Color::hex(0xC5D9EC);
/// Primary action button (Fluent blue): rest / hover / pressed.
pub const PRIMARY: Color = Color::hex(0x005FB8);
pub const PRIMARY_HOVER: Color = Color::hex(0x1A6FC4);
pub const PRIMARY_PRESSED: Color = Color::hex(0x004C93);

pub const OK: Color = Color::hex(0x1B7F4D);
pub const WARN: Color = Color::hex(0xB88325);
pub const DANGER: Color = Color::hex(0xC0392B);
pub const DANGER_SOFT: Color = Color::hex(0xC05B5B);
pub const DANGER_TINT_TEXT: Color = Color::hex(0xA32D2D);
pub const DANGER_TINT_BODY: Color = Color::hex(0x7A4B45);
#[allow(dead_code)]
pub const DANGER_TILE: Color = Color::hex(0xC05B5B);
pub const DOT_NEUTRAL: Color = Color::hex(0xA0A8B0);

// Dark hero card (the master switch): the only dark surface in the window, so
// the primary control reads at a glance. Slate gradient; the running-state
// night sky and switch colors live in fx.rs.
pub const HERO_BG_TOP: Color = Color::hex(0x2B3850);
pub const HERO_BG_BOTTOM: Color = Color::hex(0x1D2736);
pub const HERO_SHADOW: Color = Color::rgba(23, 32, 46, 82);
pub const HERO_TEXT: Color = Color::hex(0xF2F5F9);
/// White at 62% — the hero subtitle line.
pub const HERO_TEXT_SUB: Color = Color::rgba(242, 245, 249, 158);
pub const HERO_DOT_PAUSED: Color = Color::hex(0x7C8BA1);
pub const HERO_DOT_RUN: Color = Color::hex(0x3DDC97);
/// Glass track: white 16% fill over a white 14% hairline.
pub const SWITCH_OFF_TRACK: Color = Color::rgba(255, 255, 255, 41);
pub const SWITCH_OFF_BORDER: Color = Color::rgba(255, 255, 255, 36);

// Hover fills used by rows, nav items and inputs.
#[allow(dead_code)]
pub const HOVER_ROW: Color = Color::hex(0xF4F6F8);
#[allow(dead_code)]
pub const HOVER_ROW_SOFT: Color = Color::hex(0xF5F7F9);
#[allow(dead_code)]
pub const HOVER_ROW_NAV: Color = Color::hex(0xEAEDF0);
#[allow(dead_code)]
pub const HOVER_ROW_HEAD: Color = Color::hex(0xF7F8F9);
#[allow(dead_code)]
pub const HOVER_ROW_DOMAIN: Color = Color::hex(0xF1F3F5);
#[allow(dead_code)]
pub const HOVER_CONTROL: Color = Color::hex(0xF2F4F6);
#[allow(dead_code)]
pub const HOVER_ICON: Color = Color::hex(0xE9EBEE);
#[allow(dead_code)]
pub const HOVER_TILE: Color = Color::hex(0xE9EBEE);
#[allow(dead_code)]
pub const SELECTED_PRESSED: Color = Color::hex(0xECEEF0);

// Tinted banners.
pub const WARN_BANNER_BG: Color = Color::hex(0xFFF6E5);
pub const WARN_BANNER_BORDER: Color = Color::hex(0xF0DFC0);
pub const WARN_BANNER_TEXT: Color = Color::hex(0x8A6116);
pub const DANGER_BANNER_BG: Color = Color::hex(0xFDECEA);
pub const DANGER_BANNER_BORDER: Color = Color::hex(0xF2C8C2);
pub const DANGER_NOTICE_BG: Color = Color::hex(0xFBE9E7);
pub const DANGER_NOTICE_BORDER: Color = Color::hex(0xE4C7C5);
#[allow(dead_code)]
pub const DANGER_PILL_BORDER: Color = Color::hex(0xE4C7C5);
#[allow(dead_code)]
pub const DANGER_PILL_HOVER: Color = Color::hex(0xF9ECEB);

// Editor overlay + card.
pub const SCRIM: Color = Color::rgba(15, 18, 22, 77);
#[allow(dead_code)]
pub const EDITOR_BORDER: Color = Color::hex(0xDDE2E7);
/// Tinted card that hosts the domain rows in the site editor.
#[allow(dead_code)]
pub const EDITOR_ROW_BG: Color = Color::hex(0xF6F8FA);
/// Old editor card drop shadow: rgba(15,18,22,0.22), blur 28, offset-y 10.
pub const DIALOG_SHADOW: Color = Color::rgba(15, 18, 22, 56);

/// Parse one of the `#RRGGBB` strings carried in `SiteData` into a Colour.
/// These come from `model.rs`'s fixed palette, so a failure is impossible in
/// practice; fall back to the muted colour rather than panicking in the view.
pub fn from_hex(hex: &str) -> Color {
    let digits = hex.trim_start_matches('#');
    if digits.len() == 6 {
        if let Ok(value) = u32::from_str_radix(digits, 16) {
            return Color::hex(value);
        }
    }
    TEXT_MUTED
}

/// Map the sidebar status tone (0 neutral, 1 ok, 2 degraded, 3 broken) to a
/// dot colour, matching `StatusRow.dot-color` in the old `.slint`.
pub fn tone_color(tone: i32) -> Color {
    match tone {
        1 => OK,
        2 => WARN,
        3 => DANGER_SOFT,
        _ => DOT_NEUTRAL,
    }
}

/// Platform monospace for hosts, paths and latencies; Menlo is macOS-only.
pub fn mono_font() -> &'static str {
    if cfg!(target_os = "macos") {
        "Menlo"
    } else if cfg!(windows) {
        "Consolas"
    } else {
        "DejaVu Sans Mono"
    }
}

/// The whole light theme with the old palette baked in, so native widgets
/// (switch, checkbox, inputs, dropdowns, menus) use the same colours the old
/// `.slint` drew by hand. Installed via `App::theme` before the tree builds.
pub fn app_theme() -> Theme {
    let mut th = Theme::default();
    let p = &mut th.palette;
    p.accent = ACCENT;
    p.accent_hover = Color::hex(0x2E5168);
    p.accent_active = Color::hex(0x26455A);
    p.on_accent = CARD_BG;
    p.accent_text = Some(ACCENT);
    p.bg = WINDOW_BG;
    p.surface = CARD_BG;
    p.surface_alt = TOOLBAR_BG;
    p.text = TEXT;
    p.text_muted = TEXT_SECONDARY;
    p.text_subtle = TEXT_MUTED;
    p.text_disabled = TEXT_DISABLED;
    p.border = BORDER;
    p.track = Color::hex(0xB4BCC4);
    p.placeholder = TEXT_PLACEHOLDER;
    p.divider = BORDER_SOFT;
    p.danger = DANGER;
    p.success = OK;
    p.warning = WARN;

    // Primary buttons: the old ActionButton's Fluent blue trio.
    th.button.bg = Some(PRIMARY);
    th.button.hover = Some(PRIMARY_HOVER);
    th.button.active = Some(PRIMARY_PRESSED);
    th.button.fg = Some(CARD_BG);

    // Text inputs: InlineField / FormInput borders and placeholder.
    th.input.bg = Some(CARD_BG);
    th.input.border = Some(BORDER_INPUT);
    th.input.border_focus = Some(BORDER_FOCUS);
    th.input.placeholder = Some(TEXT_PLACEHOLDER);

    // Switches and checkboxes: SwitchControl / CheckSquare colours.
    th.toggle.accent = Some(ACCENT);
    th.toggle.track = Some(Color::hex(0xB4BCC4));
    th.toggle.knob = Some(CARD_BG);

    // Route select and menus.
    th.dropdown.bg = Some(CARD_BG);
    th.dropdown.border = Some(BORDER_SELECT);
    th.dropdown.border_focus = Some(BORDER_FOCUS);
    th.dropdown.border_hover = Some(BORDER_SELECT_HOVER);
    th.dropdown.text = Some(TEXT);
    th.dropdown.chevron = Some(TEXT_SECONDARY);
    th.menu.border = Some(BORDER_SELECT);

    // Site editor overlay: rgba(15, 18, 22, 0.30) from the old dialog.
    th.modal.scrim = Some(SCRIM);

    // Near-invisible scrollbar: it still needs to be grabbable (windui keeps a
    // >=16px hit area regardless of visual width), but should not compete with
    // the content. 4px wide, faint, hugging the edge, no track.
    th.scrollbar.width = Some(4.0);
    th.scrollbar.margin = Some(4.0);
    th.scrollbar.thumb = Some(Color::rgba(0, 0, 0, 26));
    th.scrollbar.thumb_active = Some(Color::rgba(0, 0, 0, 70));

    th
}
