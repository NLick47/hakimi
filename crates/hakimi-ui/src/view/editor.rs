//! Site editor modal, restyled to the dark-hero design language: header bar,
//! identity row with a live tile, the domain list on a tinted card, and a
//! gradient save button. Field semantics (route presets, SNI/custom reveal,
//! save-time URL extraction) are unchanged from the old `editor-open` overlay.

use windui::prelude::*;

use crate::app_state::{Action, EditorRowState, UiSignals};
use crate::model;
use crate::theme;
use crate::view::common::{choice_pill, pill_button_danger, text_button};

const ROUTE_PRESETS: [&str; 5] = ["继承默认", "直连", "ECH", "SNI 伪装", "自定义"];

/// Modal input: 38px, radius 8. The theme supplies border and placeholder.
fn form_input(value: Signal<String>, placeholder: &'static str) -> Element {
    Element::text_input(value, placeholder)
        .width_match()
        .height(38)
        .font_size(13.5)
        .corner(8.0)
}

/// Secondary one-line input (访问地址).
fn form_input_small(value: Signal<String>, placeholder: &'static str) -> Element {
    Element::text_input(value, placeholder)
        .width_match()
        .height(32)
        .font_size(12.5)
        .corner(8.0)
}

/// Section label: 12px, weight 600.
fn section_heading(text: &'static str) -> Element {
    Element::label(text)
        .font_size(12.0)
        .font_weight(600)
        .fg(theme::TEXT_BODY)
}

/// Small hint line under a section.
fn caption(text: &str) -> Element {
    Element::label(text.to_string())
        .font_size(11.0)
        .fg(theme::TEXT_SOFT)
}

/// A labelled field: 11.5px secondary label, 6px gap, then the input.
fn field(label: &'static str, input: Element) -> Element {
    Element::col()
        .width_match()
        .spacing(6)
        .child(Element::label(label).font_size(11.5).fg(theme::TEXT_SECONDARY))
        .child(input)
}

fn route_select(row: &EditorRowState) -> Element {
    Element::dropdown(ROUTE_PRESETS.to_vec(), row.preset)
        .width(118)
        .height(38)
        .corner(8.0)
}

/// One domain row inside the tinted card: input + route + optional remove,
/// with conditional SNI / custom fields below.
fn domain_row(row: EditorRowState, removable: bool, tx: Sender<Action>) -> Element {
    let index = row.index;
    let remove_tx = tx.clone();

    // Blur / Enter normalises a pasted URL into a bare host; save repeats it.
    let norm_pattern = row.pattern;
    let input = Element::text_input(row.pattern, "example.com 或 *.example.com")
        .weight(1.0)
        .height(38)
        .font_size(13.5)
        .corner(8.0)
        .on_commit(move |_| {
            if let Ok(host) = model::normalize_domain_host(&norm_pattern.get()) {
                norm_pattern.set(host);
            }
        });

    let mut controls = Element::row()
        .width_match()
        .height(38)
        .cross(Align::Center)
        .spacing(8)
        .child(input)
        .child(route_select(&row));
    // Always reserve the trailing slot so inputs and dropdowns line up on
    // every row. Only multi-row editors show the actual "移除" action.
    if removable {
        controls = controls.child(
            text_button("移除", false)
                .min_width(44)
                .on_click(move |_| {
                    let _ = remove_tx.send(Action::RemoveDomain(index));
                }),
        );
    } else {
        controls = controls.child(Element::leaf().width(44));
    }

    Element::col()
        .width_match()
        .spacing(6)
        .child(controls)
        .child(
            Element::col()
                .width_match()
                .spacing(4)
                .visible_signal(row.preset.map(|p| *p == 3))
                .child(caption("伪装 SNI 主机"))
                .child(form_input_small(
                    row.sni,
                    "多个用逗号分隔；留空使用默认候选",
                )),
        )
        .child(
            Element::col()
                .width_match()
                .spacing(4)
                .visible_signal(row.preset.map(|p| *p == 4))
                .child(caption("自定义线路"))
                .child(form_input_small(row.custom, "例如 ech+direct")),
        )
}

/// Identity tile next to the name field. Letter and colour both derive from
/// the name signal alone; an empty name falls back to a muted "＋" tile.
fn identity_tile(s: &UiSignals) -> Element {
    let letter = s.editor_name.map(|n| {
        let trimmed = n.trim();
        match trimmed.chars().next() {
            Some(c) => c.to_uppercase().collect::<String>(),
            None => "＋".to_string(),
        }
    });
    let empty = s.editor_name.map(|n| n.trim().is_empty());
    let colour = s.editor_name.map(|n| {
        let trimmed = n.trim();
        if trimmed.is_empty() {
            theme::TEXT_MUTED
        } else {
            theme::from_hex(model::tile_color(trimmed))
        }
    });

    Element::stack()
        .size(42, 42)
        .child(
            Element::leaf()
                .fill()
                .corner(10.0)
                .bg(theme::TEXT_MUTED)
                .visible_when(move || empty.get()),
        )
        .child(
            Element::leaf()
                .fill()
                .corner(10.0)
                .bg_when(move || colour.get())
                .shadow(Shadow::new(0.0, 2.0, 6.0, theme::DIALOG_SHADOW))
                .visible_when(move || !empty.get()),
        )
        .child(
            Element::label_signal(letter)
                .font_size(17.0)
                .font_weight(700)
                .fg(theme::CARD_BG)
                .align(Align::Center),
        )
}

/// The gradient primary button (save) — the hero card's CTA language.
fn save_button(tx: Sender<Action>) -> Element {
    Element::stack()
        .size(96, 36)
        .corner(8.0)
        .clickable()
        .on_click(move |_| {
            let _ = tx.send(Action::SaveEditor);
        })
        .child(
            Element::leaf()
                .fill()
                .corner(8.0)
                .bg_gradient(Gradient::linear(
                    (0.0, 0.0),
                    (0.0, 1.0),
                    vec![(0.0, Color::hex(0x446B8F)), (1.0, theme::ACCENT)],
                ))
                .shadow(Shadow::new(0.0, 2.0, 8.0, theme::HERO_SHADOW)),
        )
        .child(
            Element::label("保存")
                .font_size(13.5)
                .font_weight(600)
                .fg(theme::HERO_TEXT)
                .align(Align::Center),
        )
}

/// Secondary outlined button (cancel) — white fill, hairline border, so the
/// footer reads 描边取消 + 渐变主按钮 like the rest of the redesign.
fn ghost_button(label: &'static str, tx: Sender<Action>) -> Element {
    Element::stack()
        .size(84, 36)
        .corner(8.0)
        .clickable()
        .on_click(move |_| {
            let _ = tx.send(Action::CloseEditor);
        })
        .child(
            Element::leaf()
                .fill()
                .corner(8.0)
                .bg(theme::CARD_BG)
                .border(theme::BORDER_INPUT, 1),
        )
        .child(
            Element::label(label)
                .font_size(13.0)
                .fg(theme::TEXT_BODY)
                .align(Align::Center),
        )
}

pub fn view(s: UiSignals, tx: Sender<Action>) -> Element {
    let add_tx = tx.clone();
    let cancel_tx = tx.clone();
    let save_tx = tx.clone();
    let delete_tx = tx.clone();
    let dismiss_tx = tx.clone();
    let close_tx = tx.clone();

    let rows = s.editor_rows;
    let multi = rows.map(|r| r.len() > 1);
    let key_multi = multi;
    let domain_list = Element::list_signal(
        rows,
        move |row: &EditorRowState| (row.index, key_multi.get()),
        move |row| {
            let removable = multi.get();
            domain_row(row, removable, tx.clone())
        },
    );

    // Old default-route pills: flat 28px pills, "自动" not "继承默认".
    let default_labels = ["自动", "直连", "ECH", "SNI 伪装", "自定义"];
    let mut default_pills = Element::row().width_match().spacing(6);
    for (i, label) in default_labels.iter().enumerate() {
        let active = s.editor_default_preset.map(move |preset| *preset == i as i32);
        let set = s.editor_default_preset;
        default_pills = default_pills.child(
            choice_pill(label, active)
                .weight(1.0)
                .on_click(move |_| {
                    set.set(i as i32);
                }),
        );
    }

    let delete_id = s.editor_id;
    let delete_visible = s.editor_deletable;
    let custom_visible = s.editor_default_preset.map(|p| *p == 4);

    let body = Element::col()
        .width_match()
        .padding_edges(Insets {
            left: 20,
            right: 20,
            top: 16,
            bottom: 4,
        })
        .spacing(12)
        .child(
            Element::row()
                .width_match()
                .spacing(10)
                .cross(Align::Center)
                .child(identity_tile(&s))
                .child(
                    Element::text_input(s.editor_name, "站点名称，例如 Pixiv")
                        .weight(1.0)
                        .height(38)
                        .font_size(13.5)
                        .corner(8.0),
                ),
        )
        .child(field(
            "访问地址（可选）",
            form_input(
                s.editor_homepage,
                "https://www.pixiv.net/，留空使用第一个域名",
            ),
        ))
        .child(section_heading("域名与线路"))
        .child(
            Element::col()
                .width_match()
                .spacing(8)
                .child(domain_list),
        )
        .child(caption(
            "支持粘贴完整网址，保存时自动提取域名；每个域名可单独选线路，不选则用默认线路。",
        ))
        .child(
            Element::row()
                .width_match()
                .child(
                    text_button("＋ 添加域名", true)
                        .min_width(100)
                        .on_click(move |_| {
                            let _ = add_tx.send(Action::AddDomain);
                        }),
                ),
        )
        .child(section_heading("默认线路"))
        .child(default_pills)
        .child(
            Element::col()
                .width_match()
                .spacing(6)
                .visible_signal(custom_visible)
                .child(
                    Element::label("自定义默认线路（高级）")
                        .font_size(11.5)
                        .fg(theme::TEXT_SECONDARY),
                )
                .child(form_input_small(
                    s.editor_default_custom,
                    "例如 ech+direct 或 sni:www.baidu.com+direct",
                )),
        );

    let error = s.editor_error;
    let error_present = s.editor_error;
    let footer = Element::col()
        .width_match()
        .bg(theme::TOOLBAR_BG)
        .padding_edges(Insets {
            left: 20,
            right: 20,
            top: 12,
            bottom: 16,
        })
        .spacing(10)
        .child(
            Element::label_signal(error)
                .font_size(12.0)
                .fg(theme::DANGER)
                .visible_signal(error_present.map(|e| !e.is_empty())),
        )
        .child(
            Element::row()
                .width_match()
                .cross(Align::Center)
                .spacing(8)
                .child(
                    pill_button_danger("删除站点")
                        .height(36)
                        .corner(8.0)
                        .visible_signal(delete_visible)
                        .on_click(move |_| {
                            let _ = delete_tx.send(Action::DeleteSite(delete_id.get()));
                        }),
                )
                .child(Element::flex_spacer())
                .child(ghost_button("取消", cancel_tx))
                .child(save_button(save_tx)),
        );

    let panel = Element::col()
        .width(560)
        .bg(theme::CARD_BG)
        .corner(12.0)
        .shadow(Shadow::new(0.0, 18.0, 48.0, theme::DIALOG_SHADOW))
        .child(
            Element::col()
                .width_match()
                .bg(theme::TOOLBAR_BG)
                .child(
                    Element::row()
                        .width_match()
                        .height(52)
                        .padding_xy(20, 0)
                        .cross(Align::Center)
                        .child(
                            Element::label_signal(
                                s.editor_is_new
                                    .map(|new| if *new { "添加站点" } else { "编辑站点" }.to_string()),
                            )
                            .font_size(15.0)
                            .font_weight(600)
                            .fg(theme::TEXT)
                            .weight(1.0),
                        )
                        .child(
                            Element::stack()
                                .size(26, 26)
                                .corner(6.0)
                                .clickable()
                                .on_click(move |_| {
                                    let _ = close_tx.send(Action::CloseEditor);
                                })
                                .child(
                                    Element::label("✕")
                                        .font_size(14.0)
                                        .fg(theme::TEXT_MUTED)
                                        .align(Align::Center),
                                ),
                        ),
                )
                .child(Element::leaf().height(1).bg(theme::BORDER_SOFT)),
        )
        .child(
            Element::scroll()
                .width_match()
                .max_height(430)
                .child(body.width_match()),
        )
        .child(Element::leaf().height(1).bg(theme::BORDER_SOFT))
        .child(footer);

    // Instant (no animation) modal: dim the window, centre the panel, and let
    // clicking the scrim dismiss. Kept flat so it opens immediately.
    let show = s.editor_open;
    let dismiss = dismiss_tx;
    Element::stack()
        .fill()
        .visible_signal(show)
        .child(
            Element::stack()
                .fill()
                .bg(theme::SCRIM)
                .clickable()
                .on_click(move |_| {
                    let _ = dismiss.clone().send(Action::CloseEditor);
                }),
        )
        .child(panel.align(Align::Center))
}
