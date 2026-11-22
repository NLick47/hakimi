//! Environment / onboarding page: certificate trust + system proxy, in the
//! same grouped-card language as the settings pages.

use windui::prelude::*;

use crate::app_state::{Action, UiSignals};
use crate::theme;
use crate::view::common::{card, text_button};

/// A full-width hairline; a bare `leaf().height(1)` child of a col has no
/// width, so the line needs a row to stretch in.
fn hairline() -> Element {
    Element::row()
        .width_match()
        .height(1)
        .child(Element::leaf().weight(1.0).height(1).bg(theme::BORDER_SOFT))
}

/// One checklist row: label, coloured status over a muted hint, action slot —
/// the same rhythm as the settings cards.
fn status_row(
    label: &'static str,
    status: Signal<String>,
    status_role: Signal<Role>,
    hint: Signal<String>,
    error: Option<(Signal<String>, Signal<bool>)>,
    action: Element,
) -> Element {
    let mut info = Element::col()
        .weight(1.0)
        .cross(Align::Start)
        .spacing(3)
        .child(
            Element::label_signal(status)
                .font_size(12.5)
                .fg_role_signal(status_role)
                .max_lines(1)
                .truncate(Truncate::End),
        )
        .child(
            Element::label_signal(hint)
                .font_size(11.0)
                .fg(theme::TEXT_MUTED)
                .max_lines(2)
                .truncate(Truncate::End),
        );
    if let Some((error, present)) = error {
        info = info.child(
            Element::label_signal(error)
                .font_size(11.0)
                .fg(theme::WARN)
                .max_lines(2)
                .truncate(Truncate::End)
                .visible_signal(present),
        );
    }
    Element::row()
        .width_match()
        .padding_xy(20, 14)
        .cross(Align::Center)
        .spacing(12)
        .child(Element::label(label).font_size(13.0).fg(theme::TEXT).width(76))
        .child(info)
        .child(Element::col().width(96).cross(Align::Center).child(action))
}

fn ca_row(s: UiSignals, tx: Sender<Action>) -> Element {
    let status_role = s.ca_status_tone.map(|tone| match *tone {
        1 => Role::Success,
        2 => Role::Danger,
        _ => Role::TextMuted,
    });
    let install_tx = tx.clone();
    let show_button = s.ca_installed;
    let busy = s.ca_busy;
    let button = Element::stack()
        .width(96)
        .height(30)
        .visible_when(move || !show_button.get())
        .child(
            Element::button(busy.map(|busy| {
                if *busy {
                    "等待确认…"
                } else {
                    "安装证书"
                }
                .to_string()
            }))
            .width(96)
            .height(30)
            .corner(5.0)
            .font_size(12.5)
            .on_click(move |_| {
                let _ = install_tx.send(Action::CaAction(1));
            }),
        );
    status_row(
        "本地 CA",
        s.ca_status,
        status_role,
        s.ca_status_sub,
        Some((s.ca_action_error, s.ca_action_error.map(|e| !e.is_empty()))),
        button,
    )
}

fn proxy_row(s: UiSignals, tx: Sender<Action>) -> Element {
    let status_role = s.proxy_status_tone.map(|tone| match *tone {
        1 => Role::Success,
        2 => Role::Danger,
        _ => Role::TextMuted,
    });
    let reapply_tx = tx;
    let button = Element::stack()
        .width(96)
        .height(30)
        .visible_signal(s.proxy_reapply)
        .child(
            Element::button("重新应用")
                .width(96)
                .height(30)
                .corner(5.0)
                .font_size(12.5)
                .outline()
                .on_click(move |_| {
                    let _ = reapply_tx.send(Action::ReapplyProxy);
                }),
        );
    status_row(
        "系统代理",
        s.proxy_status,
        status_role,
        s.proxy_status_sub,
        None,
        button,
    )
}

pub fn view(s: UiSignals, tx: Sender<Action>) -> Element {
    let finish_tx = tx.clone();
    let finish_tx2 = tx.clone();

    let passed = s.env_ok;
    let blocked_for_button = s.fix_blocked;

    Element::col()
        .fill()
        .bg(theme::WINDOW_BG)
        .cross(Align::Center)
        .child(Element::flex_spacer())
        .child(
            card(
                Element::col()
                    .width_match()
                    .child(
                        Element::col()
                            .width_match()
                            .padding_edges(Insets {
                                left: 20,
                                right: 20,
                                top: 20,
                                bottom: 16,
                            })
                            .spacing(4)
                            .child(
                                Element::label_signal(s.fix_title)
                                    .font_size(16.0)
                                    .font_weight(500)
                                    .fg(theme::TEXT),
                            )
                            .child(
                                Element::label_signal(s.fix_subtitle)
                                    .font_size(12.0)
                                    .fg(theme::TEXT_SOFT),
                            ),
                    )
                    .child(hairline())
                    .child(ca_row(s, tx.clone()))
                    .child(hairline())
                    .child(proxy_row(s, tx.clone()))
                    .child(hairline())
                    .child(
                        Element::row()
                            .width_match()
                            .padding_xy(20, 14)
                            .cross(Align::Center)
                            .child(
                                text_button("暂不处理，返回主页", false)
                                    .on_click(move |_| {
                                        let _ = finish_tx2.send(Action::FinishOnboarding);
                                    })
                                    .visible_when(move || !passed.get()),
                            )
                            .child(Element::flex_spacer())
                            .child(
                                Element::button(blocked_for_button.map(|blocked| {
                                    if *blocked {
                                        "返回加速"
                                    } else {
                                        "完成"
                                    }
                                    .to_string()
                                }))
                                .min_width(96)
                                .height(30)
                                .corner(5.0)
                                .font_size(12.5)
                                .visible_when(move || passed.get())
                                .on_click(move |_| {
                                    let _ = finish_tx.send(Action::FinishOnboarding);
                                }),
                            ),
                    ),
            )
            .width(520),
        )
        .child(Element::flex_spacer())
}
