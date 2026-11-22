//! Home page: toolbar, sidebar (master switch + banners + overview), and the
//! site list with per-site expansion. Port of the `page == 0` tree in app.slint.

use windui::prelude::*;

use crate::app_state::{Action, UiSignals};
use crate::fx;
use crate::model::{NetEntry, SiteData};
use crate::theme;
use crate::view::common::{self, card, chevron, site_badge, stat_row, status_row, text_button};

// -- sidebar ------------------------------------------------------------------

/// The master switch as a dark hero card; the FX night sky fades in behind
/// the content while acceleration runs.
fn master_card(s: UiSignals, tx: Sender<Action>) -> Element {
    let running = s.running;
    Element::stack()
        .width_match()
        .height(56)
        .corner(10.0)
        .bg_gradient(Gradient::linear(
            (0.0, 0.0),
            (1.0, 1.0),
            vec![(0.0, theme::HERO_BG_TOP), (1.0, theme::HERO_BG_BOTTOM)],
        ))
        .shadow(Shadow::new(0.0, 5.0, 16.0, theme::HERO_SHADOW))
        .child(fx::sky_layer(s))
        .child(fx::galaxy_layer(s))
        .child(fx::twinkle_layer(s))
        .child(fx::aurora_layer(s))
        .child(fx::meteor_layer(s))
        .child(
            Element::row()
                .width_match()
                .height_match()
                .padding_xy(14, 0)
                .cross(Align::Center)
                .spacing(9)
                .child(fx::dot(s.fx_dot))
                .child(
                    Element::col()
                        .weight(1.0)
                        .spacing(3)
                        .child(
                            Element::label_signal(
                                running.map(|on| if *on { "加速运行中" } else { "加速已暂停" }.to_string()),
                            )
                            .font_size(13.5)
                            .font_weight(600)
                            .fg(theme::HERO_TEXT),
                        )
                        .child(
                            Element::label_signal(
                                s.stat_enabled.map(|n| format!("已选择 {n} 个站点")),
                            )
                            .font_size(10.5)
                            .fg(theme::HERO_TEXT_SUB)
                            .visible_when(move || !running.get()),
                        )
                        .child(
                            Element::label_signal(
                                s.stat_enabled.map(|n| format!("{n} 个站点加速中")),
                            )
                            .font_size(10.5)
                            .fg(theme::HERO_TEXT_SUB)
                            .visible_when(move || running.get()),
                        ),
                )
                .child(fx::switch(s, tx)),
        )
}

fn warn_banner(_s: UiSignals, tx: Sender<Action>) -> Element {
    let tx = tx.clone();
    Element::col()
        .width_match()
        .bg(theme::WARN_BANNER_BG)
        .corner(6.0)
        .border(theme::WARN_BANNER_BORDER, 1)
        .padding(10)
        .spacing(6)
        .child(
            Element::label("环境检查未通过，部分加速可能不生效")
                .font_size(11.5)
                .fg(theme::WARN_BANNER_TEXT),
        )
        .child(
            Element::row()
                .width_match()
                .align(Align::End)
                .child(text_button("去修复", false).on_click(move |_| {
                    let _ = tx.send(Action::OpenFix);
                })),
        )
}

fn interrupt_banner(tx: Sender<Action>) -> Element {
    let dismiss = tx.clone();
    let restart = tx;
    Element::col()
        .width_match()
        .bg(theme::DANGER_BANNER_BG)
        .corner(6.0)
        .border(theme::DANGER_BANNER_BORDER, 1)
        .padding(10)
        .spacing(6)
        .child(
            Element::label("加速已中断")
                .font_size(11.5)
                .font_weight(500)
                .fg(theme::DANGER_TINT_TEXT),
        )
        .child(
            Element::label("系统代理被其他程序修改，已自动暂停加速。")
                .font_size(11.0)
                .fg(theme::DANGER_TINT_BODY),
        )
        .child(
            Element::row()
                .width_match()
                .align(Align::End)
                .spacing(8)
                .child(text_button("知道了", false).on_click(move |_| {
                    let _ = dismiss.send(Action::DismissInterrupt);
                }))
                .child(text_button("重新开启", false).on_click(move |_| {
                    let _ = restart.send(Action::ToggleMaster);
                })),
        )
}

fn net_rows(rows: Signal<Vec<NetEntry>>) -> Element {
    Element::list_signal(
        rows,
        |row| row.key.clone(),
        |row| {
            common::net_row(
                row.label.clone(),
                row.detail.clone(),
                row.value.clone(),
                row.tone,
            )
        },
    )
}

fn overview_card(s: UiSignals) -> Element {
    // 较慢: gray at 0, amber otherwise. 超时: gray at 0, red otherwise.
    let slow_role = s.stat_slow.map(|v| {
        if v == "0" {
            Role::TextSubtle
        } else {
            Role::Warning
        }
    });
    let bad_role = s.stat_bad.map(|v| {
        if v == "0" {
            Role::TextSubtle
        } else {
            Role::Danger
        }
    });
    // The two status rows expand independently: each toggle flips only its
    // own signal, so both detail lists can be open at the same time.
    let doh_open = s.doh_open;
    let mirror_open = s.mirror_open;
    card(
        Element::col()
            .width_match()
            .padding(16)
            .spacing(10)
            .child(
                Element::label("概览")
                    .font_size(13.0)
                    .font_weight(500)
                    .fg(theme::TEXT_SOFT),
            )
            .child(
                Element::col()
                    .width_match()
                    .spacing(6)
                    .child(stat_row("站点", s.stat_sites, signal(Role::Text)))
                    .child(stat_row("已启用", s.stat_enabled, signal(Role::Text)))
                    .child(stat_row("域名", s.stat_domains, signal(Role::Text)))
                    .child(stat_row("较慢", s.stat_slow, slow_role))
                    .child(stat_row("超时", s.stat_bad, bad_role)),
            )
            .child(Element::leaf().height(1).bg(theme::BORDER_CARD_LINE))
            .child(status_row("DoH", s.stat_doh, s.stat_doh_tone, s.doh_open, move |_| {
                let opening = !doh_open.get();
                doh_open.set(opening);
                if opening {
                    mirror_open.set(false);
                }
            }))
            .child(
                Element::col()
                    .width_match()
                    .visible_signal(s.doh_open)
                    .child(Element::leaf().height(1).bg(theme::BORDER_CARD_LINE))
                    .child(net_rows(s.doh_rows)),
            )
            .child(Element::leaf().height(1).bg(theme::BORDER_CARD_LINE))
            .child(status_row("镜像", s.stat_mirror, s.stat_mirror_tone, s.mirror_open, move |_| {
                let opening = !mirror_open.get();
                mirror_open.set(opening);
                if opening {
                    doh_open.set(false);
                }
            }))
            .child(
                Element::col()
                    .width_match()
                    .visible_signal(s.mirror_open)
                    .child(Element::leaf().height(1).bg(theme::BORDER_CARD_LINE))
                    .child(net_rows(s.mirror_rows)),
            ),
    )
}

fn sidebar(s: UiSignals, tx: Sender<Action>) -> Element {
    let warn_visible = s.env_ok.map(|ok| !*ok);
    Element::col()
        .width(220)
        .height_match()
        .bg(theme::TOOLBAR_BG)
        .border(theme::BORDER_SIDEBAR, 1)
        .border_edges(Edges::RIGHT)
        .child(
            Element::scroll()
                .fill()
                .child(
                    Element::col()
                        .width_match()
                        .padding(16)
                        .spacing(14)
                        .child(master_card(s, tx.clone()))
                        .child(warn_banner(s, tx.clone()).visible_signal(warn_visible))
                        .child(
                            interrupt_banner(tx.clone()).visible_signal(s.proxy_interrupted),
                        )
                        .child(overview_card(s))
                        .child(Element::leaf().height(0)),
                ),
        )
}

// -- site list ----------------------------------------------------------------

fn site_row(site: SiteData, tx: Sender<Action>) -> Element {
    let open = site.open;
    let enabled = site.enabled;

    let check = signal(site.enabled);
    let check_state = check;
    let check_tx = tx.clone();
    let check_id = site.id.clone();

    let mut header = Element::row()
        .width_match()
        .height(52)
        .padding_xy(14, 0)
        .cross(Align::Center)
        .spacing(10)
        .child(
            Element::checkbox("", check).on_toggle(move |_| {
                // Controlled checkbox: it does not flip on its own.
                let on = !check_state.get();
                check_state.set(on);
                let _ = check_tx.send(Action::ToggleGroup(check_id.clone(), on));
            }),
        )
        .child(site_badge(
            crate::assets::site_logo(&site.icon_key),
            signal(site.initial.clone()),
            theme::from_hex(site.tile_hex),
        ))
        .child(
            Element::col()
                .weight(1.0)
                .cross(Align::Start)
                .spacing(2)
                .child(
                    Element::label(site.name.clone())
                        .font_size(13.0)
                        .font_weight(500)
                        .fg(if enabled { theme::TEXT } else { theme::TEXT_SOFT }),
                )
                .child(
                    Element::label(site.summary.clone())
                        .font_size(11.5)
                        .fg(theme::from_hex(site.summary_hex))
                        .truncate(Truncate::End),
                ),
        );

    if !site.url.is_empty() {
        let url = site.url.clone();
        let url_tx = tx.clone();
        header = header.child(
            Element::col()
                .width(42)
                .cross(Align::Center)
                .child(text_button("访问", false).on_click(move |_| {
                    let _ = url_tx.send(Action::OpenSite(url.clone()));
                })),
        );
    }

    header = header.child(
        Element::col()
            .width(10)
            .cross(Align::Center)
            .child(chevron(signal(open))),
    );

    let row_tx = tx.clone();
    let row_id = site.id.clone();
    let mut row = Element::col()
        .width_match()
        .bg(if open { theme::TOOLBAR_BG } else { theme::CARD_BG })
        .clickable()
        .on_click(move |_| {
            let _ = row_tx.send(Action::ToggleOpen(row_id.clone()));
        })
        .child(header);

    if !site.first {
        row = row.child(
            Element::row()
                .width_match()
                .height(1)
                .padding_xy(78, 0)
                .child(Element::leaf().weight(1.0).height(1).bg(theme::BORDER_SOFT)),
        );
    }

    if open && !site.domains.is_empty() {
        let mut domains = Element::col().width_match();
        for d in &site.domains {
            domains = domains.child(
                Element::row()
                    .width_match()
                    .height(26)
                    .padding_xy(58, 0)
                    .cross(Align::Center)
                    .spacing(10)
                    .child(
                        Element::label(d.host.clone())
                            .weight(1.0)
                            .font_size(11.5)
                            .font_family(theme::mono_font())
                            .fg(theme::TEXT_BODY)
                            .truncate(Truncate::End),
                    )
                    .child(
                        Element::label(d.status.clone())
                            .width(42)
                            .font_size(11.5)
                            .fg(theme::from_hex(d.status_hex))
                            .text_align(Align::End),
                    )
                    .child(
                        Element::label(d.latency.clone())
                            .width(54)
                            .font_size(11.5)
                            .font_family(theme::mono_font())
                            .fg(theme::TEXT_SOFT)
                            .text_align(Align::End),
                    ),
            );
        }
        row = row.child(
            Element::col()
                .width_match()
                .child(Element::leaf().height(1).bg(theme::BORDER_SOFT))
                .child(domains),
        );
    }
    row
}

fn sites_header(s: UiSignals, tx: Sender<Action>) -> Element {
    let probe_tx = tx.clone();
    let add_tx = tx.clone();
    // 全选 ⇄ 取消全选: the boolean is written by apply_snapshot so the label
    // follows the real site list instead of comparing formatted counters.
    let all_label =
        s.select_all.map(|all| if *all { "取消全选" } else { "全选" }.to_string());
    let select_tx = tx;
    let select_state = s.select_all;
    Element::row()
        .width_match()
        .height(34)
        .padding_xy(2, 0)
        .cross(Align::Center)
        .spacing(8)
        .child(
            Element::label("加速站点")
                .font_size(15.0)
                .font_weight(500)
                .fg(theme::TEXT)
                .weight(1.0),
        )
        .child(
            common::ghost_button("检测选中").on_click(move |_| {
                let _ = probe_tx.send(Action::ProbeSelected);
            }),
        )
        .child(
            common::ghost_button_signal(all_label).on_click(move |_| {
                let all = select_state.get();
                let _ = select_tx.send(Action::SelectAll(!all));
            }),
        )
        .child(
            Element::button("添加站点")
                .width(88)
                .height(30)
                .corner(5.0)
                .font_size(12.5)
                .on_click(move |_| {
                    let _ = add_tx.send(Action::OpenEditor(String::new()));
                }),
        )
}

// -- page ---------------------------------------------------------------------

fn toolbar(s: UiSignals, tx: Sender<Action>) -> Element {
    let gear_tx = tx;
    let dot = s.update_available;
    Element::row()
        .width_match()
        .height(44)
        .padding_edges(Insets {
            left: 16,
            right: 10,
            top: 0,
            bottom: 0,
        })
        .cross(Align::Center)
        .spacing(9)
        .bg(theme::TOOLBAR_BG)
        .child(
            Element::label("hakimi")
                .font_size(14.0)
                .font_weight(500)
                .fg(theme::TEXT)
                .weight(1.0),
        )
        .child(
            Element::stack()
                .size(30, 28)
                .clickable()
                .on_click(move |_| {
                    let _ = gear_tx.send(Action::SetPage(1));
                })
                .child(common::settings_icon().align(Align::Center))
                .child(
                    Element::leaf()
                        .size(7, 7)
                        .corner(3.5)
                        .bg(theme::ACCENT)
                        .border(theme::WINDOW_BG, 1)
                        .align_xy(Align::End, Align::Start)
                        .margin_xy(2, 1)
                        .visible_signal(dot),
                ),
        )
        .child(Element::leaf().width(1).height(44).bg(theme::BORDER))
}

/// Build the whole home page (toolbar + sidebar + site list).
pub fn view(s: UiSignals, tx: Sender<Action>) -> Element {
    let list_tx = tx.clone();
    Element::col()
        .fill()
        .bg(theme::WINDOW_BG)
        .child(
            Element::col()
                .width_match()
                .child(toolbar(s, tx.clone()))
                .child(Element::leaf().height(1).bg(theme::BORDER)),
        )
        .child(
            Element::row()
                .weight(1.0)
                .height_match()
                .child(sidebar(s, tx.clone()))
                .child(
                    Element::col()
                        .weight(1.0)
                        .height_match()
                        .padding(18)
                        .spacing(12)
                        .child(sites_header(s, tx.clone()))
                        .child(
                            Element::scroll()
                                .weight(1.0)
                                .child(
                                    card(Element::list_signal(
                                        s.sites,
                                        |site: &SiteData| site.id.clone(),
                                        move |site| site_row(site, list_tx.clone()),
                                    ))
                                    .width_match(),
                                ),
                        ),
                ),
        )
}
