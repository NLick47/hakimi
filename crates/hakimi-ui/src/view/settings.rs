//! Settings page: four sections (常规 / 网络 / 下载 / 数据与更新).
//! Port of the `page == 1` tree in app.slint. Text fields bind to draft
//! signals and commit through `Action::SaveString` on Enter/focus loss; the
//! field that owns `cfg-error-key` gets the red border.

use windui::prelude::*;

use crate::app_state::{Action, UiSignals};
use crate::model::SiteData;
use crate::theme;
use crate::view::common::{
    self, card, choice_pill, pill_button, pill_button_danger, row_line, site_badge, toggle_row,
};

const SECTIONS: [&str; 4] = ["常规", "网络", "下载", "数据与更新"];
const SECTION_SUBTITLES: [&str; 4] = [
    "管理站点、证书和启动行为",
    "设置监听端口、加密 DNS、中继与远程目录",
    "GitHub 资产的镜像与并发下载",
    "打开数据目录与检查更新",
];

/// One invalid-flag signal per settings key, shared by the section builders.
fn invalid_for(s: &UiSignals, key: &'static str) -> Signal<bool> {
    let error_key = s.cfg_error_key;
    error_key.map(move |current| current == key)
}

fn field(
    s: &UiSignals,
    key: &'static str,
    value: Signal<String>,
    placeholder: &'static str,
    tx: Sender<Action>,
) -> Element {
    common::inline_field(value, placeholder, invalid_for(s, key), tx, key)
}

/// `FieldRow` with the page-wide 132px label column; the input fills the rest.
fn field_row_fill(
    s: &UiSignals,
    label: &'static str,
    hint: &'static str,
    key: &'static str,
    value: Signal<String>,
    placeholder: &'static str,
    tx: Sender<Action>,
) -> Element {
    let input = field(s, key, value, placeholder, tx).weight(1.0);
    common::field_row(label, hint, input, 132)
}

// -- section nav ---------------------------------------------------------------

fn section_nav(s: UiSignals, tx: Sender<Action>) -> Element {
    let mut nav = Element::col()
        .width(154)
        .height_match()
        .spacing(4)
        .child(
            Element::label("偏好设置")
                .font_size(11.0)
                .fg(theme::TEXT_CAPTION)
                .height(20)
                .padding_xy(10, 0),
        )
        .child(Element::leaf().height(4));
    for (i, title) in SECTIONS.iter().enumerate() {
        let tx_click = tx.clone();
        let selected = s.settings_section.map(move |sec| *sec == i as i32);
        let not_selected = s.settings_section.map(move |sec| *sec != i as i32);
        let badge = s.update_available;
        let is_updates = i == 3;
        let row = Element::row()
            .width_match()
            .height(34)
            .cross(Align::Center)
            .padding_xy(10, 0)
            .corner(5.0)
            .clickable()
            .bg_when(move || {
                if selected.get() {
                    theme::ACCENT_TINT_BG
                } else {
                    Color::TRANSPARENT
                }
            })
            .on_click(move |_| {
                let _ = tx_click.send(Action::SetSection(i as i32));
            })
            .child(
                Element::label(*title)
                    .font_size(12.5)
                    .font_weight(500)
                    .fg(theme::TEXT_NAV_ACTIVE)
                    .weight(1.0)
                    .visible_when(move || selected.get()),
            )
            .child(
                Element::label(*title)
                    .font_size(12.5)
                    .fg(theme::TEXT_NAV)
                    .weight(1.0)
                    .visible_when(move || not_selected.get()),
            );
        let row = if is_updates {
            row.child(
                Element::stack()
                    .size(42, 18)
                    .corner(4.0)
                    .bg(theme::ACCENT_TINT_BG)
                    .visible_signal(badge)
                    .child(
                        Element::label("有新版")
                            .font_size(10.0)
                            .fg(theme::ACCENT)
                            .align(Align::Center),
                    ),
            )
        } else {
            row
        };
        nav = nav.child(row);
    }
    nav.child(Element::leaf().weight(1.0).height(0))
}

// -- section: 常规 ---------------------------------------------------------------

fn site_management_row(s: UiSignals, tx: Sender<Action>) -> Element {
    let s = s;
    let head_tx = tx.clone();
    let add_tx = tx.clone();
    let open = s.sites_expanded;
    let open_head = s.sites_expanded;
    let head = Element::row()
        .width_match()
        .height(52)
        .padding_xy(16, 0)
        .cross(Align::Center)
        .spacing(8)
        .clickable()
        .on_click(move |_| {
            let now = open_head.get();
            open_head.set(!now);
        })
        .child(
            Element::label("站点管理")
                .font_size(13.5)
                .fg(theme::TEXT_BODY)
                .weight(1.0),
        )
        .child(
            Element::label_signal(s.sites_summary)
                .font_size(12.0)
                .fg(theme::TEXT_SOFT),
        )
        .child(
            Element::button("+ 添加站点")
                .height(28)
                .min_width(86)
                .corner(5.0)
                .font_size(12.0)
                .on_click(move |_| {
                    let _ = add_tx.send(Action::OpenEditor(String::new()));
                }),
        )
        .child(common::chevron(open));
    let expanded = Element::col()
        .width_match()
        .visible_when(move || s.sites_expanded.get())
        .child(inset_line())
        .child(Element::list_signal(
            s.sites,
            |site| site.id.clone(),
            move |site| management_site_row(site, head_tx.clone()),
        ))
        .child(hidden_sites_section(s, tx));
    Element::col().width_match().child(head).child(expanded)
}

/// The collapsed block of hidden sites under the visible list.
fn hidden_sites_section(s: UiSignals, tx: Sender<Action>) -> Element {
    let count_signal = s.sites_hidden_count;
    let shown = s.sites_hidden_shown;
    let checkbox = s.sites_hidden_shown;
    let list_tx = tx.clone();
    let toggle_tx = tx;
    let head = Element::row()
        .width_match()
        .height(40)
        .padding_xy(16, 0)
        .cross(Align::Center)
        .spacing(8)
        .visible_when(move || count_signal.get() > 0)
        .child(
            Element::label("已隐藏（未加速）")
                .font_size(12.5)
                .fg(theme::TEXT_MUTED)
                .weight(1.0),
        )
        .child(Element::label("显示").font_size(12.0).fg(theme::TEXT_SOFT))
        .child(Element::checkbox("", checkbox).on_toggle(move |_| {
            let _ = toggle_tx.send(Action::ToggleShowHidden);
        }));
    let list = Element::col()
        .width_match()
        .visible_when(move || shown.get() && count_signal.get() > 0)
        .child(inset_line())
        .child(Element::list_signal(
            s.sites_hidden,
            |site| site.id.clone(),
            move |site| hidden_site_row(site, list_tx.clone()),
        ));
    Element::col().width_match().child(head).child(list)
}

/// A hidden site row: muted, opens the editor, right-click offers unhide.
fn hidden_site_row(site: SiteData, tx: Sender<Action>) -> Element {
    let id = site.id.clone();
    let row_tx = tx.clone();
    let menu_tx = tx.clone();
    let menu_id = site.id.clone();
    let menu_builtin = crate::model::is_shipped(&site);
    let row = Element::row()
        .width_match()
        .height(48)
        .padding_xy(16, 0)
        .cross(Align::Center)
        .spacing(10)
        .clickable()
        .on_click(move |_| {
            let _ = row_tx.send(Action::OpenEditor(id.clone()));
        })
        .on_context_menu(move || {
            super::site_menu(menu_tx.clone(), menu_id.clone(), menu_builtin, true, false)
        })
        .child(site_badge(
            crate::assets::site_logo(&site.icon_key),
            signal(site.initial.clone()),
            theme::from_hex(site.tile_hex),
        ))
        .child(
            Element::col()
                .weight(1.0)
                .cross(Align::Start)
                .spacing(1)
                .child(
                    Element::label(site.name.clone())
                        .font_size(13.5)
                        .font_weight(500)
                        .fg(theme::TEXT_SOFT),
                )
                .child(
                    Element::label(site.summary.clone())
                        .font_size(11.5)
                        .fg(theme::TEXT_MUTED)
                        .truncate(Truncate::End),
                ),
        )
        .child(common::chevron_right_icon());
    let line = inset_line();
    Element::col().width_match().child(line).child(row)
}

fn management_site_row(site: SiteData, tx: Sender<Action>) -> Element {
    let id = site.id.clone();
    let row_tx = tx.clone();
    let menu_tx = tx.clone();
    let menu_id = site.id.clone();
    let menu_builtin = crate::model::is_shipped(&site);
    let menu_hidden = site.hidden;
    let menu_enabled = site.enabled;
    let row = Element::row()
        .width_match()
        .height(48)
        .padding_xy(16, 0)
        .cross(Align::Center)
        .spacing(10)
        .clickable()
        .on_click(move |_| {
            let _ = row_tx.send(Action::OpenEditor(id.clone()));
        })
        .on_context_menu(move || {
            super::site_menu(
                menu_tx.clone(),
                menu_id.clone(),
                menu_builtin,
                menu_hidden,
                menu_enabled,
            )
        })
        .child(site_badge(
            crate::assets::site_logo(&site.icon_key),
            signal(site.initial.clone()),
            theme::from_hex(site.tile_hex),
        ))
        .child(
            Element::col()
                .weight(1.0)
                .cross(Align::Start)
                .spacing(1)
                .child(
                    Element::label(site.name.clone())
                        .font_size(13.5)
                        .font_weight(500)
                        .fg(if site.enabled {
                            theme::TEXT
                        } else {
                            theme::TEXT_SOFT
                        }),
                )
                .child(
                    Element::label(site.summary.clone())
                        .font_size(11.5)
                        .fg(theme::from_hex(site.summary_hex))
                        .truncate(Truncate::End),
                ),
        )
        .child(common::chevron_right_icon());
    if !site.first {
        let line = inset_line();
        return Element::col().width_match().child(line).child(row);
    }
    row
}

fn inset_line() -> Element {
    Element::row()
        .width_match()
        .height(1)
        .padding_xy(16, 0)
        .child(Element::leaf().weight(1.0).height(1).bg(theme::BORDER_SOFT))
}

fn local_ca_card(s: UiSignals, tx: Sender<Action>) -> Element {
    let status_role = s.ca_status_tone.map(|tone| match *tone {
        1 => Role::Success,
        2 => Role::Danger,
        _ => Role::TextMuted,
    });
    let installed_for_remove = s.ca_installed;
    let installed_for_click = s.ca_installed;
    let remove_tx = tx.clone();
    let main_tx = tx;
    card(
        Element::col()
            .width_match()
            .child(
                Element::row()
                    .width_match()
                    .height(58)
                    .padding_xy(16, 0)
                    .cross(Align::Center)
                    .spacing(12)
                    .child(
                        Element::label("本地 CA")
                            .width(112)
                            .font_size(13.0)
                            .fg(theme::TEXT),
                    )
                    .child(
                        Element::col()
                            .weight(1.0)
                            .spacing(2)
                            .child(
                                Element::label_signal(s.ca_status)
                                    .font_size(12.0)
                                    .max_lines(1)
                                    .truncate(Truncate::End)
                                    .fg_role_signal(status_role),
                            )
                            .child(
                                Element::label_signal(s.ca_status_sub)
                                    .font_size(11.0)
                                    .max_lines(1)
                                    .fg(theme::TEXT_MUTED)
                                    .truncate(Truncate::End),
                            ),
                    )
                    .child(
                        Element::row()
                            .height(28)
                            .spacing(8)
                            .child(
                                pill_button_danger("移除")
                                    .visible_when(move || installed_for_remove.get())
                                    .on_click(move |_| {
                                        let _ = remove_tx.send(Action::CaAction(2));
                                    }),
                            )
                            .child(
                                Element::button(s.ca_button)
                                    .height(28)
                                    .min_width(64)
                                    .corner(5.0)
                                    .font_size(12.0)
                                    .outline()
                                    .on_click(move |_| {
                                        let install = installed_for_click.get();
                                        let _ = main_tx.send(Action::CaAction(if install {
                                            3
                                        } else {
                                            1
                                        }));
                                    }),
                            ),
                    ),
            )
            .child(ca_action_error_row(s)),
    )
}

fn ca_action_error_row(s: UiSignals) -> Element {
    let error = s.ca_action_error;
    let present = s.ca_action_error;
    Element::col()
        .width_match()
        .visible_signal(present.map(|e| !e.is_empty()))
        .child(inset_line())
        .child(
            Element::row()
                .width_match()
                .padding_edges(Insets {
                    left: 16,
                    right: 14,
                    top: 8,
                    bottom: 8,
                })
                .child(Element::label_signal(error).font_size(11.5).fg(theme::WARN)),
        )
}

fn startup_card(s: UiSignals, tx: Sender<Action>) -> Element {
    let tx1 = tx.clone();
    let tx2 = tx.clone();
    let tx3 = tx;
    card(
        Element::col()
            .width_match()
            .child(toggle_row(
                "开机自启",
                "登录系统后自动在托盘运行，不显示窗口",
                s.startup_error,
                s.cfg_auto_start,
                move |_, value| {
                    let _ = tx1.send(Action::SaveBool("advanced.startup.autoStart".into(), value));
                },
            ))
            .child(row_line())
            .child(toggle_row(
                "静默启动",
                "启动时不显示窗口，只保留托盘图标",
                signal(String::new()),
                s.cfg_start_hidden,
                move |_, value| {
                    let _ = tx2.send(Action::SaveBool(
                        "advanced.startup.startHidden".into(),
                        value,
                    ));
                },
            ))
            .child(row_line())
            .child(toggle_row(
                "启动后自动加速",
                "启动时自动开启加速并接管系统代理",
                signal(String::new()),
                s.cfg_auto_connect,
                move |_, value| {
                    let _ = tx3.send(Action::SaveBool(
                        "advanced.startup.autoConnect".into(),
                        value,
                    ));
                },
            )),
    )
}

fn section_general(s: UiSignals, tx: Sender<Action>) -> Element {
    Element::col()
        .width_match()
        .spacing(8)
        .child(card(site_management_row(s, tx.clone())))
        .child(local_ca_card(s, tx.clone()))
        .child(startup_card(s, tx))
}

// -- section: 网络 ---------------------------------------------------------------

fn subhead(title: &'static str) -> Element {
    Element::label(title)
        .font_size(13.0)
        .font_weight(500)
        .fg(theme::TEXT_NAV)
}

fn section_network(s: UiSignals, tx: Sender<Action>) -> Element {
    let ip_tx = tx.clone();
    let doh_tx = tx.clone();
    let reset_tx = tx.clone();
    Element::col()
        .width_match()
        .spacing(12)
        .child(subhead("加密连接"))
        .child(
            card(
                Element::col()
                    .width_match()
                    .child(field_row_fill(
                        &s,
                        "监听端口",
                        "重启后生效",
                        "proxy.port",
                        s.cfg_proxy_port,
                        "8443",
                        tx.clone(),
                    ))
                    .child(field_row_fill(
                        &s,
                        "首选 DoH 端点",
                        "慢时并行补查",
                        "doh.primary",
                        s.cfg_doh_primary,
                        "https://…",
                        tx.clone(),
                    ))
                    .child(field_row_fill(
                        &s,
                        "次选 DoH 端点",
                        "并行补查后合并",
                        "doh.fallback",
                        s.cfg_doh_fallback,
                        "https://…",
                        tx.clone(),
                    )),
            )
            .width_match(),
        )
        .child(subhead("连接复用"))
        .child(
            card(field_row_fill(
                &s,
                "独立连接的站点",
                "逗号分隔，留空则关闭",
                "advanced.http1Hosts",
                s.cfg_http1_hosts,
                "i.pximg.net, s.pximg.net",
                tx.clone(),
            ))
            .width_match(),
        )
        .child(subhead("图片中转"))
        .child(
            card(
                Element::col()
                    .width_match()
                    .child(image_relay_toggle(
                        &s,
                        "启用中转",
                        "图片改走 Cloudflare 中转，网页与 API 不受影响",
                        "advanced.imageRelays.pixiv.enabled",
                        s.cfg_image_relay_enabled,
                        tx.clone(),
                    ))
                    .child(field_row_fill(
                        &s,
                        "中转地址",
                        "路径拼在该前缀后",
                        "advanced.imageRelays.pixiv.base",
                        s.cfg_image_relay_base,
                        "",
                        tx.clone(),
                    ))
                    .child(field_row_fill(
                        &s,
                        "适用域名",
                        "逗号分隔",
                        "advanced.imageRelays.pixiv.hosts",
                        s.cfg_image_relay_hosts,
                        "i.pximg.net",
                        tx.clone(),
                    ))
                    .child(field_row_fill(
                        &s,
                        "只匹配路径",
                        "逗号分隔；留空=整站",
                        "advanced.imageRelays.pixiv.paths",
                        s.cfg_image_relay_paths,
                        "/img-original/",
                        tx.clone(),
                    ))
                    .child(field_row_fill(
                        &s,
                        "请求 UA",
                        "留空则不覆盖",
                        "advanced.imageRelays.pixiv.userAgent",
                        s.cfg_image_relay_ua,
                        "留空不覆盖",
                        tx.clone(),
                    ))
                    .child(image_relay_toggle(
                        &s,
                        "失败回落直连",
                        "被拦截或超时后自动改走源站，代价是慢",
                        "advanced.imageRelays.pixiv.fallbackDirect",
                        s.cfg_image_relay_fallback,
                        tx.clone(),
                    )),
            )
            .width_match(),
        )
        .child(subhead("隧道中继"))
        .child(
            card(
                Element::col()
                    .width_match()
                    .child(relay_toggle(
                        &s,
                        "本地 TCP 中继",
                        "给 cloudflared 这类不走 HTTP 代理的客户端用；只转发字节，不终止 TLS",
                        "advanced.relay.enabled",
                        s.cfg_relay_enabled,
                        tx.clone(),
                    ))
                    .child(field_row_fill(
                        &s,
                        "监听地址",
                        "如 127.0.0.1:17844",
                        "advanced.relay.listen",
                        s.cfg_relay_listen,
                        "127.0.0.1:17844",
                        tx.clone(),
                    ))
                    .child(field_row_fill(
                        &s,
                        "上游目标",
                        "端口默认 7844",
                        "advanced.relay.target",
                        s.cfg_relay_target,
                        "region1.v2.argotunnel.com:7844",
                        tx.clone(),
                    )),
            )
            .width_match(),
        )
        .child(subhead("远程目录"))
        .child(
            card(
                Element::col()
                    .width_match()
                    .child(field_row_fill(
                        &s,
                        "IP 目录",
                        "留空则停用远程 IP",
                        "catalogs.ip",
                        s.cfg_catalog_ip,
                        "https://…",
                        ip_tx,
                    ))
                    .child(field_row_fill(
                        &s,
                        "DoH 目录",
                        "留空则停用远程 DoH 列表",
                        "catalogs.doh",
                        s.cfg_catalog_doh,
                        "https://…",
                        doh_tx,
                    ))
                    .child(row_line())
                    .child(
                        Element::row()
                            .width_match()
                            .height(44)
                            .padding_xy(16, 0)
                            .cross(Align::Center)
                            .child(Element::flex_spacer())
                            .child(pill_button("还原默认地址").on_click(move |_| {
                                let _ = reset_tx.send(Action::ResetCatalogUrls);
                            })),
                    ),
            )
            .width_match(),
        )
}

fn image_relay_toggle(
    _s: &UiSignals,
    label: &'static str,
    hint: &'static str,
    key: &'static str,
    value: Signal<bool>,
    tx: Sender<Action>,
) -> Element {
    toggle_row(label, hint, signal(String::new()), value, move |_, v| {
        let _ = tx.send(Action::SaveBool(key.to_string(), v));
    })
}

fn relay_toggle(
    _s: &UiSignals,
    label: &'static str,
    hint: &'static str,
    key: &'static str,
    value: Signal<bool>,
    tx: Sender<Action>,
) -> Element {
    toggle_row(label, hint, signal(String::new()), value, move |_, v| {
        let _ = tx.send(Action::SaveBool(key.to_string(), v));
    })
}

// -- section: 下载 -----------------------------------------------------------

const SEGMENT_LABELS: [&str; 6] = ["2", "3", "4", "6", "8", "12"];

/// The engine tiers the chosen ceiling by route and size; name the scenarios
/// where it lands lower. Values the pill already shows stay unsaid.
pub(crate) fn concurrency_caption(value: i32) -> String {
    let mut parts = Vec::new();
    if value.min(12) < value {
        parts.push(format!("大文件 {}", value.min(12)));
    }
    if value.min(8) < value {
        parts.push(format!("小文件 {}", value.min(8)));
    }
    if value.min(6) < value {
        parts.push(format!("镜像 {}", value.min(6)));
    }
    parts.join(" · ")
}

fn threads_row(s: UiSignals, tx: Sender<Action>) -> Element {
    let mut pills = Element::row().spacing(6);
    for label in SEGMENT_LABELS.iter() {
        let n: i32 = label.parse().unwrap();
        let active = s.cfg_download_segments.map(move |v| *v == n);
        let tx_n = tx.clone();
        pills = pills.child(choice_pill(label, active).width(44).on_click(move |_| {
            let _ = tx_n.send(Action::SaveString(
                "advanced.download.segments".into(),
                n.to_string(),
            ));
        }));
    }
    let caption = s.cfg_download_segments.map(|v| concurrency_caption(*v));
    let caption_visible = caption.map(|text| !text.is_empty());
    Element::col()
        .width_match()
        .child(
            Element::row()
                .width_match()
                .height(52)
                .padding_xy(16, 0)
                .cross(Align::Center)
                .spacing(12)
                .child(
                    Element::label("下载并发")
                        .width(132)
                        .font_size(13.0)
                        .fg(theme::TEXT),
                )
                .child(Element::flex_spacer())
                .child(pills),
        )
        .child(
            Element::col()
                .width_match()
                .visible_signal(caption_visible)
                .child(
                    Element::row()
                        .width_match()
                        .height(26)
                        .padding_xy(16, 2)
                        .cross(Align::Center)
                        .child(Element::flex_spacer())
                        .child(
                            Element::label_signal(caption)
                                .font_size(12.0)
                                .fg(theme::TEXT_MUTED),
                        ),
                ),
        )
}

fn section_downloads(s: UiSignals, tx: Sender<Action>) -> Element {
    let mirror_tx = tx.clone();
    let mirror_toggle_tx = mirror_tx.clone();
    let enable_tx = tx;
    Element::col().width_match().child(
        card(
            Element::col()
                .width_match()
                .child(toggle_row(
                    "启用分段下载",
                    "大文件并行拉取，失败自动回落单流",
                    signal(String::new()),
                    s.cfg_download_enabled,
                    move |_, v| {
                        let _ =
                            enable_tx.send(Action::SaveBool("advanced.download.enabled".into(), v));
                    },
                ))
                .child(row_line())
                .child(threads_row(s, mirror_tx.clone()))
                .child(row_line())
                .child(toggle_row(
                    "GitHub 镜像加速",
                    "release 资产与源码包走第三方镜像",
                    signal(String::new()),
                    s.cfg_download_mirror,
                    move |_, v| {
                        let _ = mirror_toggle_tx
                            .send(Action::SaveBool("advanced.download.mirrorSource".into(), v));
                    },
                ))
                .child(field_row_fill(
                    &s,
                    "镜像列表",
                    "留空则停用",
                    "advanced.download.mirrorSource",
                    s.cfg_mirror_source,
                    "https://…",
                    mirror_tx,
                )),
        )
        .width_match(),
    )
}

// -- section: 数据与更新 ------------------------------------------------------------

fn data_row(label: &'static str, middle: Element, button: Element, button_width: i32) -> Element {
    Element::row()
        .width_match()
        .height(52)
        .padding_xy(16, 0)
        .cross(Align::Center)
        .spacing(12)
        .child(
            Element::label(label)
                .width(112)
                .font_size(13.0)
                .fg(theme::TEXT),
        )
        .child(middle)
        .child(
            Element::col()
                .width(button_width)
                .cross(Align::Center)
                .child(button),
        )
}

fn section_data(s: UiSignals, tx: Sender<Action>) -> Element {
    let open_tx = tx.clone();
    let update_tx = tx.clone();
    let status_role = s.update_available.map(|available| {
        if *available {
            Role::AccentText
        } else {
            Role::TextMuted
        }
    });
    let button_state = s.update_available;
    let button_checking = s.update_checking;
    card(
        Element::col()
            .width_match()
            .child(data_row(
                "数据目录",
                Element::label_signal(s.cfg_data_dir)
                    .weight(1.0)
                    .font_size(11.5)
                    .font_family(theme::mono_font())
                    .fg(theme::TEXT_SOFT)
                    .truncate(Truncate::End),
                pill_button("打开").width(64).on_click(move |_| {
                    let _ = open_tx.send(Action::OpenDataDir);
                }),
                64,
            ))
            .child(row_line())
            .child(data_row(
                "检查更新",
                Element::col()
                    .weight(1.0)
                    .spacing(2)
                    .child(
                        Element::label_signal(s.update_status)
                            .font_size(12.0)
                            .fg_role_signal(status_role)
                            .truncate(Truncate::End),
                    )
                    .child(
                        Element::label(format!(
                            "客户端版本 {} · Rust Core {}",
                            s.cfg_version.get(),
                            s.cfg_core_version.get()
                        ))
                        .font_size(10.5)
                        .fg(theme::TEXT_SOFT)
                        .truncate(Truncate::End),
                    ),
                Element::button(s.update_button)
                    .height(28)
                    .min_width(64)
                    .corner(5.0)
                    .font_size(12.0)
                    .outline()
                    .on_click(move |_| {
                        if button_state.get() {
                            let _ = update_tx.send(Action::OpenUpdate);
                        } else if !button_checking.get() {
                            let _ = update_tx.send(Action::CheckUpdate);
                        }
                    }),
                72,
            )),
    )
    .width_match()
}

// -- page ---------------------------------------------------------------------

fn section_title_block(s: UiSignals) -> Element {
    let section = s.settings_section;
    Element::col()
        .width_match()
        .spacing(6)
        .child(
            Element::label_signal(section.map(|sec| {
                SECTIONS
                    .get(*sec as usize)
                    .map(|title| title.to_string())
                    .unwrap_or_default()
            }))
            .font_size(18.0)
            .font_weight(500)
            .fg(theme::TEXT),
        )
        .child(
            Element::label_signal(section.map(|sec| {
                SECTION_SUBTITLES
                    .get(*sec as usize)
                    .map(|text| text.to_string())
                    .unwrap_or_default()
            }))
            .font_size(12.0)
            .fg(theme::TEXT_SOFT),
        )
}

fn error_banner(s: UiSignals) -> Element {
    let error = s.cfg_error;
    let present = s.cfg_error;
    Element::stack()
        .width_match()
        .height(36)
        .corner(6.0)
        .bg(theme::DANGER_NOTICE_BG)
        .border(theme::DANGER_NOTICE_BORDER, 1)
        .visible_signal(present.map(|e| !e.is_empty()))
        .child(
            Element::label_signal(error)
                .font_size(11.5)
                .fg(theme::DANGER)
                .truncate(Truncate::End)
                .margin_xy(12, 0)
                .align(Align::Center),
        )
}

pub fn view(s: UiSignals, tx: Sender<Action>) -> Element {
    let back_tx = tx.clone();
    let bar = Element::row()
        .width_match()
        .height(44)
        .padding_xy(10, 0)
        .cross(Align::Center)
        .spacing(9)
        .bg(theme::TOOLBAR_BG)
        .child(
            Element::stack()
                .size(28, 26)
                .clickable()
                .on_click(move |_| {
                    let _ = back_tx.send(Action::SetPage(0));
                })
                .child(common::back_icon().align(Align::Center)),
        )
        .child(
            Element::label("设置")
                .font_size(14.0)
                .font_weight(500)
                .fg(theme::TEXT)
                .weight(1.0),
        )
        .child(Element::leaf().width(28).height(26));

    let section = s.settings_section;
    let sec0 = section;
    let sec1 = section;
    let sec2 = section;
    let sec3 = section;
    let pages = Element::stack()
        .fill()
        .child(section_general(s, tx.clone()).visible_when(move || sec0.get() == 0))
        .child(section_network(s, tx.clone()).visible_when(move || sec1.get() == 1))
        .child(section_downloads(s, tx.clone()).visible_when(move || sec2.get() == 2))
        .child(section_data(s, tx.clone()).visible_when(move || sec3.get() == 3));

    Element::col()
        .fill()
        .bg(theme::WINDOW_BG)
        .child(
            Element::col()
                .width_match()
                .child(bar)
                .child(Element::leaf().height(1).bg(theme::BORDER)),
        )
        .child(
            Element::row()
                .weight(1.0)
                .height_match()
                .padding_edges(Insets {
                    left: 18,
                    right: 18,
                    top: 14,
                    bottom: 14,
                })
                .spacing(18)
                .child(section_nav(s, tx.clone()))
                .child(
                    Element::scroll().weight(1.0).child(
                        Element::col()
                            .width_match()
                            .spacing(12)
                            .child(section_title_block(s))
                            .child(Element::leaf().height(4))
                            .child(pages)
                            .child(error_banner(s)),
                    ),
                ),
        )
}
