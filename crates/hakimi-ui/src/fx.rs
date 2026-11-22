use windui::anim::{motion_level, Easing, MotionLevel, Spring, Transition};
use windui::prelude::*;

use crate::app_state::{Action, UiSignals};
use crate::theme;

const KNOB_OFF_X: i32 = 3;
const KNOB_ON_X: i32 = 20;
const STAR_CX: i32 = 20;
const STAR_CY: i32 = 12;

const NIGHT_TOP: (u8, u8, u8) = (13, 19, 31);
const NIGHT_BOTTOM: (u8, u8, u8) = (8, 13, 22);
const NIGHT_EDGE: (u8, u8, u8) = (155, 216, 255);
const NIGHT_GLOW: (u8, u8, u8) = (96, 190, 170);
const STAR_WHITE: (u8, u8, u8) = (234, 242, 255);
const STAR_CYAN: (u8, u8, u8) = (155, 216, 255);
const GAL_STAR: (u8, u8, u8) = (244, 247, 255);
const AURORA_GREEN: (u8, u8, u8) = (61, 220, 151);
const AURORA_TEAL: (u8, u8, u8) = (96, 190, 170);
const RAY: (u8, u8, u8) = (255, 250, 230);
const CORE: (u8, u8, u8) = (255, 253, 246);

fn rgba(c: (u8, u8, u8), a: i32) -> Color {
    Color::rgba(c.0, c.1, c.2, a.clamp(0, 255) as u8)
}

fn faded(rgb: (u8, u8, u8), base: i32, fade: i32) -> Color {
    rgba(rgb, base * fade / 100)
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) struct SwitchFx {
    pub knob_x: i32,
    pub blend: i32,
    pub star: i32,
    pub wisp: i32,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) struct DotFx {
    pub on: bool,
    pub spread: i32,
    pub alpha: i32,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) struct Meteor {
    pub x: i32,
    pub y: i32,
    pub ux: i32,
    pub uy: i32,
    pub fade: i32,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) struct VeilFx {
    pub alpha: i32,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) struct TwinkleFx {
    pub phase: i32,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) struct AuroraFx {
    pub phase: i32,
    pub sway: i32,
}

struct MeteorState {
    spawn: u64,
    x0: f32,
    y0: f32,
    vx: f32,
    vy: f32,
    life_ms: u32,
    pinned_fade: Option<i32>,
}

pub(crate) struct Engine {
    knob: Transition<f32>,
    blend: Transition<f32>,
    veil: Transition<f32>,
    running: bool,
    next_spawn: u64,
    meteors: Vec<MeteorState>,
    last_switch: Option<SwitchFx>,
    last_dot: Option<DotFx>,
    last_veil: Option<VeilFx>,
    last_twinkle: Option<TwinkleFx>,
    last_aurora: Option<AuroraFx>,
    last_meteors: Vec<Meteor>,
    rng: u64,
}

impl Engine {
    pub(crate) fn new() -> Self {
        Self {
            knob: Transition::new(KNOB_OFF_X as f32).movement(),
            blend: Transition::new(0.0),
            veil: Transition::new(0.0),
            running: false,
            next_spawn: 0,
            meteors: Vec::new(),
            last_switch: None,
            last_dot: None,
            last_veil: None,
            last_twinkle: None,
            last_aurora: None,
            last_meteors: Vec::new(),
            rng: 0x5EED_2026_1122,
        }
    }

    fn rand(&mut self) -> f32 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng >> 11) as f32 / 9_007_199_254_740_992.0
    }

    fn spawn(&mut self, at: u64) -> MeteorState {
        let ang = (20.0 + self.rand() * 140.0).to_radians();
        let (dx, dy) = (ang.cos(), ang.sin());
        let dist = 55.0 + self.rand() * 55.0;
        let hx = 10.0 + self.rand() * 164.0;
        let hy = 10.0 + self.rand() * 38.0;
        MeteorState {
            spawn: at,
            x0: hx - dx * dist,
            y0: hy - dy * dist,
            vx: dx * dist,
            vy: dy * dist,
            life_ms: 1800,
            pinned_fade: None,
        }
    }

    pub(crate) fn tick(&mut self, running: bool, s: &UiSignals) {
        let now = windui::anim::clock_ms();
        let ambient = motion_level() != MotionLevel::Off;
        if running != self.running {
            self.running = running;
            self.knob.retarget_spring(
                if running {
                    KNOB_ON_X as f32
                } else {
                    KNOB_OFF_X as f32
                },
                Spring::SNAPPY,
            );
            self.blend.retarget(
                if running { 100.0 } else { 0.0 },
                260,
                Easing::STANDARD,
            );
            self.veil.retarget(
                if running { 100.0 } else { 0.0 },
                if ambient { 700 } else { 1 },
                Easing::STANDARD,
            );
            if running && ambient {
                let m = self.spawn(now.saturating_sub(260));
                self.meteors.push(m);
                self.next_spawn = now + 3500 + (self.rand() * 4000.0) as u64;
            } else {
                self.meteors.clear();
            }
        }

        if running && ambient && now >= self.next_spawn && self.meteors.len() < 2 {
            let m = self.spawn(now);
            self.meteors.push(m);
            self.next_spawn = now + 3500 + (self.rand() * 4000.0) as u64;
        }
        if !running {
            self.meteors.clear();
        }
        self.meteors
            .retain(|m| now.saturating_sub(m.spawn) < m.life_ms as u64);

        let dot_breath = if running && ambient {
            let t = (now % 2400) as f32 / 2400.0;
            (t * std::f32::consts::TAU).sin() * 0.5 + 0.5
        } else if running {
            0.5
        } else {
            0.0
        };
        let star_breath = if running && ambient {
            let t = (now % 2600) as f32 / 2600.0;
            (t * std::f32::consts::TAU).sin() * 0.5 + 0.5
        } else {
            0.5
        };

        let switch = SwitchFx {
            knob_x: self.knob.animate() as i32,
            blend: self.blend.animate() as i32,
            star: if running {
                (30.0 + 70.0 * star_breath) as i32
            } else {
                0
            },
            wisp: if running && ambient {
                (((now % 14000) * 360 / 14000) / 4 * 4) as i32
            } else {
                0
            },
        };
        let dot = DotFx {
            on: running,
            spread: if running { (6.0 + 5.0 * dot_breath) as i32 } else { 0 },
            alpha: if running {
                (110.0 + 78.0 * dot_breath) as i32
            } else {
                0
            },
        };
        let veil = VeilFx {
            alpha: self.veil.animate() as i32,
        };
        let meteors: Vec<Meteor> = self
            .meteors
            .iter()
            .map(|m| {
                let t = now.saturating_sub(m.spawn) as f32;
                let done = t / m.life_ms as f32;
                let fade = m.pinned_fade.unwrap_or(
                    (100.0 * (t / 450.0).min(1.0) * ((m.life_ms as f32 - t) / 450.0).min(1.0))
                        as i32,
                );
                let len = (m.vx * m.vx + m.vy * m.vy).sqrt().max(0.001);
                Meteor {
                    x: (m.x0 + m.vx * done) as i32,
                    y: (m.y0 + m.vy * done) as i32,
                    ux: (m.vx / len * 256.0) as i32,
                    uy: (m.vy / len * 256.0) as i32,
                    fade: fade as i32,
                }
            })
            .collect();

        if self.last_switch != Some(switch) {
            s.fx_switch.set(vec![switch]);
            self.last_switch = Some(switch);
        }
        if self.last_dot != Some(dot) {
            s.fx_dot.set(vec![dot]);
            self.last_dot = Some(dot);
        }
        if self.last_veil != Some(veil) {
            s.fx_veil.set(vec![veil]);
            self.last_veil = Some(veil);
        }
        if self.last_meteors != meteors {
            s.fx_meteors.set(meteors.clone());
            self.last_meteors = meteors;
        }
        if running && ambient {
            let twinkle = TwinkleFx {
                phase: (((now % 2800) * 360 / 2800) / 8 * 8) as i32,
            };
            if self.last_twinkle != Some(twinkle) {
                s.fx_twinkle.set(vec![twinkle]);
                self.last_twinkle = Some(twinkle);
            }
            let aurora = AuroraFx {
                phase: (((now % 9000) * 360 / 9000) / 3 * 3) as i32,
                sway: (4.0 * (now as f32 * std::f32::consts::TAU / 8500.0).sin()).round() as i32,
            };
            if self.last_aurora != Some(aurora) {
                s.fx_aurora.set(vec![aurora]);
                self.last_aurora = Some(aurora);
            }
        }
    }

    pub(crate) fn shot_running(&mut self, s: &UiSignals) {
        self.running = true;
        self.knob.settle(KNOB_ON_X as f32);
        self.blend.settle(100.0);
        self.veil.settle(100.0);
        self.tick(true, s);
    }

    pub(crate) fn spawn_shot_meteor(&mut self) {
        let ang = 22.0f32.to_radians();
        self.meteors.push(MeteorState {
            spawn: windui::anim::clock_ms(),
            x0: 40.0,
            y0: 6.0,
            vx: ang.cos() * 80.0,
            vy: ang.sin() * 80.0,
            life_ms: 6000,
            pinned_fade: Some(100),
        });
    }
}

struct StarSpec {
    x: i32,
    y: i32,
    size: i32,
    alpha: u8,
    cyan: bool,
    twinkle: bool,
}

fn star_table() -> &'static [StarSpec] {
    static TABLE: std::sync::OnceLock<Vec<StarSpec>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut rng: u64 = 0x5EED_2026_1122;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng >> 11) as f32 / 9_007_199_254_740_992.0
        };
        (0..20)
            .map(|i| {
                let x = 6 + (next() * 168.0) as i32;
                let y = 5 + (next() * 40.0) as i32;
                StarSpec {
                    x,
                    y,
                    size: if i % 4 == 0 { 2 } else { 1 },
                    alpha: (71 + (next() * 128.0) as i32).min(199) as u8,
                    cyan: i % 3 == 0,
                    twinkle: i % 5 == 0,
                }
            })
            .collect()
    })
}

fn galaxy_table() -> &'static [StarSpec] {
    static TABLE: std::sync::OnceLock<Vec<StarSpec>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut rng: u64 = 0xA11E_2026_1122;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng >> 11) as f32 / 9_007_199_254_740_992.0
        };
        (0..30)
            .map(|i| {
                let x = 80 + (next() * 100.0) as i32;
                let spread = (next() + next() - 1.0) * 9.0;
                let y = (46.0 + spread - (x - 80) as f32 * 0.20) as i32;
                StarSpec {
                    x: x.min(180),
                    y: y.clamp(12, 48),
                    size: if i % 5 == 0 { 2 } else { 1 },
                    alpha: (77 + (next() * 128.0) as i32).min(205) as u8,
                    cyan: false,
                    twinkle: i % 6 == 0,
                }
            })
            .collect()
    })
}

fn star_leaf(st: &StarSpec, rgb: (u8, u8, u8), alpha: i32) -> Element {
    let mut leaf = Element::leaf()
        .size(st.size, st.size)
        .corner(st.size as f32 / 2.0)
        .bg(rgba(rgb, alpha))
        .align_xy(Align::Start, Align::Start)
        .margin_xy(st.x, st.y);
    if st.size > 1 {
        leaf = leaf.shadow(Shadow::new(0.0, 0.0, 3.0, rgba(rgb, alpha / 2)));
    }
    leaf
}

fn veil_of(sig: Signal<Vec<VeilFx>>) -> impl Fn() -> f32 + 'static {
    move || {
        let a = sig
            .get()
            .first()
            .map(|v| v.alpha)
            .unwrap_or(0)
            .clamp(0, 100);
        a as f32 / 100.0
    }
}

pub(crate) fn sky_layer(s: UiSignals) -> Element {
    let veil = veil_of(s.fx_veil);
    let mut layer = Element::stack().width_match().height_match();
    for st in star_table().iter().filter(|st| !st.twinkle) {
        let rgb = if st.cyan { STAR_CYAN } else { STAR_WHITE };
        layer = layer.child(star_leaf(st, rgb, st.alpha as i32));
    }
    layer.opacity_when(veil)
}

pub(crate) fn galaxy_layer(s: UiSignals) -> Element {
    let veil = veil_of(s.fx_veil);
    let mut layer = Element::stack().width_match().height_match();
    for (w, h, x, y, rgb, peak) in [
        (122, 18, 62, 28, AURORA_TEAL, 11),
        (92, 12, 92, 30, STAR_CYAN, 14),
        (60, 8, 120, 32, GAL_STAR, 18),
    ] {
        layer = layer.child(
            Element::leaf()
                .size(w, h)
                .corner(h as f32 / 2.0)
                .bg_gradient(Gradient::linear(
                    (0.0, 0.0),
                    (0.0, 1.0),
                    vec![
                        (0.0, rgba(rgb, 0)),
                        (0.5, rgba(rgb, peak)),
                        (1.0, rgba(rgb, 0)),
                    ],
                ))
                .align_xy(Align::Start, Align::Start)
                .margin_xy(x, y),
        );
    }
    for st in galaxy_table().iter().filter(|st| !st.twinkle) {
        layer = layer.child(star_leaf(st, GAL_STAR, st.alpha as i32));
    }
    layer.opacity_when(veil)
}

pub(crate) fn twinkle_layer(s: UiSignals) -> Element {
    Element::host_signal(s.fx_twinkle, |fx: TwinkleFx| {
        let mut layer = Element::stack().fill();
        let factor = 0.2 + 0.8 * (0.5 + 0.5 * (fx.phase as f32).to_radians().sin());
        for st in star_table()
            .iter()
            .chain(galaxy_table())
            .filter(|st| st.twinkle)
        {
            let rgb = if st.cyan { STAR_CYAN } else { GAL_STAR };
            layer = layer.child(star_leaf(st, rgb, (st.alpha as f32 * factor) as i32));
        }
        layer
    })
    .opacity_when(veil_of(s.fx_veil))
}

pub(crate) fn aurora_layer(s: UiSignals) -> Element {
    Element::host_signal(s.fx_aurora, |fx: AuroraFx| {
        let mut layer = Element::stack().fill();
        for (k, (w, h, x, rgb, peak)) in [
            (104, 26, 84, AURORA_TEAL, 15),
            (84, 20, 100, AURORA_TEAL, 18),
            (64, 14, 116, AURORA_GREEN, 30),
        ]
        .into_iter()
        .enumerate()
        {
            let wave = 0.6 + 0.4 * (fx.phase as f32 + k as f32 * 90.0).to_radians().sin();
            let a = (peak as f32 * wave) as i32;
            layer = layer.child(
                Element::leaf()
                    .size(w, h)
                    .corner(h as f32 / 2.0)
                    .bg_gradient(Gradient::linear(
                        (0.0, 0.0),
                        (0.0, 1.0),
                        vec![(0.0, rgba(rgb, a)), (0.4, faded(rgb, 60, a)), (1.0, rgba(rgb, 0))],
                    ))
                    .align_xy(Align::Start, Align::Start)
                    .margin_xy(x + fx.sway, 0),
            );
        }
        layer
    })
    .opacity_when(veil_of(s.fx_veil))
}

pub(crate) fn meteor_layer(s: UiSignals) -> Element {
    Element::host_signal(s.fx_meteors, |m: Meteor| {
        let mut comet = Element::stack().fill();
        let trail: [(i32, (u8, u8, u8), i32); 7] = [
            (3, (205, 232, 250), 160),
            (3, (180, 225, 255), 130),
            (3, (150, 210, 240), 100),
            (3, (120, 200, 225), 70),
            (3, AURORA_TEAL, 45),
            (3, AURORA_TEAL, 28),
            (3, AURORA_GREEN, 14),
        ];
        for (k, (size, rgb, base)) in trail.iter().enumerate() {
            let step = (k + 1) as i32 * 3;
            let tx = m.x - m.ux * step / 256;
            let ty = m.y - m.uy * step / 256;
            if tx < 0 || ty < 0 || tx > 186 || ty > 54 {
                continue;
            }
            comet = comet.child(
                Element::leaf()
                    .size(*size, *size)
                    .corner(*size as f32 / 2.0)
                    .bg(faded(*rgb, *base, m.fade))
                    .align_xy(Align::Start, Align::Start)
                    .margin_xy(tx, ty),
            );
        }
        if m.x >= 0 && m.y >= 0 && m.x <= 186 && m.y <= 54 {
            comet = comet.child(
                Element::leaf()
                    .size(3, 3)
                    .corner(1.5)
                    .bg(faded((248, 251, 255), 235, m.fade))
                    .shadow(Shadow::new(
                        0.0,
                        0.0,
                        7.0,
                        faded((180, 225, 255), 140, m.fade),
                    ))
                    .align_xy(Align::Start, Align::Start)
                    .margin_xy(m.x, m.y),
            );
        }
        comet
    })
    .opacity_when(veil_of(s.fx_veil))
}

pub(crate) fn switch(s: UiSignals, tx: Sender<Action>) -> Element {
    Element::stack()
        .size(40, 24)
        .clickable()
        .on_click(move |_| {
            let _ = tx.send(Action::ToggleMaster);
        })
        .child(Element::host_signal(s.fx_switch, build_switch_knob))
}

fn build_switch_knob(fx: SwitchFx) -> Element {
    let blend = fx.blend.clamp(0, 100);
    let b = blend as f32 / 100.0;
    let breath = 0.55 + 0.45 * (fx.star.min(100) as f32 / 100.0);
    let mut stack = Element::stack().fill();
    stack = stack.child(
        Element::leaf()
            .fill()
            .corner(12.0)
            .bg(theme::SWITCH_OFF_TRACK)
            .border(theme::SWITCH_OFF_BORDER, 1),
    );
    if blend > 0 {
        let a = (255.0 * b) as i32;
        stack = stack.child(
            Element::leaf()
                .fill()
                .corner(12.0)
                .bg_gradient(Gradient::linear(
                    (0.0, 0.0),
                    (0.0, 1.0),
                    vec![
                        (0.0, rgba(NIGHT_TOP, a)),
                        (1.0, rgba(NIGHT_BOTTOM, a)),
                    ],
                ))
                .border(rgba(NIGHT_EDGE, (77.0 * b) as i32), 1)
                .shadow(Shadow::new(
                    0.0,
                    2.0,
                    9.0,
                    rgba(NIGHT_GLOW, (107.0 * b) as i32),
                )),
        );
        stack = stack.child(
            Element::leaf()
                .fill()
                .margin_xy(1, 1)
                .corner(11.0)
                .border(rgba(NIGHT_EDGE, (36.0 * b) as i32), 1),
        );
        let wisp_rad = fx.wisp as f32 * std::f32::consts::TAU / 360.0;
        let wdx = (3.0 * wisp_rad.sin()).round() as i32;
        let wdy = (-wisp_rad.cos()).round() as i32;
        stack = stack
            .child(
                Element::leaf()
                    .size(24, 11)
                    .corner(5.5)
                    .bg(rgba((200, 220, 255), (24.0 * b) as i32))
                    .align_xy(Align::Start, Align::Start)
                    .margin_xy(7 + wdx, 7 + wdy),
            )
            .child(
                Element::leaf()
                    .size(20, 10)
                    .corner(5.0)
                    .bg(rgba(NIGHT_EDGE, (20.0 * b) as i32))
                    .align_xy(Align::Start, Align::Start)
                    .margin_xy(3 - wdx, 2 - wdy),
            );
        stack = stack.child(
            Element::leaf()
                .size(22, 22)
                .corner(11.0)
                .bg(rgba(RAY, (24.0 * b * breath) as i32))
                .align_xy(Align::Start, Align::Start)
                .margin_xy(STAR_CX - 11, STAR_CY - 11),
        );
        let ray_alpha = (255.0 * b) as i32;
        stack = stack
            .child(
                Element::leaf()
                    .size(2, 16)
                    .corner(1.0)
                    .bg_gradient(Gradient::linear(
                        (0.0, 0.0),
                        (0.0, 1.0),
                        vec![
                            (0.0, rgba(RAY, 0)),
                            (0.5, rgba(RAY, ray_alpha)),
                            (1.0, rgba(RAY, 0)),
                        ],
                    ))
                    .align_xy(Align::Start, Align::Start)
                    .margin_xy(STAR_CX - 1, STAR_CY - 8),
            )
            .child(
                Element::leaf()
                    .size(16, 2)
                    .corner(1.0)
                    .bg_gradient(Gradient::linear(
                        (0.0, 0.0),
                        (1.0, 0.0),
                        vec![
                            (0.0, rgba(RAY, 0)),
                            (0.5, rgba(RAY, ray_alpha)),
                            (1.0, rgba(RAY, 0)),
                        ],
                    ))
                    .align_xy(Align::Start, Align::Start)
                    .margin_xy(STAR_CX - 8, STAR_CY - 1),
            );
        for i in 2..=4 {
            let alpha = match i {
                2 => (110.0 * b) as i32,
                3 => (70.0 * b) as i32,
                _ => (36.0 * b) as i32,
            };
            for (dx, dy) in [(i, i), (-i, i), (i, -i), (-i, -i)] {
                stack = stack.child(
                    Element::leaf()
                        .size(1, 1)
                        .bg(rgba(RAY, alpha))
                        .align_xy(Align::Start, Align::Start)
                        .margin_xy(STAR_CX + dx - 1, STAR_CY + dy - 1),
                );
            }
        }
        stack = stack.child(
            Element::leaf()
                .size(4, 4)
                .corner(2.0)
                .bg(rgba(CORE, (255.0 * b) as i32))
                .shadow(Shadow::new(
                    0.0,
                    0.0,
                    6.0 + 4.0 * breath,
                    rgba(RAY, (240.0 * b * breath) as i32),
                ))
                .align_xy(Align::Start, Align::Start)
                .margin_xy(STAR_CX - 2, STAR_CY - 2),
        );
    }
    stack.child(
        Element::leaf()
            .size(18, 18)
            .corner(9.0)
            .bg(Color::rgba(255, 255, 255, (255.0 * (1.0 - b)) as u8))
            .shadow(Shadow::new(
                0.0,
                1.0,
                3.0,
                Color::rgba(0, 0, 0, (89.0 * (1.0 - b)) as u8),
            ))
            .align_xy(Align::Start, Align::Center)
            .margin_xy(fx.knob_x, 0),
    )
}

pub(crate) fn dot(fx: Signal<Vec<DotFx>>) -> Element {
    Element::stack().size(8, 8).child(Element::host_signal(
        fx,
        |d| {
            let mut dot = Element::leaf().size(8, 8).corner(4.0).bg(if d.on {
                theme::HERO_DOT_RUN
            } else {
                theme::HERO_DOT_PAUSED
            });
            if d.spread > 0 {
                dot = dot.shadow(Shadow::new(
                    0.0,
                    0.0,
                    d.spread as f32,
                    Color::rgba(61, 220, 151, d.alpha.min(255) as u8),
                ));
            }
            dot
        },
    ))
}
