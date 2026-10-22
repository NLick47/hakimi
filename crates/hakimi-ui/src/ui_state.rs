//! The acceleration state machine — the single source of truth for what the
//! app is doing.
//!
//! Every question of the form "may the app accelerate right now?", "which
//! page does the window show?" and "what should the runtime do?" is answered
//! here, by pure transitions over [`AccelState`] and [`EnvState`]. The UI
//! callbacks only probe the environment, feed it in, and execute the returned
//! [`Effects`]; nothing else is allowed to flip the runtime or the window.
//!
//! States:
//!
//! - [`AccelState::Running`] — acceleration is on.
//! - [`AccelState::Stopped`] — the user stopped it; the PAC (if any) serves
//!   DIRECT, browsing is untouched. A launch with a broken environment also
//!   lands here: the banner explains the problem, nothing is forced on screen.
//! - [`AccelState::AwaitingEnvironment`] — the user asked to run but the
//!   environment check failed. The runtime stays paused and the fix page
//!   takes over; the moment the environment passes, the model resumes
//!   itself.

use std::sync::Arc;

use hakimi_core::runtime::HakimiRuntime;

use crate::AppWindow;
use slint::SharedString;

#[derive(Clone, Debug, PartialEq)]
pub struct EnvState {
    pub ca_ok: bool,
    pub ca_error: String,
    pub proxy_ok: bool,
}

impl EnvState {
    /// Whether acceleration may run at all. The CA trust is the only
    /// prerequisite the app cannot fix itself (it needs the user to confirm a
    /// system dialog); the system proxy is applied by the effects as part of
    /// entering Running, so it is not part of the gate.
    pub fn allows_acceleration(&self) -> bool {
        self.ca_ok
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AccelState {
    Running,
    Stopped,
    AwaitingEnvironment,
}

/// Side effects a transition demands. Keeping them declarative (instead of
/// touching the runtime inside the transitions) is what makes the state
/// machine pure and unit-testable.
#[derive(Debug, Default, PartialEq)]
pub struct Effects {
    pub resume: bool,
    pub pause: bool,
    pub apply_proxy: bool,
    pub disable_proxy: bool,
}

impl Effects {
    fn running() -> Self {
        Self {
            resume: true,
            apply_proxy: true,
            ..Default::default()
        }
    }
    fn stopped() -> Self {
        Self {
            pause: true,
            ..Default::default()
        }
    }
    fn awaiting() -> Self {
        Self {
            pause: true,
            disable_proxy: true,
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct AppModel {
    accel: AccelState,
    env: EnvState,
    /// The user opened the fix page from the warning banner. This is separate
    /// from [`AccelState::AwaitingEnvironment`]: a manual visit must survive the
    /// once-a-second environment sync, which recomputes the page from state and
    /// would otherwise bounce the user back to the home page immediately.
    fix_page_open: bool,
}

impl Default for AppModel {
    fn default() -> Self {
        Self {
            accel: AccelState::Stopped,
            env: EnvState {
                ca_ok: true,
                ca_error: String::new(),
                proxy_ok: true,
            },
            fix_page_open: false,
        }
    }
}

impl AppModel {
    /// App launch. A healthy environment starts accelerating right away; a
    /// broken one stays stopped and only raises the banner — the app never
    /// hijacks the window on its own, the user decides when to go fix it.
    pub fn startup(&mut self, env: EnvState) -> Effects {
        self.env = env;
        if self.env.allows_acceleration() {
            self.accel = AccelState::Running;
            self.effects()
        } else {
            // Same shape as a gated start (pause + leave the OS proxy alone),
            // minus the fix page: `fix_page_open` stays false.
            self.accel = AccelState::Stopped;
            Effects::awaiting()
        }
    }

    /// The master switch. Turning acceleration ON with a broken environment
    /// does not accelerate: it parks in [`AccelState::AwaitingEnvironment`].
    pub fn toggle(&mut self, env: EnvState) -> Effects {
        self.env = env;
        self.accel = match self.accel {
            AccelState::Running => AccelState::Stopped,
            AccelState::Stopped | AccelState::AwaitingEnvironment => {
                if self.env.allows_acceleration() {
                    AccelState::Running
                } else {
                    AccelState::AwaitingEnvironment
                }
            }
        };
        self.effects()
    }

    /// Stop acceleration outright. Used when the selection becomes empty:
    /// there is nothing left to accelerate, so the switch must not keep
    /// claiming to run. Unlike [`Self::toggle`] this never turns acceleration
    /// on and is idempotent.
    pub fn stop(&mut self) -> Effects {
        let was_active = self.accel != AccelState::Stopped;
        self.accel = AccelState::Stopped;
        if was_active {
            Effects::stopped()
        } else {
            Effects::default()
        }
    }

    /// Periodic environment probe. A pending resume completes itself the
    /// moment the environment passes. A failed proxy write only updates the
    /// warning state; it never pauses a running acceleration.
    pub fn env_changed(&mut self, env: EnvState) -> Effects {
        self.env = env;
        if self.accel == AccelState::AwaitingEnvironment && self.env.allows_acceleration() {
            self.accel = AccelState::Running;
            return self.effects();
        }
        Effects::default()
    }

    /// The user asked to see the fix page from the warning banner. Does not
    /// touch acceleration: the page is shown, the runtime is untouched.
    pub fn open_fix(&mut self) {
        self.fix_page_open = true;
    }

    /// The user left the fix page without fixing: stay stopped.
    pub fn dismiss_fix(&mut self) -> Effects {
        self.fix_page_open = false;
        if self.accel == AccelState::AwaitingEnvironment {
            self.accel = AccelState::Stopped;
            return self.effects();
        }
        Effects::default()
    }

    pub fn accel(&self) -> AccelState {
        self.accel
    }

    pub fn env(&self) -> &EnvState {
        &self.env
    }

    /// True when the fix page owns the window.
    pub fn fix_page(&self) -> bool {
        self.fix_page_open || self.accel == AccelState::AwaitingEnvironment
    }

    /// True when the page was forced by a blocked start (as opposed to the
    /// user opening it just to check). Drives the wording of the fix page.
    pub fn fix_blocked(&self) -> bool {
        self.accel == AccelState::AwaitingEnvironment
    }

    fn effects(&self) -> Effects {
        self.effects_with(Effects::running)
    }

    fn effects_with(&self, running: impl Fn() -> Effects) -> Effects {
        match self.accel {
            AccelState::Running => running(),
            AccelState::Stopped => Effects::stopped(),
            AccelState::AwaitingEnvironment => Effects::awaiting(),
        }
    }
}

/// How the runtime should treat the OS proxy at startup. The proxy effects of
/// the startup transition cannot run before the proxy is bound (the PAC URL is
/// unknown then), so they are handed to the startup sequence instead of being
/// executed like any other transition.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StartMode {
    /// Normal launch: the runtime applies the PAC takeover itself, post-bind.
    Takeover,
    /// Gated launch: leave the OS proxy alone and clear a stale takeover.
    Deferred,
}

/// Pure mapping from the startup effects to the runtime's start mode. The
/// proxy effects need the PAC URL, which only exists post-bind, so they are
/// folded into how the runtime starts instead of being executed now.
pub fn start_mode(effects: &Effects) -> StartMode {
    if effects.apply_proxy {
        StartMode::Takeover
    } else {
        StartMode::Deferred
    }
}

/// Execute the startup transition: pause/resume run now; the proxy effects are
/// mapped onto the [`StartMode`] the runtime starts with.
pub fn execute_startup(effects: &Effects, runtime: &HakimiRuntime) -> StartMode {
    if effects.resume {
        runtime.resume();
    }
    if effects.pause {
        runtime.pause();
    }
    start_mode(effects)
}

/// Execute the effects of a transition. The only place that drives the runtime
/// from state. The runtime owns OS-proxy writes and remembers the result of
/// the one-time read-back verification.
pub fn execute(effects: &Effects, runtime: &Arc<HakimiRuntime>) {
    if effects.resume {
        runtime.resume();
    }
    if effects.pause {
        runtime.pause();
    }
    if effects.apply_proxy {
        runtime.apply_system_proxy_async();
    }
    if effects.disable_proxy {
        runtime.disable_system_proxy_async();
    }
}

/// Mirror the model onto the window. The only place that writes UI state.
pub fn sync_window(model: &AppModel, app: &AppWindow) {
    let env = model.env();
    app.set_show_onboarding(model.fix_page());
    app.set_fix_blocked(model.fix_blocked());
    app.set_ca_installed(env.ca_ok);
    app.set_ca_error(SharedString::from(env.ca_error.clone()));
    app.set_proxy_ok(env.proxy_ok);
    if env.ca_ok || !env.ca_error.is_empty() {
        // Install finished (or failed loudly): the wait-for-dialog state can go.
        app.set_ob_installing(false);
    }
    if env.ca_ok && !app.get_ca_action_error().is_empty() {
        // A later successful install clears the stale password/cancel message.
        app.set_ca_action_error(SharedString::new());
    }
}

// -- environment probing ------------------------------------------------------

/// Probe the environment. Spawns subprocesses (the CA status, and `security`
/// on macOS), so it must run OFF the UI thread — callers post the result back
/// through the event loop. The system-proxy result is the last write recorded
/// by the runtime; no OS proxy process is spawned here.
pub fn probe_env(runtime: &HakimiRuntime) -> EnvState {
    let ca = runtime.ca().status();
    EnvState {
        ca_ok: ca.installed,
        ca_error: ca.error.unwrap_or_default(),
        proxy_ok: runtime.system_proxy_applied(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settle_holds_probing_sites_on_testing() {
        let mut entry = SiteSettle::default();
        let (summary, hex) = settle_display(&mut entry, "3 个域名 · 全部超时", BAD_COLOR, false);
        assert_eq!(summary, "3 个域名 · 测速中");
        assert_eq!(hex, IDLE_COLOR);

        // Flapping to 较慢 within the window must not change the display.
        let (summary, _) = settle_display(&mut entry, "3 个域名 · 全部较慢", SLOW_COLOR, false);
        assert_eq!(summary, "3 个域名 · 测速中");

        // Once a summary persists long enough it is committed verbatim.
        let (summary, hex) = settle_display(&mut entry, "3 个域名 · 全部超时", BAD_COLOR, true);
        assert_eq!(summary, "3 个域名 · 全部超时");
        assert_eq!(hex, BAD_COLOR);
    }

    #[test]
    fn settle_keeps_the_previous_state_during_a_brief_flip() {
        let mut entry = SiteSettle::default();
        let (summary, _) = settle_display(&mut entry, "2 个域名 · 全部正常", OK_COLOR, true);
        assert_eq!(summary, "2 个域名 · 全部正常");

        // A brief flip to 超时 that has not persisted yet keeps the shown state.
        let (summary, _) = settle_display(&mut entry, "2 个域名 · 全部超时", BAD_COLOR, false);
        assert_eq!(summary, "2 个域名 · 全部正常");
    }

    fn sample_site(id: &str, summary: &str) -> crate::SiteData {
        crate::SiteData {
            id: id.into(),
            name: id.into(),
            initial: "M".into(),
            icon_key: String::new(),
            tile_hex: "",
            summary: summary.into(),
            summary_hex: IDLE_COLOR,
            enabled: true,
            open: false,
            first: false,
            last: false,
            url: String::new(),
            strategy: 0,
            sni: String::new(),
            custom: false,
            domains: vec![],
        }
    }

    #[test]
    fn starting_phase_holds_instead_of_a_stale_result() {
        let mut sites = vec![sample_site("mp", "1 个域名 · 待检测")];
        apply_settle(&mut sites, SettlePhase::Starting);
        assert_eq!(sites[0].summary, "1 个域名 · 启动中");

        // The starting state is never committed: once the runtime is up the
        // summaries start from a clean slate (测速中 → results).
        sites[0].summary = "1 个域名 · 全部正常".into();
        apply_settle(&mut sites, SettlePhase::Tracking);
        assert_eq!(sites[0].summary, "1 个域名 · 测速中");
    }

    #[test]
    fn sweep_phases_drive_the_summary() {
        let mut sites = vec![sample_site("mp", "1 个域名 · 全部正常")];

        // While the sweep runs the summary holds 测速中.
        apply_settle(&mut sites, SettlePhase::Sweeping);
        assert_eq!(sites[0].summary, "1 个域名 · 测速中");

        // The finished results commit at once when the sweep ends.
        sites[0].summary = "1 个域名 · 全部较慢".into();
        apply_settle(&mut sites, SettlePhase::Commit);
        assert_eq!(sites[0].summary, "1 个域名 · 全部较慢");

        // Tracking keeps a brief flip hidden.
        sites[0].summary = "1 个域名 · 全部超时".into();
        apply_settle(&mut sites, SettlePhase::Tracking);
        assert_eq!(sites[0].summary, "1 个域名 · 全部较慢");
    }

    fn env(healthy: bool) -> EnvState {
        EnvState {
            ca_ok: healthy,
            ca_error: if healthy {
                String::new()
            } else {
                "not trusted".into()
            },
            proxy_ok: healthy,
        }
    }

    #[test]
    fn startup_with_broken_environment_stays_stopped_without_the_fix_page() {
        let mut model = AppModel::default();
        let effects = model.startup(env(false));
        assert_eq!(model.accel(), AccelState::Stopped);
        assert!(
            !model.fix_page(),
            "launch must not hijack the window; the banner is enough"
        );
        assert!(effects.pause && effects.disable_proxy && !effects.resume);
        assert_eq!(start_mode(&effects), StartMode::Deferred);
    }

    #[test]
    fn startup_with_healthy_environment_maps_to_takeover() {
        let mut model = AppModel::default();
        let effects = model.startup(env(true));
        assert_eq!(start_mode(&effects), StartMode::Takeover);
    }

    #[test]
    fn startup_with_healthy_environment_runs() {
        let mut model = AppModel::default();
        let effects = model.startup(env(true));
        assert_eq!(model.accel(), AccelState::Running);
        assert!(effects.resume && effects.apply_proxy);
    }

    #[test]
    fn toggle_refuses_to_accelerate_with_broken_environment() {
        let mut model = AppModel::default();
        model.startup(env(true));
        let effects = model.toggle(env(false)); // was running → stop
        assert_eq!(model.accel(), AccelState::Stopped);
        assert!(effects.pause && !effects.resume);

        let effects = model.toggle(env(false)); // user wants it on, env broken
        assert_eq!(model.accel(), AccelState::AwaitingEnvironment);
        assert!(!effects.resume, "must not accelerate");
        assert!(effects.pause);
    }

    #[test]
    fn pending_resume_completes_itself_when_environment_passes() {
        let mut model = AppModel::default();
        model.startup(env(true));
        model.toggle(env(true)); // running → stopped
        model.toggle(env(false)); // user wants it on, env broken
        assert_eq!(model.accel(), AccelState::AwaitingEnvironment);

        let effects = model.env_changed(env(false));
        assert_eq!(effects, Effects::default(), "still broken: nothing to do");
        assert_eq!(model.accel(), AccelState::AwaitingEnvironment);

        // The gated start deferred the PAC; `proxy_ok` cannot be trusted here
        // (it means "the last write succeeded", not "a write happened").
        // Entering Running must always re-apply.
        let fixed = env(true);
        let effects = model.env_changed(fixed);
        assert_eq!(model.accel(), AccelState::Running);
        assert!(effects.resume && effects.apply_proxy);
    }

    #[test]
    fn manually_opened_fix_page_survives_environment_ticks() {
        let mut model = AppModel::default();
        model.startup(env(true));
        // The environment degrades after launch (e.g. the CA was removed).
        model.env_changed(env(false));
        assert!(
            !model.fix_page(),
            "a degraded env alone must not hijack the window"
        );

        model.open_fix();
        assert!(model.fix_page());
        assert!(
            !model.fix_blocked(),
            "opened by hand, not by a blocked start"
        );

        // The once-a-second sync recomputes the page from state; the manual
        // visit has to survive it.
        model.env_changed(env(false));
        assert!(model.fix_page());
    }

    #[test]
    fn dismissing_a_manual_visit_does_not_stop_acceleration() {
        let mut model = AppModel::default();
        model.startup(env(true));
        model.open_fix();

        let effects = model.dismiss_fix();
        assert!(!model.fix_page());
        assert_eq!(model.accel(), AccelState::Running);
        assert_eq!(effects, Effects::default());
    }

    #[test]
    fn dismissing_the_fix_page_stays_stopped() {
        let mut model = AppModel::default();
        model.startup(env(true));
        model.toggle(env(true)); // running → stopped
        model.toggle(env(false)); // user wants it on, env broken → gated
        assert!(model.fix_page());

        let effects = model.dismiss_fix();
        assert_eq!(model.accel(), AccelState::Stopped);
        assert!(effects.pause && !effects.resume);

        // env passing later must NOT auto-start a dismissed resume
        model.env_changed(env(true));
        assert_eq!(model.accel(), AccelState::Stopped);
    }

    #[test]
    fn turning_on_reasserts_the_proxy() {
        let mut model = AppModel::default();
        model.startup(env(true));
        model.toggle(env(true)); // → Stopped
        let effects = model.toggle(env(true)); // → Running again
        assert!(effects.resume);
        assert!(
            effects.apply_proxy,
            "entering Running must write/verify the proxy instead of trusting a PAC from an earlier run"
        );
    }

    #[test]
    fn stop_never_requires_an_healthy_environment() {
        let mut model = AppModel::default();
        model.startup(env(true));
        model.toggle(env(false)); // → Stopped
        assert_eq!(model.accel(), AccelState::Stopped);
    }

    #[test]
    fn clearing_the_selection_stops_acceleration() {
        let mut model = AppModel::default();
        model.startup(env(true));

        let effects = model.stop();
        assert_eq!(model.accel(), AccelState::Stopped);
        assert!(effects.pause && !effects.resume);

        // Clearing an empty selection is a no-op.
        assert_eq!(model.stop(), Effects::default());
    }

    #[test]
    fn a_failed_proxy_write_does_not_pause_acceleration() {
        let mut model = AppModel::default();
        model.startup(env(true));

        let failed = EnvState {
            ca_ok: true,
            ca_error: String::new(),
            proxy_ok: false,
        };
        let effects = model.env_changed(failed);
        assert_eq!(effects, Effects::default());
        assert_eq!(
            model.accel(),
            AccelState::Running,
            "a proxy write failure is a warning, never an auto-pause"
        );
    }

    #[test]
    fn toggling_after_a_failed_proxy_write_reapplies_without_pausing() {
        let mut model = AppModel::default();
        model.startup(env(true));
        let failed = EnvState {
            ca_ok: true,
            ca_error: String::new(),
            proxy_ok: false,
        };
        model.env_changed(failed);
        model.toggle(env(true)); // running → stopped

        let effects = model.toggle(EnvState {
            ca_ok: true,
            ca_error: String::new(),
            proxy_ok: false,
        });
        assert_eq!(model.accel(), AccelState::Running);
        assert!(effects.resume);
        assert!(
            effects.apply_proxy,
            "a failed write must be retried when the user turns acceleration back on"
        );
    }
}

// -- site summary display lifecycle ------------------------------------------
//
// The home page summaries are derived from a noisy stream: while the engine
// hunts for a working IP the per-domain states flap between 超时 and 较慢 every
// second. The display therefore has an explicit lifecycle with three phases,
// and the phase is an input of the policy — never inferred from ambient flags.

pub const OK_COLOR: &str = "#2E7D53";
pub const SLOW_COLOR: &str = "#B88325";
pub const BAD_COLOR: &str = "#C05B5B";
pub const IDLE_COLOR: &str = "#8A95A2";

/// How long a summary must stay unchanged before it replaces the displayed one.
const SETTLE_MILLIS: u128 = 3000;

/// Where the site summaries are in their display lifecycle.
#[derive(Clone, Copy, PartialEq)]
pub enum SettlePhase {
    /// The user asked to run but the runtime has not finished starting: hold
    /// 启动中 instead of misreporting a stale 待检测/失败 state.
    Starting,
    /// A manual sweep is running: hold 测速中 for every active site.
    Sweeping,
    /// The sweep just finished: commit the fresh results at once.
    Commit,
    /// Background tracking: show a summary once it has been stable for a moment.
    Tracking,
}

/// Display bookkeeping per site. Lives in a thread-local keyed by site id and
/// only ever touched on the UI thread.
#[derive(Default, Clone)]
struct SiteSettle {
    shown: String,
    shown_hex: &'static str,
    pending: Option<(String, &'static str, std::time::Instant)>,
}

thread_local! {
    static SITE_SETTLE: std::cell::RefCell<std::collections::HashMap<String, SiteSettle>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Pure display policy: decide what a site should show given its raw summary
/// and whether that raw summary has been stable long enough (`stable`).
fn settle_display(
    entry: &mut SiteSettle,
    raw: &str,
    raw_hex: &'static str,
    stable: bool,
) -> (String, &'static str) {
    // Disabled sites are not probing states: always display them directly.
    if raw.ends_with("未选择") {
        entry.shown = raw.into();
        entry.shown_hex = raw_hex;
        entry.pending = None;
        return (raw.into(), raw_hex);
    }
    if raw == entry.shown && raw_hex == entry.shown_hex {
        entry.pending = None;
        return (raw.into(), raw_hex);
    }
    if stable {
        entry.shown = raw.into();
        entry.shown_hex = raw_hex;
        entry.pending = None;
        return (raw.into(), raw_hex);
    }
    match &entry.pending {
        Some((sum, hex, _)) if sum == raw && *hex == raw_hex => {}
        _ => entry.pending = Some((raw.into(), raw_hex, std::time::Instant::now())),
    }
    if entry.shown.is_empty() {
        // Nothing committed yet: hold a stable 测速中 instead of the flapping
        // 超时/较慢 while the engine hunts for a working IP.
        let prefix = raw.split(" · ").next().unwrap_or(raw);
        (format!("{prefix} · 测速中"), IDLE_COLOR)
    } else {
        (entry.shown.clone(), entry.shown_hex)
    }
}

/// Apply the display lifecycle to a freshly built snapshot, in place.
pub fn apply_settle(sites: &mut [crate::SiteData], phase: SettlePhase) {
    SITE_SETTLE.with(|cell| {
        let mut map = cell.borrow_mut();
        let live: std::collections::HashSet<String> =
            sites.iter().map(|site| site.id.clone()).collect();
        map.retain(|id, _| live.contains(id));
        for site in sites.iter_mut() {
            let entry = map.entry(site.id.clone()).or_default();
            let (summary, hex) = match phase {
                SettlePhase::Starting => {
                    // Never commit this state: when the runtime comes up the
                    // summaries start from a clean slate (测速中 → results).
                    if !site.enabled {
                        (site.summary.clone(), site.summary_hex)
                    } else {
                        let prefix = site.summary.split(" · ").next().unwrap_or(&site.summary);
                        (format!("{prefix} · 启动中"), IDLE_COLOR)
                    }
                }
                SettlePhase::Sweeping => {
                    if site.summary.ends_with("未选择") {
                        (site.summary.clone(), site.summary_hex)
                    } else {
                        let prefix = site.summary.split(" · ").next().unwrap_or(&site.summary);
                        (format!("{prefix} · 测速中"), IDLE_COLOR)
                    }
                }
                SettlePhase::Commit => {
                    entry.shown = site.summary.clone();
                    entry.shown_hex = site.summary_hex;
                    entry.pending = None;
                    (site.summary.clone(), site.summary_hex)
                }
                SettlePhase::Tracking => {
                    let stable = match &entry.pending {
                        Some((sum, hex, since)) => {
                            *sum == site.summary
                                && *hex == site.summary_hex
                                && since.elapsed().as_millis() >= SETTLE_MILLIS
                        }
                        None => false,
                    };
                    settle_display(entry, &site.summary, &site.summary_hex, stable)
                }
            };
            site.summary = summary;
            site.summary_hex = hex;
        }
    });
}
