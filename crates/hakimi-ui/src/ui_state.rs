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
use std::time::{Duration, Instant};

use hakimi_core::runtime::HakimiRuntime;

use crate::AppWindow;
use slint::SharedString;

#[derive(Clone, Debug, PartialEq)]
pub struct EnvState {
    pub ca_ok: bool,
    pub ca_error: String,
    pub proxy_ok: bool,
    /// The takeover we installed is no longer in the OS: another program (or
    /// the user) changed the system proxy while acceleration was running.
    pub proxy_lost: bool,
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
    /// Acceleration stopped because the system proxy no longer points here.
    /// Waiting for the user to decide: re-apply, or leave it alone.
    Interrupted,
}

/// Side effects a transition demands. Keeping them declarative (instead of
/// touching the runtime inside the transitions) is what makes the state
/// machine pure and unit-testable.
#[derive(Debug, Default, PartialEq)]
pub struct Effects {
    pub resume: bool,
    pub pause: bool,
    pub apply_proxy: bool,
    /// Hand the OS proxy back: restore the snapshot taken before the takeover,
    /// or at least switch off a PAC that still points at this instance.
    pub release_proxy: bool,
    /// Give the takeover up without writing anything back: someone else owns
    /// the setting now, so the snapshot has to be dropped, not restored.
    pub forget_proxy: bool,
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
            release_proxy: true,
            ..Default::default()
        }
    }
    fn awaiting() -> Self {
        Self {
            pause: true,
            release_proxy: true,
            ..Default::default()
        }
    }
    /// The system proxy was changed by someone else: stop accelerating and
    /// leave their settings alone.
    fn interrupted() -> Self {
        Self {
            forget_proxy: true,
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
    /// When acceleration was last entered. A takeover loss inside the grace
    /// window is our own asynchronous apply still publishing through configd,
    /// not someone else taking over.
    running_since: Option<Instant>,
    /// How long [`Self::running_since`] is trusted over an OS read-back.
    drift_grace: Duration,
    /// The user saw the interruption banner and told the app to leave it alone.
    interrupt_dismissed: bool,
}

impl Default for AppModel {
    fn default() -> Self {
        Self {
            accel: AccelState::Stopped,
            env: EnvState {
                ca_ok: true,
                ca_error: String::new(),
                proxy_ok: true,
                proxy_lost: false,
            },
            fix_page_open: false,
            running_since: None,
            drift_grace: Duration::from_secs(3),
            interrupt_dismissed: false,
        }
    }
}

impl AppModel {
    /// App launch. Acceleration always starts paused; taking over the system
    /// proxy is an explicit user action. A stale takeover from a previous run
    /// is still rolled back, so browsing keeps working directly in the
    /// meantime.
    pub fn startup(&mut self, env: EnvState) -> Effects {
        self.env = env;
        self.accel = AccelState::Stopped;
        self.running_since = None;
        self.interrupt_dismissed = false;
        Effects::awaiting()
    }

    /// The master switch. Turning acceleration ON with a broken environment
    /// does not accelerate: it parks in [`AccelState::AwaitingEnvironment`].
    /// From [`AccelState::Interrupted`] it re-applies the takeover once.
    pub fn toggle(&mut self, env: EnvState) -> Effects {
        self.env = env;
        self.accel = match self.accel {
            AccelState::Running => {
                self.running_since = None;
                AccelState::Stopped
            }
            AccelState::Stopped | AccelState::AwaitingEnvironment | AccelState::Interrupted => {
                if self.env.allows_acceleration() {
                    self.accel = AccelState::Running;
                    self.note_running();
                    AccelState::Running
                } else {
                    self.running_since = None;
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
        self.running_since = None;
        if was_active {
            Effects::stopped()
        } else {
            Effects::default()
        }
    }

    /// Periodic environment probe. A pending resume completes itself the
    /// moment the environment passes. A failed proxy write only updates the
    /// warning state; it never pauses a running acceleration — but a proxy
    /// that *used to be* ours and no longer is does: someone else took the
    /// system settings over, and pretending to accelerate would be a lie.
    ///
    /// The caller debounces the OS read-back (two consecutive reads must
    /// agree); the grace window here covers our own asynchronous apply, which
    /// macOS publishes a moment later.
    pub fn env_changed(&mut self, env: EnvState) -> Effects {
        self.env = env;
        if self.accel == AccelState::Running && self.env.proxy_lost && !self.in_grace() {
            self.running_since = None;
            self.accel = AccelState::Interrupted;
            return Effects::interrupted();
        }
        if self.accel == AccelState::AwaitingEnvironment && self.env.allows_acceleration() {
            self.accel = AccelState::Running;
            self.note_running();
            return self.effects();
        }
        Effects::default()
    }

    /// True when the switch has to show the interrupted state.
    pub fn proxy_lost(&self) -> bool {
        if self.interrupt_dismissed {
            return false;
        }
        self.accel == AccelState::Interrupted
            || (self.accel == AccelState::Running && self.env.proxy_lost)
    }

    /// The user acknowledged the interruption banner: hide it, stay stopped.
    pub fn dismiss_interrupt(&mut self) {
        self.interrupt_dismissed = true;
    }

    fn note_running(&mut self) {
        self.interrupt_dismissed = false;
        if self.accel == AccelState::Running {
            self.running_since = Some(Instant::now());
        }
    }

    fn in_grace(&self) -> bool {
        match self.running_since {
            Some(entered) => entered.elapsed() < self.drift_grace,
            None => true,
        }
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
            // The interruption already ran its effects; anything else only
            // needs to leave the runtime alone.
            AccelState::Interrupted => Effects::default(),
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
    if effects.release_proxy {
        runtime.release_system_proxy_async();
    }
    if effects.forget_proxy {
        runtime.abandon_takeover();
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
    app.set_proxy_interrupted(model.proxy_lost());
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
/// by the runtime; the OS is only read back when `check_proxy_os` is set,
/// which costs a `scutil` run on macOS and is therefore throttled by callers.
pub fn probe_env(runtime: &HakimiRuntime, check_proxy_os: bool) -> EnvState {
    let ca = runtime.ca().status();
    EnvState {
        ca_ok: ca.installed,
        ca_error: ca.error.unwrap_or_default(),
        proxy_ok: runtime.system_proxy_applied(),
        proxy_lost: check_proxy_os && runtime.takeover_lost() == Some(true),
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
            proxy_lost: false,
        }
    }

    fn env_lost() -> EnvState {
        let mut env = env(true);
        env.proxy_lost = true;
        env
    }

    /// The state right after the user flips acceleration on at launch.
    fn running_model() -> AppModel {
        let mut model = AppModel::default();
        model.startup(env(true));
        model.toggle(env(true));
        // Tests cannot wait out the grace window; the suppression test below
        // uses the real window instead.
        model.drift_grace = Duration::ZERO;
        model
    }

    #[test]
    fn startup_always_starts_paused() {
        for healthy in [true, false] {
            let mut model = AppModel::default();
            let effects = model.startup(env(healthy));
            assert_eq!(model.accel(), AccelState::Stopped);
            assert!(
                !model.fix_page(),
                "launch must not hijack the window; the banner is enough"
            );
            assert!(effects.pause && effects.release_proxy && !effects.resume);
            assert_eq!(start_mode(&effects), StartMode::Deferred);
        }
    }

    #[test]
    fn start_mode_follows_the_proxy_effect() {
        assert_eq!(start_mode(&Effects::running()), StartMode::Takeover);
        assert_eq!(start_mode(&Effects::awaiting()), StartMode::Deferred);
    }

    #[test]
    fn toggle_refuses_to_accelerate_with_broken_environment() {
        let mut model = running_model();
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
        let mut model = running_model();
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
    fn proxy_taken_over_by_another_program_interrupts_acceleration() {
        let mut model = running_model();
        assert!(!model.proxy_lost());

        let effects = model.env_changed(env_lost());
        assert_eq!(model.accel(), AccelState::Interrupted);
        assert!(model.proxy_lost());
        // Not release_proxy: restoring the snapshot would overwrite the
        // program that took the proxy over. The snapshot is dropped instead.
        assert!(effects.forget_proxy);
        assert!(!effects.release_proxy && !effects.apply_proxy && !effects.resume);
    }

    #[test]
    fn interrupted_state_waits_for_the_user_instead_of_fighting_back() {
        let mut model = running_model();
        model.env_changed(env_lost());
        assert_eq!(model.accel(), AccelState::Interrupted);

        // A tick that no longer reports the loss must not silently resume.
        let effects = model.env_changed(env(true));
        assert_eq!(effects, Effects::default());
        assert_eq!(model.accel(), AccelState::Interrupted);
    }

    #[test]
    fn re_enabling_after_an_interruption_reapplies_the_takeover() {
        let mut model = running_model();
        model.env_changed(env_lost());
        assert_eq!(model.accel(), AccelState::Interrupted);

        let effects = model.toggle(env(true));
        assert_eq!(model.accel(), AccelState::Running);
        assert!(effects.resume && effects.apply_proxy && !effects.forget_proxy);
        assert!(!model.proxy_lost());
    }

    #[test]
    fn tick_without_an_os_read_never_reports_a_loss() {
        let mut model = running_model();
        // Ticks that skip the OS read-back carry `proxy_lost: false`; they
        // must not be mistaken for "the proxy came back".
        let effects = model.env_changed(env(true));
        assert_eq!(effects, Effects::default());
        assert_eq!(model.accel(), AccelState::Running);
    }

    #[test]
    fn apply_lag_right_after_enabling_is_not_a_takeover_loss() {
        // The default grace window covers the asynchronous apply: macOS needs
        // a moment to publish the PAC, so an immediate read-back that does not
        // see it yet is our own lag, not another program.
        let mut model = AppModel::default();
        model.startup(env(true));
        model.toggle(env(true));

        let effects = model.env_changed(env_lost());
        assert_eq!(effects, Effects::default());
        assert_eq!(model.accel(), AccelState::Running);
        assert!(model.proxy_lost(), "the UI still shows the drift hint");
    }

    #[test]
    fn manually_opened_fix_page_survives_environment_ticks() {
        let mut model = running_model();
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
        let mut model = running_model();
        model.open_fix();

        let effects = model.dismiss_fix();
        assert!(!model.fix_page());
        assert_eq!(model.accel(), AccelState::Running);
        assert_eq!(effects, Effects::default());
    }

    #[test]
    fn dismissing_the_fix_page_stays_stopped() {
        let mut model = running_model();
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
        let mut model = running_model();
        model.toggle(env(true)); // → Stopped
        let effects = model.toggle(env(true)); // → Running again
        assert!(effects.resume);
        assert!(
            effects.apply_proxy,
            "entering Running must write/verify the proxy instead of trusting a PAC from an earlier run"
        );
    }

    #[test]
    fn turning_off_releases_the_os_proxy() {
        let mut model = running_model();
        let effects = model.toggle(env(true)); // → Stopped
        assert_eq!(model.accel(), AccelState::Stopped);
        assert!(
            effects.pause && effects.release_proxy,
            "stopping must hand the OS proxy back instead of leaving a PAC that points at us"
        );
        assert!(!effects.apply_proxy);
    }

    #[test]
    fn stop_never_requires_an_healthy_environment() {
        let mut model = running_model();
        model.toggle(env(false)); // → Stopped
        assert_eq!(model.accel(), AccelState::Stopped);
    }

    #[test]
    fn clearing_the_selection_stops_acceleration() {
        let mut model = running_model();

        let effects = model.stop();
        assert_eq!(model.accel(), AccelState::Stopped);
        assert!(effects.pause && !effects.resume);

        // Clearing an empty selection is a no-op.
        assert_eq!(model.stop(), Effects::default());
    }

    #[test]
    fn a_failed_proxy_write_does_not_pause_acceleration() {
        let mut model = running_model();

        let failed = EnvState {
            ca_ok: true,
            ca_error: String::new(),
            proxy_ok: false,
            proxy_lost: false,
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
        let mut model = running_model();
        let failed = EnvState {
            ca_ok: true,
            ca_error: String::new(),
            proxy_ok: false,
            proxy_lost: false,
        };
        model.env_changed(failed);
        model.toggle(env(true)); // running → stopped

        let effects = model.toggle(EnvState {
            ca_ok: true,
            ca_error: String::new(),
            proxy_ok: false,
            proxy_lost: false,
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
