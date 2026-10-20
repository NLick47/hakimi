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
//!   DIRECT, browsing is untouched.
//! - [`AccelState::AwaitingEnvironment`] — the user asked to run but the
//!   environment check failed. The runtime stays paused and the fix page
//!   takes over; the moment the environment passes, the model resumes
//!   itself.

use std::cell::RefCell;
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
        }
    }
}

impl AppModel {
    /// App launch: an unhealthy environment blocks acceleration right away.
    pub fn startup(&mut self, env: EnvState) -> Effects {
        self.env = env;
        self.accel = if self.env.allows_acceleration() {
            AccelState::Running
        } else {
            AccelState::AwaitingEnvironment
        };
        self.effects()
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
        self.effects_apply_if_needed()
    }

    /// Periodic environment probe. A pending resume completes itself the
    /// moment the environment passes.
    pub fn env_changed(&mut self, env: EnvState) -> Effects {
        self.env = env;
        if self.accel == AccelState::AwaitingEnvironment && self.env.allows_acceleration() {
            self.accel = AccelState::Running;
            return self.effects_apply_if_needed();
        }
        Effects::default()
    }

    /// The user left the fix page without fixing: stay stopped.
    pub fn dismiss_fix(&mut self) -> Effects {
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
        self.accel == AccelState::AwaitingEnvironment
    }

    fn effects(&self) -> Effects {
        self.effects_with(Effects::running)
    }

    /// Same as [`Self::effects`], but the proxy apply is skipped when the
    /// system proxy is already healthy — turning acceleration on must not
    /// re-run `networksetup` for a PAC that is already in place.
    fn effects_apply_if_needed(&self) -> Effects {
        match self.accel {
            AccelState::Running => {
                let mut effects = Effects::running();
                effects.apply_proxy = !self.env.proxy_ok;
                effects
            }
            _ => self.effects(),
        }
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
/// from state.
pub fn execute(effects: &Effects, runtime: &Arc<HakimiRuntime>) {
    if effects.resume {
        runtime.resume();
    }
    if effects.pause {
        runtime.pause();
    }
    if effects.apply_proxy {
        let runtime = runtime.clone();
        std::thread::spawn(move || {
            if let Err(error) = runtime.apply_system_proxy() {
                eprintln!("hakimi-ui: applying the system proxy failed: {error:#}");
            }
        });
    }
    if effects.disable_proxy {
        let runtime = runtime.clone();
        std::thread::spawn(move || {
            runtime.disable_system_proxy();
        });
    }
}

/// Mirror the model onto the window. The only place that writes UI state.
pub fn sync_window(model: &AppModel, app: &AppWindow) {
    let env = model.env();
    app.set_show_onboarding(model.fix_page());
    app.set_ca_installed(env.ca_ok);
    app.set_ca_error(SharedString::from(env.ca_error.clone()));
    app.set_proxy_ok(env.proxy_ok);
    if env.ca_ok || !env.ca_error.is_empty() {
        // Install finished (or failed loudly): the wait-for-dialog state can go.
        app.set_ob_installing(false);
    }
}

// -- environment probing ------------------------------------------------------

thread_local! {
    static TICK: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static PROXY_CACHE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
    static LAST_APPLY: RefCell<Option<Instant>> = const { RefCell::new(None) };
}

/// Probe the environment. Spawns subprocesses (`security`, `networksetup`),
/// so it must run OFF the UI thread — callers post the result back through the
/// event loop. The proxy health is probed every 10th call and cached in
/// between.
pub fn probe_env(runtime: &HakimiRuntime) -> EnvState {
    let ca = runtime.ca().status();
    let tick = TICK.with(|t| {
        let value = t.get() + 1;
        t.set(value);
        value
    });
    if tick % 10 == 1 {
        PROXY_CACHE.with(|t| t.set(runtime.system_proxy_healthy()));
    }
    EnvState {
        ca_ok: ca.installed,
        ca_error: ca.error.unwrap_or_default(),
        proxy_ok: PROXY_CACHE.with(|t| t.get()),
    }
}

/// Self-heal for a running instance whose system proxy got rewritten by
/// something else. Maintenance, not a state transition: only runs while
/// accelerating and at most once per 30 seconds.
pub fn maybe_self_heal(runtime: &Arc<HakimiRuntime>, model: &AppModel) {
    if model.accel() != AccelState::Running || model.env().proxy_ok {
        return;
    }
    let cooldown_over = LAST_APPLY.with(|t| {
        t.borrow()
            .map(|at| at.elapsed())
            .unwrap_or(Duration::from_secs(3600))
            > Duration::from_secs(30)
    });
    if cooldown_over {
        LAST_APPLY.with(|t| *t.borrow_mut() = Some(Instant::now()));
        let runtime = runtime.clone();
        std::thread::spawn(move || {
            if let Err(error) = runtime.apply_system_proxy() {
                eprintln!("hakimi-ui: self-heal of the system proxy failed: {error:#}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn startup_with_broken_environment_blocks_acceleration() {
        let mut model = AppModel::default();
        let effects = model.startup(env(false));
        assert_eq!(model.accel(), AccelState::AwaitingEnvironment);
        assert!(model.fix_page());
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
        model.startup(env(false));
        assert_eq!(model.accel(), AccelState::AwaitingEnvironment);

        let effects = model.env_changed(env(false));
        assert_eq!(effects, Effects::default(), "still broken: nothing to do");
        assert_eq!(model.accel(), AccelState::AwaitingEnvironment);

        // The PAC was disabled while gated, so the proxy_ok half of the env is
        // still false — entering Running re-applies it.
        let fixed = EnvState {
            ca_ok: true,
            ca_error: String::new(),
            proxy_ok: false,
        };
        let effects = model.env_changed(fixed);
        assert_eq!(model.accel(), AccelState::Running);
        assert!(effects.resume && effects.apply_proxy);
    }

    #[test]
    fn dismissing_the_fix_page_stays_stopped() {
        let mut model = AppModel::default();
        model.startup(env(false));
        let effects = model.dismiss_fix();
        assert_eq!(model.accel(), AccelState::Stopped);
        assert!(effects.pause && !effects.resume);

        // env passing later must NOT auto-start a dismissed resume
        model.env_changed(env(true));
        assert_eq!(model.accel(), AccelState::Stopped);
    }

    #[test]
    fn turning_on_does_not_reapply_an_healthy_proxy() {
        let mut model = AppModel::default();
        model.startup(env(true));
        model.toggle(env(true)); // → Stopped
        let effects = model.toggle(env(true)); // → Running again
        assert!(effects.resume);
        assert!(
            !effects.apply_proxy,
            "a healthy PAC must not be re-applied on every toggle"
        );
    }

    #[test]
    fn stop_never_requires_an_healthy_environment() {
        let mut model = AppModel::default();
        model.startup(env(true));
        model.toggle(env(false)); // → Stopped
        assert_eq!(model.accel(), AccelState::Stopped);
    }
}
