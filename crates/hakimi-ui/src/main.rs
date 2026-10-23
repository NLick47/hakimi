#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use hakimi_core::config::{AppConfig, DomainRule, GroupConfig, RouteAttempt, RoutePolicy};
use hakimi_core::instance::{InstanceLock, InstanceLockError};
use hakimi_core::runtime::HakimiRuntime;
use serde_json::Value;
use slint::{Color, Model, ModelRc, SharedString, VecModel};
use ui_state::SettlePhase;

slint::include_modules!();

mod model;
mod ui_state;

#[cfg(any(debug_assertions, feature = "dev-shot", test))]
pub(crate) use model::build_snapshot;
#[cfg(test)]
pub(crate) use model::icon_key_for;
pub(crate) use model::{
    build_sites, builtin_group_ids, finish_snapshot, format_route, normalize_domain_host,
    parse_route, route_from_preset, route_preset_index, text, SiteData, SweepState,
};

pub(crate) fn data_dir() -> Option<PathBuf> {
    std::env::var_os("HAKIMI_DATA_DIR").map(PathBuf::from)
}

/// The window is a fixed light (Acrylic/Fluent) surface, so keep the macOS title bar
/// in the same appearance even when the system is in dark mode.
#[cfg(target_os = "macos")]
fn use_light_appearance() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSAppearance, NSAppearanceNameAqua, NSApplication};

    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    if let Some(appearance) = unsafe { NSAppearance::appearanceNamed(NSAppearanceNameAqua) } {
        app.setAppearance(Some(&appearance));
    }
}

#[cfg(not(target_os = "macos"))]
fn use_light_appearance() {}

/// Raise the app after a tray click. AppKit only activates the app when the
/// click lands on its own window or menu, so a background app stays behind
/// whatever else is on screen.
#[cfg(target_os = "macos")]
fn activate_app() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSApplication;

    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);
}

#[cfg(not(target_os = "macos"))]
fn activate_app() {}

/// Bring the main window back to the front. A minimized window is still
/// "shown" as far as Slint is concerned, so `show()` alone is a no-op: the
/// minimized state has to be dropped first.
fn reveal_window(app: &AppWindow) {
    let window = app.window();
    window.set_minimized(false);
    let _ = window.show();
    activate_app();
}

fn color(hex: &str) -> Color {
    let value = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0x88_88_88);
    Color::from_argb_encoded(0xFF00_0000 | value)
}
// Plain-data snapshots cross the thread boundary; Slint types are built on the UI thread.

fn build_site_entry(site: &SiteData) -> SiteEntry {
    let domains: Vec<DomainEntry> = site
        .domains
        .iter()
        .map(|row| DomainEntry {
            host: SharedString::from(row.host.clone()),
            status: SharedString::from(row.status.clone()),
            status_color: color(row.status_hex),
            latency: SharedString::from(row.latency.clone()),
        })
        .collect();
    SiteEntry {
        id: SharedString::from(site.id.clone()),
        name: SharedString::from(site.name.clone()),
        icon: ASSETS
            .with(|assets| assets.borrow().get(&site.icon_key).cloned())
            .unwrap_or_default(),
        initial: SharedString::from(site.initial.clone()),
        tile_color: color(site.tile_hex),
        summary: SharedString::from(site.summary.clone()),
        summary_color: color(site.summary_hex),
        enabled: site.enabled,
        open: site.open,
        first: site.first,
        last: site.last,
        url: SharedString::from(site.url.clone()),
        custom: site.custom,
        domains: ModelRc::new(VecModel::from(domains)),
    }
}

thread_local! {
    // The tray lives for the whole process; dropping the handle would remove
    // the platform icon while the app keeps running.
    static TRAY: std::cell::RefCell<Option<TrayRoot>> = const { std::cell::RefCell::new(None) };
    static ASSETS: std::cell::RefCell<HashMap<String, slint::Image>> =
        std::cell::RefCell::new(HashMap::new());
    // Persistent models live on the UI thread so refreshes can be per-row:
    // unchanged rows keep their identity, so hover state, running animations
    // and the scroll position all survive, and no-op snapshots cost nothing.
    static SITES_MODEL: std::cell::RefCell<Option<Rc<VecModel<SiteEntry>>>> =
        const { std::cell::RefCell::new(None) };
    static PREV_STATE: std::cell::RefCell<Option<UiState>> =
        const { std::cell::RefCell::new(None) };
    // The window exists only while it is shown. Closing it drops the component
    // and its renderer; the tray rebuilds a fresh one from the same runtime.
    static WINDOW: std::cell::RefCell<Option<WindowShell>> =
        const { std::cell::RefCell::new(None) };
    static NEXT_WINDOW_ID: Cell<u64> = const { Cell::new(0) };
    // Rows of the currently open site editor. Slint models are not mutable from
    // the UI, so callbacks mutate this VecModel and the view re-renders.
    static EDITOR_ROWS: RefCell<Option<Rc<VecModel<EditorDomain>>>> =
        const { RefCell::new(None) };
    // UI state that must survive a window rebuild.
    static PAGE_STATE: Cell<i32> = const { Cell::new(0) };
    static SITES_EXPANDED_STATE: Cell<bool> = const { Cell::new(false) };
    static WINDOW_STATE: std::cell::RefCell<Option<(slint::PhysicalPosition, slint::PhysicalSize)>> =
        const { std::cell::RefCell::new(None) };
}

struct WindowShell {
    app: AppWindow,
    /// Keeps the visible window fresh; dropped together with the window. The
    /// field is never read: holding it is what keeps the timer registered.
    _timer: slint::Timer,
    id: u64,
    /// Set by the timer when the close transition has been handled. A tray
    /// click that races the queued drop rebuilds instead of revealing a
    /// window that is about to disappear.
    closing: Rc<Cell<bool>>,
}

/// Everything a window (re)build needs from the process.
#[derive(Clone)]
struct UiContext {
    runtime: Arc<HakimiRuntime>,
    spawner: tokio::runtime::Handle,
    expanded: Rc<std::cell::RefCell<HashSet<String>>>,
    sweep: Arc<SweepState>,
}

/// Wires every window callback. Called for the initial window and again each
/// time the tray recreates it after a close, so no callback may capture the
/// window by value.
fn wire_window(app: &AppWindow, ctx: &UiContext) {
    let runtime = ctx.runtime.clone();
    let spawner = ctx.spawner.clone();
    let expanded = ctx.expanded.clone();
    let sweep = ctx.sweep.clone();

    // -- callbacks: direct calls, applied in the same frame --
    {
        let weak = app.as_weak();
        app.on_open_fix(move || {
            // Remember the manual visit in the model: the periodic environment
            // sync derives the page from state and would otherwise slam it shut
            // on the very next tick.
            MODEL.with(|m| m.borrow_mut().open_fix());
            if let Some(app) = weak.upgrade() {
                MODEL.with(|m| ui_state::sync_window(&m.borrow(), &app));
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_toggle_master(move || {
            // Turning acceleration on with nothing selected would claim to run
            // an empty set. Leave the switch off; the subtitle explains why.
            let turning_on = MODEL.with(|m| m.borrow().accel() != ui_state::AccelState::Running);
            if turning_on && !runtime.config().snapshot().groups.iter().any(|g| g.enabled) {
                return;
            }
            // Use the last known environment (fresh within a second of the
            // probe stream) so the click never waits on a subprocess.
            let effects = MODEL.with(|m| {
                let env = m.borrow().env().clone();
                m.borrow_mut().toggle(env)
            });
            ui_state::execute(&effects, &runtime);
            if let Some(app) = weak.upgrade() {
                MODEL.with(|m| ui_state::sync_window(&m.borrow(), &app));
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_toggle_group(move |id, enabled| {
            // Selection only changes the acceleration set. Probing is an
            // explicit action ("检测选中"), never a side effect of a checkbox.
            let _ = runtime.set_group_enabled(id.as_str(), enabled);
            if let Some(app) = weak.upgrade() {
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_select_all(move |enabled| {
            // Select-all only changes the set; it never starts a test.
            let _ = runtime.config().mutate(|config| {
                for group in &mut config.groups {
                    group.enabled = enabled;
                }
                Ok(())
            });
            if !enabled {
                // Nothing is selected: stop claiming acceleration.
                let effects = MODEL.with(|m| m.borrow_mut().stop());
                ui_state::execute(&effects, &runtime);
            }
            if let Some(app) = weak.upgrade() {
                MODEL.with(|m| ui_state::sync_window(&m.borrow(), &app));
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_toggle_open(move |id| {
            let mut set = expanded.borrow_mut();
            let id = id.to_string();
            if !set.remove(&id) {
                set.insert(id);
            }
            drop(set);
            if let Some(app) = weak.upgrade() {
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
        });
    }
    {
        let runtime = runtime.clone();
        let spawner = spawner.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_probe_selected(move || {
            // One atomic sweep on the runtime: the UI only flips the phase and
            // awaits completion, no per-domain bookkeeping here.
            sweep.running.store(true, Ordering::SeqCst);
            if let Some(app) = weak.upgrade() {
                // Flip the rows to 检测中 now; the sweep runs off-thread.
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
            let runtime = runtime.clone();
            let done = sweep.clone();
            spawner.spawn(async move {
                runtime.probe_sweep().await;
                done.running.store(false, Ordering::SeqCst);
                done.commit_once.store(true, Ordering::SeqCst);
            });
        });
    }
    {
        let runtime = runtime.clone();
        let weak = app.as_weak();
        app.on_finish_onboarding(move || {
            let effects = MODEL.with(|m| m.borrow_mut().dismiss_fix());
            ui_state::execute(&effects, &runtime);
            if let Some(app) = weak.upgrade() {
                MODEL.with(|m| ui_state::sync_window(&m.borrow(), &app));
            }
        });
    }
    {
        let runtime = runtime.clone();
        app.on_reapply_proxy(move || {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                if let Err(error) = runtime.apply_system_proxy() {
                    eprintln!("hakimi-ui: manual system proxy re-apply failed: {error:#}");
                }
            });
        });
    }
    app.on_open_site(|url| {
        std::thread::spawn(move || {
            let _ = open::that(url.to_string());
        });
    });
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_settings_action(move |kind| {
            let Some(app) = weak.upgrade() else { return };
            // Installing may raise a system password prompt; keep that off the
            // UI thread. The outcome is posted back as one of three short
            // states, so a dismissed dialog can never read as success.
            app.set_ca_busy(true);
            app.set_ca_action_error(SharedString::new());
            app.set_ob_installing(true);
            tracing::info!(kind, "ca action requested");

            let runtime = runtime.clone();
            // The expanded-row set is an Rc owned by the UI thread; carry a
            // plain copy across so the refresh keeps the same rows open.
            let open_ids: Vec<String> = expanded.borrow().iter().cloned().collect();
            let weak = app.as_weak();
            let sweep = sweep.clone();
            std::thread::spawn(move || {
                let started = std::time::Instant::now();
                let outcome = match kind {
                    1 => ca_outcome(runtime.ca_install().map(|status| status.installed), true),
                    2 => ca_outcome(runtime.ca_uninstall().map(|status| status.installed), false),
                    3 => ca_outcome(runtime.ca_repair().map(|status| status.installed), true),
                    _ => CaOutcome::Done,
                };
                tracing::info!(
                    kind,
                    outcome = ?outcome,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "ca action finished"
                );
                let message = outcome.message();
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(app) = weak.upgrade() else { return };
                    app.set_ca_busy(false);
                    app.set_ob_installing(false);
                    if let Some(message) = message {
                        app.set_ca_action_error(SharedString::from(message));
                    }
                    // Re-read the trust state now instead of waiting a tick.
                    let open: HashSet<String> = open_ids.into_iter().collect();
                    refresh(&app, &runtime, &open, &sweep);
                });
            });
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_save_string(move |key, value| {
            let key = key.to_string();
            let value = value.trim().to_string();
            let error = apply_setting_string(&runtime, &key, &value);
            if let Some(app) = weak.upgrade() {
                let failed = error.is_some();
                app.set_cfg_error(SharedString::from(error.unwrap_or_default()));
                // Lets the offending field draw a red border instead of only
                // showing a message at the bottom of the page.
                app.set_cfg_error_key(SharedString::from(if failed {
                    key.clone()
                } else {
                    String::new()
                }));
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            }
        });
    }
    {
        let runtime = runtime.clone();
        app.on_open_data_dir(move || {
            let dir = runtime.paths().root().to_path_buf();
            std::thread::spawn(move || {
                let _ = open::that(dir);
            });
        });
    }
    {
        let runtime = runtime.clone();
        let weak = app.as_weak();
        app.on_open_editor(move |id| {
            let Some(app) = weak.upgrade() else { return };
            let config = runtime.config().snapshot();
            let builtins = builtin_group_ids();
            match config.group(id.as_str()) {
                Some(group) => {
                    app.set_editor_is_new(false);
                    app.set_editor_id(SharedString::from(group.id.clone()));
                    app.set_editor_name(SharedString::from(group.name.clone()));
                    set_editor_rows(
                        &app,
                        group.domains.iter().map(editor_domain_from_rule).collect(),
                    );
                    app.set_editor_homepage(SharedString::from(
                        group.homepage.clone().unwrap_or_default(),
                    ));
                    let preset = route_preset_index(&group.default_route);
                    app.set_editor_default_preset(preset);
                    app.set_editor_default_custom(SharedString::from(if preset == 4 {
                        format_route(&group.default_route)
                    } else {
                        String::new()
                    }));
                    app.set_editor_deletable(!builtins.contains(&group.id));
                }
                None => {
                    app.set_editor_is_new(true);
                    app.set_editor_id(SharedString::new());
                    app.set_editor_name(SharedString::new());
                    set_editor_rows(
                        &app,
                        vec![EditorDomain {
                            pattern: SharedString::new(),
                            route: 0,
                            route_label: SharedString::from(domain_route_label(0)),
                            sni: SharedString::new(),
                            custom: SharedString::new(),
                        }],
                    );
                    app.set_editor_homepage(SharedString::new());
                    app.set_editor_default_preset(0);
                    app.set_editor_default_custom(SharedString::new());
                    app.set_editor_deletable(false);
                }
            }
            app.set_editor_error(SharedString::new());
            app.set_editor_open(true);
        });
    }
    {
        let weak = app.as_weak();
        app.on_close_editor(move || {
            if let Some(app) = weak.upgrade() {
                app.set_editor_open(false);
                app.set_editor_error(SharedString::new());
            }
        });
    }
    app.on_editor_add_domain(|| {
        with_editor_rows(|model| {
            model.push(EditorDomain {
                pattern: SharedString::new(),
                route: 0,
                route_label: SharedString::from(domain_route_label(0)),
                sni: SharedString::new(),
                custom: SharedString::new(),
            });
        });
    });
    app.on_editor_remove_domain(|index| {
        with_editor_rows(|model| {
            if model.row_count() > 1 {
                model.remove(index.max(0) as usize);
            }
        });
    });
    app.on_editor_domain_pattern(|index, text| {
        update_editor_row(index.max(0) as usize, |row| row.pattern = text);
    });
    app.on_editor_set_domain_route(|index, route| {
        update_editor_row(index.max(0) as usize, |row| {
            row.route = route.clamp(0, 4);
            row.route_label = SharedString::from(domain_route_label(row.route));
        });
    });
    app.on_editor_domain_sni(|index, text| {
        update_editor_row(index.max(0) as usize, |row| row.sni = text);
    });
    app.on_editor_domain_custom(|index, text| {
        update_editor_row(index.max(0) as usize, |row| row.custom = text);
    });
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let sweep = sweep.clone();
        let weak = app.as_weak();
        app.on_save_editor(move || {
            let Some(app) = weak.upgrade() else { return };
            let result = save_site(&runtime, &app);
            match result {
                Ok(()) => {
                    app.set_editor_open(false);
                    app.set_editor_error(SharedString::new());
                    refresh(&app, &runtime, &expanded.borrow(), &sweep);
                }
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), "site save rejected");
                    app.set_editor_error(SharedString::from(format!("{error:#}")));
                }
            }
        });
    }
    {
        let runtime = runtime.clone();
        let expanded = expanded.clone();
        let weak = app.as_weak();
        let sweep = sweep.clone();
        app.on_delete_site(move |id| {
            let Some(app) = weak.upgrade() else { return };
            match runtime.remove_group(id.as_str()) {
                Ok(_) => {
                    tracing::info!(id = %id, "site removed");
                    app.set_editor_open(false);
                    app.set_editor_error(SharedString::new());
                    refresh(&app, &runtime, &expanded.borrow(), &sweep);
                }
                Err(error) => app.set_editor_error(SharedString::from(format!("{error:#}"))),
            }
        });
    }
}

/// Builds a window and its 1-second refresh timer. The shell owns both; when
/// the user closes the window the component is dropped, releasing the renderer
/// and every UI allocation while the proxy runtime keeps running.
fn build_window(ctx: &UiContext) -> Result<WindowShell> {
    let app = AppWindow::new()?;
    load_assets();
    app.set_cfg_data_dir(SharedString::from(
        ctx.runtime.paths().root().display().to_string(),
    ));
    app.set_cfg_version(SharedString::from(env!("CARGO_PKG_VERSION")));

    wire_window(&app, ctx);

    // Restore the UI state the previous window left behind.
    app.set_page(PAGE_STATE.with(Cell::get));
    app.set_sites_expanded(SITES_EXPANDED_STATE.with(Cell::get));
    if let Some((position, size)) = WINDOW_STATE.with(|slot| slot.borrow().as_ref().cloned()) {
        app.window().set_position(position);
        app.window().set_size(size);
    }

    MODEL.with(|m| ui_state::sync_window(&m.borrow(), &app));
    refresh(&app, &ctx.runtime, &ctx.expanded.borrow(), &ctx.sweep);

    let id = NEXT_WINDOW_ID.with(|next| {
        let id = next.get() + 1;
        next.set(id);
        id
    });
    let closing = Rc::new(Cell::new(false));
    let timer = slint::Timer::default();
    {
        let weak = app.as_weak();
        let runtime = ctx.runtime.clone();
        let expanded = ctx.expanded.clone();
        let sweep = ctx.sweep.clone();
        let closing = closing.clone();
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(1000),
            move || {
                let Some(app) = weak.upgrade() else {
                    return;
                };
                let window = app.window();
                if window.is_minimized() {
                    // A minimized window keeps its taskbar entry and state;
                    // there is nothing to paint, so just skip the refresh.
                    return;
                }
                if !window.is_visible() {
                    if !closing.replace(true) {
                        // Closed to the tray: remember the window geometry and
                        // the UI state, then free the rows/caches. The
                        // component itself is dropped after this callback
                        // returns; the runtime and the tray stay alive.
                        PAGE_STATE.with(|page| page.set(app.get_page()));
                        SITES_EXPANDED_STATE.with(|flag| flag.set(app.get_sites_expanded()));
                        WINDOW_STATE.with(|slot| {
                            *slot.borrow_mut() = Some((window.position(), window.size()));
                        });
                        release_ui_caches(&app);
                        let _ = slint::invoke_from_event_loop(move || {
                            WINDOW.with(|slot| {
                                // A tray click may have raced the drop and
                                // built a newer window; never clear that one.
                                let stale =
                                    slot.borrow().as_ref().is_some_and(|shell| shell.id == id);
                                if stale {
                                    *slot.borrow_mut() = None;
                                }
                            });
                        });
                    }
                    return;
                }
                refresh(&app, &runtime, &expanded.borrow(), &sweep);
            },
        );
    }
    Ok(WindowShell {
        app,
        _timer: timer,
        id,
        closing,
    })
}

/// Sidebar counters for the desktop layout.
fn set_stats(app: &AppWindow, sites: &[SiteData]) {
    let domains: usize = sites.iter().map(|site| site.domains.len()).sum();
    let slow = sites
        .iter()
        .flat_map(|site| &site.domains)
        .filter(|domain| domain.status == "较慢")
        .count();
    let bad = sites
        .iter()
        .flat_map(|site| &site.domains)
        .filter(|domain| domain.status == "超时")
        .count();
    app.set_stat_sites(SharedString::from(format!("{}", sites.len())));
    app.set_stat_enabled(SharedString::from(format!(
        "{}",
        sites.iter().filter(|site| site.enabled).count()
    )));
    app.set_stat_domains(SharedString::from(format!("{domains}")));
    app.set_stat_slow(SharedString::from(format!("{slow}")));
    app.set_stat_bad(SharedString::from(format!("{bad}")));
}

/// The plain-data snapshot used to decide whether the UI needs touching at all.
#[derive(Clone, PartialEq)]
struct UiState {
    sites: Vec<SiteData>,
    subtitle: String,
    sites_summary: String,
    running: bool,
    ca: (bool, bool, bool),
    settings: SettingsValues,
}

/// Applies a snapshot to the window, updating only what actually changed.
/// The snapshot is consumed (moved) so an unchanged tick costs one comparison
/// and zero clones.
fn apply_ui_update(
    app: &AppWindow,
    sites: Vec<SiteData>,
    subtitle: String,
    running: bool,
    ca: (bool, bool, bool),
    settings: SettingsValues,
) {
    let sites_summary = format!(
        "{} 个 · 已启用 {}",
        sites.len(),
        sites.iter().filter(|site| site.enabled).count()
    );
    let unchanged = PREV_STATE.with(|slot| {
        slot.borrow().as_ref().is_some_and(|prev| {
            prev.sites == sites
                && prev.subtitle == subtitle
                && prev.sites_summary == sites_summary
                && prev.running == running
                && prev.ca == ca
                && prev.settings == settings
        })
    });
    if unchanged {
        return;
    }

    let prev = PREV_STATE.with(|slot| slot.borrow_mut().take());
    let prev_sites: Option<&[SiteData]> = prev.as_ref().map(|state| state.sites.as_slice());
    if prev_sites != Some(sites.as_slice()) {
        SITES_MODEL.with(|cell| {
            let mut slot = cell.borrow_mut();
            let model = slot.get_or_insert_with(|| {
                let model = Rc::new(VecModel::default());
                app.set_sites(ModelRc::new(model.clone()));
                model
            });
            match prev_sites {
                Some(old) if old.len() == sites.len() => {
                    for index in 0..sites.len() {
                        if old[index] != sites[index] {
                            model.set_row_data(index, build_site_entry(&sites[index]));
                        }
                    }
                }
                _ => {
                    let entries: Vec<SiteEntry> = sites.iter().map(build_site_entry).collect();
                    model.set_vec(entries);
                }
            }
        });
    }

    // Settings text fields only get written when the underlying value actually
    // changed, so a half-typed input is never clobbered by the refresh tick.
    if prev.as_ref().map(|state| &state.settings) != Some(&settings) {
        let old = prev.as_ref().map(|state| &state.settings);
        let changed = |pick: fn(&SettingsValues) -> &String| {
            old.is_none_or(|prev| pick(prev) != pick(&settings))
        };
        if changed(|s| &s.proxy_port) {
            app.set_cfg_proxy_port(SharedString::from(settings.proxy_port.clone()));
        }
        if changed(|s| &s.doh_primary) {
            app.set_cfg_doh_primary(SharedString::from(settings.doh_primary.clone()));
        }
        if changed(|s| &s.doh_fallback) {
            app.set_cfg_doh_fallback(SharedString::from(settings.doh_fallback.clone()));
        }
        if changed(|s| &s.catalog_ip) {
            app.set_cfg_catalog_ip(SharedString::from(settings.catalog_ip.clone()));
        }
        if changed(|s| &s.catalog_doh) {
            app.set_cfg_catalog_doh(SharedString::from(settings.catalog_doh.clone()));
        }
    }

    if prev.as_ref().map(|state| state.ca) != Some(ca) {
        app.set_ca_installed(ca.2);
    }

    if prev.as_ref().map(|state| state.running) != Some(running) {
        app.set_running(running);
        TRAY.with(|tray| {
            if let Some(tray) = tray.borrow().as_ref() {
                tray.set_running(running);
            }
        });
    }
    if prev.as_ref().map(|state| state.subtitle.as_str()) != Some(subtitle.as_str()) {
        app.set_status_subtitle(SharedString::from(subtitle.clone()));
    }
    if prev.as_ref().map(|state| state.sites_summary.as_str()) != Some(sites_summary.as_str()) {
        app.set_sites_summary(SharedString::from(sites_summary.clone()));
    }
    // Sidebar counters. Cheap to write, and they only move when a probe lands.
    set_stats(app, &sites);

    PREV_STATE.with(|slot| {
        *slot.borrow_mut() = Some(UiState {
            sites,
            subtitle,
            sites_summary,
            running,
            ca,
            settings,
        });
    });
}

/// Drops the rows and snapshots only the hidden window owns. The proxy's
/// memory is deliberately left alone: forcing the process working set out
/// would page out its hot code and connection state, hurt live traffic, and
/// still not reduce committed memory. These UI structures really are
/// disposable and are rebuilt from the runtime on the next visible tick.
fn release_ui_caches(app: &AppWindow) {
    SITES_MODEL.with(|cell| {
        if let Some(model) = cell.borrow_mut().take() {
            model.set_vec(Vec::new());
        }
    });
    app.set_sites(ModelRc::new(VecModel::default()));
    PREV_STATE.with(|slot| *slot.borrow_mut() = None);
    REFRESH_CACHE.with(|slot| *slot.borrow_mut() = None);
    CONFIG_CACHE.with(|slot| *slot.borrow_mut() = None);
    ASSETS.with(|assets| assets.borrow_mut().clear());
}

/// Site logos are embedded in the executable. `CARGO_MANIFEST_DIR` is an
/// absolute path on the build machine, so loading them from disk would fail
/// once the binary is copied to another machine.
const ICON_ASSETS: [(&str, &[u8]); 9] = [
    ("pixiv", include_bytes!("../assets/pixiv.png")),
    ("hitomi", include_bytes!("../assets/hitomi.png")),
    ("poipiku", include_bytes!("../assets/poipiku.png")),
    ("booth", include_bytes!("../assets/booth.png")),
    ("steam", include_bytes!("../assets/steam.png")),
    ("github", include_bytes!("../assets/github.png")),
    ("ao3", include_bytes!("../assets/ao3.png")),
    ("eh", include_bytes!("../assets/eh.png")),
    ("hanime", include_bytes!("../assets/hanime.png")),
];

pub(crate) fn load_assets() {
    ASSETS.with(|assets| {
        let mut map = assets.borrow_mut();
        for &(key, bytes) in &ICON_ASSETS {
            if let Ok(image) = slint::Image::load_from_data(bytes, Some("png")) {
                map.insert(key.to_string(), image);
            }
        }
    });
}

/// Settings values pushed into the window. Text fields keep the raw string so
/// the user can type freely; validation happens on commit.
#[derive(Clone, PartialEq)]
pub(crate) struct SettingsValues {
    pub proxy_port: String,
    pub doh_primary: String,
    pub doh_fallback: String,
    pub catalog_ip: String,
    pub catalog_doh: String,
}

pub(crate) fn settings_values(config: &Value) -> SettingsValues {
    let field = |section: &str, key: &str| {
        config
            .get(section)
            .map(|value| text(value, key))
            .unwrap_or_default()
    };
    SettingsValues {
        proxy_port: field("proxy", "port"),
        doh_primary: field("doh", "primary"),
        doh_fallback: field("doh", "fallback"),
        catalog_ip: field("catalogs", "ip"),
        catalog_doh: field("catalogs", "doh"),
    }
}

// -- settings writes ------------------------------------------------------------

/// Commit one text setting. Returns `Some(error)` when the value was rejected;
/// the refresh tick then restores the field to the stored value.
fn apply_setting_string(runtime: &HakimiRuntime, key: &str, value: &str) -> Option<String> {
    let result = runtime.config().mutate(|config| {
        match key {
            "proxy.port" => {
                let port: u16 = value
                    .parse()
                    .ok()
                    .filter(|port| *port != 0)
                    .context("端口需为 1–65535 的数字")?;
                config.proxy.port = port;
            }
            "doh.primary" => config.doh.primary = value.to_string(),
            "doh.fallback" => config.doh.fallback = value.to_string(),
            "catalogs.ip" => config.catalogs.ip = value.to_string(),
            "catalogs.doh" => config.catalogs.doh = value.to_string(),
            other => bail!("未知设置项 {other}"),
        }
        Ok(())
    });
    match result {
        Ok(_) => {
            // Bind/port changes land on the next launch: the running proxy is
            // already bound and the PAC points at the live address.
            None
        }
        Err(error) => Some(format!("{error:#}")),
    }
}

/// How a CA action ended. The UI only shows these three states — no stderr,
/// no password diagnostics; the user just needs to know whether it worked.
#[derive(Clone, Copy, PartialEq, Debug)]
enum CaOutcome {
    Done,
    Cancelled,
    Failed,
}

impl CaOutcome {
    fn message(self) -> Option<&'static str> {
        match self {
            CaOutcome::Done => None,
            CaOutcome::Cancelled => Some("已取消，未做更改"),
            CaOutcome::Failed => Some("未成功，请重试"),
        }
    }
}

/// Judge an install/uninstall/repair by what the trust store says afterwards,
/// not by the exit status: `security` can report success after a dismissed
/// dialog, and a leftover trusted copy would still verify.
fn ca_outcome(result: Result<bool>, want_installed: bool) -> CaOutcome {
    match result {
        Ok(installed) if installed == want_installed => CaOutcome::Done,
        Ok(_) => CaOutcome::Failed,
        Err(error) => {
            let text = format!("{error:#}").to_ascii_lowercase();
            if text.contains("cancel") {
                CaOutcome::Cancelled
            } else {
                CaOutcome::Failed
            }
        }
    }
}

// -- site editor ----------------------------------------------------------------

/// Site editor input, kept independent of Slint so it can be unit tested.
#[derive(Clone)]
struct DomainDraft {
    pattern: String,
    /// 0 inherit, 1 direct, 2 ECH, 3 SNI, 4 custom.
    preset: i32,
    sni: String,
    custom: String,
}

struct SiteDraft {
    id: String,
    is_new: bool,
    name: String,
    domains: Vec<DomainDraft>,
    homepage: String,
    /// 0 auto, 1 direct, 2 ECH, 3 SNI, 4 custom.
    default_preset: i32,
    default_custom: String,
}

fn domain_route_label(preset: i32) -> &'static str {
    match preset {
        1 => "直连",
        2 => "ECH",
        3 => "SNI 伪装",
        4 => "自定义",
        _ => "继承默认",
    }
}

/// Recognize the preset-shaped fake-SNI routes; anything else stays custom so
/// the editor never silently rewrites a hand-written attempt list.
fn domain_sni_hosts(route: &RoutePolicy) -> Option<Vec<String>> {
    match route.attempts.as_slice() {
        [RouteAttempt::Sni { sni }] => Some(sni.clone()),
        [RouteAttempt::Sni { sni }, RouteAttempt::Direct] => Some(sni.clone()),
        _ => None,
    }
}

fn editor_domain_from_rule(rule: &DomainRule) -> EditorDomain {
    let (preset, sni, custom) = match &rule.route {
        None => (0, String::new(), String::new()),
        Some(route) if route == &RoutePolicy::direct() => (1, String::new(), String::new()),
        Some(route) if route == &RoutePolicy::ech_shared() => (2, String::new(), String::new()),
        Some(route) => match domain_sni_hosts(route) {
            Some(hosts) => (3, hosts.join(", "), String::new()),
            None => (4, String::new(), format_route(route)),
        },
    };
    EditorDomain {
        pattern: rule.pattern.clone().into(),
        route: preset,
        route_label: domain_route_label(preset).into(),
        sni: sni.into(),
        custom: custom.into(),
    }
}

fn set_editor_rows(app: &AppWindow, rows: Vec<EditorDomain>) {
    let model = Rc::new(VecModel::from(rows));
    app.set_editor_domain_rows(ModelRc::from(model.clone()));
    EDITOR_ROWS.with(|cell| *cell.borrow_mut() = Some(model));
}

fn with_editor_rows(f: impl FnOnce(&VecModel<EditorDomain>)) {
    EDITOR_ROWS.with(|cell| {
        if let Some(model) = cell.borrow().as_ref() {
            f(model);
        }
    });
}

fn update_editor_row(index: usize, update: impl FnOnce(&mut EditorDomain)) {
    with_editor_rows(|model| {
        if let Some(mut row) = model.row_data(index) {
            update(&mut row);
            model.set_row_data(index, row);
        }
    });
}

fn editor_rows_snapshot() -> Vec<DomainDraft> {
    EDITOR_ROWS.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|model| {
                (0..model.row_count())
                    .filter_map(|index| model.row_data(index))
                    .map(|row| DomainDraft {
                        pattern: row.pattern.to_string(),
                        preset: row.route,
                        sni: row.sni.to_string(),
                        custom: row.custom.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    })
}

fn parse_sni_hosts(raw: &str) -> Result<Vec<String>> {
    raw.split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(|host| {
            hakimi_core::domain::normalize_hostname(host)
                .map(|host| host.to_ascii_lowercase())
                .with_context(|| format!("SNI 主机 {host} 格式不正确"))
        })
        .collect()
}

fn build_group(config: &AppConfig, draft: &SiteDraft) -> Result<GroupConfig> {
    let mut domains: Vec<DomainRule> = Vec::new();
    for row in &draft.domains {
        let pattern = normalize_domain_host(&row.pattern)?;
        if domains.iter().any(|rule| rule.pattern == pattern) {
            continue;
        }
        let route = match row.preset {
            0 => None,
            1 => Some(RoutePolicy::direct()),
            2 => Some(RoutePolicy::ech_shared()),
            3 => Some(RoutePolicy::sni(parse_sni_hosts(&row.sni)?)),
            4 => Some(parse_route(&row.custom)?),
            _ => None,
        };
        domains.push(DomainRule { pattern, route });
    }
    if domains.is_empty() {
        bail!("请至少填写一个域名");
    }
    if !domains.iter().any(|rule| !rule.pattern.starts_with("*.")) {
        bail!("至少需要一个精确域名（不能只有 *. 通配）");
    }
    for other in &config.groups {
        if !draft.is_new && other.id == draft.id {
            continue;
        }
        if let Some(conflict) = domains.iter().find(|rule| {
            other
                .domains
                .iter()
                .any(|existing| existing.pattern.eq_ignore_ascii_case(&rule.pattern))
        }) {
            bail!("域名 {} 已属于站点「{}」", conflict.pattern, other.name);
        }
    }
    let default_route = if draft.default_preset == 4 {
        parse_route(&draft.default_custom)?
    } else {
        route_from_preset(draft.default_preset).unwrap_or_default()
    };
    let name = if draft.name.trim().is_empty() {
        domains[0].pattern.clone()
    } else {
        draft.name.trim().to_string()
    };
    let homepage = match draft.homepage.trim() {
        "" => None,
        raw => {
            let candidate = if raw.contains("://") {
                raw.to_string()
            } else {
                format!("https://{raw}")
            };
            hakimi_core::config::validate_catalog_url(&candidate, "访问地址")
                .with_context(|| "访问地址格式不正确")?;
            Some(candidate)
        }
    };

    let existing = if draft.is_new {
        None
    } else {
        config.group(&draft.id).cloned()
    };
    let mut group = existing.unwrap_or_default();
    group.id = if draft.is_new {
        unique_group_id(config, &domains[0].pattern)
    } else {
        draft.id.clone()
    };
    group.name = name;
    group.domains = domains;
    group.homepage = homepage;
    group.default_route = default_route;
    if draft.is_new {
        group.enabled = true;
    }
    Ok(group)
}

/// Read the editor fields and persist the group.
fn save_site(runtime: &HakimiRuntime, app: &AppWindow) -> Result<()> {
    let draft = SiteDraft {
        id: app.get_editor_id().to_string(),
        is_new: app.get_editor_is_new(),
        name: app.get_editor_name().to_string(),
        domains: editor_rows_snapshot(),
        homepage: app.get_editor_homepage().to_string(),
        default_preset: app.get_editor_default_preset(),
        default_custom: app.get_editor_default_custom().to_string(),
    };
    let config = runtime.config().snapshot();
    let group = build_group(&config, &draft)?;
    tracing::info!(
        id = %group.id,
        name = %group.name,
        domains = group.domains.len(),
        default_route = ?group.default_route,
        is_new = draft.is_new,
        "site saved"
    );
    runtime.upsert_group(group)?;
    Ok(())
}

/// Derive a config-safe group id from the first domain, e.g.
/// `www.example.com` -> `www-example-com`.
fn unique_group_id(config: &hakimi_core::config::AppConfig, domain: &str) -> String {
    let base: String = domain
        .trim_start_matches("*.")
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let base = base.trim_matches('-').to_string();
    let base = if base.is_empty() {
        "site".to_string()
    } else {
        base.chars().take(48).collect()
    };
    if config.group(&base).is_none() {
        return base;
    }
    for suffix in 2..1000 {
        let candidate = format!("{base}-{suffix}");
        if config.group(&candidate).is_none() {
            return candidate;
        }
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    format!("{base}-{stamp}")
}

// -- offscreen rendering (development aid) ------------------------------------

#[cfg(any(debug_assertions, feature = "dev-shot"))]
fn sample_status() -> Value {
    serde_json::json!({
        "ca": { "present": true, "supported": true, "installed": false },
        "domains": [
            { "domain": "www.pixiv.net", "state": "normal", "latencyMs": 23 },
            { "domain": "i.pximg.net", "state": "normal", "latencyMs": 31 },
            { "domain": "s.pximg.net", "state": "normal", "latencyMs": 44 },
            { "domain": "booth.pximg.net", "state": "normal", "latencyMs": 38 },
            { "domain": "novel.pixiv.net", "state": "normal", "latencyMs": 52 },
            { "domain": "e-hentai.org", "state": "normal", "latencyMs": 48 },
            { "domain": "forums.e-hentai.org", "state": "normal", "latencyMs": 212 },
            { "domain": "exhentai.org", "state": "normal", "latencyMs": 61 },
            { "domain": "hitomi.la", "state": "normal", "latencyMs": 95 },
            { "domain": "ltn.gold-usergeneratedcontent.net", "state": "failed" },
            { "domain": "github.com", "state": "normal", "latencyMs": 120 },
            { "domain": "raw.githubusercontent.com", "state": "normal", "latencyMs": 145 },
            { "domain": "api.github.com", "state": "normal", "latencyMs": 132 },
            { "domain": "ao3.org", "state": "normal", "latencyMs": 180 },
            { "domain": "archiveofourown.org", "state": "normal", "latencyMs": 175 },
            { "domain": "steamcommunity.com", "state": "normal", "latencyMs": 88 },
            { "domain": "store.steampowered.com", "state": "normal", "latencyMs": 96 },
            { "domain": "poipiku.me", "state": "normal", "latencyMs": 71 },
            { "domain": "poipiku.art", "state": "normal", "latencyMs": 66 }
        ]
    })
}

#[cfg(any(debug_assertions, feature = "dev-shot"))]
fn sample_config() -> Value {
    serde_json::json!({
        "proxy": { "port": 8443 },
        "doh": {
            "primary": "https://doh.cleanbrowsing.org/doh/security-filter/",
            "fallback": "https://doh.applied-privacy.net/query"
        },
        "catalogs": {
            "ip": "https://gitee.com/hakimi/catalogs/ip.json",
            "doh": "https://gitee.com/hakimi/catalogs/doh.json"
        },
        "groups": [
            { "id": "pixiv", "name": "Pixiv", "enabled": true,
              "defaultRoute": { "attempts": [{ "mode": "direct" }] },
              "domains": [
                { "pattern": "www.pixiv.net", "route": { "attempts": [{ "mode": "ech", "ech": "shared" }, { "mode": "direct" }] } },
                { "pattern": "i.pximg.net", "route": { "attempts": [{ "mode": "sni", "sni": ["www.baidu.com"] }, { "mode": "direct" }] } },
                { "pattern": "s.pximg.net", "route": { "attempts": [{ "mode": "sni", "sni": ["www.baidu.com"] }, { "mode": "direct" }] } }
              ] },
            { "id": "eh", "name": "E-Hentai", "enabled": true,
              "defaultRoute": { "attempts": [{ "mode": "direct" }, { "mode": "ech", "ech": "own" }, { "mode": "sni" }] },
              "domains": [{ "pattern": "e-hentai.org" }, { "pattern": "exhentai.org" }] },
            { "id": "hitomi", "name": "Hitomi", "enabled": true,
              "defaultRoute": { "attempts": [{ "mode": "direct" }, { "mode": "ech", "ech": "own" }, { "mode": "sni" }] },
              "domains": [{ "pattern": "hitomi.la" }] },
            { "id": "github", "name": "GitHub", "enabled": true,
              "defaultRoute": { "attempts": [{ "mode": "direct" }, { "mode": "ech", "ech": "own" }, { "mode": "sni" }] },
              "domains": [{ "pattern": "github.com" }, { "pattern": "raw.githubusercontent.com" }] },
            { "id": "ao3", "name": "AO3", "enabled": true,
              "defaultRoute": { "attempts": [{ "mode": "ech", "ech": "shared" }, { "mode": "direct" }] },
              "domains": [{ "pattern": "archiveofourown.org" }] },
            { "id": "steam", "name": "Steam", "enabled": true,
              "defaultRoute": { "attempts": [{ "mode": "direct" }, { "mode": "ech", "ech": "own" }, { "mode": "sni" }] },
              "domains": [{ "pattern": "steamcommunity.com" }, { "pattern": "store.steampowered.com" }] },
            { "id": "poipiku", "name": "Poipiku", "enabled": true,
              "defaultRoute": { "attempts": [{ "mode": "direct" }] },
              "domains": [{ "pattern": "poipiku.com" }] }
        ]
    })
}

/// Renders the window into a raw RGBA file so the layout can be reviewed
/// without a display. Usage: `hakimi-ui --shot <prefix> [--page N] [--running]`.
#[cfg(any(debug_assertions, feature = "dev-shot"))]
fn shot(prefix: &str, page: i32, running: bool) -> Result<()> {
    use_light_appearance();
    let app = AppWindow::new()?;
    load_assets();

    let status = sample_status();
    let config = sample_config();
    let mut expanded = HashSet::new();
    if page == 0 {
        expanded.insert("pixiv".to_string());
    }

    let (sites, subtitle) = build_snapshot(&status, &config, &expanded, running, false, None);
    let entries: Vec<SiteEntry> = sites.iter().map(build_site_entry).collect();
    let ca = &status["ca"];
    let settings = settings_values(&config);

    app.set_sites(ModelRc::new(VecModel::from(entries)));
    app.set_cfg_proxy_port(SharedString::from(settings.proxy_port.clone()));
    app.set_cfg_doh_primary(SharedString::from(settings.doh_primary.clone()));
    app.set_cfg_doh_fallback(SharedString::from(settings.doh_fallback.clone()));
    app.set_cfg_catalog_ip(SharedString::from(settings.catalog_ip.clone()));
    app.set_cfg_catalog_doh(SharedString::from(settings.catalog_doh.clone()));
    app.set_cfg_data_dir(SharedString::from("~/Library/Application Support/hakimi"));
    app.set_cfg_version(SharedString::from(env!("CARGO_PKG_VERSION")));
    app.set_status_subtitle(SharedString::from(subtitle));
    app.set_running(running);
    app.set_page(page);
    // Offscreen states for reviewing the environment-check UI.
    let broken = std::env::var("HAKIMI_UI_BROKEN").is_ok();
    let fix_page = std::env::var("HAKIMI_UI_FIXPAGE").is_ok();
    app.set_ca_installed(
        !broken
            && !fix_page
            && ca
                .get("installed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
    );
    if broken || fix_page {
        app.set_ca_error(SharedString::from("已导入，但尚未受信任"));
    }
    app.set_show_onboarding(fix_page || std::env::var("HAKIMI_UI_FIXMANUAL").is_ok());
    app.set_fix_blocked(fix_page);
    if let Ok(message) = std::env::var("HAKIMI_UI_CA_ERROR") {
        app.set_ca_action_error(SharedString::from(message));
    }
    if std::env::var("HAKIMI_UI_CA_BUSY").is_ok() {
        app.set_ca_busy(true);
    }
    app.set_sites_summary(SharedString::from(format!(
        "{} 个 · 已启用 {}",
        sites.len(),
        sites.iter().filter(|site| site.enabled).count()
    )));
    set_stats(&app, &sites);
    if std::env::var("HAKIMI_UI_SITES").is_ok() {
        app.set_sites_expanded(true);
    }
    match std::env::var("HAKIMI_UI_EDITOR").as_deref() {
        Ok("new") => {
            app.set_editor_is_new(true);
            set_editor_rows(
                &app,
                vec![EditorDomain {
                    pattern: SharedString::new(),
                    route: 0,
                    route_label: SharedString::from(domain_route_label(0)),
                    sni: SharedString::new(),
                    custom: SharedString::new(),
                }],
            );
            app.set_editor_default_preset(0);
            app.set_editor_default_custom(SharedString::new());
            app.set_editor_homepage(SharedString::new());
            app.set_editor_open(true);
        }
        Ok(_) => {
            app.set_editor_is_new(false);
            app.set_editor_id(SharedString::from("pixiv"));
            app.set_editor_name(SharedString::from("Pixiv"));
            set_editor_rows(
                &app,
                vec![
                    editor_domain_from_rule(&DomainRule::routed(
                        "pixiv.net",
                        RoutePolicy::ech_shared(),
                    )),
                    editor_domain_from_rule(&DomainRule::routed(
                        "www.pixiv.net",
                        RoutePolicy::ech_shared(),
                    )),
                    editor_domain_from_rule(&DomainRule::routed(
                        "*.pixiv.net",
                        RoutePolicy::ech_shared(),
                    )),
                    editor_domain_from_rule(&DomainRule::routed(
                        "i.pximg.net",
                        RoutePolicy::sni(vec!["www.baidu.com".into()]),
                    )),
                    editor_domain_from_rule(&DomainRule::routed(
                        "s.pximg.net",
                        RoutePolicy::sni(vec!["www.baidu.com".into()]),
                    )),
                ],
            );
            app.set_editor_default_preset(0);
            app.set_editor_default_custom(SharedString::new());
            app.set_editor_homepage(SharedString::from("https://www.pixiv.net/"));
            app.set_editor_deletable(false);
            app.set_editor_open(true);
        }
        Err(_) => {}
    }
    app.show()?;
    // let the first render pass settle
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(60));
    }

    let buffer = app.window().take_snapshot()?;
    let mut bytes = Vec::with_capacity(buffer.as_slice().len() * 4);
    for pixel in buffer.as_slice() {
        bytes.extend_from_slice(&[pixel.r, pixel.g, pixel.b, pixel.a]);
    }
    std::fs::write(format!("{prefix}.rgba"), bytes)?;
    println!(
        "wrote {prefix}.rgba ({}x{})",
        buffer.width(),
        buffer.height()
    );
    Ok(())
}

thread_local! {
    // Shared handles, not clones: the config JSON can be large and the refresh
    // path only borrows it.
    static CONFIG_CACHE: std::cell::RefCell<Option<(u64, Rc<Value>)>> =
        const { std::cell::RefCell::new(None) };
    // The last built (unsettled) site snapshot. While neither the status nor
    // the config has changed, the refresh tick reuses it instead of
    // re-serializing the whole status every second.
    static REFRESH_CACHE: std::cell::RefCell<Option<RefreshCache>> =
        const { std::cell::RefCell::new(None) };
    // The acceleration state machine lives on the UI thread.
    static MODEL: std::cell::RefCell<ui_state::AppModel> =
        std::cell::RefCell::new(ui_state::AppModel::default());
}

/// The last raw (unsettled) snapshot, keyed by everything that can change it.
/// A refresh tick that hits this reuses the rows and skips `status_json`; a
/// config-only change (enabling/disabling a site) reuses the cached status
/// JSON and rebuilds just the rows.
struct RefreshCache {
    status_revision: u64,
    config_revision: u64,
    expanded: HashSet<String>,
    status: Rc<Value>,
    raw_sites: Vec<SiteData>,
    selected: usize,
    ca: (bool, bool, bool),
    settings: SettingsValues,
}

/// Re-reads the world and applies it to the window. Runs on the UI thread on a
/// one-second timer; `apply_ui_update` diffs, and this cache keeps an idle tick
/// from rebuilding a snapshot that cannot have changed.
fn refresh(
    app: &AppWindow,
    runtime: &Arc<HakimiRuntime>,
    expanded: &HashSet<String>,
    sweep: &SweepState,
) {
    let status_revision = runtime.status_revision();
    let config_revision = runtime.config_revision();
    let running = runtime.is_started() && !runtime.status().paused();
    // Running intent without a started runtime means "still starting": the
    // summaries must not claim a stale 待检测/健康 state while the proxy is
    // coming up.
    let starting = MODEL.with(|m| m.borrow().accel()) == ui_state::AccelState::Running && !running;
    let phase = if starting {
        SettlePhase::Starting
    } else {
        sweep.phase()
    };

    // The status snapshot is the expensive part. A config-only change (a site
    // toggle) keeps the same status revision, so the cached JSON is reused and
    // only the display rows are rebuilt.
    let cached_status = REFRESH_CACHE.with(|cell| {
        let slot = cell.borrow();
        slot.as_ref()
            .filter(|cache| cache.status_revision == status_revision)
            .map(|cache| cache.status.clone())
    });

    let cached = REFRESH_CACHE.with(|cell| {
        let slot = cell.borrow();
        slot.as_ref().and_then(|cache| {
            (cache.status_revision == status_revision
                && cache.config_revision == config_revision
                && &cache.expanded == expanded)
                .then(|| {
                    (
                        cache.raw_sites.clone(),
                        cache.selected,
                        cache.ca,
                        cache.settings.clone(),
                    )
                })
        })
    });

    // Expanding or collapsing a site only flips its `open` flag. Patch the
    // cached rows instead of walking every group and domain again.
    let expanded_only = REFRESH_CACHE.with(|cell| {
        let slot = cell.borrow();
        slot.as_ref().and_then(|cache| {
            (cache.status_revision == status_revision
                && cache.config_revision == config_revision
                && cache.expanded != *expanded)
                .then(|| {
                    let mut sites = cache.raw_sites.clone();
                    for site in &mut sites {
                        site.open = expanded.contains(&site.id);
                    }
                    (sites, cache.selected, cache.ca, cache.settings.clone())
                })
        })
    });

    let (raw_sites, selected, ca_state, settings) = if let Some(hit) = expanded_only {
        REFRESH_CACHE.with(|cell| {
            if let Some(cache) = cell.borrow_mut().as_mut() {
                cache.expanded = expanded.clone();
                cache.raw_sites = hit.0.clone();
            }
        });
        hit
    } else {
        match cached {
            // Nothing the window renders has changed: reuse the rows and let
            // finish_snapshot's settle pass decide whether a pending summary
            // has been stable long enough to commit.
            Some(hit) => hit,
            None => {
                let status = cached_status.unwrap_or_else(|| Rc::new(runtime.status_json()));
                let config = cached_config(config_revision, || runtime.config_json());
                let (raw_sites, selected) = build_sites(&status, &config, expanded);
                let ca = &status["ca"];
                let ca_state = (
                    ca.get("present").and_then(Value::as_bool).unwrap_or(false),
                    ca.get("supported")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    ca.get("installed")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                );
                let settings = settings_values(&config);
                REFRESH_CACHE.with(|cell| {
                    *cell.borrow_mut() = Some(RefreshCache {
                        status_revision,
                        config_revision,
                        expanded: expanded.clone(),
                        status: status.clone(),
                        raw_sites: raw_sites.clone(),
                        selected,
                        ca: ca_state,
                        settings: settings.clone(),
                    });
                });
                (raw_sites, selected, ca_state, settings)
            }
        }
    };

    let (sites, subtitle) = finish_snapshot(raw_sites, selected, running, starting, Some(phase));
    apply_ui_update(app, sites, subtitle, running, ca_state, settings);
    // Environment state comes from the probe thread; the window already
    // mirrors the model, so there is nothing else to do here.
}

fn cached_config(revision: u64, fetch: impl FnOnce() -> Value) -> Rc<Value> {
    CONFIG_CACHE.with(|cell| {
        let mut slot = cell.borrow_mut();
        match slot.as_ref() {
            Some((cached_revision, config)) if *cached_revision == revision => config.clone(),
            _ => {
                let config = Rc::new(fetch());
                *slot = Some((revision, config.clone()));
                config
            }
        }
    })
}

fn main() -> Result<()> {
    #[cfg(any(debug_assertions, feature = "dev-shot"))]
    {
        let args: Vec<String> = std::env::args().collect();
        if let Some(index) = args.iter().position(|arg| arg == "--shot") {
            let prefix = args
                .get(index + 1)
                .cloned()
                .unwrap_or_else(|| "/tmp/hakimi-ui".into());
            let page = args
                .iter()
                .position(|arg| arg == "--page")
                .and_then(|i| args.get(i + 1))
                .and_then(|value| value.parse::<i32>().ok())
                .unwrap_or(0);
            let running = args.iter().any(|arg| arg == "--running");
            return shot(&prefix, page, running);
        }
    }

    // Single instance: a second long-running app would fight over the proxy port.
    let instance_dir = match data_dir() {
        Some(dir) => dir,
        None => hakimi_core::paths::Paths::default_location()?
            .root()
            .to_path_buf(),
    };
    let _instance_lock = match InstanceLock::acquire(&instance_dir) {
        Ok(lock) => lock,
        Err(InstanceLockError::AlreadyRunning { .. }) => {
            // Visible feedback instead of a silently dead second launch.
            let notice = AlreadyRunningWindow::new()?;
            notice.show()?;
            let timer = slint::Timer::default();
            timer.start(
                slint::TimerMode::SingleShot,
                Duration::from_millis(2500),
                || {
                    let _ = slint::quit_event_loop();
                },
            );
            notice.run()?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    use_light_appearance();

    // The runtime lives on the UI thread: every interaction is a direct
    // synchronous call, so a click applies within the same frame. Only the
    // genuinely async parts (serving the proxy, waiting for shutdown) run on a
    // dedicated tokio runtime in the background.
    let runtime = HakimiRuntime::new(data_dir())?;
    let sweep = std::sync::Arc::new(SweepState::default());

    // The state machine decides the startup posture. This one synchronous
    // probe is the only environment check on the UI thread; after this, the
    // probe thread streams results in. The proxy effects map onto the start
    // mode because they need the PAC URL, which only exists post-bind.
    let startup_effects = MODEL.with(|m| m.borrow_mut().startup(ui_state::probe_env(&runtime)));
    let start_mode = ui_state::execute_startup(&startup_effects, &runtime);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let spawner = rt.handle().clone();
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let background = {
        let runtime = runtime.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || {
            rt.block_on(async move {
                let start_result = match start_mode {
                    ui_state::StartMode::Takeover => runtime.start().await,
                    ui_state::StartMode::Deferred => runtime.start_deferring_proxy().await,
                };
                if let Err(error) = start_result {
                    eprintln!("hakimi-ui failed to start the proxy: {error:#}");
                }
                shutdown.notified().await;
                let _ = runtime.stop().await;
            });
        })
    };

    let expanded: Rc<std::cell::RefCell<HashSet<String>>> =
        Rc::new(std::cell::RefCell::new(HashSet::new()));
    if let Ok(id) = std::env::var("HAKIMI_UI_EXPAND") {
        expanded.borrow_mut().insert(id);
    }
    if std::env::var("HAKIMI_UI_PAGE").as_deref() == Ok("1") {
        PAGE_STATE.with(|page| page.set(1));
    }

    let ctx = UiContext {
        runtime: runtime.clone(),
        spawner: spawner.clone(),
        expanded: expanded.clone(),
        sweep: sweep.clone(),
    };

    // System tray: keeps the app alive with the window closed, and mirrors the
    // window actions. The tray must be created on the main thread.
    let tray = TrayRoot::new()?;
    tray.on_show_main({
        let ctx = ctx.clone();
        move || {
            let existing = WINDOW.with(|slot| {
                slot.borrow()
                    .as_ref()
                    .map(|shell| (shell.closing.clone(), shell.app.as_weak()))
            });
            if let Some((closing, weak)) = existing {
                if !closing.get() {
                    if let Some(app) = weak.upgrade() {
                        load_assets();
                        reveal_window(&app);
                        refresh(&app, &ctx.runtime, &ctx.expanded.borrow(), &ctx.sweep);
                    }
                    return;
                }
            }
            // No live window (closed to the tray, or closing): build one.
            match build_window(&ctx) {
                Ok(shell) => {
                    if let Err(error) = shell.app.show() {
                        eprintln!("hakimi-ui: showing the window failed: {error}");
                        return;
                    }
                    WINDOW.with(|slot| *slot.borrow_mut() = Some(shell));
                }
                Err(error) => eprintln!("hakimi-ui: rebuilding the window failed: {error:#}"),
            }
        }
    });
    tray.on_toggle_master({
        let ctx = ctx.clone();
        move || {
            let existing = WINDOW.with(|slot| {
                slot.borrow()
                    .as_ref()
                    .map(|shell| (shell.closing.clone(), shell.app.as_weak()))
            });
            if let Some((closing, weak)) = existing {
                if !closing.get() {
                    if let Some(app) = weak.upgrade() {
                        app.invoke_toggle_master();
                        return;
                    }
                }
            }
            // No window: drive the same state machine directly.
            let runtime = ctx.runtime.clone();
            let turning_on = MODEL.with(|m| m.borrow().accel() != ui_state::AccelState::Running);
            if turning_on && !runtime.config().snapshot().groups.iter().any(|g| g.enabled) {
                return;
            }
            let effects = MODEL.with(|m| {
                let env = m.borrow().env().clone();
                m.borrow_mut().toggle(env)
            });
            ui_state::execute(&effects, &runtime);
            let running = runtime.is_started() && !runtime.status().paused();
            TRAY.with(|slot| {
                if let Some(tray) = slot.borrow().as_ref() {
                    tray.set_running(running);
                }
            });
        }
    });
    tray.on_probe_selected({
        let ctx = ctx.clone();
        move || {
            let existing = WINDOW.with(|slot| {
                slot.borrow()
                    .as_ref()
                    .map(|shell| (shell.closing.clone(), shell.app.as_weak()))
            });
            if let Some((closing, weak)) = existing {
                if !closing.get() {
                    if let Some(app) = weak.upgrade() {
                        app.invoke_probe_selected();
                        return;
                    }
                }
            }
            // No window: run the sweep directly; the status store still
            // records every result for the next window.
            let runtime = ctx.runtime.clone();
            ctx.spawner.spawn(async move {
                runtime.probe_sweep().await;
            });
        }
    });
    tray.on_quit(|| {
        // Quitting goes through the normal path below: run_event_loop returns,
        // the background thread stops the proxy and restores the system proxy.
        let _ = slint::quit_event_loop();
    });
    TRAY.with(|slot| *slot.borrow_mut() = Some(tray));

    // The environment probe is an input stream: it runs off the UI thread and
    // posts results through the event loop. The state machine and the proxy
    // keep working even when no window exists.
    let probe_stop = Arc::new(AtomicBool::new(false));
    {
        let probe_stop = probe_stop.clone();
        let probe_runtime = runtime.clone();
        std::thread::spawn(move || {
            while !probe_stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1000));
                if probe_stop.load(Ordering::SeqCst) {
                    break;
                }
                let env = ui_state::probe_env(&probe_runtime);
                let runtime = probe_runtime.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    MODEL.with(|m| {
                        let mut model = m.borrow_mut();
                        let effects = model.env_changed(env);
                        ui_state::execute(&effects, &runtime);
                    });
                    let running = runtime.is_started() && !runtime.status().paused();
                    let has_window = WINDOW.with(|slot| {
                        let slot = slot.borrow();
                        if let Some(shell) = slot.as_ref() {
                            MODEL.with(|m| ui_state::sync_window(&m.borrow(), &shell.app));
                            true
                        } else {
                            false
                        }
                    });
                    if !has_window {
                        TRAY.with(|slot| {
                            if let Some(tray) = slot.borrow().as_ref() {
                                tray.set_running(running);
                            }
                        });
                    }
                });
            }
        });
    }

    // The initial window. `run_event_loop` keeps running while the tray icon
    // exists; closing the window drops the component without stopping it.
    let shell = build_window(&ctx)?;
    shell.app.show()?;
    WINDOW.with(|slot| *slot.borrow_mut() = Some(shell));
    slint::run_event_loop()?;

    // Quitting stops the proxy and restores the system proxy state.
    WINDOW.with(|slot| {
        *slot.borrow_mut() = None;
    });
    probe_stop.store(true, Ordering::SeqCst);
    shutdown.notify_one();
    let _ = background.join();
    Ok(())
}

#[cfg(test)]
mod tests;
