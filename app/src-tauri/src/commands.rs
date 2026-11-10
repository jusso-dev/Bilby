//! The app's only IPC surface. Each command renders a screen or fragment as
//! an HTML string with Askama (auto-escaping on) and the webview swaps it in.
//! What each screen shows is worked out in [`crate::view`].

use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use askama::Template;
use bilby_core::copy;
use bilby_core::demo::{self, DemoKind};
use bilby_core::model::ScanReport;
use bilby_core::snapshot::SystemSnapshot;
use tauri::{AppHandle, Emitter, State};

use crate::scan::{ProgressEvent, Scanner};
use crate::view;

/// Shared app state.
pub struct AppState {
    /// Set by `--demo <healthy|worth|attention>`.
    pub demo: Option<DemoKind>,
    /// Set by `--deep-check`: start a scan as soon as the window opens.
    /// Cleared once used, so going back home doesn't start another.
    pub autostart: AtomicBool,
    /// The last report, kept in memory only.
    pub last_report: Mutex<Option<ScanReport>>,
    /// The snapshot behind the last report, so "I know this one" can store
    /// the file's hash. Memory only, gone when Bilby closes.
    pub last_snapshot: Mutex<Option<SystemSnapshot>>,
    /// The running scan, if any.
    pub scanner: Scanner,
}

/// The rule catalogue, opened by "How this rule works". A fixed address:
/// nothing from the webview is added to it.
const SIGNALS_URL: &str = "https://github.com/jusso-dev/Bilby/blob/main/docs/signals.md";

/// Askama filters. `{{ "home.button"|t }}` looks a key up in the copy
/// catalogue. The text is still escaped like any other value.
// Askama's `filter_fn` requires a `Result` return and generates an
// `#[inline(always)]` method with an unused `self`. These lints only fire on
// that required shape and the generated code.
#[allow(clippy::inline_always, clippy::unused_self, clippy::unnecessary_wraps)]
mod filters {
    use askama::Values;

    #[askama::filter_fn]
    pub fn t(key: impl std::fmt::Display, _: &dyn Values) -> askama::Result<&'static str> {
        Ok(bilby_core::copy::t(&key.to_string()))
    }
}

/// The home screen with the one big button.
#[derive(Template)]
#[template(path = "home.html")]
struct Home {
    /// Start a scan straight away (after "Check more deeply").
    autostart: bool,
    /// A calm line to show under the button, for example after a cancel.
    message: Option<&'static str>,
    /// "Last check: ..." if one ran since Bilby opened.
    last: Option<String>,
    /// Bilby isn't running as administrator.
    not_admin: bool,
}

/// The progress screen.
#[derive(Template)]
#[template(path = "progress.html")]
struct Progress {
    steps: Vec<view::Step>,
}

/// The results screen. The values come from [`view::results`].
#[derive(Template)]
#[template(path = "results.html")]
struct Results {
    light: &'static str,
    headline: &'static str,
    sub: String,
    first: Option<view::Card>,
    cards: Vec<view::Card>,
    n_high: usize,
    n_medium: usize,
    n_low: usize,
    notes: Vec<view::Card>,
    ignored: Vec<view::Card>,
    areas: Vec<view::Area>,
    offer_deep_check: bool,
    helper: Vec<view::Row>,
    timings: Vec<view::Row>,
}

fn is_admin() -> bool {
    #[cfg(windows)]
    {
        bilby_collect_windows::elevation::current_is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// "Last check: Needs attention at 9:41 am." for the last report, in local
/// time when the offset can be read, otherwise UTC.
fn last_line(report: &ScanReport) -> String {
    let at = time::UtcOffset::current_local_offset()
        .map_or(report.finished_at, |o| report.finished_at.to_offset(o));
    let (h, m) = (at.hour(), at.minute());
    let half = if h < 12 { "am" } else { "pm" };
    let h12 = match h % 12 {
        0 => 12,
        x => x,
    };
    copy::tf(
        "home.last",
        &BTreeMap::from([
            (
                "light".to_owned(),
                view::light_headline(report.light).to_owned(),
            ),
            ("time".to_owned(), format!("{h12}:{m:02} {half}")),
        ]),
    )
}

fn home(
    state: &AppState,
    autostart: bool,
    message: Option<&'static str>,
) -> Result<String, String> {
    let last = state
        .last_report
        .lock()
        .map_err(|e| e.to_string())?
        .as_ref()
        .map(last_line);
    render(&Home {
        autostart,
        message,
        last,
        not_admin: cfg!(windows) && state.demo.is_none() && !is_admin(),
    })
}

/// Renders the home screen.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn render_home(state: State<'_, AppState>) -> Result<String, String> {
    home(&state, state.autostart.swap(false, Ordering::SeqCst), None)
}

/// Renders the progress screen. `app.js` shows it, calls [`start_scan`],
/// and fills it in from `scan-progress` events.
#[tauri::command]
pub fn render_progress() -> Result<String, String> {
    render(&Progress {
        steps: view::steps(),
    })
}

/// The results of the last check this session, for "See results".
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn render_last_results(state: State<'_, AppState>) -> Result<String, String> {
    let report = state.last_report.lock().map_err(|e| e.to_string())?;
    if let Some(r) = report.as_ref() {
        return render_results(r);
    }
    drop(report);
    home(&state, false, None)
}

/// Runs a scan and returns the results screen, or the home screen with a
/// short message if it was cancelled. In demo mode this walks through the
/// steps in about four seconds, then returns the demo report.
#[tauri::command]
pub async fn start_scan(app: AppHandle, state: State<'_, AppState>) -> Result<String, String> {
    let Some((_running, cancel)) = state.scanner.begin() else {
        return Err(copy::t("scan.busy").to_owned());
    };
    let (report, snapshot) = match state.demo {
        Some(kind) => (demo_scan(&app, kind, &cancel).await?, None),
        None => match real_scan(&app, std::sync::Arc::clone(&cancel)).await? {
            Some((report, snapshot)) => (Some(report), Some(snapshot)),
            None => (None, None),
        },
    };
    let Some(report) = report else {
        return home(&state, false, Some(copy::t("scan.cancelled")));
    };
    let html = render_results(&report)?;
    *state.last_report.lock().map_err(|e| e.to_string())? = Some(report);
    *state.last_snapshot.lock().map_err(|e| e.to_string())? = snapshot;
    Ok(html)
}

async fn demo_scan(
    app: &AppHandle,
    kind: DemoKind,
    cancel: &AtomicBool,
) -> Result<Option<ScanReport>, String> {
    let total = view::STEPS.len();
    for (i, step) in view::STEPS.iter().enumerate() {
        for (state, done, wait) in [("running", i, 200), ("done", i + 1, 350)] {
            if cancel.load(Ordering::SeqCst) {
                return Ok(None);
            }
            app.emit(
                "scan-progress",
                ProgressEvent {
                    step,
                    state,
                    done,
                    total,
                    label: crate::scan::step_label(step),
                },
            )
            .map_err(|e| e.to_string())?;
            tauri::async_runtime::spawn_blocking(move || {
                std::thread::sleep(Duration::from_millis(wait));
            })
            .await
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(Some(demo::demo_report(kind)))
}

#[cfg(windows)]
async fn real_scan(
    app: &AppHandle,
    cancel: std::sync::Arc<AtomicBool>,
) -> Result<Option<(ScanReport, SystemSnapshot)>, String> {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        crate::scan::run(cancel, &|p| {
            let _ = app.emit("scan-progress", p);
        })
    })
    .await
    .map_err(|e| e.to_string())
}

#[cfg(not(windows))]
async fn real_scan(
    _app: &AppHandle,
    _cancel: std::sync::Arc<AtomicBool>,
) -> Result<Option<(ScanReport, SystemSnapshot)>, String> {
    Err(copy::t("scan.not_available").to_owned())
}

/// "I know this one": ignore a finding from the last report from now on.
/// Saved to `%LOCALAPPDATA%\Bilby\suppressions.json` with the file's hash,
/// so the finding comes back if the file changes. Returns the results
/// screen again, with the light worked out without it. Demo mode keeps it
/// in memory only.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn ignore_finding(
    state: State<'_, AppState>,
    finding_id: String,
    note: String,
) -> Result<String, String> {
    let failed = || copy::t("ignore.failed").to_owned();
    let mut guard = state.last_report.lock().map_err(|_| failed())?;
    let report = guard.as_mut().ok_or_else(failed)?;
    let finding = report
        .findings
        .iter()
        .find(|f| f.id() == finding_id)
        .ok_or_else(failed)?;
    if state.demo.is_none() {
        let snapshot = state.last_snapshot.lock().map_err(|_| failed())?;
        let snapshot = snapshot.as_ref().ok_or_else(failed)?;
        let path = crate::scan::suppressions_path().ok_or_else(failed)?;
        let mut all = bilby_core::suppress::Suppressions::load(&path).map_err(|_| failed())?;
        // A file Bilby couldn't fingerprint can't be ignored safely: it
        // would stay ignored even after the file was replaced.
        if !all.add(finding, snapshot, time::OffsetDateTime::now_utc(), &note) {
            return Err(failed());
        }
        all.save(&path).map_err(|_| failed())?;
        tracing::info!(rule = %finding.rule_id, "finding ignored by the user");
    }
    if !report.suppressed.contains(&finding_id) {
        report.suppressed.push(finding_id);
    }
    rescore(report);
    render_results(report)
}

/// "Stop ignoring": counts a finding again, from this screen on.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn unignore_finding(state: State<'_, AppState>, finding_id: String) -> Result<String, String> {
    let failed = || copy::t("ignore.failed").to_owned();
    let mut guard = state.last_report.lock().map_err(|_| failed())?;
    let report = guard.as_mut().ok_or_else(failed)?;
    if state.demo.is_none() {
        let path = crate::scan::suppressions_path().ok_or_else(failed)?;
        let mut all = bilby_core::suppress::Suppressions::load(&path).map_err(|_| failed())?;
        if all.remove(&finding_id) {
            all.save(&path).map_err(|_| failed())?;
            tracing::info!("finding no longer ignored");
        }
    }
    report.suppressed.retain(|id| *id != finding_id);
    rescore(report);
    render_results(report)
}

/// Works the light out again after the ignored list changed.
fn rescore(report: &mut ScanReport) {
    let ignored: HashSet<String> = report.suppressed.iter().cloned().collect();
    report.light = bilby_core::score::overall(&report.findings, &ignored);
}

/// A card's "Open Windows Security" or "Open the setting" button. The
/// webview sends only the finding id; the page comes from the finding,
/// through the fixed list in `bilby_collect_windows::open`.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn open_next_step(state: State<'_, AppState>, finding_id: String) -> Result<(), String> {
    let failed = || copy::t("results.open_failed").to_owned();
    let setting = {
        let report = state.last_report.lock().map_err(|_| failed())?;
        report
            .as_ref()
            .and_then(|r| r.findings.iter().find(|f| f.id() == finding_id))
            .and_then(view::setting_for)
            .ok_or_else(failed)?
            .to_owned()
    };
    open_setting(&setting).map_err(|e| {
        tracing::info!(error = %e, "couldn't open a setting");
        failed()
    })
}

#[cfg(windows)]
fn open_setting(setting: &str) -> Result<(), String> {
    use bilby_collect_windows::open::{open, target};
    open(target(setting).ok_or("no page for that setting")?)
}

#[cfg(not(windows))]
// Same shape as the Windows version.
#[allow(clippy::unnecessary_wraps)]
fn open_setting(setting: &str) -> Result<(), String> {
    tracing::info!(setting, "would open a setting");
    Ok(())
}

/// "How this rule works": the rule catalogue on GitHub, in the default
/// browser.
#[tauri::command]
pub fn open_rules() -> Result<(), String> {
    #[cfg(windows)]
    {
        use bilby_collect_windows::open::{Target, open};
        open(Target::Uri(SIGNALS_URL)).map_err(|e| {
            tracing::info!(error = %e, "couldn't open the rule catalogue");
            copy::t("results.open_failed").to_owned()
        })
    }
    #[cfg(not(windows))]
    {
        tracing::info!(url = SIGNALS_URL, "would open the rule catalogue");
        Ok(())
    }
}

/// Stops the running scan. The scan command then returns the home screen.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn cancel_scan(state: State<'_, AppState>) {
    state.scanner.cancel();
}

/// `running`, `done` (a report is in memory) or `idle`.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn scan_state(state: State<'_, AppState>) -> &'static str {
    if state.scanner.is_running() {
        "running"
    } else if state.last_report.lock().is_ok_and(|r| r.is_some()) {
        "done"
    } else {
        "idle"
    }
}

/// "Check more deeply": asks Windows to start Bilby as administrator. If
/// the person agrees, this window closes and the new one starts a scan.
/// If they say no, or it can't be asked, returns a calm line to show.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn relaunch_elevated(app: AppHandle) -> String {
    #[cfg(windows)]
    {
        use bilby_collect_windows::elevation::{Relaunch, relaunch};
        match relaunch() {
            Ok(Relaunch::Started) => {
                tracing::info!("relaunched as administrator");
                app.exit(0);
                String::new()
            }
            Ok(Relaunch::Declined) => copy::t("deep.declined").to_owned(),
            Err(e) => {
                tracing::info!(error = %e, "couldn't relaunch as administrator");
                copy::t("deep.failed").to_owned()
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        copy::t("deep.failed").to_owned()
    }
}

fn render_results(report: &ScanReport) -> Result<String, String> {
    let v = view::results(report, cfg!(windows));
    render(&Results {
        light: v.light,
        headline: v.headline,
        sub: v.sub,
        first: v.first,
        cards: v.cards,
        n_high: v.counts[0],
        n_medium: v.counts[1],
        n_low: v.counts[2],
        notes: v.notes,
        ignored: v.ignored,
        areas: v.areas,
        offer_deep_check: v.offer_deep_check,
        helper: v.helper,
        timings: v.timings,
    })
}

fn render(t: &impl Template) -> Result<String, String> {
    t.render().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home_html(autostart: bool, message: Option<&'static str>, last: Option<String>) -> String {
        render(&Home {
            autostart,
            message,
            last,
            not_admin: true,
        })
        .expect("home renders")
    }

    #[test]
    fn home_has_heading_and_button() {
        let html = home_html(false, None, None);
        assert!(html.contains("<h1"));
        assert!(html.contains("Check my computer"));
        assert!(html.contains(r#"data-action="start-scan""#));
        assert!(html.contains(copy::t("home.private")));
        assert!(!html.contains("data-autostart"));
        assert!(!html.contains(r#"data-action="see-results""#));
    }

    #[test]
    fn deep_check_home_starts_by_itself_and_cancel_shows_a_message() {
        let html = home_html(true, Some(copy::t("scan.cancelled")), None);
        assert!(html.contains("data-autostart"));
        assert!(html.contains(copy::t("scan.cancelled")));
    }

    #[test]
    fn home_offers_the_last_results() {
        let line = last_line(&demo::demo_report(DemoKind::WorthALook));
        assert!(line.starts_with("Last check: Worth a look at "), "{line}");
        let html = home_html(false, None, Some(line));
        assert!(html.contains(r#"data-action="see-results""#));
    }

    #[test]
    fn progress_lists_every_step() {
        let html = render_progress().expect("progress renders");
        for step in view::STEPS {
            assert!(html.contains(&format!(r#"data-step="{step}""#)), "{step}");
        }
        assert!(html.contains("<progress"));
        assert!(html.contains(r#"aria-live="polite""#));
    }

    #[test]
    fn demo_results_show_the_light() {
        for kind in [
            DemoKind::Healthy,
            DemoKind::WorthALook,
            DemoKind::NeedsAttention,
        ] {
            let report = demo::demo_report(kind);
            let html = render_results(&report).expect("renders");
            assert!(html.contains(view::light_headline(report.light)));
            assert!(html.contains(copy::t("results.checked_heading")));
            // Full paths only inside "More detail".
            for card in html.split("<article").skip(1) {
                let face = card.split("<details").next().unwrap_or_default();
                assert!(!face.contains(":\\"), "path on a card face: {face}");
            }
        }
        let html = render_results(&demo::demo_report(DemoKind::NeedsAttention)).expect("renders");
        assert!(html.contains(r#"data-action="filter""#));
        assert!(html.contains(r#"data-action="ignore-ask""#));
    }

    #[test]
    fn ignoring_moves_the_light() {
        let mut report = demo::demo_report(DemoKind::NeedsAttention);
        let ids: Vec<String> = report
            .findings
            .iter()
            .map(bilby_core::model::Finding::id)
            .collect();
        report.suppressed = ids;
        rescore(&mut report);
        assert_eq!(report.light, bilby_core::model::Light::Healthy);
        let html = render_results(&report).expect("renders");
        assert!(html.contains(r#"data-action="unignore""#));
    }

    #[test]
    fn deep_check_offered_only_without_admin() {
        let mut report = demo::demo_report(DemoKind::Healthy);
        report.is_admin = false;
        let html = render_results(&report).expect("renders");
        assert_eq!(html.contains(r#"data-action="deep-check""#), cfg!(windows));
        report.is_admin = true;
        let html = render_results(&report).expect("renders");
        assert!(!html.contains(r#"data-action="deep-check""#));
    }
}
