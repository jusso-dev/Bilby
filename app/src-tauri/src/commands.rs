//! The app's only IPC surface. Each command renders a screen or fragment as
//! an HTML string with Askama (auto-escaping on) and the webview swaps it in.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use askama::Template;
use bilby_core::copy;
use bilby_core::demo::{self, DemoKind};
use bilby_core::model::{Light, ScanReport};
use tauri::{AppHandle, Emitter, State};

use crate::scan::{ProgressEvent, Scanner};

/// Shared app state.
pub struct AppState {
    /// Set by `--demo <healthy|worth|attention>`.
    pub demo: Option<DemoKind>,
    /// Set by `--deep-check`: start a scan as soon as the window opens.
    /// Cleared once used, so going back home doesn't start another.
    pub autostart: AtomicBool,
    /// The last report, kept in memory only.
    pub last_report: Mutex<Option<ScanReport>>,
    /// The running scan, if any.
    pub scanner: Scanner,
}

/// How long the fake demo scan takes, in steps of 250 ms.
const DEMO_STEPS: usize = 12;

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
}

/// Placeholder results until the results screen lands (#23).
#[derive(Template)]
#[template(path = "results.html")]
struct Results {
    headline_key: &'static str,
    placeholder: String,
    /// Offer "Check more deeply" when Bilby isn't running as administrator.
    offer_deep_check: bool,
}

/// Renders the home screen.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn render_home(state: State<'_, AppState>) -> Result<String, String> {
    render(&Home {
        autostart: state.autostart.swap(false, Ordering::SeqCst),
        message: None,
    })
}

/// Runs a scan and returns the results screen, or the home screen with a
/// short message if it was cancelled. In demo mode this waits about three
/// seconds, sending progress events, then returns the demo report.
#[tauri::command]
pub async fn start_scan(app: AppHandle, state: State<'_, AppState>) -> Result<String, String> {
    let Some((_running, cancel)) = state.scanner.begin() else {
        return Err(copy::t("scan.busy").to_owned());
    };
    let report = match state.demo {
        Some(kind) => demo_scan(&app, kind).await?,
        None => match real_scan(&app, cancel).await? {
            Some(report) => report,
            None => {
                return render(&Home {
                    autostart: false,
                    message: Some(copy::t("scan.cancelled")),
                });
            }
        },
    };
    let html = render_results(&report)?;
    *state.last_report.lock().map_err(|e| e.to_string())? = Some(report);
    Ok(html)
}

async fn demo_scan(app: &AppHandle, kind: DemoKind) -> Result<ScanReport, String> {
    for done in 1..=DEMO_STEPS {
        tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_millis(250)))
            .await
            .map_err(|e| e.to_string())?;
        app.emit(
            "scan-progress",
            ProgressEvent {
                step: "demo",
                state: "running",
                done,
                total: DEMO_STEPS,
                label: copy::t("scan.heading"),
            },
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(demo::demo_report(kind))
}

#[cfg(windows)]
async fn real_scan(
    app: &AppHandle,
    cancel: std::sync::Arc<AtomicBool>,
) -> Result<Option<ScanReport>, String> {
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
) -> Result<Option<ScanReport>, String> {
    Err(copy::t("scan.not_available").to_owned())
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
    let headline_key = match report.light {
        Light::Healthy => "light.healthy.headline",
        Light::WorthALook => "light.worth_a_look.headline",
        Light::NeedsAttention => "light.needs_attention.headline",
    };
    let vars = BTreeMap::from([("count".to_owned(), report.findings.len().to_string())]);
    render(&Results {
        headline_key,
        placeholder: copy::tf("results.placeholder", &vars),
        offer_deep_check: cfg!(windows) && !report.is_admin,
    })
}

fn render(t: &impl Template) -> Result<String, String> {
    t.render().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_has_heading_and_button() {
        let html = render(&Home {
            autostart: false,
            message: None,
        })
        .expect("home renders");
        assert!(html.contains("<h1"));
        assert!(html.contains("Check my computer"));
        assert!(html.contains(r#"data-action="start-scan""#));
        assert!(html.contains(r#"data-action="cancel-scan""#));
        assert!(!html.contains("data-autostart"));
    }

    #[test]
    fn deep_check_home_starts_by_itself_and_cancel_shows_a_message() {
        let html = render(&Home {
            autostart: true,
            message: Some(copy::t("scan.cancelled")),
        })
        .expect("home renders");
        assert!(html.contains("data-autostart"));
        assert!(html.contains(copy::t("scan.cancelled")));
    }

    #[test]
    fn demo_results_show_the_light() {
        let html = render_results(&demo::demo_report(DemoKind::NeedsAttention)).expect("renders");
        assert!(html.contains("Needs attention"));
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
