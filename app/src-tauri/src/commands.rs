//! The app's only IPC surface. Each command renders a screen or fragment as
//! an HTML string with Askama (auto-escaping on) and the webview swaps it in.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use askama::Template;
use bilby_core::copy;
use bilby_core::demo::{self, DemoKind};
use bilby_core::model::{Light, ScanReport};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

/// Shared app state.
pub struct AppState {
    /// Set by `--demo <healthy|worth|attention>`.
    pub demo: Option<DemoKind>,
    /// The last report, kept in memory only.
    pub last_report: Mutex<Option<ScanReport>>,
}

/// Progress sent to the webview as `scan-progress` events.
#[derive(Clone, Serialize)]
struct Progress {
    done: u32,
    total: u32,
}

/// How long the fake demo scan takes, in steps of 250 ms.
const DEMO_STEPS: u32 = 12;

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
struct Home;

/// Placeholder results until the results screen lands (#23).
#[derive(Template)]
#[template(path = "results.html")]
struct Results {
    headline_key: &'static str,
    placeholder: String,
}

/// Renders the home screen.
#[tauri::command]
pub fn render_home() -> Result<String, String> {
    render(&Home)
}

/// Runs a scan and returns the results screen. In demo mode this waits about
/// three seconds, sending progress events, then returns the demo report.
#[tauri::command]
pub async fn start_scan(app: AppHandle, state: State<'_, AppState>) -> Result<String, String> {
    let Some(kind) = state.demo else {
        // The real scan arrives with the orchestration issue (#17).
        return Err(copy::t("scan.not_available").to_owned());
    };
    for done in 1..=DEMO_STEPS {
        tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_millis(250)))
            .await
            .map_err(|e| e.to_string())?;
        app.emit(
            "scan-progress",
            Progress {
                done,
                total: DEMO_STEPS,
            },
        )
        .map_err(|e| e.to_string())?;
    }
    let report = demo::demo_report(kind);
    let html = render_results(&report)?;
    *state.last_report.lock().map_err(|e| e.to_string())? = Some(report);
    Ok(html)
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
        let html = render_home().expect("home renders");
        assert!(html.contains("<h1"));
        assert!(html.contains("Check my computer"));
        assert!(html.contains(r#"data-action="start-scan""#));
    }

    #[test]
    fn demo_results_show_the_light() {
        let html = render_results(&demo::demo_report(DemoKind::NeedsAttention)).expect("renders");
        assert!(html.contains("Needs attention"));
    }
}
