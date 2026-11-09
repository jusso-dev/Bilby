//! The app's only IPC surface. Each command renders a screen or fragment as
//! an HTML string with Askama (auto-escaping on) and the webview swaps it in.

use std::sync::Mutex;
use std::time::Duration;

use askama::Template;
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

/// The home screen with the one big button.
#[derive(Template)]
#[template(path = "home.html")]
struct Home<'a> {
    heading: &'a str,
    button: &'a str,
}

/// Placeholder results until the results screen lands (#23).
#[derive(Template)]
#[template(path = "results.html")]
struct Results<'a> {
    headline: &'a str,
    findings: usize,
}

/// Renders the home screen.
#[tauri::command]
pub fn render_home() -> Result<String, String> {
    render(&Home {
        heading: "Bilby",
        button: "Check my computer",
    })
}

/// Runs a scan and returns the results screen. In demo mode this waits about
/// three seconds, sending progress events, then returns the demo report.
#[tauri::command]
pub async fn start_scan(app: AppHandle, state: State<'_, AppState>) -> Result<String, String> {
    let Some(kind) = state.demo else {
        // The real scan arrives with the orchestration issue (#17).
        return Err("Checking isn't available in this build yet.".into());
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
    let headline = match report.light {
        Light::Healthy => "Looks healthy",
        Light::WorthALook => "Worth a look",
        Light::NeedsAttention => "Needs attention",
    };
    render(&Results {
        headline,
        findings: report.findings.len(),
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
