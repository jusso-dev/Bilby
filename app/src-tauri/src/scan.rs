//! The Tauri side of a scan: one at a time, cancellable, with progress sent
//! to the window as `scan-progress` events. The collectors and the
//! orchestrator are in `bilby-collect-windows::scan`, the rules and
//! grouping in `bilby_core::engine`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bilby_core::copy;
use serde::Serialize;

/// Progress sent to the webview as `scan-progress` events.
#[derive(Debug, Clone, Serialize)]
pub struct ProgressEvent {
    /// Collector id, for example `processes`.
    pub step: &'static str,
    /// `running`, `done`, `skipped`, `needs-admin` or `failed`.
    pub state: &'static str,
    /// Steps finished so far.
    pub done: usize,
    /// Steps in this scan.
    pub total: usize,
    /// What the window shows, for example "Looking at running programs".
    pub label: &'static str,
}

/// The copy key for a step, `scan.step.<id>`.
pub fn step_key(step: &str) -> &'static str {
    match step {
        "protection" => "scan.step.protection",
        "processes" => "scan.step.processes",
        "persistence" => "scan.step.persistence",
        "network" => "scan.step.network",
        "browser" => "scan.step.browser",
        "tamper" => "scan.step.tamper",
        "drivers" => "scan.step.drivers",
        _ => "scan.heading",
    }
}

/// The text shown for a step.
pub fn step_label(step: &str) -> &'static str {
    copy::t(step_key(step))
}

/// Whether a scan is running, and the switch that cancels it.
#[derive(Default)]
pub struct Scanner {
    running: AtomicBool,
    cancel: Mutex<Option<Arc<AtomicBool>>>,
}

/// Clears the running flag when a scan ends, however it ends.
pub struct Running<'a>(&'a Scanner);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        if let Ok(mut c) = self.0.cancel.lock() {
            *c = None;
        }
        self.0.running.store(false, Ordering::SeqCst);
    }
}

impl Scanner {
    /// Marks a scan as started and returns its cancel switch, or `None` if
    /// one is already running.
    pub fn begin(&self) -> Option<(Running<'_>, Arc<AtomicBool>)> {
        if self.running.swap(true, Ordering::SeqCst) {
            return None;
        }
        let flag = Arc::new(AtomicBool::new(false));
        if let Ok(mut c) = self.cancel.lock() {
            *c = Some(Arc::clone(&flag));
        }
        Some((Running(self), flag))
    }

    /// Asks the running scan, if any, to stop.
    pub fn cancel(&self) {
        if let Ok(c) = self.cancel.lock()
            && let Some(flag) = c.as_ref()
        {
            flag.store(true, Ordering::SeqCst);
        }
    }

    /// True while a scan runs.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// Runs a full scan on this computer: collectors, then rules. Returns
/// `None` if it was cancelled.
#[cfg(windows)]
pub fn run(
    cancel: Arc<AtomicBool>,
    progress: &dyn Fn(ProgressEvent),
) -> Option<bilby_core::model::ScanReport> {
    use bilby_collect_windows::scan::{CollectOptions, StepState, collect};
    use bilby_core::engine::{ScanMeta, evaluate};
    use bilby_core::rules::RuleContext;

    let opts = CollectOptions {
        cancel,
        ..CollectOptions::default()
    };
    tracing::info!("scan started");
    let c = collect(&opts, &|p| {
        let state = match p.state {
            StepState::Running => "running",
            StepState::Done => "done",
            StepState::Skipped => "skipped",
            StepState::NeedsAdmin => "needs-admin",
            StepState::Failed => "failed",
        };
        progress(ProgressEvent {
            step: p.step,
            state,
            done: p.done,
            total: p.total,
            label: step_label(p.step),
        });
    });
    for t in &c.timings {
        tracing::debug!(step = %t.step, millis = t.millis, "collector finished");
    }
    for ch in &c.checks {
        if ch.status != bilby_core::model::CheckStatus::Ran {
            tracing::info!(check = %ch.id, status = ?ch.status, "check didn't fully run");
        }
    }
    if c.cancelled {
        tracing::info!("scan cancelled");
        return None;
    }
    // Online checks join here once the settings screen can turn them on.
    // With both switches off (the only state today) nothing is sent and no
    // HTTP client is built (docs/privacy.md).
    let ctx = RuleContext::with_relations(c.started_at, &c.snapshot);
    let report = evaluate(
        &c.snapshot,
        &ctx,
        ScanMeta {
            started_at: c.started_at,
            finished_at: c.finished_at,
            checked: c.checks,
            machine: c.machine,
            is_admin: c.is_admin,
            timings: c.timings,
        },
    );
    tracing::info!(
        findings = report.findings.len(),
        light = ?report.light,
        admin = report.is_admin,
        "scan finished"
    );
    Some(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_scan_at_a_time_and_cancel_reaches_it() {
        let s = Scanner::default();
        let (guard, flag) = s.begin().expect("first scan starts");
        assert!(s.begin().is_none());
        assert!(s.is_running());
        s.cancel();
        assert!(flag.load(Ordering::SeqCst));
        drop(guard);
        assert!(!s.is_running());
        assert!(s.begin().is_some());
    }

    #[test]
    fn every_step_has_words() {
        for step in [
            "protection",
            "processes",
            "persistence",
            "network",
            "browser",
            "tamper",
            "drivers",
        ] {
            assert_ne!(step_key(step), "scan.heading", "{step}");
            assert_ne!(step_label(step), "");
        }
    }
}
