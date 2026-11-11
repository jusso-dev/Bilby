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
        "reputation" => "scan.step.reputation",
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

/// `%LOCALAPPDATA%\Bilby\suppressions.json`, where "I know this one" is kept.
pub fn suppressions_path() -> Option<std::path::PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|base| {
        std::path::PathBuf::from(base)
            .join("Bilby")
            .join("suppressions.json")
    })
}

/// What the user told Bilby to ignore. A file that can't be read is logged
/// and treated as empty for this scan; it's left on disk untouched. Only
/// the Windows scan uses it.
#[cfg(windows)]
pub fn load_suppressions() -> bilby_core::suppress::Suppressions {
    let Some(path) = suppressions_path() else {
        return bilby_core::suppress::Suppressions::default();
    };
    bilby_core::suppress::Suppressions::load(&path).unwrap_or_else(|e| {
        tracing::info!(error = %e, "suppressions.json couldn't be read; ignoring nothing this scan");
        bilby_core::suppress::Suppressions::default()
    })
}

/// Runs a full scan on this computer: collectors, then rules. Returns the
/// report and the snapshot it came from (kept for "I know this one", which
/// stores the file's hash), or `None` if it was cancelled.
#[cfg(windows)]
pub fn run(
    cancel: &Arc<AtomicBool>,
    progress: &dyn Fn(ProgressEvent),
    online_cache: &bilby_reputation::Cache,
) -> Option<(
    bilby_core::model::ScanReport,
    bilby_core::snapshot::SystemSnapshot,
)> {
    use bilby_collect_windows::scan::{CollectOptions, StepState, collect};
    use bilby_core::engine::{ScanMeta, evaluate};
    use bilby_core::rules::RuleContext;

    let opts = CollectOptions {
        cancel: Arc::clone(cancel),
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
    let mut snapshot = c.snapshot;
    let mut checks = c.checks;
    // Online checks, only those the user switched on. With every switch
    // off nothing is sent and no HTTP client is built (docs/privacy.md).
    let online = crate::settings::load().online;
    checks.extend(online_checks(
        online,
        &mut snapshot,
        c.started_at,
        online_cache,
        progress,
    ));
    if cancel.load(std::sync::atomic::Ordering::SeqCst) {
        tracing::info!("scan cancelled");
        return None;
    }
    let mut ctx = RuleContext::with_relations(c.started_at, &snapshot);
    ctx.suppressions = load_suppressions();
    let report = evaluate(
        &snapshot,
        &ctx,
        ScanMeta {
            started_at: c.started_at,
            finished_at: time::OffsetDateTime::now_utc(),
            checked: checks,
            machine: c.machine,
            is_admin: c.is_admin,
            timings: c.timings,
        },
    );
    tracing::info!(
        findings = report.findings.len(),
        light = ?report.light,
        admin = report.is_admin,
        ignored = report.suppressed.len(),
        "scan finished"
    );
    Some((report, snapshot))
}

/// Ran, unless nothing was sent and something went wrong.
#[cfg(windows)]
fn lookup_status(sent: usize, errors: &[String]) -> bilby_core::model::CheckStatus {
    if sent == 0 && !errors.is_empty() {
        bilby_core::model::CheckStatus::Failed(errors.join("; "))
    } else {
        bilby_core::model::CheckStatus::Ran
    }
}

/// The online step: works out which hashes and addresses the rules allow
/// (`lookup_candidates`, `ip_candidates`), asks the services the user
/// switched on, and puts the answers in the snapshot for the rules.
/// Returns the "What we checked" rows for it. Never fails a scan.
#[cfg(windows)]
fn online_checks(
    online: bilby_core::settings::OnlineChecks,
    snapshot: &mut bilby_core::snapshot::SystemSnapshot,
    now: time::OffsetDateTime,
    cache: &bilby_reputation::Cache,
    progress: &dyn Fn(ProgressEvent),
) -> Vec<bilby_core::model::Check> {
    use bilby_core::model::{Check, CheckStatus, SignalFamily};
    use bilby_core::rules::reputation::{
        MAX_CIRCL_LOOKUPS, MAX_IP_LOOKUPS, ip_candidates, lookup_candidates,
    };
    use bilby_core::rules::{RuleContext, evaluate_all};
    use bilby_reputation::key::{self, Service};
    use bilby_reputation::{Limits, allowlist::Http, check, ip};

    let row = |id: &str, status| Check {
        id: id.to_owned(),
        family: SignalFamily::Reputation,
        status,
    };
    let off = || CheckStatus::Skipped("check.skipped.online_off".to_owned());
    if !online.any() {
        return vec![row("reputation.files", off()), row("reputation.ips", off())];
    }
    let total = crate::view::STEPS.len() + 1;
    let step = |state| {
        progress(ProgressEvent {
            step: "reputation",
            state,
            done: if state == "running" { total - 1 } else { total },
            total,
            label: step_label("reputation"),
        });
    };
    step("running");
    // A first pass of the rules decides what's worth looking up.
    let first = evaluate_all(snapshot, &RuleContext::with_relations(now, snapshot));
    let hashes = lookup_candidates(snapshot, &first, MAX_CIRCL_LOOKUPS);
    let ips = ip_candidates(snapshot, &first, MAX_IP_LOOKUPS);
    let http = Http::new(true);
    let vt_key = key::load(Service::VirusTotal);
    let ab_key = key::load(Service::AbuseIpDb);
    let cs_key = key::load(Service::CrowdSec);
    let sleep = |d| std::thread::sleep(d);
    let mut facts = snapshot.reputation.take().unwrap_or_default();
    let files = match check(
        online,
        &hashes,
        vt_key.as_ref(),
        &http,
        cache,
        Limits::default(),
        &sleep,
    ) {
        Some((f, sum)) => {
            facts.virustotal.extend(f.virustotal);
            facts.known_good.extend(f.known_good);
            tracing::info!(
                circl = sum.circl_sent,
                vt = sum.vt_sent,
                problems = sum.errors.len(),
                "file lookups done"
            );
            lookup_status(sum.circl_sent + sum.vt_sent, &sum.errors)
        }
        None => off(),
    };
    let addresses = match ip::check_ips(
        online,
        &ips,
        ip::IpKeys {
            virustotal: vt_key.as_ref(),
            abuseipdb: ab_key.as_ref(),
            crowdsec: cs_key.as_ref(),
        },
        &http,
        cache,
        Limits::default(),
        &sleep,
    ) {
        Some((f, sum)) => {
            facts.ip_virustotal.extend(f.virustotal);
            facts.ip_abuseipdb.extend(f.abuseipdb);
            facts.ip_crowdsec.extend(f.crowdsec);
            tracing::info!(
                candidates = ips.len(),
                vt = sum.vt_ip_sent,
                abuseipdb = sum.abuseipdb_sent,
                crowdsec = sum.crowdsec_sent,
                problems = sum.errors.len(),
                "address lookups done"
            );
            lookup_status(
                sum.vt_ip_sent + sum.abuseipdb_sent + sum.crowdsec_sent,
                &sum.errors,
            )
        }
        None => off(),
    };
    snapshot.reputation = Some(facts);
    step("done");
    vec![
        row("reputation.files", files),
        row("reputation.ips", addresses),
    ]
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
