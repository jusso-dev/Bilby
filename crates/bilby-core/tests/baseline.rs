//! Clean baseline (#18): snapshots of clean Windows machines must look
//! healthy, apart from what's listed as expected with a reason.
//!
//! - `tests/fixtures/baseline/*.json`: `{ "note", "now", "snapshot",
//!   "expected": [{ "rule_id", "severity", "confidence", "reason" }] }`.
//!   No Medium or High finding (at Medium confidence or more) may appear
//!   unless it's listed, every listed one must still appear (so a rule
//!   change can't hide it quietly), and the light without the listed ones
//!   is Looks healthy.
//! - `BILBY_SNAPSHOT=<file>`: a raw `--dump-snapshot` file from CI, checked
//!   the same way against `tests/ci-allow.toml`.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use bilby_core::engine::{ScanMeta, evaluate};
use bilby_core::model::{Confidence, Finding, Light, MachineSummary, Severity};
use bilby_core::rules::RuleContext;
use bilby_core::score::{self, MIN_CONFIDENCE_TO_COUNT};
use bilby_core::snapshot::SystemSnapshot;
use serde::Deserialize;
use time::OffsetDateTime;

/// A finding a clean machine is expected to show, and why.
#[derive(Debug, Deserialize)]
struct Expected {
    rule_id: String,
    severity: Severity,
    confidence: Confidence,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    note: String,
    #[serde(with = "time::serde::rfc3339")]
    now: OffsetDateTime,
    snapshot: SystemSnapshot,
    #[serde(default)]
    expected: Vec<Expected>,
}

#[derive(Debug, Deserialize)]
struct Allow {
    allow: Vec<Expected>,
}

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn findings(snap: &SystemSnapshot, now: OffsetDateTime) -> (Vec<Finding>, Light) {
    let ctx = RuleContext::with_relations(now, snap);
    let report = evaluate(
        snap,
        &ctx,
        ScanMeta {
            started_at: now,
            finished_at: now,
            checked: Vec::new(),
            machine: MachineSummary::default(),
            is_admin: false,
            timings: Vec::new(),
        },
    );
    (report.findings, report.light)
}

/// A finding that would move the light on its own or with others.
fn counts(f: &Finding) -> bool {
    f.severity >= Severity::Medium && f.confidence >= MIN_CONFIDENCE_TO_COUNT
}

/// Checks one clean snapshot. Returns problems, empty if it passes.
fn check(
    name: &str,
    snap: &SystemSnapshot,
    now: OffsetDateTime,
    expected: &[Expected],
) -> Vec<String> {
    let (all, _) = findings(snap, now);
    for f in &all {
        println!(
            "{name}: {} {:?}/{:?} {:?}",
            f.rule_id, f.severity, f.confidence, f.subject
        );
    }
    let mut problems = Vec::new();
    for e in expected {
        assert!(
            !e.reason.trim().is_empty(),
            "{name}: {} needs a reason",
            e.rule_id
        );
        if !all.iter().any(|f| {
            f.rule_id == e.rule_id && f.severity == e.severity && f.confidence == e.confidence
        }) {
            problems.push(format!(
                "{name}: expected {} {:?}/{:?} no longer appears; update the list",
                e.rule_id, e.severity, e.confidence
            ));
        }
    }
    let is_expected = |f: &Finding| {
        expected.iter().any(|e| {
            e.rule_id == f.rule_id && e.severity == f.severity && e.confidence == f.confidence
        })
    };
    for f in all.iter().filter(|f| counts(f) && !is_expected(f)) {
        problems.push(format!(
            "{name}: unexpected {} {:?}/{:?} on {:?}",
            f.rule_id, f.severity, f.confidence, f.subject
        ));
    }
    let rest: Vec<Finding> = all.into_iter().filter(|f| !is_expected(f)).collect();
    let light = score::overall(&rest, &HashSet::<String>::new());
    if light != Light::Healthy {
        problems.push(format!(
            "{name}: light is {light:?} without the expected findings"
        ));
    }
    problems
}

#[test]
fn clean_baselines_look_healthy() {
    let mut problems = Vec::new();
    let mut seen = 0;
    for entry in fs::read_dir(dir().join("fixtures/baseline")).expect("baseline dir") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        seen += 1;
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let fixture: Fixture = serde_json::from_str(&fs::read_to_string(&path).expect("readable"))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!fixture.note.trim().is_empty(), "{name} needs a note");
        problems.extend(check(
            &name,
            &fixture.snapshot,
            fixture.now,
            &fixture.expected,
        ));
    }
    assert!(seen >= 2, "expected the runner and home-apps baselines");
    assert!(problems.is_empty(), "{problems:#?}");
}

/// CI runs `bilby.exe --dump-snapshot` on windows-latest, then this with
/// `BILBY_SNAPSHOT` set. Anything Medium or higher must be explained in
/// `tests/ci-allow.toml`.
#[test]
fn ci_snapshot_has_only_allowed_findings() {
    let Ok(file) = std::env::var("BILBY_SNAPSHOT") else {
        println!("BILBY_SNAPSHOT not set; nothing to check");
        return;
    };
    let snap: SystemSnapshot =
        serde_json::from_str(&fs::read_to_string(&file).expect("snapshot file"))
            .expect("valid snapshot");
    let allow: Allow =
        toml::from_str(&fs::read_to_string(dir().join("ci-allow.toml")).expect("ci-allow.toml"))
            .expect("valid ci-allow.toml");
    // Expected entries that don't appear are fine here: runners change.
    let problems: Vec<String> = check("ci", &snap, OffsetDateTime::now_utc(), &allow.allow)
        .into_iter()
        .filter(|p| !p.contains("no longer appears"))
        .collect();
    assert!(problems.is_empty(), "{problems:#?}");
}
