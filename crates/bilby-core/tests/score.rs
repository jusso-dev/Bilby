//! Table tests for `score::overall`, one per row of "Scoring" in
//! `docs/architecture.md`, plus finding ids and the demo fixtures.

use std::collections::{BTreeMap, HashSet};

use bilby_core::demo::{self, DemoKind};
use bilby_core::model::{
    Confidence as C, Finding, Light, NextStepKind, ScanReport, Severity as S, SignalFamily, Subject,
};
use bilby_core::score::overall;

fn finding(n: usize, severity: S, confidence: C) -> Finding {
    Finding {
        rule_id: format!("test.rule_{n}"),
        family: SignalFamily::Processes,
        severity,
        confidence,
        title_key: "test.title".into(),
        vars: BTreeMap::new(),
        evidence: Vec::new(),
        next_step: NextStepKind::Learn,
        subject: Subject::File(format!("c:\\test\\{n}.exe")),
    }
}

fn light(spec: &[(S, C)]) -> Light {
    let findings: Vec<Finding> = spec
        .iter()
        .enumerate()
        .map(|(n, (s, c))| finding(n, *s, *c))
        .collect();
    overall(&findings, &HashSet::new())
}

/// One row of the scoring table: name, findings as (severity, confidence), expected light.
type Case<'a> = (&'a str, &'a [(S, C)], Light);

#[test]
fn scoring_table() {
    let lm = (S::Low, C::Medium);
    let cases: &[Case] = &[
        ("no findings", &[], Light::Healthy),
        ("high/high", &[(S::High, C::High)], Light::NeedsAttention),
        (
            "high/medium",
            &[(S::High, C::Medium)],
            Light::NeedsAttention,
        ),
        ("high/low", &[(S::High, C::Low)], Light::WorthALook),
        (
            "medium/medium",
            &[(S::Medium, C::Medium)],
            Light::WorthALook,
        ),
        ("medium/high", &[(S::Medium, C::High)], Light::WorthALook),
        ("medium/low", &[(S::Medium, C::Low)], Light::Healthy),
        ("two low/medium", &[lm, lm], Light::Healthy),
        ("three low/medium", &[lm, lm, lm], Light::WorthALook),
        (
            "three low, one with low confidence",
            &[lm, (S::Low, C::High), (S::Low, C::Low)],
            Light::Healthy,
        ),
        ("one low/high", &[(S::Low, C::High)], Light::Healthy),
        (
            "info never moves the light",
            &[(S::Info, C::High); 4],
            Light::Healthy,
        ),
        (
            "high wins over medium",
            &[(S::Medium, C::High), (S::High, C::High)],
            Light::NeedsAttention,
        ),
    ];
    for (name, spec, expected) in cases {
        assert_eq!(light(spec), *expected, "case: {name}");
    }
}

#[test]
fn suppressed_high_high_is_healthy() {
    let f = finding(0, S::High, C::High);
    let suppressed = HashSet::from([f.id()]);
    assert_eq!(overall(&[f], &suppressed), Light::Healthy);
}

#[test]
fn suppression_only_hides_that_finding() {
    let a = finding(0, S::High, C::High);
    let b = finding(1, S::Medium, C::Medium);
    let suppressed = HashSet::from([a.id()]);
    assert_eq!(overall(&[a, b], &suppressed), Light::WorthALook);
}

#[test]
fn finding_id_is_stable() {
    let f = finding(7, S::High, C::High);
    assert_eq!(f.id().len(), 16);
    // Pinned value. If this changes, saved "I know this one" entries stop
    // matching, so a change here needs a migration.
    assert_eq!(f.id(), PINNED_ID);
}

const PINNED_ID: &str = "0d3d29355c43a35b";

#[test]
fn finding_id_depends_on_rule_and_subject_only() {
    let a = finding(1, S::High, C::High);
    let mut b = a.clone();
    b.severity = S::Low;
    b.vars.insert("x".into(), "y".into());
    assert_eq!(a.id(), b.id());
    b.subject = Subject::File("c:\\other.exe".into());
    assert_ne!(a.id(), b.id());
}

#[test]
fn demo_fixtures_score_to_their_name() {
    for (kind, expected) in [
        (DemoKind::Healthy, Light::Healthy),
        (DemoKind::WorthALook, Light::WorthALook),
        (DemoKind::NeedsAttention, Light::NeedsAttention),
    ] {
        assert_eq!(demo::demo_report(kind).light, expected, "{kind:?}");
        let raw: ScanReport = serde_json::from_str(demo::fixture(kind)).expect("fixture parses");
        assert_eq!(raw.light, expected, "{kind:?} fixture light field");
    }
}

#[test]
fn demo_kind_parses() {
    assert_eq!("healthy".parse::<DemoKind>(), Ok(DemoKind::Healthy));
    assert_eq!("worth".parse::<DemoKind>(), Ok(DemoKind::WorthALook));
    assert_eq!(
        "attention".parse::<DemoKind>(),
        Ok(DemoKind::NeedsAttention)
    );
    assert!("red".parse::<DemoKind>().is_err());
}
