//! Runs every rule fixture in `tests/fixtures/<family>/`.
//!
//! Each `<rule>.<case>.json` file is:
//!
//! ```json
//! { "now": "2026-11-09T09:00:00Z",
//!   "snapshot": { ... SystemSnapshot ... },
//!   "expect": [ { "rule_id": "...", "severity": "high", "confidence": "high" } ],
//!   "absent": [ "rule.id.that.must.not.fire" ] }
//! ```
//!
//! `expect` lists findings that must appear (with that severity and
//! confidence). `absent` lists rule ids that must not fire at all. Every
//! rule in `all_rules()` needs at least one `fires` and one `lookalike`
//! fixture (ADR 0007).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use bilby_core::model::{Confidence, Severity};
use bilby_core::rules::{BOOST_RULES, RuleContext, all_rules, evaluate_all};
use bilby_core::snapshot::SystemSnapshot;
use serde::Deserialize;
use time::OffsetDateTime;

#[derive(Deserialize)]
struct Fixture {
    #[serde(with = "time::serde::rfc3339")]
    now: OffsetDateTime,
    snapshot: SystemSnapshot,
    #[serde(default)]
    expect: Vec<Expected>,
    #[serde(default)]
    absent: Vec<String>,
}

#[derive(Deserialize)]
struct Expected {
    rule_id: String,
    severity: Severity,
    confidence: Confidence,
}

fn fixture_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut out = Vec::new();
    for family in fs::read_dir(&root).expect("fixtures dir").flatten() {
        let dir = family.path();
        if !dir.is_dir() || dir.ends_with("demo") || dir.ends_with("baseline") {
            continue;
        }
        for f in fs::read_dir(&dir).expect("family dir").flatten() {
            if f.path().extension().is_some_and(|e| e == "json") {
                out.push(f.path());
            }
        }
    }
    out.sort();
    out
}

#[test]
fn every_fixture_holds() {
    let mut failures = Vec::new();
    let files = fixture_files();
    for path in &files {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let text = fs::read_to_string(path).expect("readable fixture");
        let fixture: Fixture = match serde_json::from_str(&text) {
            Ok(f) => f,
            Err(e) => {
                failures.push(format!("{name}: doesn't parse: {e}"));
                continue;
            }
        };
        let findings = evaluate_all(&fixture.snapshot, &RuleContext::at(fixture.now));
        for want in &fixture.expect {
            let found = findings.iter().any(|f| {
                f.rule_id == want.rule_id
                    && f.severity == want.severity
                    && f.confidence == want.confidence
            });
            if !found {
                failures.push(format!(
                    "{name}: expected {} {:?}/{:?}, got {:?}",
                    want.rule_id,
                    want.severity,
                    want.confidence,
                    findings
                        .iter()
                        .map(|f| format!("{} {:?}/{:?}", f.rule_id, f.severity, f.confidence))
                        .collect::<Vec<_>>()
                ));
            }
        }
        for id in &fixture.absent {
            if findings.iter().any(|f| &f.rule_id == id) {
                failures.push(format!("{name}: {id} fired but must not"));
            }
        }
        if fixture.expect.is_empty() && fixture.absent.is_empty() {
            failures.push(format!("{name}: has neither expect nor absent"));
        }
    }
    println!("checked {} fixtures", files.len());
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn every_rule_has_fires_and_lookalike_fixtures() {
    let names: BTreeSet<String> = fixture_files()
        .iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    let mut missing = Vec::new();
    for id in rule_ids() {
        for case in ["fires", "lookalike"] {
            let prefix = format!("{id}.{case}");
            if !names.iter().any(|n| n.starts_with(&prefix)) {
                missing.push(prefix);
            }
        }
    }
    assert!(missing.is_empty(), "missing fixtures: {missing:?}");
}

#[test]
fn every_rule_is_in_signals_md() {
    let doc =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/signals.md"))
            .expect("docs/signals.md");
    let missing: Vec<&str> = rule_ids()
        .into_iter()
        .filter(|id| !doc.contains(&format!("| `{id}` |")))
        .collect();
    assert!(
        missing.is_empty(),
        "rules without a docs/signals.md row: {missing:?}"
    );
}

#[test]
fn every_rule_has_copy() {
    let mut missing = Vec::new();
    for id in rule_ids() {
        for part in ["title", "what", "why", "todo"] {
            let key = format!("{id}.{part}");
            if !bilby_core::copy::CATALOGUE.contains_key(&key) {
                missing.push(key);
            }
        }
    }
    assert!(missing.is_empty(), "missing copy: {missing:?}");
}

/// Every rule id: the ones that make cards and the boost-only ones.
fn rule_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = all_rules().iter().map(|r| r.id()).collect();
    ids.extend_from_slice(BOOST_RULES);
    ids
}

/// Fixture expectations can name a boost rule; it never appears as a
/// finding of its own.
#[test]
fn boost_rules_never_make_their_own_finding() {
    for path in fixture_files() {
        let text = fs::read_to_string(&path).expect("readable fixture");
        let fixture: Fixture = serde_json::from_str(&text).expect("fixture parses");
        let findings = evaluate_all(&fixture.snapshot, &RuleContext::at(fixture.now));
        for f in &findings {
            assert!(
                !BOOST_RULES.contains(&f.rule_id.as_str()),
                "{}: {} made its own finding",
                path.display(),
                f.rule_id
            );
        }
    }
}

/// No two findings in one scan may share an id, or "I know this one" on one
/// would hide the other.
#[test]
fn finding_ids_are_unique_in_every_fixture() {
    for path in fixture_files() {
        let text = fs::read_to_string(&path).expect("readable fixture");
        let fixture: Fixture = serde_json::from_str(&text).expect("fixture parses");
        let findings = evaluate_all(&fixture.snapshot, &RuleContext::at(fixture.now));
        let mut seen = BTreeSet::new();
        for f in &findings {
            assert!(
                seen.insert(f.id()),
                "{}: duplicate id for {}",
                path.display(),
                f.rule_id
            );
        }
    }
}
