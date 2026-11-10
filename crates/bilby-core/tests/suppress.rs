//! "I know this one" (#18): save, load, apply, and the file-changed case.

use bilby_core::engine::{ScanMeta, evaluate};
use bilby_core::model::{Evidence, Light, MachineSummary, ScanReport};
use bilby_core::rules::RuleContext;
use bilby_core::snapshot::SystemSnapshot;
use bilby_core::suppress::{CHANGED, Suppressions, UNVERIFIED};
use time::macros::datetime;

const TOOL: &str = r"C:\Users\Alex\Downloads\tool.exe";

/// An unsigned program running from Downloads (Worth a look), with a hash.
fn snapshot(sha256: Option<&str>) -> SystemSnapshot {
    serde_json::from_value(serde_json::json!({
        "processes": [{
            "pid": 6000, "ppid": 4, "name": "tool.exe", "image_path": TOOL,
            "created": "2026-11-09T08:00:00Z", "session_id": 1,
            "file": {
                "path": TOOL, "exists": true, "size": 1000, "sha256": sha256,
                "signature": "unsigned", "class": "downloads", "user_writable": true
            }
        }]
    }))
    .expect("valid snapshot")
}

fn scan(snap: &SystemSnapshot, suppressions: &Suppressions) -> ScanReport {
    let now = datetime!(2026-11-10 09:00 UTC);
    let mut ctx = RuleContext::with_relations(now, snap);
    ctx.suppressions = suppressions.clone();
    evaluate(
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
    )
}

fn temp_file(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bilby-suppress-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("Bilby").join("suppressions.json")
}

#[test]
fn round_trip_and_file_changed() {
    let a = "a".repeat(64);
    let snap = snapshot(Some(&a));
    let before = scan(&snap, &Suppressions::default());
    assert_eq!(before.light, Light::WorthALook, "{:#?}", before.findings);
    let finding = before.findings[0].clone();

    // The user presses "I know this one". Saved, then read back.
    let path = temp_file("round-trip");
    let mut s = Suppressions::load(&path).expect("missing file is empty");
    assert_eq!(s.entries.len(), 0);
    assert!(s.add(
        &finding,
        &snap,
        datetime!(2026-11-10 09:05 UTC),
        "my own tool",
    ));
    s.save(&path).expect("saved");
    let loaded = Suppressions::load(&path).expect("loaded");
    assert_eq!(loaded, s);
    assert_eq!(loaded.entries[0].sha256.as_deref(), Some(a.as_str()));
    assert_eq!(loaded.entries[0].note, "my own tool");
    // No temporary file is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(
        leftovers,
        vec![std::ffi::OsString::from("suppressions.json")]
    );

    // Same file: still shown, marked ignored, doesn't count.
    let after = scan(&snap, &loaded);
    assert_eq!(after.findings.len(), before.findings.len());
    assert_eq!(after.suppressed, vec![finding.id()]);
    assert_eq!(after.light, Light::Healthy);

    // The file changed: the finding comes back, saying so.
    let changed = scan(&snapshot(Some(&"b".repeat(64))), &loaded);
    assert_eq!(changed.suppressed, Vec::<String>::new());
    assert_eq!(changed.light, Light::WorthALook);
    assert!(
        changed.findings[0]
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::Text { label_key, .. } if label_key == CHANGED))
    );

    // Removing it, and ignoring twice keeps one entry.
    let mut again = loaded.clone();
    assert!(again.add(
        &finding,
        &snap,
        datetime!(2026-11-10 10:00 UTC),
        "still mine",
    ));
    assert_eq!(again.entries.len(), 1);
    assert!(again.remove(&finding.id()));
    assert_eq!(again.entries.len(), 0);
    let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
}

#[test]
fn a_broken_file_is_an_error_not_silence() {
    let path = temp_file("broken");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{ not json").unwrap();
    assert!(Suppressions::load(&path).is_err());
    let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
}

/// A file Bilby couldn't fingerprint can't be ignored, and an entry for one
/// without a hash (a hand-edited file) never applies: otherwise it would
/// stay ignored even after the file was replaced.
#[test]
fn an_unhashed_file_finding_is_never_silently_ignored() {
    let snap = snapshot(None);
    let finding = scan(&snap, &Suppressions::default()).findings[0].clone();
    let mut s = Suppressions::default();
    assert!(!s.add(&finding, &snap, datetime!(2026-11-10 09:05 UTC), ""));
    assert_eq!(s.entries.len(), 0);

    // Hand-written entry with no hash for the same finding.
    let entry = serde_json::json!({
        "entries": [{
            "finding_id": finding.id(),
            "rule_id": finding.rule_id,
            "subject": finding.subject,
            "added_at": "2026-11-10T09:05:00Z"
        }]
    });
    let s: Suppressions = serde_json::from_value(entry).expect("valid entry");
    let report = scan(&snap, &s);
    assert_eq!(report.suppressed, Vec::<String>::new());
    assert_eq!(report.light, Light::WorthALook);
    assert!(
        report.findings[0]
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::Text { label_key, .. } if label_key == UNVERIFIED))
    );
}
