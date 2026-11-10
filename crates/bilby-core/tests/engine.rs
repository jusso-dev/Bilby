//! `engine::evaluate`: grouping, order and the light.

use bilby_core::engine::{ALSO_FOUND, ScanMeta, evaluate};
use bilby_core::model::{Evidence, Light, MachineSummary, Severity};
use bilby_core::rules::RuleContext;
use bilby_core::snapshot::SystemSnapshot;
use time::macros::datetime;

const UPDATER: &str = r"C:\Users\Alex\AppData\Local\Temp\updater.exe";

fn file() -> serde_json::Value {
    serde_json::json!({
        "path": UPDATER, "exists": true, "size": 1000, "sha256": null,
        "signature": "unsigned", "class": "temp", "user_writable": true
    })
}

/// Test plan simulations 5, 6 and 17 at once: an unsigned program in Temp
/// that's running, starts from a Run key, listens and connects out.
fn snapshot() -> SystemSnapshot {
    serde_json::from_value(serde_json::json!({
        "processes": [{
            "pid": 5000, "ppid": 4, "name": "updater.exe", "image_path": UPDATER,
            "created": "2026-11-09T08:00:00Z", "session_id": 1, "file": file()
        }],
        "network": { "connections": [
            { "proto": "tcp", "local": "10.0.0.5:50000", "remote": "93.184.216.34:443", "state": "established", "pid": 5000 },
            { "proto": "tcp", "local": "0.0.0.0:4444", "remote": null, "state": "listen", "pid": 5000 }
        ]},
        "persistence": { "items": [{
            "source": "run",
            "location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "name": "Updater", "command": UPDATER, "target": file(),
            "args": null, "host": null, "host_args": null, "enabled": true
        }]}
    }))
    .expect("valid snapshot")
}

fn meta() -> ScanMeta {
    ScanMeta {
        started_at: datetime!(2026-11-09 09:00 UTC),
        finished_at: datetime!(2026-11-09 09:01 UTC),
        checked: Vec::new(),
        machine: MachineSummary::default(),
        is_admin: false,
        timings: Vec::new(),
    }
}

#[test]
fn process_run_key_and_connection_make_one_finding() {
    let snap = snapshot();
    let ctx = RuleContext::with_relations(datetime!(2026-11-09 09:00 UTC), &snap);
    let ungrouped = bilby_core::rules::evaluate_all(&snap, &ctx);
    let rules: Vec<&str> = ungrouped.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rules.contains(&"proc.unsigned_user_writable"), "{rules:?}");
    assert!(
        rules.contains(&"persist.run.unsigned_user_writable"),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"net.listen_unsigned_user_writable"),
        "{rules:?}"
    );

    let report = evaluate(&snap, &ctx, meta());
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    let f = &report.findings[0];
    let worst = ungrouped
        .iter()
        .map(|f| (f.severity, f.confidence))
        .max()
        .unwrap();
    assert_eq!((f.severity, f.confidence), worst);
    let also: Vec<&str> = f
        .evidence
        .iter()
        .filter_map(|e| match e {
            Evidence::Text { label_key, value } if label_key == ALSO_FOUND => Some(value.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(also.len(), ungrouped.len() - 1, "{also:?}");
    // The outbound connection (from the boost) and the Run key both made it in.
    assert!(f.evidence.iter().any(
        |e| matches!(e, Evidence::Connection { remote, .. } if remote.starts_with("93.184.216.34"))
    ));
    assert!(
        f.evidence
            .iter()
            .any(|e| matches!(e, Evidence::RegistryValue { name, .. } if name == "Updater"))
    );
    assert_ne!(report.light, Light::Healthy);
}

#[test]
fn different_files_stay_apart_and_worst_comes_first() {
    let mut snap = snapshot();
    // A second, unrelated unsigned program in Downloads.
    let mut other = snap.processes.as_ref().unwrap()[0].clone();
    other.pid = 6000;
    other.image_path = Some(r"C:\Users\Alex\Downloads\tool.exe".to_owned());
    if let Some(f) = other.file.as_mut() {
        f.path = r"C:\Users\Alex\Downloads\tool.exe".to_owned();
    }
    snap.processes.as_mut().unwrap().push(other);
    let ctx = RuleContext::with_relations(datetime!(2026-11-09 09:00 UTC), &snap);
    let report = evaluate(&snap, &ctx, meta());
    assert_eq!(report.findings.len(), 2, "{:#?}", report.findings);
    let keys: Vec<(Severity, _)> = report
        .findings
        .iter()
        .map(|f| (f.severity, f.confidence))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(keys, sorted);
}

#[test]
fn suppressed_findings_stay_but_do_not_count() {
    let snap = snapshot();
    let mut ctx = RuleContext::with_relations(datetime!(2026-11-09 09:00 UTC), &snap);
    let id = evaluate(&snap, &ctx, meta()).findings[0].id();
    ctx.suppressed.insert(id);
    let report = evaluate(&snap, &ctx, meta());
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.light, Light::Healthy);
}
