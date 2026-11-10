//! Smoke test on the Windows runner: loaded drivers and boot integrity are
//! read, and a clean Microsoft-built image doesn't look tampered with.
#![cfg(windows)]

use std::time::Instant;

use bilby_collect_windows::cache::FileCache;
use bilby_collect_windows::drivers::collect;
use bilby_collect_windows::paths::known_folders;
use bilby_collect_windows::persistence;
use bilby_core::model::{CheckStatus, Severity};
use bilby_core::rules::{RuleContext, evaluate_all};
use bilby_core::score::MIN_CONFIDENCE_TO_COUNT;
use bilby_core::snapshot::{CI_ENABLED, CI_TESTSIGN, SystemSnapshot};

#[test]
fn drivers_collector_runs() {
    let folders = known_folders();
    let cache = FileCache::new();
    let start = Instant::now();
    let collected = collect(&folders, &cache);
    println!(
        "drivers collected in {:.2}s: {:?}",
        start.elapsed().as_secs_f64(),
        collected.checks
    );
    let d = &collected.facts;
    println!("boot {:?}", d.boot);
    let unsigned: Vec<_> = d
        .loaded
        .iter()
        .filter(|f| !f.signature.is_signed())
        .map(|f| (&f.path, &f.signature))
        .collect();
    println!(
        "loaded {} drivers, not signed: {unsigned:?}",
        d.loaded.len()
    );

    for (name, status) in &collected.checks {
        assert_eq!(*status, CheckStatus::Ran, "{name} didn't run");
    }
    assert!(
        d.loaded.len() >= 100,
        "a Windows machine loads many drivers"
    );
    assert!(
        d.loaded.iter().all(|f| f.exists),
        "every loaded driver path resolves to a file"
    );
    let ci = d.boot.code_integrity_options.expect("code integrity read");
    assert!(
        ci & CI_ENABLED != 0,
        "code integrity enforced on the runner"
    );
    assert!(ci & CI_TESTSIGN == 0, "test signing off on the runner");

    let persistence = persistence::collect(&folders, &cache).facts;
    let snap = SystemSnapshot {
        drivers: Some(collected.facts),
        persistence: Some(persistence),
        ..Default::default()
    };
    let findings: Vec<_> = evaluate_all(&snap, &RuleContext::at(time::OffsetDateTime::now_utc()))
        .into_iter()
        .filter(|f| f.rule_id.starts_with("drivers."))
        .collect();
    for f in &findings {
        println!(
            "  finding {} {:?}/{:?} {:?}",
            f.rule_id, f.severity, f.confidence, f.subject
        );
    }
    let counted: Vec<_> = findings
        .iter()
        .filter(|f| f.severity > Severity::Info && f.confidence >= MIN_CONFIDENCE_TO_COUNT)
        .map(|f| (&f.rule_id, &f.subject))
        .collect();
    assert!(counted.is_empty(), "clean runner flagged: {counted:?}");
}
