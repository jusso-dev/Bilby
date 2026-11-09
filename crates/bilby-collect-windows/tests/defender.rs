//! Smoke test on the Windows runner: the protection collector finishes
//! quickly and finds Defender. Doesn't assert findings, because runner
//! images change (ADR 0007).
#![cfg(windows)]

use std::time::Instant;

use bilby_collect_windows::defender::collect;
use bilby_core::model::CheckStatus;

#[test]
fn protection_collector_runs() {
    let start = Instant::now();
    let collected = collect();
    let elapsed = start.elapsed();
    println!("protection collected in {:.2}s", elapsed.as_secs_f64());
    for c in &collected.checks {
        println!("  {}: {:?}", c.id, c.status);
    }
    println!("{:#?}", collected.facts);

    assert!(elapsed.as_secs() < 5, "issue #7 limit is 5 s");
    let defender = collected
        .facts
        .defender
        .as_ref()
        .expect("Defender status readable on a runner");
    assert!(defender.am_running_mode.is_some(), "running mode reported");
    // Documented allowed failures: detections can need admin. Nothing else
    // should fail outright on a runner.
    for c in &collected.checks {
        if let CheckStatus::Failed(why) = &c.status {
            assert_eq!(c.id, "protection.detections", "{} failed: {why}", c.id);
        }
    }
    assert!(collected.facts.firewall.is_some(), "firewall readable");
    assert!(collected.facts.uac.is_some(), "UAC readable");
}
