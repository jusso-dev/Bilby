//! The whole scan on this machine: every collector, in parallel, through the
//! orchestrator. Shape and sanity only (docs/test-plan.md, layer 5).
#![cfg(windows)]

use std::time::{Duration, Instant};

use bilby_collect_windows::scan::{CollectOptions, STEPS, StepState, collect};
use bilby_core::model::CheckStatus;

#[test]
fn full_scan_fills_every_section_in_time() {
    let seen = std::sync::Mutex::new(Vec::new());
    // Debug builds hash and verify many times slower than release, and a
    // cold first pass on a busy machine can pass the 30 second limit. The
    // release limits and the 90 second target are checked by the
    // --dump-snapshot step in CI, which runs the release build.
    let opts = if cfg!(debug_assertions) {
        CollectOptions {
            collector_timeout: Duration::from_secs(240),
            scan_timeout: Duration::from_secs(300),
            ..CollectOptions::default()
        }
    } else {
        CollectOptions::default()
    };
    let began = Instant::now();
    let c = collect(&opts, &|p| {
        seen.lock().unwrap().push(p);
    });
    let took = began.elapsed();
    println!("full scan took {took:?}");
    for t in &c.timings {
        println!("  {:<12} {:>6} ms", t.step, t.millis);
    }
    for ch in &c.checks {
        println!("  {:<30} {:?}", ch.id, ch.status);
    }
    // docs/architecture.md: under 90 seconds on a CI runner. Only a warning
    // here, because test builds are unoptimised.
    if took > Duration::from_secs(90) {
        println!("warning: full scan took {took:?} in a test build");
    }
    assert!(!c.cancelled);
    let s = &c.snapshot;
    assert!(s.processes.as_ref().is_some_and(|p| p.len() >= 20));
    assert!(s.protection.is_some() && s.persistence.is_some() && s.browser.is_some());
    assert!(s.tamper.is_some() && s.drivers.is_some() && s.network.is_some());
    assert!(!c.machine.os_name.is_empty() && !c.machine.arch.is_empty());

    let seen = seen.lock().unwrap();
    for step in STEPS {
        assert!(
            seen.iter()
                .any(|p| p.step == *step && p.state == StepState::Running),
            "{step} never started"
        );
        assert!(
            seen.iter()
                .any(|p| p.step == *step && p.state != StepState::Running),
            "{step} never finished"
        );
        assert!(
            c.timings.iter().any(|t| t.step == *step),
            "{step} has no timing"
        );
    }
    let last = seen.last().unwrap();
    assert_eq!(last.done, last.total);
    // Nothing timed out on a normal run.
    assert!(
        !c.checks
            .iter()
            .any(|ch| ch.status == CheckStatus::Failed("took too long".to_owned())),
        "{:?}",
        c.checks
    );
}

/// #17 acceptance: a collector that sleeps 60 seconds times out and the scan
/// still finishes, with `Failed` for it. Run with
/// `cargo test -p bilby-collect-windows --features slow-collector-test --test scan`.
#[cfg(feature = "slow-collector-test")]
#[test]
fn a_collector_that_sleeps_a_minute_times_out() {
    let opts = CollectOptions {
        collector_timeout: Duration::from_secs(20),
        ..CollectOptions::default()
    };
    let began = Instant::now();
    let c = collect(&opts, &|_| {});
    let took = began.elapsed();
    println!("scan with a hung collector took {took:?}");
    // Every other collector also has 20 seconds, so the scan ends within
    // about 20 seconds plus the ones that wait for processes.
    assert!(took < Duration::from_secs(50), "{took:?}");
    let slow = c
        .checks
        .iter()
        .find(|ch| ch.id == "test.slow")
        .expect("slow check listed");
    assert_eq!(slow.status, CheckStatus::Failed("took too long".to_owned()));
    assert!(c.snapshot.protection.is_some(), "{:?}", c.checks);
}
