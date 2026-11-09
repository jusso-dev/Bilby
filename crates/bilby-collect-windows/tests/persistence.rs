//! Smoke test on the Windows runner: startup items read without errors.
//! Prints every item and what the rules make of them, so false alarms on a
//! real machine show up in the log (ADR 0007: assert shape, not findings).
#![cfg(windows)]

use std::time::Instant;

use bilby_collect_windows::cache::FileCache;
use bilby_collect_windows::paths::known_folders;
use bilby_collect_windows::persistence::collect;
use bilby_core::model::CheckStatus;
use bilby_core::rules::{RuleContext, evaluate_all};
use bilby_core::snapshot::SystemSnapshot;

#[test]
fn persistence_collector_runs() {
    let folders = known_folders();
    let cache = FileCache::new();
    let start = Instant::now();
    let collected = collect(&folders, &cache);
    println!(
        "startup items collected in {:.2}s",
        start.elapsed().as_secs_f64()
    );
    for c in &collected.checks {
        println!("  {}: {:?}", c.id, c.status);
    }
    let p = &collected.facts;
    for item in &p.items {
        let t = item.target.as_ref();
        println!(
            "  item {:?} {} | {} | enabled {} | host {:?} -> {} ({:?}, {:?})",
            item.source,
            item.name,
            item.command,
            item.enabled,
            item.host,
            t.map_or("?", |t| t.path.as_str()),
            t.map(|t| t.class),
            t.map(|t| &t.signature),
        );
    }
    println!("  winlogon: {:?}", p.winlogon);
    println!("  ifeo: {} entries", p.ifeo.len());
    for e in &p.ifeo {
        println!("    {} {:?} {}", e.image, e.kind, e.command);
    }
    println!("  appinit: {:?}", p.appinit);

    let snap = SystemSnapshot {
        persistence: Some(collected.facts.clone()),
        ..Default::default()
    };
    let findings = evaluate_all(&snap, &RuleContext::at(time::OffsetDateTime::now_utc()));
    println!("persistence findings on this runner: {}", findings.len());
    for f in &findings {
        println!(
            "  finding {} {:?}/{:?} {:?}",
            f.rule_id, f.severity, f.confidence, f.subject
        );
    }

    assert!(
        p.items
            .iter()
            .any(|i| i.source == bilby_core::snapshot::StartupSource::Run),
        "runners have at least one Run entry"
    );
    for c in &collected.checks {
        assert!(
            !matches!(c.status, CheckStatus::Failed(_)),
            "{} failed: {:?}",
            c.id,
            c.status
        );
    }
    assert!(
        p.winlogon.as_ref().is_some_and(|w| w.userinit.is_some()),
        "Userinit readable"
    );
}
