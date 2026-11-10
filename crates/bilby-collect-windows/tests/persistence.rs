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
    // Print the command and resolved target behind every task finding, so a
    // false alarm can be traced from the log.
    for t in &p.tasks {
        if findings
            .iter()
            .any(|f| f.subject == bilby_core::model::Subject::Task(t.path.to_lowercase()))
        {
            for a in &t.actions {
                if let bilby_core::snapshot::TaskAction::Exec {
                    command, target, ..
                } = a
                {
                    println!(
                        "  task {} | {command} -> {:?} exists {:?}",
                        t.path,
                        target.as_ref().map(|f| &f.path),
                        target.as_ref().map(|f| f.exists)
                    );
                }
            }
        }
    }
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

    // Services and tasks (#10).
    let drivers = p
        .services
        .iter()
        .filter(|s| s.kind == bilby_core::snapshot::ServiceKind::Driver)
        .count();
    let with_dll = p
        .services
        .iter()
        .filter(|s| s.service_dll.is_some())
        .count();
    let task_actions: usize = p.tasks.iter().map(|t| t.actions.len()).sum();
    println!(
        "services: {} ({drivers} drivers, {with_dll} with a ServiceDll), tasks: {} with {task_actions} actions",
        p.services.len(),
        p.tasks.len()
    );
    assert!(p.services.len() >= 100, "at least 100 services");
    assert!(p.tasks.len() >= 50, "at least 50 tasks");
    assert!(start.elapsed().as_secs() < 20, "issue #10 limit is 20 s");

    // WMI subscriptions (#11). Runner test steps run as admin, so
    // root\subscription is readable, and a clean image has nothing to flag.
    println!("wmi subscriptions: {}", p.wmi.len());
    for w in &p.wmi {
        println!(
            "  wmi {} {} {:?} bound to {} filter(s)",
            w.namespace,
            w.name,
            w.consumer,
            w.filters.len()
        );
    }
    let wmi_status = collected
        .checks
        .iter()
        .find(|c| c.id == "persistence.wmi")
        .map(|c| &c.status);
    assert_eq!(
        wmi_status,
        Some(&CheckStatus::Ran),
        "admin runner can read WMI"
    );
    let wmi_findings = findings
        .iter()
        .filter(|f| f.rule_id.starts_with("persist.wmi."))
        .count();
    assert_eq!(wmi_findings, 0, "clean runner should have no WMI findings");
}
