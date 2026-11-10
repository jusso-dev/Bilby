//! Smoke test on the Windows runner: startup items read without errors.
//! Prints every item and what the rules make of them, so false alarms on a
//! real machine show up in the log (ADR 0007: assert shape, not findings).
//!
//! One collection, then one check per area, so a failure says which area.
#![cfg(windows)]

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bilby_collect_windows::cache::FileCache;
use bilby_collect_windows::paths::known_folders;
use bilby_collect_windows::persistence::{Collected, collect_timed};
use bilby_core::model::{CheckStatus, Finding, Subject};
use bilby_core::rules::{RuleContext, evaluate_all};
use bilby_core::snapshot::{ServiceKind, StartupSource, SystemSnapshot, TaskAction};

struct Run {
    collected: Collected,
    elapsed: Duration,
    findings: Vec<Finding>,
}

/// Collects once for all the tests in this file.
fn run() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| {
        let folders = known_folders();
        let cache = FileCache::new();
        let start = Instant::now();
        let (collected, phases) = collect_timed(&folders, &cache);
        let elapsed = start.elapsed();
        for (name, d) in &phases {
            println!("  phase {name}: {:.2}s", d.as_secs_f64());
        }
        println!("  distinct files checked: {}", cache.len());
        let snap = SystemSnapshot {
            persistence: Some(collected.facts.clone()),
            ..Default::default()
        };
        let findings = evaluate_all(&snap, &RuleContext::at(time::OffsetDateTime::now_utc()));
        println!("startup items collected in {:.2}s", elapsed.as_secs_f64());
        for c in &collected.checks {
            println!("  {}: {:?}", c.id, c.status);
        }
        println!("persistence findings on this runner: {}", findings.len());
        for f in &findings {
            println!(
                "  finding {} {:?}/{:?} {:?}",
                f.rule_id, f.severity, f.confidence, f.subject
            );
        }
        Run {
            collected,
            elapsed,
            findings,
        }
    })
}

#[test]
fn no_check_fails() {
    for c in &run().collected.checks {
        assert!(
            !matches!(c.status, CheckStatus::Failed(_)),
            "{} failed: {:?}",
            c.id,
            c.status
        );
    }
}

#[test]
fn run_keys_and_winlogon() {
    let p = &run().collected.facts;
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
    println!("  ifeo: {} entries, appinit: {:?}", p.ifeo.len(), p.appinit);
    assert!(
        p.items.iter().any(|i| i.source == StartupSource::Run),
        "runners have at least one Run entry"
    );
    assert!(
        p.winlogon.as_ref().is_some_and(|w| w.userinit.is_some()),
        "Userinit readable"
    );
}

#[test]
fn services_and_tasks() {
    let r = run();
    let p = &r.collected.facts;
    let drivers = p
        .services
        .iter()
        .filter(|s| s.kind == ServiceKind::Driver)
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
    // The command and target behind every task finding, so a false alarm
    // can be traced from the log.
    for t in &p.tasks {
        let lower = t.path.to_lowercase();
        if r.findings
            .iter()
            .any(|f| f.subject == Subject::Task(lower.clone()))
        {
            for a in &t.actions {
                if let TaskAction::Exec {
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
    assert!(p.services.len() >= 100, "at least 100 services");
    assert!(p.tasks.len() >= 50, "at least 50 tasks");
    assert!(
        r.elapsed.as_secs() < 20,
        "issue #10 limit is 20 s, took {:.2}s",
        r.elapsed.as_secs_f64()
    );
}

#[test]
fn wmi_subscriptions() {
    let r = run();
    let p = &r.collected.facts;
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
    // Runner test steps run as admin, so root\subscription is readable, and
    // a clean image has nothing to flag.
    let status = r
        .collected
        .checks
        .iter()
        .find(|c| c.id == "persistence.wmi")
        .map(|c| &c.status);
    assert_eq!(status, Some(&CheckStatus::Ran), "admin runner can read WMI");
    let wmi_findings = r
        .findings
        .iter()
        .filter(|f| f.rule_id.starts_with("persist.wmi."))
        .count();
    assert_eq!(wmi_findings, 0, "clean runner should have no WMI findings");
}
