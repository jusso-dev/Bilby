//! Smoke test on the Windows runner: the tampering collector reads the
//! hosts file, proxy settings and root stores, and changes none of them.
#![cfg(windows)]

use std::time::Instant;

use bilby_collect_windows::paths::known_folders;
use bilby_collect_windows::tamper::collect;
use bilby_core::model::CheckStatus;
use bilby_core::rules::{RuleContext, evaluate_all};
use bilby_core::snapshot::{Management, RootStore, SystemSnapshot};

#[test]
fn tamper_collector_runs() {
    let folders = known_folders();
    let hosts = std::path::Path::new(&folders.system_root).join(r"System32\drivers\etc\hosts");
    let before = std::fs::metadata(&hosts).and_then(|m| m.modified()).ok();

    let start = Instant::now();
    let collected = collect(&folders, &[], &[], Management::default());
    println!(
        "tamper collected in {:.2}s: {:?}",
        start.elapsed().as_secs_f64(),
        collected.checks
    );
    let t = &collected.facts;
    let h = t.hosts.as_ref().expect("hosts file read");
    println!(
        "hosts {} default {} entries {}",
        h.path,
        h.default_path,
        h.entries.len()
    );
    println!("proxy {:?}", t.proxy);
    println!("winhttp {:?}", t.winhttp_proxy);
    println!("dns servers {:?}", t.dns_servers);
    println!("computer name {:?}", t.computer_name);
    println!(
        "roots {} microsoft list read {}",
        t.roots.len(),
        t.microsoft_list_read
    );
    let outside: Vec<_> = t
        .roots
        .iter()
        .filter(|r| {
            !r.in_microsoft_list
                && !matches!(r.store, RootStore::Enterprise | RootStore::GroupPolicy)
        })
        .collect();
    for r in &outside {
        println!(
            "  outside list: {:?} {} {:?} {:?} serial {:?} ca {:?} issuer {:?} from {:?}",
            r.store, r.sha1, r.subject_cn, r.subject_o, r.serial, r.is_ca, r.issuer, r.not_before
        );
    }

    for (name, status) in &collected.checks {
        assert_eq!(*status, CheckStatus::Ran, "{name} didn't run");
    }
    assert!(h.default_path, "the runner uses the default hosts path");
    assert!(t.roots.len() > 10, "a Windows machine has many roots");
    assert!(
        t.roots.iter().all(|r| r.sha1.len() == 40),
        "thumbprints are SHA-1 hex"
    );
    assert!(
        t.roots
            .iter()
            .all(|r| r.sha256.as_ref().is_some_and(|h| h.len() == 64)),
        "every root has a SHA-256"
    );
    assert!(!t.dns_servers.is_empty(), "the runner has a DNS server");
    assert!(
        t.roots.iter().any(|r| r.subject_cn.is_some()),
        "subject names are read"
    );
    if t.microsoft_list_read {
        // A clean runner's machine roots are almost all in Microsoft's list.
        let machine = t
            .roots
            .iter()
            .filter(|r| r.store == RootStore::Machine)
            .count();
        let listed = t
            .roots
            .iter()
            .filter(|r| r.store == RootStore::Machine && r.in_microsoft_list)
            .count();
        assert!(
            listed * 10 >= machine * 8,
            "{listed} of {machine} machine roots in Microsoft's list"
        );
    }
    let after = std::fs::metadata(&hosts).and_then(|m| m.modified()).ok();
    assert_eq!(before, after, "the hosts file must not change");

    let snap = SystemSnapshot {
        tamper: Some(collected.facts),
        ..Default::default()
    };
    let findings = evaluate_all(&snap, &RuleContext::at(time::OffsetDateTime::now_utc()));
    for f in &findings {
        println!(
            "  finding {} {:?}/{:?} {:?}",
            f.rule_id, f.severity, f.confidence, f.subject
        );
    }
    // A clean Microsoft-built image must not look tampered with: no
    // tampering finding is sure enough to change the light.
    let counted: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.severity > bilby_core::model::Severity::Info
                && f.confidence >= bilby_core::score::MIN_CONFIDENCE_TO_COUNT
        })
        .map(|f| (&f.rule_id, &f.subject))
        .collect();
    assert!(counted.is_empty(), "clean runner flagged: {counted:?}");
}
