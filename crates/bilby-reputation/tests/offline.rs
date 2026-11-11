//! With every online switch off (the default), a full scan makes no network
//! connections. Two proofs, as #16 asks:
//!
//! 1. Built with `--features no-network-guard`, constructing the HTTP client
//!    while every switch is off panics. This test runs a full scan's
//!    reputation step with the defaults and doesn't panic.
//! 2. On Windows, every collector plus the rules and the reputation step
//!    runs, then this process's own TCP connections are read with
//!    `GetExtendedTcpTable` (what `Get-NetTCPConnection -OwningProcess`
//!    reads): none may be to a remote address.
//!
//! The orchestrator (#18) will call the same `check` the same way.

use std::time::Duration;

use bilby_core::rules::reputation::{MAX_CIRCL_LOOKUPS, lookup_candidates};
use bilby_core::rules::{RuleContext, evaluate_all};
use bilby_core::settings::OnlineChecks;
use bilby_core::snapshot::SystemSnapshot;
use bilby_reputation::allowlist::Http;
use bilby_reputation::{Cache, Limits, check};

/// What a scan does after the collectors: rules, then the reputation step
/// with the user's settings. The client is only built if a switch is on.
fn reputation_step(snap: &SystemSnapshot, settings: OnlineChecks) -> bool {
    let findings = evaluate_all(snap, &RuleContext::at(time::OffsetDateTime::now_utc()));
    let hashes = lookup_candidates(snap, &findings, MAX_CIRCL_LOOKUPS);
    if !settings.any() {
        return false;
    }
    let http = Http::new(settings.any());
    check(
        settings,
        &hashes,
        None,
        &http,
        &Cache::default(),
        Limits::default(),
        &|_: Duration| {},
    )
    .is_some()
}

#[test]
fn defaults_never_build_a_client() {
    assert_eq!(
        OnlineChecks::default(),
        OnlineChecks {
            circl: false,
            virustotal: false,
            ..OnlineChecks::default()
        }
    );
    assert!(!reputation_step(
        &SystemSnapshot::default(),
        OnlineChecks::default()
    ));
}

#[cfg(windows)]
#[test]
fn full_scan_with_defaults_opens_no_connections() {
    use std::collections::HashSet;

    use bilby_collect_windows::cache::FileCache;
    use bilby_collect_windows::paths::known_folders;
    use bilby_collect_windows::{
        browser, defender, drivers, network, persistence, processes, tamper,
    };

    let folders = known_folders();
    let cache = FileCache::new();
    let procs = processes::collect(&folders, &cache).expect("process snapshot");
    let pids: HashSet<u32> = procs.iter().map(|p| p.pid).collect();
    let net = network::collect(&pids).facts;
    let browser = browser::collect(&folders).facts;
    let tamper = tamper::collect(
        &folders,
        &procs,
        net.as_ref().map_or(&[][..], |n| &n.connections),
        browser.management.clone(),
    )
    .facts;
    let snap = SystemSnapshot {
        protection: Some(defender::collect().facts),
        persistence: Some(persistence::collect(&folders, &cache).facts),
        drivers: Some(drivers::collect(&folders, &cache).facts),
        processes: Some(procs),
        network: net,
        browser: Some(browser),
        tamper: Some(tamper),
        ..Default::default()
    };
    assert!(!reputation_step(&snap, OnlineChecks::default()));

    // This process's own connections, read the way Get-NetTCPConnection
    // -OwningProcess does.
    let me = std::process::id();
    let mine: Vec<_> = network::collect(&HashSet::from([me]))
        .facts
        .map(|n| n.connections)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.pid == me)
        .filter(|c| {
            c.remote
                .is_some_and(|r| !r.ip().is_unspecified() && !r.ip().is_loopback())
        })
        .collect();
    println!("bilby test process {me} remote connections: {mine:?}");
    assert!(mine.is_empty(), "a default scan connected out: {mine:?}");
}
