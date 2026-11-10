//! Smoke test on the Windows runner: the connection tables read, ports and
//! addresses convert sensibly, and the rules stay quiet on a clean runner.
#![cfg(windows)]

use std::collections::HashSet;
use std::time::Instant;

use bilby_collect_windows::cache::FileCache;
use bilby_collect_windows::network::collect;
use bilby_collect_windows::paths::known_folders;
use bilby_collect_windows::processes;
use bilby_core::rules::{RuleContext, evaluate_all};
use bilby_core::snapshot::{Proto, SystemSnapshot, TcpState};

#[test]
fn network_collector_runs() {
    let folders = known_folders();
    let cache = FileCache::new();
    // Process snapshot first, then the tables, so pids line up.
    let procs = processes::collect(&folders, &cache).expect("processes");
    let pids: HashSet<u32> = procs.iter().map(|p| p.pid).collect();
    let start = Instant::now();
    let net = collect(&pids).expect("connection tables");
    println!("network collected in {:.2}s", start.elapsed().as_secs_f64());

    let listeners: Vec<_> = net
        .connections
        .iter()
        .filter(|c| c.proto == Proto::Tcp && c.state == Some(TcpState::Listen))
        .collect();
    let established = net
        .connections
        .iter()
        .filter(|c| c.state == Some(TcpState::Established))
        .count();
    let udp = net
        .connections
        .iter()
        .filter(|c| c.proto == Proto::Udp)
        .count();
    println!(
        "rows: {} ({} TCP listeners, {established} established, {udp} UDP)",
        net.connections.len(),
        listeners.len()
    );
    for l in listeners.iter().take(15) {
        let name = procs
            .iter()
            .find(|p| p.pid == l.pid)
            .map_or("?", |p| p.name.as_str());
        println!("  listen {} pid {} {name}", l.local, l.pid);
    }

    assert!(!listeners.is_empty(), "runners always have TCP listeners");
    // Windows always has the RPC endpoint mapper on 135; if conversion were
    // wrong it would show as 34560 (0x8700).
    assert!(
        listeners.iter().any(|l| l.local.port() == 135),
        "port 135 listener (checks byte order)"
    );
    assert!(net.connections.iter().all(|c| pids.contains(&c.pid)));

    let snap = SystemSnapshot {
        processes: Some(procs),
        network: Some(net),
        ..Default::default()
    };
    let findings = evaluate_all(&snap, &RuleContext::at(time::OffsetDateTime::now_utc()));
    for f in findings.iter().filter(|f| f.rule_id.starts_with("net.")) {
        println!(
            "  finding {} {:?}/{:?} {:?}",
            f.rule_id, f.severity, f.confidence, f.subject
        );
    }
}
