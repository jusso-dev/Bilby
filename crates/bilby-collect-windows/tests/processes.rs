//! Smoke test on the Windows runner. Asserts shape, not findings (ADR 0007),
//! and prints every core Windows process it sees so the expected folders in
//! `bilby-core/src/data/windows_core_processes.toml` can be checked against
//! a real install.
#![cfg(windows)]

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use bilby_collect_windows::cache::FileCache;
use bilby_collect_windows::paths::known_folders;
use bilby_collect_windows::processes::collect;
use bilby_core::rules::processes::CORE;
use bilby_core::snapshot::SignatureStatus;

#[test]
fn processes_collector_runs() {
    let folders = known_folders();
    let cache = FileCache::new();
    let start = Instant::now();
    let procs = collect(&folders, &cache).expect("process snapshot");
    let elapsed = start.elapsed();

    let with_path = procs.iter().filter(|p| p.image_path.is_some()).count();
    let windows_components = procs
        .iter()
        .filter(|p| {
            p.file.as_ref().is_some_and(|f| {
                matches!(
                    f.signature,
                    SignatureStatus::Signed {
                        is_windows_component: true,
                        ..
                    }
                )
            })
        })
        .count();
    let with_cmd = procs.iter().filter(|p| p.command_line.is_some()).count();
    println!(
        "processes: {} total, {with_path} with a path, {windows_components} Windows components, \
         {with_cmd} with a command line, {} distinct files, in {:.2}s",
        procs.len(),
        cache.len(),
        elapsed.as_secs_f64()
    );

    // Core process table check: what each core process looks like here.
    let names: HashMap<u32, &str> = procs.iter().map(|p| (p.pid, p.name.as_str())).collect();
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in &procs {
        let lower = p.name.to_lowercase();
        if CORE.contains_key(&lower) {
            let parent = names.get(&p.ppid).copied().unwrap_or("?");
            let line = format!(
                "{} (parent {parent}, user {})",
                p.image_path.as_deref().unwrap_or("<no access>"),
                p.user.as_deref().unwrap_or("?")
            );
            let list = seen.entry(lower).or_default();
            if !list.contains(&line) {
                list.push(line);
            }
        }
    }
    for (name, lines) in &seen {
        for line in lines {
            println!("  core {name}: {line}");
        }
    }

    assert!(procs.len() >= 20, "at least 20 processes");
    assert!(
        windows_components >= 5,
        "at least 5 Windows component signatures"
    );
    assert!(elapsed.as_secs() < 20, "issue #8 limit is 20 s cold");
}
