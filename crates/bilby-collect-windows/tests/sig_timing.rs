//! Signature check timing, in its own test binary on purpose.
//!
//! Cargo runs test binaries one after another, but tests inside a binary in
//! parallel. In `sig.rs` this timing ran next to tests that write fresh
//! `.exe` copies to Temp, which Windows Defender scans as they land. On
//! those runs the 300 files took 16 to 21 s; run alone they took 0.3 to
//! 0.6 s on the same runner image. Keeping it separate measures Bilby's
//! code, not the other tests.
#![cfg(windows)]

use std::path::PathBuf;
use std::time::Instant;

use bilby_collect_windows::paths::known_folders;
use bilby_collect_windows::sig::{verify, verify_many};
use bilby_core::snapshot::SignatureStatus;

fn system32() -> PathBuf {
    PathBuf::from(known_folders().system32)
}

#[test]
fn verifying_300_files_cold_is_fast_enough() {
    let mut files: Vec<PathBuf> = std::fs::read_dir(system32())
        .expect("read System32")
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("exe") || e.eq_ignore_ascii_case("dll"))
        })
        .collect();
    files.sort();
    files.truncate(300);
    let paths: Vec<String> = files
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    // The first catalog lookup on a fresh machine makes Windows load its
    // catalog database, a one-off that took over 15 s on one runner and
    // under a second on another. It isn't a per-file cost, so time it
    // separately and report it, then time the 300 files with Bilby's own
    // cache empty, as a scan sees them.
    let start = Instant::now();
    let _ = verify(&system32().join("notepad.exe").to_string_lossy());
    println!(
        "first catalog lookup (Windows warm-up): {:.2}s",
        start.elapsed().as_secs_f64()
    );

    let start = Instant::now();
    let results = verify_many(&paths);
    let elapsed = start.elapsed();
    let signed = results.iter().filter(|s| s.is_signed()).count();
    println!(
        "verify_many: {} files in {:.2}s on {} cores, {signed} signed",
        paths.len(),
        elapsed.as_secs_f64(),
        std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
    );
    for (path, status) in paths.iter().zip(&results) {
        if !status.is_signed() {
            println!("  not signed: {path}: {status:?}");
        }
    }
    // Per-file timing, single thread, to see where time goes when a runner
    // is slow. Second pass over the same files, so Windows' own caches are
    // warm; anything still slow here is a genuinely slow file.
    let mut timed: Vec<(f64, &String, bool)> = paths
        .iter()
        .map(|p| {
            let t = Instant::now();
            let status = verify(p);
            let kind = matches!(
                status,
                SignatureStatus::Signed {
                    kind: bilby_core::snapshot::SigKind::Catalog,
                    ..
                }
            );
            (t.elapsed().as_secs_f64(), p, kind)
        })
        .collect();
    let total: f64 = timed.iter().map(|t| t.0).sum();
    let catalog = timed.iter().filter(|t| t.2).count();
    timed.sort_by(|a, b| b.0.total_cmp(&a.0));
    println!("single thread, second pass: {total:.2}s total, {catalog} catalog-signed");
    for (secs, path, is_catalog) in timed.iter().take(8) {
        println!("  slowest: {secs:.3}s {path} (catalog: {is_catalog})");
    }
    assert_eq!(results.len(), paths.len());
    assert!(paths.len() >= 100, "expected plenty of System32 binaries");
    assert!(
        signed * 10 >= paths.len() * 9,
        "almost all System32 files should be signed"
    );
    assert!(
        elapsed.as_secs() < 15,
        "issue #6 limit is 15 s for 300 files"
    );
}
