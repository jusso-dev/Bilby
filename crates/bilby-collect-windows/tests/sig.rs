//! Windows-only checks against real files on the runner. They assert shape
//! and sanity, not exact values, because runner images change.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use bilby_collect_windows::cache::FileCache;
use bilby_collect_windows::files::file_facts;
use bilby_collect_windows::paths::known_folders;
use bilby_collect_windows::sig::verify;
use bilby_core::snapshot::{PathClass, SignatureStatus};

fn system32() -> PathBuf {
    PathBuf::from(known_folders().system32)
}

fn assert_windows_signed(path: &Path) {
    let status = verify(&path.to_string_lossy());
    match &status {
        SignatureStatus::Signed {
            publisher,
            is_windows_component,
            kind,
            ..
        } => {
            println!(
                "{}: {publisher} ({kind:?}, windows component: {is_windows_component})",
                path.display()
            );
            assert!(publisher.starts_with("Microsoft"), "{status:?}");
            assert!(is_windows_component, "{status:?}");
        }
        other => panic!("{} should be signed, got {other:?}", path.display()),
    }
}

#[test]
fn windows_binaries_are_signed_windows_components() {
    let dir = system32();
    // Embedded or catalog: either is fine, so check a few that differ.
    for name in ["notepad.exe", "cmd.exe", "kernel32.dll"] {
        let path = dir.join(name);
        if path.exists() {
            assert_windows_signed(&path);
        }
    }
}

fn temp_copy(from: &Path, name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bilby-sig-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let to = dir.join(name);
    std::fs::copy(from, &to).expect("copy");
    to
}

#[test]
fn test_binary_copy_is_unsigned() {
    // cargo test binaries are never signed.
    let me = std::env::current_exe().expect("current exe");
    let copy = temp_copy(&me, "bilby-unsigned-copy.exe");
    let status = verify(&copy.to_string_lossy());
    assert_eq!(status, SignatureStatus::Unsigned, "{}", copy.display());
    let _ = std::fs::remove_file(copy);
}

#[test]
fn tampered_signed_file_is_invalid() {
    // Find a file with an embedded signature: tampering with a
    // catalog-signed file just makes it "unsigned" (its hash is no longer in
    // any catalog), which is a different, also correct, result.
    let dir = system32();
    let candidate = [
        "mrt.exe",
        "wuauclt.exe",
        "ntoskrnl.exe",
        "notepad.exe",
        "cmd.exe",
    ]
    .iter()
    .map(|n| dir.join(n))
    .find(|p| {
        matches!(
            verify(&p.to_string_lossy()),
            SignatureStatus::Signed {
                kind: bilby_core::snapshot::SigKind::Embedded,
                ..
            }
        )
    });
    let Some(signed) = candidate else {
        println!("no embedded-signed candidate on this runner; skipping");
        return;
    };
    let copy = temp_copy(&signed, "bilby-tampered.exe");
    let mut bytes = std::fs::read(&copy).expect("read copy");
    // Flip a byte in the middle of the file, inside the signed content.
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&copy, bytes).expect("write copy");
    let status = verify(&copy.to_string_lossy());
    println!("tampered copy of {}: {status:?}", signed.display());
    assert!(
        matches!(status, SignatureStatus::Invalid { .. }),
        "{status:?}"
    );
    let _ = std::fs::remove_file(copy);
}

#[test]
fn missing_file_is_an_error_not_unsigned() {
    let status = verify(r"C:\definitely\not\here\bilby.exe");
    assert!(
        matches!(status, SignatureStatus::Error { .. }),
        "{status:?}"
    );
}

#[test]
fn known_folders_look_sane() {
    let f = known_folders();
    println!("{f:#?}");
    assert!(f.system32.to_lowercase().ends_with(r"\system32"));
    assert_ne!(f.profile, "");
    assert_ne!(f.temp, "");
    let cache = FileCache::new();
    let notepad = system32().join("notepad.exe");
    let facts = file_facts(&notepad.to_string_lossy(), &f, &cache);
    assert_eq!(facts.class, PathClass::WindowsSystem);
    assert!(!facts.user_writable);
    assert!(facts.sha256.as_ref().is_some_and(|h| h.len() == 64));
    // A second lookup is served from the cache.
    let again = file_facts(&notepad.to_string_lossy(), &f, &cache);
    assert_eq!(facts, again);
    assert_eq!(cache.len(), 1);
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
    let start = Instant::now();
    let mut signed = 0;
    for path in &files {
        if verify(&path.to_string_lossy()).is_signed() {
            signed += 1;
        }
    }
    let elapsed = start.elapsed();
    println!(
        "verified {} files in {:.2}s, {signed} signed",
        files.len(),
        elapsed.as_secs_f64()
    );
    assert!(files.len() >= 100, "expected plenty of System32 binaries");
    assert!(
        signed * 10 >= files.len() * 9,
        "almost all System32 files should be signed"
    );
    assert!(
        elapsed.as_secs() < 15,
        "issue #6 limit is 15 s for 300 files"
    );
}
