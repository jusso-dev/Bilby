//! Windows-only checks against real files on the runner. They assert shape
//! and sanity, not exact values, because runner images change.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use bilby_collect_windows::cache::FileCache;
use bilby_collect_windows::files::file_facts;
use bilby_collect_windows::paths::known_folders;
use bilby_collect_windows::sig::{embedded_hresult, verify, verify_many};
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
    // Flip a byte in the middle of the first section with data. Section
    // contents are covered by the signature's digest; headers and the
    // certificate table partly aren't, and breaking them makes Windows see
    // no signature at all rather than a tampered one.
    let offset = middle_of_first_section(&bytes).expect("a PE file with sections");
    bytes[offset] ^= 0xFF;
    std::fs::write(&copy, bytes).expect("write copy");
    let status = verify(&copy.to_string_lossy());
    println!(
        "tampered copy of {}: {status:?}, embedded HRESULT {:#010x} (original {:#010x})",
        signed.display(),
        embedded_hresult(&copy.to_string_lossy()),
        embedded_hresult(&signed.to_string_lossy()),
    );
    assert!(
        matches!(status, SignatureStatus::Invalid { .. }),
        "{status:?}"
    );
    let _ = std::fs::remove_file(copy);
}

/// File offset of the middle of the first section that has raw data, from
/// the PE headers: `e_lfanew` at 0x3C, then `PE\0\0`, the 20-byte COFF header
/// and the optional header, then 40-byte section headers.
fn middle_of_first_section(pe: &[u8]) -> Option<usize> {
    let u16_at = |o: usize| {
        pe.get(o..o + 2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
    };
    let u32_at = |o: usize| {
        pe.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let pe_header = u32_at(0x3C)?;
    if pe.get(pe_header..pe_header + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe_header + 4;
    let sections = u16_at(coff + 2)?;
    let optional_size = u16_at(coff + 16)?;
    let table = coff + 20 + optional_size;
    (0..sections).find_map(|i| {
        let header = table + i * 40;
        let raw_size = u32_at(header + 16)?;
        let raw_pointer = u32_at(header + 20)?;
        (raw_size > 0 && raw_pointer + raw_size <= pe.len()).then_some(raw_pointer + raw_size / 2)
    })
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
    let paths: Vec<String> = files
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

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

    // Warm: a second single-threaded pass, for comparison only.
    let start = Instant::now();
    for p in paths.iter().take(50) {
        let _ = verify(p);
    }
    println!(
        "single thread, warm: 50 files in {:.2}s",
        start.elapsed().as_secs_f64()
    );
}
