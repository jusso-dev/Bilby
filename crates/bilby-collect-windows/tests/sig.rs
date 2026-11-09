//! Windows-only checks against real files on the runner. They assert shape
//! and sanity, not exact values, because runner images change.
#![cfg(windows)]

use std::path::{Path, PathBuf};

use bilby_collect_windows::cache::FileCache;
use bilby_collect_windows::files::file_facts;
use bilby_collect_windows::paths::known_folders;
use bilby_collect_windows::sig::{embedded_hresult, verify};
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
    // Pick a file whose *copy* still verifies with an embedded signature.
    // Checking the original isn't enough: Windows caches signature results
    // on system files, so an original can verify even when its copy
    // doesn't. Catalog-signed files also don't qualify: once tampered, their
    // hash is in no catalog, so they read as Unsigned, which is correct but
    // a different case.
    let dir = system32();
    let mut candidates: Vec<PathBuf> = [
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    candidates.extend(
        ["mrt.exe", "notepad.exe", "cmd.exe"]
            .iter()
            .map(|n| dir.join(n)),
    );

    let mut chosen = None;
    for original in candidates.iter().filter(|p| p.exists()) {
        let copy = temp_copy(original, "bilby-tamper-candidate.exe");
        let status = verify(&copy.to_string_lossy());
        println!(
            "candidate {}: unmodified copy is {status:?}",
            original.display()
        );
        if matches!(
            status,
            SignatureStatus::Signed {
                kind: bilby_core::snapshot::SigKind::Embedded,
                ..
            }
        ) {
            chosen = Some((original.clone(), copy));
            break;
        }
        let _ = std::fs::remove_file(copy);
    }
    let Some((signed, copy)) = chosen else {
        panic!("no candidate's copy has an embedded signature on this runner");
    };
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

/// The 8.3 short form of `path`, from Windows, or `None` if this volume
/// doesn't keep short names.
fn short_path(path: &str) -> Option<String> {
    use windows::Win32::Storage::FileSystem::GetShortPathNameW;
    use windows::core::HSTRING;
    let wide = HSTRING::from(path);
    // SAFETY: NUL-terminated input; first call only reports the length.
    let needed = unsafe { GetShortPathNameW(&wide, None) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u16; needed as usize];
    // SAFETY: buffer of the length Windows asked for.
    let written = unsafe { GetShortPathNameW(&wide, Some(&mut buf)) } as usize;
    (written > 0 && written < buf.len()).then(|| String::from_utf16_lossy(&buf[..written]))
}

#[test]
fn short_names_classify_like_long_names() {
    let f = known_folders();
    let cache = FileCache::new();
    let me = std::env::current_exe().expect("current exe");
    let copy = temp_copy(&me, "bilby-short-name-test.exe");
    let long = copy.to_string_lossy().into_owned();
    let Some(short) = short_path(&long).filter(|s| s.contains('~')) else {
        println!("no 8.3 short name for {long}; skipping");
        let _ = std::fs::remove_file(copy);
        return;
    };
    let facts = file_facts(&short, &f, &cache);
    println!(
        "{short} -> {:?}, user-writable {}",
        facts.class, facts.user_writable
    );
    assert_eq!(
        facts.class,
        bilby_core::snapshot::PathClass::Temp,
        "{short}"
    );
    assert!(facts.user_writable);
    assert_eq!(
        bilby_collect_windows::paths::long_path(&short).to_lowercase(),
        long.to_lowercase()
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
