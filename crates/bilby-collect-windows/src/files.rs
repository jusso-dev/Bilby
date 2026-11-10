//! Everything Bilby wants to know about one file, in one call.

use std::path::Path;

use bilby_core::paths::{KnownFolders, classify};
use bilby_core::snapshot::{FileFacts, SignatureStatus};
use time::OffsetDateTime;

use crate::cache::FileCache;
use crate::{hash, sig};

/// Facts about `path`: size, times, hash, signature and folder class. Uses
/// `cache` so repeat lookups in one scan are free. Never follows the path
/// anywhere it doesn't say: reparse points are reported as the path given.
pub fn file_facts(path: &str, folders: &KnownFolders, cache: &FileCache) -> FileFacts {
    // A cancelled scan's results are thrown away, so don't open the file.
    if cache.cancelled() {
        return not_checked(path, folders, "scan cancelled");
    }
    // Classify the long form, so a short 8.3 spelling can't dodge a folder
    // class. The reported path stays as Windows gave it.
    let classified = classify(&crate::paths::long_path(path), folders);
    let meta = std::fs::metadata(path)
        .ok()
        .filter(std::fs::Metadata::is_file);
    let Some(meta) = meta else {
        return FileFacts {
            path: path.to_owned(),
            exists: false,
            size: None,
            created: None,
            modified: None,
            sha256: None,
            signature: SignatureStatus::Error {
                reason: "file not found".to_owned(),
            },
            class: classified.class,
            user_writable: classified.user_writable,
        };
    };
    let modified = meta.modified().ok();
    let key = (classified.normalised.clone(), meta.len(), modified);
    cache.get_or_insert_with(key, || FileFacts {
        path: path.to_owned(),
        exists: true,
        size: Some(meta.len()),
        created: meta.created().ok().map(OffsetDateTime::from),
        modified: modified.map(OffsetDateTime::from),
        sha256: hash::sha256_file(Path::new(path)).ok().flatten(),
        signature: sig::verify(path),
        class: classified.class,
        user_writable: classified.user_writable,
    })
}

/// Facts for a file Bilby chose not to open (for example on a network
/// drive). `exists` is true so it's never reported as missing; the
/// signature says it wasn't checked.
pub fn not_checked(path: &str, folders: &KnownFolders, why: &str) -> FileFacts {
    let classified = classify(path, folders);
    FileFacts {
        path: path.to_owned(),
        exists: true,
        size: None,
        created: None,
        modified: None,
        sha256: None,
        signature: SignatureStatus::Error {
            reason: why.to_owned(),
        },
        class: classified.class,
        user_writable: classified.user_writable,
    }
}

/// Facts for many files at once, spread over the machine's cores, in the
/// same order as `paths`. Signature checks and hashing dominate a scan, and
/// each file is independent, so this is what collectors should call when
/// they have a list. Uses and fills the shared cache.
pub fn file_facts_many(
    paths: &[String],
    folders: &KnownFolders,
    cache: &FileCache,
) -> Vec<FileFacts> {
    if paths.is_empty() {
        return Vec::new();
    }
    let workers = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(paths.len());
    let chunk = paths.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let handles: Vec<_> = paths
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    part.iter()
                        .map(|p| file_facts(p, folders, cache))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .zip(paths.chunks(chunk))
            .flat_map(|(h, part)| {
                // A panic in one worker shouldn't lose the whole scan: report
                // its files as not checked.
                h.join().unwrap_or_else(|_| {
                    part.iter()
                        .map(|p| not_checked(p, folders, "check failed"))
                        .collect()
                })
            })
            .collect()
    })
}
