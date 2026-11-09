//! Per-scan cache of file facts, so a scan doesn't verify the same
//! `svchost.exe` eighty times. Idea from System Informer's cached verify
//! (docs/research/system-informer.md, idea 2); our own code.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use bilby_core::snapshot::FileFacts;

/// What identifies a file's contents for caching: its normalised path, size
/// and last-write time. If any changes, the file is checked again.
pub type CacheKey = (String, u64, Option<SystemTime>);

/// A thread-safe cache, shared by collectors running in parallel. Lives for
/// one scan.
#[derive(Debug, Default)]
pub struct FileCache {
    inner: Mutex<HashMap<CacheKey, FileFacts>>,
}

impl FileCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The cached facts for `key`, or works them out with `make` and stores
    /// them. `make` runs outside the lock, so two threads may both work out
    /// the same file; the result is the same either way.
    pub fn get_or_insert_with(&self, key: CacheKey, make: impl FnOnce() -> FileFacts) -> FileFacts {
        if let Some(found) = self.lock().get(&key) {
            return found.clone();
        }
        let facts = make();
        self.lock().entry(key).or_insert(facts).clone()
    }

    /// How many files are cached.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// True if nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, FileFacts>> {
        // A panic while holding the lock can't leave the map half-written,
        // because each insert is a single call, so a poisoned lock is safe
        // to keep using.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
