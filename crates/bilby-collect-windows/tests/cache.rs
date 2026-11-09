//! The cache is shared by collectors on different threads.
#![cfg(windows)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bilby_collect_windows::cache::FileCache;
use bilby_core::snapshot::{FileFacts, PathClass, SignatureStatus};

fn facts(path: &str) -> FileFacts {
    FileFacts {
        path: path.to_owned(),
        exists: true,
        size: Some(1),
        created: None,
        modified: None,
        sha256: None,
        signature: SignatureStatus::Unsigned,
        class: PathClass::Other,
        user_writable: false,
    }
}

#[test]
fn cache_is_shared_across_threads() {
    let cache = Arc::new(FileCache::new());
    let made = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let made = Arc::clone(&made);
            std::thread::spawn(move || {
                for i in 0..50 {
                    let path = format!(r"c:\x\{i}.exe");
                    cache.get_or_insert_with((path.clone(), 1, None), || {
                        made.fetch_add(1, Ordering::Relaxed);
                        facts(&path)
                    });
                }
            })
        })
        .collect();
    for t in threads {
        t.join().expect("thread");
    }
    assert_eq!(cache.len(), 50);
    // Racing threads may both compute a value, but never more than once each.
    assert!(made.load(Ordering::Relaxed) <= 50 * 8);
}

#[test]
fn changed_size_is_a_new_entry() {
    let cache = FileCache::new();
    cache.get_or_insert_with(("a".into(), 1, None), || facts("a"));
    cache.get_or_insert_with(("a".into(), 2, None), || facts("a"));
    assert_eq!(cache.len(), 2);
}
