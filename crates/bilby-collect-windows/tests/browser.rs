//! Smoke test on the Windows runner: the browser collector runs without
//! error even when there are no browser profiles (runners have Edge, maybe
//! without a profile), and writes nothing.
#![cfg(windows)]

use std::time::Instant;

use bilby_collect_windows::browser::collect;
use bilby_collect_windows::paths::known_folders;
use bilby_core::model::CheckStatus;
use bilby_core::rules::{RuleContext, evaluate_all};
use bilby_core::snapshot::SystemSnapshot;

#[test]
fn browser_collector_runs() {
    let folders = known_folders();
    // Note when each browser folder was last changed, so the test can check
    // the collector didn't write anything there.
    let edge = std::path::Path::new(&folders.local_app_data).join(r"Microsoft\Edge\User Data");
    let before = std::fs::metadata(&edge).and_then(|m| m.modified()).ok();

    let start = Instant::now();
    let collected = collect(&folders);
    println!(
        "browser collected in {:.2}s: {:?}",
        start.elapsed().as_secs_f64(),
        collected.status
    );
    let b = &collected.facts;
    println!(
        "extensions: {}, policies: {}, shortcuts: {}, management: {:?}",
        b.extensions.len(),
        b.policies.len(),
        b.shortcuts.len(),
        b.management
    );
    for e in &b.extensions {
        println!(
            "  ext {} {} {} {:?} enabled {} perms {}",
            e.browser,
            e.profile,
            e.name.as_deref().unwrap_or(&e.id),
            e.source,
            e.enabled,
            e.permissions.len()
        );
    }
    for s in &b.shortcuts {
        println!("  shortcut {} {} [{}]", s.browser, s.path, s.arguments);
    }
    print_enrollments();
    // GitHub's runners aren't enrolled in an organisation's MDM: their
    // Enrollments key only holds Windows' built-in providers (Deploy,
    // Cloud and Local Authority). Those must not count as managed.
    assert!(
        !b.management.reasons.iter().any(|r| r == "mdm enrolled"),
        "built-in enrolment records must not count as MDM: {:?}",
        b.management
    );

    assert_eq!(
        collected.status,
        CheckStatus::Ran,
        "browser collector failed"
    );
    let after = std::fs::metadata(&edge).and_then(|m| m.modified()).ok();
    assert_eq!(before, after, "the Edge user data folder must not change");

    let snap = SystemSnapshot {
        browser: Some(collected.facts),
        ..Default::default()
    };
    let findings = evaluate_all(&snap, &RuleContext::at(time::OffsetDateTime::now_utc()));
    for f in &findings {
        println!(
            "  finding {} {:?}/{:?} {:?}",
            f.rule_id, f.severity, f.confidence, f.subject
        );
    }
}

/// What made the runner count as managed, for checking the MDM test.
fn print_enrollments() {
    use bilby_collect_windows::registry::Key;
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY};
    let Some(k) = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Enrollments",
        KEY_WOW64_64KEY,
    ) else {
        println!("  no Enrollments key");
        return;
    };
    for sub in k.subkeys() {
        let s = k.sub(&sub, KEY_WOW64_64KEY);
        let get = |n: &str| {
            s.as_ref()
                .and_then(|s| s.value(n))
                .map(|d| format!("{d:?}"))
        };
        println!(
            "  enrollment {sub}: ProviderID {:?} EnrollmentType {:?} EnrollmentState {:?} DiscoveryServiceFullURL set: {}",
            get("ProviderID"),
            get("EnrollmentType"),
            get("EnrollmentState"),
            get("DiscoveryServiceFullURL").is_some()
        );
    }
}
