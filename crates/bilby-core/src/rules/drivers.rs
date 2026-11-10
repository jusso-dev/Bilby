//! Driver and boot integrity rules. See `docs/signals.md`.
//!
//! Loaded drivers come from [`DriverFacts::loaded`]; driver services from
//! the persistence facts ([`ServiceKind::Driver`]).

use std::sync::LazyLock;

use serde::Deserialize;
use time::Duration;

use super::{FindingBuilder, Rule, RuleContext};
use crate::model::{Confidence, Evidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::paths::{KnownFolders, normalise};
use crate::snapshot::{
    BootIntegrity, CI_DEBUGMODE, CI_ENABLED, CI_HVCI_KMCI, CI_TESTSIGN, DriverFacts, FileFacts,
    ServiceFact, ServiceKind, SignatureStatus, StartType, SystemSnapshot,
};

/// Windows Security's Device security page (memory integrity, Secure Boot).
pub const SETTING_DEVICE_SECURITY: &str = "windowsdefender://devicesecurity";

/// A driver file newer than this is "recently added".
pub const RECENT_DRIVER: Duration = Duration::days(14);

#[derive(Deserialize)]
struct Publishers {
    publishers: Vec<String>,
}

static KNOWN: LazyLock<Publishers> = LazyLock::new(|| {
    toml::from_str(include_str!("../../data/known_driver_publishers.toml"))
        .expect("known_driver_publishers.toml is valid")
});

/// A publisher common on home PCs, or Windows itself.
pub fn known_publisher(sig: &SignatureStatus) -> bool {
    match sig {
        SignatureStatus::Signed {
            publisher,
            is_windows_component,
            ..
        } => {
            let p = publisher.to_ascii_lowercase();
            *is_windows_component || KNOWN.publishers.iter().any(|k| p.starts_with(k.as_str()))
        }
        _ => false,
    }
}

fn norm(p: &str) -> String {
    normalise(p, &KnownFolders::default())
}

/// Unsigned or a broken signature. A check that errored (file gone,
/// access denied) is neither: Bilby doesn't know.
fn bad_signature(s: &SignatureStatus) -> bool {
    matches!(
        s,
        SignatureStatus::Unsigned
            | SignatureStatus::Invalid { .. }
            | SignatureStatus::Untrusted { .. }
    )
}

fn signature_word(s: &SignatureStatus) -> &'static str {
    match s {
        SignatureStatus::Signed { .. } => "signed",
        SignatureStatus::Unsigned => "unsigned",
        SignatureStatus::Invalid { .. } => "invalid",
        SignatureStatus::Untrusted { .. } => "untrusted",
        SignatureStatus::Error { .. } => "error",
    }
}

fn setting(id: &str, severity: Severity, confidence: Confidence) -> FindingBuilder {
    FindingBuilder::new(
        id,
        SignalFamily::Drivers,
        severity,
        confidence,
        Subject::Setting(id.to_owned()),
    )
    .next(NextStepKind::TalkToHelper)
}

fn file_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    f: &FileFacts,
) -> FindingBuilder {
    let name = f.path.rsplit(['\\', '/']).next().unwrap_or(&f.path);
    FindingBuilder::new(
        id,
        SignalFamily::Drivers,
        severity,
        confidence,
        Subject::File(norm(&f.path)),
    )
    .var("name", name)
    .evidence(Evidence::Path(f.path.clone()))
    .evidence(Evidence::Signature {
        status: signature_word(&f.signature).to_owned(),
        publisher: f.signature.publisher().map(str::to_owned),
    })
    .next(NextStepKind::TalkToHelper)
}

fn options(b: &BootIntegrity) -> Option<u32> {
    b.code_integrity_options
}

/// `SystemStartOptions` holds this switch (space-separated, upper case,
/// for example ` NOEXECUTE=OPTIN  TESTSIGNING`).
fn start_option(b: &BootIntegrity, word: &str) -> bool {
    b.start_options.as_deref().is_some_and(|s| {
        s.split_whitespace().any(|w| {
            w.split('=')
                .next()
                .is_some_and(|k| k.eq_ignore_ascii_case(word))
        })
    })
}

fn test_signing(d: &DriverFacts, _: &SnapshotView, _: &RuleContext) -> Vec<Finding> {
    let b = &d.boot;
    let flag = options(b).is_some_and(|o| o & CI_TESTSIGN != 0);
    let switch = start_option(b, "TESTSIGNING");
    if !flag && !switch {
        return Vec::new();
    }
    let mut f = setting("drivers.test_signing", Severity::High, Confidence::High);
    if let Some(o) = options(b) {
        f = f.text("evidence.code_integrity", format!("{o:#x}"));
    }
    if let Some(s) = &b.start_options {
        f = f.text("evidence.start_options", s.trim());
    }
    vec![f.build()]
}

fn integrity_off(d: &DriverFacts, _: &SnapshotView, _: &RuleContext) -> Vec<Finding> {
    let b = &d.boot;
    let not_enforced = options(b).is_some_and(|o| o & CI_ENABLED == 0);
    let switch = start_option(b, "DISABLE_INTEGRITY_CHECKS");
    if !not_enforced && !switch {
        return Vec::new();
    }
    let mut f = setting("drivers.integrity_off", Severity::High, Confidence::High);
    if let Some(o) = options(b) {
        f = f.text("evidence.code_integrity", format!("{o:#x}"));
    }
    if let Some(s) = &b.start_options {
        f = f.text("evidence.start_options", s.trim());
    }
    vec![f.build()]
}

fn kernel_debug(d: &DriverFacts, _: &SnapshotView, _: &RuleContext) -> Vec<Finding> {
    let b = &d.boot;
    let flag = options(b).is_some_and(|o| o & CI_DEBUGMODE != 0);
    let switch = start_option(b, "DEBUG");
    if !flag && !switch {
        return Vec::new();
    }
    let mut f = setting("drivers.kernel_debug", Severity::Medium, Confidence::High);
    if let Some(s) = &b.start_options {
        f = f.text("evidence.start_options", s.trim());
    }
    vec![f.build()]
}

fn unsigned_loaded(d: &DriverFacts, _: &SnapshotView, _: &RuleContext) -> Vec<Finding> {
    d.loaded
        .iter()
        .filter(|f| f.exists && bad_signature(&f.signature))
        .map(|f| {
            file_finding(
                "drivers.unsigned_loaded",
                Severity::High,
                Confidence::High,
                f,
            )
            .build()
        })
        .collect()
}

/// Driver services set to start, with a file, that aren't loaded now.
fn starting_driver_services<'a>(
    d: &'a DriverFacts,
    view: &'a SnapshotView,
) -> impl Iterator<Item = (&'a ServiceFact, &'a FileFacts)> {
    view.services
        .iter()
        .filter(|s| s.kind == ServiceKind::Driver && s.start != StartType::Disabled)
        .filter_map(|s| s.binary.as_ref().map(|b| (s, b)))
        .filter(move |(_, b)| {
            let n = norm(&b.path);
            !d.loaded.iter().any(|l| norm(&l.path) == n)
        })
}

fn unsigned_service(d: &DriverFacts, view: &SnapshotView, _: &RuleContext) -> Vec<Finding> {
    starting_driver_services(d, view)
        // Demand-start drivers sit unused for hardware that isn't plugged in;
        // only ones Windows starts by itself matter here.
        .filter(|(s, b)| s.start != StartType::Demand && b.exists && bad_signature(&b.signature))
        .map(|(s, b)| {
            file_finding(
                "drivers.unsigned_service",
                Severity::Medium,
                Confidence::Medium,
                b,
            )
            .text("evidence.service", &s.name)
            .build()
        })
        .collect()
}

/// Every driver file Bilby knows about, loaded or set to start, once each.
fn all_driver_files<'a>(d: &'a DriverFacts, view: &'a SnapshotView) -> Vec<&'a FileFacts> {
    let mut out: Vec<&FileFacts> = d.loaded.iter().collect();
    for (_, b) in starting_driver_services(d, view) {
        if !out.iter().any(|o| norm(&o.path) == norm(&b.path)) {
            out.push(b);
        }
    }
    out
}

fn user_writable(d: &DriverFacts, view: &SnapshotView, _: &RuleContext) -> Vec<Finding> {
    all_driver_files(d, view)
        .into_iter()
        .filter(|f| f.exists && f.user_writable)
        .map(|f| {
            file_finding("drivers.user_writable", Severity::High, Confidence::High, f)
                .text(
                    "evidence.location",
                    f.path.rsplit_once('\\').map_or("", |(dir, _)| dir),
                )
                .build()
        })
        .collect()
}

fn recent_unknown(d: &DriverFacts, view: &SnapshotView, ctx: &RuleContext) -> Vec<Finding> {
    all_driver_files(d, view)
        .into_iter()
        .filter(|f| {
            f.exists
                && f.signature.is_signed()
                && !known_publisher(&f.signature)
                && f.created.is_some_and(|c| c >= ctx.now - RECENT_DRIVER)
        })
        .map(|f| {
            let mut b = file_finding("drivers.recent_unknown", Severity::Low, Confidence::Low, f);
            if let Some(c) = f.created {
                b = b.text("evidence.created", c);
            }
            b.next(NextStepKind::Learn).build()
        })
        .collect()
}

fn blocklist_off(d: &DriverFacts, _: &SnapshotView, _: &RuleContext) -> Vec<Finding> {
    // Missing means on: Microsoft turned it on by default from the Windows
    // 11 2022 update. Only an explicit 0 is "switched off".
    if d.boot.blocklist_value != Some(0) {
        return Vec::new();
    }
    vec![
        setting("drivers.blocklist_off", Severity::Low, Confidence::High)
            .next(NextStepKind::OpenSetting(
                SETTING_DEVICE_SECURITY.to_owned(),
            ))
            .build(),
    ]
}

fn memory_integrity_off(d: &DriverFacts, _: &SnapshotView, _: &RuleContext) -> Vec<Finding> {
    let b = &d.boot;
    let running = b.memory_integrity_running == Some(true)
        || options(b).is_some_and(|o| o & CI_HVCI_KMCI != 0);
    if running || b.memory_integrity_available != Some(true) || b.memory_integrity_running.is_none()
    {
        return Vec::new();
    }
    vec![
        setting(
            "drivers.memory_integrity_off",
            Severity::Info,
            Confidence::High,
        )
        .next(NextStepKind::OpenSetting(
            SETTING_DEVICE_SECURITY.to_owned(),
        ))
        .build(),
    ]
}

fn secure_boot_off(d: &DriverFacts, _: &SnapshotView, _: &RuleContext) -> Vec<Finding> {
    if d.boot.secure_boot != Some(false) {
        return Vec::new();
    }
    vec![setting("drivers.secure_boot_off", Severity::Info, Confidence::High).build()]
}

/// The parts of the snapshot driver rules read besides `DriverFacts`.
struct SnapshotView<'a> {
    services: &'a [ServiceFact],
}

macro_rules! rule {
    ($name:ident, $id:literal, $fn:ident) => {
        struct $name;
        impl Rule for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn family(&self) -> SignalFamily {
                SignalFamily::Drivers
            }
            fn evaluate(&self, snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding> {
                let Some(d) = &snap.drivers else {
                    return Vec::new();
                };
                let view = SnapshotView {
                    services: snap.persistence.as_ref().map_or(&[], |p| &p.services),
                };
                $fn(d, &view, ctx)
            }
        }
    };
}

rule!(TestSigning, "drivers.test_signing", test_signing);
rule!(IntegrityOff, "drivers.integrity_off", integrity_off);
rule!(KernelDebug, "drivers.kernel_debug", kernel_debug);
rule!(UnsignedLoaded, "drivers.unsigned_loaded", unsigned_loaded);
rule!(
    UnsignedService,
    "drivers.unsigned_service",
    unsigned_service
);
rule!(UserWritable, "drivers.user_writable", user_writable);
rule!(RecentUnknown, "drivers.recent_unknown", recent_unknown);
rule!(BlocklistOff, "drivers.blocklist_off", blocklist_off);
rule!(
    MemoryIntegrityOff,
    "drivers.memory_integrity_off",
    memory_integrity_off
);
rule!(SecureBootOff, "drivers.secure_boot_off", secure_boot_off);

/// The driver rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(TestSigning),
        Box::new(IntegrityOff),
        Box::new(KernelDebug),
        Box::new(UnsignedLoaded),
        Box::new(UnsignedService),
        Box::new(UserWritable),
        Box::new(RecentUnknown),
        Box::new(BlocklistOff),
        Box::new(MemoryIntegrityOff),
        Box::new(SecureBootOff),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishers_load() {
        assert!(KNOWN.publishers.len() > 30);
        assert!(
            KNOWN
                .publishers
                .iter()
                .all(|p| p == &p.to_ascii_lowercase())
        );
    }

    #[test]
    fn start_options_match_whole_switches() {
        let b = |s: &str| BootIntegrity {
            start_options: Some(s.to_owned()),
            ..BootIntegrity::default()
        };
        assert!(start_option(
            &b(" NOEXECUTE=OPTIN  TESTSIGNING"),
            "TESTSIGNING"
        ));
        assert!(start_option(&b(" DEBUG=1394"), "DEBUG"));
        assert!(!start_option(&b(" NODEBUG"), "DEBUG"));
        assert!(!start_option(&b(" NOEXECUTE=OPTIN"), "TESTSIGNING"));
    }
}
