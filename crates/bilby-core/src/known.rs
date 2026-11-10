//! Known-good publishers and startup items (#18), and the pass that uses
//! them to quiet weak findings. See `data/known_publishers.toml` and
//! `data/known_good_items.toml`; every entry says where it was checked.
//!
//! A valid signature from a known publisher:
//!
//! - removes `*unsigned*` findings about that file (it isn't unsigned), and
//! - lowers Low or Medium findings about that file by one confidence level.
//!
//! It never touches masquerading, script hosts, WMI consumers, hosts file,
//! root certificate, driver or reputation findings: a trusted name doesn't
//! make those safe.

use std::sync::LazyLock;

use serde::Deserialize;

use crate::model::{Evidence, Finding, Severity, SignalFamily, Subject};
use crate::rules::reputation::{down, files, finding_paths};
use crate::snapshot::{FileFacts, SignatureStatus, SystemSnapshot};

/// Copy key for the evidence line a softened finding gets.
pub const KNOWN_PUBLISHER: &str = "evidence.known_publisher";

/// One known publisher.
#[derive(Debug, Clone, Deserialize)]
pub struct Publisher {
    /// Exact signer display name.
    pub name: String,
    /// Where the string was checked against a real signed file.
    pub checked: String,
}

/// What kind of startup item a known entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// A scheduled task path.
    Task,
    /// A service name.
    Service,
    /// A WMI event consumer name.
    WmiConsumer,
    /// A browser extension id.
    Extension,
}

/// One known startup item.
#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    /// What it is.
    pub kind: ItemKind,
    /// Name or path prefix, any case.
    pub name: String,
    /// The publisher its file must be validly signed by.
    pub publisher: String,
    /// Where it was seen.
    pub checked: String,
}

#[derive(Deserialize)]
struct Publishers {
    publisher: Vec<Publisher>,
}

#[derive(Deserialize)]
struct Items {
    item: Vec<Entry>,
}

static PUBLISHERS: LazyLock<Vec<Publisher>> = LazyLock::new(|| {
    toml::from_str::<Publishers>(include_str!("../data/known_publishers.toml"))
        .expect("known_publishers.toml is valid, checked by tests")
        .publisher
});

static ITEMS: LazyLock<Vec<Entry>> = LazyLock::new(|| {
    toml::from_str::<Items>(include_str!("../data/known_good_items.toml"))
        .expect("known_good_items.toml is valid, checked by tests")
        .item
});

/// Every known publisher.
pub fn publishers() -> &'static [Publisher] {
    &PUBLISHERS
}

/// Every known startup item.
pub fn items() -> &'static [Entry] {
    &ITEMS
}

/// True only for a valid signature whose signer is exactly a known
/// publisher. Unsigned, invalid, untrusted or unchecked never counts.
pub fn is_known_publisher(sig: &SignatureStatus) -> bool {
    sig.publisher()
        .is_some_and(|p| PUBLISHERS.iter().any(|k| k.name == p))
}

/// The known entry for this item, if its name matches and its file is
/// validly signed by the entry's publisher.
pub fn known_item(
    kind: ItemKind,
    name: &str,
    target: Option<&FileFacts>,
) -> Option<&'static Entry> {
    let name = name.to_lowercase();
    let signer = target.and_then(|t| t.signature.publisher())?;
    ITEMS.iter().find(|e| {
        e.kind == kind && name.starts_with(&e.name.to_lowercase()) && e.publisher == signer
    })
}

/// Rules that fire because of where a file lives (a user-writable folder or
/// `AppData`). Only these are lowered: a trusted signer says nothing about,
/// say, `lsass.exe` having the wrong parent.
fn location_based(f: &Finding) -> bool {
    let id = f.rule_id.as_str();
    (id.contains("user_writable") || id.contains("appdata")) && !id.contains("rundll32")
}

/// Rules a trusted signature must never quiet.
fn never_softened(f: &Finding) -> bool {
    let id = f.rule_id.as_str();
    f.family == SignalFamily::Reputation
        || id.starts_with("proc.masquerade.")
        || id.contains("script_host")
        || id.starts_with("persist.wmi.")
        || id.starts_with("tamper.hosts.")
        || id.starts_with("tamper.root.")
        || id.starts_with("drivers.")
}

/// Applies the known-good lists to findings other rules made. Runs after
/// the boost passes in `rules::evaluate_all`.
pub fn soften_known(snap: &SystemSnapshot, findings: &mut Vec<Finding>) {
    let by_path = files(snap);
    let signer_of = |f: &Finding| -> Option<&'static Publisher> {
        finding_paths(f).iter().find_map(|p| {
            let facts = by_path.get(p)?;
            let name = facts.signature.publisher()?;
            PUBLISHERS.iter().find(|k| k.name == name)
        })
    };
    // A known, validly signed file isn't unsigned, whatever a rule thought.
    findings
        .retain(|f| never_softened(f) || !f.rule_id.contains("unsigned") || signer_of(f).is_none());
    for f in findings.iter_mut() {
        if never_softened(f)
            || !location_based(f)
            || !matches!(f.severity, Severity::Low | Severity::Medium)
        {
            continue;
        }
        let Some(p) = signer_of(f) else { continue };
        let item = match &f.subject {
            Subject::Task(t) => Some((ItemKind::Task, t.as_str())),
            Subject::Service(s) => Some((ItemKind::Service, s.as_str())),
            _ => None,
        };
        let value = match item.and_then(|(kind, name)| {
            let target = finding_paths(f)
                .iter()
                .find_map(|x| by_path.get(x).copied());
            known_item(kind, name, target)
        }) {
            Some(e) => format!("{} ({})", e.publisher, e.name),
            None => p.name.clone(),
        };
        f.confidence = down(f.confidence);
        f.evidence.push(Evidence::Text {
            label_key: KNOWN_PUBLISHER.to_owned(),
            value,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_load_and_every_entry_has_a_source() {
        assert!(publishers().len() >= 10);
        for p in publishers() {
            assert!(
                !p.checked.trim().is_empty(),
                "{} has no source note",
                p.name
            );
            assert_eq!(p.name.trim(), p.name, "{:?} has stray spaces", p.name);
        }
        for e in items() {
            assert!(
                !e.checked.trim().is_empty(),
                "{} has no source note",
                e.name
            );
            assert!(
                publishers().iter().any(|p| p.name == e.publisher),
                "{} names a publisher that isn't in the list",
                e.name
            );
        }
    }

    /// A snapshot with one program at `path` signed by `publisher`.
    fn snap(path: &str, publisher: &str) -> SystemSnapshot {
        serde_json::from_value(serde_json::json!({
            "processes": [{
                "pid": 10, "ppid": 4, "name": "x.exe", "image_path": path,
                "created": "2026-11-10T08:00:00Z", "session_id": 1,
                "file": {
                    "path": path, "exists": true, "size": 1, "sha256": null,
                    "signature": { "signed": {
                        "publisher": publisher, "issuer": "Example CA",
                        "kind": "embedded", "is_windows_component": false
                    }},
                    "class": "user_app_data", "user_writable": true
                }
            }]
        }))
        .expect("valid snapshot")
    }

    fn finding(
        rule: &str,
        severity: Severity,
        confidence: crate::model::Confidence,
        path: &str,
    ) -> Finding {
        Finding {
            rule_id: rule.to_owned(),
            family: SignalFamily::Processes,
            severity,
            confidence,
            title_key: rule.to_owned(),
            vars: std::collections::BTreeMap::new(),
            evidence: Vec::new(),
            next_step: crate::model::NextStepKind::Learn,
            subject: Subject::File(path.to_lowercase()),
        }
    }

    #[test]
    fn a_known_publisher_lowers_location_findings_and_drops_unsigned_ones() {
        use crate::model::Confidence;
        let path = r"C:\Users\Alex\AppData\Roaming\Zoom\bin\Zoom.exe";
        let s = snap(path, "Zoom Video Communications, Inc.");
        let mut f = vec![
            finding(
                "persist.service.user_writable",
                Severity::Medium,
                Confidence::Medium,
                path,
            ),
            finding(
                "net.example_user_writable",
                Severity::Low,
                Confidence::Low,
                path,
            ),
            finding(
                "proc.unsigned_appdata",
                Severity::Low,
                Confidence::Medium,
                path,
            ),
            finding(
                "proc.masquerade.lookalike",
                Severity::Medium,
                Confidence::Medium,
                path,
            ),
            finding(
                "proc.core_parent",
                Severity::Medium,
                Confidence::Medium,
                path,
            ),
        ];
        soften_known(&s, &mut f);
        let got: Vec<(&str, Confidence)> = f
            .iter()
            .map(|x| (x.rule_id.as_str(), x.confidence))
            .collect();
        assert_eq!(
            got,
            vec![
                ("persist.service.user_writable", Confidence::Low),
                ("net.example_user_writable", Confidence::Low),
                // Masquerading is never lowered, and a wrong parent isn't
                // about where the file lives.
                ("proc.masquerade.lookalike", Confidence::Medium),
                ("proc.core_parent", Confidence::Medium),
            ]
        );
        assert!(f[0].evidence.iter().any(
            |e| matches!(e, Evidence::Text { label_key, .. } if label_key == KNOWN_PUBLISHER)
        ));
    }

    #[test]
    fn a_stranger_or_a_look_alike_name_changes_nothing() {
        use crate::model::Confidence;
        let path = r"C:\Users\Alex\AppData\Roaming\Zoom\bin\Zoom.exe";
        for signer in ["Zoom Video Communications Inc", "Some Other Pty Ltd"] {
            let mut f = vec![finding(
                "persist.service.user_writable",
                Severity::Medium,
                Confidence::Medium,
                path,
            )];
            soften_known(&snap(path, signer), &mut f);
            assert_eq!(f[0].confidence, Confidence::Medium, "{signer}");
        }
    }

    #[test]
    fn known_items_need_the_right_signer() {
        let signed = |p: &str| FileFacts {
            path: r"C:\Program Files (x86)\Google\GoogleUpdater\157.0.8089.0\updater.exe"
                .to_owned(),
            exists: true,
            size: Some(1),
            created: None,
            modified: None,
            sha256: None,
            signature: SignatureStatus::Signed {
                publisher: p.to_owned(),
                issuer: "Example CA".to_owned(),
                kind: crate::snapshot::SigKind::Embedded,
                is_windows_component: false,
            },
            class: crate::snapshot::PathClass::ProgramFiles,
            user_writable: false,
        };
        let name = "GoogleUpdaterService157.0.8089.0";
        assert!(known_item(ItemKind::Service, name, Some(&signed("Google LLC"))).is_some());
        assert!(known_item(ItemKind::Service, name, Some(&signed("Evil Ltd"))).is_none());
        assert!(known_item(ItemKind::Service, name, None).is_none());
        assert!(known_item(ItemKind::Task, name, Some(&signed("Google LLC"))).is_none());
    }

    #[test]
    fn only_a_valid_signature_counts() {
        let signed = |p: &str| SignatureStatus::Signed {
            publisher: p.to_owned(),
            issuer: "Example CA".to_owned(),
            kind: crate::snapshot::SigKind::Embedded,
            is_windows_component: false,
        };
        assert!(is_known_publisher(&signed("Google LLC")));
        // Exact strings only: case and look-alikes don't count.
        assert!(!is_known_publisher(&signed("google llc")));
        assert!(!is_known_publisher(&signed("Google LLC.")));
        assert!(!is_known_publisher(&SignatureStatus::Unsigned));
        assert!(!is_known_publisher(&SignatureStatus::Invalid {
            reason: "bad hash".to_owned()
        }));
    }
}
