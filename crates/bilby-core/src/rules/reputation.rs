//! Reputation rules: VirusTotal results, Defender scans the user asked for,
//! and CIRCL "known good" adjustments. See `docs/signals.md` and ADR 0004.
//!
//! Also decides which hashes are worth looking up ([`lookup_candidates`]),
//! so the online client never sees more than the rules allow.

use std::collections::{BTreeSet, HashMap};

use super::{FindingBuilder, Rule, RuleContext};
use crate::model::{Confidence, Evidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::paths::{KnownFolders, normalise};
use crate::snapshot::{
    DefenderScanOutcome, FileFacts, ReputationFacts, SignatureStatus, SystemSnapshot, VtResult,
};

/// Rule id of the known-good adjustment. It never makes a card.
pub const KNOWN_GOOD: &str = "rep.known_good";

/// VirusTotal engines that must call a file malicious for High.
pub const VT_MALICIOUS: u32 = 5;

/// Most CIRCL lookups in one scan.
pub const MAX_CIRCL_LOOKUPS: usize = 100;

fn norm(p: &str) -> String {
    normalise(p, &KnownFolders::default())
}

/// Every file fact in the snapshot, by normalised path.
fn files(snap: &SystemSnapshot) -> HashMap<String, &FileFacts> {
    let mut all: Vec<&FileFacts> = Vec::new();
    if let Some(p) = &snap.processes {
        all.extend(p.iter().filter_map(|x| x.file.as_ref()));
    }
    if let Some(p) = &snap.persistence {
        all.extend(p.items.iter().filter_map(|i| i.target.as_ref()));
        all.extend(p.ifeo.iter().filter_map(|i| i.target.as_ref()));
        for s in &p.services {
            all.extend(s.binary.iter().chain(s.service_dll.iter()));
        }
        for t in &p.tasks {
            for a in &t.actions {
                if let crate::snapshot::TaskAction::Exec {
                    target: Some(f), ..
                } = a
                {
                    all.push(f);
                }
            }
        }
    }
    if let Some(d) = &snap.drivers {
        all.extend(d.loaded.iter());
    }
    let mut out = HashMap::new();
    for f in all {
        out.entry(norm(&f.path)).or_insert(f);
    }
    out
}

/// Every file path a finding is about: its subject and path evidence.
fn finding_paths(f: &Finding) -> Vec<String> {
    let mut out = Vec::new();
    if let Subject::File(p) = &f.subject {
        out.push(norm(p));
    }
    for e in &f.evidence {
        if let Evidence::Path(p) = e {
            let n = norm(p);
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

/// Hashes worth looking up: files behind findings of Low or higher, the
/// targets of startup items, and running programs that aren't part of
/// Windows. Never every file. Sorted, at most `cap`.
pub fn lookup_candidates(snap: &SystemSnapshot, findings: &[Finding], cap: usize) -> Vec<String> {
    let by_path = files(snap);
    let mut out = BTreeSet::new();
    for f in findings.iter().filter(|f| f.severity >= Severity::Low) {
        for p in finding_paths(f) {
            if let Some(h) = by_path.get(&p).and_then(|x| x.sha256.clone()) {
                out.insert(h);
            }
        }
    }
    if let Some(p) = &snap.persistence {
        for t in p.items.iter().filter_map(|i| i.target.as_ref()) {
            out.extend(t.sha256.clone());
        }
    }
    if let Some(ps) = &snap.processes {
        for f in ps.iter().filter_map(|p| p.file.as_ref()) {
            let windows = matches!(
                f.signature,
                SignatureStatus::Signed {
                    is_windows_component: true,
                    ..
                }
            );
            if !windows {
                out.extend(f.sha256.clone());
            }
        }
    }
    out.into_iter()
        .map(|h| h.to_ascii_lowercase())
        .take(cap)
        .collect()
}

fn down(c: Confidence) -> Confidence {
    match c {
        Confidence::High => Confidence::Medium,
        Confidence::Medium | Confidence::Low => Confidence::Low,
    }
}

/// `rep.known_good`: lowers confidence by one level on findings about a
/// file CIRCL recognised. Runs after every other rule and never makes a
/// card. Reputation findings themselves are left alone: a VirusTotal
/// verdict isn't softened by a known-software list.
pub fn soften_known_good(snap: &SystemSnapshot, findings: &mut [Finding]) {
    let Some(rep) = &snap.reputation else { return };
    if rep.known_good.is_empty() {
        return;
    }
    let known: BTreeSet<String> = rep
        .known_good
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    let by_path = files(snap);
    for f in findings
        .iter_mut()
        .filter(|f| f.family != SignalFamily::Reputation)
    {
        let hit = finding_paths(f).iter().any(|p| {
            by_path
                .get(p)
                .and_then(|x| x.sha256.as_deref())
                .is_some_and(|h| known.contains(&h.to_ascii_lowercase()))
        });
        if hit {
            f.confidence = down(f.confidence);
            f.evidence.push(Evidence::Text {
                label_key: "evidence.lowered_by".to_owned(),
                value: KNOWN_GOOD.to_owned(),
            });
        }
    }
}

fn vt_files<'a>(snap: &'a SystemSnapshot, r: &VtResult) -> Vec<&'a FileFacts> {
    let mut v: Vec<&FileFacts> = files(snap)
        .into_values()
        .filter(|f| {
            f.sha256
                .as_deref()
                .is_some_and(|h| h.eq_ignore_ascii_case(&r.sha256))
        })
        .collect();
    v.sort_by(|a, b| a.path.cmp(&b.path));
    v
}

fn vt_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    snap: &SystemSnapshot,
    r: &VtResult,
) -> Finding {
    let files = vt_files(snap, r);
    let name = files
        .first()
        .and_then(|f| f.path.rsplit(['\\', '/']).next())
        .unwrap_or(&r.sha256)
        .to_owned();
    let mut b = FindingBuilder::new(
        id,
        SignalFamily::Reputation,
        severity,
        confidence,
        Subject::File(
            files
                .first()
                .map_or_else(|| r.sha256.clone(), |f| norm(&f.path)),
        ),
    )
    .var("name", &name)
    .var("count", r.malicious)
    .text("evidence.sha256", &r.sha256)
    .text(
        "evidence.vt_stats",
        format!(
            "{} malicious, {} suspicious, {} undetected, {} harmless",
            r.malicious, r.suspicious, r.undetected, r.harmless
        ),
    )
    .next(NextStepKind::AskDefender);
    if let Some(d) = r.analysed {
        b = b.text("evidence.vt_date", d);
    }
    for f in files {
        b = b.evidence(Evidence::Path(f.path.clone()));
    }
    b.build()
}

fn vt_malicious(rep: &ReputationFacts, snap: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
    rep.virustotal
        .iter()
        .filter(|r| r.malicious >= VT_MALICIOUS)
        .map(|r| {
            vt_finding(
                "rep.vt.malicious",
                Severity::High,
                Confidence::High,
                snap,
                r,
            )
        })
        .collect()
}

fn vt_few(rep: &ReputationFacts, snap: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
    rep.virustotal
        .iter()
        .filter(|r| (1..VT_MALICIOUS).contains(&r.malicious))
        .map(|r| vt_finding("rep.vt.few", Severity::Low, Confidence::Low, snap, r))
        .collect()
}

fn defender_threat(rep: &ReputationFacts, _: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
    rep.defender_scans
        .iter()
        .filter_map(|s| {
            let DefenderScanOutcome::Threat { name } = &s.outcome else {
                return None;
            };
            let file = s.path.rsplit(['\\', '/']).next().unwrap_or(&s.path);
            let mut b = FindingBuilder::new(
                "rep.defender.threat",
                SignalFamily::Reputation,
                Severity::High,
                Confidence::High,
                Subject::File(norm(&s.path)),
            )
            .var("name", file)
            .evidence(Evidence::Path(s.path.clone()))
            .next(NextStepKind::AskDefender);
            if let Some(n) = name {
                b = b.text("evidence.threat", n);
            }
            Some(b.build())
        })
        .collect()
}

macro_rules! rule {
    ($name:ident, $id:literal, $fn:ident) => {
        struct $name;
        impl Rule for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn family(&self) -> SignalFamily {
                SignalFamily::Reputation
            }
            fn evaluate(&self, snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding> {
                snap.reputation
                    .as_ref()
                    .map(|r| $fn(r, snap, ctx))
                    .unwrap_or_default()
            }
        }
    };
}

rule!(VtMalicious, "rep.vt.malicious", vt_malicious);
rule!(VtFew, "rep.vt.few", vt_few);
rule!(DefenderThreat, "rep.defender.threat", defender_threat);

/// The reputation rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(VtMalicious),
        Box::new(VtFew),
        Box::new(DefenderThreat),
    ]
}
