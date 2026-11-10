//! Snapshot to report: every rule, the boost passes, grouping, order and the
//! light. See "Scan orchestration" in `docs/architecture.md`.
//!
//! Pure, like the rules: the collectors' timings, checks and machine facts
//! come in through [`ScanMeta`], so the same snapshot gives the same report
//! on any machine.

use std::collections::HashMap;

use time::OffsetDateTime;

use crate::model::{
    Check, Evidence, Finding, MachineSummary, ScanReport, SignalFamily, Subject, Timing,
};
use crate::paths::{KnownFolders, normalise};
use crate::rules::{RuleContext, evaluate_all};
use crate::score;

/// Copy key for the evidence line that names a rule folded into a group.
pub const ALSO_FOUND: &str = "evidence.also_found";

/// What the orchestrator knows about the scan, apart from the snapshot.
#[derive(Debug, Clone)]
pub struct ScanMeta {
    /// When the scan started (UTC).
    pub started_at: OffsetDateTime,
    /// When the collectors finished (UTC).
    pub finished_at: OffsetDateTime,
    /// Every check and how it went.
    pub checked: Vec<Check>,
    /// Basic facts about the computer.
    pub machine: MachineSummary,
    /// True if Bilby ran as administrator.
    pub is_admin: bool,
    /// How long each collector took.
    pub timings: Vec<Timing>,
}

/// Runs every rule (boosts included), groups findings about the same file,
/// orders them most serious first and works out the light. Findings in
/// `ctx.suppressed` stay in the report but don't count toward the light.
pub fn evaluate(
    snap: &crate::snapshot::SystemSnapshot,
    ctx: &RuleContext,
    meta: ScanMeta,
) -> ScanReport {
    let mut findings = order(group(evaluate_all(snap, ctx)));
    let mut suppressed = ctx.suppressions.apply(&mut findings, snap);
    suppressed.extend(
        findings
            .iter()
            .map(Finding::id)
            .filter(|id| ctx.suppressed.contains(id)),
    );
    let light = score::overall(&findings, &suppressed);
    let mut ignored: Vec<String> = suppressed.into_iter().collect();
    ignored.sort();
    ScanReport {
        suppressed: ignored,
        started_at: meta.started_at,
        finished_at: meta.finished_at,
        light,
        findings,
        checked: meta.checked,
        machine: meta.machine,
        bilby_version: env!("CARGO_PKG_VERSION").to_owned(),
        is_admin: meta.is_admin,
        timings: meta.timings,
    }
}

/// The file a finding is about, if it's a program, startup item or
/// connection finding. Process and network findings name the file as their
/// subject; startup items name the registry value, task or service, with
/// the file they run as path evidence.
fn group_key(f: &Finding) -> Option<String> {
    let norm = |p: &str| normalise(p, &KnownFolders::default()).to_lowercase();
    match (f.family, &f.subject) {
        (
            SignalFamily::Processes | SignalFamily::Network | SignalFamily::Persistence,
            Subject::File(p),
        ) => Some(norm(p)),
        (SignalFamily::Persistence, _) => f.evidence.iter().find_map(|e| match e {
            Evidence::Path(p) => Some(norm(p)),
            _ => None,
        }),
        _ => None,
    }
}

/// Folds findings about the same file (a program, the startup item that
/// runs it and its connections) into one. The most serious finding leads,
/// by severity then confidence, and keeps its own severity, confidence and
/// id, so grouping never makes the light worse. The others add an "also
/// found" line naming their rule, then any evidence the lead doesn't
/// already have.
pub fn group(findings: Vec<Finding>) -> Vec<Finding> {
    let mut groups: Vec<Vec<Finding>> = Vec::new();
    let mut by_key: HashMap<String, usize> = HashMap::new();
    for f in findings {
        match group_key(&f) {
            Some(key) => {
                if let Some(&i) = by_key.get(&key) {
                    groups[i].push(f);
                } else {
                    by_key.insert(key, groups.len());
                    groups.push(vec![f]);
                }
            }
            None => groups.push(vec![f]),
        }
    }
    groups
        .into_iter()
        .filter_map(|mut g| {
            // Stable, so equal findings keep the rules' order.
            g.sort_by_key(|f| std::cmp::Reverse((f.severity, f.confidence)));
            let mut parts = g.into_iter();
            let mut lead = parts.next()?;
            for other in parts {
                lead.evidence.push(Evidence::Text {
                    label_key: ALSO_FOUND.to_owned(),
                    value: other.rule_id.clone(),
                });
                for e in other.evidence {
                    if !lead.evidence.contains(&e) {
                        lead.evidence.push(e);
                    }
                }
            }
            Some(lead)
        })
        .collect()
}

/// Most serious first: severity, then confidence. Stable, so findings that
/// tie keep the order the rules made them in.
pub fn order(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by_key(|f| std::cmp::Reverse((f.severity, f.confidence)));
    findings
}
