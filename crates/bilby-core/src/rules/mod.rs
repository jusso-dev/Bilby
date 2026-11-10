//! Rules: pure functions from a snapshot to findings. One module per signal
//! family. Every rule needs a row in `docs/signals.md` and fixtures for
//! "fires" and "look-alike".

pub mod browser;
pub mod drivers;
pub mod network;
pub mod persistence;
pub mod processes;
pub mod protection;
pub mod tamper;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use time::OffsetDateTime;

use crate::model::{Confidence, Evidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::snapshot::SystemSnapshot;

/// Something another signal family knows about a file, used to raise
/// confidence across families: an unsigned program in `AppData` means more
/// if it also starts by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relation {
    /// The file is the target of a startup item (Run key, task, service...).
    StartsByItself,
    /// A process running this file has an outbound connection.
    OutboundConnection,
    /// A process running this file is listening for connections.
    ListeningPort,
}

/// Context every rule can read. Known-good lists are filled in by #18.
#[derive(Debug, Clone)]
pub struct RuleContext {
    /// Finding ids the user has marked "I know this one".
    pub suppressed: HashSet<String>,
    /// When the scan ran. Rules use this for ages ("updated 9 days ago") so
    /// they never read the clock themselves and fixtures stay repeatable.
    pub now: OffsetDateTime,
    /// Cross-family facts keyed by normalised, lower-case file path. Built
    /// once per scan by [`RuleContext::with_relations`].
    relations: HashMap<String, BTreeSet<Relation>>,
}

impl RuleContext {
    /// A context for a scan at `now` with nothing suppressed and no
    /// cross-family facts.
    pub fn at(now: OffsetDateTime) -> Self {
        Self {
            suppressed: HashSet::new(),
            now,
            relations: HashMap::new(),
        }
    }

    /// A context with cross-family facts worked out from `snap`. Families
    /// add what they know in `relations_from` as their collectors land.
    pub fn with_relations(now: OffsetDateTime, snap: &SystemSnapshot) -> Self {
        let mut ctx = Self::at(now);
        ctx.relations = relations_from(snap);
        ctx
    }

    /// Records a cross-family fact about a file. For tests and for
    /// families whose facts aren't in the snapshot yet.
    pub fn relate(&mut self, path: &str, relation: Relation) {
        self.relations
            .entry(path.to_lowercase())
            .or_default()
            .insert(relation);
    }

    /// What other families know about the file at `path` (normalised,
    /// any case).
    pub fn related(&self, path: &str) -> BTreeSet<Relation> {
        self.relations
            .get(&path.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }
}

/// Cross-family facts from a snapshot. Persistence (#9 to #11) and network
/// (#12) add theirs here.
fn relations_from(snap: &SystemSnapshot) -> HashMap<String, BTreeSet<Relation>> {
    let mut out: HashMap<String, BTreeSet<Relation>> = HashMap::new();
    if let Some(p) = &snap.persistence {
        for item in p.items.iter().filter(|i| i.enabled) {
            if let Some(t) = &item.target {
                out.entry(crate::paths::normalise(
                    &t.path,
                    &crate::paths::KnownFolders::default(),
                ))
                .or_default()
                .insert(Relation::StartsByItself);
            }
        }
    }
    out
}

/// A single check over a snapshot.
pub trait Rule {
    /// Stable rule id, for example `proc.masquerade.system_name`.
    fn id(&self) -> &'static str;
    /// The family this rule belongs to.
    fn family(&self) -> SignalFamily;
    /// Findings for this snapshot. Must not touch the operating system.
    fn evaluate(&self, snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding>;
}

/// Every rule Bilby knows about.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    let mut rules = Vec::new();
    rules.extend(protection::rules());
    rules.extend(processes::rules());
    rules.extend(persistence::rules());
    rules.extend(network::rules());
    rules.extend(browser::rules());
    rules.extend(tamper::rules());
    rules.extend(drivers::rules());
    rules
}

/// Ids of rules that only change other findings and never make their own
/// card. They still need a `docs/signals.md` row and copy for the helper
/// view.
pub const BOOST_RULES: &[&str] = &[network::OUTBOUND_FROM_SUSPICIOUS];

/// Runs every rule over a snapshot, then the boost passes that adjust
/// findings other rules made.
pub fn evaluate_all(snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding> {
    let mut findings: Vec<Finding> = all_rules()
        .iter()
        .flat_map(|rule| rule.evaluate(snap, ctx))
        .collect();
    network::boost_outbound(snap, &mut findings);
    findings
}

/// Builder for findings, so rules read as what they decide rather than
/// struct plumbing. `rule_id` doubles as the copy key prefix.
pub(crate) struct FindingBuilder {
    finding: Finding,
}

impl FindingBuilder {
    pub(crate) fn new(
        rule_id: &str,
        family: SignalFamily,
        severity: Severity,
        confidence: Confidence,
        subject: Subject,
    ) -> Self {
        Self {
            finding: Finding {
                rule_id: rule_id.to_owned(),
                family,
                severity,
                confidence,
                title_key: rule_id.to_owned(),
                vars: BTreeMap::new(),
                evidence: Vec::new(),
                next_step: NextStepKind::Learn,
                subject,
            },
        }
    }

    pub(crate) fn var(mut self, name: &str, value: impl std::fmt::Display) -> Self {
        self.finding.vars.insert(name.to_owned(), value.to_string());
        self
    }

    pub(crate) fn evidence(mut self, evidence: Evidence) -> Self {
        self.finding.evidence.push(evidence);
        self
    }

    pub(crate) fn text(self, label_key: &str, value: impl std::fmt::Display) -> Self {
        self.evidence(Evidence::Text {
            label_key: label_key.to_owned(),
            value: value.to_string(),
        })
    }

    pub(crate) fn next(mut self, step: NextStepKind) -> Self {
        self.finding.next_step = step;
        self
    }

    pub(crate) fn build(self) -> Finding {
        self.finding
    }
}
