//! Rules: pure functions from a snapshot to findings. One module per signal
//! family. Every rule needs a row in `docs/signals.md` and fixtures for
//! "fires" and "look-alike".

pub mod protection;

use std::collections::{BTreeMap, HashSet};

use time::OffsetDateTime;

use crate::model::{Confidence, Evidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::snapshot::SystemSnapshot;

/// Context every rule can read. Known-good lists are filled in by #18.
#[derive(Debug, Clone)]
pub struct RuleContext {
    /// Finding ids the user has marked "I know this one".
    pub suppressed: HashSet<String>,
    /// When the scan ran. Rules use this for ages ("updated 9 days ago") so
    /// they never read the clock themselves and fixtures stay repeatable.
    pub now: OffsetDateTime,
}

impl RuleContext {
    /// A context for a scan at `now` with nothing suppressed.
    pub fn at(now: OffsetDateTime) -> Self {
        Self {
            suppressed: HashSet::new(),
            now,
        }
    }
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
    rules
}

/// Runs every rule over a snapshot.
pub fn evaluate_all(snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding> {
    all_rules()
        .iter()
        .flat_map(|rule| rule.evaluate(snap, ctx))
        .collect()
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
