//! Rules: pure functions from a snapshot to findings. One module per signal
//! family, added by the scan engine issues. Every rule needs a row in
//! `docs/signals.md` and fixtures for "fires" and "look-alike".

use std::collections::HashSet;

use crate::model::{Finding, SignalFamily};
use crate::snapshot::SystemSnapshot;

/// Context every rule can read. Known-good lists are filled in by #18.
#[derive(Debug, Clone, Default)]
pub struct RuleContext {
    /// Finding ids the user has marked "I know this one".
    pub suppressed: HashSet<String>,
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
    Vec::new()
}

/// Runs every rule over a snapshot.
pub fn evaluate_all(snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding> {
    all_rules()
        .iter()
        .flat_map(|rule| rule.evaluate(snap, ctx))
        .collect()
}
