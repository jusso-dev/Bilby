//! Findings to traffic light. Implements "Scoring" in `docs/architecture.md`
//! exactly, and ADR 0005.

use std::collections::HashSet;
use std::hash::BuildHasher;

use crate::model::{Confidence, Finding, Light, Severity};

/// Confidence a finding needs before it can turn the light red or amber.
pub const MIN_CONFIDENCE_TO_COUNT: Confidence = Confidence::Medium;

/// How many Low severity findings (at Medium confidence or more) add up to
/// "Worth a look".
pub const LOW_FINDINGS_FOR_WORTH_A_LOOK: usize = 3;

/// The overall light for these findings. Findings whose [`Finding::id`] is in
/// `suppressed` don't count.
pub fn overall<H: BuildHasher>(findings: &[Finding], suppressed: &HashSet<String, H>) -> Light {
    let counted: Vec<&Finding> = findings
        .iter()
        .filter(|f| !suppressed.contains(&f.id()))
        .collect();
    let sure = |f: &&Finding| f.confidence >= MIN_CONFIDENCE_TO_COUNT;

    if counted
        .iter()
        .any(|f| f.severity == Severity::High && sure(f))
    {
        return Light::NeedsAttention;
    }

    let medium_sure = counted
        .iter()
        .any(|f| f.severity == Severity::Medium && sure(f));
    let high_unsure = counted.iter().any(|f| f.severity == Severity::High);
    let low_sure = counted
        .iter()
        .filter(|f| f.severity == Severity::Low && sure(f))
        .count();

    if medium_sure || high_unsure || low_sure >= LOW_FINDINGS_FOR_WORTH_A_LOOK {
        Light::WorthALook
    } else {
        Light::Healthy
    }
}
