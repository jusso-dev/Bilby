//! Demo mode: fixed reports so the UI can be built and tested on any OS.

use std::collections::HashSet;
use std::str::FromStr;

use crate::model::ScanReport;
use crate::score;

/// Which demo report to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoKind {
    /// Looks healthy.
    Healthy,
    /// Worth a look.
    WorthALook,
    /// Needs attention.
    NeedsAttention,
}

impl FromStr for DemoKind {
    type Err = String;

    /// Accepts `healthy`, `worth` or `attention`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "healthy" => Ok(Self::Healthy),
            "worth" => Ok(Self::WorthALook),
            "attention" => Ok(Self::NeedsAttention),
            other => Err(format!(
                "unknown demo kind {other:?}, expected healthy, worth or attention"
            )),
        }
    }
}

/// The raw fixture JSON for a demo kind.
pub fn fixture(kind: DemoKind) -> &'static str {
    match kind {
        DemoKind::Healthy => include_str!("../tests/fixtures/demo/healthy.json"),
        DemoKind::WorthALook => include_str!("../tests/fixtures/demo/worth_a_look.json"),
        DemoKind::NeedsAttention => include_str!("../tests/fixtures/demo/needs_attention.json"),
    }
}

/// A demo report. The light is worked out from the findings, so a fixture
/// can't claim a light its findings don't earn.
///
/// # Panics
///
/// Only if a bundled fixture is invalid JSON, which the tests rule out.
pub fn demo_report(kind: DemoKind) -> ScanReport {
    let mut report: ScanReport =
        serde_json::from_str(fixture(kind)).expect("demo fixtures are valid, checked by tests");
    report.light = score::overall(&report.findings, &HashSet::new());
    report
}
