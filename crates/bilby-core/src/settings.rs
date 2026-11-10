//! User settings that change what a scan does. Stored as booleans only:
//! the VirusTotal key lives in Windows Credential Manager, never here
//! (ADR 0004).

use serde::{Deserialize, Serialize};

/// Which online services the user switched on. Both are off by default,
/// and with both off a scan makes no network connections at all.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OnlineChecks {
    /// CIRCL hashlookup: sends SHA-256 hashes to CIRCL, the Luxembourg
    /// national CERT, to recognise known software.
    #[serde(default)]
    pub circl: bool,
    /// VirusTotal: sends SHA-256 hashes to VirusTotal with the user's own
    /// key. Never uploads files.
    #[serde(default)]
    pub virustotal: bool,
}

impl OnlineChecks {
    /// True if any online service is switched on.
    pub fn any(self) -> bool {
        self.circl || self.virustotal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_by_default_and_booleans_only() {
        let d = OnlineChecks::default();
        assert!(!d.circl && !d.virustotal && !d.any());
        assert_eq!(
            serde_json::to_string(&d).unwrap(),
            r#"{"circl":false,"virustotal":false}"#
        );
        // A key or anything else in the file is refused, so it can't be
        // stored there by mistake.
        assert!(serde_json::from_str::<OnlineChecks>(r#"{"virustotal":true,"key":"x"}"#).is_err());
    }
}
