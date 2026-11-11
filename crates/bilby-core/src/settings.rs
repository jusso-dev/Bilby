//! User settings that change what a scan does. Stored as booleans only:
//! the VirusTotal key lives in Windows Credential Manager, never here
//! (ADR 0004).

use serde::{Deserialize, Serialize};

/// Which online services the user switched on. Both are off by default,
/// and with both off a scan makes no network connections at all.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
// One switch per service, each its own consent: not a state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct OnlineChecks {
    /// CIRCL hashlookup: sends SHA-256 hashes to CIRCL, the Luxembourg
    /// national CERT, to recognise known software.
    #[serde(default)]
    pub circl: bool,
    /// VirusTotal: sends SHA-256 hashes to VirusTotal with the user's own
    /// key. Never uploads files.
    #[serde(default)]
    pub virustotal: bool,
    /// VirusTotal IP reports: sends the public internet addresses that
    /// programs Bilby already flagged are connected to. Uses the same key.
    #[serde(default)]
    pub virustotal_ips: bool,
    /// AbuseIPDB: sends the same addresses to AbuseIPDB with the user's
    /// own key.
    #[serde(default)]
    pub abuseipdb: bool,
    /// CrowdSec CTI: sends the same addresses to CrowdSec with the user's
    /// own key.
    #[serde(default)]
    pub crowdsec: bool,
}

impl OnlineChecks {
    /// True if any online service is switched on.
    pub fn any(self) -> bool {
        self.circl || self.virustotal || self.ips()
    }

    /// True if any service that receives IP addresses is switched on.
    pub fn ips(self) -> bool {
        self.virustotal_ips || self.abuseipdb || self.crowdsec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_by_default_and_booleans_only() {
        let d = OnlineChecks::default();
        assert!(!d.circl && !d.virustotal && !d.ips() && !d.any());
        assert_eq!(
            serde_json::to_string(&d).unwrap(),
            r#"{"circl":false,"virustotal":false,"virustotal_ips":false,"abuseipdb":false,"crowdsec":false}"#
        );
        // Files from before IP lookups existed still load, with them off.
        let old: OnlineChecks = serde_json::from_str(r#"{"circl":true}"#).unwrap();
        assert!(old.circl && !old.ips());
        // A key or anything else in the file is refused, so it can't be
        // stored there by mistake.
        assert!(serde_json::from_str::<OnlineChecks>(r#"{"virustotal":true,"key":"x"}"#).is_err());
    }
}
