//! The raw facts collectors return. Collectors fill these and never decide
//! what's bad. Each scan engine issue fills in its own section.

use serde::{Deserialize, Serialize};

/// Current snapshot schema. Bump when a change would break old fixtures.
pub const SCHEMA_VERSION: u32 = 1;

fn schema_version() -> u32 {
    SCHEMA_VERSION
}

/// Everything collectors found on one computer. A section is `None` when its
/// collector didn't run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemSnapshot {
    /// Schema version of this snapshot.
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// Antivirus, firewall, UAC and updates.
    #[serde(default)]
    pub protection: Option<ProtectionFacts>,
    /// Running programs.
    #[serde(default)]
    pub processes: Option<Vec<ProcessFact>>,
    /// Things that start by themselves.
    #[serde(default)]
    pub persistence: Option<PersistenceFacts>,
    /// Network connections.
    #[serde(default)]
    pub network: Option<NetworkFacts>,
    /// Browser extensions and policies.
    #[serde(default)]
    pub browser: Option<BrowserFacts>,
    /// Hosts file, proxy and root certificates.
    #[serde(default)]
    pub tamper: Option<TamperFacts>,
    /// Drivers and boot settings.
    #[serde(default)]
    pub drivers: Option<DriverFacts>,
    /// Optional online hash lookups.
    #[serde(default)]
    pub reputation: Option<ReputationFacts>,
}

impl Default for SystemSnapshot {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            protection: None,
            processes: None,
            persistence: None,
            network: None,
            browser: None,
            tamper: None,
            drivers: None,
            reputation: None,
        }
    }
}

/// Protection status. Filled in by the protection issue.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectionFacts {}

/// One running program. Filled in by the processes issue.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessFact {}

/// Startup items. Filled in by the startup items issues.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistenceFacts {}

/// Network connections. Filled in by the network issue.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkFacts {}

/// Browser extensions. Filled in by the browser issue.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserFacts {}

/// Hosts, proxy and certificates. Filled in by the tampering issue.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TamperFacts {}

/// Drivers and boot settings. Filled in by the drivers issue.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriverFacts {}

/// Online lookup results. Filled in by the online checks issue.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReputationFacts {}
