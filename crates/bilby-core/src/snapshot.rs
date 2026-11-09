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

/// Protection status: antivirus, firewall, UAC and Windows Update. Every
/// part is optional because each comes from a different source that can be
/// missing or need admin.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectionFacts {
    /// Microsoft Defender status (`MSFT_MpComputerStatus`).
    #[serde(default)]
    pub defender: Option<DefenderStatus>,
    /// Defender detections from the last 30 days. `None` if they couldn't
    /// be read (often needs admin).
    #[serde(default)]
    pub detections: Option<Vec<Detection>>,
    /// Antivirus products registered with Windows Security Center
    /// (`root\SecurityCenter2`). `None` on Windows Server, where it doesn't
    /// exist.
    #[serde(default)]
    pub antivirus_products: Option<Vec<SecurityProduct>>,
    /// Third-party firewalls registered with Windows Security Center.
    #[serde(default)]
    pub firewall_products: Option<Vec<SecurityProduct>>,
    /// Windows Firewall per profile.
    #[serde(default)]
    pub firewall: Option<FirewallStatus>,
    /// User Account Control settings.
    #[serde(default)]
    pub uac: Option<UacStatus>,
    /// Newest successful Windows Update install, if any was found.
    #[serde(default)]
    pub updates: Option<UpdateStatus>,
}

/// The parts of `MSFT_MpComputerStatus` Bilby uses. Raw values, no
/// judgement.
// Mirrors Windows' own boolean fields one to one, so a struct of bools
// is the honest shape.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DefenderStatus {
    /// `AMServiceEnabled`.
    pub am_service_enabled: bool,
    /// `AntivirusEnabled`.
    pub antivirus_enabled: bool,
    /// `RealTimeProtectionEnabled`.
    pub real_time_protection_enabled: bool,
    /// `BehaviorMonitorEnabled`.
    pub behavior_monitor_enabled: bool,
    /// `IoavProtectionEnabled` (scanning downloads and attachments).
    pub ioav_protection_enabled: bool,
    /// `AntivirusSignatureAge`, in days.
    #[serde(default)]
    pub antivirus_signature_age_days: Option<u32>,
    /// `AntivirusSignatureLastUpdated`.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub antivirus_signature_last_updated: Option<time::OffsetDateTime>,
    /// `QuickScanAge`, in days.
    #[serde(default)]
    pub quick_scan_age_days: Option<u32>,
    /// `FullScanAge`, in days.
    #[serde(default)]
    pub full_scan_age_days: Option<u32>,
    /// `IsTamperProtected`.
    #[serde(default)]
    pub is_tamper_protected: Option<bool>,
    /// `AMRunningMode` as Windows reports it, for example `Normal`,
    /// `Passive Mode` or `EDR Block Mode`.
    #[serde(default)]
    pub am_running_mode: Option<String>,
}

impl DefenderStatus {
    /// Defender is the active antivirus: switched on and not in passive
    /// mode (passive means another antivirus is in charge).
    pub fn is_active(&self) -> bool {
        self.antivirus_enabled && !self.is_passive()
    }

    /// Defender is in passive mode.
    pub fn is_passive(&self) -> bool {
        self.am_running_mode
            .as_deref()
            .is_some_and(|m| m.to_ascii_lowercase().contains("passive"))
    }
}

/// One Defender detection (`MSFT_MpThreatDetection` joined with
/// `MSFT_MpThreat`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Detection {
    /// `ThreatID`.
    pub threat_id: String,
    /// `ThreatName`, for example `Virus:DOS/EICAR_Test_File`.
    #[serde(default)]
    pub threat_name: Option<String>,
    /// `InitialDetectionTime`.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub initial_detection_time: Option<time::OffsetDateTime>,
    /// `LastThreatStatusChangeTime`.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_status_change_time: Option<time::OffsetDateTime>,
    /// `ThreatStatusID`.
    #[serde(default)]
    pub threat_status_id: Option<u32>,
    /// `ActionSuccess`.
    #[serde(default)]
    pub action_success: Option<bool>,
    /// `IsActive` from `MSFT_MpThreat`.
    #[serde(default)]
    pub is_active: Option<bool>,
    /// `DidThreatExecute` from `MSFT_MpThreat`.
    #[serde(default)]
    pub did_threat_execute: Option<bool>,
    /// `SeverityID` from `MSFT_MpThreat`.
    #[serde(default)]
    pub severity_id: Option<u32>,
    /// `Resources`: affected files and keys, as Defender lists them.
    #[serde(default)]
    pub resources: Vec<String>,
    /// `ProcessName`.
    #[serde(default)]
    pub process_name: Option<String>,
}

/// A product registered with Windows Security Center.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityProduct {
    /// `displayName`.
    pub display_name: String,
    /// `productState`, undocumented bit field. See
    /// `crate::rules::protection::decode_product_state`.
    pub product_state: u32,
    /// `pathToSignedProductExe`.
    #[serde(default)]
    pub path: Option<String>,
}

/// Windows Firewall, per network profile.
// Mirrors Windows' own boolean fields one to one, so a struct of bools
// is the honest shape.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallStatus {
    /// Domain profile on.
    pub domain_enabled: bool,
    /// Private profile on.
    pub private_enabled: bool,
    /// Public profile on.
    pub public_enabled: bool,
    /// Profiles in use right now (`CurrentProfileTypes`).
    pub current_domain: bool,
    /// Private is a current profile.
    pub current_private: bool,
    /// Public is a current profile.
    pub current_public: bool,
}

impl FirewallStatus {
    /// Names of current profiles whose firewall is off.
    pub fn current_profiles_off(&self) -> Vec<&'static str> {
        let mut off = Vec::new();
        for (current, enabled, name) in [
            (self.current_domain, self.domain_enabled, "domain"),
            (self.current_private, self.private_enabled, "private"),
            (self.current_public, self.public_enabled, "public"),
        ] {
            if current && !enabled {
                off.push(name);
            }
        }
        off
    }
}

/// User Account Control registry values.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UacStatus {
    /// `EnableLUA`. `None` if the value is absent (Windows treats that as on).
    #[serde(default)]
    pub enable_lua: Option<u32>,
    /// `ConsentPromptBehaviorAdmin`.
    #[serde(default)]
    pub consent_prompt_behavior_admin: Option<u32>,
}

/// Windows Update history.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateStatus {
    /// Date of the newest update that installed successfully.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_success: Option<time::OffsetDateTime>,
    /// Entries in the update history.
    pub history_count: u32,
}

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

/// How a file's digital signature checked out.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Validly signed and trusted.
    Signed {
        /// The signer's display name, for example `Microsoft Windows`.
        publisher: String,
        /// The signing certificate's issuer.
        issuer: String,
        /// Where the signature was found.
        kind: SigKind,
        /// Signed as part of Windows itself.
        is_windows_component: bool,
    },
    /// No signature at all, embedded or in a catalog.
    Unsigned,
    /// A signature is present but doesn't match the file (tampered, bad digest).
    Invalid {
        /// Technical reason, for the helper view.
        reason: String,
    },
    /// Signed, but the chain isn't trusted (untrusted root, expired, distrusted).
    Untrusted {
        /// Technical reason, for the helper view.
        reason: String,
    },
    /// Couldn't check (access denied, file gone, not supported on this OS).
    Error {
        /// Technical reason, for the helper view.
        reason: String,
    },
}

impl SignatureStatus {
    /// True for a valid, trusted signature.
    pub fn is_signed(&self) -> bool {
        matches!(self, Self::Signed { .. })
    }

    /// The publisher, if validly signed.
    pub fn publisher(&self) -> Option<&str> {
        match self {
            Self::Signed { publisher, .. } => Some(publisher),
            _ => None,
        }
    }
}

/// Where a valid signature was found.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigKind {
    /// Inside the file itself.
    Embedded,
    /// In a Windows catalog file that lists the file's hash.
    Catalog,
}

/// What kind of folder a path is in. See `crate::paths::classify`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PathClass {
    /// `%SystemRoot%\System32`, `SysWOW64`, `WinSxS` and drivers.
    WindowsSystem,
    /// The rest of `%SystemRoot%`.
    Windows,
    /// Both Program Files folders.
    ProgramFiles,
    /// `%ProgramFiles%\WindowsApps` (Store apps).
    WindowsApps,
    /// `%ProgramData%`.
    ProgramData,
    /// `%LOCALAPPDATA%\Programs` and known per-user app installs.
    UserAppPrograms,
    /// The rest of `%APPDATA%` and `%LOCALAPPDATA%`.
    UserAppData,
    /// `%TEMP%` and `%SystemRoot%\Temp`.
    Temp,
    /// The user's Downloads folder.
    Downloads,
    /// The user's Desktop.
    Desktop,
    /// The user's Documents folder.
    Documents,
    /// `C:\Users\Public`.
    Public,
    /// Any drive's `$Recycle.Bin`.
    RecycleBin,
    /// A removable drive (USB stick, SD card).
    Removable,
    /// A network share or mapped network drive.
    Network,
    /// Anywhere else.
    Other,
}

impl PathClass {
    /// Folders where an ordinary user (or a program running as them) can
    /// write, so a file there could have been dropped without an installer.
    /// `ProgramData` counts only for files directly in its root; see
    /// `crate::paths::Classified::user_writable`.
    pub fn user_writable(self) -> bool {
        matches!(
            self,
            Self::Temp
                | Self::Downloads
                | Self::Desktop
                | Self::Documents
                | Self::UserAppData
                | Self::UserAppPrograms
                | Self::Public
                | Self::RecycleBin
                | Self::Removable
        )
    }
}

/// Facts about one file on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileFacts {
    /// The path as Windows reported it.
    pub path: String,
    /// Whether the file existed when checked.
    pub exists: bool,
    /// Size in bytes.
    #[serde(default)]
    pub size: Option<u64>,
    /// Creation time (UTC).
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created: Option<time::OffsetDateTime>,
    /// Last-write time (UTC).
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub modified: Option<time::OffsetDateTime>,
    /// Lower-case hex SHA-256. `None` if unread or over the size limit.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Digital signature.
    pub signature: SignatureStatus,
    /// Folder class.
    pub class: PathClass,
    /// Whether an ordinary user can write where this file lives.
    pub user_writable: bool,
}
