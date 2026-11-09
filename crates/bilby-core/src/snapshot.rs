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
