//! Findings, the overall light and the scan report. See `docs/architecture.md`
//! ("Data model").

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// How bad a finding would be if it's true.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Context only. Never moves the light.
    Info,
    /// Minor on its own.
    Low,
    /// Worth a look.
    Medium,
    /// A real problem if true.
    High,
}

/// How likely a finding is to be true.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// "This might be nothing."
    Low,
    /// "This is likely, but check first."
    Medium,
    /// "We're confident about this."
    High,
}

/// The family of checks a finding or check belongs to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SignalFamily {
    /// Antivirus, firewall, UAC and updates.
    Protection,
    /// Running programs.
    Processes,
    /// Things that start by themselves.
    Persistence,
    /// Network connections.
    Network,
    /// Browser extensions and policies.
    Browser,
    /// Hosts file, proxy and root certificates.
    Tamper,
    /// Drivers and boot settings.
    Drivers,
    /// Optional online hash lookups.
    Reputation,
}

/// The overall result shown on the results screen.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Light {
    /// Nothing we checked needs the user.
    Healthy,
    /// Something is unusual and probably fine.
    WorthALook,
    /// Something looks like a real problem.
    NeedsAttention,
}

/// A technical fact behind a finding, shown in the "For your helper" view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// A file or folder path.
    Path(String),
    /// A registry value.
    RegistryValue {
        /// Full key path, for example `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
        key: String,
        /// Value name.
        name: String,
        /// Value data as text.
        data: String,
    },
    /// The digital signature of a file.
    Signature {
        /// Signature status as text, for example `unsigned` or `signed`.
        status: String,
        /// The signer's name, if signed.
        publisher: Option<String>,
    },
    /// A running program.
    Process {
        /// Process id.
        pid: u32,
        /// Image file name.
        name: String,
        /// Full image path, if readable.
        path: Option<String>,
        /// Parent program name, if known.
        parent: Option<String>,
    },
    /// A network connection.
    Connection {
        /// Local address and port.
        local: String,
        /// Remote address and port.
        remote: String,
        /// Connection state, for example `established` or `listen`.
        state: String,
    },
    /// Any other labelled fact. The label is a copy key.
    Text {
        /// Copy key for the label.
        label_key: String,
        /// The value.
        value: String,
    },
}

/// What a finding is about. Used with the rule id for "I know this one".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Subject {
    /// A file, as a lower-cased normalised path.
    File(String),
    /// A registry value, as `key\name`.
    RegistryValue(String),
    /// A scheduled task path.
    Task(String),
    /// A service name.
    Service(String),
    /// A browser extension.
    Extension {
        /// Browser name, for example `chrome`.
        browser: String,
        /// Extension id.
        id: String,
    },
    /// A hosts file line.
    HostsEntry(String),
    /// A certificate thumbprint.
    Certificate(String),
    /// A system setting, for example `defender.realtime`.
    Setting(String),
}

/// The one next step a finding offers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NextStepKind {
    /// Read more about it, nothing to do.
    Learn,
    /// Open a Windows setting. The value is a setting id the app maps to a page.
    OpenSetting(String),
    /// Ask Microsoft Defender to scan the subject file.
    AskDefender,
    /// Offer a reversible fix. The value is the fix id.
    Fix(String),
    /// Ask someone you trust to look.
    TalkToHelper,
}

/// One thing Bilby noticed.
///
/// Rule ids and copy keys are `String` rather than `&'static str` so reports
/// and fixtures can be read back from JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    /// Rule id, for example `proc.masquerade.system_name`.
    pub rule_id: String,
    /// The family the rule belongs to.
    pub family: SignalFamily,
    /// How bad it would be if true.
    pub severity: Severity,
    /// How likely it is to be true.
    pub confidence: Confidence,
    /// Copy key prefix for the title, what, why and to-do strings.
    pub title_key: String,
    /// Values substituted into the copy. Escaped when rendered.
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// Technical facts for the helper view.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// What the UI offers the user.
    pub next_step: NextStepKind,
    /// What the finding is about.
    pub subject: Subject,
}

impl Finding {
    /// A stable id from the rule id and subject: the first 16 hex characters
    /// of a SHA-256 hash. Same input gives the same id on every run and build.
    ///
    /// # Panics
    ///
    /// Never in practice: a `Subject` holds only strings, so it always
    /// serialises.
    pub fn id(&self) -> String {
        use std::fmt::Write as _;

        let subject = serde_json::to_string(&self.subject)
            .expect("a Subject always serialises, it holds only strings");
        let mut hasher = Sha256::new();
        hasher.update(self.rule_id.as_bytes());
        hasher.update([0]);
        hasher.update(subject.as_bytes());
        hasher.finalize()[..8]
            .iter()
            .fold(String::with_capacity(16), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            })
    }
}

/// How one check went.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// The check ran.
    Ran,
    /// The check didn't run. The reason is a copy key.
    Skipped(String),
    /// The check needs Bilby to run as administrator.
    NeedsAdmin,
    /// The check failed. The reason is technical text for the helper view.
    Failed(String),
}

/// One entry in "What we checked".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Check {
    /// Check id, for example `protection.defender`.
    pub id: String,
    /// The family the check belongs to.
    pub family: SignalFamily,
    /// How it went.
    pub status: CheckStatus,
}

/// Basic facts about the computer. Host and user name are only filled in if
/// the user opts in on export.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineSummary {
    /// Operating system name, for example `Windows 11 Home`.
    pub os_name: String,
    /// Version and build, for example `24H2 (26100.2314)`.
    pub os_version: String,
    /// CPU architecture, for example `x64` or `arm64`.
    pub arch: String,
    /// Computer name, only with opt-in.
    #[serde(default)]
    pub hostname: Option<String>,
    /// User name, only with opt-in.
    #[serde(default)]
    pub user: Option<String>,
}

/// The result of one scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanReport {
    /// When the scan started (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// When the scan finished (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
    /// The overall light.
    pub light: Light,
    /// Everything Bilby noticed.
    pub findings: Vec<Finding>,
    /// Every check and how it went.
    pub checked: Vec<Check>,
    /// Basic facts about the computer.
    pub machine: MachineSummary,
    /// The Bilby version that made the report.
    pub bilby_version: String,
    /// True if Bilby ran as administrator ("Check more deeply").
    #[serde(default)]
    pub is_admin: bool,
    /// How long each collector took, for the helper view.
    #[serde(default)]
    pub timings: Vec<Timing>,
}

/// How long one collector took.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Timing {
    /// Collector id, for example `processes`.
    pub step: String,
    /// Wall-clock time in milliseconds. For a collector that timed out,
    /// how long Bilby waited before giving up on it.
    pub millis: u64,
}
