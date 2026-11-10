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

/// One running program. Anything Windows wouldn't tell us without admin is
/// `None`; that's normal for other users' and protected processes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessFact {
    /// Process id.
    pub pid: u32,
    /// Parent process id, as recorded when this process started. The parent
    /// may have exited and its id been reused since.
    pub ppid: u32,
    /// Image file name, for example `svchost.exe`.
    pub name: String,
    /// Full image path.
    #[serde(default)]
    pub image_path: Option<String>,
    /// When the process started (UTC).
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created: Option<time::OffsetDateTime>,
    /// Terminal Services session id.
    #[serde(default)]
    pub session_id: Option<u32>,
    /// Account the process runs as, `DOMAIN\user`.
    #[serde(default)]
    pub user: Option<String>,
    /// Running elevated.
    #[serde(default)]
    pub is_elevated: Option<bool>,
    /// Command line, only for the current user's processes without admin.
    #[serde(default)]
    pub command_line: Option<String>,
    /// Facts about the image file.
    #[serde(default)]
    pub file: Option<FileFacts>,
}

/// Things set to start by themselves. Each source is optional because
/// each is read on its own.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistenceFacts {
    /// Run keys, startup folders and policy Run entries.
    #[serde(default)]
    pub items: Vec<StartupItem>,
    /// Winlogon `Shell` and `Userinit` values.
    #[serde(default)]
    pub winlogon: Option<WinlogonValues>,
    /// Image File Execution Options debuggers and silent-exit monitors.
    #[serde(default)]
    pub ifeo: Vec<IfeoEntry>,
    /// `AppInit_DLLs` settings, 64-bit and 32-bit views.
    #[serde(default)]
    pub appinit: Vec<AppInit>,
    /// Windows services and kernel drivers.
    #[serde(default)]
    pub services: Vec<ServiceFact>,
    /// Scheduled tasks.
    #[serde(default)]
    pub tasks: Vec<TaskFact>,
    /// WMI event consumers, from `root\\subscription` and `root\\default`.
    #[serde(default)]
    pub wmi: Vec<WmiSubscription>,
}

/// What a WMI event consumer does when its event fires.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WmiConsumerKind {
    /// `CommandLineEventConsumer`: runs a program.
    CommandLine {
        /// `CommandLineTemplate`.
        #[serde(default)]
        command_line: Option<String>,
        /// `ExecutablePath`.
        #[serde(default)]
        executable: Option<String>,
    },
    /// `ActiveScriptEventConsumer`: runs a `VBScript` or `JScript` script.
    ActiveScript {
        /// `ScriptingEngine`.
        #[serde(default)]
        engine: Option<String>,
        /// `ScriptText`, cut to 2,000 characters.
        #[serde(default)]
        text: Option<String>,
        /// `ScriptFileName`.
        #[serde(default)]
        file: Option<String>,
    },
    /// Writes to the event log, a file or email. Recorded, never flagged.
    Other {
        /// The WMI class, for example `NTEventLogEventConsumer`.
        class: String,
    },
}

/// One WMI event consumer and whether anything binds a filter to it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WmiSubscription {
    /// `root\\subscription` or `root\\default`.
    pub namespace: String,
    /// Consumer `Name`.
    pub name: String,
    /// What it does.
    pub consumer: WmiConsumerKind,
    /// Filters bound to it (their `Name` and `Query`). Empty means unbound.
    #[serde(default)]
    pub filters: Vec<WmiFilter>,
}

/// An `__EventFilter` bound to a consumer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WmiFilter {
    /// Filter `Name`.
    pub name: String,
    /// The WQL query that triggers it.
    #[serde(default)]
    pub query: Option<String>,
}

/// A service or driver.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    /// Runs in its own process.
    OwnProcess,
    /// Shares a process, usually `svchost.exe`.
    SharedProcess,
    /// A kernel or file-system driver. Evaluated by the drivers rules (#15).
    Driver,
}

/// When a service starts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartType {
    /// Boot or system start (drivers).
    Boot,
    /// Starts with Windows.
    Auto,
    /// Starts when something asks for it.
    Demand,
    /// Turned off.
    Disabled,
}

/// One service from the Service Control Manager.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceFact {
    /// Service name.
    pub name: String,
    /// Display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Process type.
    pub kind: ServiceKind,
    /// When it starts.
    pub start: StartType,
    /// Running now.
    pub running: bool,
    /// `lpBinaryPathName` as stored.
    pub binary_path: String,
    /// The file the binary path runs.
    #[serde(default)]
    pub binary: Option<FileFacts>,
    /// The host the binary path runs through, if any.
    #[serde(default)]
    pub host: Option<String>,
    /// Arguments given to that host.
    #[serde(default)]
    pub host_args: Option<String>,
    /// `Parameters\ServiceDll` for shared services.
    #[serde(default)]
    pub service_dll: Option<FileFacts>,
    /// Account it runs as.
    #[serde(default)]
    pub account: Option<String>,
}

/// One scheduled task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskFact {
    /// Full path, for example `\Microsoft\Windows\Defrag\ScheduledDefrag`.
    pub path: String,
    /// Enabled.
    pub enabled: bool,
    /// Marked hidden in its settings.
    #[serde(default)]
    pub hidden: bool,
    /// `RegistrationInfo.Author`.
    #[serde(default)]
    pub author: Option<String>,
    /// Account it runs as.
    #[serde(default)]
    pub user: Option<String>,
    /// Runs with highest privileges.
    #[serde(default)]
    pub elevated: bool,
    /// Last time it ran.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_run: Option<time::OffsetDateTime>,
    /// What it runs.
    #[serde(default)]
    pub actions: Vec<TaskAction>,
}

/// One task action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskAction {
    /// Runs a program.
    Exec {
        /// `Path` and `Arguments` joined, as a command line.
        command: String,
        /// The file it runs, after looking through hosts. Boxed, because
        /// file facts are large next to a COM class id.
        #[serde(default)]
        target: Option<Box<FileFacts>>,
        /// The host it runs through.
        #[serde(default)]
        host: Option<String>,
        /// Arguments given to that host.
        #[serde(default)]
        host_args: Option<String>,
    },
    /// Calls a COM handler. Recorded, Info only.
    ComHandler {
        /// The class id.
        class_id: String,
    },
}

/// Where a startup item came from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum StartupSource {
    /// A `Run` key.
    Run,
    /// A `RunOnce` key.
    RunOnce,
    /// `RunOnceEx`.
    RunOnceEx,
    /// `Policies\Explorer\Run`.
    PolicyRun,
    /// A startup folder shortcut or file.
    StartupFolder,
}

/// One program set to start by itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartupItem {
    /// Where it came from.
    pub source: StartupSource,
    /// Registry key or folder path.
    pub location: String,
    /// Value name or file name.
    pub name: String,
    /// The command as stored (for shortcuts, target plus arguments).
    pub command: String,
    /// The file the command runs, after looking through hosts.
    #[serde(default)]
    pub target: Option<FileFacts>,
    /// Arguments after the target.
    #[serde(default)]
    pub args: Option<String>,
    /// The host the command runs through, for example `powershell`.
    #[serde(default)]
    pub host: Option<String>,
    /// Arguments given to the host itself.
    #[serde(default)]
    pub host_args: Option<String>,
    /// From `StartupApproved`: false if the user turned it off in Task
    /// Manager or Settings.
    pub enabled: bool,
    /// When the key was last written.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_write: Option<time::OffsetDateTime>,
}

/// Winlogon values that choose the shell and the sign-in program.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WinlogonValues {
    /// `HKLM` `Shell`.
    #[serde(default)]
    pub shell_machine: Option<String>,
    /// `HKCU` `Shell`, which overrides it for one user.
    #[serde(default)]
    pub shell_user: Option<String>,
    /// `HKLM` `Userinit`.
    #[serde(default)]
    pub userinit: Option<String>,
}

/// An Image File Execution Options entry that runs something else.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IfeoEntry {
    /// The program it attaches to, for example `taskmgr.exe`.
    pub image: String,
    /// `Debugger` (runs instead) or `MonitorProcess` (runs on exit).
    pub kind: IfeoKind,
    /// The command it runs.
    pub command: String,
    /// The file that command runs.
    #[serde(default)]
    pub target: Option<FileFacts>,
}

/// Which IFEO mechanism.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IfeoKind {
    /// `Image File Execution Options\<image>\Debugger`.
    Debugger,
    /// `SilentProcessExit\<image>\MonitorProcess`.
    MonitorProcess,
}

/// `AppInit_DLLs` for one registry view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppInit {
    /// The key it came from.
    pub location: String,
    /// `LoadAppInit_DLLs`.
    pub load: Option<u32>,
    /// `AppInit_DLLs`.
    pub dlls: Option<String>,
}

/// Network connections and listeners, with the process that owns each.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkFacts {
    /// Every TCP and UDP row whose process was in the process list.
    #[serde(default)]
    pub connections: Vec<ConnectionFact>,
}

/// TCP or UDP.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// TCP state, for the states the rules care about.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    /// Waiting for connections.
    Listen,
    /// Connected.
    Established,
    /// Anything else (closing, time-wait...).
    Other,
}

/// One row from the connection tables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionFact {
    /// TCP or UDP.
    pub proto: Proto,
    /// Local address and port.
    pub local: std::net::SocketAddr,
    /// Remote address and port, for TCP rows that have one.
    #[serde(default)]
    pub remote: Option<std::net::SocketAddr>,
    /// TCP state. `None` for UDP.
    #[serde(default)]
    pub state: Option<TcpState>,
    /// Owning process id.
    pub pid: u32,
}

/// Browser extensions, extension policies and browser shortcuts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserFacts {
    /// Every extension in every profile that could be read.
    #[serde(default)]
    pub extensions: Vec<ExtensionFact>,
    /// Extensions forced on by policy.
    #[serde(default)]
    pub policies: Vec<BrowserPolicy>,
    /// Shortcuts that start a browser, with their arguments.
    #[serde(default)]
    pub shortcuts: Vec<BrowserShortcut>,
    /// Whether an organisation manages this computer.
    #[serde(default)]
    pub management: Management,
}

/// How an extension was installed. Chromium's `ManifestLocation` values
/// (`extensions/common/mojom/manifest.mojom`), plus Firefox's locations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionSource {
    /// From the browser's store (Chromium 1, Firefox `app-profile` signed).
    Store,
    /// Added by another program through prefs or the registry (2, 3, 6).
    External,
    /// Loaded from a folder in developer mode (4).
    Unpacked,
    /// Part of the browser itself (5, 10, Firefox built-in). Skipped.
    Component,
    /// Installed by policy (7, 9).
    Policy,
    /// `--load-extension` on the command line (8).
    CommandLine,
    /// Firefox `app-profile`: installed by the user.
    FirefoxProfile,
    /// Anything else.
    Other,
}

/// One extension in one browser profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtensionFact {
    /// `chrome`, `edge`, `brave`, `vivaldi`, `opera` or `firefox`.
    pub browser: String,
    /// Profile folder name.
    pub profile: String,
    /// Extension id.
    pub id: String,
    /// Display name, with `__MSG_x__` resolved where possible.
    #[serde(default)]
    pub name: Option<String>,
    /// Version.
    #[serde(default)]
    pub version: Option<String>,
    /// How it was installed.
    pub source: ExtensionSource,
    /// Raw location as the browser stores it, for the helper view.
    #[serde(default)]
    pub raw_location: Option<String>,
    /// Turned on.
    pub enabled: bool,
    /// Every permission, host permission and content script match.
    #[serde(default)]
    pub permissions: Vec<String>,
    /// `update_url` from the manifest.
    #[serde(default)]
    pub update_url: Option<String>,
    /// Firefox `signedState`.
    #[serde(default)]
    pub signed_state: Option<i64>,
}

/// One force-installed extension from policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserPolicy {
    /// Browser the policy is for.
    pub browser: String,
    /// Where it came from, for example a registry key.
    pub location: String,
    /// Extension id.
    pub id: String,
    /// Update URL from the forcelist entry.
    #[serde(default)]
    pub update_url: Option<String>,
}

/// A shortcut that starts a browser.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserShortcut {
    /// The `.lnk` file.
    pub path: String,
    /// Browser it starts.
    pub browser: String,
    /// Arguments on the shortcut.
    pub arguments: String,
}

/// Whether an organisation manages this computer, and how Bilby knows.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Management {
    /// Managed by an organisation.
    pub managed: bool,
    /// Why: `entra joined`, `domain joined`, `mdm enrolled`. Empty if not.
    #[serde(default)]
    pub reasons: Vec<String>,
}

/// Hosts file, proxy settings, root certificates and DNS servers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TamperFacts {
    /// The hosts file.
    #[serde(default)]
    pub hosts: Option<HostsFacts>,
    /// Per-user (`WinINet`) proxy.
    #[serde(default)]
    pub proxy: Option<ProxyFacts>,
    /// Machine-wide (`WinHTTP`) proxy server, if one is set.
    #[serde(default)]
    pub winhttp_proxy: Option<String>,
    /// Root certificates in the user and machine stores.
    #[serde(default)]
    pub roots: Vec<RootCert>,
    /// Whether Microsoft's trusted root list could be read; if not, "not in
    /// Microsoft's list" findings are less sure.
    #[serde(default)]
    pub microsoft_list_read: bool,
    /// DNS servers per adapter. Shown to the helper, never a finding.
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// This computer's name, to recognise certificates Windows made for
    /// itself (Remote Desktop, `WinRM`).
    #[serde(default)]
    pub computer_name: Option<String>,
    /// Whether an organisation manages this computer (from #13's check).
    #[serde(default)]
    pub management: Management,
}

/// The hosts file and where Windows reads it from.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostsFacts {
    /// Full path of the file Windows uses.
    pub path: String,
    /// Whether `DataBasePath` is Windows' default folder.
    pub default_path: bool,
    /// Every mapping in the file.
    #[serde(default)]
    pub entries: Vec<crate::hosts::HostsEntry>,
}

/// `WinINet` proxy settings for the current user.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyFacts {
    /// `ProxyEnable`.
    pub enabled: bool,
    /// `ProxyServer`.
    #[serde(default)]
    pub server: Option<String>,
    /// `ProxyOverride`.
    #[serde(default)]
    pub bypass: Option<String>,
    /// `AutoConfigURL` (a PAC file).
    #[serde(default)]
    pub pac_url: Option<String>,
    /// The program listening on the proxy port, when the proxy is on this
    /// computer.
    #[serde(default)]
    pub listener: Option<ProcessFact>,
    /// `AutoDetect` (WPAD). Windows' default, so shown but never a finding.
    #[serde(default)]
    pub auto_detect: bool,
    /// The `ProxySettingsPerUser` policy is 0: an organisation set one proxy
    /// for the whole machine.
    #[serde(default)]
    pub per_machine_policy: bool,
}

/// Which certificate store a root was found in.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RootStore {
    /// The current user's `Root` store.
    User,
    /// The machine's `Root` store.
    Machine,
    /// Pushed by group policy.
    GroupPolicy,
    /// The machine's enterprise store.
    Enterprise,
}

/// One trusted root certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootCert {
    /// Where it was found.
    pub store: RootStore,
    /// SHA-1 thumbprint, lower-case hex.
    pub sha1: String,
    /// SHA-256 of the certificate, lower-case hex.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Serial number, lower-case hex, most significant byte first.
    #[serde(default)]
    pub serial: Option<String>,
    /// The basic constraints extension's CA flag. `Some(false)` means the
    /// certificate can't vouch for any other site, only itself. `None` when
    /// the extension is missing (old roots often lack it).
    #[serde(default)]
    pub is_ca: Option<bool>,
    /// Subject common name.
    #[serde(default)]
    pub subject_cn: Option<String>,
    /// Subject organisation.
    #[serde(default)]
    pub subject_o: Option<String>,
    /// Issuer, as Windows displays it.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Start of validity, used as a stand-in for when it was added.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub not_before: Option<time::OffsetDateTime>,
    /// End of validity.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub not_after: Option<time::OffsetDateTime>,
    /// In Microsoft's trusted root program list.
    pub in_microsoft_list: bool,
}

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
