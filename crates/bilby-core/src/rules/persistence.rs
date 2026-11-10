//! Startup item rules: Run keys and startup folders, Winlogon, Image File
//! Execution Options and `AppInit_DLLs`. See `docs/signals.md`.

use super::processes::encoded_powershell;
use super::{FindingBuilder, Rule, RuleContext};
use crate::model::{Confidence, Evidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::paths::{KnownFolders, normalise};
use crate::snapshot::{
    FileFacts, IfeoEntry, PathClass, PersistenceFacts, ServiceFact, ServiceKind, SignatureStatus,
    StartType, StartupItem, SystemSnapshot, TaskAction, TaskFact,
};

/// Fix id for turning a startup item off the way Task Manager does (#31).
pub const FIX_DISABLE_STARTUP: &str = "disable_startup_item";

fn norm(path: &str) -> String {
    normalise(path, &KnownFolders::default())
}

fn unsigned(f: &FileFacts) -> bool {
    matches!(
        f.signature,
        SignatureStatus::Unsigned | SignatureStatus::Invalid { .. }
    )
}

/// User-writable, but not a per-user install under `AppData\Local\Programs`.
fn writable_not_installed(f: &FileFacts) -> bool {
    f.user_writable && f.class != PathClass::UserAppPrograms
}

fn item_subject(item: &StartupItem) -> Subject {
    Subject::RegistryValue(format!("{}\\{}", item.location, item.name).to_lowercase())
}

fn item_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    item: &StartupItem,
) -> FindingBuilder {
    // A disabled item can't run, so it's never more than Info.
    let (severity, confidence) = if item.enabled {
        (severity, confidence)
    } else {
        (Severity::Info, confidence)
    };
    let mut b = FindingBuilder::new(
        id,
        SignalFamily::Persistence,
        severity,
        confidence,
        item_subject(item),
    )
    .var("name", &item.name)
    .evidence(Evidence::RegistryValue {
        key: item.location.clone(),
        name: item.name.clone(),
        data: item.command.clone(),
    });
    if let Some(t) = &item.target {
        b = b.evidence(Evidence::Path(t.path.clone()));
        if let Some(publisher) = t.signature.publisher() {
            b = b.text("evidence.publisher", publisher);
        }
    }
    if !item.enabled {
        b = b.text("evidence.startup_state", "turned off in Task Manager");
    }
    b.next(NextStepKind::Fix(FIX_DISABLE_STARTUP.to_owned()))
}

macro_rules! rule {
    ($name:ident, $id:literal, $fn:ident) => {
        struct $name;
        impl Rule for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn family(&self) -> SignalFamily {
                SignalFamily::Persistence
            }
            fn evaluate(&self, snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding> {
                snap.persistence
                    .as_ref()
                    .map(|p| $fn(p, ctx))
                    .unwrap_or_default()
            }
        }
    };
}

rule!(
    RunUnsigned,
    "persist.run.unsigned_user_writable",
    run_unsigned
);
rule!(RunScriptHost, "persist.run.script_host", run_script_host);
rule!(
    RunRundll32,
    "persist.run.rundll32_user_writable",
    run_rundll32
);
rule!(RunMissing, "persist.run.missing_target", run_missing);
rule!(WinlogonShell, "persist.winlogon.shell", winlogon_shell);
rule!(
    WinlogonUserinit,
    "persist.winlogon.userinit",
    winlogon_userinit
);
rule!(IfeoDebugger, "persist.ifeo.debugger", ifeo_debugger);
rule!(AppInitDlls, "persist.appinit", appinit);
rule!(
    ServiceUserWritable,
    "persist.service.user_writable",
    service_user_writable
);
rule!(
    ServiceUnsigned,
    "persist.service.unsigned",
    service_unsigned
);
rule!(
    ServiceSvchostDll,
    "persist.service.svchost_dll_outside_system",
    service_svchost_dll
);
rule!(
    ServiceScriptHost,
    "persist.service.script_host",
    service_script_host
);
rule!(
    TaskUserWritable,
    "persist.task.user_writable",
    task_user_writable
);
rule!(TaskScriptHost, "persist.task.script_host", task_script_host);
rule!(
    TaskHiddenUnsigned,
    "persist.task.hidden_unsigned",
    task_hidden_unsigned
);
rule!(TaskMissing, "persist.task.missing_target", task_missing);

/// Every persistence rule in this module.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RunUnsigned),
        Box::new(RunScriptHost),
        Box::new(RunRundll32),
        Box::new(RunMissing),
        Box::new(WinlogonShell),
        Box::new(WinlogonUserinit),
        Box::new(IfeoDebugger),
        Box::new(AppInitDlls),
        Box::new(ServiceUserWritable),
        Box::new(ServiceUnsigned),
        Box::new(ServiceSvchostDll),
        Box::new(ServiceScriptHost),
        Box::new(TaskUserWritable),
        Box::new(TaskScriptHost),
        Box::new(TaskHiddenUnsigned),
        Box::new(TaskMissing),
    ]
}

fn run_unsigned(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.items
        .iter()
        // Hosts that run the target as a local file: their target is what
        // matters. rundll32 and script hosts have their own rules, so a
        // file isn't flagged twice. mshta and regsvr32 URL targets don't
        // exist as files, so the exists check below skips them (they're
        // run_script_host's).
        .filter(|i| {
            matches!(
                i.host.as_deref(),
                None | Some("cmd" | "powershell" | "explorer" | "msiexec" | "mshta" | "regsvr32")
            )
        })
        .filter_map(|item| {
            let t = item.target.as_ref().filter(|t| t.exists)?;
            if !(unsigned(t) && writable_not_installed(t)) {
                return None;
            }
            let high = matches!(
                t.class,
                PathClass::Temp | PathClass::Downloads | PathClass::Public | PathClass::RecycleBin
            );
            let confidence = if high {
                Confidence::High
            } else {
                Confidence::Medium
            };
            Some(
                item_finding(
                    "persist.run.unsigned_user_writable",
                    Severity::Medium,
                    confidence,
                    item,
                )
                .build(),
            )
        })
        .collect()
}

fn is_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    ["http://", "https://", "ftp://", "javascript:", "vbscript:"]
        .iter()
        .any(|p| lower.starts_with(p))
}

fn run_script_host(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.items
        .iter()
        .filter(|item| {
            let host_args = item.host_args.as_deref().unwrap_or_default();
            let target = item.target.as_ref();
            let target_path = target.map_or("", |t| t.path.as_str());
            match item.host.as_deref() {
                Some("powershell") => encoded_powershell(&format!("powershell {host_args}")),
                // Both run whatever is at the URL.
                Some("mshta" | "regsvr32") => is_url(target_path),
                Some("script_host") => target.is_some_and(writable_not_installed),
                _ => false,
            }
        })
        .map(|item| {
            let mut b = item_finding(
                "persist.run.script_host",
                Severity::High,
                Confidence::High,
                item,
            );
            if let Some(h) = &item.host {
                b = b.var("host", h);
            }
            b.build()
        })
        .collect()
}

fn run_rundll32(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.items
        .iter()
        .filter(|i| i.host.as_deref() == Some("rundll32"))
        .filter(|i| i.target.as_ref().is_some_and(writable_not_installed))
        .map(|item| {
            item_finding(
                "persist.run.rundll32_user_writable",
                Severity::High,
                Confidence::Medium,
                item,
            )
            .build()
        })
        .collect()
}

fn run_missing(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.items
        .iter()
        .filter(|i| {
            // URLs and bare-host commands (PowerShell -Command) have no file.
            i.target
                .as_ref()
                .is_some_and(|t| !t.exists && !is_url(&t.path))
        })
        .map(|item| {
            let mut f = item_finding(
                "persist.run.missing_target",
                Severity::Info,
                Confidence::High,
                item,
            );
            // Nothing to turn off that would help; it's a leftover.
            f = f.next(NextStepKind::Learn);
            f.build()
        })
        .collect()
}

const WINLOGON_KEY: &str = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon";

fn winlogon_finding(id: &str, name: &str, key: &str, value: &str) -> Finding {
    FindingBuilder::new(
        id,
        SignalFamily::Persistence,
        Severity::High,
        Confidence::High,
        Subject::RegistryValue(format!("{key}\\{name}").to_lowercase()),
    )
    .var("value", value)
    .evidence(Evidence::RegistryValue {
        key: key.to_owned(),
        name: name.to_owned(),
        data: value.to_owned(),
    })
    .next(NextStepKind::TalkToHelper)
    .build()
}

/// `explorer.exe`, optionally with a path to `%SystemRoot%\explorer.exe`.
fn is_default_shell(value: &str) -> bool {
    let v = norm(value.trim().trim_matches('"'));
    v == "explorer.exe"
        || v.strip_suffix(r"\explorer.exe")
            .is_some_and(|dir| is_drive_windows(dir) || dir == "%systemroot%" || dir == "%windir%")
}

/// `x:\windows` exactly: the Windows folder at the root of a drive, not any
/// folder that happens to be called Windows (`C:\Users\Alex\Windows`).
fn is_drive_windows(dir: &str) -> bool {
    dir.len() == r"c:\windows".len()
        && dir.as_bytes()[0].is_ascii_alphabetic()
        && dir[1..] == *r":\windows"
}

fn winlogon_shell(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(w) = &p.winlogon else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(v) = w.shell_machine.as_deref().filter(|v| !is_default_shell(v)) {
        out.push(winlogon_finding(
            "persist.winlogon.shell",
            "Shell",
            WINLOGON_KEY,
            v,
        ));
    }
    // The per-user value is unusual on its own; only an explorer.exe there
    // is harmless.
    if let Some(v) = w.shell_user.as_deref().filter(|v| !is_default_shell(v)) {
        out.push(winlogon_finding(
            "persist.winlogon.shell",
            "Shell",
            r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            v,
        ));
    }
    out
}

/// `C:\Windows\system32\userinit.exe,` with any case, any Windows folder,
/// and with or without the trailing comma.
fn is_default_userinit(value: &str) -> bool {
    let v = value.trim().trim_end_matches(',').trim();
    if v.contains(',') {
        // A second program after the comma runs at every sign-in.
        return false;
    }
    let n = norm(v.trim_matches('"'));
    n == "userinit.exe"
        || n.strip_suffix(r"\system32\userinit.exe")
            .is_some_and(is_drive_windows)
        || n == r"%systemroot%\system32\userinit.exe"
}

fn winlogon_userinit(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(v) = p.winlogon.as_ref().and_then(|w| w.userinit.as_deref()) else {
        return Vec::new();
    };
    if is_default_userinit(v) {
        return Vec::new();
    }
    vec![winlogon_finding(
        "persist.winlogon.userinit",
        "Userinit",
        WINLOGON_KEY,
        v,
    )]
}

/// Signed tools that people install on purpose as a Task Manager or
/// debugger replacement.
const KNOWN_DEBUGGERS: &[&str] = &[
    "procexp.exe",
    "procexp64.exe",
    "procexp64a.exe",
    "vsjitdebugger.exe",
];

fn known_debugger(e: &IfeoEntry) -> bool {
    // Process Explorer and the Visual Studio debugger are Microsoft's, so a
    // signature from anyone else under one of these names is a disguise.
    e.target.as_ref().is_some_and(|t| {
        t.signature.publisher() == Some("Microsoft Corporation")
            && KNOWN_DEBUGGERS
                .iter()
                .any(|k| norm(&t.path).ends_with(&format!(r"\{k}")))
    })
}

fn ifeo_debugger(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.ifeo
        .iter()
        .map(|e| {
            let (severity, confidence) = if known_debugger(e) {
                (Severity::Info, Confidence::High)
            } else {
                (Severity::Medium, Confidence::Medium)
            };
            let mut b = FindingBuilder::new(
                "persist.ifeo.debugger",
                SignalFamily::Persistence,
                severity,
                confidence,
                Subject::RegistryValue(format!("ifeo\\{}\\{:?}", e.image, e.kind).to_lowercase()),
            )
            .var("image", &e.image)
            .text("evidence.command", &e.command)
            .next(NextStepKind::TalkToHelper);
            if let Some(t) = &e.target {
                b = b.evidence(Evidence::Path(t.path.clone()));
            }
            b.build()
        })
        .collect()
}

fn appinit(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.appinit
        .iter()
        .filter(|a| a.load == Some(1) && a.dlls.as_deref().is_some_and(|d| !d.trim().is_empty()))
        .map(|a| {
            let dlls = a.dlls.clone().unwrap_or_default();
            FindingBuilder::new(
                "persist.appinit",
                SignalFamily::Persistence,
                Severity::Medium,
                Confidence::Medium,
                Subject::RegistryValue(format!("{}\\AppInit_DLLs", a.location).to_lowercase()),
            )
            .evidence(Evidence::RegistryValue {
                key: a.location.clone(),
                name: "AppInit_DLLs".to_owned(),
                data: dlls,
            })
            .next(NextStepKind::TalkToHelper)
            .build()
        })
        .collect()
}

/// Fix id for disabling a service or task the way Windows does (#31).
pub const FIX_DISABLE_SERVICE: &str = "disable_service";
/// Fix id for disabling a scheduled task (#31).
pub const FIX_DISABLE_TASK: &str = "disable_task";

/// Would this service run without anyone asking? Drivers are #15's.
fn service_runs(s: &ServiceFact) -> bool {
    s.kind != ServiceKind::Driver
        && (matches!(s.start, StartType::Auto | StartType::Boot)
            || (s.start == StartType::Demand && s.running))
}

fn service_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    s: &ServiceFact,
) -> FindingBuilder {
    let mut b = FindingBuilder::new(
        id,
        SignalFamily::Persistence,
        severity,
        confidence,
        Subject::Service(s.name.to_lowercase()),
    )
    .var("name", s.display_name.as_deref().unwrap_or(&s.name))
    .text("evidence.service", &s.name)
    .text("evidence.command", &s.binary_path)
    .next(NextStepKind::Fix(FIX_DISABLE_SERVICE.to_owned()));
    for f in [&s.binary, &s.service_dll].into_iter().flatten() {
        b = b.evidence(Evidence::Path(f.path.clone()));
        if let Some(p) = f.signature.publisher() {
            b = b.text("evidence.publisher", p);
        }
    }
    b
}

fn service_user_writable(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.services
        .iter()
        .filter(|s| service_runs(s))
        .filter_map(|s| {
            let files: Vec<&FileFacts> = [&s.binary, &s.service_dll]
                .into_iter()
                .flatten()
                .filter(|f| f.exists && f.user_writable)
                .collect();
            if files.is_empty() {
                return None;
            }
            let confidence = if files.iter().any(|f| unsigned(f)) {
                Confidence::High
            } else {
                Confidence::Medium
            };
            Some(
                service_finding(
                    "persist.service.user_writable",
                    Severity::High,
                    confidence,
                    s,
                )
                .build(),
            )
        })
        .collect()
}

fn service_unsigned(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.services
        .iter()
        .filter(|s| s.kind != ServiceKind::Driver && s.start != StartType::Disabled)
        .filter(|s| {
            s.binary.as_ref().is_some_and(|f| {
                f.exists
                    && unsigned(f)
                    && !matches!(f.class, PathClass::WindowsSystem | PathClass::ProgramFiles)
                    // A user-writable binary is already High above.
                    && !f.user_writable
            })
        })
        .map(|s| {
            service_finding(
                "persist.service.unsigned",
                Severity::Medium,
                Confidence::Medium,
                s,
            )
            .build()
        })
        .collect()
}

fn service_svchost_dll(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.services
        .iter()
        .filter(|s| s.kind != ServiceKind::Driver)
        .filter(|s| {
            s.service_dll
                .as_ref()
                .is_some_and(|d| d.exists && d.class != PathClass::WindowsSystem)
        })
        .map(|s| {
            service_finding(
                "persist.service.svchost_dll_outside_system",
                Severity::High,
                Confidence::Medium,
                s,
            )
            .build()
        })
        .collect()
}

/// A script host or loader running something from a user-writable folder,
/// or PowerShell hiding its command.
fn hosted_badly(host: Option<&str>, host_args: Option<&str>, target: Option<&FileFacts>) -> bool {
    let writable = target.is_some_and(writable_not_installed);
    match host {
        Some("powershell") => {
            writable || encoded_powershell(&format!("powershell {}", host_args.unwrap_or_default()))
        }
        Some("cmd" | "rundll32" | "script_host") => writable,
        Some("mshta" | "regsvr32") => writable || target.is_some_and(|t| is_url(&t.path)),
        _ => false,
    }
}

fn service_script_host(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.services
        .iter()
        .filter(|s| s.kind != ServiceKind::Driver && s.start != StartType::Disabled)
        .filter(|s| hosted_badly(s.host.as_deref(), s.host_args.as_deref(), s.binary.as_ref()))
        .map(|s| {
            service_finding(
                "persist.service.script_host",
                Severity::High,
                Confidence::High,
                s,
            )
            .build()
        })
        .collect()
}

/// Tasks Windows itself ships, under `\Microsoft\Windows\`.
fn microsoft_windows_task(t: &TaskFact) -> bool {
    t.path
        .to_ascii_lowercase()
        .starts_with(r"\microsoft\windows\")
}

fn task_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    t: &TaskFact,
    cmd: &str,
) -> FindingBuilder {
    let name = t.path.rsplit('\\').next().unwrap_or(&t.path);
    FindingBuilder::new(
        id,
        SignalFamily::Persistence,
        severity,
        confidence,
        Subject::Task(t.path.to_lowercase()),
    )
    .var("name", name)
    .text("evidence.task", &t.path)
    .text("evidence.command", cmd)
    .next(NextStepKind::Fix(FIX_DISABLE_TASK.to_owned()))
}

/// Exec actions of enabled tasks, as (command, target, host, host args).
fn exec_actions(
    t: &TaskFact,
) -> impl Iterator<Item = (&str, Option<&FileFacts>, Option<&str>, Option<&str>)> {
    t.actions.iter().filter_map(|a| match a {
        TaskAction::Exec {
            command,
            target,
            host,
            host_args,
        } => Some((
            command.as_str(),
            target.as_deref(),
            host.as_deref(),
            host_args.as_deref(),
        )),
        TaskAction::ComHandler { .. } => None,
    })
}

fn task_user_writable(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    let mut out = Vec::new();
    for t in p.tasks.iter().filter(|t| t.enabled) {
        for (cmd, target, host, _) in exec_actions(t) {
            // Script hosts and loaders have their own rule.
            if !matches!(host, None | Some("cmd" | "explorer" | "msiexec")) {
                continue;
            }
            let Some(f) = target.filter(|f| f.exists && unsigned(f) && writable_not_installed(f))
            else {
                continue;
            };
            let high = matches!(
                f.class,
                PathClass::Temp | PathClass::Downloads | PathClass::Public | PathClass::RecycleBin
            );
            let confidence = if high {
                Confidence::High
            } else {
                Confidence::Medium
            };
            out.push(
                task_finding(
                    "persist.task.user_writable",
                    Severity::Medium,
                    confidence,
                    t,
                    cmd,
                )
                .build(),
            );
        }
    }
    out
}

fn task_script_host(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    let mut out = Vec::new();
    for t in p.tasks.iter().filter(|t| t.enabled) {
        for (cmd, target, host, host_args) in exec_actions(t) {
            if hosted_badly(host, host_args, target) {
                out.push(
                    task_finding(
                        "persist.task.script_host",
                        Severity::High,
                        Confidence::High,
                        t,
                        cmd,
                    )
                    .build(),
                );
            }
        }
    }
    out
}

fn task_hidden_unsigned(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    p.tasks
        .iter()
        .filter(|t| {
            t.enabled && t.hidden && !t.path.to_ascii_lowercase().starts_with(r"\microsoft\")
        })
        .filter_map(|t| {
            let (cmd, _, _, _) = exec_actions(t)
                .find(|(_, target, _, _)| target.is_some_and(|f| f.exists && unsigned(f)))?;
            Some(
                task_finding(
                    "persist.task.hidden_unsigned",
                    Severity::Medium,
                    Confidence::Medium,
                    t,
                    cmd,
                )
                .build(),
            )
        })
        .collect()
}

fn task_missing(p: &PersistenceFacts, _: &RuleContext) -> Vec<Finding> {
    let mut out = Vec::new();
    for t in &p.tasks {
        // Windows' own tasks sometimes point at features that aren't
        // installed; that's Windows' business, not a leftover.
        if microsoft_windows_task(t) {
            continue;
        }
        for (cmd, target, _, _) in exec_actions(t) {
            if target.is_some_and(|f| !f.exists && !is_url(&f.path)) {
                out.push(
                    task_finding(
                        "persist.task.missing_target",
                        Severity::Info,
                        Confidence::High,
                        t,
                        cmd,
                    )
                    .next(NextStepKind::Learn)
                    .build(),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shells() {
        for ok in [
            "explorer.exe",
            "Explorer.exe",
            r"C:\Windows\explorer.exe",
            r"%SystemRoot%\explorer.exe",
            r#""C:\WINDOWS\explorer.exe""#,
        ] {
            assert!(is_default_shell(ok), "{ok}");
        }
        for bad in [
            "explorer.exe, C:\\Users\\Public\\x.exe",
            r"C:\Users\Alex\explorer.exe",
            "cmd.exe",
            r"C:\Windows\System32\explorer.exe\..\..\evil.exe",
            // Any folder called Windows isn't the Windows folder.
            r"C:\Users\Alex\Windows\explorer.exe",
            r"D:\Stuff\Windows\explorer.exe",
        ] {
            assert!(!is_default_shell(bad), "{bad}");
        }
    }

    #[test]
    fn userinits() {
        for ok in [
            r"C:\Windows\system32\userinit.exe,",
            r"C:\WINDOWS\System32\userinit.exe",
            r"C:\Windows\system32\userinit.exe ,",
            "userinit.exe,",
        ] {
            assert!(is_default_userinit(ok), "{ok}");
        }
        for bad in [
            r"C:\Windows\system32\userinit.exe,C:\Users\Public\x.exe,",
            r"C:\Users\Alex\userinit.exe,",
            r"C:\Windows\system32\userinit.exe, C:\x.exe",
            r"C:\Users\Public\Windows\System32\userinit.exe,",
        ] {
            assert!(!is_default_userinit(bad), "{bad}");
        }
    }
}
