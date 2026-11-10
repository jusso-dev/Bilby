//! Startup item rules: Run keys and startup folders, Winlogon, Image File
//! Execution Options and `AppInit_DLLs`. See `docs/signals.md`.

use super::processes::encoded_powershell;
use super::{FindingBuilder, Rule, RuleContext};
use crate::model::{Confidence, Evidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::paths::{KnownFolders, normalise};
use crate::snapshot::{
    FileFacts, IfeoEntry, PathClass, PersistenceFacts, SignatureStatus, StartupItem, SystemSnapshot,
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
