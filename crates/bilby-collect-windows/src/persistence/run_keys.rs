//! Run keys and friends, Winlogon, IFEO and `AppInit_DLLs`. Read-only.

use std::collections::HashMap;

use bilby_core::cmdline::resolve;
use bilby_core::paths::KnownFolders;
use bilby_core::snapshot::{
    AppInit, IfeoEntry, IfeoKind, StartupItem, StartupSource, WinlogonValues,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_SAM_FLAGS,
};

use super::registry_item;
use crate::cache::FileCache;
use crate::files::file_facts;
use crate::registry::{Data, Key};

const CV: &str = r"Software\Microsoft\Windows\CurrentVersion";
const NT: &str = r"Software\Microsoft\Windows NT\CurrentVersion";

/// One key to read: root, path, label used in findings, source and the
/// `StartupApproved` key that says whether its items are enabled.
struct RunKey {
    root: HKEY,
    root_name: &'static str,
    path: &'static str,
    view: REG_SAM_FLAGS,
    source: StartupSource,
    approved: Option<&'static str>,
}

fn run_keys() -> Vec<RunKey> {
    let k = |root, root_name, path, view, source, approved| RunKey {
        root,
        root_name,
        path,
        view,
        source,
        approved,
    };
    vec![
        k(
            HKEY_LOCAL_MACHINE,
            "HKLM",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            KEY_WOW64_64KEY,
            StartupSource::Run,
            Some("Run"),
        ),
        k(
            HKEY_LOCAL_MACHINE,
            "HKLM",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            KEY_WOW64_64KEY,
            StartupSource::RunOnce,
            None,
        ),
        // The 32-bit view of HKLM is WOW6432Node.
        k(
            HKEY_LOCAL_MACHINE,
            r"HKLM\Software\WOW6432Node",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            KEY_WOW64_32KEY,
            StartupSource::Run,
            Some("Run32"),
        ),
        k(
            HKEY_LOCAL_MACHINE,
            r"HKLM\Software\WOW6432Node",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            KEY_WOW64_32KEY,
            StartupSource::RunOnce,
            None,
        ),
        k(
            HKEY_CURRENT_USER,
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            REG_SAM_FLAGS(0),
            StartupSource::Run,
            Some("Run"),
        ),
        k(
            HKEY_CURRENT_USER,
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            REG_SAM_FLAGS(0),
            StartupSource::RunOnce,
            None,
        ),
        k(
            HKEY_LOCAL_MACHINE,
            "HKLM",
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            KEY_WOW64_64KEY,
            StartupSource::PolicyRun,
            None,
        ),
        k(
            HKEY_CURRENT_USER,
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            REG_SAM_FLAGS(0),
            StartupSource::PolicyRun,
            None,
        ),
    ]
}

/// Enabled state from `Explorer\StartupApproved\<sub>` in HKCU and HKLM,
/// keyed by lower-case value name. First byte 0x02 or 0x06 is enabled,
/// anything with bit 0 set (0x03, 0x07...) is disabled. A missing value
/// is enabled.
pub(crate) fn approved(sub: &str) -> HashMap<String, bool> {
    let mut out = HashMap::new();
    for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        let path = format!(r"{CV}\Explorer\StartupApproved\{sub}");
        let Some(key) = Key::open(root, &path, REG_SAM_FLAGS(0)) else {
            continue;
        };
        for (name, data) in key.values() {
            if let Data::Bytes(bytes) = data
                && let Some(first) = bytes.first()
            {
                out.insert(name.to_lowercase(), first & 1 == 0);
            }
        }
    }
    out
}

/// Every `Run`, `RunOnce`, `RunOnceEx` and policy `Run` entry.
pub(super) fn run_items() -> Vec<StartupItem> {
    let mut items = Vec::new();
    for rk in run_keys() {
        let Some(key) = Key::open(rk.root, rk.path, rk.view) else {
            continue;
        };
        let enabled = rk.approved.map(approved).unwrap_or_default();
        let location = if rk.root_name.contains("WOW6432Node") {
            format!(
                r"{}\{}",
                rk.root_name,
                rk.path.trim_start_matches("Software\\")
            )
        } else {
            format!(r"{}\{}", rk.root_name, rk.path)
        };
        let last_write = key.last_write();
        for (name, data) in key.values() {
            let Some(command) = data.text().filter(|c| !c.trim().is_empty()) else {
                continue;
            };
            let on = enabled.get(&name.to_lowercase()).copied().unwrap_or(true);
            items.push(registry_item(
                rk.source,
                &location,
                name,
                command.to_owned(),
                on,
                last_write,
            ));
        }
    }
    items.extend(run_once_ex());
    items
}

/// `RunOnceEx\<n>\<value>` entries, used by some installers.
fn run_once_ex() -> Vec<StartupItem> {
    let path = format!(r"{CV}\RunOnceEx");
    let Some(key) = Key::open(HKEY_LOCAL_MACHINE, &path, KEY_WOW64_64KEY) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for sub in key.subkeys() {
        let Some(child) = key.sub(&sub, KEY_WOW64_64KEY) else {
            continue;
        };
        let location = format!(r"HKLM\{path}\{sub}");
        for (name, data) in child.values() {
            if let Some(cmd) = data
                .text()
                .filter(|c| !c.trim().is_empty() && !name.is_empty())
            {
                out.push(registry_item(
                    StartupSource::RunOnceEx,
                    &location,
                    name,
                    cmd.to_owned(),
                    true,
                    child.last_write(),
                ));
            }
        }
    }
    out
}

fn text_value(root: HKEY, path: &str, view: REG_SAM_FLAGS, name: &str) -> Option<String> {
    Key::open(root, path, view)?
        .value(name)?
        .text()
        .map(str::to_owned)
}

fn dword_value(root: HKEY, path: &str, view: REG_SAM_FLAGS, name: &str) -> Option<u32> {
    match Key::open(root, path, view)?.value(name)? {
        Data::Dword(v) => Some(v),
        Data::Text(s) => s.trim().parse().ok(),
        Data::Bytes(_) => None,
    }
}

/// Winlogon `Shell` (machine and user) and `Userinit`.
pub fn winlogon() -> WinlogonValues {
    let path = format!(r"{NT}\Winlogon");
    WinlogonValues {
        shell_machine: text_value(HKEY_LOCAL_MACHINE, &path, KEY_WOW64_64KEY, "Shell"),
        shell_user: text_value(HKEY_CURRENT_USER, &path, REG_SAM_FLAGS(0), "Shell"),
        userinit: text_value(HKEY_LOCAL_MACHINE, &path, KEY_WOW64_64KEY, "Userinit"),
    }
}

/// IFEO `Debugger` values and `SilentProcessExit` `MonitorProcess` values.
pub fn ifeo(folders: &KnownFolders, cache: &FileCache) -> Vec<IfeoEntry> {
    let mut out = Vec::new();
    let exists = |p: &str| std::path::Path::new(p).is_file();
    for (sub, kind, value) in [
        (
            "Image File Execution Options",
            IfeoKind::Debugger,
            "Debugger",
        ),
        (
            "SilentProcessExit",
            IfeoKind::MonitorProcess,
            "MonitorProcess",
        ),
    ] {
        let path = format!(r"{NT}\{sub}");
        let Some(key) = Key::open(HKEY_LOCAL_MACHINE, &path, KEY_WOW64_64KEY) else {
            continue;
        };
        for image in key.subkeys() {
            let Some(command) = key
                .sub(&image, KEY_WOW64_64KEY)
                .and_then(|k| k.value(value))
                .and_then(|d| d.text().map(str::to_owned))
                .filter(|c| !c.trim().is_empty())
            else {
                continue;
            };
            let target = resolve(&command, folders, &exists).target;
            out.push(IfeoEntry {
                image,
                kind,
                target: Some(file_facts(&target, folders, cache)),
                command,
            });
        }
    }
    out
}

/// `AppInit_DLLs` and `LoadAppInit_DLLs` in the 64-bit and 32-bit views.
pub fn appinit() -> Vec<AppInit> {
    let path = format!(r"{NT}\Windows");
    [
        (KEY_WOW64_64KEY, format!(r"HKLM\{path}")),
        (
            KEY_WOW64_32KEY,
            r"HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows".to_owned(),
        ),
    ]
    .into_iter()
    .map(|(view, location)| AppInit {
        location,
        load: dword_value(HKEY_LOCAL_MACHINE, &path, view, "LoadAppInit_DLLs"),
        dlls: text_value(HKEY_LOCAL_MACHINE, &path, view, "AppInit_DLLs"),
    })
    .collect()
}
