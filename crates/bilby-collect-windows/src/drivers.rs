//! Loaded drivers and boot integrity. Read-only: `EnumDeviceDrivers` and
//! `GetDeviceDriverFileNameW` list what's loaded, code integrity comes from
//! one `NtQuerySystemInformation` call, and settings from registry reads
//! and one WMI query. No driver is opened, loaded or queried beyond that.

use bilby_core::model::CheckStatus;
use bilby_core::paths::KnownFolders;
use bilby_core::snapshot::{BootIntegrity, DriverFacts};
use windows::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemCodeIntegrityInformation,
};
use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY};
use wmi::{Variant, WMIConnection};

use crate::cache::FileCache;
use crate::defender::{Row, init_com};
use crate::files::file_facts_many;
use crate::registry::{Data, Key};

/// What the drivers collector found and how each part went.
pub struct Collected {
    /// The facts.
    pub facts: DriverFacts,
    /// One status per part: loaded drivers, code integrity, memory integrity.
    pub checks: Vec<(&'static str, CheckStatus)>,
}

/// Collects loaded drivers and boot integrity.
pub fn collect(folders: &KnownFolders, cache: &FileCache) -> Collected {
    let mut checks = Vec::new();
    let (paths, hidden) = loaded_paths(folders);
    checks.push((
        "drivers.loaded",
        if hidden {
            // Windows 11 24H2 and later only give driver addresses to
            // callers with SeDebugPrivilege; the rest get all NULLs.
            CheckStatus::NeedsAdmin
        } else if paths.is_empty() {
            CheckStatus::Failed("no loaded drivers listed".to_owned())
        } else {
            CheckStatus::Ran
        },
    ));
    let loaded = file_facts_many(&paths, folders, cache);

    let code_integrity_options = code_integrity();
    checks.push((
        "drivers.code_integrity",
        if code_integrity_options.is_some() {
            CheckStatus::Ran
        } else {
            CheckStatus::Failed("code integrity state couldn't be read".to_owned())
        },
    ));
    let (memory_integrity_running, memory_integrity_available, status) = device_guard();
    checks.push(("drivers.memory_integrity", status));

    let control = |path: &str, name: &str| {
        Key::open(HKEY_LOCAL_MACHINE, path, KEY_WOW64_64KEY).and_then(|k| k.value(name))
    };
    let dword = |d: Option<Data>| match d {
        Some(Data::Dword(v)) => Some(v),
        _ => None,
    };
    let boot = BootIntegrity {
        code_integrity_options,
        start_options: control(r"SYSTEM\CurrentControlSet\Control", "SystemStartOptions")
            .and_then(|d| d.text().map(str::to_owned)),
        memory_integrity_running,
        memory_integrity_available,
        blocklist_value: dword(control(
            r"SYSTEM\CurrentControlSet\Control\CI\Config",
            "VulnerableDriverBlocklistEnable",
        )),
        secure_boot: dword(control(
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled",
        ))
        .map(|v| v == 1),
    };
    Collected {
        facts: DriverFacts { loaded, boot },
        checks,
    }
}

/// Paths of every loaded driver, as Win32 paths, and whether Windows hid
/// the list. From Windows 11 24H2, `EnumDeviceDrivers` "will require
/// `SeDebugPrivilege` to return valid `ImageBase` values ... the returned
/// `lpImageBase` array will contain addresses that are all NULL" (Microsoft
/// Learn, `EnumDeviceDrivers`). Bilby then can't name the drivers and says it
/// needs admin rather than report a near-empty list as checked.
fn loaded_paths(folders: &KnownFolders) -> (Vec<String>, bool) {
    let mut bases: Vec<*mut core::ffi::c_void> = vec![std::ptr::null_mut(); 1024];
    for _ in 0..3 {
        let mut needed = 0u32;
        let bytes = u32::try_from(bases.len() * size_of::<usize>()).unwrap_or(u32::MAX);
        // SAFETY: `bases` holds `bytes` bytes of pointers.
        if unsafe { EnumDeviceDrivers(bases.as_mut_ptr(), bytes, &raw mut needed) }.is_err() {
            return (Vec::new(), false);
        }
        let count = needed as usize / size_of::<usize>();
        if count <= bases.len() {
            bases.truncate(count);
            break;
        }
        bases = vec![std::ptr::null_mut(); count + 64];
    }
    if !bases.is_empty() && bases.iter().all(|b| b.is_null()) {
        return (Vec::new(), true);
    }
    let mut out = Vec::with_capacity(bases.len());
    let mut buf = vec![0u16; 1024];
    for base in bases {
        // SAFETY: a base address from EnumDeviceDrivers and a sized buffer.
        let n = unsafe { GetDeviceDriverFileNameW(base, &mut buf) } as usize;
        if n == 0 {
            continue;
        }
        let raw = String::from_utf16_lossy(&buf[..n.min(buf.len())]);
        let path = win32_path(&raw, folders);
        if is_crash_dump_copy(&path) {
            continue;
        }
        if !out.contains(&path) {
            out.push(path);
        }
    }
    (out, false)
}

/// Crash dump drivers (`dump_diskdump.sys`, `dump_storvsc.sys`, ...) are
/// in-memory copies of the storage drivers, renamed with a `dump_` prefix.
/// They're loaded but have no file of their own, so they can't be checked.
pub fn is_crash_dump_copy(path: &str) -> bool {
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    name.len() > 5 && name[..5].eq_ignore_ascii_case("dump_")
}

/// `\SystemRoot\System32\...`, `\??\C:\...` and `\Windows\...` to a
/// normal path that can be opened.
fn win32_path(raw: &str, folders: &KnownFolders) -> String {
    let lower = raw.to_ascii_lowercase();
    if let Some(rest) = lower
        .starts_with(r"\systemroot\")
        .then(|| &raw[r"\SystemRoot\".len()..])
    {
        return format!(r"{}\{rest}", folders.system_root);
    }
    if let Some(rest) = raw.strip_prefix(r"\??\") {
        return rest.to_owned();
    }
    if lower.starts_with(r"\windows\") {
        let drive = folders.system_root.get(..2).unwrap_or("C:");
        return format!("{drive}{raw}");
    }
    if lower.starts_with(r"system32\") {
        return format!(r"{}\{raw}", folders.system_root);
    }
    raw.to_owned()
}

/// `CodeIntegrityOptions` from `SYSTEM_CODEINTEGRITY_INFORMATION`
/// (documented on Microsoft Learn under `NtQuerySystemInformation`).
fn code_integrity() -> Option<u32> {
    #[repr(C)]
    struct Info {
        length: u32,
        options: u32,
    }
    let mut info = Info {
        length: u32::try_from(size_of::<Info>()).ok()?,
        options: 0,
    };
    let mut returned = 0u32;
    // SAFETY: the buffer is an initialised SYSTEM_CODEINTEGRITY_INFORMATION
    // with Length set, as the docs require.
    let status = unsafe {
        NtQuerySystemInformation(
            SystemCodeIntegrityInformation,
            (&raw mut info).cast(),
            info.length,
            &raw mut returned,
        )
    };
    status.is_ok().then_some(info.options)
}

/// Memory integrity running, hardware support, and how the query went.
fn device_guard() -> (Option<bool>, Option<bool>, CheckStatus) {
    init_com();
    let con = match WMIConnection::with_namespace_path(r"root\Microsoft\Windows\DeviceGuard") {
        Ok(c) => c,
        Err(e) => return (None, None, CheckStatus::Failed(e.to_string())),
    };
    let rows: Vec<Row> = match con.raw_query(
        "SELECT SecurityServicesRunning, AvailableSecurityProperties FROM Win32_DeviceGuard",
    ) {
        Ok(r) => r,
        Err(e) => return (None, None, CheckStatus::Failed(e.to_string())),
    };
    let Some(row) = rows.first() else {
        return (
            None,
            None,
            CheckStatus::Failed("no Win32_DeviceGuard row".to_owned()),
        );
    };
    let has = |key: &str, want: u32| match row.get(key) {
        Some(Variant::Array(items)) => Some(items.iter().any(|v| as_u32(v) == Some(want))),
        Some(Variant::Null | Variant::Empty) | None => Some(false),
        Some(v) => Some(as_u32(v) == Some(want)),
    };
    // SecurityServicesRunning 2 = memory integrity running;
    // AvailableSecurityProperties 1 = hypervisor support available.
    (
        has("SecurityServicesRunning", 2),
        has("AvailableSecurityProperties", 1),
        CheckStatus::Ran,
    )
}

fn as_u32(v: &Variant) -> Option<u32> {
    match v {
        Variant::UI1(x) => Some(u32::from(*x)),
        Variant::UI2(x) => Some(u32::from(*x)),
        Variant::UI4(x) => Some(*x),
        Variant::I4(x) => u32::try_from(*x).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_dump_copies_are_recognised() {
        assert!(is_crash_dump_copy(
            r"C:\Windows\System32\Drivers\dump_diskdump.sys"
        ));
        assert!(is_crash_dump_copy(
            r"C:\Windows\System32\drivers\DUMP_storvsc.sys"
        ));
        assert!(!is_crash_dump_copy(
            r"C:\Windows\System32\drivers\dumpfve.sys"
        ));
        assert!(!is_crash_dump_copy(r"C:\Windows\System32\drivers\disk.sys"));
    }

    #[test]
    fn driver_paths_become_win32_paths() {
        let f = KnownFolders {
            system_root: r"C:\Windows".to_owned(),
            ..KnownFolders::default()
        };
        assert_eq!(
            win32_path(r"\SystemRoot\system32\ntoskrnl.exe", &f),
            r"C:\Windows\system32\ntoskrnl.exe"
        );
        assert_eq!(
            win32_path(r"\??\C:\Program Files\x\a.sys", &f),
            r"C:\Program Files\x\a.sys"
        );
        assert_eq!(
            win32_path(r"\Windows\System32\drivers\b.sys", &f),
            r"C:\Windows\System32\drivers\b.sys"
        );
        assert_eq!(
            win32_path(r"System32\drivers\c.sys", &f),
            r"C:\Windows\System32\drivers\c.sys"
        );
    }
}
