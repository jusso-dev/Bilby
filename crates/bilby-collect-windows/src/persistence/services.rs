//! Services and drivers from the Service Control Manager. Read-only: the
//! manager is opened with `SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE`
//! and each service with `SERVICE_QUERY_CONFIG`, which work without admin.

use bilby_core::cmdline::resolve;
use bilby_core::paths::KnownFolders;
use bilby_core::snapshot::{ServiceFact, ServiceKind, StartType};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY};
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_AUTO_START, SERVICE_BOOT_START,
    SERVICE_DEMAND_START, SERVICE_DRIVER, SERVICE_QUERY_CONFIG, SERVICE_RUNNING, SERVICE_STATE_ALL,
    SERVICE_SYSTEM_START, SERVICE_WIN32, SERVICE_WIN32_SHARE_PROCESS,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use crate::cache::FileCache;
use crate::files::file_facts;
use crate::registry::Key;

/// A service manager or service handle, closed on drop.
struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the handle came from OpenSCManagerW or OpenServiceW and
            // is closed exactly once.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn wide(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: Windows filled this with a NUL-terminated string inside a
    // buffer we still hold.
    unsafe { p.to_string() }.ok().filter(|s| !s.is_empty())
}

/// Every Win32 service and driver.
pub fn collect(
    folders: &KnownFolders,
    cache: &FileCache,
) -> windows::core::Result<Vec<ServiceFact>> {
    // SAFETY: local machine, default database, least access that lists.
    let scm = Handle(unsafe {
        OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
    }?);
    let mut needed = 0u32;
    let mut count = 0u32;
    let kinds =
        windows::Win32::System::Services::ENUM_SERVICE_TYPE(SERVICE_WIN32.0 | SERVICE_DRIVER.0);
    // SAFETY: first call with no buffer reports the size needed. Fails
    // with ERROR_MORE_DATA, which is expected.
    let _ = unsafe {
        EnumServicesStatusExW(
            scm.0,
            SC_ENUM_PROCESS_INFO,
            kinds,
            SERVICE_STATE_ALL,
            None,
            &raw mut needed,
            &raw mut count,
            None,
            PCWSTR::null(),
        )
    };
    // The list can grow between calls; leave room.
    let mut buf = vec![0u64; (needed as usize + 16 * 1024).div_ceil(8)];
    let bytes = buf.len() * 8;
    // SAFETY: `buf` is 8-byte aligned and `bytes` long, as passed.
    let slice = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), bytes) };
    // SAFETY: as above, with the real buffer.
    unsafe {
        EnumServicesStatusExW(
            scm.0,
            SC_ENUM_PROCESS_INFO,
            kinds,
            SERVICE_STATE_ALL,
            Some(slice),
            &raw mut needed,
            &raw mut count,
            None,
            PCWSTR::null(),
        )
    }?;
    // SAFETY: on success the buffer starts with `count` entries, and their
    // strings point into the same buffer, which outlives this slice.
    let entries = unsafe {
        std::slice::from_raw_parts(
            buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
            count as usize,
        )
    };
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let Some(name) = wide(e.lpServiceName) else {
            continue;
        };
        let running = e.ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING;
        let raw_kind = e.ServiceStatusProcess.dwServiceType.0;
        let kind = if raw_kind & SERVICE_DRIVER.0 != 0 {
            ServiceKind::Driver
        } else if raw_kind & SERVICE_WIN32_SHARE_PROCESS.0 != 0 {
            ServiceKind::SharedProcess
        } else {
            ServiceKind::OwnProcess
        };
        let Some(config) = config(&scm, &name) else {
            continue;
        };
        let binary_path = config.binary_path.unwrap_or_default();
        let exists = |p: &str| std::path::Path::new(p).is_file();
        let r = resolve(&binary_path, folders, &exists);
        let service_dll = if kind == ServiceKind::SharedProcess {
            service_dll(&name).map(|p| {
                let target = resolve(&format!("\"{p}\""), folders, &exists).target;
                file_facts(&target, folders, cache)
            })
        } else {
            None
        };
        out.push(ServiceFact {
            display_name: wide(e.lpDisplayName),
            kind,
            start: config.start,
            running,
            binary: (!r.target.is_empty()).then(|| file_facts(&r.target, folders, cache)),
            host: r.via.map(|h| super::host_name(h).to_owned()),
            host_args: (!r.host_args.is_empty()).then_some(r.host_args),
            service_dll,
            account: config.account,
            binary_path,
            name,
        });
    }
    Ok(out)
}

struct Config {
    binary_path: Option<String>,
    start: StartType,
    account: Option<String>,
}

fn config(scm: &Handle, name: &str) -> Option<Config> {
    // SAFETY: valid manager handle and NUL-terminated name; config read only.
    let service =
        Handle(unsafe { OpenServiceW(scm.0, &HSTRING::from(name), SERVICE_QUERY_CONFIG) }.ok()?);
    let mut needed = 0u32;
    // SAFETY: size query only.
    let _ = unsafe { QueryServiceConfigW(service.0, None, 0, &raw mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let cfg = buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: `buf` is at least `needed` bytes and aligned for the struct.
    unsafe { QueryServiceConfigW(service.0, Some(cfg), needed, &raw mut needed) }.ok()?;
    // SAFETY: filled by the call above; strings point into `buf`.
    let cfg = unsafe { &*cfg };
    let start = match cfg.dwStartType {
        SERVICE_BOOT_START | SERVICE_SYSTEM_START => StartType::Boot,
        SERVICE_AUTO_START => StartType::Auto,
        SERVICE_DEMAND_START => StartType::Demand,
        _ => StartType::Disabled,
    };
    Some(Config {
        binary_path: wide(cfg.lpBinaryPathName),
        start,
        account: wide(cfg.lpServiceStartName),
    })
}

/// `Parameters\ServiceDll` for a shared service, falling back to the
/// service key itself. `%SystemRoot%` and friends are expanded by the
/// path classifier and resolver, the same as every other path.
fn service_dll(name: &str) -> Option<String> {
    let base = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
    for path in [format!(r"{base}\Parameters"), base] {
        if let Some(text) = Key::open(HKEY_LOCAL_MACHINE, &path, KEY_WOW64_64KEY)
            .and_then(|k| k.value("ServiceDll"))
            .and_then(|d| d.text().map(str::to_owned))
            .filter(|t| !t.trim().is_empty())
        {
            return Some(text);
        }
    }
    None
}
