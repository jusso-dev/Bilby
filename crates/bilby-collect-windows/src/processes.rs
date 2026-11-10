//! Running programs. Read-only: a Toolhelp snapshot, then each process is
//! opened with `PROCESS_QUERY_LIMITED_INFORMATION` only, the least access
//! Windows offers. Bilby never reads another process's memory. Command
//! lines come from WMI, which only returns the current user's without admin.

use std::collections::HashMap;
use std::ffi::c_void;

use bilby_core::paths::KnownFolders;
use bilby_core::snapshot::ProcessFact;
use time::OffsetDateTime;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    TokenElevation, TokenUser,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{PCWSTR, PWSTR};
use wmi::{Variant, WMIConnection};

use crate::cache::FileCache;
use crate::files::file_facts;

/// Closes a handle on drop.
struct Guard(HANDLE);

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: we own the handle and close it exactly once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

/// Every running process with what Windows will tell an ordinary user.
pub fn collect(
    folders: &KnownFolders,
    cache: &FileCache,
) -> windows::core::Result<Vec<ProcessFact>> {
    let mut procs = snapshot()?;
    let command_lines = command_lines();
    // Distinct image paths, so 40 svchost.exe are looked at once (the cache
    // would catch it anyway, this just saves the lock traffic).
    for p in &mut procs {
        if p.pid == 0 || p.pid == 4 {
            continue;
        }
        details(p);
        p.command_line = command_lines.get(&p.pid).cloned();
    }
    let mut paths: Vec<&str> = procs
        .iter()
        .filter_map(|p| p.image_path.as_deref())
        .collect();
    paths.sort_unstable();
    paths.dedup();
    let facts: HashMap<String, _> = paths
        .iter()
        .map(|path| ((*path).to_owned(), file_facts(path, folders, cache)))
        .collect();
    for p in &mut procs {
        if let Some(path) = &p.image_path {
            p.file = facts.get(path).cloned();
        }
    }
    Ok(procs)
}

fn snapshot() -> windows::core::Result<Vec<ProcessFact>> {
    // SAFETY: TH32CS_SNAPPROCESS with pid 0 snapshots all processes. The
    // returned handle is closed by the guard.
    let snap = Guard(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?);
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: `entry` has dwSize set as the API requires; the snapshot handle
    // is valid while `snap` lives.
    let mut ok = unsafe { Process32FirstW(snap.0, &raw mut entry) }.is_ok();
    while ok {
        let len = entry
            .szExeFile
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(entry.szExeFile.len());
        out.push(ProcessFact {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            name: String::from_utf16_lossy(&entry.szExeFile[..len]),
            ..ProcessFact::default()
        });
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snap.0, &raw mut entry) }.is_ok();
    }
    Ok(out)
}

/// Fills path, start time, session, user and elevation. Each one is
/// optional: access denied is normal for protected and other users'
/// processes.
fn details(p: &mut ProcessFact) {
    let mut session = 0u32;
    // SAFETY: writes one u32. Works for any pid without opening it.
    if unsafe { ProcessIdToSessionId(p.pid, &raw mut session) }.is_ok() {
        p.session_id = Some(session);
    }
    // SAFETY: the least access right that allows reading the image path and
    // times. No inheritance. The handle is closed by the guard.
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid) })
    else {
        return;
    };
    let process = Guard(handle);
    p.image_path = image_path(process.0);
    p.created = created(process.0);
    let mut token = HANDLE::default();
    // SAFETY: TOKEN_QUERY only; the token handle is closed by the guard.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &raw mut token) }.is_ok() {
        let token = Guard(token);
        p.user = token_user(token.0);
        p.is_elevated = token_elevated(token.0);
    }
}

fn image_path(process: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut len = u32::try_from(buf.len()).ok()?;
    // SAFETY: `buf` has `len` u16s; Windows writes at most that and updates
    // `len` to the characters written.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &raw mut len,
        )
    }
    .ok()?;
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

/// Seconds between 1601-01-01 (the FILETIME epoch) and 1970-01-01.
const FILETIME_EPOCH_DIFF: i64 = 11_644_473_600;

/// FILETIME (100 ns ticks since 1601) to UTC.
pub(crate) fn from_filetime(ft: FILETIME) -> Option<OffsetDateTime> {
    let ticks = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    if ticks == 0 {
        return None;
    }
    let secs = i64::try_from(ticks / 10_000_000).ok()? - FILETIME_EPOCH_DIFF;
    let nanos = i64::try_from(ticks % 10_000_000).ok()? * 100;
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()?
        .checked_add(time::Duration::nanoseconds(nanos))
}

fn created(process: HANDLE) -> Option<OffsetDateTime> {
    let (mut c, mut e, mut k, mut u) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: four FILETIME out-parameters, all valid for writing.
    unsafe { GetProcessTimes(process, &raw mut c, &raw mut e, &raw mut k, &raw mut u) }.ok()?;
    from_filetime(c)
}

/// Reads a token information class into an aligned buffer.
fn token_info(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Option<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: first call with no buffer only reports the size needed.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &raw mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` is at least `needed` bytes and 8-byte aligned, enough for
    // any token information structure.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buf.as_mut_ptr().cast::<c_void>()),
            needed,
            &raw mut needed,
        )
    }
    .ok()?;
    Some(buf)
}

fn token_user(token: HANDLE) -> Option<String> {
    let buf = token_info(token, TokenUser)?;
    // SAFETY: GetTokenInformation(TokenUser) filled `buf` with a TOKEN_USER
    // at the start; `buf` outlives `user`.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let (mut name_len, mut domain_len) = (0u32, 0u32);
    let mut kind = SID_NAME_USE::default();
    // SAFETY: first call reports the buffer sizes. The SID points into `buf`.
    let _ = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            user.User.Sid,
            None,
            &raw mut name_len,
            None,
            &raw mut domain_len,
            &raw mut kind,
        )
    };
    if name_len == 0 {
        return None;
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    // SAFETY: buffers sized from the first call.
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            user.User.Sid,
            Some(PWSTR(name.as_mut_ptr())),
            &raw mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &raw mut domain_len,
            &raw mut kind,
        )
    }
    .ok()?;
    let name = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    Some(if domain.is_empty() {
        name
    } else {
        format!(r"{domain}\{name}")
    })
}

/// True if Bilby itself is running elevated (as administrator), from
/// `GetTokenInformation(TokenElevation)` on its own token.
pub fn current_is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess is a pseudo handle that needs no closing;
    // TOKEN_QUERY only, and the token handle is closed by the guard.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }
    let token = Guard(token);
    token_elevated(token.0).unwrap_or(false)
}

fn token_elevated(token: HANDLE) -> Option<bool> {
    let buf = token_info(token, TokenElevation)?;
    // SAFETY: GetTokenInformation(TokenElevation) filled a TOKEN_ELEVATION.
    let elevation = unsafe { &*buf.as_ptr().cast::<TOKEN_ELEVATION>() };
    Some(elevation.TokenIsElevated != 0)
}

/// Command lines by pid from `Win32_Process`. Without admin Windows only
/// fills them in for the current user's processes, which is enough.
fn command_lines() -> HashMap<u32, String> {
    crate::defender::init_com();
    let Ok(con) = WMIConnection::new() else {
        return HashMap::new();
    };
    let rows: Vec<HashMap<String, Variant>> = con
        .raw_query("SELECT ProcessId, CommandLine FROM Win32_Process")
        .unwrap_or_default();
    rows.into_iter()
        .filter_map(|r| {
            let pid = match r.get("ProcessId")? {
                Variant::UI4(v) => *v,
                Variant::I4(v) => u32::try_from(*v).ok()?,
                _ => return None,
            };
            match r.get("CommandLine")? {
                Variant::String(s) if !s.is_empty() => Some((pid, s.clone())),
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_converts() {
        // 2026-11-09 09:00:00 UTC in FILETIME ticks.
        let ticks: u64 = (1_794_214_800 + 11_644_473_600) * 10_000_000;
        let ft = FILETIME {
            dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        assert_eq!(
            from_filetime(ft),
            Some(time::macros::datetime!(2026-11-09 09:00:00 UTC))
        );
        assert_eq!(from_filetime(FILETIME::default()), None);
    }
}
