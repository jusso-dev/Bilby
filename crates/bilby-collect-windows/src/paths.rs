//! Fills [`KnownFolders`] from the real system, for path classification in
//! `bilby_core::paths`.

use std::collections::BTreeMap;

use bilby_core::paths::KnownFolders;
use windows::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetLogicalDrives, GetLongPathNameW, GetTempPathW,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::SystemInformation::{
    GetSystemDirectoryW, GetSystemWindowsDirectoryW, GetSystemWow64DirectoryW,
};
use windows::Win32::System::WindowsProgramming::{DRIVE_REMOTE, DRIVE_REMOVABLE};
use windows::Win32::UI::Shell::{
    FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_LocalAppData,
    FOLDERID_Profile, FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86,
    FOLDERID_Public, FOLDERID_RoamingAppData, FOLDERID_UserProgramFiles, KF_FLAG_DEFAULT,
    SHGetKnownFolderPath,
};
use windows::core::{GUID, HSTRING};

/// Reads a path from one of the `GetSystem*DirectoryW` style functions,
/// which take a buffer and return the length written (or needed).
fn from_buffer(call: impl Fn(Option<&mut [u16]>) -> u32) -> Option<String> {
    let needed = call(None);
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u16; needed as usize + 1];
    let written = call(Some(&mut buf)) as usize;
    if written == 0 || written > buf.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..written]))
}

/// The path of a known folder (`FOLDERID_*`) for the current user.
pub fn known_folder_path(id: &GUID) -> Option<String> {
    known_folder(id)
}

fn known_folder(id: &GUID) -> Option<String> {
    // SAFETY: `id` points to a valid GUID for the call's duration. No token
    // is passed, so it's the current user's folder.
    let path = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None) }.ok()?;
    // SAFETY: on success Windows returns a valid NUL-terminated string that
    // we must free with CoTaskMemFree, which we do straight after copying.
    let text = unsafe { path.to_string() }.ok();
    // SAFETY: `path` came from SHGetKnownFolderPath and is freed once.
    unsafe { CoTaskMemFree(Some(path.0 as *const _)) };
    text
}

/// Expands 8.3 short names (`C:\Users\RUNNER~1\...`) to the long form, so
/// short and long spellings of a folder classify the same. Returns the input
/// unchanged if Windows can't expand it (for example the file is gone).
pub fn long_path(path: &str) -> String {
    if !path.contains('~') {
        return path.to_owned();
    }
    let wide = HSTRING::from(path);
    // SAFETY: `wide` is NUL-terminated. With no buffer the call returns the
    // length needed, including the terminator.
    let needed = unsafe { GetLongPathNameW(&wide, None) };
    if needed == 0 {
        return path.to_owned();
    }
    let mut buf = vec![0u16; needed as usize];
    // SAFETY: `buf` has the length Windows asked for.
    let written = unsafe { GetLongPathNameW(&wide, Some(&mut buf)) } as usize;
    if written == 0 || written >= buf.len() {
        return path.to_owned();
    }
    String::from_utf16_lossy(&buf[..written])
}

/// Resolves every folder classification needs. Anything Windows can't tell
/// us falls back to the usual default under the system drive.
pub fn known_folders() -> KnownFolders {
    // SAFETY: each closure passes a correctly sized buffer or None, as
    // `from_buffer` requires, and the functions only write within it.
    let system_root = from_buffer(|b| unsafe { GetSystemWindowsDirectoryW(b) })
        .unwrap_or_else(|| r"C:\Windows".to_owned());
    // SAFETY: as above.
    let system32 = from_buffer(|b| unsafe { GetSystemDirectoryW(b) })
        .unwrap_or_else(|| format!(r"{system_root}\System32"));
    // SAFETY: as above. Returns 0 on 32-bit Windows, giving None.
    let syswow64 = from_buffer(|b| unsafe { GetSystemWow64DirectoryW(b) });
    // SAFETY: as above.
    let temp = from_buffer(|b| unsafe { GetTempPathW(b) })
        .map(|t| long_path(t.trim_end_matches('\\')))
        .unwrap_or_default();

    let drive = system_root.get(..2).unwrap_or("C:").to_owned();
    let profile = known_folder(&FOLDERID_Profile).unwrap_or_default();
    let local_app_data =
        known_folder(&FOLDERID_LocalAppData).unwrap_or_else(|| format!(r"{profile}\AppData\Local"));
    let (removable_drives, network_drives) = drives_by_type();

    KnownFolders {
        system32,
        syswow64,
        program_files: known_folder(&FOLDERID_ProgramFiles)
            .unwrap_or_else(|| format!(r"{drive}\Program Files")),
        program_files_x86: known_folder(&FOLDERID_ProgramFilesX86),
        program_data: known_folder(&FOLDERID_ProgramData)
            .unwrap_or_else(|| format!(r"{drive}\ProgramData")),
        roaming_app_data: known_folder(&FOLDERID_RoamingAppData)
            .unwrap_or_else(|| format!(r"{profile}\AppData\Roaming")),
        user_program_files: known_folder(&FOLDERID_UserProgramFiles)
            .unwrap_or_else(|| format!(r"{local_app_data}\Programs")),
        downloads: known_folder(&FOLDERID_Downloads)
            .unwrap_or_else(|| format!(r"{profile}\Downloads")),
        desktop: known_folder(&FOLDERID_Desktop).unwrap_or_else(|| format!(r"{profile}\Desktop")),
        documents: known_folder(&FOLDERID_Documents)
            .unwrap_or_else(|| format!(r"{profile}\Documents")),
        public: known_folder(&FOLDERID_Public).unwrap_or_else(|| format!(r"{drive}\Users\Public")),
        temp,
        local_app_data,
        profile,
        system_root,
        removable_drives,
        network_drives,
        env: std::env::vars().collect::<BTreeMap<_, _>>(),
    }
}

/// Drive letters (`e:`) that are removable and that are network drives.
fn drives_by_type() -> (Vec<String>, Vec<String>) {
    // SAFETY: takes no arguments and returns a bitmask of drive letters.
    let mask = unsafe { GetLogicalDrives() };
    let mut removable = Vec::new();
    let mut network = Vec::new();
    for i in 0..26u8 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = char::from(b'a' + i);
        let root = HSTRING::from(format!(r"{letter}:\"));
        // SAFETY: `root` is a valid NUL-terminated wide string for the call.
        let kind = unsafe { GetDriveTypeW(&root) };
        if kind == DRIVE_REMOVABLE {
            removable.push(format!("{letter}:"));
        } else if kind == DRIVE_REMOTE {
            network.push(format!("{letter}:"));
        }
    }
    (removable, network)
}
