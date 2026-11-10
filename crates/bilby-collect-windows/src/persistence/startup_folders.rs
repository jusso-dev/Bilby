//! The user and all-users Startup folders. Shortcuts are read with
//! `IShellLinkW` loaded through `IPersistFile::Load(STGM_READ)`. `Resolve`
//! is never called, because it can rewrite the shortcut.

use bilby_core::model::CheckStatus;
use bilby_core::snapshot::{StartupItem, StartupSource};
use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, CoCreateInstance, IPersistFile, STGM_READ,
};
use windows::Win32::UI::Shell::{
    FOLDERID_CommonStartup, FOLDERID_Startup, IShellLinkW, SLGP_RAWPATH, ShellLink,
};
use windows::core::{HSTRING, Interface};

use super::registry_item;
use super::run_keys::approved;
use crate::paths::known_folder_path;

/// Every file in both Startup folders, and how reading them went.
pub(super) fn items() -> (Vec<StartupItem>, CheckStatus) {
    let enabled = approved("StartupFolder");
    let mut out = Vec::new();
    let mut failed = Vec::new();
    for id in [&FOLDERID_Startup, &FOLDERID_CommonStartup] {
        let Some(dir) = known_folder_path(id) else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            // desktop.ini is Explorer's folder settings, not a program.
            if name.eq_ignore_ascii_case("desktop.ini") || !path.is_file() {
                continue;
            }
            let full = path.to_string_lossy().into_owned();
            let command = if name.to_ascii_lowercase().ends_with(".lnk") {
                match shortcut_command(&full) {
                    // Shortcuts to Store apps and shell items have no file
                    // path. Nothing to check, and calling them "missing"
                    // would be a false alarm.
                    Ok(None) => continue,
                    Ok(Some(c)) => c,
                    Err(e) => {
                        failed.push(format!("{name}: {}", e.message()));
                        continue;
                    }
                }
            } else {
                // A program or script dropped straight in the folder.
                format!("\"{full}\"")
            };
            let on = enabled.get(&name.to_lowercase()).copied().unwrap_or(true);
            let modified = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(time::OffsetDateTime::from);
            out.push(registry_item(
                StartupSource::StartupFolder,
                &dir,
                name,
                command,
                on,
                modified,
            ));
        }
    }
    let status = if failed.is_empty() {
        CheckStatus::Ran
    } else {
        CheckStatus::Failed(failed.join("; "))
    };
    (out, status)
}

/// The shortcut's target and arguments as one quoted command line.
/// `None` when the shortcut points at something that isn't a file.
fn shortcut_command(lnk_path: &str) -> windows::core::Result<Option<String>> {
    // SAFETY: COM is initialised by the caller (init_com). ShellLink is an
    // in-process class.
    let shell_link: IShellLinkW =
        unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }?;
    let file: IPersistFile = shell_link.cast()?;
    // SAFETY: read-only load of the .lnk; the path is NUL-terminated.
    unsafe { file.Load(&HSTRING::from(lnk_path), STGM_READ) }?;
    let mut target = vec![0u16; 32_768];
    let mut find = WIN32_FIND_DATAW::default();
    // SAFETY: buffer for the path; SLGP_RAWPATH returns it unexpanded so
    // %VAR% stays visible, and resolve() expands it the same way for all
    // sources. No Resolve call.
    unsafe {
        shell_link.GetPath(
            &mut target,
            &raw mut find,
            u32::try_from(SLGP_RAWPATH.0).unwrap_or(0),
        )
    }?;
    let mut args = vec![0u16; 32_768];
    // SAFETY: buffer for the arguments.
    unsafe { shell_link.GetArguments(&mut args) }?;
    let text = |b: &[u16]| {
        let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
        String::from_utf16_lossy(&b[..end])
    };
    let (target, args) = (text(&target), text(&args));
    if target.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(if args.is_empty() {
        format!("\"{target}\"")
    } else {
        format!("\"{target}\" {args}")
    }))
}
