//! Opens a Windows Settings or Windows Security page for a finding's "What
//! to do" button (#23).
//!
//! Only the fixed targets in [`target`] can be opened. The webview never
//! passes a URI: it passes a finding id, the app looks up that finding's
//! setting id, and this maps the id to one of these constants. Anything
//! else opens nothing.

/// Where a setting id goes: a `ms-settings:` or `windowsdefender:` page, or
/// one program in System32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A Settings or Windows Security page, opened by its URI.
    Uri(&'static str),
    /// `UserAccountControlSettings.exe`, which has no Settings page.
    UacSettings,
}

/// The page for a finding's setting id, or `None` if Bilby can't open it
/// (a browser's own extensions page, say, which only the browser can show).
pub fn target(setting: &str) -> Option<Target> {
    Some(match setting {
        "windowsdefender:" | "windows_security" | "windows_security.virus" => {
            Target::Uri("windowsdefender://threat")
        }
        "windowsdefender://network" => Target::Uri("windowsdefender://network"),
        "windowsdefender://devicesecurity" => Target::Uri("windowsdefender://devicesecurity"),
        "ms-settings:windowsupdate" => Target::Uri("ms-settings:windowsupdate"),
        "ms-settings:network-proxy" => Target::Uri("ms-settings:network-proxy"),
        "ms-settings:startupapps" => Target::Uri("ms-settings:startupapps"),
        "ms-settings:appsfeatures" => Target::Uri("ms-settings:appsfeatures"),
        "uac" => Target::UacSettings,
        _ => return None,
    })
}

/// Opens a target with the shell's default "open" action.
pub fn open(target: Target) -> Result<(), String> {
    use windows::Win32::UI::Shell::{SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{HSTRING, PCWSTR, w};

    let file = match target {
        Target::Uri(uri) => HSTRING::from(uri),
        Target::UacSettings => {
            let root = crate::paths::known_folders().system_root;
            HSTRING::from(
                std::path::Path::new(&root)
                    .join("System32")
                    .join("UserAccountControlSettings.exe")
                    .as_os_str(),
            )
        }
    };
    let mut info = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>())
            .map_err(|e| e.to_string())?,
        fMask: SEE_MASK_NOASYNC,
        lpVerb: w!("open"),
        lpFile: PCWSTR(file.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: `info` is fully initialised with its size set, and the strings
    // it points to (`file` and a static verb) outlive the call.
    unsafe { ShellExecuteExW(&raw mut info) }.map_err(|e| e.message())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_settings_open() {
        assert_eq!(
            target("windowsdefender:"),
            Some(Target::Uri("windowsdefender://threat"))
        );
        assert_eq!(target("uac"), Some(Target::UacSettings));
        assert_eq!(target("browser.extensions"), None);
        assert_eq!(target("https://example.com"), None);
        assert_eq!(target("ms-settings:"), None);
        assert_eq!(target("file:///C:/Windows/System32/cmd.exe"), None);
    }
}
