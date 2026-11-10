//! "Check more deeply": start Bilby again as administrator through the
//! normal UAC prompt, with `--deep-check` so the new window starts a scan
//! straight away. Nothing runs elevated in the background, and nothing
//! stays elevated after that window closes.
//!
//! This starts Bilby itself and changes nothing on the computer, so it
//! stays within ADR 0003. It lives here because this crate is where Bilby's
//! audited Win32 calls are.

/// What happened when Bilby asked Windows to start it as administrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relaunch {
    /// The elevated copy started. This window should close.
    Started,
    /// The person said no at the UAC prompt.
    Declined,
}

/// Asks Windows to start this program again as administrator.
pub fn relaunch() -> Result<Relaunch, String> {
    use windows::Win32::Foundation::ERROR_CANCELLED;
    use windows::Win32::UI::Shell::{SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{HSTRING, PCWSTR, w};

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let file = HSTRING::from(exe.as_os_str());
    let params = HSTRING::from("--deep-check");
    let mut info = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>())
            .map_err(|e| e.to_string())?,
        fMask: SEE_MASK_NOASYNC,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: `info` is fully initialised with its size set, and the strings
    // it points to (`file`, `params` and a static verb) outlive the call.
    match unsafe { ShellExecuteExW(&raw mut info) } {
        Ok(()) => Ok(Relaunch::Started),
        Err(e) if e.code() == ERROR_CANCELLED.to_hresult() => Ok(Relaunch::Declined),
        Err(e) => Err(e.message()),
    }
}

pub use crate::processes::current_is_elevated;
