//! RAII guards so no handle leaks, whatever path a function takes out.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::core::{HSTRING, Result};

/// An open Win32 file handle, closed on drop.
#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Opens a file for reading only, sharing with everyone so Bilby never
    /// gets in the way of the program that owns it.
    pub fn open_read(path: &str) -> Result<Self> {
        let wide = HSTRING::from(path);
        // SAFETY: `wide` is a valid NUL-terminated wide string that outlives
        // the call. No security attributes or template handle are passed.
        // GENERIC_READ (0x8000_0000) only: read-only access.
        let handle = unsafe {
            CreateFileW(
                &wide,
                windows::Win32::Foundation::GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_SEQUENTIAL_SCAN,
                None,
            )
        }?;
        Ok(Self(handle))
    }

    /// The raw handle, valid while `self` lives.
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: we own this handle, it came from CreateFileW and it's
            // closed exactly once, here.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}
