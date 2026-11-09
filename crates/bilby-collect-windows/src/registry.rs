//! Small read-only registry helpers. Every key is opened with `KEY_READ`
//! and closed on drop. Nothing here can write.

use time::OffsetDateTime;
use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME};
use windows::Win32::System::Registry::{
    HKEY, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE,
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW,
};
use windows::core::{HSTRING, PWSTR};

/// A registry value's data, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// `REG_SZ`, `REG_EXPAND_SZ` (not expanded), `REG_MULTI_SZ` (joined
    /// with spaces).
    Text(String),
    /// `REG_DWORD`.
    Dword(u32),
    /// `REG_BINARY` and any other type.
    Bytes(Vec<u8>),
}

impl Data {
    /// The text, if it's a string value.
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }
}

/// An open registry key, closed on drop.
pub struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key came from RegOpenKeyExW and is closed exactly once.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

impl Key {
    /// Opens `root\path` for reading. `view` adds `KEY_WOW64_64KEY` or
    /// `KEY_WOW64_32KEY` when a specific registry view is wanted.
    pub fn open(root: HKEY, path: &str, view: REG_SAM_FLAGS) -> Option<Self> {
        let mut key = HKEY::default();
        let wide = HSTRING::from(path);
        // SAFETY: valid root and NUL-terminated path; `key` receives the
        // handle. KEY_READ only.
        let rc = unsafe { RegOpenKeyExW(root, &wide, None, KEY_READ | view, &raw mut key) };
        (rc == ERROR_SUCCESS).then_some(Self(key))
    }

    /// Opens a subkey of this key for reading, in the same view.
    pub fn sub(&self, name: &str, view: REG_SAM_FLAGS) -> Option<Self> {
        Self::open(self.0, name, view)
    }

    /// When the key was last written.
    pub fn last_write(&self) -> Option<OffsetDateTime> {
        let mut ft = FILETIME::default();
        // SAFETY: only the last-write time is asked for; everything else None.
        let rc = unsafe {
            RegQueryInfoKeyW(
                self.0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(&raw mut ft),
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        crate::processes::from_filetime(ft)
    }

    /// Every value as (name, data). Names longer than 16,383 characters
    /// can't exist in the registry.
    pub fn values(&self) -> Vec<(String, Data)> {
        let mut out = Vec::new();
        for index in 0.. {
            let mut name = vec![0u16; 16_384];
            let mut name_len = u32::try_from(name.len()).unwrap_or(u32::MAX);
            let mut kind = 0u32;
            let mut size = 0u32;
            // SAFETY: first call gets the name and the data size only.
            let rc = unsafe {
                RegEnumValueW(
                    self.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &raw mut name_len,
                    None,
                    Some(&raw mut kind),
                    None,
                    Some(&raw mut size),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                continue;
            }
            let value_name = String::from_utf16_lossy(&name[..name_len as usize]);
            if let Some(data) = self.value(&value_name) {
                out.push((value_name, data));
            }
        }
        out
    }

    /// One value. `None` if it doesn't exist.
    pub fn value(&self, name: &str) -> Option<Data> {
        let wide = HSTRING::from(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        // SAFETY: first call reports the type and size only.
        let rc = unsafe {
            RegQueryValueExW(
                self.0,
                &wide,
                None,
                Some(&raw mut kind),
                None,
                Some(&raw mut size),
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        // Room for a missing terminator, aligned for u16 reads.
        let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut got = size;
        // SAFETY: `buf` holds at least `size` bytes.
        let rc = unsafe {
            RegQueryValueExW(
                self.0,
                &wide,
                None,
                Some(&raw mut kind),
                Some(buf.as_mut_ptr().cast::<u8>()),
                Some(&raw mut got),
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let bytes = got as usize;
        Some(decode(kind, &buf, bytes))
    }

    /// Names of every subkey.
    pub fn subkeys(&self) -> Vec<String> {
        let mut out = Vec::new();
        for index in 0.. {
            let mut name = vec![0u16; 256];
            let mut len = u32::try_from(name.len()).unwrap_or(256);
            // SAFETY: name buffer of `len` characters; nothing else asked for.
            let rc = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &raw mut len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc == ERROR_SUCCESS {
                out.push(String::from_utf16_lossy(&name[..len as usize]));
            }
        }
        out
    }
}

fn decode(kind: REG_VALUE_TYPE, buf: &[u16], bytes: usize) -> Data {
    let words = &buf[..bytes / 2];
    match kind {
        REG_SZ | REG_EXPAND_SZ => {
            let end = words.iter().position(|c| *c == 0).unwrap_or(words.len());
            Data::Text(String::from_utf16_lossy(&words[..end]))
        }
        REG_MULTI_SZ => Data::Text(
            words
                .split(|c| *c == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        REG_DWORD if bytes >= 4 => Data::Dword(u32::from(words[0]) | (u32::from(words[1]) << 16)),
        _ => {
            // SAFETY: `buf` holds at least `bytes` bytes; reading them as u8
            // is always valid.
            let raw = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), bytes) };
            Data::Bytes(raw.to_vec())
        }
    }
}
