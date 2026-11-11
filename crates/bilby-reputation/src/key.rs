//! The user's own API keys, kept in Windows Credential Manager as generic
//! credentials named `Bilby/VirusTotal`, `Bilby/AbuseIPDB` and
//! `Bilby/CrowdSec`. Never
//! written to `settings.json`, logs or reports, and never printed.

/// Credential Manager target name for the VirusTotal key.
pub const TARGET: &str = "Bilby/VirusTotal";

/// Credential Manager target name for the AbuseIPDB key.
pub const ABUSEIPDB_TARGET: &str = "Bilby/AbuseIPDB";

/// Credential Manager target name for the CrowdSec CTI key.
pub const CROWDSEC_TARGET: &str = "Bilby/CrowdSec";

/// Which service a key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// VirusTotal: file hashes and IP reports.
    VirusTotal,
    /// AbuseIPDB: IP reports.
    AbuseIpDb,
    /// CrowdSec CTI: IP reports.
    CrowdSec,
}

impl Service {
    /// The Credential Manager target name.
    pub fn target(self) -> &'static str {
        match self {
            Self::VirusTotal => TARGET,
            Self::AbuseIpDb => ABUSEIPDB_TARGET,
            Self::CrowdSec => CROWDSEC_TARGET,
        }
    }
}

/// A key that never shows itself in `Debug` output.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    /// Wraps a key typed by the user, trimmed. `None` if blank.
    pub fn new(raw: &str) -> Option<Self> {
        let k = raw.trim();
        (!k.is_empty()).then(|| Self(k.to_owned()))
    }

    /// The key, for the `x-apikey` header only.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(hidden)")
    }
}

#[cfg(windows)]
mod store {
    use super::{ApiKey, Service};
    use windows::Win32::Security::Credentials::{
        CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW,
        CredFree, CredReadW, CredWriteW,
    };
    use windows::core::{HSTRING, PWSTR};

    /// Reads a service's key, if one is saved.
    pub fn load(service: Service) -> Option<ApiKey> {
        let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: reads a generic credential by name; Windows allocates
        // `cred`, freed below with CredFree.
        unsafe {
            CredReadW(
                &HSTRING::from(service.target()),
                CRED_TYPE_GENERIC,
                None,
                &raw mut cred,
            )
        }
        .ok()?;
        // SAFETY: on success `cred` points at a valid CREDENTIALW whose blob
        // is CredentialBlobSize bytes.
        let key = unsafe {
            let c = &*cred;
            if c.CredentialBlob.is_null() || c.CredentialBlobSize == 0 {
                None
            } else {
                let blob =
                    std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize);
                String::from_utf8(blob.to_vec()).ok()
            }
        };
        // SAFETY: freeing what CredReadW allocated.
        unsafe { CredFree(cred.cast()) };
        key.and_then(|k| ApiKey::new(&k))
    }

    /// Saves a service's key for this user on this computer.
    pub fn save(service: Service, key: &ApiKey) -> windows::core::Result<()> {
        let mut target: Vec<u16> = service.target().encode_utf16().chain([0]).collect();
        let mut blob = key.expose().as_bytes().to_vec();
        let cred = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target.as_mut_ptr()),
            CredentialBlobSize: u32::try_from(blob.len()).unwrap_or(0),
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..CREDENTIALW::default()
        };
        // SAFETY: `cred` points at buffers that outlive the call.
        let r = unsafe { CredWriteW(&raw const cred, 0) };
        blob.fill(0);
        r
    }

    /// Removes a service's key.
    pub fn delete(service: Service) -> windows::core::Result<()> {
        // SAFETY: deletes a generic credential by name.
        unsafe { CredDeleteW(&HSTRING::from(service.target()), CRED_TYPE_GENERIC, None) }
    }
}

#[cfg(windows)]
pub use store::{delete, load, save};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_never_prints() {
        let k = ApiKey::new("  abc123  ").unwrap();
        assert_eq!(k.expose(), "abc123");
        assert_eq!(format!("{k:?}"), "ApiKey(hidden)");
        assert!(ApiKey::new("   ").is_none());
    }
}
