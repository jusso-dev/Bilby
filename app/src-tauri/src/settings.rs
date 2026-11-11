//! `%LOCALAPPDATA%\Bilby\settings.json`: the online check switches
//! (ADR 0004). Booleans only. API keys live in Windows Credential Manager
//! (`bilby_reputation::key`), never here.

use std::io;
use std::path::{Path, PathBuf};

use bilby_core::settings::OnlineChecks;
use serde::{Deserialize, Serialize};

/// Everything in `settings.json`. Theme and text size join later (#25).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    /// Online check switches, all off by default.
    #[serde(default)]
    pub online: OnlineChecks,
}

/// Where the file lives.
pub fn path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(|base| PathBuf::from(base).join("Bilby").join("settings.json"))
}

/// Reads the settings. A missing file means the defaults (everything
/// off). A file that can't be read is logged and also means everything
/// off: never switch an online check on by accident.
pub fn load() -> Settings {
    path().map_or_else(Settings::default, |p| load_from(&p))
}

fn load_from(p: &Path) -> Settings {
    match std::fs::read_to_string(p) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
            tracing::info!(error = %e, "settings.json couldn't be read; online checks stay off");
            Settings::default()
        }),
        Err(_) => Settings::default(),
    }
}

/// Writes the settings: a temporary file, then a rename over the old one.
pub fn save(s: Settings) -> io::Result<()> {
    let p = path().ok_or_else(|| io::Error::other("LOCALAPPDATA isn't set"))?;
    save_to(&p, s)
}

fn save_to(p: &Path, s: Settings) -> io::Result<()> {
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = p.as_os_str().to_owned();
    tmp.push(".tmp");
    let text = serde_json::to_string_pretty(&s).map_err(io::Error::other)?;
    std::fs::write(&tmp, text + "\n")?;
    std::fs::rename(&tmp, p)
}

/// A service whose switches are on the settings screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Switch {
    /// CIRCL known-software lookups.
    Circl,
    /// VirusTotal file lookups.
    VirusTotal,
    /// VirusTotal IP reports.
    VirusTotalIps,
    /// AbuseIPDB IP reports.
    AbuseIpDb,
    /// CrowdSec CTI IP reports.
    CrowdSec,
}

impl Switch {
    /// From the `data-setting` name the webview sends.
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "circl" => Self::Circl,
            "virustotal" => Self::VirusTotal,
            "virustotal_ips" => Self::VirusTotalIps,
            "abuseipdb" => Self::AbuseIpDb,
            "crowdsec" => Self::CrowdSec,
            _ => return None,
        })
    }

    /// Turns this switch on or off.
    pub fn set(self, o: &mut OnlineChecks, on: bool) {
        match self {
            Self::Circl => o.circl = on,
            Self::VirusTotal => o.virustotal = on,
            Self::VirusTotalIps => o.virustotal_ips = on,
            Self::AbuseIpDb => o.abuseipdb = on,
            Self::CrowdSec => o.crowdsec = on,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_broken_file_means_everything_off() {
        let dir = std::env::temp_dir().join(format!("bilby-settings-{}", std::process::id()));
        let p = dir.join("settings.json");
        assert_eq!(load_from(&p), Settings::default());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&p, "{ not json").unwrap();
        assert!(!load_from(&p).online.any());
        // A key in the file is refused, so the switches stay off.
        std::fs::write(&p, r#"{"online":{"virustotal":true,"key":"x"}}"#).unwrap();
        assert!(!load_from(&p).online.any());
        let mut s = Settings::default();
        Switch::parse("crowdsec").unwrap().set(&mut s.online, true);
        save_to(&p, s).unwrap();
        assert!(load_from(&p).online.crowdsec);
        assert!(Switch::parse("anything").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
