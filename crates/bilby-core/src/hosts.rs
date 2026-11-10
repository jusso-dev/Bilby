//! The hosts file: decoding, parsing and the watch list of domains that
//! should never be redirected. Pure, so it's tested on any OS.

use std::net::IpAddr;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

/// One mapping from the hosts file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostsEntry {
    /// 1-based line number, so a fix can remove exactly this line (#32).
    pub line: usize,
    /// The address names are sent to.
    pub ip: String,
    /// Names on the line, lower case.
    pub names: Vec<String>,
}

/// Decodes hosts file bytes: UTF-8 with or without a byte order mark, or
/// UTF-16 (little or big endian, with a mark, or detected from the zero
/// bytes Notepad leaves when it saves as "Unicode").
pub fn decode(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    let utf16 = |data: &[u8], le: bool| {
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, true);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, false);
    }
    // No mark: ASCII text saved as UTF-16 has a zero in every other byte.
    if bytes.len() >= 4 {
        let sample = &bytes[..bytes.len().min(512) & !1];
        let odd_zeros = sample
            .iter()
            .skip(1)
            .step_by(2)
            .filter(|b| **b == 0)
            .count();
        let even_zeros = sample.iter().step_by(2).filter(|b| **b == 0).count();
        let half = sample.len() / 2;
        if odd_zeros * 10 >= half * 9 && even_zeros == 0 {
            return utf16(bytes, true);
        }
        if even_zeros * 10 >= half * 9 && odd_zeros == 0 {
            return utf16(bytes, false);
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// Parses hosts file text. Comments (`#` to end of line) and blank lines
/// are skipped. Lines whose first field isn't an IP address are skipped
/// too: Windows ignores them.
pub fn parse(text: &str) -> Vec<HostsEntry> {
    text.lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let line = raw.split('#').next().unwrap_or_default().trim();
            let mut fields = line.split_whitespace();
            let ip = fields.next()?;
            // Allow a zone id on link-local IPv6 (fe80::1%3).
            ip.split('%').next()?.parse::<IpAddr>().ok()?;
            let names: Vec<String> = fields.map(str::to_ascii_lowercase).collect();
            (!names.is_empty()).then(|| HostsEntry {
                line: i + 1,
                ip: ip.to_owned(),
                names,
            })
        })
        .collect()
}

/// Is this a "send it nowhere" address, as ad-blocking lists use?
pub fn is_blackhole(ip: &str) -> bool {
    matches!(ip, "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "::0")
}

/// A watch-list group: why its domains matter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchGroup {
    /// Banks.
    Banking,
    /// Government services.
    Government,
    /// Payments and accounts.
    Payments,
    /// Email and sign-in.
    Email,
    /// Windows Update and security software. Some privacy tools block
    /// these on purpose, so blocking them is less sure to be harmful.
    UpdatesAndSecurity,
}

/// Domains that should never be redirected, with their group.
pub static WATCH: LazyLock<Vec<(String, WatchGroup)>> = LazyLock::new(|| {
    let mut group = WatchGroup::Banking;
    let mut out = Vec::new();
    for line in include_str!("../data/watch_domains.txt").lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("## ") {
            group = match name.trim() {
                "banking" => WatchGroup::Banking,
                "government" => WatchGroup::Government,
                "payments" => WatchGroup::Payments,
                "email" => WatchGroup::Email,
                "updates and security" => WatchGroup::UpdatesAndSecurity,
                other => panic!("unknown watch group {other:?} in watch_domains.txt"),
            };
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push((line.to_ascii_lowercase(), group));
    }
    out
});

/// The watch-list domain this name is, or is a subdomain of.
pub fn watched(name: &str) -> Option<(&'static str, WatchGroup)> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    // The most specific entry wins: wdcp.microsoft.com is in the updates
    // and security group even though microsoft.com is in email.
    WATCH
        .iter()
        .filter(|(d, _)| name == *d || name.ends_with(&format!(".{d}")))
        .max_by_key(|(d, _)| d.len())
        .map(|(d, g)| (d.as_str(), *g))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_list_loads_every_group() {
        // Every domain the issue lists: 14 banks, 5 government, 4 payments,
        // 8 email, 16 updates and security.
        assert_eq!(WATCH.len(), 47);
        assert_eq!(
            watched("netbank.commbank.com.au"),
            Some(("commbank.com.au", WatchGroup::Banking))
        );
        assert_eq!(
            watched("MY.GOV.AU."),
            Some(("my.gov.au", WatchGroup::Government))
        );
        assert_eq!(
            watched("www.paypal.com"),
            Some(("paypal.com", WatchGroup::Payments))
        );
        assert_eq!(
            watched("mail.google.com"),
            Some(("google.com", WatchGroup::Email))
        );
        assert_eq!(
            watched("download.windowsupdate.com"),
            Some(("windowsupdate.com", WatchGroup::UpdatesAndSecurity))
        );
        // Look-alikes aren't the watched domain.
        assert_eq!(watched("notcommbank.com.au"), None);
        assert_eq!(watched("commbank.com.au.evil.test"), None);
        assert_eq!(watched("my-dev-site.test"), None);
    }
}
