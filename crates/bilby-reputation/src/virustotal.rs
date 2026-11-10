//! VirusTotal file reports, with the user's own key. Never uploads files.
//!
//! `GET https://www.virustotal.com/api/v3/files/<sha256>` with header
//! `x-apikey`. Reads `data.attributes.last_analysis_stats` and
//! `last_analysis_date` (Unix seconds). 404 means VirusTotal hasn't seen
//! the file. The free public API allows 4 requests a minute and 500 a day,
//! and must not be used in commercial products (VirusTotal, "Public vs
//! Premium API", checked 10-11-2026). Bilby is free and the key is the
//! user's own.

use serde::Deserialize;
use time::OffsetDateTime;

use bilby_core::snapshot::VtResult;

use crate::allowlist::{HttpError, Transport};
use crate::is_sha256;

/// Public API rate: requests per minute.
pub const PUBLIC_PER_MINUTE: u32 = 4;
/// Public API quota: requests per day.
pub const PUBLIC_PER_DAY: u32 = 500;

/// URL for a hash.
pub fn url(sha256: &str) -> String {
    format!(
        "https://www.virustotal.com/api/v3/files/{}",
        sha256.to_ascii_lowercase()
    )
}

#[derive(Deserialize)]
struct Report {
    data: Data,
}

#[derive(Deserialize)]
struct Data {
    attributes: Attributes,
}

#[derive(Deserialize)]
struct Attributes {
    last_analysis_stats: Stats,
    #[serde(default)]
    last_analysis_date: Option<i64>,
}

#[derive(Deserialize)]
struct Stats {
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default)]
    undetected: u32,
    #[serde(default)]
    harmless: u32,
}

/// Parses a 200 response body.
pub fn parse(sha256: &str, body: &str) -> Result<VtResult, HttpError> {
    let r: Report =
        serde_json::from_str(body).map_err(|e| HttpError::Failed(format!("bad JSON: {e}")))?;
    let a = r.data.attributes;
    Ok(VtResult {
        sha256: sha256.to_ascii_lowercase(),
        malicious: a.last_analysis_stats.malicious,
        suspicious: a.last_analysis_stats.suspicious,
        undetected: a.last_analysis_stats.undetected,
        harmless: a.last_analysis_stats.harmless,
        analysed: a
            .last_analysis_date
            .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok()),
    })
}

/// Looks up one hash. `Ok(None)` means VirusTotal hasn't seen it.
pub fn lookup(
    http: &dyn Transport,
    key: &str,
    sha256: &str,
) -> Result<Option<VtResult>, HttpError> {
    if !is_sha256(sha256) {
        return Err(HttpError::NotAllowed("not a SHA-256".to_owned()));
    }
    let r = http.get(&url(sha256), &[("x-apikey", key)])?;
    match r.status {
        200 => parse(sha256, &r.body).map(Some),
        404 => Ok(None),
        // 401 bad key, 429 quota: the scan carries on without VirusTotal.
        s => Err(HttpError::Failed(format!("VirusTotal returned {s}"))),
    }
}
