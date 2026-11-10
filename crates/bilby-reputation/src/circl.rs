//! CIRCL hashlookup: is this hash in a known-software set?
//!
//! `GET https://hashlookup.circl.lu/lookup/sha256/<hash>` with
//! `accept: application/json`. 200 means the hash is in at least one of
//! CIRCL's databases (NIST NSRL, Windows builds, Linux packages and
//! others); 404 means it isn't, which says nothing bad. Checked against
//! CIRCL's service page, <https://www.circl.lu/services/hashlookup/>.

use crate::allowlist::{HttpError, Transport};
use crate::is_sha256;

/// What CIRCL said about one hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Known {
    /// In a known-software set.
    Yes,
    /// Not in any set. Not a bad sign.
    No,
}

/// URL for a hash.
pub fn url(sha256: &str) -> String {
    format!(
        "https://hashlookup.circl.lu/lookup/sha256/{}",
        sha256.to_ascii_lowercase()
    )
}

/// Looks up one hash.
pub fn lookup(http: &dyn Transport, sha256: &str) -> Result<Known, HttpError> {
    if !is_sha256(sha256) {
        return Err(HttpError::NotAllowed("not a SHA-256".to_owned()));
    }
    let r = http.get(&url(sha256), &[("accept", "application/json")])?;
    match r.status {
        200 => Ok(Known::Yes),
        404 => Ok(Known::No),
        s => Err(HttpError::Status(s)),
    }
}
