//! "I know this one" (#18): findings the user told Bilby to ignore, kept in
//! `%LOCALAPPDATA%\Bilby\suppressions.json`.
//!
//! An ignored finding still shows, under "Things you've told Bilby to
//! ignore", but doesn't count toward the light. If it's about a file, the
//! file's SHA-256 is stored too: when the file changes, the suppression no
//! longer applies and the finding comes back with a line saying so.
//!
//! Plain file reading and writing only, so it's tested on any OS. Saving
//! writes a temporary file and renames it over the old one, so a crash
//! can't leave half a file.

use std::collections::HashSet;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::model::{Evidence, Finding, Subject};
use crate::rules::reputation::{files, finding_paths};
use crate::snapshot::SystemSnapshot;

/// Copy key for the line on a finding whose file changed since it was
/// ignored.
pub const CHANGED: &str = "evidence.changed_since_ignored";

/// Copy key for the line on a file finding whose suppression has no stored
/// hash, so it can't be shown to be the same file.
pub const UNVERIFIED: &str = "evidence.ignore_unverified";

/// File format version.
const VERSION: u32 = 1;

/// One "I know this one".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Suppression {
    /// [`Finding::id`]: rule id plus subject.
    pub finding_id: String,
    /// The rule, for the helper view and for people reading the file.
    pub rule_id: String,
    /// What the finding was about.
    pub subject: Subject,
    /// When the user said to ignore it.
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: OffsetDateTime,
    /// The user's own note, if any.
    #[serde(default)]
    pub note: String,
    /// SHA-256 of the finding's file when it was ignored, if it's about a
    /// file and the file could be hashed.
    #[serde(default)]
    pub sha256: Option<String>,
}

/// Everything the user told Bilby to ignore.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Suppressions {
    /// File format version.
    #[serde(default = "version")]
    pub version: u32,
    /// The entries, oldest first.
    #[serde(default)]
    pub entries: Vec<Suppression>,
}

fn version() -> u32 {
    VERSION
}

/// True if the finding is about a file that exists: its subject is a file,
/// or it names an existing file the snapshot has facts for (a startup item
/// or task target, say). A missing target ("starts a program that isn't
/// there") has nothing to fingerprint, and can be ignored without one.
fn about_file(f: &Finding, snap: &SystemSnapshot) -> bool {
    if matches!(f.subject, Subject::File(_)) {
        return true;
    }
    let by_path = files(snap);
    finding_paths(f)
        .iter()
        .any(|p| by_path.get(p).is_some_and(|x| x.exists))
}

/// The SHA-256 of the file a finding is about, from the snapshot.
fn file_hash(f: &Finding, snap: &SystemSnapshot) -> Option<String> {
    let by_path = files(snap);
    finding_paths(f)
        .iter()
        .find_map(|p| by_path.get(p).and_then(|x| x.sha256.clone()))
        .map(|h| h.to_ascii_lowercase())
}

impl Suppressions {
    /// Reads `path`. A missing file means nothing is ignored. A file that
    /// can't be read or parsed is an error, so the caller can say so
    /// rather than silently forget what the user asked.
    pub fn load(path: &Path) -> io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self {
                version: VERSION,
                entries: Vec::new(),
            }),
            Err(e) => Err(e),
        }
    }

    /// Writes `path` atomically: a temporary file next to it, then a rename
    /// over the old one.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        {
            use std::io::Write as _;
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(text.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Ignores `f` from now on, remembering its file's hash if it's about a
    /// file. Ignoring the same finding twice keeps one entry, with the new
    /// note and hash.
    ///
    /// Returns false, and changes nothing, for a finding about a file that
    /// couldn't be hashed (unreadable, or over the size limit): without a
    /// fingerprint Bilby couldn't tell when the file changes, so the
    /// suppression would never expire.
    #[must_use]
    pub fn add(
        &mut self,
        f: &Finding,
        snap: &SystemSnapshot,
        now: OffsetDateTime,
        note: &str,
    ) -> bool {
        let hash = file_hash(f, snap);
        if hash.is_none() && about_file(f, snap) {
            return false;
        }
        let id = f.id();
        self.entries.retain(|e| e.finding_id != id);
        self.entries.push(Suppression {
            finding_id: id,
            rule_id: f.rule_id.clone(),
            subject: f.subject.clone(),
            added_at: now,
            note: note.to_owned(),
            sha256: hash,
        });
        true
    }

    /// Stops ignoring a finding. True if it was ignored.
    pub fn remove(&mut self, finding_id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.finding_id != finding_id);
        self.entries.len() != before
    }

    /// The ids of findings that are still ignored. A finding whose file
    /// changed (or can no longer be hashed) since it was ignored isn't, and
    /// gets an evidence line saying so. Neither is a file finding whose
    /// entry has no stored hash (a hand-edited file, say): there's nothing
    /// to compare, so it can't be shown to be the same file.
    pub fn apply(&self, findings: &mut [Finding], snap: &SystemSnapshot) -> HashSet<String> {
        let mut out = HashSet::new();
        for f in findings.iter_mut() {
            let id = f.id();
            let Some(entry) = self.entries.iter().find(|e| e.finding_id == id) else {
                continue;
            };
            match &entry.sha256 {
                None if about_file(f, snap) => {
                    f.evidence.push(Evidence::Text {
                        label_key: UNVERIFIED.to_owned(),
                        value: format!("ignored on {}, no fingerprint kept", entry.added_at.date()),
                    });
                }
                Some(then)
                    if file_hash(f, snap).as_deref()
                        != Some(then.to_ascii_lowercase().as_str()) =>
                {
                    f.evidence.push(Evidence::Text {
                        label_key: CHANGED.to_owned(),
                        value: format!("ignored on {}", entry.added_at.date()),
                    });
                }
                _ => {
                    out.insert(id);
                }
            }
        }
        out
    }
}
