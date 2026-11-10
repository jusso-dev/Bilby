//! Removes the user name, computer name, profile path and account SIDs from
//! text and JSON, for snapshot dumps, saved reports and logs.
//!
//! - The profile folder (`C:\Users\alex`, and its 8.3 short form if the
//!   caller passes it) becomes `%USERPROFILE%`.
//! - Machine and account SIDs (`S-1-5-21-...`, Entra `S-1-12-1-...`) become
//!   `<sid>`. Well-known SIDs like `S-1-5-18` are the same on every
//!   computer and stay.
//! - The user name and computer name become `<user>` and `<computer>`
//!   wherever they appear as a whole word, in any case.
//!
//! Matching ignores case, because Windows paths do and rules lower-case
//! subjects. Over-scrubbing is fine; under-scrubbing isn't.

use serde_json::Value;

/// Replaces personal names in text. Build one per scan with [`Scrubber::new`].
#[derive(Debug, Clone, Default)]
pub struct Scrubber {
    /// Profile paths, folded, longest first.
    profiles: Vec<Vec<char>>,
    /// Whole-word names and what replaces them, folded, longest first.
    words: Vec<(Vec<char>, &'static str)>,
}

/// Case folding that keeps one char per char, so positions line up with the
/// original text.
fn fold(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

fn folded(s: &str) -> Vec<char> {
    s.chars().map(fold).collect()
}

/// Characters that can be part of a user or computer name. Anything else
/// ends the word.
fn in_word(c: char) -> bool {
    c.is_alphanumeric() || c == '-' || c == '_' || c == '$'
}

const PROFILE: &str = "%USERPROFILE%";
const SID: &str = "<sid>";
/// What a user name becomes.
pub const USER: &str = "<user>";
/// What the computer name becomes.
pub const COMPUTER: &str = "<computer>";
/// SID prefixes that identify one computer or account.
const SID_PREFIXES: &[&str] = &["s-1-5-21-", "s-1-12-1-"];

impl Scrubber {
    /// A scrubber for these profile paths (long and short forms), user name
    /// and computer name. Empty values and one-letter names are ignored, so
    /// they can't blank out every "a".
    pub fn new(profiles: &[&str], user: Option<&str>, computer: Option<&str>) -> Self {
        let mut p: Vec<Vec<char>> = profiles
            .iter()
            .map(|s| s.trim().trim_end_matches(['\\', '/']))
            .filter(|s| s.len() > 3)
            // As written, with forward slashes, and with doubled
            // backslashes as `Debug` formatting writes them in log lines.
            .flat_map(|s| {
                [
                    folded(s),
                    folded(&s.replace('\\', "/")),
                    folded(&s.replace('\\', r"\\")),
                ]
            })
            .collect();
        p.sort_by_key(|v| std::cmp::Reverse(v.len()));
        p.dedup();
        let mut words: Vec<(Vec<char>, &'static str)> = [(user, USER), (computer, COMPUTER)]
            .into_iter()
            .filter_map(|(v, with)| {
                v.map(str::trim)
                    .filter(|v| v.chars().count() > 1)
                    .map(|v| (folded(v), with))
            })
            .collect();
        words.sort_by_key(|(v, _)| std::cmp::Reverse(v.len()));
        Self { profiles: p, words }
    }

    /// `s` with personal names replaced.
    pub fn text(&self, s: &str) -> String {
        let chars: Vec<char> = s.chars().collect();
        let low: Vec<char> = chars.iter().copied().map(fold).collect();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < chars.len() {
            let start_of_word = i == 0 || !in_word(chars[i - 1]);
            if let Some(n) = self.profile_at(&low, i) {
                out.push_str(PROFILE);
                i += n;
                continue;
            }
            // Task names glue SIDs on with a dash or underscore
            // (`OneDrive Startup Task-S-1-12-1-...`), so a SID only needs a
            // non-alphanumeric character before it.
            if (i == 0 || !chars[i - 1].is_alphanumeric())
                && let Some(n) = sid_at(&low, i)
            {
                out.push_str(SID);
                i += n;
                continue;
            }
            if start_of_word && let Some((n, with)) = self.word_at(&low, i) {
                out.push_str(with);
                i += n;
                continue;
            }
            out.push(chars[i]);
            i += 1;
        }
        out
    }

    /// Scrubs every string in a JSON value, object keys included.
    pub fn json(&self, v: &mut Value) {
        match v {
            Value::String(s) => *s = self.text(s),
            Value::Array(items) => items.iter_mut().for_each(|x| self.json(x)),
            Value::Object(map) => {
                let old = std::mem::take(map);
                for (k, mut val) in old {
                    self.json(&mut val);
                    map.insert(self.text(&k), val);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Length of a profile path starting at `i`, if it ends there or at a
    /// path separator (so `C:\Users\al` doesn't match `C:\Users\alex`).
    fn profile_at(&self, low: &[char], i: usize) -> Option<usize> {
        self.profiles.iter().find_map(|p| {
            let end = i + p.len();
            let hit = low.get(i..end) == Some(p.as_slice())
                && low
                    .get(end)
                    .is_none_or(|c| !in_word(*c) && *c != '.' && *c != '~');
            hit.then_some(p.len())
        })
    }

    fn word_at(&self, low: &[char], i: usize) -> Option<(usize, &'static str)> {
        self.words.iter().find_map(|(w, with)| {
            let end = i + w.len();
            let hit =
                low.get(i..end) == Some(w.as_slice()) && low.get(end).is_none_or(|c| !in_word(*c));
            hit.then_some((w.len(), *with))
        })
    }
}

/// Length of an account or machine SID starting at `i`.
fn sid_at(low: &[char], i: usize) -> Option<usize> {
    SID_PREFIXES.iter().find_map(|prefix| {
        let p: Vec<char> = prefix.chars().collect();
        if low.get(i..i + p.len()) != Some(p.as_slice()) {
            return None;
        }
        let rest = low[i + p.len()..]
            .iter()
            .take_while(|c| c.is_ascii_digit() || **c == '-')
            .count();
        // A SID can't end in a dash; leave a trailing one in the text.
        let rest = if low.get(i + p.len() + rest - usize::from(rest > 0)) == Some(&'-') {
            rest - 1
        } else {
            rest
        };
        (rest > 0).then_some(p.len() + rest)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s() -> Scrubber {
        Scrubber::new(
            &[r"C:\Users\runneradmin", r"C:\Users\RUNNER~1"],
            Some("runneradmin"),
            Some("fv-az123-456"),
        )
    }

    #[test]
    fn profile_paths_any_case_and_short_form() {
        let s = s();
        assert_eq!(
            s.text(r"C:\Users\runneradmin\AppData\Local\Temp\x.exe"),
            r"%USERPROFILE%\AppData\Local\Temp\x.exe"
        );
        assert_eq!(
            s.text(r"c:\users\RUNNERADMIN\downloads"),
            r"%USERPROFILE%\downloads"
        );
        assert_eq!(
            s.text(r"C:\Users\RUNNER~1\AppData\Local\Temp"),
            r"%USERPROFILE%\AppData\Local\Temp"
        );
        assert_eq!(s.text("C:/Users/runneradmin/x"), "%USERPROFILE%/x");
        assert_eq!(
            s.text(r#"Failed("C:\\Users\\runneradmin\\x")"#),
            r#"Failed("%USERPROFILE%\\x")"#
        );
        assert_eq!(s.text(r#""C:\Users\runneradmin""#), r#""%USERPROFILE%""#);
        // A longer name that starts the same is a different profile, but
        // its user-name part still isn't this user.
        assert_eq!(
            s.text(r"C:\Users\runneradmin2\x"),
            r"C:\Users\runneradmin2\x"
        );
    }

    #[test]
    fn names_as_whole_words() {
        let s = s();
        assert_eq!(s.text(r"FV-AZ123-456\runneradmin"), r"<computer>\<user>");
        assert_eq!(s.text("CN=fv-az123-456.internal"), "CN=<computer>.internal");
        assert_eq!(s.text("superrunneradmin"), "superrunneradmin");
        assert_eq!(s.text("runneradmins"), "runneradmins");
    }

    #[test]
    fn sids() {
        let s = s();
        assert_eq!(
            s.text(r"HKU\S-1-5-21-1004336348-1177238915-682003330-1001\Software"),
            r"HKU\<sid>\Software"
        );
        assert_eq!(s.text("S-1-12-1-111-222-333-444"), "<sid>");
        assert_eq!(s.text("S-1-5-18 and S-1-5-19"), "S-1-5-18 and S-1-5-19");
        assert_eq!(s.text("S-1-5-21-1-2-3-"), "<sid>-");
        assert_eq!(
            s.text(r"\OneDrive Startup Task-S-1-12-1-12-34-56-78"),
            r"\OneDrive Startup Task-<sid>"
        );
        assert_eq!(
            s.text(r"\Updates\UpdateConfiguration_S-1-5-21-1-2-3-1001"),
            r"\Updates\UpdateConfiguration_<sid>"
        );
        assert_eq!(s.text("XS-1-5-21-1-2-3"), "XS-1-5-21-1-2-3");
    }

    #[test]
    fn short_or_missing_names_are_ignored() {
        let s = Scrubber::new(&["C:"], Some("a"), None);
        assert_eq!(s.text(r"a C:\a"), r"a C:\a");
    }

    #[test]
    fn json_strings_and_keys() {
        let s = s();
        let mut v = serde_json::json!({
            r"C:\Users\runneradmin\x": [r"fv-az123-456\runneradmin", 3, null],
            "nested": { "user": "RunnerAdmin" }
        });
        s.json(&mut v);
        assert_eq!(
            v,
            serde_json::json!({
                r"%USERPROFILE%\x": [r"<computer>\<user>", 3, null],
                "nested": { "user": "<user>" }
            })
        );
    }
}
