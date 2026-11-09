//! Copy lint: every user-facing string follows `docs/copy-guide.md`, every
//! key used in code exists, and every key in the catalogue is used.
//!
//! Run on its own with `cargo test -p bilby-core --test copy_lint`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use bilby_core::copy::CATALOGUE;
use regex::Regex;

/// Banned anywhere in copy (whole word, any case). Must match the list in
/// `docs/copy-guide.md`, which `guide_and_lint_agree` checks.
const BANNED: &[&str] = &[
    "seamless",
    "robust",
    "cutting-edge",
    "leverage",
    "unlock",
    "harness",
    "empower",
    "elevate",
    "transform",
    "journey",
    "critical",
    "urgent",
    "hacker",
];

/// Banned in headlines only: `title` keys and everything under `light.`.
const BANNED_IN_HEADLINES: &[&str] = &["infected", "compromised"];

/// US spellings that slip in, and the Australian spelling to use.
const US_SPELLINGS: &[(&str, &str)] = &[
    ("color", "colour"),
    ("organiz", "organis"),
    ("license", "licence (noun)"),
    ("center", "centre"),
    ("behavior", "behaviour"),
    ("favorite", "favourite"),
    ("recogniz", "recognis"),
];

/// Keys kept for screens and rules that later issues add. Listed here so
/// unused keys are a deliberate choice, not an accident.
const RESERVED: &[&str] = &[
    "app.name",
    "home.intro",
    "scan.heading",
    "scan.online_off",
    "light.healthy.sub",
    "light.worth_a_look.sub",
    "light.needs_attention.sub",
    "confidence.high",
    "confidence.medium",
    "confidence.low",
    "location.desktop",
    "location.documents",
    "location.appdata",
    "location.windows",
    "location.program_files",
    "location.other",
];

const TITLE_MAX: usize = 160;
const OTHER_MAX: usize = 240;

fn is_emoji(c: char) -> bool {
    matches!(u32::from(c),
        0x1F000..=0x1FAFF   // pictographs, emoticons, transport, flags, symbols
        | 0x2600..=0x27BF   // misc symbols and dingbats
        | 0x2B00..=0x2BFF   // arrows and stars often shown as emoji
        | 0xFE0F            // emoji presentation selector
        | 0x200D) // zero-width joiner
}

/// Every problem with one string. Empty means it passes.
fn lint(key: &str, text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let lower = text.to_lowercase();
    let word = |w: &str| {
        Regex::new(&format!(r"(?i)\b{}\b", regex::escape(w)))
            .expect("valid regex")
            .is_match(text)
    };

    if text.contains('\u{2014}') {
        problems.push("has an em dash; use a comma, full stop or brackets".to_owned());
    }
    let en_dash_words = Regex::new(r"\D\s*\u{2013}\s*\D|^\u{2013}|\u{2013}$").expect("valid regex");
    if en_dash_words.is_match(text) {
        problems
            .push("has an en dash between words; en dashes are only for number ranges".to_owned());
    }
    if text.contains('!') {
        problems.push("has an exclamation mark".to_owned());
    }
    if let Some(c) = text.chars().find(|c| is_emoji(*c)) {
        problems.push(format!("has an emoji or symbol {c:?}"));
    }
    // Copy keys, not file names, so the extension lint doesn't apply.
    let is_title = key.rsplit('.').next() == Some("title");
    let is_headline = is_title || key.starts_with("light.");
    let max = if is_title { TITLE_MAX } else { OTHER_MAX };
    if text.chars().count() > max {
        problems.push(format!(
            "is {} characters, limit {max}",
            text.chars().count()
        ));
    }
    for banned in BANNED {
        if word(banned) {
            problems.push(format!("uses the banned word {banned:?}"));
        }
    }
    if is_headline {
        for banned in BANNED_IN_HEADLINES {
            if word(banned) {
                problems.push(format!("uses {banned:?} in a headline"));
            }
        }
    }
    for (us, au) in US_SPELLINGS {
        if Regex::new(&format!(r"\b{us}"))
            .expect("valid regex")
            .is_match(&lower)
        {
            problems.push(format!("uses US spelling {us:?}; use {au:?}"));
        }
    }
    let ident = Regex::new(r"^[a-z_][a-z0-9_]*$").expect("valid regex");
    for cap in Regex::new(r"\{([^}]*)\}")
        .expect("valid regex")
        .captures_iter(text)
    {
        if !ident.is_match(&cap[1]) {
            problems.push(format!("has a bad placeholder {{{}}}", &cap[1]));
        }
    }
    if text.contains('{') != text.contains('}') {
        problems.push("has an unmatched brace".to_owned());
    }
    problems
}

#[test]
fn every_string_follows_the_copy_guide() {
    let mut failures = Vec::new();
    for (key, text) in CATALOGUE.iter() {
        for problem in lint(key, text) {
            failures.push(format!("{key} {problem}: {text:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "copy lint failed:\n{}",
        failures.join("\n")
    );
}

#[test]
fn lint_catches_known_bad_strings() {
    let bad = [
        ("x.what", "Fast \u{2014} and calm"),
        ("x.what", "Scan done!"),
        ("x.what", "A seamless check"),
        ("x.what", "Pick a color"),
        ("x.what", "All good \u{1F600}"),
        ("x.what", "Before \u{2013} after"),
        ("x.title", "Your computer is infected"),
        ("light.healthy.headline", "Not compromised"),
        ("x.what", "Hello {Name}"),
        ("x.title", &"a".repeat(TITLE_MAX + 1)),
    ];
    for (key, text) in bad {
        assert!(
            !lint(key, text).is_empty(),
            "lint should reject {key} = {text:?}"
        );
    }
    // Look-alikes that must pass.
    let good = [
        ("x.what", "Updated 0\u{2013}30 days ago."),
        (
            "x.what",
            "We found something that looks like a real problem.",
        ),
        ("x.why", "Old definitions can miss newer threats."),
        ("x.what", "The file is {name}."),
        // "infected" is fine outside headlines.
        (
            "x.why",
            "Files that look infected are handed to Windows Security.",
        ),
    ];
    for (key, text) in good {
        assert!(
            lint(key, text).is_empty(),
            "lint should accept {key} = {text:?}: {:?}",
            lint(key, text)
        );
    }
}

#[test]
fn guide_and_lint_agree() {
    let guide = fs::read_to_string(repo_root().join("docs/copy-guide.md")).expect("copy guide");
    let section = guide
        .split("## Banned words in UI copy")
        .nth(1)
        .and_then(|s| s.split("\n## ").next())
        .expect("banned words section");
    let list = section
        .split_once(':')
        .map(|(_, rest)| rest)
        .expect("banned words list after a colon");
    let mut from_guide = BTreeSet::new();
    for item in list.split(',') {
        let word = item
            .split('(')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_end_matches('.')
            .trim_start_matches("the ")
            .to_owned();
        if !word.is_empty() && !word.contains("em dash") {
            from_guide.insert(word);
        }
    }
    let from_lint: BTreeSet<String> = BANNED
        .iter()
        .chain(BANNED_IN_HEADLINES)
        .map(|w| (*w).to_owned())
        .collect();
    assert_eq!(
        from_guide, from_lint,
        "docs/copy-guide.md and the lint list differ"
    );
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn files(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" || name == "gen" || name.to_string_lossy().starts_with('.') {
            continue;
        }
        if path.is_dir() {
            files(&path, exts, out);
        } else if path
            .extension()
            .is_some_and(|e| exts.iter().any(|x| e == *x))
        {
            out.push(path);
        }
    }
}

/// Every copy key the code, templates and fixtures refer to.
fn referenced_keys() -> BTreeSet<String> {
    let root = repo_root();
    let mut paths = Vec::new();
    for dir in ["crates", "app/src-tauri"] {
        files(&root.join(dir), &["rs", "html", "json"], &mut paths);
    }
    let in_code = Regex::new(r#"\btf?\(\s*"([a-z0-9_.]+)""#).expect("valid regex");
    let in_template = Regex::new(r#""([a-z0-9_.]+)"\s*\|\s*t\b"#).expect("valid regex");
    let title_key = Regex::new(r#""title_key"\s*:\s*"([a-z0-9_.]+)""#).expect("valid regex");
    let any_string = Regex::new(r#""([a-z0-9_]+\.[a-z0-9_.]+)""#).expect("valid regex");

    let mut keys = BTreeSet::new();
    for path in paths {
        // This file names keys in its own tests; don't count those.
        if path.ends_with("tests/copy_lint.rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("readable source");
        for re in [&in_code, &in_template] {
            for cap in re.captures_iter(&text) {
                keys.insert(cap[1].to_owned());
            }
        }
        if path.extension().is_some_and(|e| e == "json") {
            // A finding's title_key is a prefix for title, what, why and todo.
            for cap in title_key.captures_iter(&text) {
                for part in ["title", "what", "why", "todo"] {
                    keys.insert(format!("{}.{part}", &cap[1]));
                }
            }
        }
        // Any whole string literal that is exactly a catalogue key counts as
        // a use: keys picked in a `match` and passed on, label keys in
        // fixtures, skipped reasons and location variables.
        for cap in any_string.captures_iter(&text) {
            if CATALOGUE.contains_key(&cap[1]) {
                keys.insert(cap[1].to_owned());
            }
        }
    }
    keys
}

#[test]
fn every_referenced_key_exists() {
    let missing: Vec<String> = referenced_keys()
        .into_iter()
        .filter(|k| !CATALOGUE.contains_key(k))
        .collect();
    assert!(
        missing.is_empty(),
        "keys used but not in en-AU.toml: {missing:?}"
    );
}

#[test]
fn every_key_is_used_or_reserved() {
    let used = referenced_keys();
    let mut unused = Vec::new();
    for key in CATALOGUE.keys() {
        if used.contains(key) {
            continue;
        }
        if RESERVED.contains(&key.as_str()) {
            println!("warning: copy key {key} is reserved and not used yet");
        } else {
            unused.push(key.clone());
        }
    }
    assert!(
        unused.is_empty(),
        "keys in en-AU.toml that nothing uses (use them, delete them, or add to RESERVED): {unused:?}"
    );
    let stale: Vec<&&str> = RESERVED
        .iter()
        .filter(|k| !CATALOGUE.contains_key(**k))
        .collect();
    assert!(
        stale.is_empty(),
        "RESERVED keys missing from en-AU.toml: {stale:?}"
    );
}
