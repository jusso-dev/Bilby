//! Running program rules: Windows names in the wrong place, look-alike
//! names, unsigned programs in user-writable folders, odd parents for core
//! processes, duplicates and encoded script hosts. See `docs/signals.md`.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;

use super::{FindingBuilder, Relation, Rule, RuleContext};
use crate::model::{Confidence, Evidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::paths::{KnownFolders, normalise};
use crate::snapshot::{FileFacts, PathClass, ProcessFact, SignatureStatus, SystemSnapshot};

/// One row of `data/windows_core_processes.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct CoreProcess {
    /// Lower-case image name.
    pub name: String,
    /// Expected folders relative to `%SystemRoot%`; `""` is the root itself.
    pub folders: Vec<String>,
    /// The only programs allowed to start it, lower case. Empty means not
    /// checked. Only `lsass.exe` and `services.exe` set it today.
    #[serde(default)]
    pub parents: Vec<String>,
    /// Only one should ever run.
    #[serde(default)]
    pub single: bool,
}

#[derive(Deserialize)]
struct CoreTable {
    process: Vec<CoreProcess>,
}

/// The core process table, keyed by lower-case name.
pub static CORE: LazyLock<HashMap<String, CoreProcess>> = LazyLock::new(|| {
    let table: CoreTable = toml::from_str(include_str!("../data/windows_core_processes.toml"))
        .expect("windows_core_processes.toml is valid, checked by tests");
    table
        .process
        .into_iter()
        .map(|p| (p.name.to_lowercase(), p))
        .collect()
});

/// Is `file` validly signed as part of Windows?
fn windows_component(file: &FileFacts) -> bool {
    matches!(
        file.signature,
        SignatureStatus::Signed {
            is_windows_component: true,
            ..
        }
    )
}

fn microsoft_signed(file: &FileFacts) -> bool {
    file.signature
        .publisher()
        .is_some_and(|p| p.starts_with("Microsoft"))
}

/// Normalises a path that's already absolute. No folder lookups are
/// needed for that, so an empty [`KnownFolders`] is enough.
fn norm(path: &str) -> String {
    normalise(path, &KnownFolders::default())
}

/// Is `path` directly inside one of the expected folders under
/// `%SystemRoot%`? Uses the folder the file is in, not just a prefix, so
/// `System32\evil\svchost.exe` doesn't count.
fn in_expected_folder(path: &str, core: &CoreProcess, system_root: &str) -> bool {
    let n = norm(path);
    let Some((parent, _)) = n.rsplit_once('\\') else {
        return false;
    };
    let root = system_root.trim_end_matches('\\').to_lowercase();
    core.folders.iter().any(|f| {
        let expected = if f.is_empty() {
            root.clone()
        } else {
            format!(r"{root}\{}", f.to_lowercase())
        };
        parent == expected
    })
}

/// `%SystemRoot%` for path checks. Taken from a process we trust to be in
/// System32 (Windows component signature), falling back to `c:\windows`.
fn system_root(procs: &[ProcessFact]) -> String {
    procs
        .iter()
        .filter_map(|p| p.file.as_ref().filter(|f| windows_component(f)))
        .find_map(|f| {
            let n = norm(&f.path);
            n.find(r"\system32\").map(|i| n[..i].to_owned())
        })
        .unwrap_or_else(|| r"c:\windows".to_owned())
}

fn location_key(class: PathClass) -> &'static str {
    match class {
        PathClass::Downloads => "location.downloads",
        PathClass::Temp => "location.temp",
        PathClass::Desktop => "location.desktop",
        PathClass::Documents => "location.documents",
        PathClass::UserAppData | PathClass::UserAppPrograms => "location.appdata",
        PathClass::Windows | PathClass::WindowsSystem => "location.windows",
        PathClass::ProgramFiles | PathClass::WindowsApps => "location.program_files",
        PathClass::Public => "location.public",
        PathClass::RecycleBin => "location.recycle_bin",
        PathClass::ProgramData => "location.program_data",
        PathClass::Removable => "location.removable",
        PathClass::Network => "location.network",
        PathClass::Other => "location.other",
    }
}

fn base(id: &str, severity: Severity, confidence: Confidence, p: &ProcessFact) -> FindingBuilder {
    let path = p.image_path.clone().unwrap_or_else(|| p.name.clone());
    let mut b = FindingBuilder::new(
        id,
        SignalFamily::Processes,
        severity,
        confidence,
        Subject::File(norm(&path)),
    )
    .var("name", &p.name)
    .evidence(Evidence::Process {
        pid: p.pid,
        name: p.name.clone(),
        path: p.image_path.clone(),
        parent: None,
    });
    if let Some(f) = &p.file {
        b = b
            .var("location", location_key(f.class))
            .evidence(Evidence::Signature {
                status: signature_word(&f.signature).to_owned(),
                publisher: f.signature.publisher().map(str::to_owned),
            });
    }
    b
}

fn signature_word(s: &SignatureStatus) -> &'static str {
    match s {
        SignatureStatus::Signed { .. } => "signed",
        SignatureStatus::Unsigned => "unsigned",
        SignatureStatus::Invalid { .. } => "invalid",
        SignatureStatus::Untrusted { .. } => "untrusted",
        SignatureStatus::Error { .. } => "error",
    }
}

macro_rules! rule {
    ($name:ident, $id:literal, $fn:ident) => {
        struct $name;
        impl Rule for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn family(&self) -> SignalFamily {
                SignalFamily::Processes
            }
            fn evaluate(&self, snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding> {
                snap.processes
                    .as_deref()
                    .map(|p| $fn(p, ctx))
                    .unwrap_or_default()
            }
        }
    };
}

rule!(SystemName, "proc.masquerade.system_name", system_name);
rule!(Lookalike, "proc.masquerade.lookalike", lookalike);
rule!(
    UnsignedUserWritable,
    "proc.unsigned_user_writable",
    unsigned_user_writable
);
rule!(UnsignedAppData, "proc.unsigned_appdata", unsigned_appdata);
rule!(CoreParent, "proc.core_parent", core_parent);
rule!(CoreDuplicate, "proc.core_duplicate", core_duplicate);
rule!(
    ScriptHostEncoded,
    "proc.script_host_encoded",
    script_host_encoded
);

/// Every process rule.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SystemName),
        Box::new(Lookalike),
        Box::new(UnsignedUserWritable),
        Box::new(UnsignedAppData),
        Box::new(CoreParent),
        Box::new(CoreDuplicate),
        Box::new(ScriptHostEncoded),
    ]
}

/// One finding per distinct image file, so 40 copies of one program are one
/// card. Keeps the first process seen for each path.
fn distinct_by_file<'a>(procs: impl Iterator<Item = &'a ProcessFact>) -> Vec<&'a ProcessFact> {
    let mut seen = std::collections::HashSet::new();
    procs
        .filter(|p| {
            let key = p
                .image_path
                .as_deref()
                .map_or_else(|| format!("pid:{}", p.pid), norm);
            seen.insert(key)
        })
        .collect()
}

fn system_name(procs: &[ProcessFact], _: &RuleContext) -> Vec<Finding> {
    let root = system_root(procs);
    let suspicious = procs.iter().filter(|p| {
        let Some(core) = CORE.get(&p.name.to_lowercase()) else {
            return false;
        };
        // Without a path (access denied) we can't say it's in the wrong place.
        p.image_path
            .as_deref()
            .is_some_and(|path| !in_expected_folder(path, core, &root))
    });
    distinct_by_file(suspicious)
        .into_iter()
        .map(|p| {
            // A Microsoft-signed file in the wrong place is a copy of the
            // real thing: still wrong, but less sure it's harmful.
            let confidence = match &p.file {
                Some(f) if windows_component(f) || microsoft_signed(f) => Confidence::Medium,
                _ => Confidence::High,
            };
            base("proc.masquerade.system_name", Severity::High, confidence, p)
                .next(NextStepKind::AskDefender)
                .build()
        })
        .collect()
}

/// Common character swaps used in look-alike names, applied to the core
/// name to produce variants.
const SWAPS: &[(&str, &str)] = &[
    ("o", "0"),
    ("l", "1"),
    ("i", "1"),
    ("l", "i"),
    ("i", "l"),
    ("m", "rn"),
    ("w", "vv"),
];

/// Optimal string alignment distance (Damerau-Levenshtein with adjacent
/// transpositions, no substring edited twice). Names are short, so the
/// simple table is fine.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}

/// The core name `name` imitates, if any. Compares the stem without
/// `.exe`, so `svch0st.exe` and `scvhost.exe` match `svchost.exe`. Stems
/// under 5 letters are skipped: too many real programs are one letter away
/// from `dwm` or `lsass`-length names by chance.
pub fn imitates(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    if CORE.contains_key(&lower) {
        return None;
    }
    let stem = lower.strip_suffix(".exe")?;
    let mut names: Vec<&'static str> = CORE.keys().map(String::as_str).collect();
    // Same answer every run, whatever the hash map order.
    names.sort_unstable();
    names.into_iter().find(|core| {
        let Some(core_stem) = core.strip_suffix(".exe") else {
            return false;
        };
        core_stem.len() >= 5
            && (edit_distance(stem, core_stem) == 1
                || SWAPS.iter().any(|(from, to)| {
                    core_stem.contains(from) && core_stem.replace(from, to) == stem
                }))
    })
}

fn lookalike(procs: &[ProcessFact], _: &RuleContext) -> Vec<Finding> {
    // Only unsigned (or tampered, or unverifiable) look-alikes. A valid
    // signature from anyone trusted means the name is a coincidence, and
    // without the file we can't tell, so stay quiet rather than turn the
    // light red on a name alone.
    let hits = procs.iter().filter(|p| {
        imitates(&p.name).is_some() && p.file.as_ref().is_some_and(|f| !f.signature.is_signed())
    });
    distinct_by_file(hits)
        .into_iter()
        .map(|p| {
            let real = imitates(&p.name).unwrap_or_default();
            base(
                "proc.masquerade.lookalike",
                Severity::High,
                Confidence::Medium,
                p,
            )
            .var("real", real)
            .next(NextStepKind::AskDefender)
            .build()
        })
        .collect()
}

fn not_signed(file: &FileFacts) -> bool {
    matches!(
        file.signature,
        SignatureStatus::Unsigned | SignatureStatus::Invalid { .. }
    )
}

fn unsigned_user_writable(procs: &[ProcessFact], _: &RuleContext) -> Vec<Finding> {
    let hits = procs.iter().filter(|p| {
        p.file.as_ref().is_some_and(|f| {
            let risky_place = matches!(
                f.class,
                PathClass::Temp
                    | PathClass::Downloads
                    | PathClass::Desktop
                    | PathClass::Public
                    | PathClass::RecycleBin
            ) || (f.class == PathClass::ProgramData && f.user_writable);
            risky_place && not_signed(f)
        })
    });
    distinct_by_file(hits)
        .into_iter()
        .map(|p| {
            let tampered = p
                .file
                .as_ref()
                .is_some_and(|f| matches!(f.signature, SignatureStatus::Invalid { .. }));
            let confidence = if tampered {
                Confidence::High
            } else {
                Confidence::Medium
            };
            base(
                "proc.unsigned_user_writable",
                Severity::Medium,
                confidence,
                p,
            )
            .next(NextStepKind::AskDefender)
            .build()
        })
        .collect()
}

fn unsigned_appdata(procs: &[ProcessFact], ctx: &RuleContext) -> Vec<Finding> {
    let hits = procs.iter().filter(|p| {
        p.file
            .as_ref()
            .is_some_and(|f| f.class == PathClass::UserAppData && not_signed(f))
    });
    distinct_by_file(hits)
        .into_iter()
        .map(|p| {
            let related = p
                .image_path
                .as_deref()
                .map(|path| ctx.related(&norm(path)))
                .unwrap_or_default();
            // Many real apps run unsigned from AppData. It only means more
            // if the same file also starts by itself or talks out.
            let boosted = related.contains(&Relation::StartsByItself)
                || related.contains(&Relation::OutboundConnection);
            let confidence = if boosted {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            let mut b = base("proc.unsigned_appdata", Severity::Low, confidence, p)
                .next(NextStepKind::TalkToHelper);
            for r in related {
                b = b.text("evidence.related", format!("{r:?}"));
            }
            b.build()
        })
        .collect()
}

fn core_parent(procs: &[ProcessFact], _: &RuleContext) -> Vec<Finding> {
    let by_pid: HashMap<u32, &ProcessFact> = procs.iter().map(|p| (p.pid, p)).collect();
    procs
        .iter()
        .filter_map(|p| {
            let core = CORE.get(&p.name.to_lowercase())?;
            if core.parents.is_empty() {
                return None;
            }
            let parent = by_pid.get(&p.ppid)?;
            // The parent id may have been reused by a newer process. Only
            // trust it if the parent started before the child.
            let older = matches!((parent.created, p.created), (Some(pc), Some(cc)) if pc <= cc);
            let expected = core
                .parents
                .iter()
                .any(|e| e.eq_ignore_ascii_case(&parent.name));
            if !older || expected {
                return None;
            }
            Some(
                base("proc.core_parent", Severity::Medium, Confidence::Medium, p)
                    .var("parent", &parent.name)
                    .text(
                        "evidence.parent",
                        format!("{} (pid {})", parent.name, parent.pid),
                    )
                    .next(NextStepKind::TalkToHelper)
                    .build(),
            )
        })
        .collect()
}

fn core_duplicate(procs: &[ProcessFact], _: &RuleContext) -> Vec<Finding> {
    let mut by_name: HashMap<String, Vec<&ProcessFact>> = HashMap::new();
    for p in procs {
        let lower = p.name.to_lowercase();
        if CORE.get(&lower).is_some_and(|c| c.single) {
            by_name.entry(lower).or_default().push(p);
        }
    }
    let mut names: Vec<_> = by_name.into_iter().filter(|(_, v)| v.len() > 1).collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    names
        .into_iter()
        .map(|(name, list)| {
            let mut b = FindingBuilder::new(
                "proc.core_duplicate",
                SignalFamily::Processes,
                Severity::High,
                Confidence::Medium,
                Subject::Setting(format!("process.duplicate.{name}")),
            )
            .var("name", &list[0].name)
            .var("count", list.len())
            .next(NextStepKind::AskDefender);
            for p in list {
                b = b.evidence(Evidence::Process {
                    pid: p.pid,
                    name: p.name.clone(),
                    path: p.image_path.clone(),
                    parent: None,
                });
            }
            b.build()
        })
        .collect()
}

/// Does this PowerShell command line hide what it runs? Matches
/// `-EncodedCommand` and every prefix PowerShell accepts for it (`-e`,
/// `-ec`, `-enc`...), with `-` or `/`. Also a hidden window together with
/// download-and-run commands.
///
/// Only PowerShell's own parameters count. Scanning stops at `-File` and at
/// `-Command`: everything after `-File <script>` goes to the script, and
/// `-Command` text is PowerShell code, not flags. Download-and-run words are
/// matched as whole words inside that code, so `iexplore` isn't `iex`.
pub fn encoded_powershell(command_line: &str) -> bool {
    let lower = command_line.to_lowercase();
    let tokens = crate::cmdline::split_args(&lower);
    // Skip the program itself, then read flags until -File or -Command.
    let mut hidden = false;
    let mut code = String::new();
    let mut i = 1;
    while i < tokens.len() {
        let Some(flag) = flag_name(&tokens[i]) else {
            // A bare word where a flag was expected: PowerShell treats the
            // rest as a command.
            code = tokens[i..].join(" ");
            break;
        };
        if flag == "ec" || ("encodedcommand".starts_with(flag) && !flag.starts_with("ex")) {
            return true;
        }
        if flag.len() >= 2 && "file".starts_with(flag) {
            break;
        }
        if "command".starts_with(flag) {
            code = tokens[i + 1..].join(" ");
            break;
        }
        if "windowstyle".starts_with(flag) {
            hidden |= tokens.get(i + 1).is_some_and(|v| v.starts_with("hid"));
            i += 2;
            continue;
        }
        // Flags whose next token is their value, not a command.
        i += if takes_value(flag) { 2 } else { 1 };
    }
    let mut words = code
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter(|w| !w.is_empty());
    hidden
        && words.any(|w| {
            matches!(
                w,
                "iex" | "invoke-expression" | "downloadstring" | "frombase64string"
            )
        })
}

/// The flag name without its `-` or `/`, if `token` is a flag.
fn flag_name(token: &str) -> Option<&str> {
    let f = token.trim_start_matches(['-', '/', '\u{2013}', '\u{2014}']);
    (f.len() < token.len() && !f.is_empty()).then_some(f)
}

/// PowerShell parameters (besides `-WindowStyle`) that take a value.
/// Matched by unambiguous prefix, as PowerShell does, plus the `-ep` alias.
fn takes_value(flag: &str) -> bool {
    const WITH_VALUE: &[&str] = &[
        "executionpolicy",
        "version",
        "inputformat",
        "outputformat",
        "configurationname",
        "workingdirectory",
        "psconsolefile",
        "settingsfile",
        "custompipename",
    ];
    flag == "ep" || (flag.len() >= 2 && WITH_VALUE.iter().any(|name| name.starts_with(flag)))
}

fn script_host_encoded(procs: &[ProcessFact], _: &RuleContext) -> Vec<Finding> {
    procs
        .iter()
        .filter(|p| {
            matches!(
                p.name.to_lowercase().as_str(),
                "powershell.exe" | "pwsh.exe"
            )
        })
        .filter(|p| p.command_line.as_deref().is_some_and(encoded_powershell))
        .map(|p| {
            let mut b = base(
                "proc.script_host_encoded",
                Severity::High,
                Confidence::Medium,
                p,
            )
            .next(NextStepKind::TalkToHelper);
            // Command lines go in the helper view as they are. They can be
            // long, so only the first 500 characters.
            if let Some(cmd) = &p.command_line {
                b = b.text(
                    "evidence.command_line",
                    cmd.chars().take(500).collect::<String>(),
                );
            }
            // One finding per process: two hidden PowerShells are two things.
            b.finding.subject = Subject::Setting(format!("process.encoded.{}", p.pid));
            b.build()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_table_loads() {
        assert!(CORE.len() >= 23);
        assert!(CORE.contains_key("svchost.exe"));
        assert!(CORE["lsass.exe"].single);
        // Only the programs proc.core_parent checks have parents listed.
        let with_parents: Vec<&str> = {
            let mut v: Vec<&str> = CORE
                .values()
                .filter(|c| !c.parents.is_empty())
                .map(|c| c.name.as_str())
                .collect();
            v.sort_unstable();
            v
        };
        assert_eq!(with_parents, ["lsass.exe", "services.exe"]);
    }

    #[test]
    fn distances() {
        assert_eq!(edit_distance("svchost", "svchost"), 0);
        assert_eq!(edit_distance("scvhost", "svchost"), 1, "adjacent swap");
        assert_eq!(edit_distance("svhost", "svchost"), 1, "deletion");
        assert_eq!(edit_distance("svchosts", "svchost"), 1, "insertion");
        assert_eq!(edit_distance("svch0st", "svchost"), 1, "substitution");
        assert_eq!(edit_distance("chrome", "svchost"), 5);
    }

    #[test]
    fn lookalikes() {
        for (fake, real) in [
            ("scvhost.exe", "svchost.exe"),
            ("svch0st.exe", "svchost.exe"),
            ("SVCHOST1.exe", "svchost.exe"),
            ("lsasss.exe", "lsass.exe"),
            ("expl0rer.exe", "explorer.exe"),
            ("expiorer.exe", "explorer.exe"),
            ("csrsss.exe", "csrss.exe"),
            ("rundl132.exe", "rundll32.exe"),
            ("wininit1.exe", "wininit.exe"),
        ] {
            assert_eq!(imitates(fake), Some(real), "{fake}");
        }
        for name in [
            "svchost.exe", // the real name isn't a look-alike
            "Discord.exe",
            "chrome.exe",
            "Code.exe",
            "dwm.exe",
            "explorer", // no .exe
            "notepad.exe",
        ] {
            assert_eq!(imitates(name), None, "{name}");
        }
    }

    #[test]
    fn splits_quoted_arguments() {
        assert_eq!(
            crate::cmdline::split_args(
                r#"powershell -wd "c:\program files\x" -c "get-date; exit""#
            ),
            [
                "powershell",
                "-wd",
                r"c:\program files\x",
                "-c",
                "get-date; exit"
            ]
        );
        assert_eq!(crate::cmdline::split_args("a  b"), ["a", "b"]);
        assert_eq!(crate::cmdline::split_args(r#"a """#), ["a", ""]);
    }

    #[test]
    fn encoded_flags() {
        for yes in [
            "powershell.exe -NoProfile -EncodedCommand UwB0AGEA",
            "powershell -enc UwB0AGEA",
            "powershell -e UwB0AGEA",
            "powershell -ec UwB0AGEA",
            "pwsh /enc UwB0AGEA",
            "powershell -w hidden -c \"iex (New-Object Net.WebClient).DownloadString('x')\"",
            "powershell -WindowStyle Hidden -Command IEX $x",
            "powershell -NoP -W Hidden -C \"[Convert]::FromBase64String($s)\"",
            // Value-taking flags before -EncodedCommand (the common form).
            "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand UwB0AGEA",
            "powershell -ep bypass -enc UwB0AGEA",
            "powershell -Version 5.1 -NonInteractive -e UwB0AGEA",
            r#"powershell -WorkingDirectory "C:\Program Files\x" -ec UwB0AGEA"#,
        ] {
            assert!(encoded_powershell(yes), "{yes}");
        }
        for no in [
            r#"powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\Vendor\x.ps1""#,
            "powershell -ex bypass -file x.ps1",
            "powershell -NoProfile -Command Get-Date",
            "powershell -w hidden -File C:\\tools\\backup.ps1",
            "powershell -NonInteractive -c \"Write-Output 'iexplore'\"",
            // After -File, flags belong to the script.
            "powershell -File x.ps1 -e foo",
            "powershell -NoProfile -File C:\\tools\\run.ps1 -enc data",
            // A hidden window running iexplore or iexpress isn't iex.
            "powershell -w hidden -c Start-Process iexplore.exe",
            "powershell -WindowStyle Hidden -Command iexpress /n x.sed",
            // iex in the script's own arguments isn't PowerShell running it.
            "powershell -w hidden -File update.ps1 iex",
            // -ex takes its value; nothing after it is encoded.
            "powershell -ex bypass -noprofile -file x.ps1 -enc y",
            r#"powershell -WorkingDirectory "C:\Program Files\Vendor" -File run.ps1"#,
        ] {
            assert!(!encoded_powershell(no), "{no}");
        }
    }
}
