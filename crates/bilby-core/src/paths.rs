//! Path normalisation and classification. Pure string work, so it runs and
//! is tested on any OS. The Windows collector fills [`KnownFolders`] from the
//! real system; tests fill it by hand.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::snapshot::PathClass;

/// The folders classification depends on, as resolved on one computer.
/// Paths can be in any case and use either slash; they're normalised before
/// use.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownFolders {
    /// `%SystemRoot%`, for example `C:\Windows`.
    pub system_root: String,
    /// `System32`.
    pub system32: String,
    /// `SysWOW64`, absent on 32-bit Windows.
    #[serde(default)]
    pub syswow64: Option<String>,
    /// `C:\Program Files`.
    pub program_files: String,
    /// `C:\Program Files (x86)`, absent on 32-bit Windows.
    #[serde(default)]
    pub program_files_x86: Option<String>,
    /// `C:\ProgramData`.
    pub program_data: String,
    /// The user profile, `C:\Users\<name>`.
    pub profile: String,
    /// `%APPDATA%` (Roaming).
    pub roaming_app_data: String,
    /// `%LOCALAPPDATA%`.
    pub local_app_data: String,
    /// `%LOCALAPPDATA%\Programs`.
    pub user_program_files: String,
    /// `%TEMP%`.
    pub temp: String,
    /// Downloads.
    pub downloads: String,
    /// Desktop.
    pub desktop: String,
    /// Documents.
    pub documents: String,
    /// `C:\Users\Public`.
    pub public: String,
    /// Drive letters (lower case, with colon, for example `e:`) that are
    /// removable.
    #[serde(default)]
    pub removable_drives: Vec<String>,
    /// Drive letters that are mapped network drives.
    #[serde(default)]
    pub network_drives: Vec<String>,
    /// Environment variables for `%VAR%` expansion. Names are matched
    /// without regard to case.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// Known per-user app installs under `%LOCALAPPDATA%` that are installed the
/// same way as programs in Program Files, just per user. Relative to
/// `%LOCALAPPDATA%`, lower case.
const PER_USER_APP_INSTALLS: &[&str] = &[
    r"microsoft\teams",
    r"microsoft\onedrive",
    r"microsoft\windowsapps",
    r"microsoft\edge sxs\application",
    r"google\chrome\application",
    r"bravesoftware\brave-browser\application",
    r"mozilla firefox",
    r"discord",
    r"slack",
    r"zoom\bin",
    r"spotify",
];

/// A classified path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    /// The normalised, lower-case path that was classified.
    pub normalised: String,
    /// Its folder class.
    pub class: PathClass,
    /// Whether an ordinary user can write there.
    pub user_writable: bool,
}

/// Normalises a Windows path for comparison: strips `\\?\` and `\??\`, maps
/// `\SystemRoot\` and `%VAR%`, unifies slashes, resolves `.` and `..`
/// lexically, and lower-cases. UNC paths come out as `\\server\share\...`.
pub fn normalise(path: &str, env: &KnownFolders) -> String {
    let mut p = path.trim().trim_matches('"').replace('/', "\\");

    for prefix in [r"\\?\UNC\", r"\??\UNC\"] {
        if let Some(rest) = strip_prefix_ci(&p, prefix) {
            p = format!(r"\\{rest}");
        }
    }
    for prefix in [r"\\?\", r"\??\", r"\\.\"] {
        if let Some(rest) = strip_prefix_ci(&p, prefix) {
            p = rest.to_owned();
        }
    }
    if let Some(rest) = strip_prefix_ci(&p, r"\SystemRoot\") {
        p = format!(r"{}\{rest}", env.system_root);
    } else if let Some(rest) = strip_prefix_ci(&p, r"System32\") {
        // Driver image paths in the registry are often relative to SystemRoot.
        p = format!(r"{}\System32\{rest}", env.system_root);
    }
    p = expand_vars(&p, env).replace('/', "\\");

    let lower = p.to_lowercase();
    let (root, rest) = if let Some(unc) = lower.strip_prefix(r"\\") {
        (r"\\".to_owned(), unc.to_owned())
    } else if lower.len() >= 2 && lower.as_bytes()[1] == b':' {
        (lower[..2].to_owned(), lower[2..].to_owned())
    } else {
        (String::new(), lower)
    };

    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                // Never climb above the drive or the UNC server and share.
                let floor = if root == r"\\" { 2 } else { 0 };
                if parts.len() > floor {
                    parts.pop();
                }
            }
            other => parts.push(other.trim_end_matches(['.', ' '])),
        }
    }
    let joined = parts.join("\\");
    match root.as_str() {
        r"\\" => format!(r"\\{joined}"),
        "" => joined,
        drive => format!(r"{drive}\{joined}"),
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len()
        && s.is_char_boundary(prefix.len())
        && s[..prefix.len()].eq_ignore_ascii_case(prefix)
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Expands `%VAR%` using `env.env`, then the known folders. Unknown variables
/// are left as they are.
fn expand_vars(s: &str, env: &KnownFolders) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let name = &after[..end];
        if let Some(value) = lookup_var(name, env) {
            out.push_str(&value);
        } else {
            out.push('%');
            out.push_str(name);
            out.push('%');
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn lookup_var(name: &str, env: &KnownFolders) -> Option<String> {
    if let Some((_, v)) = env.env.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
        return Some(v.clone());
    }
    let known = match name.to_ascii_lowercase().as_str() {
        "systemroot" | "windir" => &env.system_root,
        "programfiles" => &env.program_files,
        "programfiles(x86)" => env.program_files_x86.as_ref()?,
        "programdata" | "allusersprofile" => &env.program_data,
        "userprofile" => &env.profile,
        "appdata" => &env.roaming_app_data,
        "localappdata" => &env.local_app_data,
        "temp" | "tmp" => &env.temp,
        "public" => &env.public,
        _ => return None,
    };
    Some(known.clone())
}

/// True if `path` is `dir` or inside it. Both must already be normalised.
fn within(path: &str, dir: &str) -> bool {
    !dir.is_empty()
        && (path == dir
            || (path.len() > dir.len()
                && path.starts_with(dir)
                && path.as_bytes()[dir.len()] == b'\\'))
}

/// Classifies a path. See [`PathClass`] for the classes. Most specific
/// folder wins, so Temp inside `%LOCALAPPDATA%` is Temp, not `UserAppData`.
pub fn classify(path: &str, env: &KnownFolders) -> Classified {
    let normalised = normalise(path, env);
    let n = |dir: &str| normalise(dir, env);
    let p = normalised.as_str();
    let program_data = n(&env.program_data);

    let class = classify_normalised(p, env, &n);
    // Files directly in the ProgramData root (not in a vendor folder) are
    // writable by ordinary users on default Windows installs.
    let program_data_root = class == PathClass::ProgramData
        && p.rsplit_once('\\')
            .is_some_and(|(parent, _)| parent == program_data);

    Classified {
        user_writable: class.user_writable() || program_data_root,
        class,
        normalised,
    }
}

fn classify_normalised(p: &str, env: &KnownFolders, n: &dyn Fn(&str) -> String) -> PathClass {
    if p.starts_with(r"\\") {
        return PathClass::Network;
    }
    let drive = p.get(..2).unwrap_or_default();
    if env
        .network_drives
        .iter()
        .any(|d| d.eq_ignore_ascii_case(drive))
    {
        return PathClass::Network;
    }
    if env
        .removable_drives
        .iter()
        .any(|d| d.eq_ignore_ascii_case(drive))
    {
        return PathClass::Removable;
    }
    if p.get(2..)
        .is_some_and(|rest| within(rest, r"\$recycle.bin"))
    {
        return PathClass::RecycleBin;
    }

    let root = n(&env.system_root);
    let system_dirs = [
        Some(n(&env.system32)),
        env.syswow64.as_deref().map(n),
        Some(format!(r"{root}\winsxs")),
        Some(format!(r"{root}\sysnative")),
    ];
    if system_dirs.iter().flatten().any(|d| within(p, d)) {
        return PathClass::WindowsSystem;
    }
    if within(p, &format!(r"{root}\temp")) || within(p, &n(&env.temp)) {
        return PathClass::Temp;
    }
    if within(p, &root) {
        return PathClass::Windows;
    }

    let program_files = [
        Some(n(&env.program_files)),
        env.program_files_x86.as_deref().map(n),
    ];
    if within(p, &format!(r"{}\windowsapps", n(&env.program_files))) {
        return PathClass::WindowsApps;
    }
    if program_files.iter().flatten().any(|d| within(p, d)) {
        return PathClass::ProgramFiles;
    }
    if within(p, &n(&env.program_data)) {
        return PathClass::ProgramData;
    }

    for (dir, class) in [
        (&env.downloads, PathClass::Downloads),
        (&env.desktop, PathClass::Desktop),
        (&env.documents, PathClass::Documents),
        (&env.public, PathClass::Public),
    ] {
        if within(p, &n(dir)) {
            return class;
        }
    }

    let local = n(&env.local_app_data);
    if within(p, &n(&env.user_program_files))
        || PER_USER_APP_INSTALLS
            .iter()
            .any(|app| within(p, &format!(r"{local}\{app}")))
    {
        return PathClass::UserAppPrograms;
    }
    if within(p, &local) || within(p, &n(&env.roaming_app_data)) {
        return PathClass::UserAppData;
    }
    PathClass::Other
}
