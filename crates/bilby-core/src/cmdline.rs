//! Works out which file a startup command actually runs. Pure string work,
//! so it's tested on any OS. The Windows collector checks the file it finds.
//!
//! Follows how Windows itself reads a command line: a quoted first token is
//! the program; an unquoted one with spaces is tried prefix by prefix, the
//! way `CreateProcess` does; bare names live in System32. Script hosts and
//! loaders (`rundll32`, `cmd /c`, `powershell -File`, `wscript`, `mshta`,
//! `regsvr32`, `msiexec`, `explorer`) are looked through to the file they
//! run, and the host is recorded.

use crate::paths::KnownFolders;

/// A program that runs something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// `rundll32.exe <dll>,<entry>`.
    Rundll32,
    /// `cmd.exe /c <command>`.
    Cmd,
    /// `powershell.exe` or `pwsh.exe`.
    PowerShell,
    /// `wscript.exe` or `cscript.exe`.
    ScriptHost,
    /// `mshta.exe <url or file>`.
    Mshta,
    /// `regsvr32.exe`, with `/i:<url>` it can run remote scripts.
    Regsvr32,
    /// `msiexec.exe`.
    Msiexec,
    /// `explorer.exe <file>`.
    Explorer,
}

/// What a command line runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The file that runs (or, for `mshta` and `regsvr32 /i:`, the URL).
    pub target: String,
    /// Arguments after the target, as written.
    pub args: String,
    /// The outermost host the command went through, if any.
    pub via: Option<Host>,
    /// Arguments given to the host itself (for PowerShell, its flags).
    pub host_args: String,
}

/// Extensions `CreateProcess`-style resolution stops at.
const RUNNABLE: &[&str] = &[".exe", ".com", ".bat", ".cmd"];

/// Resolves a command line. `env` supplies `%VAR%` values and System32 for
/// bare names. `exists` says whether a path is a file, so unquoted paths
/// with spaces can be tried the way Windows tries them; pass `|_| false`
/// when that can't be checked and the first runnable-looking prefix wins.
pub fn resolve(cmd: &str, env: &KnownFolders, exists: &dyn Fn(&str) -> bool) -> Resolved {
    resolve_depth(cmd, env, exists, 0)
}

fn resolve_depth(
    cmd: &str,
    env: &KnownFolders,
    exists: &dyn Fn(&str) -> bool,
    depth: u8,
) -> Resolved {
    let expanded = expand(cmd.trim(), env);
    let (program, rest) = first_program(&expanded, exists);
    let program = qualify(&program, env);
    let name = file_name(&program).to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    let plain = || Resolved {
        target: program.clone(),
        args: rest.to_owned(),
        via: None,
        host_args: String::new(),
    };
    // Don't recurse forever on cmd /c cmd /c cmd /c ... The deepest level
    // reports what it is without looking further.
    if depth > 4 {
        return plain();
    }
    // Only look through a host that's Windows' own copy. A `cmd.exe` in
    // AppData isn't cmd: it's an unknown program, and it's what runs, so
    // it must be the target the rules check.
    if !in_windows_folder(&program, env) {
        return plain();
    }
    let found = match name {
        "rundll32" => Some(rundll32(rest, env)),
        "cmd" => cmd_inner(rest).map(|inner| {
            let r = resolve_depth(inner, env, exists, depth + 1);
            // A command cmd runs directly keeps cmd as its host; one that
            // goes through another host reports that one.
            Resolved {
                via: Some(r.via.unwrap_or(Host::Cmd)),
                ..r
            }
        }),
        "powershell" | "pwsh" => Some(powershell(&program, rest, env)),
        "wscript" | "cscript" => Some(script_host(rest, env)),
        "mshta" => Some(mshta(rest, env)),
        "regsvr32" => Some(regsvr32(rest, env)),
        "msiexec" => msiexec(rest, env),
        "explorer" => explorer(rest, env),
        _ => None,
    };
    found.unwrap_or_else(plain)
}

fn hosted(target: String, args: String, host: Host, host_args: String) -> Resolved {
    Resolved {
        target,
        args,
        via: Some(host),
        host_args,
    }
}

/// `rundll32.exe <dll>,<entry> [args]`.
fn rundll32(rest: &str, env: &KnownFolders) -> Resolved {
    let (dll, after) = split_first(rest);
    let (dll, entry) = match dll.split_once(',') {
        Some((d, e)) => (d.to_owned(), format!(",{e} {after}").trim().to_owned()),
        None => (dll.trim_end_matches(',').to_owned(), after.to_owned()),
    };
    hosted(qualify(&dll, env), entry, Host::Rundll32, String::new())
}

/// The command after `cmd /c` or `/k`, possibly with other switches first.
/// cmd strips one pair of quotes around the whole command.
fn cmd_inner(rest: &str) -> Option<&str> {
    let lower = rest.to_ascii_lowercase();
    let i = ["/c ", "/k ", "/c\"", "/k\""]
        .iter()
        .filter_map(|s| lower.find(s))
        .min()?;
    Some(strip_outer_quotes(rest[i + 2..].trim()))
}

/// `powershell -File <script>` targets the script; anything else (including
/// `-Command` and `-EncodedCommand`) targets PowerShell with its flags kept.
fn powershell(program: &str, rest: &str, env: &KnownFolders) -> Resolved {
    let args = split_args(rest);
    for (i, arg) in args.iter().enumerate() {
        let a = arg.to_ascii_lowercase();
        let flag = a.trim_start_matches(['-', '/']);
        // `-f` is how PowerShell itself abbreviates -File.
        if a.len() > flag.len() && !flag.is_empty() && "file".starts_with(flag) {
            let script = args.get(i + 1).cloned().unwrap_or_default();
            let after = args.get(i + 2..).map(|r| r.join(" ")).unwrap_or_default();
            return hosted(
                qualify(&script, env),
                after,
                Host::PowerShell,
                args[..i].join(" "),
            );
        }
    }
    hosted(
        program.to_owned(),
        String::new(),
        Host::PowerShell,
        rest.to_owned(),
    )
}

/// `wscript`/`cscript`, skipping `//B`, `//Nologo`, `//E:jscript` and so on.
fn script_host(rest: &str, env: &KnownFolders) -> Resolved {
    let mut tail = rest;
    loop {
        let (tok, after) = split_first(tail);
        if tok.starts_with("//") && !after.is_empty() {
            tail = after;
        } else {
            return hosted(
                qualify(&tok, env),
                after.to_owned(),
                Host::ScriptHost,
                String::new(),
            );
        }
    }
}

/// `mshta <url or file>`.
fn mshta(rest: &str, env: &KnownFolders) -> Resolved {
    let (what, after) = split_first(rest);
    let target = if is_url(&what) {
        what
    } else {
        qualify(&what, env)
    };
    hosted(target, after.to_owned(), Host::Mshta, String::new())
}

/// `regsvr32 [/s] [/i:<url>] <dll>`. With `/i:` the URL is the target,
/// because that's what runs.
fn regsvr32(rest: &str, env: &KnownFolders) -> Resolved {
    let args = split_args(rest);
    let url = args.iter().find_map(|a| {
        let lower = a.to_ascii_lowercase();
        (lower.starts_with("/i:") || lower.starts_with("-i:")).then(|| a[3..].to_owned())
    });
    let dll = args
        .iter()
        .rev()
        .find(|a| !a.starts_with('/') && !a.starts_with('-'))
        .cloned()
        .unwrap_or_default();
    match url {
        Some(u) => hosted(u, dll, Host::Regsvr32, rest.to_owned()),
        None => hosted(
            qualify(&dll, env),
            String::new(),
            Host::Regsvr32,
            rest.to_owned(),
        ),
    }
}

/// `msiexec /i <package>` (and /x, /p, /f). Other forms run msiexec itself.
fn msiexec(rest: &str, env: &KnownFolders) -> Option<Resolved> {
    let args = split_args(rest);
    let package = args.windows(2).find_map(|w| {
        let f = w[0].to_ascii_lowercase();
        matches!(
            f.as_str(),
            "/i" | "/x" | "/p" | "/f" | "-i" | "-x" | "/package"
        )
        .then(|| w[1].clone())
    })?;
    Some(hosted(
        qualify(&package, env),
        String::new(),
        Host::Msiexec,
        rest.to_owned(),
    ))
}

/// `explorer.exe <file>` opens the file. Switches like `/select` and
/// `shell:` folders aren't files.
fn explorer(rest: &str, env: &KnownFolders) -> Option<Resolved> {
    if rest.is_empty() {
        return None;
    }
    let (what, after) = split_first(rest);
    if what.starts_with('/') || what.starts_with("shell:") {
        return None;
    }
    Some(hosted(
        qualify(&what, env),
        after.to_owned(),
        Host::Explorer,
        String::new(),
    ))
}

/// Splits a command line into arguments, keeping `"double quoted"` values
/// together the way Windows does, so `-WorkingDirectory "C:\Program Files"`
/// is one flag and one value.
pub fn split_args(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut current));
                    any = false;
                }
            }
            c => {
                current.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(current);
    }
    out
}

/// Expands `%VAR%`, keeping the case of everything else. Unknown variables
/// are left as written.
fn expand(cmd: &str, env: &KnownFolders) -> String {
    let mut out = String::with_capacity(cmd.len());
    let mut rest = cmd;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let name = &after[..end];
        match lookup(name, env) {
            Some(value) if !name.is_empty() => out.push_str(&value),
            _ => {
                out.push('%');
                out.push_str(name);
                out.push('%');
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn lookup(name: &str, env: &KnownFolders) -> Option<String> {
    if let Some((_, v)) = env.env.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
        return Some(v.clone());
    }
    Some(
        match name.to_ascii_lowercase().as_str() {
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
        }
        .clone(),
    )
}

/// The program and the rest. Quoted: up to the closing quote. Unquoted with
/// spaces: the shortest prefix that ends in a runnable extension and exists,
/// then the shortest that ends in one, then the first word.
fn first_program<'a>(cmd: &'a str, exists: &dyn Fn(&str) -> bool) -> (String, &'a str) {
    if let Some(rest) = cmd.strip_prefix('"') {
        return match rest.find('"') {
            Some(end) => (rest[..end].to_owned(), rest[end + 1..].trim_start()),
            None => (rest.to_owned(), ""),
        };
    }
    let spaces: Vec<usize> = cmd
        .match_indices(' ')
        .map(|(i, _)| i)
        .chain([cmd.len()])
        .collect();
    let runnable = |s: &str| {
        let lower = s.to_ascii_lowercase();
        RUNNABLE.iter().any(|e| lower.ends_with(e))
    };
    let first = &cmd[..spaces[0]];
    // A first word that's already a program (`x.exe`) or a bare name
    // (`cmd`, `start`) is the program. Only a path whose first word stops
    // mid-folder (`C:\Program`) carries on past a space, as CreateProcess
    // does: a prefix that exists first, then the shortest runnable one.
    let is_path = first.contains(['\\', '/']) || first.get(1..2) == Some(":");
    if is_path && !runnable(first) {
        for want_exists in [true, false] {
            for &end in &spaces {
                let candidate = &cmd[..end];
                if runnable(candidate) && (!want_exists || exists(candidate)) {
                    return (candidate.to_owned(), cmd[end..].trim_start());
                }
            }
        }
    }
    let end = spaces[0];
    (cmd[..end].to_owned(), cmd[end..].trim_start())
}

/// First argument (honouring quotes) and the rest.
fn split_first(s: &str) -> (String, &str) {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('"') {
        match rest.find('"') {
            Some(end) => (rest[..end].to_owned(), rest[end + 1..].trim_start()),
            None => (rest.to_owned(), ""),
        }
    } else {
        match s.find(char::is_whitespace) {
            Some(i) => (s[..i].to_owned(), s[i..].trim_start()),
            None => (s.to_owned(), ""),
        }
    }
}

fn strip_outer_quotes(s: &str) -> &str {
    if s.len() >= 2
        && s.starts_with('"')
        && s.ends_with('"')
        && s[1..s.len() - 1].matches('"').count() % 2 == 1
    {
        // `"a" "b"`: the outer pair isn't one pair, leave it.
        return s;
    }
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') && !s[1..s.len() - 1].contains('"') {
        return &s[1..s.len() - 1];
    }
    s
}

/// Is `path` directly in `System32`, `SysWOW64` or the Windows folder itself
/// (where `explorer.exe` lives), or in their `WindowsPowerShell` folders?
fn in_windows_folder(path: &str, env: &KnownFolders) -> bool {
    let n = crate::paths::normalise(path, env);
    let Some((dir, _)) = n.rsplit_once('\\') else {
        return false;
    };
    let root = crate::paths::normalise(&env.system_root, env);
    let mut trusted = vec![root.clone(), crate::paths::normalise(&env.system32, env)];
    if let Some(wow) = &env.syswow64 {
        trusted.push(crate::paths::normalise(wow, env));
    }
    let powershell: Vec<String> = trusted
        .iter()
        .skip(1)
        .map(|d| format!(r"{d}\windowspowershell\v1.0"))
        .collect();
    trusted.extend(powershell);
    // PowerShell 7 installs under Program Files.
    trusted.push(format!(
        r"{}\powershell\7",
        crate::paths::normalise(&env.program_files, env)
    ));
    trusted.iter().any(|t| *t == dir)
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn is_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    [
        "http://",
        "https://",
        "javascript:",
        "vbscript:",
        "about:",
        "ftp://",
    ]
    .iter()
    .any(|p| lower.starts_with(p))
}

/// Puts a bare name (`rundll32.exe`, `x.dll`) in System32, as Windows'
/// search finds them there first. Paths are left alone.
fn qualify(name: &str, env: &KnownFolders) -> String {
    let name = name.trim().trim_matches('"');
    if name.is_empty() || name.contains(['\\', '/', ':']) || is_url(name) {
        return name.to_owned();
    }
    let with_ext = if name.contains('.') {
        name.to_owned()
    } else {
        format!("{name}.exe")
    };
    format!(r"{}\{with_ext}", env.system32.trim_end_matches('\\'))
}
