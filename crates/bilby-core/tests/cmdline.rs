//! Command-line to target resolution. Runs on any OS.

use std::collections::BTreeMap;

use bilby_core::cmdline::{Host, resolve};
use bilby_core::paths::KnownFolders;

fn env() -> KnownFolders {
    KnownFolders {
        system_root: r"C:\Windows".into(),
        system32: r"C:\Windows\System32".into(),
        syswow64: Some(r"C:\Windows\SysWOW64".into()),
        program_files: r"C:\Program Files".into(),
        program_files_x86: Some(r"C:\Program Files (x86)".into()),
        program_data: r"C:\ProgramData".into(),
        profile: r"C:\Users\Alex".into(),
        roaming_app_data: r"C:\Users\Alex\AppData\Roaming".into(),
        local_app_data: r"C:\Users\Alex\AppData\Local".into(),
        user_program_files: r"C:\Users\Alex\AppData\Local\Programs".into(),
        temp: r"C:\Users\Alex\AppData\Local\Temp".into(),
        downloads: r"C:\Users\Alex\Downloads".into(),
        desktop: r"C:\Users\Alex\Desktop".into(),
        documents: r"C:\Users\Alex\Documents".into(),
        public: r"C:\Users\Public".into(),
        removable_drives: vec![],
        network_drives: vec![],
        env: BTreeMap::from([("ONEDRIVE".into(), r"C:\Users\Alex\OneDrive".into())]),
    }
}

/// Files that "exist" for the CreateProcess-style search.
fn exists(path: &str) -> bool {
    [
        r"C:\Program Files\Foo\bar.exe",
        r"C:\Program Files (x86)\Steam\steam.exe",
        r"C:\Program Files\My App.exe",
    ]
    .iter()
    .any(|p| p.eq_ignore_ascii_case(path))
}

struct Case {
    cmd: &'static str,
    target: &'static str,
    args: &'static str,
    via: Option<Host>,
}

const fn c(cmd: &'static str, target: &'static str, args: &'static str, via: Option<Host>) -> Case {
    Case {
        cmd,
        target,
        args,
        via,
    }
}

// One long table reads better than many small tests.
#[allow(clippy::too_many_lines)]
#[test]
fn resolution_table() {
    use Host::{Cmd, Explorer, Mshta, Msiexec, PowerShell, Regsvr32, Rundll32, ScriptHost};
    let cases = [
        // Quoted program.
        c(
            r#""C:\Program Files\App\app.exe" --background"#,
            r"C:\Program Files\App\app.exe",
            "--background",
            None,
        ),
        c(
            r#""C:\Program Files\App\app.exe""#,
            r"C:\Program Files\App\app.exe",
            "",
            None,
        ),
        c(
            r#""C:\Program Files\App\app.exe"--x"#,
            r"C:\Program Files\App\app.exe",
            "--x",
            None,
        ),
        c(r#""C:\Unclosed\app.exe"#, r"C:\Unclosed\app.exe", "", None),
        // Unquoted with spaces, CreateProcess style.
        c(
            r"C:\Program Files\Foo\bar.exe -x",
            r"C:\Program Files\Foo\bar.exe",
            "-x",
            None,
        ),
        c(
            r"C:\Program Files (x86)\Steam\steam.exe -silent",
            r"C:\Program Files (x86)\Steam\steam.exe",
            "-silent",
            None,
        ),
        c(
            r"C:\Program Files\My App.exe /start",
            r"C:\Program Files\My App.exe",
            "/start",
            None,
        ),
        // Doesn't exist: first prefix that looks runnable.
        c(
            r"C:\Program Files\Other\tool.exe /q",
            r"C:\Program Files\Other\tool.exe",
            "/q",
            None,
        ),
        c(r"C:\Tools\run.bat now", r"C:\Tools\run.bat", "now", None),
        c(r"C:\Tools\run.cmd", r"C:\Tools\run.cmd", "", None),
        c(r"C:\Tools\noext arg", r"C:\Tools\noext", "arg", None),
        // Environment variables.
        c(
            r"%windir%\system32\SecurityHealthSystray.exe",
            r"C:\Windows\system32\SecurityHealthSystray.exe",
            "",
            None,
        ),
        c(
            r#""%LOCALAPPDATA%\Microsoft\OneDrive\OneDrive.exe" /background"#,
            r"C:\Users\Alex\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
            "/background",
            None,
        ),
        c(
            r"%LocalAppData%\Microsoft\OneDrive\OneDrive.exe /background",
            r"C:\Users\Alex\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
            "/background",
            None,
        ),
        c(
            r"%OneDrive%\x.exe",
            r"C:\Users\Alex\OneDrive\x.exe",
            "",
            None,
        ),
        c(r"%UNKNOWN%\x.exe", r"%UNKNOWN%\x.exe", "", None),
        c(r"C:\50%\x.exe", r"C:\50%\x.exe", "", None),
        // Bare names go to System32.
        c("ctfmon.exe", r"C:\Windows\System32\ctfmon.exe", "", None),
        c("ctfmon", r"C:\Windows\System32\ctfmon.exe", "", None),
        c(
            "  notepad.exe   file.txt",
            r"C:\Windows\System32\notepad.exe",
            "file.txt",
            None,
        ),
        // rundll32.
        c(
            r"rundll32.exe C:\Users\Alex\AppData\Roaming\x.dll,Start",
            r"C:\Users\Alex\AppData\Roaming\x.dll",
            ",Start",
            Some(Rundll32),
        ),
        c(
            r#"rundll32.exe "C:\Program Files\App\a b.dll",Run arg"#,
            r"C:\Program Files\App\a b.dll",
            ",Run arg",
            Some(Rundll32),
        ),
        c(
            r"C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL",
            r"C:\Windows\System32\shell32.dll",
            ",Control_RunDLL",
            Some(Rundll32),
        ),
        c(
            r"rundll32 x.dll,#1",
            r"C:\Windows\System32\x.dll",
            ",#1",
            Some(Rundll32),
        ),
        c(
            r"RUNDLL32.EXE %TEMP%\a.dll, Go",
            r"C:\Users\Alex\AppData\Local\Temp\a.dll",
            ", Go",
            Some(Rundll32),
        ),
        // cmd /c, recursing.
        c(
            r"cmd.exe /c C:\Users\Alex\AppData\Local\Temp\a.bat",
            r"C:\Users\Alex\AppData\Local\Temp\a.bat",
            "",
            Some(Cmd),
        ),
        c(
            r#"cmd /c "C:\Program Files\App\app.exe" -x"#,
            r"C:\Program Files\App\app.exe",
            "-x",
            Some(Cmd),
        ),
        c(
            r#"cmd.exe /q /c "start /min x.exe""#,
            // `start` is a cmd built-in; reported as a bare name like any
            // other. The rules only care about targets they can check.
            r"C:\Windows\System32\start.exe",
            "/min x.exe",
            Some(Cmd),
        ),
        c(
            r"cmd /k echo hi",
            r"C:\Windows\System32\echo.exe",
            "hi",
            Some(Cmd),
        ),
        c(
            r"cmd.exe /c rundll32.exe C:\x\y.dll,Go",
            r"C:\x\y.dll",
            ",Go",
            Some(Rundll32),
        ),
        c(
            r"cmd.exe /c powershell -File C:\s\a.ps1",
            r"C:\s\a.ps1",
            "",
            Some(PowerShell),
        ),
        c(r"cmd.exe", r"C:\Windows\System32\cmd.exe", "", None),
        // PowerShell.
        c(
            r"powershell.exe -NoProfile -File C:\Scripts\start.ps1 -Quiet",
            r"C:\Scripts\start.ps1",
            "-Quiet",
            Some(PowerShell),
        ),
        c(
            r#"powershell -ExecutionPolicy Bypass -File "C:\Program Files\V\x.ps1""#,
            r"C:\Program Files\V\x.ps1",
            "",
            Some(PowerShell),
        ),
        c(
            r"pwsh.exe -f x.ps1",
            r"C:\Windows\System32\x.ps1",
            "",
            Some(PowerShell),
        ),
        c(
            r"powershell.exe -NoProfile -EncodedCommand UwB0AGEA",
            r"C:\Windows\System32\powershell.exe",
            "",
            Some(PowerShell),
        ),
        c(
            r#"powershell -Command "Start-Sleep 1""#,
            r"C:\Windows\System32\powershell.exe",
            "",
            Some(PowerShell),
        ),
        // Script hosts.
        c(
            r"wscript.exe C:\Users\Alex\AppData\Roaming\a.vbs",
            r"C:\Users\Alex\AppData\Roaming\a.vbs",
            "",
            Some(ScriptHost),
        ),
        c(
            r#"wscript.exe //B //Nologo "C:\Users\Alex\a b.js" x"#,
            r"C:\Users\Alex\a b.js",
            "x",
            Some(ScriptHost),
        ),
        c(
            r"cscript //E:jscript C:\x\y.txt",
            r"C:\x\y.txt",
            "",
            Some(ScriptHost),
        ),
        // mshta.
        c(
            r"mshta.exe https://example.test/a.hta",
            "https://example.test/a.hta",
            "",
            Some(Mshta),
        ),
        c(
            r#"mshta.exe "javascript:close()""#,
            "javascript:close()",
            "",
            Some(Mshta),
        ),
        c(r"mshta.exe C:\x\a.hta", r"C:\x\a.hta", "", Some(Mshta)),
        // regsvr32.
        c(
            r"regsvr32.exe /s /n /u /i:https://example.test/a.sct scrobj.dll",
            "https://example.test/a.sct",
            "scrobj.dll",
            Some(Regsvr32),
        ),
        c(r"regsvr32 /s C:\x\y.dll", r"C:\x\y.dll", "", Some(Regsvr32)),
        // msiexec.
        c(
            r#"msiexec.exe /i "C:\Users\Alex\Downloads\setup.msi" /qn"#,
            r"C:\Users\Alex\Downloads\setup.msi",
            "",
            Some(Msiexec),
        ),
        c(
            r"msiexec /fa {GUID}",
            r"C:\Windows\System32\msiexec.exe",
            "/fa {GUID}",
            None,
        ),
        // explorer.
        c(
            r"explorer.exe C:\Users\Alex\Desktop\a.lnk",
            r"C:\Users\Alex\Desktop\a.lnk",
            "",
            Some(Explorer),
        ),
        c(
            r"explorer.exe /select,C:\x",
            r"C:\Windows\System32\explorer.exe",
            r"/select,C:\x",
            None,
        ),
        c(
            r"explorer.exe",
            r"C:\Windows\System32\explorer.exe",
            "",
            None,
        ),
        // Forward slashes are kept as written.
        c(r"C:/Tools/x.exe -a", "C:/Tools/x.exe", "-a", None),
    ];
    let env = env();
    let mut failures = Vec::new();
    for case in &cases {
        let r = resolve(case.cmd, &env, &exists);
        if r.target != case.target || r.args != case.args || r.via != case.via {
            failures.push(format!(
                "{}\n   want {:?} {:?} {:?}\n   got  {:?} {:?} {:?}",
                case.cmd, case.target, case.args, case.via, r.target, r.args, r.via
            ));
        }
    }
    assert!(cases.len() >= 40, "issue #9 asks for at least 40 cases");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn powershell_host_args_are_kept() {
    let r = resolve(
        "powershell.exe -NoProfile -EncodedCommand UwB0AGEA",
        &env(),
        &exists,
    );
    assert_eq!(r.host_args, "-NoProfile -EncodedCommand UwB0AGEA");
}

#[test]
fn deep_cmd_nesting_stops() {
    let cmd = "cmd /c cmd /c cmd /c cmd /c cmd /c cmd /c cmd /c x.exe";
    let r = resolve(cmd, &env(), &exists);
    assert_eq!(r.via, Some(Host::Cmd));
}
