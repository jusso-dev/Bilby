//! Path classification cases. Runs on any OS: the folders are filled in by
//! hand to look like a typical Windows 11 install.

use std::collections::BTreeMap;

use bilby_core::paths::{KnownFolders, classify, normalise};
use bilby_core::snapshot::PathClass::{
    self, Desktop, Documents, Downloads, Network, Other, ProgramData, ProgramFiles, Public,
    RecycleBin, Removable, Temp, UserAppData, UserAppPrograms, Windows, WindowsApps, WindowsSystem,
};

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
        // OneDrive folder backup moves these, so test a moved Documents.
        downloads: r"C:\Users\Alex\Downloads".into(),
        desktop: r"C:\Users\Alex\Desktop".into(),
        documents: r"C:\Users\Alex\OneDrive\Documents".into(),
        public: r"C:\Users\Public".into(),
        removable_drives: vec!["e:".into()],
        network_drives: vec!["z:".into()],
        env: BTreeMap::from([("CUSTOMTOOLS".into(), r"D:\Tools".into())]),
    }
}

// One long table reads better than several short ones.
#[allow(clippy::too_many_lines)]
#[test]
fn classification_table() {
    let cases: &[(&str, PathClass, bool)] = &[
        // Windows' own folders.
        (r"C:\Windows\System32\svchost.exe", WindowsSystem, false),
        (r"C:\Windows\SysWOW64\cmd.exe", WindowsSystem, false),
        (
            r"C:\Windows\WinSxS\amd64_microsoft-windows-foo\bar.dll",
            WindowsSystem,
            false,
        ),
        (
            r"C:\Windows\System32\drivers\etc\hosts",
            WindowsSystem,
            false,
        ),
        (r"\SystemRoot\System32\drivers\x.sys", WindowsSystem, false),
        (r"System32\drivers\acpi.sys", WindowsSystem, false),
        (r"\??\C:\Windows\System32\csrss.exe", WindowsSystem, false),
        (r"\\?\C:\Windows\System32\lsass.exe", WindowsSystem, false),
        (r"%SystemRoot%\system32\conhost.exe", WindowsSystem, false),
        (r"%windir%\System32\rundll32.exe", WindowsSystem, false),
        (r"C:\WINDOWS\SYSTEM32\SVCHOST.EXE", WindowsSystem, false),
        (r"c:/windows/system32/svchost.exe", WindowsSystem, false),
        (r"C:\Windows\explorer.exe", Windows, false),
        (r"C:\Windows\Temp\setup.exe", Temp, true),
        // A folder whose name only starts like System32 isn't System32.
        (r"C:\Windows\System32x\evil.exe", Windows, false),
        (r"C:\Windows\System32\..\explorer.exe", Windows, false),
        // Program Files.
        (
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            ProgramFiles,
            false,
        ),
        (
            r"C:\Program Files (x86)\Steam\steam.exe",
            ProgramFiles,
            false,
        ),
        (r"%ProgramFiles%\7-Zip\7z.exe", ProgramFiles, false),
        (
            r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.0\wt.exe",
            WindowsApps,
            false,
        ),
        (r"C:\Program Files Evil\x.exe", Other, false),
        // ProgramData: only the root is user-writable.
        (r"C:\ProgramData\dropper.exe", ProgramData, true),
        (
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
            ProgramData,
            false,
        ),
        // Per-user folders.
        (r"C:\Users\Alex\Downloads\setup.exe", Downloads, true),
        (r"C:\Users\Alex\Desktop\game.exe", Desktop, true),
        (
            r"C:\Users\Alex\OneDrive\Documents\macro.docm",
            Documents,
            true,
        ),
        (r"C:\Users\Alex\AppData\Local\Temp\updater.exe", Temp, true),
        (r"%TEMP%\scvhost.exe", Temp, true),
        (r"%TMP%\x.exe", Temp, true),
        (
            r"%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe",
            UserAppPrograms,
            true,
        ),
        (
            r"C:\Users\Alex\AppData\Local\Microsoft\Teams\current\Teams.exe",
            UserAppPrograms,
            true,
        ),
        (
            r"C:\Users\Alex\AppData\Local\Google\Chrome\Application\chrome.exe",
            UserAppPrograms,
            true,
        ),
        (
            r"C:\Users\Alex\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk",
            UserAppData,
            true,
        ),
        (r"%APPDATA%\SomeApp\helper.exe", UserAppData, true),
        (
            r"C:\Users\Alex\AppData\Local\Packages\x\y.exe",
            UserAppData,
            true,
        ),
        (r"C:\Users\Public\Libraries\x.exe", Public, true),
        // The profile itself isn't any special folder.
        (r"C:\Users\Alex\tool.exe", Other, false),
        // .. tricks.
        (
            r"C:\Windows\System32\..\..\Users\Alex\Downloads\a.exe",
            Downloads,
            true,
        ),
        (
            r"C:\Users\Alex\Downloads\..\..\..\..\..\Windows\notepad.exe",
            Windows,
            false,
        ),
        (r"C:\Users\Alex\.\Downloads\.\a.exe", Downloads, true),
        // Recycle Bin on any drive.
        (r"C:\$Recycle.Bin\S-1-5-21-1\$R1234.exe", RecycleBin, true),
        (r"D:\$RECYCLE.BIN\x.exe", RecycleBin, true),
        // Removable and network.
        (r"E:\autorun.exe", Removable, true),
        (r"Z:\share\tool.exe", Network, false),
        (r"\\fileserver\share\tool.exe", Network, false),
        (r"\\?\UNC\fileserver\share\tool.exe", Network, false),
        // Other.
        (r"D:\Games\game.exe", Other, false),
        (r"%CUSTOMTOOLS%\x.exe", Other, false),
        (r"%NOTSET%\x.exe", Other, false),
        // Quotes around a path, as in many registry values.
        (r#""C:\Program Files\App\app.exe""#, ProgramFiles, false),
    ];
    let env = env();
    let mut failures = Vec::new();
    for (path, class, writable) in cases {
        let got = classify(path, &env);
        if got.class != *class || got.user_writable != *writable {
            failures.push(format!(
                "{path}: expected {class:?}/{writable}, got {:?}/{} ({})",
                got.class, got.user_writable, got.normalised
            ));
        }
    }
    assert!(cases.len() >= 30, "issue #6 asks for at least 30 cases");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn normalise_examples() {
    let env = env();
    assert_eq!(
        normalise(r"\??\C:\Windows\System32\x.dll", &env),
        r"c:\windows\system32\x.dll"
    );
    assert_eq!(
        normalise(r"\SystemRoot\system32\drivers\x.sys", &env),
        r"c:\windows\system32\drivers\x.sys"
    );
    assert_eq!(normalise(r"C:\a\b\..\..\..\c", &env), r"c:\c");
    assert_eq!(normalise(r"\\srv\share\..\..\x", &env), r"\\srv\share\x");
    assert_eq!(normalise(r"%customtools%\x", &env), r"d:\tools\x");
    // Windows ignores trailing dots and spaces in names.
    assert_eq!(
        normalise(r"C:\Windows\System32. \svchost.exe", &env),
        r"c:\windows\system32\svchost.exe"
    );
    // An unclosed % is left alone.
    assert_eq!(normalise(r"C:\50%\x", &env), r"c:\50%\x");
}

#[test]
fn no_syswow64_on_32_bit() {
    let mut env = env();
    env.syswow64 = None;
    env.program_files_x86 = None;
    assert_eq!(classify(r"C:\Windows\SysWOW64\x.exe", &env).class, Windows);
    assert_eq!(classify(r"C:\Program Files (x86)\x.exe", &env).class, Other);
}
