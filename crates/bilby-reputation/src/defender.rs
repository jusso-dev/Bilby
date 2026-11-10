//! "Ask Windows Security to check this file": a Defender custom scan of one
//! file, started only when the user presses the button on a finding.
//!
//! Runs `MpCmdRun.exe -Scan -ScanType 3 -File "<path>" -DisableRemediation`.
//! Bilby sends nothing itself; Defender's own cloud protection and sample
//! submission settings still apply. From Microsoft Learn, "Use the command
//! line to manage Microsoft Defender Antivirus" (checked 10-11-2026):
//!
//! - `MpCmdRun.exe` is newest in `%ProgramData%\Microsoft\Windows
//!   Defender\Platform\<version>`, with `%ProgramFiles%\Windows Defender`
//!   as the fallback.
//! - Return code 0: no malware found (or found and remediated, which can't
//!   happen with `-DisableRemediation`). 2: malware found, user action
//!   needed, **or scanning errors**. So 2 alone isn't a threat: Bilby only
//!   reports one when the output names it.
//! - `-DisableRemediation` applies no actions, writes no event log entries
//!   and shows nothing in Windows Security, and prints detections to the
//!   command output.

use std::path::{Path, PathBuf};

use bilby_core::snapshot::DefenderScanOutcome;

/// Picks `MpCmdRun.exe`: the highest-named version folder under
/// `platform_dir` that has one, else `program_files_dir`.
pub fn find_mpcmdrun(platform_dir: &Path, program_files_dir: &Path) -> Option<PathBuf> {
    let mut versions: Vec<PathBuf> = std::fs::read_dir(platform_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("MpCmdRun.exe").is_file())
        .collect();
    versions.sort_by_key(|p| version_key(p));
    versions.pop().map(|p| p.join("MpCmdRun.exe")).or_else(|| {
        let p = program_files_dir.join("MpCmdRun.exe");
        p.is_file().then_some(p)
    })
}

/// `4.18.25070.5-0` sorts by its numbers, not as text.
fn version_key(p: &Path) -> Vec<u64> {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .split(['.', '-'])
        .map(|s| s.parse().unwrap_or(0))
        .collect()
}

/// Turns `MpCmdRun` output and exit code into an outcome.
pub fn interpret(exit_code: Option<i32>, stdout: &str) -> DefenderScanOutcome {
    let threat = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("Threat").map(str::trim))
        .and_then(|rest| rest.strip_prefix(':').map(str::trim))
        .filter(|n| !n.is_empty())
        .map(str::to_owned);
    match (exit_code, threat) {
        (Some(_), Some(name)) => DefenderScanOutcome::Threat { name: Some(name) },
        (Some(0), None) => DefenderScanOutcome::Clean,
        (Some(2), None) => DefenderScanOutcome::Failed {
            reason: "exit code 2 with no threat named (scanning error)".to_owned(),
        },
        (Some(c), None) => DefenderScanOutcome::Failed {
            reason: format!("exit code {c}"),
        },
        (None, _) => DefenderScanOutcome::Failed {
            reason: "Windows Security's scanner was stopped".to_owned(),
        },
    }
}

/// Scans one file. Windows only; only called from the "Ask Windows
/// Security" button, never from the automatic scan.
#[cfg(windows)]
pub fn scan(path: &str) -> DefenderScanOutcome {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    let (Some(pd), Some(pf)) = (env("ProgramData"), env("ProgramFiles")) else {
        return DefenderScanOutcome::Failed {
            reason: "Windows folders not found".to_owned(),
        };
    };
    let Some(exe) = find_mpcmdrun(
        &pd.join(r"Microsoft\Windows Defender\Platform"),
        &pf.join("Windows Defender"),
    ) else {
        return DefenderScanOutcome::Failed {
            reason: "MpCmdRun.exe not found".to_owned(),
        };
    };
    match std::process::Command::new(exe)
        .args([
            "-Scan",
            "-ScanType",
            "3",
            "-File",
            path,
            "-DisableRemediation",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) => interpret(o.status.code(), &String::from_utf8_lossy(&o.stdout)),
        Err(e) => DefenderScanOutcome::Failed {
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_and_output() {
        assert_eq!(
            interpret(Some(0), "Scan starting...\nScan finished.\n"),
            DefenderScanOutcome::Clean
        );
        let found = "Scan starting...\nScan finished.\nScanning C:\\x\\a.exe found 1 threats.\n\
                     <===========================LIST OF DETECTED THREATS==========================>\n\
                     ----------------------------- Threat information ------------------------------\n\
                     Threat                  : Virus:DOS/EICAR_Test_File\n\
                     Resources               : 1 total\n";
        assert_eq!(
            interpret(Some(2), found),
            DefenderScanOutcome::Threat {
                name: Some("Virus:DOS/EICAR_Test_File".to_owned())
            }
        );
        // 2 without a named threat is a scanning error, not a threat.
        assert!(matches!(
            interpret(Some(2), "CmdTool: Failed with hr = 0x80508023"),
            DefenderScanOutcome::Failed { .. }
        ));
        assert!(matches!(
            interpret(None, ""),
            DefenderScanOutcome::Failed { .. }
        ));
        // "Threat information" heading isn't a threat name.
        assert_eq!(
            interpret(Some(0), "----- Threat information -----"),
            DefenderScanOutcome::Clean
        );
    }

    #[test]
    fn newest_platform_folder_wins() {
        let root = std::env::temp_dir().join(format!("bilby-mpcmdrun-{}", std::process::id()));
        let platform = root.join("Platform");
        let pf = root.join("PF");
        for v in ["4.18.2207.7-0", "4.18.25070.5-0", "4.18.9999.1-0"] {
            std::fs::create_dir_all(platform.join(v)).unwrap();
        }
        // 25070 is the highest version but has no MpCmdRun.exe; of the
        // folders that have one, 9999 is higher than 2207 by number.
        std::fs::write(platform.join("4.18.2207.7-0").join("MpCmdRun.exe"), b"").unwrap();
        std::fs::write(platform.join("4.18.9999.1-0").join("MpCmdRun.exe"), b"").unwrap();
        std::fs::create_dir_all(&pf).unwrap();
        std::fs::write(pf.join("MpCmdRun.exe"), b"").unwrap();
        assert_eq!(
            find_mpcmdrun(&platform, &pf),
            Some(platform.join("4.18.9999.1-0").join("MpCmdRun.exe"))
        );
        std::fs::remove_dir_all(&platform).unwrap();
        assert_eq!(find_mpcmdrun(&platform, &pf), Some(pf.join("MpCmdRun.exe")));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
