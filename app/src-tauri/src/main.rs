//! Bilby desktop app: a Tauri v2 window over Rust-rendered HTML screens.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod logging;
mod scan;
mod view;

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use bilby_core::demo::DemoKind;

/// What the command line asked for.
#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    /// `--demo <healthy|worth|attention>`.
    demo: Option<DemoKind>,
    /// `--dump-snapshot <file>`: collect, scrub, write JSON, exit.
    dump_snapshot: Option<String>,
    /// `--deep-check`: started elevated by "Check more deeply".
    deep_check: bool,
}

/// Reads the flags (`--flag value` or `--flag=value`). Anything else is
/// ignored.
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut out = Args::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n.to_owned(), Some(v.to_owned())),
            None => (arg.clone(), None),
        };
        match name.as_str() {
            "--demo" => {
                let kind = inline
                    .or_else(|| args.next())
                    .ok_or("--demo needs healthy, worth or attention")?;
                out.demo = Some(kind.parse()?);
            }
            "--dump-snapshot" => {
                let file = inline
                    .or_else(|| args.next())
                    .filter(|f| !f.is_empty())
                    .ok_or("--dump-snapshot needs a file name")?;
                out.dump_snapshot = Some(file);
            }
            "--deep-check" => out.deep_check = true,
            _ => {}
        }
    }
    Ok(out)
}

/// A scrubber for this computer's user name, computer name and profile.
fn scrubber() -> bilby_core::scrub::Scrubber {
    #[cfg(windows)]
    {
        bilby_collect_windows::scan::scrubber(&bilby_collect_windows::paths::known_folders())
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let user = std::env::var("USER").ok();
        let host = std::env::var("HOSTNAME").ok();
        bilby_core::scrub::Scrubber::new(&[home.as_str()], user.as_deref(), host.as_deref())
    }
}

/// `--dump-snapshot <file>`: runs every collector, scrubs the user name,
/// computer name, profile path and SIDs, and writes pretty JSON. Used for
/// fixtures and the clean baseline (docs/test-plan.md). Returns the exit
/// code.
#[cfg(windows)]
fn dump_snapshot(file: &str) -> i32 {
    use bilby_collect_windows::scan::{CollectOptions, collect};

    let began = std::time::Instant::now();
    let c = collect(&CollectOptions::default(), &|_| {});
    let took = began.elapsed();
    tracing::info!(millis = took.as_millis(), "snapshot collected");
    let mut json = match serde_json::to_value(&c.snapshot) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("bilby: couldn't encode the snapshot: {e}");
            return 1;
        }
    };
    scrubber().json(&mut json);
    let text = match serde_json::to_string_pretty(&json) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("bilby: couldn't encode the snapshot: {e}");
            return 1;
        }
    };
    if let Err(e) = std::fs::write(file, text + "\n") {
        eprintln!("bilby: couldn't write {file}: {e}");
        return 1;
    }
    // Timings and statuses go next to the snapshot for whoever made it.
    // They're scrubbed too: a failure reason can name a path.
    let mut summary = serde_json::json!({
        "took_ms": u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
        "is_admin": c.is_admin,
        "machine": c.machine,
        "timings": c.timings,
        "checks": c.checks,
    });
    scrubber().json(&mut summary);
    let _ = std::fs::write(
        format!("{file}.checks.json"),
        serde_json::to_string_pretty(&summary).unwrap_or_default() + "\n",
    );
    0
}

#[cfg(not(windows))]
fn dump_snapshot(_file: &str) -> i32 {
    eprintln!("bilby: --dump-snapshot only works on Windows");
    2
}

fn main() {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("bilby: {message}");
            std::process::exit(2);
        }
    };
    logging::init(scrubber());
    if let Some(file) = &args.dump_snapshot {
        std::process::exit(dump_snapshot(file));
    }
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        deep_check = args.deep_check,
        "Bilby started"
    );
    tauri::Builder::default()
        .manage(commands::AppState {
            demo: args.demo,
            autostart: AtomicBool::new(args.deep_check),
            last_report: Mutex::new(None),
            last_snapshot: Mutex::new(None),
            scanner: scan::Scanner::default(),
        })
        .invoke_handler(tauri::generate_handler![
            commands::render_home,
            commands::render_progress,
            commands::render_last_results,
            commands::start_scan,
            commands::cancel_scan,
            commands::scan_state,
            commands::relaunch_elevated,
            commands::ignore_finding,
            commands::unignore_finding,
            commands::open_next_step,
            commands::open_rules
        ])
        .run(tauri::generate_context!())
        .expect("Bilby couldn't start its window");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, String> {
        parse_args(args.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn demo_flag() {
        assert_eq!(parse(&[]), Ok(Args::default()));
        assert_eq!(
            parse(&["--demo", "attention"]).map(|a| a.demo),
            Ok(Some(DemoKind::NeedsAttention))
        );
        assert_eq!(
            parse(&["--demo=worth"]).map(|a| a.demo),
            Ok(Some(DemoKind::WorthALook))
        );
        assert_eq!(
            parse(&["--other", "--demo", "healthy"]).map(|a| a.demo),
            Ok(Some(DemoKind::Healthy))
        );
        assert!(parse(&["--demo"]).is_err());
        assert!(parse(&["--demo", "red"]).is_err());
    }

    #[test]
    fn dump_and_deep_check_flags() {
        let a = parse(&["--dump-snapshot", "out.json"]).unwrap();
        assert_eq!(a.dump_snapshot.as_deref(), Some("out.json"));
        let a = parse(&["--dump-snapshot=C:\\x y\\out.json", "--deep-check"]).unwrap();
        assert_eq!(a.dump_snapshot.as_deref(), Some("C:\\x y\\out.json"));
        assert!(a.deep_check);
        assert!(parse(&["--dump-snapshot"]).is_err());
        assert!(parse(&["--dump-snapshot="]).is_err());
    }
}
