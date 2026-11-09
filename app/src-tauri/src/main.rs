//! Bilby desktop app: a Tauri v2 window over Rust-rendered HTML screens.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use std::sync::Mutex;

use bilby_core::demo::DemoKind;

/// Reads `--demo <healthy|worth|attention>` (or `--demo=<kind>`) from the
/// command line. Anything else is ignored.
fn demo_from_args(args: impl IntoIterator<Item = String>) -> Result<Option<DemoKind>, String> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--demo" {
            let kind = args
                .next()
                .ok_or("--demo needs healthy, worth or attention")?;
            return kind.parse().map(Some);
        }
        if let Some(kind) = arg.strip_prefix("--demo=") {
            return kind.parse().map(Some);
        }
    }
    Ok(None)
}

fn main() {
    let demo = match demo_from_args(std::env::args().skip(1)) {
        Ok(demo) => demo,
        Err(message) => {
            eprintln!("bilby: {message}");
            std::process::exit(2);
        }
    };
    tauri::Builder::default()
        .manage(commands::AppState {
            demo,
            last_report: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            commands::render_home,
            commands::start_scan
        ])
        .run(tauri::generate_context!())
        .expect("Bilby couldn't start its window");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<DemoKind>, String> {
        demo_from_args(args.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn demo_flag() {
        assert_eq!(parse(&[]), Ok(None));
        assert_eq!(
            parse(&["--demo", "attention"]),
            Ok(Some(DemoKind::NeedsAttention))
        );
        assert_eq!(parse(&["--demo=worth"]), Ok(Some(DemoKind::WorthALook)));
        assert_eq!(
            parse(&["--other", "--demo", "healthy"]),
            Ok(Some(DemoKind::Healthy))
        );
        assert!(parse(&["--demo"]).is_err());
        assert!(parse(&["--demo", "red"]).is_err());
    }
}
