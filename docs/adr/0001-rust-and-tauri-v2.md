# 0001: Rust and Tauri v2

Date: 2026-11-09. Status: Accepted.

## Context

Bilby reads sensitive parts of the operating system and shows the results to people who can't judge whether the tool itself is trustworthy. It has to be small, fast to start, memory safe, and easy to audit. Justin's other recent projects (Keyring) moved to Rust to cut JavaScript supply-chain risk.

## Decision

- Write Bilby in Rust, pinned in `rust-toolchain.toml`.
- Use Tauri v2 (2.12.x at the time of writing) for the window, using the system webview (WebView2 on Windows, WKWebView on macOS).
- Use Microsoft's `windows` crate for Win32 and COM, and the `wmi` crate for WMI queries.
- Install the Tauri CLI with `cargo install tauri-cli --locked`. Don't use the npm-distributed CLI.

## Consequences

- Small binaries (a few MB) and quick start-up.
- WebView2 must be present. It ships with Windows 11 and current Windows 10. The installer uses Tauri's WebView2 bootstrapper option for the rare machine without it.
- The `windows` crate is large but maintained by Microsoft and has no build scripts that download anything.
- Tauri pulls in a sizeable crate tree. `cargo-deny` and `cargo-audit` keep an eye on it.

## Alternatives considered

- **Egui or Iced (pure Rust GUI).** No webview, smaller tree. Rejected for now: accessibility support (screen readers via AccessKit) is less mature than the browser's, and large-text, high-contrast layouts are harder to get right. Worth revisiting.
- **Electron.** Rejected: large, Node and npm.
- **WinUI 3 / .NET.** Rejected: Windows only, which blocks the macOS milestone, and a different language from Justin's other Rust work.
