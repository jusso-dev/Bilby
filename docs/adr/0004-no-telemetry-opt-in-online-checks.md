# 0004: No telemetry, online checks opt-in

Date: 2026-11-09. Status: Accepted.

## Context

The data Bilby reads (running programs, browser extensions, network connections) is private. Users can't evaluate a privacy policy, so the safe default has to be that nothing leaves the machine.

## Decision

- No telemetry, crash reporting, analytics or update pings. Not even anonymous ones.
- Online hash lookups are off by default. Each service is a separate switch in Settings with a sentence saying who receives what.
- Only SHA-256 hashes are sent. Never file contents, names, paths, the hostname or the user name.
- Lookups only run for files a rule has already flagged, plus the files behind startup items, never every file on disk.
- Authenticode checks run with revocation checks set to cache-only (`WTD_REVOKE_NONE` with `WTD_CACHE_ONLY_URL_RETRIEVAL`) so a scan doesn't trigger network fetches.
- The VirusTotal key, if the user adds one, is stored in Windows Credential Manager.
- All HTTP calls happen in Rust with `rustls` and a fixed allowlist of hosts. The webview has no network permission (`connect-src` limited to IPC).
- Checking for Bilby updates is a manual button, not automatic, until signed updates exist.

## Consequences

- Offline results rely on local evidence only. The copy must not imply Bilby "checked online" unless it did.
- Some confidence is lost without reputation data. Rules are written to be useful without it.
