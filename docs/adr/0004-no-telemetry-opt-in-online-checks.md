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

## Amendment, 2026-11-11: IP address lookups

Justin chose to add opt-in IP reputation (VirusTotal IP reports, AbuseIPDB, CrowdSec CTI), limited to programs Bilby already flagged. Sending addresses tells a third party who this computer talks to, which is more than a file hash, so:

- Each IP service is its own switch, off by default, separate from the file-hash switches. VirusTotal's IP switch is separate from its file switch even though they share a key.
- Only public remote addresses of established TCP connections owned by a program that already has a finding of Low or higher are sent (`rules::reputation::ip_candidates`), at most 20 a scan, and at most 10 to CrowdSec, whose free key allows 120 a month. Never every connection, never private, loopback or link-local addresses (checked again in `bilby-reputation::ip` before sending), and nothing else about the computer or the program.
- Keys are the user's own, in Credential Manager (`Bilby/AbuseIPDB`, `Bilby/CrowdSec`).
- Hosts added to the allowlist: `api.abuseipdb.com`, `cti.api.crowdsec.net`. Same client rules as before.
- The "only SHA-256 hashes are sent" decision above still holds for files; addresses are the only other thing that can leave the machine, and only through these switches.

## Consequences

- Offline results rely on local evidence only. The copy must not imply Bilby "checked online" unless it did.
- Some confidence is lost without reputation data. Rules are written to be useful without it.
