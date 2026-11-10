# Bilby architecture

This is the target design. Issues reference sections here by heading. If an issue and this file disagree, fix this file in the same PR.

## Goals

1. A person with no technical knowledge can press one button and get a calm, correct answer about whether their computer shows signs of infection.
2. Low false alarms. Every finding carries a confidence level, and the overall result only turns red on high-confidence evidence.
3. Read-only by default. Fixes are opt-in, explained, confirmed and reversible.
4. No telemetry and no network traffic unless the user turns on online checks.
5. Small, auditable supply chain: Rust, no npm, few crates.

## Non-goals

- Replacing antivirus. Bilby doesn't remove malware itself. Where a file needs dealing with, it hands it to Microsoft Defender or quarantines it reversibly.
- Real-time protection. Bilby runs when you ask it to.
- Kernel drivers, memory scanning of other processes, or anything that needs a Microsoft-attested driver.
- Fleet management. Bilby is for one computer and the person sitting at it.

## Platforms

- Windows 10 22H2 and Windows 11, x64 and Arm64. First.
- macOS 13 and later. Later milestone, see "macOS" below.
- Linux is out of scope, though `bilby-core` builds and tests on Linux so CI can run the engine there.

## Repository layout

```
Cargo.toml                  workspace, shared lints, release profile
rust-toolchain.toml         pinned toolchain (exact version, not "stable")
deny.toml                   cargo-deny policy
crates/
  bilby-core/               platform-neutral: data model, rules, scoring, copy, fixtures
    src/model.rs            Finding, Severity, Confidence, Evidence, NextStep, ScanReport
    src/snapshot.rs         SystemSnapshot: the raw facts collectors return
    src/rules/              one module per signal family, pure functions snapshot -> findings
    src/settings.rs         OnlineChecks { circl, virustotal }, both off by default, booleans only
    src/score.rs            findings -> traffic light
    src/engine.rs           snapshot -> report: rules, boosts, grouping, order, light
    src/scrub.rs            removes user name, computer name, profile path and SIDs
    src/paths.rs            pure path normalisation and PathClass classification
    src/cim.rs              WMI datetime and OLE date parsing
    src/cmdline.rs          command line to target resolution (CreateProcess rules, hosts)
    src/net.rs              address classes and Windows table byte order
    src/browser.rs          lenient parsing of Preferences, manifests, profiles.ini, extensions.json
    src/hosts.rs            hosts file decoding (UTF-8, UTF-16) and parsing, domain watch list
    src/data/               windows_core_processes.toml (where each core Windows program belongs)
    data/                   watch_domains.txt, known_bad_roots.toml, known_dev_roots.toml, known_windows_roots.toml, known_driver_publishers.toml (each entry cites its source)
    src/copy/en-AU.toml     every user-facing string
    src/copy.rs             loader and lint for the copy file
    tests/fixtures/         JSON snapshots used by unit tests
  bilby-collect-windows/    #[cfg(windows)] collectors that fill a SystemSnapshot
    src/handle.rs           RAII file handle, read-only opens
    src/sig.rs              Authenticode verification (embedded, then catalog SHA-256, then SHA-1)
    src/paths.rs            fills bilby_core::paths::KnownFolders from Windows
    src/hash.rs             streaming SHA-256, files over 512 MiB skipped
    src/cache.rs            per-scan FileFacts cache keyed by (path, size, mtime)
    src/files.rs            file_facts(): everything about one file in one call
    src/defender.rs         protection status: Defender, Security Center, firewall, UAC, updates
    src/processes.rs        Toolhelp snapshot, PROCESS_QUERY_LIMITED_INFORMATION only, WMI command lines
    src/persistence/        run_keys.rs, startup_folders.rs, services.rs, tasks.rs, wmi_subs.rs
    src/network.rs          GetExtendedTcpTable/UdpTable, IPv4 and IPv6, owning pids, no lookups
    src/browser.rs          Chromium and Firefox profiles, extension policies, join state, browser shortcuts
    src/tamper.rs           hosts (DataBasePath), WinINet and WinHTTP proxy, read-only root stores, Microsoft's root list (EncodedCtl)
    src/scan.rs             the orchestrator: Collector trait, threads, timeouts, cancel, progress, machine summary, scrubber
    src/elevation.rs        own-token elevation check and the "Check more deeply" UAC relaunch
    src/drivers.rs          EnumDeviceDrivers paths, code integrity (NtQuerySystemInformation), DeviceGuard WMI, blocklist and Secure Boot values
  bilby-collect-macos/      later
  bilby-reputation/         opt-in hash lookups (Defender file scan, CIRCL, VirusTotal); see docs/privacy.md
    src/allowlist.rs        the only HTTP client: HTTPS to two hosts, no redirects, no env proxy, 10 s timeout
    src/circl.rs            hashlookup.circl.lu, 200 known / 404 unknown
    src/virustotal.rs       /api/v3/files/<sha256> last_analysis_stats, key from Credential Manager (key.rs)
    src/defender.rs         MpCmdRun custom scan of one file, user-started only
  bilby-report/             HTML report (Askama) and PDF export
  bilby-fix/                reversible fix actions and the undo journal
app/
  src-tauri/                Tauri v2 binary crate "bilby"
    tauri.conf.json
    capabilities/default.json
    src/main.rs
    src/commands.rs         the only IPC surface: render_home, start_scan, cancel_scan, scan_state, relaunch_elevated
    src/scan.rs             one scan at a time, cancel switch, progress events
    src/logging.rs          rotating, scrubbed log file
    templates/              Askama templates for screens and fragments
  ui/                       static frontend: index.html, app.css, app.js, fonts, icons
docs/
  architecture.md
  adr/
  research/system-informer.md
  copy-guide.md
  test-plan.md
  signals.md                every rule: id, what it means, severity, confidence, false positive notes
```

## Data flow

```
[Check my computer]
      |
      v
commands::start_scan  --spawn_blocking-->  scan::collect (one thread per collector, timeouts)
                                          |
                                          v
                         Collectors (Windows APIs, read-only) -> SystemSnapshot
                                          |
                                          v
                         engine::evaluate: rules, boosts, grouping, order (pure) -> Vec<Finding>
                                          |
                                          v
                         score::overall(&findings) -> Light { Healthy | WorthALook | NeedsAttention }
                                          |
                                          v
                         ScanReport (kept in memory, optional save to disk)
                                          |
                                          v
                         Askama templates -> HTML fragments -> UI
```

The split between collectors and rules matters. Collectors only gather facts and never decide what's bad. Rules are pure functions over a snapshot, so every rule can be unit tested on Linux or macOS with JSON fixtures, without a Windows machine.

## Data model (bilby-core)

```rust
pub enum Severity { Info, Low, Medium, High }
pub enum Confidence { Low, Medium, High }

pub struct Finding {
    pub rule_id: String,                // e.g. "proc.masquerade.system_name"
    pub family: SignalFamily,           // Protection, Processes, Persistence, Network, Browser, Tamper, Drivers, Reputation
    pub severity: Severity,
    pub confidence: Confidence,
    pub title_key: String,              // copy key prefix, e.g. "proc.masquerade"
    pub vars: BTreeMap<String, String>, // values substituted into copy, all escaped on render
    pub evidence: Vec<Evidence>,        // technical facts for the helper view
    pub next_step: NextStepKind,        // what the UI offers: Learn, OpenSetting, AskDefender, Fix(FixId), TalkToHelper
    pub subject: Subject,               // the thing the finding is about (file path, reg key, task name...), used for suppressions
}

pub struct ScanReport {
    pub started_at, pub finished_at,    // UTC, RFC 3339 in JSON
    pub light: Light,
    pub findings: Vec<Finding>,
    pub checked: Vec<Check>,            // every check: id, family, status Ran | Skipped(reason) | NeedsAdmin | Failed(reason)
    pub machine: MachineSummary,        // OS version, edition, arch; hostname and user only if the user opts in on export
    pub bilby_version: String,
    pub is_admin: bool,                 // ran elevated ("Check more deeply")
    pub timings: Vec<Timing>,           // per collector, in milliseconds, for the helper view
}
```

Ids and copy keys are `String` rather than `&'static str` so reports and fixtures can be read back from JSON. `Finding::id()` is the first 16 hex characters of SHA-256 over the rule id, a zero byte and the JSON of the subject. It's stable across runs and builds, and it's what suppressions store.

### Demo mode

`bilby --demo <healthy|worth|attention>` (in development: `cargo tauri dev -- -- --demo attention`) makes the scan command send progress events for about three seconds and then return a fixed report from `crates/bilby-core/tests/fixtures/demo/`. The light is recomputed from the fixture's findings, so a fixture can't show a light it doesn't earn.

## Scan orchestration

`bilby_collect_windows::scan::collect(opts, progress)` runs every collector and returns a `Collection` (snapshot, checks, timings, `is_admin`, machine summary). `bilby_core::engine::evaluate(snapshot, ctx, meta)` turns that into a `ScanReport`. The app calls the first inside `tauri::async_runtime::spawn_blocking` so the window never waits on it.

- **Collectors.** Each implements `Collector { id, family, run(&CollectCtx) -> Result<Output, CollectError> }`. `CollectError::{NeedsAdmin, Skipped, Failed}` maps to `CheckStatus`. Step ids are `protection`, `processes`, `persistence`, `network`, `browser`, `tamper` and `drivers`.
- **Threads, not tasks.** Each collector runs on its own `std::thread` with COM initialised for that thread (MTA). A thread can be walked away from, which a hung COM or WMI call needs: the scan stops waiting and the thread's late result is dropped.
- **Order.** Processes starts at once, alongside everything that doesn't need it. Network starts when processes is in (it keeps only rows owned by known pids). Tamper starts when processes, network and browser are in (it ties a local proxy to its listening program, and needs the device's management state).
- **Timeouts.** 30 seconds per collector, from when it starts, and 120 seconds for the whole scan. A collector over its limit becomes `Failed("took too long")`.
- **Cancel.** An `Arc<AtomicBool>`. The orchestrator checks it every 100 ms and returns at once. File checks (`files::file_facts`, which covers the signature and hash loops in processes, startup items and drivers) stop opening files once a scan is cancelled or has stopped waiting, so abandoned collectors finish quickly.
- **Progress.** `scan-progress` events `{ step, state: running | done | skipped | needs-admin | failed, done, total, label }`. The label is the copy `scan.step.<id>`, worked out in Rust.
- **Grouping.** `engine::group` folds findings about the same file into one: the program, the startup item that runs it (matched by its path evidence) and its connections. The most serious finding leads (severity, then confidence) and keeps its own severity, confidence and id, so grouping never makes the light worse. The rest add an `evidence.also_found` line naming their rule, then any evidence the lead doesn't have. Findings are then sorted by severity, then confidence.
- **Admin.** `is_admin` comes from `GetTokenInformation(TokenElevation)` on Bilby's own token. When it's false the results screen offers "Check more deeply" (see Privileges).
- **Timings.** Per collector, in the report and at debug level in the log. Target: a full scan under 60 seconds on a typical laptop and under 90 on a CI runner (release build). The CI `build-app` job prints the release `--dump-snapshot` timings.

### Snapshot dump

`bilby.exe --dump-snapshot <file>` runs every collector, scrubs the result with `bilby_core::scrub` and writes pretty JSON, without opening a window. It also writes `<file>.checks.json` with timings and check statuses. It's how fixtures and the clean baseline are made (docs/test-plan.md). CI runs it on `windows-latest` and fails if the runner's user or computer name appears in either file.

### Scrubbing

`bilby_core::scrub::Scrubber` replaces, in any case: the profile folder (long and 8.3 short form) with `%USERPROFILE%`; machine and account SIDs (`S-1-5-21-...`, Entra `S-1-12-1-...`) with `<sid>`; and the user name and computer name, as whole words, with `<user>` and `<computer>`. Well-known SIDs such as `S-1-5-18` are the same everywhere and stay. Dumps, logs and (later) saved reports use it.

### Logging

`tracing` with one file layer at `%LOCALAPPDATA%\Bilby\logs\bilby.log`, info level (debug with `BILBY_LOG=debug`), rotated at 5 MB with one old file kept as `bilby.log.1`. Every line passes through the scrubber. Bilby logs steps, check statuses and timings; never file hashes, settings values or keys.

## Scoring

Overall light, worked out in `score.rs`:

- **Needs attention** if any finding is `High` severity with `Medium` or `High` confidence.
- **Worth a look** if any finding is `Medium` severity with `Medium` or `High` confidence, or any `High` severity with `Low` confidence, or there are 3 or more `Low` severity findings with at least `Medium` confidence.
- **Looks healthy** otherwise.
- Suppressed findings (the user said "I know this one") never count, but stay visible under "Things you've told Bilby to ignore".
- If a whole check family failed or was skipped, the result can still be "Looks healthy" but the screen must say what wasn't checked.

Examples of what earns each level are in `docs/signals.md`. A finding should only be `High` confidence when a clean machine essentially never produces it (for example Defender reporting an active threat, or a file named `lsass.exe` running from the Downloads folder).

## Files, signatures and folders

Most rules depend on three facts about a file, worked out once per scan by `bilby_collect_windows::files::file_facts` and cached by path, size and last-write time:

- **Signature** (`SignatureStatus`): `Signed { publisher, issuer, kind, is_windows_component }`, `Unsigned`, `Invalid` (tampered), `Untrusted` (chain problem) or `Error` (couldn't check). The embedded signature is checked first, then the Windows catalogs, because most Windows files are catalog-signed. `is_windows_component` needs both a Microsoft root and the Windows System Component Verification EKU (`1.3.6.1.4.1.311.10.3.6`), so a third party with an ordinary Microsoft-issued certificate doesn't count. Revocation checks are off and URL retrieval is cache-only, so verifying never touches the network.
- **Folder class** (`PathClass`) from `bilby_core::paths::classify`: pure string work over a `KnownFolders` the collector fills from Windows, so it's unit tested on any OS. The most specific folder wins (Temp inside `%LOCALAPPDATA%` is Temp).
- **User-writable**: Temp, Downloads, Desktop, Documents, user app data and user app installs, Public, Recycle Bin, removable drives, and files directly in the `ProgramData` root.

## Rules and fixtures

Rules get a `RuleContext` holding the suppressions and `now`, the scan's start time. Rules never read the clock, so the same fixture gives the same findings on any day. `tests/rules.rs` runs every JSON fixture under `tests/fixtures/<family>/` and checks that each rule in `all_rules()` has a `fires` and a `lookalike` fixture, a row in `docs/signals.md`, and `title`, `what`, `why` and `todo` copy keyed by its rule id.

### Cross-family facts

Some findings mean more together. An unsigned program in AppData is Low on its own, but it's more interesting if the same file also starts by itself or connects out. `RuleContext::with_relations(now, snapshot)` builds a map from normalised file path to `Relation`s (`StartsByItself`, `OutboundConnection`, `ListeningPort`). `RuleContext::related(path)` reads it. Each family adds its relations in `rules::relations_from` as its collector lands: persistence in #9 to #11, network in #12. Rules only ever raise confidence this way. They never lower a finding because of it.

### Boost-only rules

Some rules only adjust findings that other rules made, and never make a card of their own. They're listed in `rules::BOOST_RULES` and run after all the other rules, in `evaluate_all`. `net.outbound_from_suspicious` is the first: an unsigned or masquerading program that's also connected to a public address gets its process finding raised one confidence level, with the connections added as evidence. The fixture harness checks that a boost rule never appears as a finding.

## Signal families (Windows)

Each family is one collector module and one rules module. Details and rule tables are in the matching issue and in `docs/signals.md`.

| Family | Collector source | Typical rules |
|---|---|---|
| Protection | WMI `root\Microsoft\Windows\Defender` (`MSFT_MpComputerStatus`, `MSFT_MpThreatDetection`), `root\SecurityCenter2` `AntiVirusProduct`, firewall policy, UAC registry | AV off, real-time off, signatures stale, recent detection not resolved, firewall off |
| Processes | Toolhelp snapshot, `QueryFullProcessImageNameW`, Authenticode | Windows name outside System32, look-alike names, unsigned from Temp or Downloads, odd parents for core processes |
| Persistence | Registry Run keys and friends, startup folders, Service Control Manager, Task Scheduler COM, WMI `root\subscription` | Startup item pointing at an unsigned file in a user-writable folder, script hosts with encoded commands, WMI consumers |
| Network | `GetExtendedTcpTable`, `GetExtendedUdpTable` | Unsigned program in a user-writable folder with outbound connections or a listening port |
| Browser | Chromium `Preferences` and `Secure Preferences`, Firefox `extensions.json`, browser policy registry keys | Sideloaded extension with wide permissions, force-installed extension on an unmanaged PC |
| Tamper | hosts file, WinINet and WinHTTP proxy, PAC URL, `ROOT` certificate stores | Popular domains redirected, unexpected proxy, non-Microsoft root certificate added recently |
| Drivers | `EnumDeviceDrivers`, kernel driver services, boot options, Device Guard WMI | Test signing on, integrity checks off, unsigned or recently added drivers, memory integrity off (info) |
| Reputation (opt-in) | Defender on-demand file scan, CIRCL hashlookup, VirusTotal with the user's own key | Hash known bad, hash known good (reduces other findings' confidence) |

## Privileges

- Bilby runs as the signed-in user (`asInvoker`). Most checks work without admin.
- Checks that need admin (other users' processes, some service details, `MSFT_MpThreatDetection` on some builds, driver boot options, and the loaded driver list on Windows 11 24H2 and later, where `EnumDeviceDrivers` returns all-NULL addresses without SeDebugPrivilege) report `NeedsAdmin` rather than failing silently.
- "Check more deeply" relaunches Bilby elevated through a normal UAC prompt, after the user presses a clearly labelled button. It's `ShellExecuteExW` with the `runas` verb on Bilby's own exe and `--deep-check`. If the user says no, the current window stays and shows a calm line. If yes, the current window closes and the elevated one starts a scan straight away. There's no background service and no persistent elevated component.

## Frontend and IPC

See ADR 0002. In short:

- `app/ui/index.html` is the only page. It loads `app.css` and `app.js` from the app bundle. No CDN, no remote content.
- Screens and fragments are rendered in Rust with Askama (auto-escaping on) and returned as HTML strings from Tauri commands. `app.js` swaps them into the page and wires buttons to commands. Target size for `app.js` is under 300 lines.
- `withGlobalTauri: true` exposes `window.__TAURI__.core.invoke`, so there's no `@tauri-apps/api` npm package.
- Strict CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src ipc: http://ipc.localhost; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`. No inline scripts or styles.
- The Tauri capability file grants only `core:default` and the app's own commands. No shell, fs, http or opener plugins. Network calls for opt-in reputation are made from Rust, never from the webview.

## Online checks (opt-in)

Off by default. When on:

- Only SHA-256 hashes leave the machine, never files, file names or paths.
- Each lookup service is a separate switch with a plain-English description of who receives the hash.
- A VirusTotal key is the user's own and is stored in Windows Credential Manager, never in a config file.
- The scan screen says "Online checks: off" or names the services in use.
- Local first: "Ask Defender to scan this file" uses `MpCmdRun.exe -Scan -ScanType 3 -File <path>` and needs no network.

## Fixes

See ADR 0003 and the Safe fixes milestone. Every fix:

1. Is offered only on a finding that supports it.
2. Shows a confirmation with what will change, in plain words, and how to undo it.
3. Writes a journal entry to `%LOCALAPPDATA%\Bilby\journal.jsonl` before acting, with enough data to undo.
4. Prefers the mechanism Windows itself uses (for example the `StartupApproved` registry values Task Manager uses to disable startup apps) so undo also works from Windows settings.
5. Never deletes. Files are handed to Defender or moved to Bilby's quarantine folder with a restore record.

## Reports

- HTML: one self-contained file, inline CSS, no JavaScript, no remote resources. Opens in any browser.
- PDF: generated from the same HTML. See the Report export milestone for the method.
- Hostname, user name and full paths under the user profile are replaced with placeholders unless the user ticks "Include my computer and user name".

## Local data

`%LOCALAPPDATA%\Bilby\`:

- `settings.json`: online check switches, theme, text size.
- `suppressions.json`: rule id plus subject for each "I know this one".
- `journal.jsonl`: fix journal.
- `logs\bilby.log`: scrubbed log, 5 MB at most, plus one older file.
- `quarantine\`: quarantined files and their restore records.
- No scan history is kept unless the user saves a report.

## Supply chain

- `rust-toolchain.toml` pins an exact version (1.99.1 at the time of writing; bump deliberately).
- `Cargo.lock` is committed. CI and release builds use `--locked`.
- `cargo-deny` checks advisories, licences (allowlist: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, MPL-2.0 by exception only), bans duplicate major versions where practical, and allows only crates.io as a source.
- `cargo-audit` runs on every PR and weekly.
- GitHub Actions are pinned by commit SHA. Workflows run with `permissions: contents: read` unless a job needs more.
- Dependabot opens weekly PRs for cargo and actions.
- Crates are added only with a reason in the PR description.

## macOS (later)

Same core and UI. A `bilby-collect-macos` crate covers XProtect and Gatekeeper status, SIP, FileVault, running processes with code signing checks (`SecStaticCodeCheckValidity`), LaunchAgents and LaunchDaemons, login items, configuration profiles, proxy and hosts, and browser extensions. No Endpoint Security entitlement, so no live process events.

## Accessibility and copy

- WCAG 2.2 AA. Base text 18px, scalable to 200% without loss. Contrast 4.5:1 for text, 3:1 for UI parts. Targets at least 24 by 24 CSS pixels, main buttons much larger. Visible focus. Works with Narrator and NVDA. Respects reduced motion and Windows high contrast.
- Colour is never the only signal. The traffic light always has an icon shape and words.
- Copy rules are in `docs/copy-guide.md`. Calm, plain Australian English, no blame, no fear.
