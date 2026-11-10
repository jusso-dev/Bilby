# Test plan

## Layers

1. **Rule unit tests (any OS).** Every rule in `bilby-core` is tested with JSON fixtures in `crates/bilby-core/tests/fixtures/<family>/`. Each rule has at least:
   - `<rule>.fires.json`: a snapshot where it must fire, with expected severity and confidence.
   - `<rule>.lookalike.json`: a near miss that must not fire (for example a real `svchost.exe` in `System32`, or Teams running from `%LOCALAPPDATA%\Microsoft\Teams` signed by Microsoft).
2. **Scoring tests.** Table tests for `score::overall` covering every row in the Scoring section of `architecture.md`.
3. **Copy tests.** Every copy key used in code exists in `en-AU.toml`, every key in the file is used, and no string contains banned words or an em dash.
4. **Template snapshot tests.** `insta` snapshots of each screen rendered from fixtures.
5. **Collector smoke tests (Windows CI).** On `windows-latest` runners: each collector runs, returns without error and returns plausible data (for example at least 20 processes, at least one Microsoft-signed, Defender status readable). They must not assert specific findings because runners change.
6. **Clean baseline (manual, release gate).** See below.
7. **Benign simulations (manual).** See below.

## Clean baseline

Use a fresh Windows 11 Enterprise evaluation VM (free 90-day ISO from Microsoft's Evaluation Center) with Hyper-V, VirtualBox or UTM. Install: Chrome, Firefox, Microsoft 365 apps or LibreOffice, Zoom, Teams, Spotify, Steam, Adobe Acrobat Reader, 7-Zip, VLC, Dropbox or OneDrive. Fully update Windows.

Run Bilby as a standard user and as admin. Pass: **Looks healthy**, and zero Medium or High findings. Save the JSON snapshot (`bilby.exe --dump-snapshot <file>`, a hidden flag that writes the scrubbed snapshot and exits without a window) with user names and hostnames scrubbed, and add it to `tests/fixtures/baseline/` as a regression fixture.

## Benign simulations

Take a VM snapshot first and revert after. Do these one at a time, run Bilby, and check the expected result. Never use real malware.

| # | Simulation | How | Expected |
|---|---|---|---|
| 1 | Defender detection | Create a text file containing the EICAR test string in `%USERPROFILE%\Downloads` (type it or build it; don't download it from a mirror). Defender quarantines it. | Protection finding "Windows Security caught something recently", Low or Medium severity since it was handled. Light: Worth a look at most. |
| 2 | Real-time protection off | Turn off real-time protection in Windows Security (needs Tamper Protection off first). | Needs attention, unless another AV is registered and on. |
| 3 | Masquerading name | Build a hello-world Rust exe (`cargo new hello`), copy it to `%USERPROFILE%\Downloads\svchost.exe` and run it with a `sleep` loop. | Needs attention, high confidence. |
| 4 | Look-alike name | Same exe as `%TEMP%\scvhost.exe`. | Needs attention or Worth a look depending on signature, rule documented. |
| 5 | Unsigned from Temp | Same exe as `%TEMP%\updater.exe`, running. | Worth a look. |
| 6 | Run key | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v BilbyTest /d "%TEMP%\updater.exe"` | Worth a look, fix offered (disable startup item). Undo works. |
| 7 | Encoded PowerShell at startup | Run key value `powershell.exe -NoProfile -EncodedCommand <base64 of "Start-Sleep 1">` | Needs attention. |
| 8 | Scheduled task | `schtasks /create /tn BilbyTest /tr "%TEMP%\updater.exe" /sc onlogon` | Worth a look, fix offered. |
| 9 | WMI subscription | PowerShell: create an `__EventFilter`, a `CommandLineEventConsumer` running `cmd.exe /c echo bilby`, and a binding, in `root\subscription`. Remove afterwards. | Needs attention (WMI consumers are rare on home PCs). |
| 10 | Hosts redirect | Add `127.0.0.1 www.commbank.com.au` to the hosts file (admin). | Needs attention. Fix offered (remove the line, backup kept). |
| 11 | Hosts benign | Add `127.0.0.1 my-dev-site.test`. | No finding or Info. |
| 12 | Proxy | Settings, Network, Proxy: manual proxy `127.0.0.1:8888`. | Worth a look. Fix offered. |
| 13 | Root certificate | Create a self-signed cert with `New-SelfSignedCertificate` and import it into `Cert:\CurrentUser\Root`. | Worth a look, or Needs attention if it was added in the last 30 days and isn't from a known vendor. |
| 14 | Sideloaded extension | Chrome, `chrome://extensions`, Developer mode, Load unpacked: a folder with a `manifest.json` asking for `<all_urls>` and `webRequest`. | Worth a look. |
| 15 | Force-installed extension | Set `HKCU\Software\Policies\Google\Chrome\ExtensionInstallForcelist` with a store extension id on an unmanaged VM. | Needs attention. |
| 16 | Test signing | `bcdedit /set testsigning on`, reboot. | Needs attention. |
| 17 | Outbound from Temp | Run the hello exe from Temp with code that opens a TCP connection to `example.com:443`. | Worth a look (network finding grouped with the process finding). |
| 18 | Firewall off | Turn off the private network firewall. | Worth a look. |

Record each result in the PR that changes the rule, with the Bilby version and Windows build.

## EICAR handling in automated tests

Don't commit EICAR as a file. Tests that need it build it at runtime from pieces and write it only inside a temp folder on the Windows runner, and only in the opt-in `eicar` test (`cargo test -p bilby-collect-windows --features eicar-test`). CI doesn't enable it by default because Defender on runners may block the job.
