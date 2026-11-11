# Privacy

Bilby looks at your computer and tells you what it finds. It doesn't send anything about you or your computer anywhere unless you switch an online check on.

## What Bilby never does

- It never sends telemetry, crash reports, usage statistics or update checks. Not even anonymous ones.
- It never uploads your files.
- It never sends file names, folder paths, your computer's name or your user name.
- It never sends a list of everything your computer talks to.

## Online checks (off unless you switch them on)

Each online check is a separate switch in Settings. When one is on, Bilby asks that service about a file's fingerprint (a SHA-256 hash, a long string of letters and numbers worked out from the file). A fingerprint can't be turned back into the file.

Along with the fingerprint, the service also sees:

- your internet address (IP address), as with any website you visit,
- that the request came from Bilby and which version (`Bilby/0.1.0`), and
- for VirusTotal only, your own VirusTotal key, which tells VirusTotal which account is asking.

Bilby never sends the file, its name or folder, your computer's name or your user name.

Bilby only sends fingerprints for:

- files behind something Bilby already found,
- programs that start by themselves, and
- running programs that aren't part of Windows.

It never sends fingerprints for every file on your computer. It sends at most 100 to CIRCL in one check, and stays inside VirusTotal's limits. Results are kept in memory until you close Bilby, then forgotten.

| Switch | What's sent | Who receives it | What comes back |
|---|---|---|---|
| Check against known software | Fingerprints | CIRCL, Luxembourg's national computer emergency response team, through its free hashlookup service (`hashlookup.circl.lu`) | Whether the file is in a list of known software, such as programs that come with Windows. If it is, Bilby is less sure about anything it found there. |
| VirusTotal | Fingerprints, and the free key you created on VirusTotal | VirusTotal, run by Google (`www.virustotal.com`) | How many security tools flagged the file, if VirusTotal has seen it before. |

Your VirusTotal key is stored in Windows Credential Manager under `Bilby/VirusTotal`, the same place Windows keeps other saved passwords. It's never written to Bilby's settings file, logs or reports. VirusTotal's free key allows 4 checks a minute and 500 a day, and is for personal, non-commercial use.

### Checking internet addresses (also off unless you switch them on)

Three more switches check the internet addresses that a program Bilby already flagged is talking to. This tells the service which addresses that program was connected to, so each one is a separate choice.

Bilby only sends:

- public internet addresses (never addresses on your home network),
- of programs that already have a finding (something unsigned running from Temp, say),
- at most 20 in one check, and at most 10 to CrowdSec.

It never sends the program's name, your computer's name, your user name, or the addresses your browser and other programs are talking to.

| Switch | What's sent | Who receives it | What comes back |
|---|---|---|---|
| VirusTotal addresses | Addresses, and your VirusTotal key | VirusTotal (`www.virustotal.com`) | How many security tools flag the address. Shares the 4 a minute and 500 a day limit with file checks. |
| AbuseIPDB | Addresses, and your AbuseIPDB key | AbuseIPDB (`api.abuseipdb.com`) | A 0 to 100 abuse score and how many people reported it in the last 90 days. The free key allows 1,000 checks a day. |
| CrowdSec | Addresses, and your CrowdSec key | CrowdSec, a French security company (`cti.api.crowdsec.net`) | Whether CrowdSec's users have seen the address attacking them, and what it did. The free key allows 120 checks a month. |

Your AbuseIPDB and CrowdSec keys are stored in Windows Credential Manager under `Bilby/AbuseIPDB` and `Bilby/CrowdSec`.

Bilby only connects to those addresses, over an encrypted connection (HTTPS). It refuses to follow a redirect anywhere else, and it doesn't use proxy settings from the environment.

## Ask Windows Security to check a file

On some findings you can press "Ask Windows Security to check this file". Bilby then asks Windows Security, on this computer, to scan that one file. Bilby doesn't send anything itself.

Windows Security has its own settings for Microsoft's cloud protection and for sending samples to Microsoft. Those still apply, as they do for any scan Windows Security runs. You can see and change them in Windows Security, under Virus and threat protection settings.

This only happens when you press the button. It's never part of the automatic check.

## What isn't available

Microsoft has a cloud lookup for file fingerprints, but it's only for businesses using Microsoft Defender for Endpoint. Home users can't use it, so Bilby doesn't.

## Certificate checks

When Bilby checks a program's digital signature (a seal that shows who made it), it uses only what Windows already has saved. It doesn't go online to check whether a certificate was withdrawn, so a check never causes a network connection.

## For your helper

- Design decision: `docs/adr/0004-no-telemetry-opt-in-online-checks.md`.
- Settings: `OnlineChecks { circl, virustotal, virustotal_ips, abuseipdb, crowdsec }` in `crates/bilby-core/src/settings.rs`, saved in `%LOCALAPPDATA%\Bilby\settings.json`. Booleans only, all `false` by default. The file refuses unknown fields, so a key can't end up there.
- Hosts: `crates/bilby-reputation/src/allowlist.rs`. HTTPS only, redirects refused, environment proxies ignored, 10 second timeout, User-Agent `Bilby/<version>`. TLS is rustls with Mozilla's roots; no OpenSSL.
- Proof of "nothing sent by default": CI builds `bilby-reputation` with the `no-network-guard` feature, which panics if the HTTP client is built while every switch is off. On Windows it runs every collector and then checks the test process's own TCP connections (`GetExtendedTcpTable`, what `Get-NetTCPConnection -OwningProcess` reads).
