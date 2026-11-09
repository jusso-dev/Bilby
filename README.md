# Bilby

Bilby is a free desktop app that answers one question for people who aren't technical: is something wrong with my computer?

You press **Check my computer**. A minute later Bilby tells you one of three things:

- **Looks healthy.** Nothing we checked needs you.
- **Worth a look.** Something is unusual. It's probably fine, but here's what to check.
- **Needs attention.** We found something that looks like a real problem. Here's what to do next.

Every finding says what Bilby saw, why it matters, how sure it is, and one safe next step. If you want a family member or a local repairer to look, you can save a report and send it to them yourself.

Bilby is named after the bilby, a small Australian marsupial with big ears that digs around at night. It listens carefully and doesn't make a fuss.

## Status

Early. Nothing is built yet. The plan lives in the [issues](https://github.com/jusso-dev/Bilby/issues) and [milestones](https://github.com/jusso-dev/Bilby/milestones). Windows comes first. macOS is a later milestone.

## What Bilby checks (Windows)

- Whether Microsoft Defender or another antivirus is switched on and up to date, and what it has caught recently.
- Running programs: who made them (their digital signature), where they run from, and whether any are pretending to be a Windows program.
- Programs set to start on their own: startup entries, services, scheduled tasks, startup folders and WMI event subscriptions.
- Network connections from programs that look out of place.
- Browser extensions that were installed outside the store or have very wide access.
- Changes to the hosts file, proxy settings and trusted root certificates that can redirect or read your web traffic.
- Drivers that were added recently or aren't signed, and whether driver signature checks have been turned off.
- Optional online lookups of file fingerprints (hashes). These are off unless you turn them on, and Bilby never uploads your files.

## Promises

- **Read-only by default.** A check changes nothing on your computer.
- **Fixes are your call.** Any fix is explained first, needs you to confirm, and can be undone.
- **No telemetry.** Bilby doesn't phone home. Online checks only happen if you switch them on.
- **Plain English.** No jargon on the main screens. Technical detail is one click away for whoever is helping you.
- **Low false alarms.** Bilby would rather say "worth a look" than scare you about a program you've used for years.

Bilby doesn't replace your antivirus. It looks for the signs that something got past it, or that your protection was switched off.

## How it's built

- Rust and [Tauri v2](https://v2.tauri.app/).
- The interface is plain HTML and CSS rendered from Rust templates, with a small amount of hand-written JavaScript. There's no npm, no Node and no JavaScript build step. See [ADR 0002](docs/adr/0002-frontend-without-npm.md).
- Windows checks use documented, user-mode Windows APIs through Microsoft's `windows` crate and WMI. There's no kernel driver.
- Supply chain: pinned Rust toolchain, committed `Cargo.lock`, `cargo-deny` and `cargo-audit` in CI.

Read [docs/architecture.md](docs/architecture.md) for the design and [docs/research/system-informer.md](docs/research/system-informer.md) for what we learned from System Informer.

## Building

Not yet. The scaffold issue sets this up. You'll need the Rust toolchain pinned in `rust-toolchain.toml` and the Tauri CLI installed with `cargo install tauri-cli --locked`.

## Testing without real malware

Bilby is tested with fixture data and a clean virtual machine where we plant harmless look-alikes, such as the EICAR test file and a self-built "hello world" program renamed to look suspicious. We never use real malware. See [docs/test-plan.md](docs/test-plan.md).

## Credits

Some of Bilby's ideas come from [System Informer](https://github.com/winsiderss/systeminformer) by Winsider Seminars & Solutions (MIT licence). No System Informer code has been copied into Bilby. If that changes, the copied file will carry its original copyright notice and be listed in [NOTICE](NOTICE).

## Licence

MIT. See [LICENSE](LICENSE).
