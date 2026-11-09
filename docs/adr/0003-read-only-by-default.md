# 0003: Read-only by default

Date: 2026-11-09. Status: Accepted.

## Context

People who aren't technical may click whatever looks like the fix. A security tool that deletes the wrong startup entry or driver can leave a computer broken, and they won't know how to undo it.

## Decision

- A check never changes anything on the computer. Collectors open handles, registry keys and WMI namespaces read-only. Code review must reject any write in `bilby-collect-*`.
- All writes live in the `bilby-fix` crate, behind a `Fix` trait with `describe()`, `apply()` and `undo()`.
- A fix runs only after the user presses a button on a confirmation screen that says, in plain words, what will change and how to undo it.
- Before `apply()`, the fix writes a journal entry with everything `undo()` needs.
- Fixes use Windows' own switches where they exist (for example `StartupApproved` values, task `Enabled` flag, service start type) so the change also shows in Windows settings and can be reversed there.
- Bilby never deletes files. It asks Defender to scan, or moves a file to its own quarantine folder with a restore record.
- No fix runs in bulk. There's no "fix everything" button.

## Consequences

- Undo needs testing as much as apply. Each fix gets a round-trip test.
- Some problems can't be fixed by Bilby. For those it gives a next step (for example, open the browser's extension page, or talk to a helper).

## Alternatives considered

- **One-click clean-up.** Rejected for the reasons above.
