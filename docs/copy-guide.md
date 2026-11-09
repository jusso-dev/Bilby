# Copy guide

Bilby's readers might be your nan, a busy parent or someone who has just been told by a pop-up that their PC is "infected". Write for them.

## Rules

1. Lead with what we found, in one short sentence.
2. Then why it matters, in one sentence, without fear words.
3. Then one thing to do. A verb first: "Open Windows Security", "Ask someone you trust to look", "Leave it".
4. Say how sure we are, in words.
5. Australian English: colour, organise, licence (noun), program (software).
6. No em dashes. No emojis. No exclamation marks.
7. No jargon on main screens: say "program" not "process", "starts by itself" not "persistence", "digital signature" (first use explained as "a seal that shows who made it").
8. No blame: "This was turned off" not "You turned this off".
9. No hype or fear: never "critical threat", "your PC is at risk", "act now", "infected" in a headline. "Needs attention" is our strongest phrase.
10. Technical detail belongs in "For your helper", where paths, rule ids and hashes are fine.

## Confidence phrases

| Confidence | Phrase |
|---|---|
| High | "We're confident about this." |
| Medium | "This is likely, but check first." |
| Low | "This might be nothing." |

## Light headlines

| Light | Headline | Sub-line |
|---|---|---|
| Healthy | Looks healthy | We checked {count} things and nothing needs you. |
| Worth a look | Worth a look | {n} thing(s) looked unusual. They're probably fine, but here's what to check. |
| Needs attention | Needs attention | We found something that looks like a real problem. Here's what to do next. |

## Banned words in UI copy

Checked by `crates/bilby-core/tests/copy_lint.rs` (the `copy-lint` CI job), which also checks that this list matches its own: seamless, robust, cutting-edge, leverage, unlock, harness, empower, elevate, transform, journey, critical, urgent, infected (in headlines), hacker, compromised (main screens), the em dash character.

## Example finding

> **A program is pretending to be part of Windows.**
> A file called svchost.exe is running from your Downloads folder. The real one only lives inside Windows' own folder, so this is a common trick.
> **What to do:** Ask Windows Security to scan it. Bilby can start that for you.
> We're confident about this.

## Where copy lives

Every user-facing string is in `crates/bilby-core/src/copy/en-AU.toml`. Code uses `copy::t("key")` or `copy::tf("key", &vars)`, and templates use `{{ "key"|t }}`. Each finding rule has `title`, `what`, `why` and `todo` under its own table. Placeholders look like `{name}`.

The lint also rejects:

- em dashes, and en dashes between words (en dashes are only for number ranges like 0–30)
- exclamation marks and emojis
- titles over 160 characters and other strings over 240
- US spellings: color, organize, license, center, behavior, favorite, recognize
- placeholders that aren't lower-case identifiers
- keys used in code that aren't in the catalogue, and keys in the catalogue that nothing uses (unless listed in `RESERVED` in the lint, for screens still to come)
