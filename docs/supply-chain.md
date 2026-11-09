# Supply chain

Bilby reads private parts of a computer, so the code that goes into it has to be easy to trust. This page sets out the rules and how to work within them.

## The rules

- **Toolchain pinned.** `rust-toolchain.toml` names an exact Rust version. rustup and CI both read it.
- **Lockfile committed.** `Cargo.lock` is in git. Every cargo command in CI uses `--locked`, and each job checks early with `cargo metadata --locked` so a stale lockfile fails fast.
- **No npm.** No Node or JavaScript packages at all (ADR 0002). The `no-npm` CI job enforces this.
- **cargo-deny** (`deny.toml`) runs on every PR:
  - Advisories: yanked crates are denied. Any ignored advisory has an id, a reason and a review date.
  - Licences: MIT, Apache-2.0 (with or without LLVM exception), BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib and CC0-1.0. MPL-2.0 is allowed only per crate, with a reason. Anything else, including GPL, fails.
  - Bans: `openssl`, `openssl-sys` and `native-tls` are denied (use `rustls`). Wildcard versions are denied. Duplicate versions only warn, because Tauri's tree has some we can't avoid.
  - Sources: crates.io only. No git dependencies or other registries.
- **cargo-audit** runs on every PR and every Monday at 07:00 UTC (`.github/workflows/audit.yml`). Its ignore list is in `.cargo/audit.toml` and matches `deny.toml`.
- **Actions pinned by commit SHA**, with the version in a comment. Workflows have `contents: read` unless a job truly needs more.
- **Dependabot** opens weekly grouped PRs for cargo and GitHub Actions, at most 5 at a time.

## Current exceptions

| What | Why | Review |
|---|---|---|
| MPL-2.0: `cssparser`, `cssparser-macros`, `dtoa-short`, `selectors` | Pulled in by Tauri (`tauri-utils` uses `dom_query` to edit HTML at build time). Used unmodified. | When Tauri changes it |
| MPL-2.0: `option-ext` | Pulled in by Tauri and wry through `dirs`. Used unmodified. | When Tauri changes it |
| RUSTSEC-2024-0370, `proc-macro-error` unmaintained | Only reached through gtk, Tauri's Linux webview stack. Bilby ships no Linux app. | 09-05-2027 |
| RUSTSEC-2024-0429, `glib` unsound iterator | Same Linux-only gtk stack. Bilby never calls it. Listed in `.cargo/audit.toml` only, because cargo-deny doesn't report unsound advisories by default. | 09-05-2027 |

`askama` is used with `default-features = false, features = ["derive", "std"]`. Its `config` feature pulls in `basic-toml`, which is unmaintained (RUSTSEC-2026-0374), and Bilby doesn't need a template config file.

## Adding a dependency

1. Check whether a crate already in the tree does the job: `cargo tree -i <crate>`.
2. Look at the crate on crates.io and its repository: who maintains it, how recently it was released, download counts, open security issues, whether it has a build script and what that does.
3. Turn off default features you don't need.
4. Run `cargo deny check` and `cargo audit` locally.
5. Say in the PR description which crate you added, which version and features, and why.

## Bumping the Rust toolchain

1. Change `channel` in `rust-toolchain.toml` and `rust-version` in the root `Cargo.toml`.
2. Update the version in `docs/architecture.md` ("Supply chain").
3. Run fmt, clippy and tests locally, then let CI run on all three platforms.
4. Fix any new Clippy warnings in the same PR.

## Possible next steps

- `cargo-vet` to record who has reviewed each dependency. Out of scope for now.
