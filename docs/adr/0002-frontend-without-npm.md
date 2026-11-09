# 0002: Frontend without npm

Date: 2026-11-09. Status: Accepted.

## Context

Justin doesn't want a JavaScript dependency tree. An npm `node_modules` folder for a typical framework pulls in hundreds of packages, any of which can run install scripts or ship a compromised update. Bilby's interface is also simple: a home screen, a progress screen, results, a detail view, settings and a report preview.

Options were:

1. A Rust WebAssembly frontend (Leptos, Dioxus or Yew), built with Trunk.
2. Plain HTML and CSS rendered from Rust with Askama, plus a small hand-written JavaScript file.
3. A pure Rust GUI with no webview (see ADR 0001).

## Decision

Option 2.

- Screens and fragments are Askama templates in `app/src-tauri/templates/`, rendered by Tauri commands and returned as HTML strings. Askama's auto-escaping is on for every template.
- `app/ui/` holds `index.html`, `app.css` and `app.js`. No build step. No bundler. No npm, no Node, no `package.json`.
- `app.js` is plain ES2022, loaded as a module, under 300 lines, and does three jobs: call commands through `window.__TAURI__.core.invoke` (`withGlobalTauri: true`), swap returned HTML into the page, and manage focus after a swap.
- Strict CSP with no inline script or style. Event handlers are bound in `app.js` using `data-action` attributes, never `onclick=` in markup.
- Fonts and icons are vendored files with their licences recorded in `NOTICE`. Icons are inline SVG in templates.

## Consequences

- All user-facing logic and copy live in Rust, where they're unit tested. Templates can be snapshot tested with `insta`.
- Semantic HTML gives screen readers, keyboard support and text scaling for free, which matters more here than for most apps.
- The only JavaScript to review is one short file.
- Fewer interactive widgets than a framework would offer. That's fine for Bilby's screens.
- Progress updates during a scan come through Tauri events (`window.__TAURI__.event.listen`), handled in `app.js`.

## Alternatives considered

- **Leptos (CSR via Trunk).** No npm either, and a good choice. Rejected because it adds a wasm32 target, Trunk, `wasm-bindgen` and a second large crate tree to audit, for screens that don't need client-side state. It also moves copy and rendering into wasm where screen reader testing is the same but debugging is harder.
- **Dioxus desktop.** Its own renderer and CLI, more moving parts than Bilby needs.
- **htmx.** Small, but still a vendored third-party script. The few lines it would save aren't worth it.
