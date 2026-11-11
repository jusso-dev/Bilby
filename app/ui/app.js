// Bilby's only script. It asks Rust for screens as HTML, swaps them into
// #screen and routes clicks on [data-action] elements. No inline handlers,
// no third-party code (see docs/adr/0002-frontend-without-npm.md). Every
// word on screen comes from Rust; this file only moves it around.

const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;
const screen = document.getElementById("screen");
const root = document.documentElement;

// Light or dark, remembered on this computer only. Settings (#25) takes
// this over later.
const THEMES = ["light", "dark"];
function applyTheme(theme) {
  if (THEMES.includes(theme)) root.dataset.theme = theme;
}
try {
  applyTheme(localStorage.getItem("bilby-theme"));
} catch {
  // Storage can be unavailable; the system theme is used instead.
}

// Replace the current screen with HTML rendered by a Rust command, then
// move focus to its heading (or a marked button) so screen readers
// announce the new content.
async function show(command, args = {}) {
  screen.innerHTML = await invoke(command, args);
  const target = screen.querySelector("[data-autofocus]") || screen.querySelector("h1");
  (target || screen).focus();
  window.scrollTo(0, 0);
}

// ---------- Progress (#22) ----------

const slowTimers = new Map();
const SLOW_AFTER_MS = 15000;

function word(state) {
  const t = document.getElementById("step-words");
  const el = t && t.content.querySelector(`[data-state="${state}"]`);
  return el ? el.textContent : "";
}

listen("scan-progress", ({ payload }) => {
  const row = screen.querySelector(`.step[data-step="${payload.step}"]`);
  const bar = document.getElementById("scan-bar");
  if (bar) {
    bar.max = payload.total;
    bar.value = payload.done;
  }
  // The torch moves across the photo as each area finishes.
  const scene = screen.querySelector(".scene");
  if (scene && payload.total) scene.style.setProperty("--p", String(payload.done / payload.total));
  const now = document.getElementById("scan-now");
  if (now && payload.state === "running") now.textContent = payload.label;
  if (!row) return;
  // Only text and attribute changes, never a re-render of the list.
  row.dataset.state = payload.state;
  row.querySelector(".step-state").textContent = word(payload.state);
  clearTimeout(slowTimers.get(payload.step));
  const slow = row.querySelector(".step-slow");
  if (payload.state === "running") {
    slowTimers.set(payload.step, setTimeout(() => { slow.hidden = false; }, SLOW_AFTER_MS));
  } else {
    slow.hidden = true;
    // One polite announcement per finished step, not every update.
    const live = document.getElementById("scan-live");
    const name = row.querySelector(".step-name").textContent;
    if (live && payload.state === "done") live.textContent = word("announce").replace("{step}", name);
  }
});

function clearSlowTimers() {
  slowTimers.forEach((t) => clearTimeout(t));
  slowTimers.clear();
}

async function startScan() {
  try {
    await show("render_progress");
    screen.innerHTML = await invoke("start_scan");
  } catch (message) {
    await show("render_home").catch(() => {});
    const status = document.getElementById("scan-status");
    if (status) status.textContent = String(message);
    return;
  } finally {
    clearSlowTimers();
  }
  const h1 = screen.querySelector("h1");
  if (h1) h1.focus();
  window.scrollTo(0, 0);
}

// ---------- Results (#23) ----------

function card(el) {
  return el.closest(".card");
}

// Swap in a new results screen but keep the reader roughly where they were.
async function refreshResults(command, args) {
  const y = window.scrollY;
  try {
    screen.innerHTML = await invoke(command, args);
    window.scrollTo(0, y);
    const h1 = screen.querySelector("h1");
    if (h1) h1.focus({ preventScroll: true });
  } catch (message) {
    const msg = args.findingId && screen.querySelector(`.card[data-finding="${args.findingId}"] .card-message`);
    if (msg) msg.textContent = message;
  }
}

// Click handlers keyed by data-action.
const actions = {
  "start-scan": () => startScan(),
  "cancel-scan": async (button) => {
    button.disabled = true;
    await invoke("cancel_scan");
  },
  "go-home": () => show("render_home"),
  "see-results": () => show("render_last_results"),
  // Asks Windows for administrator permission. If the person agrees this
  // window closes; otherwise Rust returns a calm line to show.
  "deep-check": async (button) => {
    button.disabled = true;
    const message = await invoke("relaunch_elevated");
    const status = document.getElementById("deep-status");
    if (status) status.textContent = message;
    button.disabled = false;
  },
  filter: (button) => {
    const group = button.closest(".filters");
    group.querySelectorAll(".filter").forEach((b) => b.setAttribute("aria-pressed", String(b === button)));
    const list = screen.querySelector(".cards");
    if (list) list.dataset.filter = button.dataset.filter;
  },
  "open-setting": async (button) => {
    const msg = card(button) && card(button).querySelector(".card-message");
    if (msg) msg.textContent = "";
    try {
      await invoke("open_next_step", { findingId: button.dataset.id });
    } catch (message) {
      if (msg) msg.textContent = message;
    }
  },
  "open-rules": () => invoke("open_rules").catch(() => {}),
  talk: (button) => {
    const help = card(button).querySelector(".talk-help");
    help.hidden = !help.hidden;
  },
  "ignore-ask": (button) => {
    const c = card(button);
    c.querySelector(".confirm").hidden = false;
    c.querySelector('[data-action="ignore-yes"]').focus();
  },
  "ignore-no": (button) => {
    const c = card(button);
    c.querySelector(".confirm").hidden = true;
    c.querySelector('[data-action="ignore-ask"]').focus();
  },
  "ignore-yes": (button) => refreshResults("ignore_finding", { findingId: button.dataset.id, note: "" }),
  unignore: (button) => refreshResults("unignore_finding", { findingId: button.dataset.id }),
  "open-settings": () => show("render_settings"),
  "save-key": async (button) => {
    const input = button.closest(".service").querySelector(".key-input");
    // The key is cleared only once Rust has it; a failure keeps it typed.
    if (await refreshScreen("save_key", { service: button.dataset.service, key: input.value })) {
      input.value = "";
    }
  },
  "remove-key": (button) => refreshScreen("remove_key", { service: button.dataset.service }),
  "open-licence": () => invoke("open_key_page", { service: "licence" }).catch(() => {}),
  "open-key-page": (button) => invoke("open_key_page", { service: button.dataset.service }).catch(() => {}),
  "toggle-theme": () => {
    const dark = root.dataset.theme
      ? root.dataset.theme === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    const next = dark ? "light" : "dark";
    applyTheme(next);
    try {
      localStorage.setItem("bilby-theme", next);
    } catch {
      // Not remembered, still applied.
    }
  },
};

// Settings switches: save on change, then show the screen Rust returns.
document.addEventListener("change", (event) => {
  const input = event.target.closest("[data-setting]");
  if (input) refreshScreen("set_online", { name: input.dataset.setting, on: input.checked });
});

// Swap in a fresh copy of the current screen, keeping the scroll position.
// On failure the screen stays and the reason shows in a status line.
async function refreshScreen(command, args) {
  const y = window.scrollY;
  try {
    screen.innerHTML = await invoke(command, args);
    window.scrollTo(0, y);
    return true;
  } catch (message) {
    let status = screen.querySelector("#screen-status");
    if (!status) {
      status = document.createElement("p");
      status.id = "screen-status";
      status.className = "message notice";
      status.setAttribute("role", "status");
      screen.querySelector("h1")?.after(status);
    }
    status.textContent = String(message);
    return false;
  }
}

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  const handler = target && actions[target.dataset.action];
  if (handler) handler(target, event);
});

// After "Check more deeply" the elevated window starts checking at once.
document.addEventListener("DOMContentLoaded", async () => {
  await show("render_home");
  if (screen.querySelector("[data-autostart]")) startScan();
});
