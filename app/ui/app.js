// Bilby's only script. It asks Rust for screens as HTML, swaps them into
// #screen and routes clicks on [data-action] elements. No inline handlers,
// no third-party code (see docs/adr/0002-frontend-without-npm.md).

const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;
const screen = document.getElementById("screen");

// Progress from the scan: Rust sends the words, this only shows them.
listen("scan-progress", (event) => {
  const status = document.getElementById("scan-status");
  if (status) status.textContent = event.payload.label;
});

// Replace the current screen with HTML rendered by a Rust command, then move
// focus to it so screen readers announce the new content.
async function show(command, args = {}) {
  screen.innerHTML = await invoke(command, args);
  screen.focus();
}

// Click handlers keyed by data-action. Filled in as screens land.
const actions = {
  // Placeholder until the progress screen (#22): disable the button while
  // the scan runs, then show whatever screen Rust returns.
  "start-scan": async (button) => {
    button.disabled = true;
    const cancel = screen.querySelector('[data-action="cancel-scan"]');
    if (cancel) cancel.hidden = false;
    try {
      await show("start_scan");
    } catch (message) {
      button.disabled = false;
      if (cancel) cancel.hidden = true;
      const status = document.getElementById("scan-status");
      if (status) status.textContent = message;
    }
  },
  "cancel-scan": async (button) => {
    button.disabled = true;
    await invoke("cancel_scan");
  },
  // Asks Windows for administrator permission. If the person agrees this
  // window closes; otherwise Rust returns a calm line to show.
  "deep-check": async (button) => {
    button.disabled = true;
    const message = await invoke("relaunch_elevated");
    const status = document.getElementById("deep-status");
    if (status) status.textContent = message;
    button.disabled = false;
  },
};

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  const handler = target && actions[target.dataset.action];
  if (handler) handler(target, event);
});

// After "Check more deeply" the elevated window starts checking at once.
document.addEventListener("DOMContentLoaded", async () => {
  await show("render_home");
  const start = screen.querySelector('[data-autostart] [data-action="start-scan"]');
  if (start) actions["start-scan"](start);
});
