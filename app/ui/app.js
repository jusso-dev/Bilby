// Bilby's only script. It asks Rust for screens as HTML, swaps them into
// #screen and routes clicks on [data-action] elements. No inline handlers,
// no third-party code (see docs/adr/0002-frontend-without-npm.md).

const invoke = window.__TAURI__.core.invoke;
const screen = document.getElementById("screen");

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
    try {
      await show("start_scan");
    } catch (message) {
      button.disabled = false;
      button.insertAdjacentText("afterend", ` ${message}`);
    }
  },
};

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  const handler = target && actions[target.dataset.action];
  if (handler) handler(target, event);
});

document.addEventListener("DOMContentLoaded", () => {
  show("render_home");
});
