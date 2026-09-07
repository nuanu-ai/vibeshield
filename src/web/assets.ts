import { LIMITS } from "../scan/limits.js";

export const browserScript = `"use strict";
if (document.body.hasAttribute("data-progress")) {
  const status = document.querySelector("[data-status]");
  const error = document.querySelector("[data-error]");
  const retry = document.querySelector("[data-retry]");
  let pending = false;
  let timer;
  async function refreshStatus() {
    if (pending) return;
    clearTimeout(timer);
    pending = true;
    retry.hidden = true;
    let again = false;
    try {
      const response = await fetch(location.pathname + "/status", { cache: "no-store" });
      if (response.status === 404) { location.reload(); return; }
      if (!response.ok) throw new Error();
      const state = await response.json();
      status.textContent = state.status === "running" ? "Running" : state.status === "completed" ? "Completed" : "Scan needs attention";
      error.textContent = state.error || "";
      for (const stage of state.stages) {
        const row = [...document.querySelectorAll("[data-stage]")].find(row => row.dataset.stage === stage.stage);
        if (row) row.querySelector("[data-stage-state]").textContent = stage.status + " — " + stage.message;
      }
      if (state.reportReady) { location.assign(location.pathname + "/report"); return; }
      again = state.status === "running" || state.status === "cleanup-failed";
    } catch {
      error.textContent = "Progress is temporarily unavailable. Retry to reconnect to this scan.";
      retry.hidden = false;
    } finally {
      pending = false;
      if (again) timer = setTimeout(refreshStatus, ${LIMITS.pollMs});
    }
  }
  retry.addEventListener("click", refreshStatus);
  refreshStatus();
}
for (const button of document.querySelectorAll("[data-copy]")) {
  button.addEventListener("click", async () => {
    const issue = button.closest("[data-issue]");
    const prompt = issue.querySelector("[data-prompt]");
    const status = issue.querySelector("[data-copy-status]");
    try {
      await navigator.clipboard.writeText(prompt.textContent);
      status.textContent = "Copied prompt.";
    } catch {
      prompt.focus();
      const range = document.createRange();
      range.selectNodeContents(prompt);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = "Select and copy the prompt above with your keyboard or context menu.";
    }
  });
}
`;

export const stylesheet = `
:root { color-scheme: light; font-family: system-ui, sans-serif; color: #172c2b; background: #f7f8f5; line-height: 1.6; }
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 920px; padding: 24px; }
header { display: flex; justify-content: space-between; gap: 20px; flex-wrap: wrap; border-bottom: 1px solid #bdc9c5; padding-bottom: 18px; }
header a { font-weight: 750; font-size: 1.3rem; }
main { padding: 36px 0; }
h1 { font-size: clamp(1.8rem, 4vw, 2.5rem); line-height: 1.2; max-width: 760px; }
h2 { margin-top: 36px; } h3 { font-size: 1rem; margin-bottom: 4px; }
a { color: #005e53; text-underline-offset: 3px; }
label { display: block; font-weight: 650; }
input { width: 100%; padding: 12px; margin-top: 8px; font: inherit; border: 1px solid #607b75; border-radius: 5px; }
button { min-height: 44px; padding: 10px 20px; font: inherit; font-weight: 650; color: white; background: #075d50; border: 0; border-radius: 5px; cursor: pointer; }
button:hover { background: #03463c; }
:focus-visible { outline: 3px solid #bc5800; outline-offset: 4px; }
[role=alert]:not(:empty) { border-left: 4px solid #a04412; padding: 12px; background: #fff2e5; }
[data-status] { font-size: 1.15rem; font-weight: 650; }
li { margin: 12px 0; } [data-stage-state], .coverage span { display: block; }
details { background: white; border: 1px solid #bdc9c5; border-radius: 6px; margin: 18px 0; padding: 18px; }
summary { cursor: pointer; font-size: 1.1rem; font-weight: 650; overflow-wrap: anywhere; }
summary span { text-transform: uppercase; font-size: .8rem; color: #934010; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; padding: 16px; background: #edf3f0; border: 1px solid #bdc9c5; border-radius: 4px; font: .9rem/1.65 ui-monospace, monospace; user-select: text; }
code, p, li { overflow-wrap: anywhere; }
footer { border-top: 1px solid #bdc9c5; padding: 18px 0; color: #445d57; }
[hidden] { display: none !important; }
@media (max-width: 600px) { body { padding: 16px; } main { padding: 20px 0; } details { padding: 14px; } }
`;
