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
      const done = state.stages.filter(stage => stage.status === "completed").length;
      status.textContent = state.status === "running" ? done + " of " + state.stages.length + " steps done" : state.status === "completed" ? "Opening your report" : "Here is what happened";
      error.textContent = state.error || "";
      for (const stage of state.stages) {
        const row = [...document.querySelectorAll("[data-stage]")].find(row => row.dataset.stage === stage.stage);
        if (row) { row.dataset.state = stage.status; row.querySelector("[data-stage-state]").textContent = stage.message; }
      }
      if (state.reportReady) { location.assign(location.pathname + "/report"); return; }
      again = state.status === "running" || state.status === "cleanup-failed";
    } catch {
      error.textContent = "We lost the connection to this scan. It is still running.";
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
    const fix = button.closest("[data-fix]");
    const prompt = fix.querySelector("[data-prompt]");
    const status = fix.querySelector("[data-copy-status]");
    try {
      await navigator.clipboard.writeText(prompt.textContent);
      status.textContent = "Copied";
    } catch {
      prompt.focus();
      const range = document.createRange();
      range.selectNodeContents(prompt);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = "Select the text above and copy it yourself.";
    }
  });
}
`;

export const stylesheet = `
:root {
  color-scheme: light dark;
  --ground: #f4f6f3;
  --surface: #ffffff;
  --sunken: #eef1ed;
  --ink: #14201d;
  --ink-soft: #4c5f59;
  --ink-faint: #6f837c;
  --line: #d9e0da;
  --line-strong: #c1ccc5;
  --accent: #0c5c4d;
  --accent-hover: #084438;
  --accent-ink: #ffffff;
  --alarm: #a3271a;
  --alarm-soft: #fbe9e6;
  --font-ui: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground: #0f1614; --surface: #16201d; --sunken: #121b18;
    --ink: #e9efec; --ink-soft: #a4b4ae; --ink-faint: #82938d;
    --line: #263330; --line-strong: #35443f;
    --accent: #57c9aa; --accent-hover: #7ad9c0; --accent-ink: #06231d;
    --alarm: #f08a76; --alarm-soft: #331a15;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0 auto; max-width: 780px; padding: 24px 24px 72px;
  font-family: var(--font-ui); font-size: 16px; line-height: 1.6;
  color: var(--ink); background: var(--ground);
}
header { display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap; padding-bottom: 16px; border-bottom: 1px solid var(--line); }
header a { font-weight: 700; font-size: 17px; letter-spacing: -.02em; text-decoration: none; color: var(--ink); }
header span { color: var(--ink-faint); font-size: 13px; }
main { padding: 40px 0 0; }
h1 { font-size: clamp(1.6rem, 4vw, 2.1rem); line-height: 1.2; letter-spacing: -.02em; margin: 0; text-wrap: balance; }
h2 { font-size: 1.1rem; line-height: 1.3; margin: 0; letter-spacing: -.01em; }
p { margin: 12px 0 0; }
a { color: var(--accent); text-underline-offset: 3px; }
code { font-family: var(--font-mono); font-size: .85em; overflow-wrap: anywhere; }
.eyebrow { font-family: var(--font-mono); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--ink-faint); margin: 0 0 10px; }
.lead { color: var(--ink-soft); font-size: 17px; max-width: 60ch; }
.quiet { color: var(--ink-faint); font-size: 13.5px; }
ul.plain { list-style: none; margin: 12px 0 0; padding: 0; display: grid; gap: 8px; }
ul.plain li { color: var(--ink-soft); font-size: 14.5px; padding-left: 18px; position: relative; overflow-wrap: anywhere; }
ul.plain li::before { content: "—"; position: absolute; left: 0; color: var(--ink-faint); }

label { display: block; font-weight: 600; margin-top: 28px; }
input { width: 100%; padding: 12px; margin-top: 8px; font: inherit; font-family: var(--font-mono); font-size: 14px; color: var(--ink); background: var(--surface); border: 1px solid var(--line-strong); border-radius: 6px; }
#input-help { color: var(--ink-faint); font-size: 13.5px; }
button { min-height: 44px; margin-top: 12px; padding: 10px 20px; font: inherit; font-weight: 600; color: var(--accent-ink); background: var(--accent); border: 0; border-radius: 6px; cursor: pointer; }
button:hover { background: var(--accent-hover); }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
[role=alert]:not(:empty) { margin-top: 20px; padding: 12px 16px; border-radius: 6px; color: var(--alarm); background: var(--alarm-soft); }
[data-retry] { background: transparent; color: var(--ink); border: 1px solid var(--line-strong); }
[data-retry]:hover { background: var(--sunken); }
.split { display: grid; gap: 28px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); margin-top: 44px; }

ol.stages { list-style: none; margin: 28px 0 0; padding: 0; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); }
ol.stages li { display: grid; grid-template-columns: 16px 1fr; gap: 2px 12px; padding: 12px 18px; border-bottom: 1px solid var(--line); }
ol.stages li::before { content: ""; grid-row: 1 / span 2; align-self: center; justify-self: center; width: 8px; height: 8px; border-radius: 50%; background: var(--line-strong); }
ol.stages li[data-state="completed"]::before { background: var(--accent); }
ol.stages li[data-state="running"]::before { background: var(--accent); animation: blink 1.4s ease-in-out infinite; }
ol.stages li[data-state="failed"]::before { background: var(--alarm); }
ol.stages li[data-state="waiting"] strong { color: var(--ink-faint); font-weight: 500; }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: .25; } }
@media (prefers-reduced-motion: reduce) { ol.stages li[data-state="running"]::before { animation: none; } }
ol.stages li:last-child { border-bottom: 0; }
ol.stages strong { font-weight: 600; font-size: 15px; }
[data-stage-state] { color: var(--ink-soft); font-size: 13.5px; }

article[data-fix] { margin-top: 20px; padding: 20px 22px; background: var(--surface); border: 1px solid var(--line); border-radius: 11px; }
article[data-fix]:not([open]) { padding: 0; }
article[data-fix]:not([open]) > details > summary { padding: 14px 22px; }
.where { color: var(--ink-faint); font-size: 13.5px; margin-top: 4px; }
.why { color: var(--ink-soft); max-width: 62ch; }
dl.what { display: grid; grid-template-columns: 96px 1fr; gap: 6px 16px; margin: 18px 0 0; font-size: 15px; }
dl.what dt { font-family: var(--font-mono); font-size: 11px; letter-spacing: .07em; text-transform: uppercase; color: var(--ink-faint); padding-top: 4px; }
dl.what dd { margin: 0; max-width: 60ch; }
@media (max-width: 620px) { dl.what { grid-template-columns: 1fr; } dl.what dd { margin-bottom: 8px; } }

.prompt { margin-top: 20px; padding: 14px; background: var(--sunken); border: 1px solid var(--line); border-radius: 8px; }
.prompt .label { margin: 0 0 8px; font-family: var(--font-mono); font-size: 11px; letter-spacing: .07em; text-transform: uppercase; color: var(--ink-faint); }
.prompt pre { margin: 0; padding: 0; max-height: 220px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font-family: var(--font-mono); font-size: 12.5px; line-height: 1.65; }
.prompt button { margin-top: 12px; min-height: 36px; padding: 6px 14px; font-size: 14px; }
[data-copy-status]:not(:empty) { margin-left: 10px; font-size: 13px; color: var(--ink-faint); }

details.tech { margin-top: 18px; }
details.tech > summary { cursor: pointer; font-size: 13.5px; color: var(--ink-faint); }
details.tech > summary:hover { color: var(--ink); }
details.tech ul.plain, details.tech p { font-size: 13px; }
section.after { margin-top: 52px; padding-top: 24px; border-top: 1px solid var(--line); }
section.after p { color: var(--ink-soft); font-size: 14.5px; }
footer { margin-top: 48px; padding-top: 18px; border-top: 1px solid var(--line); color: var(--ink-faint); font-size: 13px; }
[hidden] { display: none !important; }
@media (max-width: 600px) { body { padding: 16px 16px 56px; } main { padding-top: 28px; } article[data-fix] { padding: 16px; } }
`;
