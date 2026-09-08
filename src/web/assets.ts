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
      status.textContent = state.status === "waiting" ? "Someone else's scan is finishing. Yours starts on its own, and this page will follow it." : state.status === "running" ? done + " of " + state.stages.length + " steps done" : state.status === "completed" ? "Opening your report" : "Here is what happened";
      error.textContent = state.error || "";
      for (const stage of state.stages) {
        const row = [...document.querySelectorAll("[data-stage]")].find(row => row.dataset.stage === stage.stage);
        if (row) { row.dataset.state = stage.status; row.querySelector("[data-stage-state]").textContent = stage.message; }
      }
      if (state.reportReady) { location.assign(location.pathname + "/report"); return; }
      again = state.status === "waiting" || state.status === "running" || state.status === "cleanup-failed";
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
  --ground: #f3f4f7;
  --surface: #ffffff;
  --sunken: #f6f7fa;
  --ink: #16181d;
  --ink-soft: #4a4f5c;
  --ink-faint: #787f8e;
  --line: #e5e7ee;
  --accent: #4f46e5;
  --accent-hover: #4338ca;
  --accent-ink: #ffffff;
  --accent-soft: #eef0fe;
  --alarm: #b42318;
  --alarm-soft: #fef3f2;
  --lift: 0 1px 2px rgba(22, 24, 29, .04), 0 12px 28px -22px rgba(22, 24, 29, .5);
  --round: 14px;
  --font-ui: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground: #0f1117; --surface: #171a22; --sunken: #1c202a;
    --ink: #e8eaf2; --ink-soft: #a3a9ba; --ink-faint: #7b8296;
    --line: #262a36;
    --accent: #9c97ff; --accent-hover: #b3aeff; --accent-ink: #14122b; --accent-soft: #1e1f3a;
    --alarm: #f49e93; --alarm-soft: #2a1614;
    --lift: 0 1px 2px rgba(0, 0, 0, .4), 0 12px 30px -24px rgba(0, 0, 0, .9);
  }
}
* { box-sizing: border-box; }
body {
  margin: 0 auto; max-width: 680px; padding: 20px 20px 80px;
  font-family: var(--font-ui); font-size: 16px; line-height: 1.55;
  color: var(--ink); background: var(--ground);
  -webkit-font-smoothing: antialiased;
}
header { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 8px 0 32px; }
header a { display: flex; align-items: center; gap: 9px; font-weight: 650; font-size: 16px; letter-spacing: -.01em; text-decoration: none; color: var(--ink); }
header a::before { content: ""; width: 20px; height: 20px; border-radius: 7px; background: var(--accent); }
header span { color: var(--ink-faint); font-size: 13px; }
main { display: block; }
h1 { font-size: clamp(1.75rem, 5vw, 2.15rem); line-height: 1.15; letter-spacing: -.025em; font-weight: 700; margin: 0; text-wrap: balance; }
h2 { font-size: 1.06rem; line-height: 1.35; margin: 0; font-weight: 650; letter-spacing: -.01em; }
p { margin: 14px 0 0; }
a { color: var(--accent); text-underline-offset: 3px; }
.eyebrow { font-size: 12px; font-weight: 650; letter-spacing: .09em; text-transform: uppercase; color: var(--accent); margin: 0 0 12px; }
.lead { color: var(--ink-soft); font-size: 17px; max-width: 46ch; }
.quiet { color: var(--ink-faint); font-size: 13.5px; }
ul.plain { list-style: none; margin: 12px 0 0; padding: 0; display: grid; gap: 9px; }
ul.plain li { color: var(--ink-soft); font-size: 14.5px; padding-left: 18px; position: relative; overflow-wrap: anywhere; }
ul.plain li::before { content: ""; position: absolute; left: 0; top: .62em; width: 5px; height: 5px; border-radius: 50%; background: var(--line); }

button {
  min-height: 46px; margin-top: 14px; padding: 12px 22px; font: inherit; font-weight: 650;
  color: var(--accent-ink); background: var(--accent); border: 0; border-radius: 10px; cursor: pointer;
}
button:hover { background: var(--accent-hover); }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; border-radius: 6px; }
label { display: block; font-weight: 650; margin-top: 32px; }
input {
  width: 100%; padding: 14px 16px; margin-top: 10px; font: inherit; font-size: 15px;
  color: var(--ink); background: var(--surface); border: 1px solid var(--line);
  border-radius: 12px; box-shadow: var(--lift);
}
input:focus { outline: 2px solid var(--accent); outline-offset: 1px; border-color: transparent; }
#input-help { color: var(--ink-faint); font-size: 13.5px; }
[role=alert]:not(:empty) {
  margin-top: 20px; padding: 14px 18px; border-radius: 12px;
  color: var(--alarm); background: var(--alarm-soft); font-size: 15px;
}
[data-retry] { background: var(--surface); color: var(--ink); box-shadow: var(--lift); }
[data-retry]:hover { background: var(--sunken); }
.split { display: grid; gap: 26px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); margin-top: 48px; }

ol.stages { list-style: none; margin: 30px 0 0; padding: 8px; border-radius: var(--round); background: var(--surface); box-shadow: var(--lift); }
ol.stages li { display: grid; grid-template-columns: 18px 1fr; gap: 1px 12px; padding: 11px 14px; border-radius: 10px; }
ol.stages li::before { content: ""; grid-row: 1 / span 2; align-self: center; justify-self: center; width: 9px; height: 9px; border-radius: 50%; background: var(--line); }
ol.stages li[data-state="completed"]::before { background: var(--accent); }
ol.stages li[data-state="running"]::before { background: var(--accent); animation: blink 1.5s ease-in-out infinite; }
ol.stages li[data-state="running"] { background: var(--accent-soft); }
ol.stages li[data-state="failed"]::before { background: var(--alarm); }
ol.stages li[data-state="waiting"] strong { color: var(--ink-faint); font-weight: 500; }
ol.stages strong { font-weight: 600; font-size: 15px; }
[data-stage-state] { color: var(--ink-soft); font-size: 13.5px; }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: .3; } }
@media (prefers-reduced-motion: reduce) { ol.stages li[data-state="running"]::before { animation: none; } }

article[data-fix] { margin-top: 16px; padding: 24px; background: var(--surface); border-radius: var(--round); box-shadow: var(--lift); }
article[data-fix]:not([open]) { padding: 4px 8px; }
article[data-fix]:not([open]) > details > summary { padding: 14px 16px; font-size: 15px; color: var(--ink); font-weight: 600; }
.where { color: var(--ink-faint); font-size: 13.5px; margin-top: 6px; }
.why { color: var(--ink-soft); max-width: 48ch; }
.todo { color: var(--ink); max-width: 48ch; font-weight: 500; }
.act { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
[data-copy-status]:not(:empty) { margin-top: 14px; font-size: 14px; color: var(--accent); font-weight: 600; }

details.tech { margin-top: 16px; }
details.tech + details.tech { margin-top: 8px; }
details.tech > summary { cursor: pointer; font-size: 13.5px; color: var(--ink-faint); width: fit-content; }
details.tech > summary:hover { color: var(--ink); }
details.tech ul.plain li, details.tech p { font-size: 13px; }
code { font-family: var(--font-mono); font-size: .85em; overflow-wrap: anywhere; }
pre {
  margin: 12px 0 0; padding: 16px; max-height: 240px; overflow: auto;
  white-space: pre-wrap; overflow-wrap: anywhere; border-radius: 12px;
  background: var(--sunken); color: var(--ink-soft);
  font-family: var(--font-mono); font-size: 12.5px; line-height: 1.6;
}
section.after { margin-top: 56px; }
section.after p { color: var(--ink-soft); font-size: 14.5px; }
footer { margin-top: 56px; color: var(--ink-faint); font-size: 13px; }
[hidden] { display: none !important; }
@media (max-width: 600px) { body { padding: 14px 14px 60px; } article[data-fix] { padding: 20px; } }
`;
