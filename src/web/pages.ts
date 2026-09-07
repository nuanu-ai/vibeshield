import type { Issue, Report, Stage } from "../scan/contracts.js";
import type { Job } from "./jobs.js";

const labels: Record<Stage, string> = {
  prepare: "Prepare scan environment",
  acquire: "Fetch repository",
  gitleaks: "Check exposed credentials",
  opengrep: "Check code security",
  osv: "Check dependency advisories",
  trivy: "Check infrastructure configuration",
  zizmor: "Check GitHub Actions",
  report: "Prepare report",
  cleanup: "Remove temporary resources",
};
function escapeHtml(value: string | number): string {
  return String(value).replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char,
  );
}
function page(title: string, body: string, progress = false): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)} · VibeShield</title><link rel="stylesheet" href="/assets/app.css"><script src="/assets/app.js" defer></script></head><body${progress ? " data-progress" : ""}><header><a href="/">VibeShield</a><span>Private repository security checks</span></header><main>${body}</main><footer>This scan does not run your app. Authorization logic and runtime behavior are not checked.</footer></body></html>`;
}
export function renderHome(error?: string): string {
  return page(
    "Scan a repository",
    `<h1>Find important security problems in your repository</h1><p>Submit a public GitHub repository. Get the findings, check coverage, and concrete prompts for your coding agent.</p>${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}<form action="/scans" method="post"><label for="repository">GitHub repository</label><input id="repository" name="repository" type="url" required placeholder="https://github.com/owner/repo" autocomplete="url" aria-describedby="input-help"><p id="input-help">Use the repository root URL. We scan its default branch.</p><button type="submit">Scan</button></form><p>One scan at a time. Results expire after one hour and are cleared when this service restarts.</p>`,
  );
}
export function renderProgress(job: Job): string {
  return page(
    "Scan progress",
    `<h1>Scan progress</h1><p>${escapeHtml(job.url)}</p><p role="status" data-status>${job.status === "running" ? "Running" : job.status === "completed" ? "Completed" : "Scan needs attention"}</p><p data-error role="alert">${escapeHtml(job.error ?? "")}</p><button type="button" data-retry hidden>Retry status</button><ol data-stages>${job.stages.map((entry) => `<li data-stage="${escapeHtml(entry.stage)}"><strong>${escapeHtml(labels[entry.stage])}</strong><span data-stage-state>${escapeHtml(entry.status)} — ${escapeHtml(entry.message)}</span></li>`).join("")}</ol><p>You can reload this page while the scan runs.</p><a href="/">Start another scan</a>`,
    true,
  );
}
function issueBody(issue: Issue): string {
  return `<p>${escapeHtml(issue.why)}</p><h3>Evidence</h3><ul>${issue.locations.map((location) => `<li><code>${escapeHtml(location.path)}:${escapeHtml(location.line)}</code>${location.commit ? ` (commit ${escapeHtml(location.commit)})` : ""}</li>`).join("")}</ul>${issue.evidence.map((evidence) => `<p>${escapeHtml(evidence)}</p>`).join("")}<h3>What to fix</h3><p>${escapeHtml(issue.remediation)}</p><h3>How to verify</h3><p>${escapeHtml(issue.verification)}</p><h3>Prompt for your coding agent</h3><pre data-prompt tabindex="0">${escapeHtml(issue.prompt)}</pre><button type="button" data-copy>Copy prompt</button><p role="status" data-copy-status></p>`;
}
export function renderReport(report: Report): string {
  const summary = report.issues.length
    ? `${report.issues.length} important ${report.issues.length === 1 ? "issue" : "issues"}`
    : report.incomplete
      ? "Scan incomplete"
      : "No important problems found by the completed checks";
  return page(
    "Repository report",
    `<h1>${escapeHtml(summary)}</h1><p>${escapeHtml(report.repository.url)}</p><p>Commit <code>${escapeHtml(report.repository.commit)}</code></p><p>Generated ${escapeHtml(report.generatedAt)}</p>${report.incomplete && report.issues.length ? "<h2>Scan incomplete</h2><p>Some applicable checks did not complete fully. Findings below remain useful; review the coverage limits.</p>" : ""}${report.issues.map((issue, index) => `${index === 5 ? `<p>${escapeHtml(report.issues.length - 5)} more important issues</p>` : ""}<details data-issue${index < 5 ? " open" : ""}><summary><span>${escapeHtml(issue.severity)}</span> ${escapeHtml(issue.title)}</summary>${issueBody(issue)}</details>`).join("")}<h2>Check coverage</h2><ul class="coverage">${report.coverage.map((entry) => `<li><strong>${escapeHtml(entry.scanner)} · ${escapeHtml(entry.area)}</strong><span>${escapeHtml(entry.status)}${entry.applicable ? "" : " · not applicable"}</span><p>${escapeHtml(entry.reason)}</p></li>`).join("")}</ul><p>Inspected ${escapeHtml(report.repository.history.commits)} fetched commits${report.repository.history.truncated ? "; older history was not fetched" : ""}.</p><details><summary>Scanner provenance</summary><p>Image: ${escapeHtml(report.provenance.image)}</p><p>Rules revision: ${escapeHtml(report.provenance.rulesRevision)}</p><ul>${Object.entries(
      report.provenance.tools,
    )
      .map(([tool, version]) => `<li>${escapeHtml(tool)}: ${escapeHtml(version)}</li>`)
      .join(
        "",
      )}${report.provenance.advisoryData.map((data) => `<li>${escapeHtml(data.source)}: ${escapeHtml(data.retrievedAt)}${data.revision ? ` · ${escapeHtml(data.revision)}` : ""}${data.stale ? " · stale" : ""}</li>`).join("")}</ul></details><p><a href="/">Start another scan</a></p>`,
  );
}
export function renderUnavailable(): string {
  return page(
    "Result unavailable",
    '<h1>This result is no longer available</h1><p>It may have expired, been removed to make room for newer results, or belonged to a previous service session.</p><a href="/">Start another scan</a>',
  );
}
