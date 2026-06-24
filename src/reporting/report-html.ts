/**
 * Shared HTML report kit for VibeShield.
 *
 * One source of truth for the owner-facing report shell, CSS, and components,
 * so the Quick Scan and Deep Static reports look and read the same. Quick Scan
 * composes the verdict, stats, action cards, and coverage; Deep Static reuses
 * all of that and adds the "Likely attack paths" section.
 */

import type { Verdict } from "../domain/assessment.js";
import { verdictLabel } from "../domain/assessment.js";
import type { CoverageEntry } from "../domain/coverage-summary.js";
import type { DeepCoverageEntry } from "../domain/deep-coverage.js";
import type { HypothesisEnrichment } from "../domain/hypothesis-enrichment.js";
import type { RankedAction, SecurityAssessment } from "../domain/security-assessment.js";
import type { StaticHypothesis } from "../domain/static-hypothesis.js";
import type { ValidationRecipe } from "../domain/validation-recipe.js";

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

export function repositoryName(assessment: SecurityAssessment): string {
  const name = assessment.repository.name.trim();
  return name.length > 0 ? name : "this repository";
}

// Owner-facing wrapper: doctype, head + shared CSS, brand header, sections, and
// a muted footer. Callers pass already-rendered section HTML in display order.
export function renderReportDocument(input: {
  readonly repoName: string;
  readonly brandSub: string;
  readonly sections: ReadonlyArray<string>;
  readonly footerMeta: string;
}): string {
  const repo = escapeHtml(input.repoName);
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>VibeShield — ${repo}</title>`,
    `<style>${REPORT_CSS}</style>`,
    "</head>",
    "<body>",
    "<main>",
    '<header class="head">',
    `<div class="brand"><span class="dot"></span>VibeShield <span class="brand-sub">${escapeHtml(
      input.brandSub,
    )}</span></div>`,
    `<h1>${repo}</h1>`,
    "</header>",
    ...input.sections,
    `<footer class="foot">${escapeHtml(input.footerMeta)}</footer>`,
    "</main>",
    `<script>${COPY_SCRIPT}</script>`,
    "</body></html>",
  ].join("");
}

export function verdictBannerHtml(assessment: SecurityAssessment): string {
  return [
    `<section class="verdict verdict--${verdictHtmlClass(assessment.verdict)}">`,
    `<div class="verdict-label">${escapeHtml(verdictLabel(assessment.verdict))}</div>`,
    `<div class="verdict-sub">${escapeHtml(verdictSubline(assessment))}</div>`,
    "</section>",
  ].join("");
}

export function statsHtml(
  items: ReadonlyArray<{ readonly value: string; readonly label: string }>,
): string {
  const cells = items
    .map(
      (item) =>
        `<div class="stat"><b>${escapeHtml(item.value)}</b><span>${escapeHtml(item.label)}</span></div>`,
    )
    .join("");
  return `<div class="stats">${cells}</div>`;
}

export function noteHtml(text: string): string {
  return `<p class="note">${escapeHtml(text)}</p>`;
}

export function sectionHeadingHtml(title: string, lede?: string): string {
  const ledeHtml = lede === undefined ? "" : `<p class="lede">${escapeHtml(lede)}</p>`;
  return `<h2>${escapeHtml(title)}</h2>${ledeHtml}`;
}

export function footerMetaLine(assessment: SecurityAssessment): string {
  const commit = assessment.repository.commitSha ?? assessment.manifest.commitSha;
  return [
    `Generated ${assessment.generatedAt.replace("T", " ").slice(0, 16)}`,
    commit !== undefined && commit !== null
      ? `commit ${commit.length <= 12 ? commit : commit.slice(0, 12)}`
      : undefined,
    "VibeShield",
  ]
    .filter((part): part is string => part !== undefined)
    .join(" · ");
}

// One fix as a card: plain problem + "why now" + the agent prompt as the hero,
// human-only steps surfaced, and the technical detail tucked into a disclosure.
export function actionCardHtml(
  rank: number,
  ranked: RankedAction,
  assessment: SecurityAssessment,
): string {
  const { remediation } = ranked;
  const severity = actionSeverity(ranked, assessment);
  const locations = actionLocationsForReport(ranked, assessment);
  const whereHtml =
    locations.length > 0
      ? locations.map((value) => `<code>${escapeHtml(value)}</code>`).join(" ")
      : "across the repository";
  const ops =
    remediation.operationalSteps.length > 0
      ? `<div class="ops"><strong>You'll need to do this yourself (your agent can't):</strong>${htmlList(
          remediation.operationalSteps,
        )}</div>`
      : "";
  const details = [
    `<dl class="facts"><dt>Where</dt><dd>${whereHtml}</dd></dl>`,
    renderHtmlList("Or change it by hand", remediation.fixSteps),
    renderHtmlList("Check it worked", remediation.verifySteps),
  ].join("");
  return [
    '<article class="action">',
    '<div class="action-head">',
    `<span class="rank">${rank}</span>`,
    `<h3>${escapeHtml(remediation.title)}</h3>`,
    severity === undefined
      ? ""
      : `<span class="pill pill--${escapeHtml(severity)}">${escapeHtml(severityLabel(severity))}</span>`,
    "</div>",
    `<p class="risk">${escapeHtml(remediation.risk)}</p>`,
    `<p class="why"><strong>Why now:</strong> ${escapeHtml(remediation.whyFixNow)}</p>`,
    promptBlockHtml(remediation.agentPrompt),
    ops,
    `<details class="more"><summary>Technical details</summary>${details}</details>`,
    "</article>",
  ].join("");
}

// One attack path as a card: plain "what could happen" + confidence, the agent
// prompt to fix it, and a disclosure with how to confirm it. No graph ids, no
// raw statuses - those stay in report.json.
export function attackPathCardHtml(
  rank: number,
  hypothesis: StaticHypothesis,
  enrichment: HypothesisEnrichment | undefined,
  recipe: ValidationRecipe | undefined,
): string {
  const description = enrichment?.attackDescription ?? hypothesis.pathSummary;
  const impact = enrichment?.impact;
  const runtimePill = hypothesis.runtimeValidationRequired
    ? '<span class="pill pill--check">Needs a runtime check</span>'
    : "";
  const howToConfirm = confirmDetailsHtml(hypothesis, enrichment, recipe);
  return [
    '<article class="action">',
    '<div class="action-head">',
    `<span class="rank">${rank}</span>`,
    `<h3>${escapeHtml(hypothesis.title)}</h3>`,
    `<span class="pill pill--conf-${confidenceClass(hypothesis.staticConfidence)}">${escapeHtml(
      confidenceLabel(hypothesis.staticConfidence),
    )}</span>`,
    runtimePill,
    "</div>",
    `<p class="risk">${escapeHtml(description)}</p>`,
    impact === undefined || impact.trim() === ""
      ? ""
      : `<p class="why"><strong>If real, the impact:</strong> ${escapeHtml(impact)}</p>`,
    enrichment === undefined ? "" : promptBlockHtml(enrichment.agentPrompt),
    howToConfirm,
    "</article>",
  ].join("");
}

function confirmDetailsHtml(
  hypothesis: StaticHypothesis,
  enrichment: HypothesisEnrichment | undefined,
  recipe: ValidationRecipe | undefined,
): string {
  const parts: string[] = [];
  parts.push(`<p class="muted-line">Static path: ${escapeHtml(hypothesis.pathSummary)}</p>`);
  if (recipe !== undefined) {
    parts.push(renderHtmlList("What you'd need", recipe.requiredFixtures));
    parts.push(renderOrderedHtmlList("How to check it", recipe.steps));
    parts.push(`<p class="muted-line">Expected if safe: ${escapeHtml(recipe.expectedResult)}</p>`);
  } else if (enrichment !== undefined && enrichment.validationRecipeText.trim() !== "") {
    parts.push(`<p class="muted-line">${escapeHtml(enrichment.validationRecipeText)}</p>`);
  }
  return `<details class="more"><summary>How to confirm this</summary>${parts.join("")}</details>`;
}

function promptBlockHtml(prompt: string): string {
  return [
    '<div class="prompt">',
    '<div class="prompt-head"><span>Prompt for your coding agent</span><button class="copy" type="button">Copy</button></div>',
    '<p class="prompt-hint">Copy this whole block into your coding agent.</p>',
    `<pre>${escapeHtml(prompt)}</pre>`,
    "</div>",
  ].join("");
}

// Collapsed "what was checked" with friendly check names and status pills. Quick
// Scan checks and Deep Static areas render the same way.
export function coverageDetailsHtml(
  summary: string,
  rows: ReadonlyArray<{
    readonly label: string;
    readonly statusClass: string;
    readonly statusLabel: string;
    readonly note: string;
  }>,
): string {
  if (rows.length === 0) {
    return "";
  }
  const body = rows
    .map(
      (row) =>
        `<tr><td>${escapeHtml(row.label)}</td><td><span class="status status--${row.statusClass}">${escapeHtml(
          row.statusLabel,
        )}</span></td><td>${escapeHtml(row.note)}</td></tr>`,
    )
    .join("");
  return [
    '<details class="coverage">',
    `<summary>${escapeHtml(summary)}</summary>`,
    "<table><thead><tr><th>Check</th><th>Status</th><th>Notes</th></tr></thead>",
    `<tbody>${body}</tbody></table>`,
    "</details>",
  ].join("");
}

export function coverageRowFromQuickCheck(entry: CoverageEntry): {
  label: string;
  statusClass: string;
  statusLabel: string;
  note: string;
} {
  return {
    label: coverageCheckLabel(entry.check),
    statusClass: coverageStatusClass(entry.status),
    statusLabel: coverageStatusLabel(entry.status),
    note: entry.reason ?? "",
  };
}

export function coverageRowFromDeepArea(entry: DeepCoverageEntry): {
  label: string;
  statusClass: string;
  statusLabel: string;
  note: string;
} {
  return {
    label: deepCoverageAreaLabel(entry.area),
    statusClass: coverageStatusClass(entry.state),
    statusLabel: coverageStatusLabel(entry.state),
    note: entry.reason ?? "",
  };
}

export function renderHtmlList(heading: string, values: ReadonlyArray<string>): string {
  if (values.length === 0) {
    return "";
  }
  return `<h4>${escapeHtml(heading)}</h4>${htmlList(values)}`;
}

function renderOrderedHtmlList(heading: string, values: ReadonlyArray<string>): string {
  if (values.length === 0) {
    return "";
  }
  const items = values.map((value) => `<li>${escapeHtml(value)}</li>`).join("");
  return `<h4>${escapeHtml(heading)}</h4><ol class="steps">${items}</ol>`;
}

export function htmlList(values: ReadonlyArray<string>): string {
  const items = values.map((value) => `<li>${escapeHtml(value)}</li>`).join("");
  return `<ul class="steps">${items}</ul>`;
}

const SEVERITY_RANK: Readonly<Record<string, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};

export function actionSeverity(
  ranked: RankedAction,
  assessment: SecurityAssessment,
): string | undefined {
  const findingsById = new Map(assessment.findings.map((finding) => [finding.id, finding]));
  let best: string | undefined;
  for (const findingId of ranked.candidate.findingIds) {
    const severity = findingsById.get(findingId)?.severity;
    if (severity === undefined) {
      continue;
    }
    if (best === undefined || (SEVERITY_RANK[severity] ?? 0) > (SEVERITY_RANK[best] ?? 0)) {
      best = severity;
    }
  }
  return best;
}

export function actionLocationsForReport(
  ranked: RankedAction,
  assessment: SecurityAssessment,
): string[] {
  const findingsById = new Map(assessment.findings.map((finding) => [finding.id, finding]));
  const seen = new Set<string>();
  const out: string[] = [];
  for (const findingId of ranked.candidate.findingIds) {
    for (const location of findingsById.get(findingId)?.locations ?? []) {
      const value = `${location.filePath}:${location.startLine}`;
      if (!seen.has(value)) {
        seen.add(value);
        out.push(value);
      }
    }
  }
  return out;
}

export function severityLabel(severity: string): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

export function verdictHtmlClass(verdict: Verdict): string {
  if (verdict === "critical-fix-needed" || verdict === "not-ready-to-deploy") {
    return "critical";
  }
  if (verdict === "scan-incomplete") {
    return "warn";
  }
  return "ok";
}

export function verdictSubline(assessment: SecurityAssessment): string {
  const count = assessment.rankedActions.length;
  switch (assessment.verdict) {
    case "critical-fix-needed":
    case "not-ready-to-deploy":
      return count === 0
        ? "Fix the issues below before you rely on this code."
        : `${count} ${count === 1 ? "fix" : "fixes"} to make before you ship. Start with the first one.`;
    case "scan-incomplete":
      return "Some checks didn't finish, so this isn't the full picture — see the coverage below.";
    case "looks-ok-for-now":
      return "No blocking issues from the checks that ran. Not a guarantee — keep reviewing.";
  }
}

export function confidenceLabel(value: number): string {
  if (value >= 0.66) {
    return "High confidence";
  }
  if (value >= 0.34) {
    return "Medium confidence";
  }
  return "Low confidence";
}

export function confidenceClass(value: number): string {
  if (value >= 0.66) {
    return "high";
  }
  if (value >= 0.34) {
    return "medium";
  }
  return "low";
}

export function coverageStatusLabel(status: string): string {
  switch (status) {
    case "checked":
      return "Checked";
    case "degraded":
      return "Partial";
    case "partial":
      return "Partial";
    case "failed":
      return "Failed";
    case "skipped":
      return "Skipped";
    default:
      return status;
  }
}

export function coverageStatusClass(status: string): string {
  switch (status) {
    case "checked":
      return "ok";
    case "degraded":
    case "partial":
      return "warn";
    case "failed":
      return "fail";
    default:
      return "skip";
  }
}

export function coverageCheckLabel(check: string): string {
  const group = check.split(".")[0] ?? check;
  switch (group) {
    case "secrets":
      return "Secrets";
    case "code":
      return "Code patterns";
    case "sbom":
      return "Software inventory";
    case "dependencies":
      return "Dependencies";
    case "github-actions":
      return "GitHub Actions";
    case "iac":
      return "Infrastructure config";
    default:
      return group.replaceAll("-", " ").replace(/^./, (character) => character.toUpperCase());
  }
}

export function deepCoverageAreaLabel(area: string): string {
  switch (area) {
    case "language_support":
      return "Language support";
    case "model":
      return "AI enrichment";
    case "entities":
      return "Code map";
    case "boundaries":
      return "Entry points";
    case "call_graph":
      return "Call graph";
    case "data_flow":
      return "Data flows";
    case "component_usage":
    case "dependency_usage":
      return "Dependency usage";
    case "ci_iac":
      return "CI / infrastructure";
    default:
      return area.replaceAll("_", " ").replace(/^./, (character) => character.toUpperCase());
  }
}

export const REPORT_CSS = [
  ":root{--bg:#f6f7f9;--card:#fff;--ink:#15171a;--muted:#5b6470;--line:#e4e7eb;--accent:#5b5bd6}",
  "*{box-sizing:border-box}",
  'body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}',
  "main{max-width:820px;margin:0 auto;padding:40px 20px 64px}",
  ".head{margin-bottom:20px}",
  ".brand{font-size:13px;font-weight:600;letter-spacing:.02em;color:var(--muted);display:flex;align-items:center;gap:8px}",
  ".brand .dot{width:9px;height:9px;border-radius:50%;background:var(--accent);display:inline-block}",
  ".brand-sub{color:var(--muted);font-weight:400}",
  "h1{font-size:26px;margin:10px 0 4px}",
  ".verdict{border-radius:14px;padding:18px 20px;margin:22px 0;color:#fff}",
  ".verdict--critical{background:#b42318}.verdict--warn{background:#b54708}.verdict--ok{background:#1f7a4d}",
  ".verdict-label{font-size:20px;font-weight:600}",
  ".verdict-sub{opacity:.92;margin-top:4px;font-size:14.5px}",
  ".stats{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 18px}",
  ".stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px;min-width:120px}",
  ".stat b{display:block;font-size:22px}.stat span{color:var(--muted);font-size:13px}",
  ".note{background:#fff8e6;border:1px solid #f3e2b3;color:#6b4e00;border-radius:10px;padding:10px 14px;font-size:14px}",
  "h2{font-size:18px;margin:32px 0 6px}",
  ".lede{color:var(--muted);margin:0 0 14px}",
  ".action{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px 22px;margin:14px 0}",
  ".action-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}",
  ".rank{width:26px;height:26px;border-radius:50%;background:var(--ink);color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:600;flex:none}",
  ".action-head h3{font-size:17px;margin:0;flex:1}",
  ".risk{margin:14px 0 6px;font-size:15.5px}",
  ".why{margin:0 0 14px;color:var(--muted);font-size:14px}",
  ".why strong{color:var(--ink)}",
  ".muted-line{color:var(--muted);font-size:13.5px;margin:8px 0}",
  ".ops{background:#fff8e6;border:1px solid #f3e2b3;border-radius:10px;padding:10px 14px;margin:14px 0;font-size:14px}",
  ".ops strong{display:block;margin-bottom:4px}",
  ".ops ul.steps{margin:0}",
  ".more{margin-top:12px}",
  ".more summary{cursor:pointer;color:var(--muted);font-size:13px;font-weight:600;padding:4px 0}",
  ".more .facts{margin-top:8px}",
  ".pill{font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px;white-space:nowrap}",
  ".pill--critical{background:#fde7e4;color:#a3271c}.pill--high{background:#fde9e0;color:#9a4a13}",
  ".pill--medium{background:#fcf3d6;color:#7a5800}.pill--low{background:#e6f0fb;color:#1f5aa8}",
  ".pill--unknown{background:#eef0f2;color:#5b6470}",
  ".pill--conf-high{background:#fde7e4;color:#a3271c}.pill--conf-medium{background:#fcf3d6;color:#7a5800}",
  ".pill--conf-low{background:#eef0f2;color:#5b6470}",
  ".pill--check{background:#e6eefb;color:#274a8a}",
  ".facts{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:14px 0 4px}",
  ".facts dt{color:var(--muted);font-size:13px;font-weight:600}.facts dd{margin:0}",
  "h4{font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);margin:16px 0 6px}",
  "ul.steps,ol.steps{margin:0;padding-left:20px}ul.steps li,ol.steps li{margin:3px 0}",
  "code{background:#eef0f2;padding:1px 6px;border-radius:5px;font-size:13.5px}",
  ".prompt{margin:16px 0;border:1px solid #cdd0ef;border-radius:12px;overflow:hidden}",
  ".prompt-head{display:flex;align-items:center;justify-content:space-between;background:#f1f2f4;padding:8px 12px;font-size:13px;font-weight:600}",
  ".prompt-hint{margin:0;padding:8px 12px 0;color:var(--muted);font-size:13px}",
  ".copy{font:inherit;font-size:12px;font-weight:600;border:1px solid var(--line);background:#fff;border-radius:7px;padding:4px 12px;cursor:pointer}",
  ".copy:hover{background:#fafbfc}",
  "pre{white-space:pre-wrap;word-break:break-word;background:#15171a;color:#f3f4f6;margin:8px 12px 12px;padding:14px;border-radius:8px;font-size:13px;line-height:1.55}",
  ".coverage{margin:28px 0 0;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:4px 16px}",
  ".coverage summary{cursor:pointer;font-weight:600;padding:12px 0}",
  "table{border-collapse:collapse;width:100%;font-size:14px;margin-bottom:12px}",
  "th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}",
  "th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.03em}",
  ".status{font-size:12px;font-weight:600;padding:2px 9px;border-radius:999px}",
  ".status--ok{background:#e3f4ea;color:#1f7a4d}.status--warn{background:#fcf3d6;color:#7a5800}",
  ".status--fail{background:#fde7e4;color:#a3271c}.status--skip{background:#eef0f2;color:#5b6470}",
  ".foot{margin-top:32px;color:var(--muted);font-size:13px;text-align:center}",
].join("");

export const COPY_SCRIPT = [
  "document.querySelectorAll('.copy').forEach(function(btn){",
  "btn.addEventListener('click',function(){",
  "var pre=btn.closest('.prompt').querySelector('pre');",
  "navigator.clipboard.writeText(pre.innerText).then(function(){",
  "var prev=btn.textContent;btn.textContent='Copied';",
  "setTimeout(function(){btn.textContent=prev;},1500);});});});",
].join("");
