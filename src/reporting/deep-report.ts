import { verdictLabel } from "../domain/assessment.js";
import type { DeepCoverageEntry } from "../domain/deep-coverage.js";
import type { FindingContextAssessment } from "../domain/finding-context-assessment.js";
import type { HypothesisEnrichment } from "../domain/hypothesis-enrichment.js";
import type { SecurityAssessment } from "../domain/security-assessment.js";
import type { StaticHypothesis } from "../domain/static-hypothesis.js";
import type { ValidationRecipe } from "../domain/validation-recipe.js";

export interface DeepReportJson {
  readonly runId: string;
  readonly assessment: SecurityAssessment;
}

export function renderDeepReportJson(
  runId: string,
  assessment: SecurityAssessment,
): DeepReportJson {
  return { runId, assessment };
}

export function renderDeepMarkdownReport(runId: string, assessment: SecurityAssessment): string {
  const lines = [
    `# VibeShield Deep Static - ${repositoryName(assessment)}`,
    "",
    `**Run:** ${runId}`,
    `**Verdict:** ${verdictLabel(assessment.verdict)}`,
    "",
    `> ${assessment.limitation}`,
    "",
    "## Fix now",
    "",
  ];

  if (assessment.rankedActions.length === 0) {
    lines.push("No direct Fix Pack actions were produced.", "");
  } else {
    assessment.rankedActions.forEach((ranked, index) => {
      lines.push(
        `### ${index + 1}. ${ranked.remediation.title}`,
        "",
        ranked.remediation.risk,
        "",
        `**Why now:** ${ranked.remediation.whyFixNow}`,
        "",
        `**Direct action id:** \`${ranked.candidate.id}\``,
        "",
      );
    });
  }

  appendAttackPaths(lines, assessment);
  appendDeepCoverage(lines, assessment.deepCoverage ?? []);
  appendFindingContext(lines, assessment.findingContextAssessments ?? []);
  appendValidationRecipes(lines, assessment.validationRecipes ?? []);
  appendLimitations(lines, assessment);

  return lines
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trimEnd();
}

export function renderDeepHtmlReport(runId: string, assessment: SecurityAssessment): string {
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    "<title>VibeShield Deep Static</title>",
    "<style>",
    "body{font-family:Inter,system-ui,sans-serif;margin:32px;line-height:1.5;color:#17202a}",
    "section{margin:28px 0}",
    "h1,h2,h3{line-height:1.2}",
    "code{background:#f3f5f7;padding:2px 4px;border-radius:4px}",
    "table{border-collapse:collapse;width:100%}",
    "th,td{border:1px solid #d9dee5;padding:8px;text-align:left;vertical-align:top}",
    ".muted{color:#5f6b7a}",
    "</style>",
    "</head>",
    "<body>",
    `<h1>VibeShield Deep Static - ${escapeHtml(repositoryName(assessment))}</h1>`,
    `<p class="muted">Run ${escapeHtml(runId)} - ${escapeHtml(verdictLabel(assessment.verdict))}</p>`,
    `<p>${escapeHtml(assessment.limitation)}</p>`,
    renderFixNowHtml(assessment),
    renderAttackPathsHtml(assessment),
    renderDeepCoverageHtml(assessment.deepCoverage ?? []),
    renderFindingContextHtml(assessment.findingContextAssessments ?? []),
    renderValidationRecipesHtml(assessment.validationRecipes ?? []),
    renderLimitationsHtml(assessment),
    "</body>",
    "</html>",
  ].join("\n");
}

function appendAttackPaths(lines: string[], assessment: SecurityAssessment): void {
  lines.push("## Likely attack paths", "");
  const hypotheses = reportableHypotheses(assessment.staticHypotheses ?? []);
  if (hypotheses.length === 0) {
    lines.push("No non-contradicted static hypotheses were produced.", "");
    return;
  }

  const enrichmentsByHypothesisId = byHypothesisId(assessment.hypothesisEnrichments ?? []);
  const recipesByHypothesisId = recipeByHypothesisId(assessment.validationRecipes ?? []);
  hypotheses.forEach((hypothesis, index) => {
    const enrichment = enrichmentsByHypothesisId.get(hypothesis.id);
    lines.push(
      `### ${index + 1}. ${hypothesis.title}`,
      "",
      `**Hypothesis id:** \`${hypothesis.id}\``,
      "",
      `**Status:** ${hypothesis.status} (${Math.round(hypothesis.staticConfidence * 100)}% static confidence)`,
      "",
      enrichment?.attackDescription ?? hypothesis.pathSummary,
      "",
      `**Runtime validation required:** ${hypothesis.runtimeValidationRequired ? "yes" : "no"}`,
      "",
    );
    const recipe = recipesByHypothesisId.get(hypothesis.id);
    if (recipe !== undefined) {
      lines.push(`**Validation recipe:** \`${recipe.id}\``, "");
    }
  });
}

function appendDeepCoverage(lines: string[], coverage: ReadonlyArray<DeepCoverageEntry>): void {
  lines.push("## Deep analysis coverage", "");
  if (coverage.length === 0) {
    lines.push("No Deep Static coverage was recorded.", "");
    return;
  }
  lines.push("| Area | State | Producer | Reason |", "| --- | --- | --- | --- |");
  for (const entry of coverage) {
    lines.push(`| ${entry.area} | ${entry.state} | ${entry.producer} | ${entry.reason ?? ""} |`);
  }
  lines.push("");
}

function appendFindingContext(
  lines: string[],
  contexts: ReadonlyArray<FindingContextAssessment>,
): void {
  lines.push("## Quick finding context", "");
  if (contexts.length === 0) {
    lines.push("No Quick finding context statuses were recorded.", "");
    return;
  }
  lines.push("| Finding | Status | Hypotheses | Reason |", "| --- | --- | --- | --- |");
  for (const context of contexts) {
    lines.push(
      `| \`${context.findingId}\` | ${context.status} | ${context.hypothesisIds.join(
        ", ",
      )} | ${context.reason} |`,
    );
  }
  lines.push("");
}

function appendValidationRecipes(lines: string[], recipes: ReadonlyArray<ValidationRecipe>): void {
  lines.push("## Validation recipes", "");
  if (recipes.length === 0) {
    lines.push("No future runtime validation recipes were generated.", "");
    return;
  }
  for (const recipe of recipes) {
    lines.push(
      `### ${recipe.id}`,
      "",
      `**Hypothesis:** \`${recipe.hypothesisId}\``,
      "",
      `**Required fixtures:** ${recipe.requiredFixtures.join(", ")}`,
      "",
      `**Expected result:** ${recipe.expectedResult}`,
      "",
      "**Steps:**",
      "",
      ...recipe.steps.map((step) => `- ${step}`),
      "",
      "**Safety notes:**",
      "",
      ...recipe.safetyNotes.map((note) => `- ${note}`),
      "",
    );
  }
}

function appendLimitations(lines: string[], assessment: SecurityAssessment): void {
  const limitations = assessment.limitations ?? [];
  if (limitations.length === 0 && assessment.repositoryMapArtifactRef === undefined) {
    return;
  }
  lines.push("## Deep report metadata", "");
  if (assessment.repositoryMapArtifactRef !== undefined) {
    lines.push(
      `Repository map artifact: \`${assessment.repositoryMapArtifactRef.blobSha256}\``,
      "",
    );
  }
  for (const limitation of limitations) {
    lines.push(`- ${limitation}`);
  }
  lines.push("");
}

function renderFixNowHtml(assessment: SecurityAssessment): string {
  if (assessment.rankedActions.length === 0) {
    return "<section><h2>Fix now</h2><p>No direct Fix Pack actions were produced.</p></section>";
  }
  return [
    "<section>",
    "<h2>Fix now</h2>",
    ...assessment.rankedActions.map(
      (ranked, index) =>
        `<article><h3>${index + 1}. ${escapeHtml(
          ranked.remediation.title,
        )}</h3><p>${escapeHtml(ranked.remediation.risk)}</p><p><strong>Why now:</strong> ${escapeHtml(
          ranked.remediation.whyFixNow,
        )}</p><p><strong>Direct action id:</strong> <code>${escapeHtml(
          ranked.candidate.id,
        )}</code></p></article>`,
    ),
    "</section>",
  ].join("\n");
}

function renderAttackPathsHtml(assessment: SecurityAssessment): string {
  const hypotheses = reportableHypotheses(assessment.staticHypotheses ?? []);
  if (hypotheses.length === 0) {
    return "<section><h2>Likely attack paths</h2><p>No non-contradicted static hypotheses were produced.</p></section>";
  }
  const enrichmentsByHypothesisId = byHypothesisId(assessment.hypothesisEnrichments ?? []);
  const recipesByHypothesisId = recipeByHypothesisId(assessment.validationRecipes ?? []);
  return [
    "<section>",
    "<h2>Likely attack paths</h2>",
    ...hypotheses.map((hypothesis, index) => {
      const enrichment = enrichmentsByHypothesisId.get(hypothesis.id);
      const recipe = recipesByHypothesisId.get(hypothesis.id);
      return `<article><h3>${index + 1}. ${escapeHtml(
        hypothesis.title,
      )}</h3><p><strong>Hypothesis id:</strong> <code>${escapeHtml(
        hypothesis.id,
      )}</code></p><p><strong>Status:</strong> ${escapeHtml(
        hypothesis.status,
      )} (${Math.round(hypothesis.staticConfidence * 100)}% static confidence)</p><p>${escapeHtml(
        enrichment?.attackDescription ?? hypothesis.pathSummary,
      )}</p><p><strong>Runtime validation required:</strong> ${
        hypothesis.runtimeValidationRequired ? "yes" : "no"
      }</p>${
        recipe === undefined
          ? ""
          : `<p><strong>Validation recipe:</strong> <code>${escapeHtml(recipe.id)}</code></p>`
      }</article>`;
    }),
    "</section>",
  ].join("\n");
}

function renderDeepCoverageHtml(coverage: ReadonlyArray<DeepCoverageEntry>): string {
  if (coverage.length === 0) {
    return "<section><h2>Deep analysis coverage</h2><p>No Deep Static coverage was recorded.</p></section>";
  }
  return [
    "<section>",
    "<h2>Deep analysis coverage</h2>",
    "<table><thead><tr><th>Area</th><th>State</th><th>Producer</th><th>Reason</th></tr></thead><tbody>",
    ...coverage.map(
      (entry) =>
        `<tr><td>${escapeHtml(entry.area)}</td><td>${escapeHtml(
          entry.state,
        )}</td><td>${escapeHtml(entry.producer)}</td><td>${escapeHtml(
          entry.reason ?? "",
        )}</td></tr>`,
    ),
    "</tbody></table>",
    "</section>",
  ].join("\n");
}

function renderFindingContextHtml(contexts: ReadonlyArray<FindingContextAssessment>): string {
  if (contexts.length === 0) {
    return "<section><h2>Quick finding context</h2><p>No Quick finding context statuses were recorded.</p></section>";
  }
  return [
    "<section>",
    "<h2>Quick finding context</h2>",
    "<table><thead><tr><th>Finding</th><th>Status</th><th>Hypotheses</th><th>Reason</th></tr></thead><tbody>",
    ...contexts.map(
      (context) =>
        `<tr><td><code>${escapeHtml(context.findingId)}</code></td><td>${escapeHtml(
          context.status,
        )}</td><td>${escapeHtml(context.hypothesisIds.join(", "))}</td><td>${escapeHtml(
          context.reason,
        )}</td></tr>`,
    ),
    "</tbody></table>",
    "</section>",
  ].join("\n");
}

function renderValidationRecipesHtml(recipes: ReadonlyArray<ValidationRecipe>): string {
  if (recipes.length === 0) {
    return "<section><h2>Validation recipes</h2><p>No future runtime validation recipes were generated.</p></section>";
  }
  return [
    "<section>",
    "<h2>Validation recipes</h2>",
    ...recipes.map(
      (recipe) =>
        `<article><h3>${escapeHtml(recipe.id)}</h3><p><strong>Hypothesis:</strong> <code>${escapeHtml(
          recipe.hypothesisId,
        )}</code></p><p><strong>Required fixtures:</strong> ${escapeHtml(
          recipe.requiredFixtures.join(", "),
        )}</p><p><strong>Expected result:</strong> ${escapeHtml(
          recipe.expectedResult,
        )}</p><h4>Steps</h4>${htmlList(recipe.steps)}<h4>Safety notes</h4>${htmlList(
          recipe.safetyNotes,
        )}</article>`,
    ),
    "</section>",
  ].join("\n");
}

function renderLimitationsHtml(assessment: SecurityAssessment): string {
  const limitations = assessment.limitations ?? [];
  if (limitations.length === 0 && assessment.repositoryMapArtifactRef === undefined) {
    return "";
  }
  return [
    "<section>",
    "<h2>Deep report metadata</h2>",
    assessment.repositoryMapArtifactRef === undefined
      ? ""
      : `<p>Repository map artifact: <code>${escapeHtml(
          assessment.repositoryMapArtifactRef.blobSha256,
        )}</code></p>`,
    limitations.length === 0 ? "" : htmlList(limitations),
    "</section>",
  ].join("\n");
}

function reportableHypotheses(hypotheses: ReadonlyArray<StaticHypothesis>): StaticHypothesis[] {
  return [...hypotheses]
    .filter((hypothesis) => hypothesis.status !== "statically_contradicted")
    .sort(
      (a, b) =>
        b.staticConfidence - a.staticConfidence ||
        a.title.localeCompare(b.title) ||
        a.id.localeCompare(b.id),
    );
}

function byHypothesisId(
  enrichments: ReadonlyArray<HypothesisEnrichment>,
): Map<string, HypothesisEnrichment> {
  return new Map(enrichments.map((enrichment) => [enrichment.hypothesisId, enrichment]));
}

function recipeByHypothesisId(
  recipes: ReadonlyArray<ValidationRecipe>,
): Map<string, ValidationRecipe> {
  return new Map(recipes.map((recipe) => [recipe.hypothesisId, recipe]));
}

function repositoryName(assessment: SecurityAssessment): string {
  return assessment.repository.name.trim() || "repository";
}

function htmlList(values: ReadonlyArray<string>): string {
  return `<ul>${values.map((value) => `<li>${escapeHtml(value)}</li>`).join("")}</ul>`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
