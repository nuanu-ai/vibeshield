import { verdictLabel } from "../domain/assessment.js";
import type { Evidence } from "../domain/evidence.js";
import type { FindingContextAssessment } from "../domain/finding-context-assessment.js";
import type { HypothesisEnrichment } from "../domain/hypothesis-enrichment.js";
import type { RankedAction, SecurityAssessment } from "../domain/security-assessment.js";
import type { StaticHypothesis } from "../domain/static-hypothesis.js";
import type { ValidationRecipe } from "../domain/validation-recipe.js";
import {
  type AttackPathSignal,
  actionCardHtml,
  actionLocationsForReport,
  attackPathCardHtml,
  confidenceLabel,
  coverageDetailsHtml,
  coverageRowFromDeepArea,
  coverageRowFromQuickCheck,
  footerMetaLine,
  noteHtml,
  renderReportDocument,
  repositoryName,
  sectionHeadingHtml,
  statsHtml,
  verdictBannerHtml,
  verdictSubline,
} from "./report-html.js";

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

export function renderDeepHtmlReport(_runId: string, assessment: SecurityAssessment): string {
  const actions = assessment.rankedActions;
  const enrichments = byHypothesisId(assessment.hypothesisEnrichments ?? []);
  const recipes = recipeByHypothesisId(assessment.validationRecipes ?? []);
  const evidenceById = evidenceIndex(assessment.evidence);
  const hypotheses = reportableHypotheses(assessment.staticHypotheses ?? [], enrichments, recipes);

  const sections: string[] = [
    verdictBannerHtml(assessment),
    statsHtml([
      {
        value: String(actions.length),
        label: actions.length === 1 ? "fix to make" : "fixes to make",
      },
      {
        value: String(hypotheses.length),
        label: hypotheses.length === 1 ? "attack path to check" : "attack paths to check",
      },
      { value: String(assessment.manifest.fileCount), label: "files scanned" },
    ]),
    noteHtml(assessment.limitation),
  ];

  sections.push(
    sectionHeadingHtml(
      "Fix these first",
      actions.length > 0
        ? "Confirmed problems. Each comes with a prompt you can paste straight into your coding agent."
        : "No confirmed fixes were produced by the checks that completed.",
    ),
    ...actions.map((ranked, index) => actionCardHtml(index + 1, ranked, assessment)),
  );

  sections.push(
    sectionHeadingHtml(
      "Likely attack paths",
      hypotheses.length > 0
        ? "Unconfirmed — possible problems the deep analysis traced through your code. Each card says how to confirm it."
        : "The deep analysis didn't trace any likely attack paths.",
    ),
    ...hypotheses.map((hypothesis, index) =>
      attackPathCardHtml(
        index + 1,
        hypothesis,
        enrichments.get(hypothesis.id),
        signalsForHypothesis(hypothesis, evidenceById),
      ),
    ),
  );

  const coverageRows = [
    ...assessment.coverage.map(coverageRowFromQuickCheck),
    ...(assessment.deepCoverage ?? []).map(coverageRowFromDeepArea),
  ];
  sections.push(coverageDetailsHtml("What was checked", coverageRows));

  return renderReportDocument({
    repoName: repositoryName(assessment),
    brandSub: "Deep Static",
    sections,
    footerMeta: footerMetaLine(assessment),
  });
}

export function renderDeepMarkdownReport(_runId: string, assessment: SecurityAssessment): string {
  const actions = assessment.rankedActions;
  const enrichments = byHypothesisId(assessment.hypothesisEnrichments ?? []);
  const recipes = recipeByHypothesisId(assessment.validationRecipes ?? []);
  const evidenceById = evidenceIndex(assessment.evidence);
  const hypotheses = reportableHypotheses(assessment.staticHypotheses ?? [], enrichments, recipes);

  const lines = [
    `# VibeShield — ${repositoryName(assessment)}`,
    "",
    `**Verdict:** ${verdictLabel(assessment.verdict)}`,
    "",
    verdictSubline(assessment),
    "",
    `${actions.length} ${actions.length === 1 ? "fix" : "fixes"} to make · ${hypotheses.length} likely attack ${
      hypotheses.length === 1 ? "path" : "paths"
    } · ${assessment.manifest.fileCount} files scanned`,
    "",
    `> ${assessment.limitation}`,
    "",
    "## Fix these first",
    "",
    actions.length > 0
      ? "Confirmed problems. Each comes with a prompt you can paste straight into your coding agent."
      : "No confirmed fixes were produced by the checks that completed.",
    "",
  ];
  actions.forEach((ranked, index) => {
    appendActionMarkdown(lines, index + 1, ranked, assessment);
  });

  lines.push(
    "## Likely attack paths",
    "",
    hypotheses.length > 0
      ? "Unconfirmed — possible problems the deep analysis traced through your code. Each says how to confirm it."
      : "The deep analysis didn't trace any likely attack paths.",
    "",
  );
  hypotheses.forEach((hypothesis, index) => {
    appendHypothesisMarkdown(
      lines,
      index + 1,
      hypothesis,
      enrichments.get(hypothesis.id),
      signalsForHypothesis(hypothesis, evidenceById),
    );
  });

  lines.push("## What was checked", "", "| Check | Status | Notes |", "| --- | --- | --- |");
  for (const entry of assessment.coverage) {
    const row = coverageRowFromQuickCheck(entry);
    lines.push(`| ${row.label} | ${row.statusLabel} | ${row.note} |`);
  }
  for (const entry of assessment.deepCoverage ?? []) {
    const row = coverageRowFromDeepArea(entry);
    lines.push(`| ${row.label} | ${row.statusLabel} | ${row.note} |`);
  }
  lines.push("");

  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n")}\n`;
}

function appendActionMarkdown(
  lines: string[],
  rank: number,
  ranked: RankedAction,
  assessment: SecurityAssessment,
): void {
  const { remediation } = ranked;
  lines.push(`### ${rank}. ${remediation.title}`, "");
  lines.push(remediation.risk, "");
  lines.push(`**Why now:** ${remediation.whyFixNow}`, "");
  lines.push("**Prompt for your coding agent**", "");
  lines.push("Copy this whole block into your coding agent:");
  lines.push("", "```text", remediation.agentPrompt, "```", "");
  appendList(
    lines,
    "You'll need to do this yourself (your agent can't)",
    remediation.operationalSteps,
  );
  const where = actionLocationsForReport(ranked, assessment);
  lines.push(`**Where:** ${where.length > 0 ? where.join(", ") : "across the repository"}`, "");
  appendList(lines, "Or change it by hand", remediation.fixSteps);
  appendList(lines, "Check it worked", remediation.verifySteps);
}

function appendHypothesisMarkdown(
  lines: string[],
  rank: number,
  hypothesis: StaticHypothesis,
  enrichment: HypothesisEnrichment | undefined,
  signals: ReadonlyArray<AttackPathSignal>,
): void {
  lines.push(`### ${rank}. ${hypothesis.title}`, "");
  lines.push(enrichment?.attackDescription ?? hypothesis.pathSummary, "");
  if (enrichment !== undefined && enrichment.impact.trim() !== "") {
    lines.push(`**If real, the impact:** ${enrichment.impact}`, "");
  }
  const confidence = confidenceLabel(hypothesis.staticConfidence);
  const runtime = hypothesis.runtimeValidationRequired ? " · needs a runtime check" : "";
  lines.push(`**Confidence:** ${confidence}${runtime}`, "");
  if (enrichment !== undefined) {
    lines.push("**Prompt for your coding agent**", "");
    lines.push("Copy this whole block into your coding agent:");
    lines.push("", "```text", enrichment.agentPrompt, "```", "");
  }
  lines.push("**Technical details**", "");
  lines.push(`- Static path: ${hypothesis.pathSummary}`);
  if (signals.length > 0) {
    for (const signal of signals) {
      lines.push(`- Signal: ${signal.tool} - ${signal.location}`);
    }
  }
  lines.push("");
}

function appendList(lines: string[], heading: string, values: ReadonlyArray<string>): void {
  if (values.length === 0) {
    return;
  }
  lines.push(`**${heading}**`, "");
  for (const value of values) {
    lines.push(`- ${value}`);
  }
  lines.push("");
}

function reportableHypotheses(
  hypotheses: ReadonlyArray<StaticHypothesis>,
  enrichments: ReadonlyMap<string, HypothesisEnrichment>,
  recipes: ReadonlyMap<string, ValidationRecipe>,
): StaticHypothesis[] {
  const seenOwnerFacingPaths = new Set<string>();
  const reportable: StaticHypothesis[] = [];

  for (const hypothesis of [...hypotheses]
    .filter((hypothesis) => hypothesis.status !== "statically_contradicted")
    .sort(
      (a, b) =>
        b.staticConfidence - a.staticConfidence ||
        a.title.localeCompare(b.title) ||
        a.id.localeCompare(b.id),
    )) {
    const key = ownerFacingAttackPathKey(
      hypothesis,
      enrichments.get(hypothesis.id),
      recipes.get(hypothesis.id),
    );
    if (key !== undefined) {
      if (seenOwnerFacingPaths.has(key)) {
        continue;
      }
      seenOwnerFacingPaths.add(key);
    }
    reportable.push(hypothesis);
  }

  return reportable;
}

function ownerFacingAttackPathKey(
  hypothesis: StaticHypothesis,
  enrichment: HypothesisEnrichment | undefined,
  recipe: ValidationRecipe | undefined,
): string | undefined {
  if (enrichment === undefined) {
    return undefined;
  }

  return [
    normalizeReportText(hypothesis.title),
    hypothesis.status,
    hypothesis.runtimeValidationRequired ? "runtime" : "static",
    normalizeReportText(enrichment.attackDescription),
    normalizeReportText(enrichment.impact),
    normalizeReportText(enrichment.agentPrompt),
    recipe === undefined
      ? "no-recipe"
      : recipe.requiredFixtures.map(normalizeReportText).join("\0"),
    recipe === undefined ? "" : normalizeReportText(recipe.expectedResult),
  ].join("\u0001");
}

function normalizeReportText(value: string): string {
  return value.replace(/\s+/g, " ").trim().toLowerCase();
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

function evidenceIndex(evidence: ReadonlyArray<Evidence>): Map<string, Evidence> {
  return new Map(evidence.map((record) => [record.id, record]));
}

function signalsForHypothesis(
  hypothesis: StaticHypothesis,
  evidenceById: ReadonlyMap<string, Evidence>,
): AttackPathSignal[] {
  const seen = new Set<string>();
  const signals: AttackPathSignal[] = [];

  for (const evidenceId of hypothesis.supportingEvidenceIds) {
    const evidence = evidenceById.get(evidenceId);
    if (evidence === undefined) {
      continue;
    }
    const signal = {
      tool: evidence.tool,
      location: evidenceLocation(evidence),
    };
    const key = `${signal.tool}\0${signal.location}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    signals.push(signal);
  }

  return signals;
}

function evidenceLocation(evidence: Evidence): string {
  const line =
    evidence.startLine === evidence.endLine
      ? `${evidence.startLine}`
      : `${evidence.startLine}-${evidence.endLine}`;
  return `${evidence.filePath}:${line}`;
}

// Kept for the JSON contract surface; finding-context detail stays in report.json
// rather than the owner-facing HTML/Markdown.
export type { FindingContextAssessment };
