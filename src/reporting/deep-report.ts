import type { FindingContextAssessment } from "../domain/finding-context-assessment.js";
import type { SecurityAssessment } from "../domain/security-assessment.js";
import {
  buildOwnerReportProjection,
  type OwnerFixGroup,
  type OwnerReportProjection,
  type OwnerValidationGroup,
} from "./owner-report-projection.js";
import {
  actionCardHtml,
  actionLocationsForReport,
  coverageDetailsHtml,
  coverageRowFromDeepArea,
  coverageRowFromQuickCheck,
  footerMetaLine,
  htmlList,
  noteHtml,
  ownerVerdictBannerHtml,
  renderReportDocument,
  repositoryName,
  sectionHeadingHtml,
  statsHtml,
  validationGroupCardHtml,
} from "./report-html.js";

export interface DeepReportJson {
  readonly runId: string;
  readonly assessment: SecurityAssessment;
  readonly ownerReport: OwnerReportProjection;
}

export function renderDeepReportJson(
  runId: string,
  assessment: SecurityAssessment,
): DeepReportJson {
  return { runId, assessment, ownerReport: buildOwnerReportProjection(assessment) };
}

export function renderDeepHtmlReport(_runId: string, assessment: SecurityAssessment): string {
  const projection = buildOwnerReportProjection(assessment);
  const sections: string[] = [
    ownerVerdictBannerHtml(projection.banner),
    statsHtml([
      {
        value: String(projection.fixGroups.length),
        label: projection.fixGroups.length === 1 ? "fix group" : "fix groups",
      },
      {
        value: String(projection.validationGroups.length),
        label: projection.validationGroups.length === 1 ? "validation group" : "validation groups",
      },
      { value: projection.coverage.label, label: "coverage" },
    ]),
    noteHtml(assessment.limitation),
  ];

  sections.push(
    sectionHeadingHtml("Fix now", fixNowLede(projection)),
    ...projection.visibleFixGroups.map((group, index) =>
      actionCardHtml(index + 1, group.action, assessment, group.relatedStaticEvidence),
    ),
    sectionHeadingHtml("Validate next", validateNextLede(projection)),
    ...projection.visibleValidationGroups.map((group, index) =>
      validationGroupCardHtml(index + 1, group),
    ),
    '<h2 id="technical-appendix">Technical appendix</h2>',
    '<p class="lede">Remaining groups, raw static traces, candidates, coverage, and scanner limitations. Complete machine records remain in report.json.</p>',
    technicalAppendixHtml(projection, assessment),
  );

  return renderReportDocument({
    repoName: repositoryName(assessment),
    brandSub: "Report v1",
    sections,
    footerMeta: footerMetaLine(assessment),
  });
}

export function renderDeepMarkdownReport(_runId: string, assessment: SecurityAssessment): string {
  const projection = buildOwnerReportProjection(assessment);
  const lines = [
    `# VibeShield — ${repositoryName(assessment)}`,
    "",
    `**Verdict:** ${projection.banner.label}`,
    "",
    projection.banner.subline,
    "",
    `${projection.fixGroups.length} ${
      projection.fixGroups.length === 1 ? "fix group" : "fix groups"
    } · ${projection.validationGroups.length} ${
      projection.validationGroups.length === 1 ? "validation group" : "validation groups"
    } · Coverage: ${projection.coverage.label}`,
    "",
    `> ${assessment.limitation}`,
    "",
    "## Fix now",
    "",
    fixNowLede(projection),
    "",
  ];
  projection.visibleFixGroups.forEach((group, index) => {
    appendActionMarkdown(lines, index + 1, group, assessment);
  });

  lines.push("## Validate next", "", validateNextLede(projection), "");
  projection.visibleValidationGroups.forEach((group, index) => {
    appendValidationGroupMarkdown(lines, index + 1, group);
  });

  appendTechnicalAppendixMarkdown(lines, projection, assessment);
  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n")}\n`;
}

function appendActionMarkdown(
  lines: string[],
  rank: number,
  group: OwnerFixGroup,
  assessment: SecurityAssessment,
): void {
  const ranked = group.action;
  const { remediation } = ranked;
  lines.push(`### ${rank}. ${remediation.title}`, "");
  lines.push(remediation.risk, "");
  lines.push(`**Why now:** ${remediation.whyFixNow}`, "");
  if (group.relatedStaticEvidence.length > 0) {
    lines.push("**Related static evidence (not a separate confirmed issue)**", "");
    for (const trace of group.relatedStaticEvidence.slice(0, 3)) {
      lines.push(`- ${trace.reason}`);
    }
    const locations = uniqueStrings(
      group.relatedStaticEvidence.flatMap((trace) => trace.evidenceLocations),
    ).slice(0, 8);
    for (const location of locations) {
      lines.push(`- Evidence: ${location}`);
    }
    if (group.relatedStaticEvidence.length > 3) {
      lines.push("- Additional linked traces are in the Technical appendix.");
    }
    lines.push("");
  }
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

function appendValidationGroupMarkdown(
  lines: string[],
  rank: number,
  group: OwnerValidationGroup,
): void {
  lines.push(`### ${rank}. ${group.title} — Unconfirmed`, "");
  lines.push(`**Possible attack scenario:** ${group.traces[0]?.reason ?? group.title}`, "");
  lines.push(`**If confirmed:** ${group.impact}`, "");
  lines.push(`**Why validate next:** ${group.reasonToValidate}`, "");
  lines.push("**Line-pinned evidence and path to sink**", "");
  const pathEvidence = uniqueStrings([
    ...group.traces.slice(0, 3).map((trace) => trace.reason),
    ...group.evidenceLocations.slice(0, 8),
  ]);
  for (const value of pathEvidence) {
    lines.push(`- ${value}`);
  }
  if (group.traces.length > 3 || group.evidenceLocations.length > 8) {
    lines.push("- Additional traces and locations are in the Technical appendix.");
  }
  lines.push("", "**Validation recipe**", "");
  group.validationSteps.forEach((step, index) => {
    lines.push(`${index + 1}. ${step}`);
  });
  lines.push("", `**Expected result:** ${group.expectedResult}`, "");
  lines.push("**Prompt for your coding agent**", "");
  lines.push("```text", group.agentPrompt, "```", "");
  lines.push(
    `*Deterministic actionability score: ${group.actionabilityScore}; static confidence contributes ${group.actionabilitySignals.staticConfidence} points.*`,
    "",
  );
}

function technicalAppendixHtml(
  projection: OwnerReportProjection,
  assessment: SecurityAssessment,
): string {
  const parts: string[] = [];
  if (projection.hiddenFixGroupCount > 0) {
    const hidden = projection.fixGroups.slice(projection.visibleFixGroups.length);
    parts.push(
      '<details class="coverage"><summary>Additional Fix now groups</summary>',
      compactFixGroupsHtml(hidden, assessment),
      "</details>",
    );
  }
  if (projection.hiddenValidationGroupCount > 0) {
    const hidden = projection.validationGroups.slice(projection.visibleValidationGroups.length);
    parts.push(
      `<details class="coverage"><summary>Additional Validate next groups (${hidden.length})</summary>`,
      htmlList(
        hidden.map(
          (group) =>
            `${group.title} — ${group.traces.length} static traces — actionability ${group.actionabilityScore}`,
        ),
      ),
      "</details>",
    );
  }

  const coverageRows = [
    ...assessment.coverage.map(coverageRowFromQuickCheck),
    ...(assessment.deepCoverage ?? []).map(coverageRowFromDeepArea),
  ];
  parts.push(coverageDetailsHtml(`Coverage — ${projection.coverage.label}`, coverageRows));

  const limitations = uniqueStrings([assessment.limitation, ...(assessment.limitations ?? [])]);
  parts.push(
    '<details class="coverage"><summary>Limitations</summary>',
    htmlList(limitations),
    "</details>",
  );

  const candidatesById = new Map(
    (assessment.hypothesisCandidates ?? []).map((candidate) => [candidate.id, candidate]),
  );
  parts.push(
    `<details class="coverage"><summary>Raw static traces (${assessment.staticHypotheses?.length ?? 0})</summary>`,
    htmlList(
      (assessment.staticHypotheses ?? []).map((hypothesis) => {
        const candidate = candidatesById.get(hypothesis.candidateId);
        return `[${hypothesis.status}] ${hypothesis.title} — ${
          candidate?.candidateReason ?? hypothesis.pathSummary
        } — promotion: ${hypothesis.promotion.reasons.join(", ")}`;
      }),
    ),
    "</details>",
    `<details class="coverage"><summary>Hypothesis candidates (${assessment.hypothesisCandidates?.length ?? 0})</summary>`,
    htmlList(
      (assessment.hypothesisCandidates ?? []).map(
        (candidate) => `[${candidate.family}] ${candidate.candidateReason}`,
      ),
    ),
    "</details>",
    `<p class="note">Repository snapshot: ${assessment.manifest.fileCount} files, ${assessment.findings.length} raw direct findings. Full evidence, graph refs, recipes, and machine records are in report.json.</p>`,
  );
  return parts.join("");
}

function compactFixGroupsHtml(
  groups: ReadonlyArray<OwnerFixGroup>,
  assessment: SecurityAssessment,
): string {
  return htmlList(
    groups.map((group) => {
      const locations = actionLocationsForReport(group.action, assessment);
      return `${group.action.remediation.title}${
        locations.length > 0 ? ` — ${locations.join(", ")}` : ""
      }`;
    }),
  );
}

function appendTechnicalAppendixMarkdown(
  lines: string[],
  projection: OwnerReportProjection,
  assessment: SecurityAssessment,
): void {
  lines.push(
    "## Technical appendix",
    "",
    "Remaining groups, raw static traces, candidates, coverage, and scanner limitations. Complete machine records remain in `report.json`.",
    "",
  );
  if (projection.hiddenFixGroupCount > 0) {
    lines.push(
      `<details><summary>Additional Fix now groups (${projection.hiddenFixGroupCount})</summary>`,
      "",
    );
    for (const group of projection.fixGroups.slice(projection.visibleFixGroups.length)) {
      const locations = actionLocationsForReport(group.action, assessment);
      lines.push(
        `- **${group.action.remediation.title}**${
          locations.length > 0 ? ` — ${locations.join(", ")}` : ""
        }`,
      );
    }
    lines.push("", "</details>", "");
  }
  if (projection.hiddenValidationGroupCount > 0) {
    lines.push(
      `<details><summary>Additional Validate next groups (${projection.hiddenValidationGroupCount})</summary>`,
      "",
    );
    for (const group of projection.validationGroups.slice(
      projection.visibleValidationGroups.length,
    )) {
      lines.push(
        `- **${group.title}** — ${group.traces.length} static traces — actionability ${group.actionabilityScore}`,
      );
    }
    lines.push("", "</details>", "");
  }

  lines.push(
    "### Coverage",
    "",
    `**State:** ${projection.coverage.label}. ${projection.coverage.detail}`,
    "",
  );
  lines.push("| Check | Status | Notes |", "| --- | --- | --- |");
  for (const entry of assessment.coverage) {
    const row = coverageRowFromQuickCheck(entry);
    lines.push(`| ${row.label} | ${row.statusLabel} | ${row.note} |`);
  }
  for (const entry of assessment.deepCoverage ?? []) {
    const row = coverageRowFromDeepArea(entry);
    lines.push(`| ${row.label} | ${row.statusLabel} | ${row.note} |`);
  }
  lines.push("", "### Limitations", "");
  for (const limitation of uniqueStrings([
    assessment.limitation,
    ...(assessment.limitations ?? []),
  ])) {
    lines.push(`- ${limitation}`);
  }
  lines.push("");

  const candidatesById = new Map(
    (assessment.hypothesisCandidates ?? []).map((candidate) => [candidate.id, candidate]),
  );
  lines.push(
    `<details><summary>Raw static traces (${assessment.staticHypotheses?.length ?? 0})</summary>`,
    "",
  );
  for (const hypothesis of assessment.staticHypotheses ?? []) {
    const candidate = candidatesById.get(hypothesis.candidateId);
    lines.push(
      `- \`${hypothesis.status}\` **${hypothesis.title}** — ${
        candidate?.candidateReason ?? hypothesis.pathSummary
      } — promotion: ${hypothesis.promotion.reasons.join(", ")}`,
    );
  }
  lines.push("", "</details>", "");
  lines.push(
    `<details><summary>Hypothesis candidates (${assessment.hypothesisCandidates?.length ?? 0})</summary>`,
    "",
  );
  for (const candidate of assessment.hypothesisCandidates ?? []) {
    lines.push(`- \`${candidate.family}\` ${candidate.candidateReason}`);
  }
  lines.push(
    "",
    "</details>",
    "",
    `${assessment.manifest.fileCount} files · ${assessment.findings.length} raw direct findings · full evidence, graph refs, recipes, and machine records in \`report.json\`.`,
    "",
  );
}

function fixNowLede(projection: OwnerReportProjection): string {
  if (projection.fixGroups.length === 0) {
    return "No direct scanner-backed fixes were produced by the checks that completed.";
  }
  const hidden = projection.hiddenFixGroupCount;
  return `Direct scanner-backed action groups, in deterministic priority order.${
    hidden > 0
      ? ` Showing ${projection.visibleFixGroups.length} of ${projection.fixGroups.length}; ${hidden} additional blocking ${
          hidden === 1 ? "group is" : "groups are"
        } in the Technical appendix.`
      : ""
  }`;
}

function validateNextLede(projection: OwnerReportProjection): string {
  if (projection.validationGroups.length === 0) {
    return "No unlinked, statically supported hypotheses require owner validation.";
  }
  const hidden = projection.hiddenValidationGroupCount;
  return `Unconfirmed static paths, grouped by deterministic root-cause facts. Confirm or disprove each group before changing code.${
    hidden > 0
      ? ` Showing ${projection.visibleValidationGroups.length} of ${projection.validationGroups.length}; ${hidden} additional ${
          hidden === 1 ? "group is" : "groups are"
        } in the Technical appendix.`
      : ""
  }`;
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

function uniqueStrings(values: ReadonlyArray<string>): string[] {
  return [...new Set(values)];
}

// Kept for the JSON contract surface; finding-context detail stays in report.json
// rather than the owner-facing HTML/Markdown.
export type { FindingContextAssessment };
