import { verdictLabel } from "../domain/assessment.js";
import type { Evidence } from "../domain/evidence.js";
import type { HypothesisCandidate } from "../domain/hypothesis-candidate.js";
import type { RankedAction, SecurityAssessment } from "../domain/security-assessment.js";
import { securityGraphStableId } from "../domain/security-graph.js";
import type { StaticHypothesis } from "../domain/static-hypothesis.js";
import type { ValidationRecipe } from "../domain/validation-recipe.js";

export const MAX_FIX_NOW_GROUPS = 5;
export const MAX_VALIDATE_NEXT_GROUPS = 3;

export type OwnerCoverageState = "complete" | "partial" | "incomplete";
export type OwnerBannerTone = "critical" | "warn" | "ok";

export interface OwnerHypothesisTrace {
  readonly hypothesis: StaticHypothesis;
  readonly candidate?: HypothesisCandidate;
  readonly recipe?: ValidationRecipe;
  readonly reason: string;
  readonly evidenceLocations: ReadonlyArray<string>;
}

export interface OwnerFixGroup {
  readonly id: string;
  readonly action: RankedAction;
  readonly relatedStaticEvidence: ReadonlyArray<OwnerHypothesisTrace>;
}

export interface OwnerActionabilitySignals {
  readonly potentialImpact: number;
  readonly externalReachability: number;
  readonly evidenceCompleteness: number;
  readonly missingObservedGuard: number;
  readonly staticSupport: number;
  readonly remediationBreadth: number;
  readonly staticConfidence: number;
}

export interface OwnerValidationGroup {
  readonly id: string;
  readonly rootCauseKey: string;
  readonly family: string;
  readonly title: string;
  readonly impact: string;
  readonly reasonToValidate: string;
  readonly actionabilityScore: number;
  readonly actionabilitySignals: OwnerActionabilitySignals;
  readonly traces: ReadonlyArray<OwnerHypothesisTrace>;
  readonly evidenceLocations: ReadonlyArray<string>;
  readonly validationSteps: ReadonlyArray<string>;
  readonly expectedResult: string;
  readonly agentPrompt: string;
}

export interface OwnerCoverageSummary {
  readonly state: OwnerCoverageState;
  readonly label: string;
  readonly detail: string;
}

export interface OwnerReportBanner {
  readonly label: string;
  readonly subline: string;
  readonly tone: OwnerBannerTone;
}

export interface OwnerReportProjection {
  readonly fixGroups: ReadonlyArray<OwnerFixGroup>;
  readonly visibleFixGroups: ReadonlyArray<OwnerFixGroup>;
  readonly hiddenFixGroupCount: number;
  readonly validationGroups: ReadonlyArray<OwnerValidationGroup>;
  readonly visibleValidationGroups: ReadonlyArray<OwnerValidationGroup>;
  readonly hiddenValidationGroupCount: number;
  readonly coverage: OwnerCoverageSummary;
  readonly banner: OwnerReportBanner;
}

interface ValidationGroupAccumulator {
  readonly key: string;
  readonly rootCauseKey: string;
  readonly family: string;
  readonly title: string;
  readonly traces: OwnerHypothesisTrace[];
}

const FAMILY_IMPACT_SCORE: Readonly<Record<string, number>> = {
  external_input_to_dangerous_operation: 32,
  secret_impact_chain: 40,
  smart_contract_risk_path: 38,
  ci_supply_chain_path: 36,
  sast_reachable_path: 34,
  dependency_usage_path: 32,
  content_resource_exposure_path: 28,
};

const EXTERNALLY_REACHABLE_FAMILIES = new Set([
  "external_input_to_dangerous_operation",
  "sast_reachable_path",
  "content_resource_exposure_path",
]);

export function buildOwnerReportProjection(assessment: SecurityAssessment): OwnerReportProjection {
  const candidatesById = new Map(
    (assessment.hypothesisCandidates ?? []).map((candidate) => [candidate.id, candidate]),
  );
  const recipesByHypothesisId = new Map(
    (assessment.validationRecipes ?? []).map((recipe) => [recipe.hypothesisId, recipe]),
  );
  const evidenceById = new Map(assessment.evidence.map((record) => [record.id, record]));
  const supportedHypotheses = (assessment.staticHypotheses ?? []).filter(
    (hypothesis) =>
      hypothesis.status === "statically_supported" && hypothesis.promotion.publishable,
  );
  const explicitLinks = explicitHypothesisLinksByAction(assessment);
  const contextLinks = contextHypothesisLinksByFinding(assessment);
  const claimedHypothesisIds = new Set<string>();

  const fixGroups = assessment.rankedActions.map((action) => {
    const actionFindingIds = new Set(action.candidate.findingIds);
    const explicitlyLinked = explicitLinks.get(action.candidate.id) ?? new Set<string>();
    const contextLinked = new Set(
      action.candidate.findingIds.flatMap((findingId) => [...(contextLinks.get(findingId) ?? [])]),
    );
    const linked = supportedHypotheses
      .filter((hypothesis) => {
        if (claimedHypothesisIds.has(hypothesis.id)) {
          return false;
        }
        const candidate = candidatesById.get(hypothesis.candidateId);
        return (
          explicitlyLinked.has(hypothesis.id) ||
          contextLinked.has(hypothesis.id) ||
          candidate?.findingIds.some((findingId) => actionFindingIds.has(findingId)) === true
        );
      })
      .map((hypothesis) =>
        hypothesisTrace(
          hypothesis,
          candidatesById.get(hypothesis.candidateId),
          recipesByHypothesisId.get(hypothesis.id),
          evidenceById,
        ),
      )
      .sort(compareTraces);

    for (const trace of linked) {
      claimedHypothesisIds.add(trace.hypothesis.id);
    }

    return {
      id: action.candidate.id,
      action,
      relatedStaticEvidence: linked,
    } satisfies OwnerFixGroup;
  });

  const directFindingIds = new Set(
    assessment.rankedActions.flatMap((action) => action.candidate.findingIds),
  );
  const validationGroups = buildValidationGroups(
    supportedHypotheses.filter((hypothesis) => {
      if (claimedHypothesisIds.has(hypothesis.id)) {
        return false;
      }
      const candidate = candidatesById.get(hypothesis.candidateId);
      return candidate?.findingIds.some((findingId) => directFindingIds.has(findingId)) !== true;
    }),
    candidatesById,
    recipesByHypothesisId,
    evidenceById,
  );
  const coverage = ownerCoverageSummary(assessment);
  const banner = ownerBanner(assessment, fixGroups, validationGroups, coverage);

  return {
    fixGroups,
    visibleFixGroups: fixGroups.slice(0, MAX_FIX_NOW_GROUPS),
    hiddenFixGroupCount: Math.max(0, fixGroups.length - MAX_FIX_NOW_GROUPS),
    validationGroups,
    visibleValidationGroups: validationGroups.slice(0, MAX_VALIDATE_NEXT_GROUPS),
    hiddenValidationGroupCount: Math.max(0, validationGroups.length - MAX_VALIDATE_NEXT_GROUPS),
    coverage,
    banner,
  };
}

function buildValidationGroups(
  hypotheses: ReadonlyArray<StaticHypothesis>,
  candidatesById: ReadonlyMap<string, HypothesisCandidate>,
  recipesByHypothesisId: ReadonlyMap<string, ValidationRecipe>,
  evidenceById: ReadonlyMap<string, Evidence>,
): OwnerValidationGroup[] {
  const grouped = new Map<string, ValidationGroupAccumulator>();

  for (const hypothesis of hypotheses) {
    const candidate = candidatesById.get(hypothesis.candidateId);
    const family = candidate?.family ?? "static_analysis";
    const title = candidate?.title ?? hypothesis.title;
    const rootCauseKey = hypothesis.promotion.rootCauseKey;
    if (rootCauseKey === undefined) {
      continue;
    }
    const key = rootCauseKey;
    const trace = hypothesisTrace(
      hypothesis,
      candidate,
      recipesByHypothesisId.get(hypothesis.id),
      evidenceById,
    );
    const existing = grouped.get(key);
    if (existing === undefined) {
      grouped.set(key, { key, rootCauseKey, family, title, traces: [trace] });
    } else {
      existing.traces.push(trace);
    }
  }

  return [...grouped.values()]
    .map(ownerValidationGroup)
    .sort(
      (a, b) =>
        b.actionabilityScore - a.actionabilityScore ||
        a.family.localeCompare(b.family) ||
        a.title.localeCompare(b.title) ||
        a.id.localeCompare(b.id),
    );
}

function ownerValidationGroup(group: ValidationGroupAccumulator): OwnerValidationGroup {
  const traces = [...group.traces].sort(compareTraces);
  const evidenceLocations = uniqueSorted(traces.flatMap((trace) => trace.evidenceLocations));
  const representative = requiredFirst(traces, `validation group ${group.title}`);
  const validationSteps = uniquePreservingOrder(
    representative.recipe?.steps ??
      representative.candidate?.requiredValidation.map(humanizeValidationStep) ?? [
        "Trace the observed entrypoint to the sink and identify any guard or control on the path.",
        "Exercise the path with a disposable, non-production fixture.",
      ],
  );
  const expectedResult =
    representative.recipe?.expectedResult ??
    "The path is either reproduced without an effective guard, or the blocking guard is identified with line-pinned evidence.";
  const signals = actionabilitySignals(group.family, group.title, traces, evidenceLocations.length);
  const actionabilityScore = Object.values(signals).reduce((sum, value) => sum + value, 0);
  const impact = impactForFamily(group.family);
  const reasonToValidate = validationReason(traces, evidenceLocations.length);
  const id = securityGraphStableId("owner_validation_group", [group.key]);

  return {
    id,
    rootCauseKey: group.rootCauseKey,
    family: group.family,
    title: group.title,
    impact,
    reasonToValidate,
    actionabilityScore,
    actionabilitySignals: signals,
    traces,
    evidenceLocations,
    validationSteps,
    expectedResult,
    agentPrompt: validationAgentPrompt(
      group.title,
      traces,
      evidenceLocations,
      validationSteps,
      expectedResult,
    ),
  };
}

function actionabilitySignals(
  family: string,
  title: string,
  traces: ReadonlyArray<OwnerHypothesisTrace>,
  evidenceLocationCount: number,
): OwnerActionabilitySignals {
  const completeChains = traces.filter((trace) => {
    return (
      trace.hypothesis.promotion.source === "external_input" &&
      trace.hypothesis.promotion.sink === "typed_security_sink" &&
      trace.hypothesis.promotion.path === "connected_security_flow" &&
      trace.hypothesis.promotion.evidence === "current_line_pinned" &&
      trace.hypothesis.supportingEvidenceIds.length > 0 &&
      trace.hypothesis.coverageState === "checked"
    );
  }).length;
  const withoutObservedGuard = traces.filter(
    (trace) =>
      trace.hypothesis.promotion.control === "absent" ||
      trace.hypothesis.promotion.control === "irrelevant",
  ).length;
  const averageConfidence =
    traces.reduce((sum, trace) => sum + trace.hypothesis.staticConfidence, 0) /
    Math.max(1, traces.length);

  return {
    potentialImpact: potentialImpactScore(family, title),
    externalReachability: EXTERNALLY_REACHABLE_FAMILIES.has(family) ? 20 : 8,
    evidenceCompleteness: Math.round((completeChains / Math.max(1, traces.length)) * 20),
    missingObservedGuard: Math.round((withoutObservedGuard / Math.max(1, traces.length)) * 10),
    staticSupport: 10,
    remediationBreadth: Math.min(
      10,
      Math.max(1, Math.ceil(Math.log2(traces.length + 1))) +
        Math.min(3, Math.floor(evidenceLocationCount / 5)),
    ),
    staticConfidence: Math.round(averageConfidence * 5),
  };
}

function potentialImpactScore(family: string, title: string): number {
  const normalized = normalizeFact(title);
  if (/(remote code|command execution|deseriali[sz]ation|reentrancy)/.test(normalized)) {
    return 40;
  }
  if (
    /(sql|nosql|xxe|file access|path traversal|secret|credential|access control|ssrf)/.test(
      normalized,
    )
  ) {
    return 38;
  }
  if (/(xss|csrf|redirect|cookie|jwt|two-factor|authentication)/.test(normalized)) {
    return 34;
  }
  return FAMILY_IMPACT_SCORE[family] ?? 24;
}

function hypothesisTrace(
  hypothesis: StaticHypothesis,
  candidate: HypothesisCandidate | undefined,
  recipe: ValidationRecipe | undefined,
  evidenceById: ReadonlyMap<string, Evidence>,
): OwnerHypothesisTrace {
  const evidenceLocations = uniqueSorted([
    ...hypothesis.supportingEvidenceIds.flatMap((evidenceId) => {
      const evidence = evidenceById.get(evidenceId);
      return evidence === undefined ? [] : [evidenceLocation(evidence)];
    }),
    ...locationsFromFact(candidate?.candidateReason ?? ""),
  ]);
  return {
    hypothesis,
    ...(candidate === undefined ? {} : { candidate }),
    ...(recipe === undefined ? {} : { recipe }),
    reason: candidate?.candidateReason ?? hypothesis.pathSummary,
    evidenceLocations,
  };
}

function explicitHypothesisLinksByAction(assessment: SecurityAssessment): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const group of assessment.deepActionGroups ?? []) {
    if (group.leadKind !== "direct_finding") {
      continue;
    }
    for (const actionId of group.directActionIds) {
      const links = out.get(actionId) ?? new Set<string>();
      for (const hypothesisId of group.hypothesisIds) {
        links.add(hypothesisId);
      }
      out.set(actionId, links);
    }
  }
  return out;
}

function contextHypothesisLinksByFinding(
  assessment: SecurityAssessment,
): Map<string, ReadonlyArray<string>> {
  return new Map(
    (assessment.findingContextAssessments ?? [])
      .filter((context) => context.hypothesisIds.length > 0)
      .map((context) => [context.findingId, context.hypothesisIds]),
  );
}

function ownerCoverageSummary(assessment: SecurityAssessment): OwnerCoverageSummary {
  const states = [
    ...assessment.coverage.map((entry) => entry.status),
    ...(assessment.deepCoverage ?? []).map((entry) => entry.state),
  ];
  const failed = states.filter((state) => state === "failed").length;
  const skippedSecurityAnalysis = (assessment.deepCoverage ?? []).filter(
    (entry) =>
      entry.state === "skipped" &&
      ["call_graph", "control_flow", "data_flow", "language_support"].includes(entry.area),
  ).length;
  const limited =
    states.filter((state) => state === "degraded" || state === "partial").length +
    skippedSecurityAnalysis;
  if (failed > 0) {
    return {
      state: "incomplete",
      label: "Incomplete",
      detail: `${failed} ${failed === 1 ? "check failed" : "checks failed"}; review coverage before deploying.`,
    };
  }
  if (limited > 0) {
    return {
      state: "partial",
      label: "Partial",
      detail: `${limited} ${limited === 1 ? "coverage area is" : "coverage areas are"} partial, skipped, or degraded.`,
    };
  }
  return {
    state: "complete",
    label: "Complete",
    detail: "All applicable checks reported complete coverage or were not applicable.",
  };
}

function ownerBanner(
  assessment: SecurityAssessment,
  fixGroups: ReadonlyArray<OwnerFixGroup>,
  validationGroups: ReadonlyArray<OwnerValidationGroup>,
  coverage: OwnerCoverageSummary,
): OwnerReportBanner {
  const redVerdict =
    assessment.verdict === "critical-fix-needed" || assessment.verdict === "not-ready-to-deploy";
  if (assessment.verdict === "not-ready-to-deploy" && validationGroups.length > 0) {
    const firstTitle = requiredFirst(validationGroups, "validation groups").title;
    const directPrefix =
      fixGroups.length === 0
        ? ""
        : `${fixGroups.length} direct ${fixGroups.length === 1 ? "fix is" : "fixes are"} also listed. `;
    return {
      label: "Validation required before deploy",
      subline: `${directPrefix}${validationGroups.length} unconfirmed static ${
        validationGroups.length === 1 ? "group needs" : "groups need"
      } validation. Confirm or disprove “${firstTitle}” before deploying.`,
      tone: "critical",
    };
  }
  if (fixGroups.length > 0) {
    const firstTitle = requiredFirst(fixGroups, "fix groups").action.remediation.title;
    return {
      label: verdictLabel(assessment.verdict),
      subline: `${fixGroups.length} direct ${fixGroups.length === 1 ? "fix" : "fixes"} before deploy. Start with “${firstTitle}”.`,
      tone: redVerdict ? "critical" : "warn",
    };
  }
  if (redVerdict && validationGroups.length > 0) {
    const firstTitle = requiredFirst(validationGroups, "validation groups").title;
    return {
      label: "Validation required before deploy",
      subline: `${validationGroups.length} unconfirmed static ${
        validationGroups.length === 1 ? "group needs" : "groups need"
      } validation. Start by confirming or disproving “${firstTitle}”.`,
      tone: "critical",
    };
  }
  if (assessment.verdict === "scan-incomplete" || coverage.state === "incomplete") {
    return {
      label: "Scan incomplete",
      subline: `${coverage.detail} Use the Technical appendix to identify the missing checks.`,
      tone: "warn",
    };
  }
  if (coverage.state === "partial") {
    return {
      label: "Coverage limited",
      subline:
        "No direct fixes or supported validation groups block the report, but partial coverage limits the deploy decision.",
      tone: "warn",
    };
  }
  if (redVerdict) {
    return {
      label: "Deployment decision needs review",
      subline:
        "No direct fix or supported validation group explains the stored red verdict. Review the Technical appendix before deploying.",
      tone: "critical",
    };
  }
  return {
    label: verdictLabel(assessment.verdict),
    subline:
      "No direct fixes or supported static validation groups were found by the checks that completed.",
    tone: "ok",
  };
}

function validationAgentPrompt(
  title: string,
  traces: ReadonlyArray<OwnerHypothesisTrace>,
  evidenceLocations: ReadonlyArray<string>,
  validationSteps: ReadonlyArray<string>,
  expectedResult: string,
): string {
  const pathLines = uniquePreservingOrder(traces.map((trace) => trace.reason))
    .slice(0, 3)
    .map((reason) => `- ${reason}`);
  const locationLines = evidenceLocations.slice(0, 8).map((location) => `- ${location}`);
  const stepLines = validationSteps.map((step, index) => `${index + 1}. ${step}`);
  return [
    "First confirm or disprove this static hypothesis. Do not change code based on the hypothesis alone.",
    "",
    `Hypothesis group: ${title}`,
    "",
    "Observed static paths:",
    ...(pathLines.length > 0 ? pathLines : ["- No line-pinned path summary was recorded."]),
    "",
    "Evidence locations:",
    ...(locationLines.length > 0 ? locationLines : ["- See report.json graph and evidence refs."]),
    "",
    "Validation steps:",
    ...stepLines,
    "",
    `Expected result: ${expectedResult}`,
    "",
    "If the path is confirmed, implement the narrowest root-cause fix and add a regression test. If it is disproved, document the observed guard or control and leave behavior unchanged.",
  ].join("\n");
}

function validationReason(
  traces: ReadonlyArray<OwnerHypothesisTrace>,
  evidenceLocationCount: number,
): string {
  const withoutGuard = traces.filter(
    (trace) =>
      trace.hypothesis.promotion.control === "absent" ||
      trace.hypothesis.promotion.control === "irrelevant",
  ).length;
  return `${traces.length} statically supported ${traces.length === 1 ? "trace" : "traces"} across ${
    evidenceLocationCount === 0
      ? "graph-referenced evidence"
      : `${evidenceLocationCount} line-pinned locations`
  }; ${withoutGuard === traces.length ? "no blocking guard was observed" : "some guard evidence exists and must be checked"}.`;
}

function impactForFamily(family: string): string {
  switch (family) {
    case "external_input_to_dangerous_operation":
      return "Request-controlled data may reach a security-sensitive operation without an effective guard.";
    case "sast_reachable_path":
      return "A direct scanner finding may be reachable from an analyzed boundary.";
    case "dependency_usage_path":
      return "A vulnerable component may be imported, used, or reachable in the application path.";
    case "ci_supply_chain_path":
      return "A build workflow may reach mutable or privileged supply-chain resources.";
    case "secret_impact_chain":
      return "A secret may reach a privileged integration or exposed resource.";
    case "content_resource_exposure_path":
      return "Static content may expose a hidden or private resource.";
    case "smart_contract_risk_path":
      return "A contract value-transfer path may execute before the related state update.";
    default:
      return "The static graph supports a potentially security-relevant path that needs validation.";
  }
}

function locationsFromFact(value: string): string[] {
  const locations: string[] = [];
  const pattern = /\(([^()\n]+):(\d+)(?:-\d+)?\)/g;
  for (const match of value.matchAll(pattern)) {
    const filePath = match[1]?.trim();
    const line = match[2];
    if (filePath !== undefined && filePath !== "" && line !== undefined) {
      locations.push(`${filePath}:${line}`);
    }
  }
  return uniqueSorted(locations);
}

function evidenceLocation(evidence: Evidence): string {
  const line =
    evidence.startLine === evidence.endLine
      ? `${evidence.startLine}`
      : `${evidence.startLine}-${evidence.endLine}`;
  return `${evidence.filePath}:${line}`;
}

function compareTraces(a: OwnerHypothesisTrace, b: OwnerHypothesisTrace): number {
  return (
    b.hypothesis.staticConfidence - a.hypothesis.staticConfidence ||
    a.reason.localeCompare(b.reason) ||
    a.hypothesis.id.localeCompare(b.hypothesis.id)
  );
}

function humanizeValidationStep(value: string): string {
  const words = value.replaceAll("_", " ");
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}.`;
}

function normalizeFact(value: string): string {
  return value.replace(/\s+/g, " ").trim().toLowerCase();
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function uniquePreservingOrder(values: ReadonlyArray<string>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    if (seen.has(value)) {
      continue;
    }
    seen.add(value);
    out.push(value);
  }
  return out;
}

function requiredFirst<T>(values: ReadonlyArray<T>, label: string): T {
  const first = values[0];
  if (first === undefined) {
    throw new Error(`${label} requires at least one record`);
  }
  return first;
}
