import type { ActionCandidate, VerdictImpact } from "../domain/action.js";
import {
  type DeepActionGroup,
  deepActionGroupId,
  validateDeepActionGroups,
} from "../domain/action-group.js";
import type { FindingContextAssessment } from "../domain/finding-context-assessment.js";
import { validateFindingContextAssessments } from "../domain/finding-context-assessment.js";
import type { HypothesisCandidate } from "../domain/hypothesis-candidate.js";
import { validateHypothesisCandidates } from "../domain/hypothesis-candidate.js";
import type { StaticHypothesis } from "../domain/static-hypothesis.js";
import { validateStaticHypothesisRecords } from "../domain/static-hypothesis.js";

export interface GroupDeepActionsInput {
  readonly directActions: ReadonlyArray<ActionCandidate>;
  readonly staticHypotheses: ReadonlyArray<StaticHypothesis>;
  readonly candidates: ReadonlyArray<HypothesisCandidate>;
  readonly findingContexts?: ReadonlyArray<FindingContextAssessment>;
}

interface ValidatedDirectAction extends ActionCandidate {}

export function groupDeepActions(input: GroupDeepActionsInput): DeepActionGroup[] {
  const directActions = validateDirectActions(input.directActions);
  const candidates = validateHypothesisCandidates(input.candidates);
  const candidateById = new Map(candidates.map((candidate) => [candidate.id, candidate]));
  const staticHypotheses = validateStaticHypothesisRecords(input.staticHypotheses, {
    candidateIds: candidates.map((candidate) => candidate.id),
  });
  const knownFindingIds = new Set([
    ...directActions.flatMap((action) => action.findingIds),
    ...candidates.flatMap((candidate) => candidate.findingIds),
  ]);
  const findingContexts = validateFindingContextAssessments(input.findingContexts ?? [], {
    hypothesisIds: staticHypotheses.map((hypothesis) => hypothesis.id),
  });
  validateContextFindingIds(findingContexts, knownFindingIds);

  const contextHypothesesByFindingId = linkedContextHypothesesByFindingId(findingContexts);
  const linkedHypothesisIds = new Set<string>();
  const groups: DeepActionGroup[] = [];

  for (const action of directActions) {
    const hypothesisIds = linkedHypothesesForAction(
      action,
      staticHypotheses,
      candidateById,
      contextHypothesesByFindingId,
    );
    for (const hypothesisId of hypothesisIds) {
      linkedHypothesisIds.add(hypothesisId);
    }
    groups.push(directActionGroup(action, hypothesisIds));
  }

  for (const hypothesis of staticHypotheses) {
    if (hypothesis.status === "statically_contradicted" || linkedHypothesisIds.has(hypothesis.id)) {
      continue;
    }
    groups.push(hypothesisOnlyGroup(hypothesis, requiredCandidate(hypothesis, candidateById)));
  }

  return validateDeepActionGroups(groups, {
    directActionIds: directActions.map((action) => action.id),
    findingIds: [...knownFindingIds],
    evidenceIds: uniqueSorted([
      ...directActions.flatMap((action) => action.evidenceIds),
      ...staticHypotheses.flatMap((hypothesis) => [
        ...hypothesis.supportingEvidenceIds,
        ...hypothesis.contradictingEvidenceIds,
      ]),
    ]),
    hypothesisIds: staticHypotheses.map((hypothesis) => hypothesis.id),
  });
}

function directActionGroup(
  action: ValidatedDirectAction,
  hypothesisIds: ReadonlyArray<string>,
): DeepActionGroup {
  return {
    id: deepActionGroupId(["direct", action.id, ...hypothesisIds]),
    leadKind: "direct_finding",
    remediationKey: action.remediationKey,
    priorityScore: action.priorityScore,
    verdictImpact: action.verdictImpact,
    directActionIds: [action.id],
    findingIds: action.findingIds,
    hypothesisIds,
    evidenceIds: action.evidenceIds,
    affectedFiles: action.affectedFiles,
    reason:
      hypothesisIds.length === 0
        ? `Direct action ${action.id} has no linked static hypotheses.`
        : `Direct action ${action.id} includes linked static hypotheses: ${hypothesisIds.join(
            ", ",
          )}.`,
  };
}

function hypothesisOnlyGroup(
  hypothesis: StaticHypothesis,
  candidate: HypothesisCandidate,
): DeepActionGroup {
  return {
    id: deepActionGroupId(["hypothesis", hypothesis.id]),
    leadKind: "hypothesis",
    remediationKey: `hypothesis:${candidate.family}`,
    priorityScore: hypothesisPriorityScore(hypothesis),
    verdictImpact: hypothesisVerdictImpact(hypothesis),
    directActionIds: [],
    findingIds: uniqueSorted(candidate.findingIds),
    hypothesisIds: [hypothesis.id],
    evidenceIds: uniqueSorted([
      ...hypothesis.supportingEvidenceIds,
      ...hypothesis.contradictingEvidenceIds,
    ]),
    affectedFiles: [],
    reason: `Static hypothesis ${hypothesis.id} has no matching direct action and should be shown as a likely attack path.`,
  };
}

function linkedHypothesesForAction(
  action: ValidatedDirectAction,
  staticHypotheses: ReadonlyArray<StaticHypothesis>,
  candidateById: ReadonlyMap<string, HypothesisCandidate>,
  contextHypothesesByFindingId: ReadonlyMap<string, ReadonlyArray<string>>,
): string[] {
  const actionFindingIds = new Set(action.findingIds);
  const linkedByCandidate = staticHypotheses.flatMap((hypothesis) => {
    if (hypothesis.status === "statically_contradicted") {
      return [];
    }
    const candidate = requiredCandidate(hypothesis, candidateById);
    return candidate.findingIds.some((findingId) => actionFindingIds.has(findingId))
      ? [hypothesis.id]
      : [];
  });
  const linkedByContext = action.findingIds.flatMap(
    (findingId) => contextHypothesesByFindingId.get(findingId) ?? [],
  );
  const allowedHypothesisIds = new Set(
    staticHypotheses
      .filter((hypothesis) => hypothesis.status !== "statically_contradicted")
      .map((hypothesis) => hypothesis.id),
  );
  return uniqueSorted([...linkedByCandidate, ...linkedByContext]).filter((hypothesisId) =>
    allowedHypothesisIds.has(hypothesisId),
  );
}

function linkedContextHypothesesByFindingId(
  findingContexts: ReadonlyArray<FindingContextAssessment>,
): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const context of findingContexts) {
    if (context.status !== "linked_to_hypothesis") {
      continue;
    }
    out.set(context.findingId, uniqueSorted(context.hypothesisIds));
  }
  return out;
}

function hypothesisPriorityScore(hypothesis: StaticHypothesis): number {
  const base = (() => {
    switch (hypothesis.status) {
      case "statically_supported":
        return 80;
      case "candidate":
        return 50;
      case "inconclusive":
        return 30;
      case "statically_contradicted":
        return 0;
    }
  })();
  return base + Math.round(hypothesis.staticConfidence * 10);
}

function hypothesisVerdictImpact(hypothesis: StaticHypothesis): VerdictImpact {
  switch (hypothesis.status) {
    case "statically_supported":
      return "degrades";
    case "candidate":
    case "inconclusive":
    case "statically_contradicted":
      return "informational";
  }
}

function validateDirectActions(
  directActions: ReadonlyArray<ActionCandidate>,
): ValidatedDirectAction[] {
  const seenIds = new Set<string>();
  for (const action of directActions) {
    assertNonEmpty(action.id, "action id");
    assertUnique(action.id, seenIds, "action id");
    assertNonEmpty(action.remediationKey, `action ${action.id} remediationKey`);
    if (!Number.isFinite(action.priorityScore) || action.priorityScore < 0) {
      throw new Error(`action ${action.id} priorityScore must be a non-negative finite number`);
    }
    assertNonEmptyList(action.findingIds, `action ${action.id} findingIds`);
    for (const evidenceId of action.evidenceIds) {
      assertNonEmpty(evidenceId, `action ${action.id} evidenceId`);
    }
    for (const affectedFile of action.affectedFiles) {
      assertNonEmpty(affectedFile, `action ${action.id} affectedFile`);
    }
  }
  return [...directActions].sort(
    (a, b) => b.priorityScore - a.priorityScore || a.remediationKey.localeCompare(b.remediationKey),
  );
}

function validateContextFindingIds(
  findingContexts: ReadonlyArray<FindingContextAssessment>,
  knownFindingIds: ReadonlySet<string>,
): void {
  for (const context of findingContexts) {
    if (!knownFindingIds.has(context.findingId)) {
      throw new Error(`findingContext references unknown finding: ${context.findingId}`);
    }
  }
}

function requiredCandidate(
  hypothesis: StaticHypothesis,
  candidateById: ReadonlyMap<string, HypothesisCandidate>,
): HypothesisCandidate {
  const candidate = candidateById.get(hypothesis.candidateId);
  if (candidate === undefined) {
    throw new Error(
      `staticHypothesis ${hypothesis.id} references unknown candidate: ${hypothesis.candidateId}`,
    );
  }
  return candidate;
}

function assertNonEmpty(value: string, label: string): void {
  if (value.trim() === "") {
    throw new Error(`${label} is required`);
  }
}

function assertNonEmptyList(values: ReadonlyArray<string>, label: string): void {
  if (values.length === 0) {
    throw new Error(`${label} are required`);
  }
  for (const value of values) {
    assertNonEmpty(value, label);
  }
}

function assertUnique(value: string, seen: Set<string>, label: string): void {
  if (seen.has(value)) {
    throw new Error(`${label} is duplicated: ${value}`);
  }
  seen.add(value);
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}
