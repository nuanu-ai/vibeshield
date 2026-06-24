import { securityGraphStableId } from "./security-graph.js";

export interface HypothesisCandidate {
  readonly id: string;
  readonly ruleId: string;
  readonly family: string;
  readonly title: string;
  readonly findingIds: ReadonlyArray<string>;
  readonly supportingNodeIds: ReadonlyArray<string>;
  readonly supportingEdgeIds: ReadonlyArray<string>;
  readonly contradictingNodeIds: ReadonlyArray<string>;
  readonly contradictingEdgeIds: ReadonlyArray<string>;
  readonly coverageRefs: ReadonlyArray<string>;
  readonly requiredValidation: ReadonlyArray<string>;
  readonly candidateReason: string;
}

export interface HypothesisCandidateValidationContext {
  readonly findingIds?: ReadonlySet<string> | ReadonlyArray<string>;
  readonly graphNodeIds?: ReadonlySet<string> | ReadonlyArray<string>;
  readonly graphEdgeIds?: ReadonlySet<string> | ReadonlyArray<string>;
}

export class HypothesisCandidateValidationError extends Error {
  override readonly name = "HypothesisCandidateValidationError";
}

export function hypothesisCandidateId(
  graphVersion: string,
  ruleId: string,
  parts: ReadonlyArray<string>,
): string {
  return securityGraphStableId("hypothesis_candidate", [graphVersion, ruleId, ...parts]);
}

export function validateHypothesisCandidates(
  candidates: ReadonlyArray<HypothesisCandidate>,
  context: HypothesisCandidateValidationContext = {},
): HypothesisCandidate[] {
  const findingIds = context.findingIds === undefined ? undefined : toSet(context.findingIds);
  const graphNodeIds = context.graphNodeIds === undefined ? undefined : toSet(context.graphNodeIds);
  const graphEdgeIds = context.graphEdgeIds === undefined ? undefined : toSet(context.graphEdgeIds);
  const seenIds = new Set<string>();

  for (const candidate of candidates) {
    assertNonEmpty(candidate.id, "hypothesisCandidate id");
    assertUnique(candidate.id, seenIds, "hypothesisCandidate id");
    assertNonEmpty(candidate.ruleId, `hypothesisCandidate ${candidate.id} ruleId`);
    assertNonEmpty(candidate.family, `hypothesisCandidate ${candidate.id} family`);
    assertNonEmpty(candidate.title, `hypothesisCandidate ${candidate.id} title`);
    assertNonEmpty(
      candidate.candidateReason,
      `hypothesisCandidate ${candidate.id} candidateReason`,
    );
    assertNonEmptyList(candidate.coverageRefs, `hypothesisCandidate ${candidate.id} coverageRefs`);
    assertNonEmptyList(
      candidate.requiredValidation,
      `hypothesisCandidate ${candidate.id} requiredValidation`,
    );

    if (candidate.supportingNodeIds.length === 0 && candidate.supportingEdgeIds.length === 0) {
      fail(`hypothesisCandidate ${candidate.id} requires supporting graph refs`);
    }
    for (const findingId of candidate.findingIds) {
      assertNonEmpty(findingId, `hypothesisCandidate ${candidate.id} findingId`);
      if (findingIds !== undefined && !findingIds.has(findingId)) {
        fail(`hypothesisCandidate ${candidate.id} references unknown finding: ${findingId}`);
      }
    }
    for (const nodeId of [...candidate.supportingNodeIds, ...candidate.contradictingNodeIds]) {
      assertNonEmpty(nodeId, `hypothesisCandidate ${candidate.id} graphNodeId`);
      if (graphNodeIds !== undefined && !graphNodeIds.has(nodeId)) {
        fail(`hypothesisCandidate ${candidate.id} references unknown graph node: ${nodeId}`);
      }
    }
    for (const edgeId of [...candidate.supportingEdgeIds, ...candidate.contradictingEdgeIds]) {
      assertNonEmpty(edgeId, `hypothesisCandidate ${candidate.id} graphEdgeId`);
      if (graphEdgeIds !== undefined && !graphEdgeIds.has(edgeId)) {
        fail(`hypothesisCandidate ${candidate.id} references unknown graph edge: ${edgeId}`);
      }
    }
  }

  return sortHypothesisCandidates(candidates);
}

export function sortHypothesisCandidates(
  candidates: ReadonlyArray<HypothesisCandidate>,
): HypothesisCandidate[] {
  return [...candidates].sort(
    (a, b) =>
      a.family.localeCompare(b.family) ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.title.localeCompare(b.title) ||
      a.id.localeCompare(b.id),
  );
}

function assertNonEmpty(value: string, label: string): void {
  if (value.trim() === "") {
    fail(`${label} is required`);
  }
}

function assertNonEmptyList(values: ReadonlyArray<string>, label: string): void {
  if (values.length === 0) {
    fail(`${label} are required`);
  }
  for (const value of values) {
    assertNonEmpty(value, label);
  }
}

function assertUnique(value: string, seen: Set<string>, label: string): void {
  if (seen.has(value)) {
    fail(`${label} is duplicated: ${value}`);
  }
  seen.add(value);
}

function toSet(values: ReadonlySet<string> | ReadonlyArray<string>): Set<string> {
  return values instanceof Set ? new Set(values) : new Set(values);
}

function fail(message: string): never {
  throw new HypothesisCandidateValidationError(message);
}
