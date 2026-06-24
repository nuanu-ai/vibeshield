import type { GraphCoverageState } from "./security-graph.js";

export interface FindingContextAssessment {
  readonly findingId: string;
  readonly status: FindingContextStatus;
  readonly graphNodeIds: ReadonlyArray<string>;
  readonly graphEdgeIds: ReadonlyArray<string>;
  readonly hypothesisIds: ReadonlyArray<string>;
  readonly reason: string;
  readonly coverageState: GraphCoverageState;
}

export type FindingContextStatus =
  | "standalone"
  | "corroborated"
  | "weakened"
  | "contradicted"
  | "linked_to_hypothesis";

export interface FindingContextAssessmentValidationContext {
  readonly findingIds?: ReadonlySet<string> | ReadonlyArray<string>;
  readonly graphNodeIds?: ReadonlySet<string> | ReadonlyArray<string>;
  readonly graphEdgeIds?: ReadonlySet<string> | ReadonlyArray<string>;
  readonly hypothesisIds?: ReadonlySet<string> | ReadonlyArray<string>;
}

const STATUSES = new Set<FindingContextStatus>([
  "standalone",
  "corroborated",
  "weakened",
  "contradicted",
  "linked_to_hypothesis",
]);

const COVERAGE_STATES = new Set<GraphCoverageState>([
  "checked",
  "skipped",
  "failed",
  "degraded",
  "partial",
]);

export class FindingContextAssessmentValidationError extends Error {
  override readonly name = "FindingContextAssessmentValidationError";
}

export function validateFindingContextAssessments(
  records: ReadonlyArray<FindingContextAssessment>,
  context: FindingContextAssessmentValidationContext = {},
): FindingContextAssessment[] {
  const expectedFindingIds =
    context.findingIds === undefined ? undefined : toSet(context.findingIds);
  const graphNodeIds = context.graphNodeIds === undefined ? undefined : toSet(context.graphNodeIds);
  const graphEdgeIds = context.graphEdgeIds === undefined ? undefined : toSet(context.graphEdgeIds);
  const hypothesisIds =
    context.hypothesisIds === undefined ? undefined : toSet(context.hypothesisIds);
  const seenFindingIds = new Set<string>();

  for (const record of records) {
    assertNonEmpty(record.findingId, "findingContext findingId");
    assertKnown(record.status, STATUSES, `findingContext ${record.findingId} status`);
    assertKnown(
      record.coverageState,
      COVERAGE_STATES,
      `findingContext ${record.findingId} coverageState`,
    );
    assertNonEmpty(record.reason, `findingContext ${record.findingId} reason`);
    assertUnique(record.findingId, seenFindingIds, "findingContext findingId");

    if (expectedFindingIds !== undefined && !expectedFindingIds.has(record.findingId)) {
      fail(`findingContext references unknown finding: ${record.findingId}`);
    }
    for (const nodeId of record.graphNodeIds) {
      assertNonEmpty(nodeId, `findingContext ${record.findingId} graphNodeId`);
      if (graphNodeIds !== undefined && !graphNodeIds.has(nodeId)) {
        fail(`findingContext ${record.findingId} references unknown graph node: ${nodeId}`);
      }
    }
    for (const edgeId of record.graphEdgeIds) {
      assertNonEmpty(edgeId, `findingContext ${record.findingId} graphEdgeId`);
      if (graphEdgeIds !== undefined && !graphEdgeIds.has(edgeId)) {
        fail(`findingContext ${record.findingId} references unknown graph edge: ${edgeId}`);
      }
    }
    for (const hypothesisId of record.hypothesisIds) {
      assertNonEmpty(hypothesisId, `findingContext ${record.findingId} hypothesisId`);
      if (hypothesisIds !== undefined && !hypothesisIds.has(hypothesisId)) {
        fail(`findingContext ${record.findingId} references unknown hypothesis: ${hypothesisId}`);
      }
    }

    if (record.status === "standalone") {
      if (record.graphNodeIds.length > 0 || record.graphEdgeIds.length > 0) {
        fail(`findingContext ${record.findingId} standalone status cannot carry graph context`);
      }
      if (record.hypothesisIds.length > 0) {
        fail(`findingContext ${record.findingId} standalone status cannot carry hypotheses`);
      }
    } else if (record.status === "linked_to_hypothesis") {
      if (record.hypothesisIds.length === 0) {
        fail(`findingContext ${record.findingId} linked_to_hypothesis requires hypothesisIds`);
      }
    } else {
      if (record.hypothesisIds.length > 0) {
        fail(`findingContext ${record.findingId} ${record.status} cannot carry hypotheses`);
      }
      if (record.graphNodeIds.length === 0 && record.graphEdgeIds.length === 0) {
        fail(`findingContext ${record.findingId} ${record.status} requires graph context`);
      }
    }
  }

  if (expectedFindingIds !== undefined) {
    for (const findingId of expectedFindingIds) {
      if (!seenFindingIds.has(findingId)) {
        fail(`findingContext missing assessment for finding: ${findingId}`);
      }
    }
  }

  return sortFindingContextAssessments(records);
}

export function sortFindingContextAssessments(
  records: ReadonlyArray<FindingContextAssessment>,
): FindingContextAssessment[] {
  return [...records].sort((a, b) => a.findingId.localeCompare(b.findingId));
}

function assertKnown<T extends string>(value: string, known: ReadonlySet<T>, label: string): void {
  if (!known.has(value as T)) {
    fail(`${label} is invalid: ${value}`);
  }
}

function assertNonEmpty(value: string, label: string): void {
  if (value.trim() === "") {
    fail(`${label} is required`);
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
  throw new FindingContextAssessmentValidationError(message);
}
