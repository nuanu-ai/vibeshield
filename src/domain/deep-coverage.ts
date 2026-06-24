import type { RunId } from "./run.js";

export interface DeepCoverage {
  readonly runId: RunId;
  readonly snapshotId: string;
  readonly entries: ReadonlyArray<DeepCoverageEntry>;
  readonly createdAt: string;
}

export interface DeepCoverageEntry {
  readonly area: DeepCoverageArea;
  readonly state: DeepCoverageState;
  readonly coveredCount?: number;
  readonly totalCount?: number;
  readonly reason?: string;
  readonly producer: string;
  readonly producerVersion: string;
}

export type DeepCoverageArea =
  | "language_support"
  | "model"
  | "entities"
  | "boundaries"
  | "call_graph"
  | "data_flow"
  | "component_usage"
  | "dependency_usage"
  | "ci_iac";

export type DeepCoverageState = "checked" | "skipped" | "failed" | "degraded" | "partial";

const COVERAGE_AREAS = new Set<DeepCoverageArea>([
  "language_support",
  "model",
  "entities",
  "boundaries",
  "call_graph",
  "data_flow",
  "component_usage",
  "dependency_usage",
  "ci_iac",
]);

const COVERAGE_STATES = new Set<DeepCoverageState>([
  "checked",
  "skipped",
  "failed",
  "degraded",
  "partial",
]);

export class DeepCoverageValidationError extends Error {
  override readonly name = "DeepCoverageValidationError";
}

export function validateDeepCoverage(coverage: DeepCoverage): DeepCoverage {
  assertNonEmpty(coverage.runId, "deepCoverage runId");
  assertNonEmpty(coverage.snapshotId, "deepCoverage snapshotId");
  assertNonEmpty(coverage.createdAt, "deepCoverage createdAt");

  const keys = new Set<string>();
  for (const entry of coverage.entries) {
    assertKnown(entry.area, COVERAGE_AREAS, `deepCoverage ${entry.area} area`);
    assertKnown(entry.state, COVERAGE_STATES, `deepCoverage ${entry.area} state`);
    assertNonEmpty(entry.producer, `deepCoverage ${entry.area} producer`);
    assertNonEmpty(entry.producerVersion, `deepCoverage ${entry.area} producerVersion`);
    if (entry.coveredCount !== undefined) {
      assertNonNegativeInteger(entry.coveredCount, `deepCoverage ${entry.area} coveredCount`);
    }
    if (entry.totalCount !== undefined) {
      assertNonNegativeInteger(entry.totalCount, `deepCoverage ${entry.area} totalCount`);
    }
    if (
      entry.coveredCount !== undefined &&
      entry.totalCount !== undefined &&
      entry.coveredCount > entry.totalCount
    ) {
      fail(`deepCoverage ${entry.area} coveredCount exceeds totalCount`);
    }
    if (entry.state !== "checked") {
      assertNonEmpty(entry.reason, `deepCoverage ${entry.area} reason`);
    }
    assertUnique(`${entry.area}:${entry.producer}`, keys, "deepCoverage entry key");
  }

  return sortDeepCoverage(coverage);
}

export function sortDeepCoverage(coverage: DeepCoverage): DeepCoverage {
  return {
    ...coverage,
    entries: [...coverage.entries].sort((a, b) =>
      `${a.area}:${a.producer}`.localeCompare(`${b.area}:${b.producer}`),
    ),
  };
}

function assertKnown<T extends string>(value: string, known: ReadonlySet<T>, label: string): void {
  if (!known.has(value as T)) {
    fail(`${label} is invalid: ${value}`);
  }
}

function assertNonEmpty(value: string | undefined, label: string): void {
  if (value === undefined || value.trim() === "") {
    fail(`${label} is required`);
  }
}

function assertNonNegativeInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0) {
    fail(`${label} must be a non-negative integer`);
  }
}

function assertUnique(value: string, seen: Set<string>, label: string): void {
  if (seen.has(value)) {
    fail(`${label} is duplicated: ${value}`);
  }
  seen.add(value);
}

function fail(message: string): never {
  throw new DeepCoverageValidationError(message);
}
