import type { GraphCoverageState } from "./security-graph.js";

export interface ComponentReachability {
  readonly componentNodeId: string;
  readonly packageName: string;
  readonly version?: string;
  readonly findingIds: ReadonlyArray<string>;
  readonly level: ComponentReachabilityLevel;
  readonly pathEdgeIds: ReadonlyArray<string>;
  readonly affectedSymbol?: string;
  readonly affectedSymbolReachability: AffectedSymbolReachability;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly coverageState: GraphCoverageState;
}

export type ComponentReachabilityLevel =
  | "present"
  | "imported"
  | "used"
  | "reachable_from_boundary"
  | "affected_symbol_reachable"
  | "unknown";

export type AffectedSymbolReachability = "reachable" | "unknown";

const LEVELS = new Set<ComponentReachabilityLevel>([
  "present",
  "imported",
  "used",
  "reachable_from_boundary",
  "affected_symbol_reachable",
  "unknown",
]);

const COVERAGE_STATES = new Set<GraphCoverageState>([
  "checked",
  "skipped",
  "failed",
  "degraded",
  "partial",
]);

export class ComponentReachabilityValidationError extends Error {
  override readonly name = "ComponentReachabilityValidationError";
}

export function validateComponentReachability(
  records: ReadonlyArray<ComponentReachability>,
): ComponentReachability[] {
  const keys = new Set<string>();
  for (const record of records) {
    assertNonEmpty(record.componentNodeId, "componentReachability componentNodeId");
    assertNonEmpty(record.packageName, "componentReachability packageName");
    assertKnown(record.level, LEVELS, `componentReachability ${record.packageName} level`);
    assertKnown(
      record.coverageState,
      COVERAGE_STATES,
      `componentReachability ${record.packageName} coverageState`,
    );
    assertKnownAffectedSymbolReachability(record.affectedSymbolReachability, record.packageName);
    if (
      record.level !== "present" &&
      record.level !== "unknown" &&
      record.pathEdgeIds.length === 0
    ) {
      fail(`componentReachability ${record.packageName} pathEdgeIds are required`);
    }
    if (record.level === "affected_symbol_reachable" && record.affectedSymbol === undefined) {
      fail(`componentReachability ${record.packageName} affectedSymbol is required`);
    }
    if (record.affectedSymbolReachability === "reachable" && record.affectedSymbol === undefined) {
      fail(`componentReachability ${record.packageName} reachable affectedSymbol is required`);
    }
    assertUnique(record.componentNodeId, keys, "componentReachability componentNodeId");
  }

  return sortComponentReachability(records);
}

export function sortComponentReachability(
  records: ReadonlyArray<ComponentReachability>,
): ComponentReachability[] {
  return [...records].sort(
    (a, b) =>
      a.packageName.localeCompare(b.packageName) ||
      a.componentNodeId.localeCompare(b.componentNodeId),
  );
}

function assertKnown<T extends string>(value: string, known: ReadonlySet<T>, label: string): void {
  if (!known.has(value as T)) {
    fail(`${label} is invalid: ${value}`);
  }
}

function assertKnownAffectedSymbolReachability(value: string, packageName: string): void {
  if (value !== "reachable" && value !== "unknown") {
    fail(`componentReachability ${packageName} affectedSymbolReachability is invalid: ${value}`);
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

function fail(message: string): never {
  throw new ComponentReachabilityValidationError(message);
}
