import type { DeepCoverage, DeepCoverageArea, DeepCoverageEntry } from "../domain/deep-coverage.js";
import { validateDeepCoverage } from "../domain/deep-coverage.js";
import type { Manifest } from "../domain/manifest.js";
import type { RunId } from "../domain/run.js";
import type { GraphCoverage } from "../domain/security-graph.js";
import type {
  ProgramAnalysisCoverage,
  ProgramAnalysisCoverageArea,
  ProgramAnalysisFailure,
} from "../ports/program-analysis-backend.js";
import { languageSupportFromManifest } from "../ports/program-analysis-backend.js";

export interface ComposeDeepCoverageInput {
  readonly runId: RunId;
  readonly snapshotId: string;
  readonly manifest: Manifest;
  readonly backendCoverage?: ReadonlyArray<ProgramAnalysisCoverage>;
  readonly graphCoverage?: ReadonlyArray<GraphCoverage>;
  readonly failures?: ReadonlyArray<ProgramAnalysisFailure>;
  readonly createdAt: string;
  readonly producerVersion?: string;
}

const PRODUCER = "vibeshield";
const DEFAULT_PRODUCER_VERSION = "deep-static-v1";

const STATE_RANK = {
  checked: 0,
  skipped: 1,
  partial: 2,
  degraded: 3,
  failed: 4,
} as const;

export function composeDeepCoverage(input: ComposeDeepCoverageInput): DeepCoverage {
  const entries = new Map<string, DeepCoverageEntry>();
  const producerVersion = input.producerVersion ?? DEFAULT_PRODUCER_VERSION;
  const hasBackendLanguageSupport =
    input.backendCoverage?.some((entry) => entry.area === "language_support") ?? false;

  if (!hasBackendLanguageSupport) {
    addEntry(entries, languageSupportEntry(input.manifest, producerVersion));
  }

  for (const entry of input.backendCoverage ?? []) {
    addEntry(entries, fromBackendCoverage(entry));
  }

  for (const entry of input.graphCoverage ?? []) {
    addEntry(entries, fromGraphCoverage(entry));
  }

  for (const failure of input.failures ?? []) {
    addEntry(entries, {
      area: mapBackendArea(failure.area),
      state: "failed",
      reason: failure.reason,
      producer: PRODUCER,
      producerVersion,
    });
  }

  addKnownGap(
    entries,
    "entities",
    "Program entity extraction coverage has not been produced yet.",
    producerVersion,
  );
  addKnownGap(
    entries,
    "boundaries",
    "Boundary graph coverage has not been produced yet.",
    producerVersion,
  );
  addKnownGap(
    entries,
    "call_graph",
    "Call graph coverage has not been produced yet.",
    producerVersion,
  );
  addKnownGap(
    entries,
    "data_flow",
    "Data-flow coverage has not been produced yet.",
    producerVersion,
  );
  addKnownGap(
    entries,
    "component_usage",
    "Component usage projection is not wired into Deep Static yet.",
    producerVersion,
  );
  addKnownGap(
    entries,
    "dependency_usage",
    "Dependency reachability is not wired into Deep Static yet.",
    producerVersion,
  );
  addKnownGap(
    entries,
    "ci_iac",
    "CI/IaC context projection is not wired into Deep Static yet.",
    producerVersion,
  );

  return validateDeepCoverage({
    runId: input.runId,
    snapshotId: input.snapshotId,
    entries: [...entries.values()],
    createdAt: input.createdAt,
  });
}

function languageSupportEntry(manifest: Manifest, producerVersion: string): DeepCoverageEntry {
  const support = languageSupportFromManifest(manifest);
  const supportedCount = support.supported.reduce((sum, item) => sum + item.fileCount, 0);
  return {
    area: "language_support",
    state: support.coverageState,
    coveredCount: supportedCount,
    totalCount: support.totalSourceFiles,
    ...(support.reason === undefined ? {} : { reason: support.reason }),
    producer: PRODUCER,
    producerVersion,
  };
}

function fromBackendCoverage(entry: ProgramAnalysisCoverage): DeepCoverageEntry {
  return {
    area: mapBackendArea(entry.area),
    state: entry.state,
    ...(entry.coveredCount === undefined ? {} : { coveredCount: entry.coveredCount }),
    ...(entry.totalCount === undefined ? {} : { totalCount: entry.totalCount }),
    ...(entry.reason === undefined ? {} : { reason: entry.reason }),
    producer: entry.producer,
    producerVersion: entry.producerVersion,
  };
}

function fromGraphCoverage(entry: GraphCoverage): DeepCoverageEntry {
  return {
    area: entry.area,
    state: entry.state,
    ...(entry.coveredCount === undefined ? {} : { coveredCount: entry.coveredCount }),
    ...(entry.totalCount === undefined ? {} : { totalCount: entry.totalCount }),
    ...(entry.reason === undefined ? {} : { reason: entry.reason }),
    producer: entry.producer,
    producerVersion: entry.producerVersion,
  };
}

function mapBackendArea(area: ProgramAnalysisCoverageArea): DeepCoverageArea {
  switch (area) {
    case "call_edges":
      return "call_graph";
    case "flows":
      return "data_flow";
    default:
      return area;
  }
}

function addKnownGap(
  entries: Map<string, DeepCoverageEntry>,
  area: DeepCoverageArea,
  reason: string,
  producerVersion: string,
): void {
  if ([...entries.values()].some((entry) => entry.area === area)) {
    return;
  }
  addEntry(entries, {
    area,
    state: "skipped",
    reason,
    producer: PRODUCER,
    producerVersion,
  });
}

function addEntry(entries: Map<string, DeepCoverageEntry>, entry: DeepCoverageEntry): void {
  const key = `${entry.area}:${entry.producer}`;
  const existing = entries.get(key);
  entries.set(key, existing === undefined ? entry : mergeEntries(existing, entry));
}

function mergeEntries(left: DeepCoverageEntry, right: DeepCoverageEntry): DeepCoverageEntry {
  const state = STATE_RANK[right.state] > STATE_RANK[left.state] ? right.state : left.state;
  const coveredCount = right.coveredCount ?? left.coveredCount;
  const totalCount = right.totalCount ?? left.totalCount;
  const reason = combineReasons(left.reason, right.reason);
  return {
    area: left.area,
    state,
    ...(coveredCount === undefined ? {} : { coveredCount }),
    ...(totalCount === undefined ? {} : { totalCount }),
    ...(reason === undefined ? {} : { reason }),
    producer: left.producer,
    producerVersion: left.producerVersion,
  };
}

function combineReasons(left: string | undefined, right: string | undefined): string | undefined {
  const reasons = [left, right].filter((reason): reason is string => reason !== undefined);
  return reasons.length === 0 ? undefined : [...new Set(reasons)].join("; ");
}
