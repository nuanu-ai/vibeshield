/**
 * SecurityGraph — deterministic Deep Static projection.
 *
 * The full program model stays in blob storage. This projection is the small,
 * stable graph later stages use for correlation, validation, and reports.
 */

import { createHash } from "node:crypto";
import type { RunId } from "./run.js";

export interface SecurityGraph {
  readonly id: string;
  readonly runId: RunId;
  readonly snapshotId: string;
  readonly graphVersion: string;
  readonly nodes: ReadonlyArray<SecurityGraphNode>;
  readonly edges: ReadonlyArray<SecurityGraphEdge>;
  readonly flows: ReadonlyArray<SecurityFlow>;
  readonly coverage: ReadonlyArray<GraphCoverage>;
  readonly createdAt: string;
}

export interface SecurityGraphNode {
  readonly id: string;
  readonly kind: SecurityGraphNodeKind;
  readonly stableKey: string;
  readonly label: string;
  readonly repoPath?: string;
  readonly lineRange?: LineRange;
  readonly symbol?: string;
  readonly properties: Readonly<Record<string, unknown>>;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly producer: string;
  readonly producerVersion: string;
  readonly confidence: number;
  readonly coverageState: GraphCoverageState;
}

export type SecurityGraphNodeKind =
  | "Boundary"
  | "CodeEntity"
  | "Source"
  | "Sink"
  | "Control"
  | "Flow"
  | "Component"
  | "Finding"
  | "Secret"
  | "BuildStep"
  | "InfraResource"
  | "ExternalService"
  | "DataStore"
  | "Resource";

export interface SecurityGraphEdge {
  readonly id: string;
  readonly kind: SecurityGraphEdgeKind;
  readonly stableKey: string;
  readonly fromNodeId: string;
  readonly toNodeId: string;
  readonly properties: Readonly<Record<string, unknown>>;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly producer: string;
  readonly producerVersion: string;
  readonly confidence: number;
  readonly coverageState: GraphCoverageState;
}

export type SecurityGraphEdgeKind =
  | "contains"
  | "imports"
  | "calls"
  | "registers"
  | "receives"
  | "flows_to"
  | "uses"
  | "reads"
  | "writes"
  | "protected_by"
  | "exposes"
  | "depends_on"
  | "located_in"
  | "affects"
  | "supported_by"
  | "contradicted_by";

export interface SecurityFlow {
  readonly id: string;
  readonly sourceNodeId: string;
  readonly sinkNodeId: string;
  readonly pathEdgeIds: ReadonlyArray<string>;
  readonly controlNodeIds: ReadonlyArray<string>;
  readonly coverageState: GraphCoverageState;
  readonly confidence: number;
  readonly evidenceIds: ReadonlyArray<string>;
}

export interface GraphCoverage {
  readonly area: GraphCoverageArea;
  readonly state: GraphCoverageState;
  readonly coveredCount?: number;
  readonly totalCount?: number;
  readonly reason?: string;
  readonly producer: string;
  readonly producerVersion: string;
}

export type GraphCoverageArea =
  | "entities"
  | "boundaries"
  | "call_graph"
  | "data_flow"
  | "dependency_usage"
  | "ci_iac"
  | "language_support";

export type GraphCoverageState = "checked" | "skipped" | "failed" | "degraded" | "partial";

export interface LineRange {
  readonly startLine: number;
  readonly endLine: number;
}

export interface SecurityGraphValidationContext {
  readonly manifestPaths: ReadonlySet<string> | ReadonlyArray<string>;
  readonly evidenceIds: ReadonlySet<string> | ReadonlyArray<string>;
}

const NODE_KINDS = new Set<SecurityGraphNodeKind>([
  "Boundary",
  "CodeEntity",
  "Source",
  "Sink",
  "Control",
  "Flow",
  "Component",
  "Finding",
  "Secret",
  "BuildStep",
  "InfraResource",
  "ExternalService",
  "DataStore",
  "Resource",
]);

const EDGE_KINDS = new Set<SecurityGraphEdgeKind>([
  "contains",
  "imports",
  "calls",
  "registers",
  "receives",
  "flows_to",
  "uses",
  "reads",
  "writes",
  "protected_by",
  "exposes",
  "depends_on",
  "located_in",
  "affects",
  "supported_by",
  "contradicted_by",
]);

const COVERAGE_AREAS = new Set<GraphCoverageArea>([
  "entities",
  "boundaries",
  "call_graph",
  "data_flow",
  "dependency_usage",
  "ci_iac",
  "language_support",
]);

const COVERAGE_STATES = new Set<GraphCoverageState>([
  "checked",
  "skipped",
  "failed",
  "degraded",
  "partial",
]);

export class SecurityGraphValidationError extends Error {
  override readonly name = "SecurityGraphValidationError";
}

export function securityGraphId(snapshotId: string, graphVersion: string): string {
  return securityGraphStableId("graph", [snapshotId, graphVersion]);
}

export function securityGraphNodeId(graphVersion: string, stableKey: string): string {
  return securityGraphStableId("node", [graphVersion, stableKey]);
}

export function securityGraphEdgeId(graphVersion: string, stableKey: string): string {
  return securityGraphStableId("edge", [graphVersion, stableKey]);
}

export function securityFlowId(graphVersion: string, stableKey: string): string {
  return securityGraphStableId("flow", [graphVersion, stableKey]);
}

export function securityGraphStableId(prefix: string, parts: ReadonlyArray<string>): string {
  const hash = createHash("sha256").update(parts.join("\0")).digest("hex").slice(0, 16);
  return `${prefix}_${hash}`;
}

export function validateSecurityGraph(
  graph: SecurityGraph,
  context: SecurityGraphValidationContext,
): SecurityGraph {
  const manifestPaths = toSet(context.manifestPaths);
  const evidenceIds = toSet(context.evidenceIds);
  assertNonEmpty(graph.id, "graph id");
  assertNonEmpty(graph.runId, "graph runId");
  assertNonEmpty(graph.snapshotId, "graph snapshotId");
  assertNonEmpty(graph.graphVersion, "graph graphVersion");
  assertNonEmpty(graph.createdAt, "graph createdAt");

  const nodeIds = new Set<string>();
  const nodeStableKeys = new Set<string>();
  for (const node of graph.nodes) {
    assertKnown(node.kind, NODE_KINDS, `node ${node.id} kind`);
    validateGraphRecord(node, evidenceIds, manifestPaths, `node ${node.id}`);
    assertUnique(node.id, nodeIds, "node id");
    assertUnique(node.stableKey, nodeStableKeys, "node stableKey");
  }

  const edgeIds = new Set<string>();
  const edgeStableKeys = new Set<string>();
  for (const edge of graph.edges) {
    assertKnown(edge.kind, EDGE_KINDS, `edge ${edge.id} kind`);
    validateGraphRecord(edge, evidenceIds, manifestPaths, `edge ${edge.id}`);
    assertUnique(edge.id, edgeIds, "edge id");
    assertUnique(edge.stableKey, edgeStableKeys, "edge stableKey");
    if (!nodeIds.has(edge.fromNodeId)) {
      fail(`edge ${edge.id} has dangling fromNodeId: ${edge.fromNodeId}`);
    }
    if (!nodeIds.has(edge.toNodeId)) {
      fail(`edge ${edge.id} has dangling toNodeId: ${edge.toNodeId}`);
    }
  }

  const flowIds = new Set<string>();
  for (const flow of graph.flows) {
    assertNonEmpty(flow.id, "flow id");
    assertUnique(flow.id, flowIds, "flow id");
    assertCoverageState(flow.coverageState, `flow ${flow.id} coverageState`);
    assertConfidence(flow.confidence, `flow ${flow.id} confidence`);
    assertEvidenceIds(flow.evidenceIds, evidenceIds, `flow ${flow.id}`);
    if (!nodeIds.has(flow.sourceNodeId)) {
      fail(`flow ${flow.id} has dangling sourceNodeId: ${flow.sourceNodeId}`);
    }
    if (!nodeIds.has(flow.sinkNodeId)) {
      fail(`flow ${flow.id} has dangling sinkNodeId: ${flow.sinkNodeId}`);
    }
    validateFlowPath(flow, graph.edges);
    for (const controlNodeId of flow.controlNodeIds) {
      if (!nodeIds.has(controlNodeId)) {
        fail(`flow ${flow.id} has dangling controlNodeId: ${controlNodeId}`);
      }
    }
  }

  const coverageKeys = new Set<string>();
  for (const coverage of graph.coverage) {
    assertKnown(coverage.area, COVERAGE_AREAS, `coverage ${coverage.area} area`);
    assertCoverageState(coverage.state, `coverage ${coverage.area} state`);
    assertNonEmpty(coverage.producer, `coverage ${coverage.area} producer`);
    assertNonEmpty(coverage.producerVersion, `coverage ${coverage.area} producerVersion`);
    if (coverage.coveredCount !== undefined) {
      assertNonNegativeInteger(coverage.coveredCount, `coverage ${coverage.area} coveredCount`);
    }
    if (coverage.totalCount !== undefined) {
      assertNonNegativeInteger(coverage.totalCount, `coverage ${coverage.area} totalCount`);
    }
    if (
      coverage.coveredCount !== undefined &&
      coverage.totalCount !== undefined &&
      coverage.coveredCount > coverage.totalCount
    ) {
      fail(`coverage ${coverage.area} coveredCount exceeds totalCount`);
    }
    assertUnique(`${coverage.area}:${coverage.producer}`, coverageKeys, "coverage key");
  }

  return sortSecurityGraph(graph);
}

export function sortSecurityGraph(graph: SecurityGraph): SecurityGraph {
  return {
    ...graph,
    nodes: [...graph.nodes].sort((a, b) => a.id.localeCompare(b.id)),
    edges: [...graph.edges].sort((a, b) => a.id.localeCompare(b.id)),
    flows: [...graph.flows].sort((a, b) => a.id.localeCompare(b.id)),
    coverage: [...graph.coverage].sort((a, b) =>
      `${a.area}:${a.producer}`.localeCompare(`${b.area}:${b.producer}`),
    ),
  };
}

function validateGraphRecord(
  record: Pick<
    SecurityGraphNode | SecurityGraphEdge,
    | "id"
    | "stableKey"
    | "producer"
    | "producerVersion"
    | "confidence"
    | "coverageState"
    | "evidenceIds"
  > & { readonly repoPath?: string; readonly lineRange?: LineRange },
  evidenceIds: ReadonlySet<string>,
  manifestPaths: ReadonlySet<string>,
  label: string,
): void {
  assertNonEmpty(record.id, `${label} id`);
  assertNonEmpty(record.stableKey, `${label} stableKey`);
  assertNonEmpty(record.producer, `${label} producer`);
  assertNonEmpty(record.producerVersion, `${label} producerVersion`);
  assertConfidence(record.confidence, `${label} confidence`);
  assertCoverageState(record.coverageState, `${label} coverageState`);
  assertEvidenceIds(record.evidenceIds, evidenceIds, label);
  if (record.repoPath !== undefined) {
    assertManifestPath(record.repoPath, manifestPaths, label);
  }
  if (record.lineRange !== undefined) {
    assertLineRange(record.lineRange, `${label} lineRange`);
  }
}

function validateFlowPath(flow: SecurityFlow, edges: ReadonlyArray<SecurityGraphEdge>): void {
  const byId = new Map(edges.map((edge) => [edge.id, edge]));
  if (flow.pathEdgeIds.length === 0) {
    return;
  }
  let expectedFrom = flow.sourceNodeId;
  for (const edgeId of flow.pathEdgeIds) {
    const edge = byId.get(edgeId);
    if (edge === undefined) {
      fail(`flow ${flow.id} has dangling pathEdgeId: ${edgeId}`);
    }
    if (edge.fromNodeId !== expectedFrom) {
      fail(`flow ${flow.id} path is not connected at edge ${edgeId}`);
    }
    expectedFrom = edge.toNodeId;
  }
  if (expectedFrom !== flow.sinkNodeId) {
    fail(`flow ${flow.id} path does not end at sinkNodeId: ${flow.sinkNodeId}`);
  }
}

function assertEvidenceIds(
  actual: ReadonlyArray<string>,
  known: ReadonlySet<string>,
  label: string,
): void {
  for (const evidenceId of actual) {
    assertNonEmpty(evidenceId, `${label} evidenceId`);
    if (!known.has(evidenceId)) {
      fail(`${label} references missing evidence id: ${evidenceId}`);
    }
  }
}

function assertManifestPath(
  repoPath: string,
  manifestPaths: ReadonlySet<string>,
  label: string,
): void {
  if (!isSafeRepoPath(repoPath)) {
    fail(`${label} has unsafe repoPath: ${repoPath}`);
  }
  if (!manifestPaths.has(repoPath)) {
    fail(`${label} points outside the snapshot: ${repoPath}`);
  }
}

function assertLineRange(range: LineRange, label: string): void {
  assertPositiveInteger(range.startLine, `${label} startLine`);
  assertPositiveInteger(range.endLine, `${label} endLine`);
  if (range.endLine < range.startLine) {
    fail(`${label} endLine is before startLine`);
  }
}

function assertConfidence(value: number, label: string): void {
  if (!Number.isFinite(value) || value < 0 || value > 1) {
    fail(`${label} must be between 0 and 1`);
  }
}

function assertCoverageState(value: string, label: string): void {
  assertKnown(value, COVERAGE_STATES, label);
}

function assertKnown<T extends string>(
  value: string,
  allowed: ReadonlySet<T>,
  label: string,
): asserts value is T {
  if (!allowed.has(value as T)) {
    fail(`${label} is invalid: ${value}`);
  }
}

function assertUnique(value: string, seen: Set<string>, label: string): void {
  assertNonEmpty(value, label);
  if (seen.has(value)) {
    fail(`duplicate ${label}: ${value}`);
  }
  seen.add(value);
}

function assertNonEmpty(value: string, label: string): void {
  if (value.trim() === "") {
    fail(`${label} is required`);
  }
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 1) {
    fail(`${label} must be a positive integer`);
  }
}

function assertNonNegativeInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0) {
    fail(`${label} must be a non-negative integer`);
  }
}

function toSet(values: ReadonlySet<string> | ReadonlyArray<string>): ReadonlySet<string> {
  return values instanceof Set ? values : new Set(values);
}

function isSafeRepoPath(repoPath: string): boolean {
  return (
    repoPath.length > 0 &&
    !repoPath.startsWith("/") &&
    repoPath.split("/").every((part) => part !== "" && part !== "." && part !== "..")
  );
}

function fail(message: string): never {
  throw new SecurityGraphValidationError(message);
}
