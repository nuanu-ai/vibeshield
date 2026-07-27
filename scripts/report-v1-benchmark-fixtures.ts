import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Evidence } from "../src/domain/evidence.js";
import type { FindingContextAssessment } from "../src/domain/finding-context-assessment.js";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
import type {
  GraphCoverageState,
  SecurityFlow,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphEdgeKind,
  SecurityGraphNode,
} from "../src/domain/security-graph.js";
import {
  securityFlowId,
  securityGraphEdgeId,
  securityGraphId,
  securityGraphNodeId,
} from "../src/domain/security-graph.js";
import { correlateStage2Hypotheses } from "../src/stages/stage2-hypothesis-rules.js";

export const REPORT_V1_BENCHMARK_CONTRACT_PATH = "benchmarks/report-v1-ground-truth.json";

export type ReportV1BenchmarkSplit = "development" | "synthetic-holdback";
export type ReportV1BenchmarkVariant =
  | "clean"
  | "direct_overlap"
  | "duplicate"
  | "guarded"
  | "irrelevant_guard"
  | "partial"
  | "stale_evidence"
  | "structural_only"
  | "vulnerable";

export interface ReportV1BenchmarkTargets {
  readonly ownerGroupPrecision: number;
  readonly staticSupportPrecision: number;
  readonly candidateRecall: number;
  readonly falseDeployBlockers: number;
}

export interface ReportV1BenchmarkContract {
  readonly version: 1;
  readonly targets: ReportV1BenchmarkTargets;
  readonly cases: ReadonlyArray<ReportV1BenchmarkCase>;
}

export interface ReportV1BenchmarkCase {
  readonly id: string;
  readonly split: ReportV1BenchmarkSplit;
  readonly language: "Go" | "Java" | "Python" | "TypeScript";
  readonly fixturePath: string;
  readonly variant: ReportV1BenchmarkVariant;
  readonly sinkType: string;
  readonly sources: ReadonlyArray<ReportV1BenchmarkEndpoint>;
  readonly sinks: ReadonlyArray<ReportV1BenchmarkEndpoint>;
  readonly routes: ReadonlyArray<ReportV1BenchmarkRoute>;
  readonly control?: ReportV1BenchmarkControl;
  readonly truth: ReportV1BenchmarkTruth;
}

export interface ReportV1BenchmarkEndpoint {
  readonly name: string;
  readonly line: number;
}

export interface ReportV1BenchmarkRoute {
  readonly source: string;
  readonly sink: string;
}

export interface ReportV1BenchmarkControl {
  readonly line: number;
  readonly effect: "blocks_untrusted";
  readonly protectsSinkType: string;
}

export interface ReportV1BenchmarkTruth {
  readonly candidateRootCauses: ReadonlyArray<string>;
  readonly supportedRootCauses: ReadonlyArray<string>;
  readonly ownerValidationRootCauses: ReadonlyArray<string>;
  readonly directFindingIds: ReadonlyArray<string>;
}

export interface BuiltReportV1BenchmarkCase {
  readonly record: ReportV1BenchmarkCase;
  readonly graph: SecurityGraph;
  readonly evidence: ReadonlyArray<Evidence>;
  readonly findingContexts: ReadonlyArray<FindingContextAssessment>;
  readonly candidates: ReadonlyArray<HypothesisCandidate>;
}

const GRAPH_VERSION = "report-v1-benchmark-v1";
const PRODUCER = "report-v1-benchmark";

export async function loadReportV1BenchmarkContract(
  contractPath = REPORT_V1_BENCHMARK_CONTRACT_PATH,
): Promise<ReportV1BenchmarkContract> {
  const parsed: unknown = JSON.parse(await readFile(contractPath, "utf8"));
  return validateContract(parsed);
}

export async function buildReportV1BenchmarkCases(
  contract: ReportV1BenchmarkContract,
  split: ReportV1BenchmarkSplit,
): Promise<BuiltReportV1BenchmarkCase[]> {
  const selected = contract.cases.filter((record) => record.split === split);
  const built = await Promise.all(selected.map(buildReportV1BenchmarkCase));
  return built.sort((a, b) => a.record.id.localeCompare(b.record.id));
}

export async function buildReportV1BenchmarkCase(
  record: ReportV1BenchmarkCase,
): Promise<BuiltReportV1BenchmarkCase> {
  const sourceText = await readFile(record.fixturePath, "utf8");
  const sourceLines = sourceText.split(/\r?\n/);
  const evidence: Evidence[] = [];
  const nodes: SecurityGraphNode[] = [];
  const edges: SecurityGraphEdge[] = [];
  const flows: SecurityFlow[] = [];
  const sourceNodes = new Map<string, SecurityGraphNode>();
  const sinkNodes = new Map<string, SecurityGraphNode>();

  for (const endpoint of record.sources) {
    const node = benchmarkNode({
      record,
      endpoint,
      kind: "Source",
      role: "source",
      properties: { sourceType: "external_input", inputName: endpoint.name },
      sourceLines,
      evidence,
    });
    nodes.push(node);
    sourceNodes.set(endpoint.name, node);
  }
  for (const endpoint of record.sinks) {
    const node = benchmarkNode({
      record,
      endpoint,
      kind: "Sink",
      role: "sink",
      properties: { sinkType: record.sinkType, callName: endpoint.name },
      sourceLines,
      evidence,
    });
    nodes.push(node);
    sinkNodes.set(endpoint.name, node);
  }

  let controlNode: SecurityGraphNode | undefined;
  if (record.control !== undefined) {
    const controlEndpoint = { name: "path-control", line: record.control.line };
    controlNode = benchmarkNode({
      record,
      endpoint: controlEndpoint,
      kind: "Control",
      role: "control",
      properties: {
        controlType: "input_validation",
        controlEffect: record.control.effect,
        protectsSinkType: record.control.protectsSinkType,
      },
      sourceLines,
      evidence,
    });
    nodes.push(controlNode);
  }

  const flowCoverage: GraphCoverageState = record.variant === "partial" ? "partial" : "checked";
  for (const [index, route] of record.routes.entries()) {
    const source = requiredEndpoint(sourceNodes, route.source, record.id, "source");
    const sink = requiredEndpoint(sinkNodes, route.sink, record.id, "sink");
    const edgeKind: SecurityGraphEdgeKind =
      record.variant === "structural_only" ? "calls" : "flows_to";
    const edge = benchmarkEdge({
      record,
      index,
      kind: edgeKind,
      source,
      sink,
      sourceLines,
      evidence,
      coverageState: flowCoverage,
    });
    edges.push(edge);
    if (record.variant !== "structural_only") {
      flows.push({
        id: securityFlowId(GRAPH_VERSION, `${record.id}:${index}:${route.source}:${route.sink}`),
        sourceNodeId: source.id,
        sinkNodeId: sink.id,
        pathEdgeIds: [edge.id],
        controlNodeIds: controlNode === undefined ? [] : [controlNode.id],
        coverageState: flowCoverage,
        confidence: 1,
        evidenceIds: uniqueSorted([
          ...source.evidenceIds,
          ...sink.evidenceIds,
          ...edge.evidenceIds,
          ...(controlNode?.evidenceIds ?? []),
        ]),
      });
    }
    if (controlNode !== undefined) {
      edges.push(
        benchmarkControlEdge({
          record,
          sink,
          control: controlNode,
          sourceLines,
          evidence,
        }),
      );
    }
  }

  const graph: SecurityGraph = {
    id: securityGraphId(`snapshot:${record.id}`, GRAPH_VERSION),
    runId: `benchmark:${record.id}`,
    snapshotId: `snapshot:${record.id}`,
    graphVersion: GRAPH_VERSION,
    nodes,
    edges,
    flows,
    coverage: [
      coverage("boundaries", "checked"),
      coverage("call_graph", "checked"),
      coverage("data_flow", flowCoverage),
      coverage("control_flow", "checked"),
      coverage("language_support", "checked"),
    ],
    createdAt: "2026-07-17T00:00:00.000Z",
  };
  const findingContexts = record.truth.directFindingIds.map((findingId) => {
    const sink = requiredFirst([...sinkNodes.values()], `${record.id} direct finding sink`);
    const routeEdge = edges.find(
      (edge) => edge.toNodeId === sink.id && (edge.kind === "flows_to" || edge.kind === "calls"),
    );
    return {
      findingId,
      status: "corroborated",
      graphNodeIds: [sink.id],
      graphEdgeIds: routeEdge === undefined ? [] : [routeEdge.id],
      hypothesisIds: [],
      reason: "independent benchmark direct finding is corroborated by the path sink",
      coverageState: flowCoverage,
    } satisfies FindingContextAssessment;
  });
  const candidates = correlateStage2Hypotheses({ graph, findingContexts });
  return { record, graph, evidence, findingContexts, candidates };
}

export function candidateRootCause(
  benchmarkCase: BuiltReportV1BenchmarkCase,
  candidate: HypothesisCandidate,
): string | undefined {
  const nodesById = new Map(benchmarkCase.graph.nodes.map((node) => [node.id, node]));
  const sinks = candidate.supportingNodeIds.flatMap((nodeId) => {
    const node = nodesById.get(nodeId);
    return node?.kind === "Sink" && node.symbol !== undefined ? [node.symbol] : [];
  });
  return uniqueSorted(sinks)[0];
}

function benchmarkNode(input: {
  readonly record: ReportV1BenchmarkCase;
  readonly endpoint: ReportV1BenchmarkEndpoint;
  readonly kind: SecurityGraphNode["kind"];
  readonly role: string;
  readonly properties: Readonly<Record<string, unknown>>;
  readonly sourceLines: ReadonlyArray<string>;
  readonly evidence: Evidence[];
}): SecurityGraphNode {
  const stableKey = `${input.kind}:${input.record.id}:${input.endpoint.name}`;
  const evidenceId = `evidence:${input.record.id}:${input.role}:${input.endpoint.name}`;
  input.evidence.push(
    benchmarkEvidence(
      evidenceId,
      input.record,
      input.endpoint.line,
      input.sourceLines,
      input.record.variant === "stale_evidence",
    ),
  );
  return {
    id: securityGraphNodeId(GRAPH_VERSION, stableKey),
    kind: input.kind,
    stableKey,
    label: input.endpoint.name,
    repoPath: input.record.fixturePath,
    lineRange: { startLine: input.endpoint.line, endLine: input.endpoint.line },
    symbol: input.endpoint.name,
    properties: input.properties,
    evidenceIds: [evidenceId],
    producer: PRODUCER,
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState: input.record.variant === "partial" ? "partial" : "checked",
  };
}

function benchmarkEdge(input: {
  readonly record: ReportV1BenchmarkCase;
  readonly index: number;
  readonly kind: SecurityGraphEdgeKind;
  readonly source: SecurityGraphNode;
  readonly sink: SecurityGraphNode;
  readonly sourceLines: ReadonlyArray<string>;
  readonly evidence: Evidence[];
  readonly coverageState: GraphCoverageState;
}): SecurityGraphEdge {
  const stableKey = `${input.kind}:${input.record.id}:${input.index}:${input.source.symbol}:${input.sink.symbol}`;
  const evidenceId = `evidence:${input.record.id}:edge:${input.index}`;
  const line = input.sink.lineRange?.startLine ?? 1;
  input.evidence.push(
    benchmarkEvidence(
      evidenceId,
      input.record,
      line,
      input.sourceLines,
      input.record.variant === "stale_evidence",
    ),
  );
  return {
    id: securityGraphEdgeId(GRAPH_VERSION, stableKey),
    kind: input.kind,
    stableKey,
    fromNodeId: input.source.id,
    toNodeId: input.sink.id,
    properties: { semantic: input.kind === "flows_to" ? "value_flow" : "structural_reference" },
    evidenceIds: [evidenceId],
    producer: PRODUCER,
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState: input.coverageState,
  };
}

function benchmarkControlEdge(input: {
  readonly record: ReportV1BenchmarkCase;
  readonly sink: SecurityGraphNode;
  readonly control: SecurityGraphNode;
  readonly sourceLines: ReadonlyArray<string>;
  readonly evidence: Evidence[];
}): SecurityGraphEdge {
  const stableKey = `protected_by:${input.record.id}:${input.sink.symbol}`;
  const evidenceId = `evidence:${input.record.id}:control-edge:${input.sink.symbol}`;
  const line = input.control.lineRange?.startLine ?? 1;
  input.evidence.push(benchmarkEvidence(evidenceId, input.record, line, input.sourceLines, false));
  return {
    id: securityGraphEdgeId(GRAPH_VERSION, stableKey),
    kind: "protected_by",
    stableKey,
    fromNodeId: input.sink.id,
    toNodeId: input.control.id,
    properties: { relation: "dominates_sink" },
    evidenceIds: [evidenceId],
    producer: PRODUCER,
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState: "checked",
  };
}

function benchmarkEvidence(
  id: string,
  record: ReportV1BenchmarkCase,
  line: number,
  sourceLines: ReadonlyArray<string>,
  stale: boolean,
): Evidence {
  const evidenceLine = stale ? 1 : line;
  const snippet = sourceLines[evidenceLine - 1]?.trim() ?? "benchmark evidence";
  return {
    id,
    rawArtifactBlobSha256: sha256(`raw:${record.id}`),
    filePath: record.fixturePath,
    startLine: evidenceLine,
    endLine: evidenceLine,
    snippet,
    snippetHash: sha256(snippet),
    tool: PRODUCER,
  };
}

function coverage(
  area: SecurityGraph["coverage"][number]["area"],
  state: GraphCoverageState,
): SecurityGraph["coverage"][number] {
  return { area, state, producer: PRODUCER, producerVersion: GRAPH_VERSION };
}

function validateContract(value: unknown): ReportV1BenchmarkContract {
  if (!isRecord(value) || value.version !== 1 || !isRecord(value.targets)) {
    throw new Error("report-v1 benchmark contract must have version 1 and targets");
  }
  if (!Array.isArray(value.cases) || value.cases.length === 0) {
    throw new Error("report-v1 benchmark contract requires cases");
  }
  const cases = value.cases.map(validateCase);
  const ids = new Set<string>();
  for (const record of cases) {
    if (ids.has(record.id)) {
      throw new Error(`report-v1 benchmark case id is duplicated: ${record.id}`);
    }
    ids.add(record.id);
  }
  const languages = new Set(cases.map((record) => record.language));
  for (const language of ["TypeScript", "Java", "Python", "Go"] as const) {
    if (!languages.has(language)) {
      throw new Error(`report-v1 benchmark is missing language: ${language}`);
    }
  }
  for (const split of ["development", "synthetic-holdback"] as const) {
    if (!cases.some((record) => record.split === split)) {
      throw new Error(`report-v1 benchmark is missing split: ${split}`);
    }
  }
  return {
    version: 1,
    targets: {
      ownerGroupPrecision: ratio(value.targets.ownerGroupPrecision, "ownerGroupPrecision"),
      staticSupportPrecision: ratio(value.targets.staticSupportPrecision, "staticSupportPrecision"),
      candidateRecall: ratio(value.targets.candidateRecall, "candidateRecall"),
      falseDeployBlockers: nonNegativeInteger(
        value.targets.falseDeployBlockers,
        "falseDeployBlockers",
      ),
    },
    cases,
  };
}

function validateCase(value: unknown): ReportV1BenchmarkCase {
  if (!isRecord(value) || !isRecord(value.truth)) {
    throw new Error("report-v1 benchmark case must be an object with truth");
  }
  const id = nonEmptyString(value.id, "case id");
  const split = knownString(
    value.split,
    ["development", "synthetic-holdback"] as const,
    `${id} split`,
  );
  const language = knownString(
    value.language,
    ["TypeScript", "Java", "Python", "Go"] as const,
    `${id} language`,
  );
  const variant = knownString(
    value.variant,
    [
      "clean",
      "direct_overlap",
      "duplicate",
      "guarded",
      "irrelevant_guard",
      "partial",
      "stale_evidence",
      "structural_only",
      "vulnerable",
    ] as const,
    `${id} variant`,
  );
  const sources = endpointList(value.sources, `${id} sources`);
  const sinks = endpointList(value.sinks, `${id} sinks`);
  const routes = routeList(value.routes, `${id} routes`);
  const sourceNames = new Set(sources.map((endpoint) => endpoint.name));
  const sinkNames = new Set(sinks.map((endpoint) => endpoint.name));
  for (const route of routes) {
    if (!sourceNames.has(route.source) || !sinkNames.has(route.sink)) {
      throw new Error(`${id} route references an unknown source or sink`);
    }
  }
  const control = value.control === undefined ? undefined : validateControl(value.control, id);
  if ((variant === "guarded" || variant === "irrelevant_guard") && control === undefined) {
    throw new Error(`${id} ${variant} requires control`);
  }
  return {
    id,
    split,
    language,
    fixturePath: safeRepoPath(value.fixturePath, `${id} fixturePath`),
    variant,
    sinkType: nonEmptyString(value.sinkType, `${id} sinkType`),
    sources,
    sinks,
    routes,
    ...(control === undefined ? {} : { control }),
    truth: {
      candidateRootCauses: stringList(value.truth.candidateRootCauses, `${id} candidateRootCauses`),
      supportedRootCauses: stringList(value.truth.supportedRootCauses, `${id} supportedRootCauses`),
      ownerValidationRootCauses: stringList(
        value.truth.ownerValidationRootCauses,
        `${id} ownerValidationRootCauses`,
      ),
      directFindingIds: stringList(value.truth.directFindingIds, `${id} directFindingIds`),
    },
  };
}

function validateControl(value: unknown, id: string): ReportV1BenchmarkControl {
  if (!isRecord(value)) {
    throw new Error(`${id} control must be an object`);
  }
  return {
    line: positiveInteger(value.line, `${id} control line`),
    effect: knownString(value.effect, ["blocks_untrusted"] as const, `${id} control effect`),
    protectsSinkType: nonEmptyString(value.protectsSinkType, `${id} control protectsSinkType`),
  };
}

function endpointList(value: unknown, label: string): ReportV1BenchmarkEndpoint[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${label} must be a non-empty array`);
  }
  return value.map((item) => {
    if (!isRecord(item)) {
      throw new Error(`${label} entries must be objects`);
    }
    return {
      name: nonEmptyString(item.name, `${label} name`),
      line: positiveInteger(item.line, `${label} line`),
    };
  });
}

function routeList(value: unknown, label: string): ReportV1BenchmarkRoute[] {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value.map((item) => {
    if (!isRecord(item)) {
      throw new Error(`${label} entries must be objects`);
    }
    return {
      source: nonEmptyString(item.source, `${label} source`),
      sink: nonEmptyString(item.sink, `${label} sink`),
    };
  });
}

function stringList(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return uniqueSorted(value.map((item) => nonEmptyString(item, label)));
}

function safeRepoPath(value: unknown, label: string): string {
  const result = nonEmptyString(value, label);
  if (path.isAbsolute(result) || result.split("/").some((part) => part === ".." || part === "")) {
    throw new Error(`${label} must be a safe repository-relative path`);
  }
  return result;
}

function knownString<const T extends string>(
  value: unknown,
  allowed: ReadonlyArray<T>,
  label: string,
): T {
  const result = nonEmptyString(value, label);
  if (!allowed.includes(result as T)) {
    throw new Error(`${label} is invalid: ${result}`);
  }
  return result as T;
}

function ratio(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${label} must be a ratio between 0 and 1`);
  }
  return value;
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isInteger(value) || typeof value !== "number" || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isInteger(value) || typeof value !== "number" || value < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return value;
}

function nonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function requiredEndpoint(
  endpoints: ReadonlyMap<string, SecurityGraphNode>,
  name: string,
  caseId: string,
  kind: string,
): SecurityGraphNode {
  const endpoint = endpoints.get(name);
  if (endpoint === undefined) {
    throw new Error(`${caseId} is missing ${kind} endpoint: ${name}`);
  }
  return endpoint;
}

function requiredFirst<T>(values: ReadonlyArray<T>, label: string): T {
  const first = values[0];
  if (first === undefined) {
    throw new Error(`${label} requires at least one value`);
  }
  return first;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
