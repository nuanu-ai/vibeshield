import type {
  RepositoryMap,
  RepositoryMapCoverage,
  RepositoryMapFactGap,
  RepositoryMapJsonValue,
  RepositoryMapNode,
  RepositoryMapProperties,
  RepositoryMapRelationship,
} from "../domain/repository-map.js";
import type {
  GraphCoverageArea,
  GraphCoverageState,
  SecurityFlow,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../domain/security-graph.js";

const EXPECTED_COVERAGE_AREAS: ReadonlyArray<GraphCoverageArea> = [
  "boundaries",
  "call_graph",
  "data_flow",
  "dependency_usage",
  "ci_iac",
  "language_support",
];

const INCOMPLETE_COVERAGE_STATES = new Set<GraphCoverageState>([
  "skipped",
  "failed",
  "degraded",
  "partial",
]);

export function renderRepositoryMap(graph: SecurityGraph): RepositoryMap {
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const mapNodes = graph.nodes.map(toMapNode);
  const mapNodeById = new Map(mapNodes.map((node) => [node.id, node]));

  return {
    graph: {
      id: graph.id,
      runId: graph.runId,
      snapshotId: graph.snapshotId,
      graphVersion: graph.graphVersion,
      createdAt: graph.createdAt,
    },
    boundaries: nodesByKind(mapNodes, ["Boundary"]),
    codeEntities: nodesByKind(mapNodes, ["CodeEntity"]),
    integrations: nodesByKind(mapNodes, ["Component", "ExternalService"]),
    dataStores: nodesByKind(mapNodes, ["DataStore"]),
    ciIacResources: nodesByKind(mapNodes, ["BuildStep", "InfraResource"]),
    resources: nodesByKind(mapNodes, ["Resource"]),
    securityFacts: nodesByKind(mapNodes, [
      "Source",
      "Sink",
      "Control",
      "Flow",
      "Finding",
      "Secret",
    ]),
    relationships: sortedRelationships(
      graph.edges.map((edge) => toRelationship(edge, mapNodeById)),
    ),
    flows: sortedFlows(graph.flows.map((flow) => toMapFlow(flow, mapNodeById))),
    coverage: sortedCoverage(graph.coverage.map(toCoverage)),
    factGaps: factGaps(graph, nodeById),
  };
}

function nodesByKind(
  nodes: ReadonlyArray<RepositoryMapNode>,
  kinds: ReadonlyArray<SecurityGraphNode["kind"]>,
): RepositoryMapNode[] {
  const allowed = new Set(kinds);
  return nodes.filter((node) => allowed.has(node.kind)).sort(compareNodes);
}

function toMapNode(node: SecurityGraphNode): RepositoryMapNode {
  return {
    id: node.id,
    kind: node.kind,
    label: node.label,
    ...(node.repoPath === undefined ? {} : { repoPath: node.repoPath }),
    ...(node.lineRange === undefined ? {} : { lineRange: node.lineRange }),
    ...(node.symbol === undefined ? {} : { symbol: node.symbol }),
    properties: normalizeProperties(node.properties),
    evidenceIds: [...node.evidenceIds].sort(),
    producer: node.producer,
    producerVersion: node.producerVersion,
    confidence: node.confidence,
    coverageState: node.coverageState,
  };
}

function toRelationship(
  edge: SecurityGraphEdge,
  nodeById: ReadonlyMap<string, RepositoryMapNode>,
): RepositoryMapRelationship {
  return {
    id: edge.id,
    kind: edge.kind,
    fromNodeId: edge.fromNodeId,
    fromLabel: nodeById.get(edge.fromNodeId)?.label ?? edge.fromNodeId,
    toNodeId: edge.toNodeId,
    toLabel: nodeById.get(edge.toNodeId)?.label ?? edge.toNodeId,
    properties: normalizeProperties(edge.properties),
    evidenceIds: [...edge.evidenceIds].sort(),
    producer: edge.producer,
    producerVersion: edge.producerVersion,
    confidence: edge.confidence,
    coverageState: edge.coverageState,
  };
}

function toMapFlow(
  flow: SecurityFlow,
  nodeById: ReadonlyMap<string, RepositoryMapNode>,
): RepositoryMap["flows"][number] {
  return {
    id: flow.id,
    sourceNodeId: flow.sourceNodeId,
    sourceLabel: nodeById.get(flow.sourceNodeId)?.label ?? flow.sourceNodeId,
    sinkNodeId: flow.sinkNodeId,
    sinkLabel: nodeById.get(flow.sinkNodeId)?.label ?? flow.sinkNodeId,
    pathEdgeIds: [...flow.pathEdgeIds],
    controlNodeIds: [...flow.controlNodeIds].sort(),
    evidenceIds: [...flow.evidenceIds].sort(),
    confidence: flow.confidence,
    coverageState: flow.coverageState,
  };
}

function toCoverage(coverage: SecurityGraph["coverage"][number]): RepositoryMapCoverage {
  return {
    area: coverage.area,
    state: coverage.state,
    ...(coverage.coveredCount === undefined ? {} : { coveredCount: coverage.coveredCount }),
    ...(coverage.totalCount === undefined ? {} : { totalCount: coverage.totalCount }),
    ...(coverage.reason === undefined ? {} : { reason: coverage.reason }),
    producer: coverage.producer,
    producerVersion: coverage.producerVersion,
  };
}

function factGaps(
  graph: SecurityGraph,
  nodeById: ReadonlyMap<string, SecurityGraphNode>,
): RepositoryMapFactGap[] {
  return [
    ...coverageGaps(graph.coverage),
    ...graph.nodes.filter(hasIncompleteCoverage).map(nodeGap),
    ...graph.edges.filter(hasIncompleteCoverage).map((edge) => edgeGap(edge, nodeById)),
    ...graph.flows.filter(hasIncompleteCoverage).map((flow) => flowGap(flow, nodeById)),
  ].sort(compareFactGaps);
}

function coverageGaps(coverage: SecurityGraph["coverage"]): RepositoryMapFactGap[] {
  const gaps: RepositoryMapFactGap[] = coverage.filter(hasIncompleteCoverage).map((entry) => ({
    id: `coverage:${entry.area}:${entry.producer}`,
    source: "coverage" as const,
    area: entry.area,
    producer: entry.producer,
    state: entry.state,
    label: entry.area,
    description: entry.reason ?? `Coverage for ${entry.area} is ${entry.state}.`,
  }));
  const seenAreas = new Set(coverage.map((entry) => entry.area));
  for (const area of EXPECTED_COVERAGE_AREAS) {
    if (!seenAreas.has(area)) {
      gaps.push({
        id: `coverage:${area}:missing`,
        source: "coverage",
        area,
        state: "skipped",
        label: area,
        description: `No graph coverage was recorded for ${area}.`,
      });
    }
  }
  return gaps;
}

function nodeGap(node: SecurityGraphNode): RepositoryMapFactGap {
  return {
    id: `node:${node.id}`,
    source: "node",
    state: node.coverageState,
    label: node.label,
    description: `${node.kind} coverage is ${node.coverageState}.`,
    graphNodeId: node.id,
  };
}

function edgeGap(
  edge: SecurityGraphEdge,
  nodeById: ReadonlyMap<string, SecurityGraphNode>,
): RepositoryMapFactGap {
  const from = nodeById.get(edge.fromNodeId)?.label ?? edge.fromNodeId;
  const to = nodeById.get(edge.toNodeId)?.label ?? edge.toNodeId;
  return {
    id: `edge:${edge.id}`,
    source: "edge",
    state: edge.coverageState,
    label: `${from} ${edge.kind} ${to}`,
    description: `${edge.kind} relationship coverage is ${edge.coverageState}.`,
    graphEdgeId: edge.id,
  };
}

function flowGap(
  flow: SecurityFlow,
  nodeById: ReadonlyMap<string, SecurityGraphNode>,
): RepositoryMapFactGap {
  const source = nodeById.get(flow.sourceNodeId)?.label ?? flow.sourceNodeId;
  const sink = nodeById.get(flow.sinkNodeId)?.label ?? flow.sinkNodeId;
  return {
    id: `flow:${flow.id}`,
    source: "flow",
    state: flow.coverageState,
    label: `${source} -> ${sink}`,
    description: `Flow coverage is ${flow.coverageState}.`,
    graphFlowId: flow.id,
  };
}

function hasIncompleteCoverage(record: { readonly coverageState: GraphCoverageState }): boolean;
function hasIncompleteCoverage(record: { readonly state: GraphCoverageState }): boolean;
function hasIncompleteCoverage(record: {
  readonly coverageState?: GraphCoverageState;
  readonly state?: GraphCoverageState;
}): boolean {
  return INCOMPLETE_COVERAGE_STATES.has(record.coverageState ?? record.state ?? "checked");
}

function normalizeProperties(
  properties: Readonly<Record<string, unknown>>,
): RepositoryMapProperties {
  return normalizeJson(properties) as RepositoryMapProperties;
}

function normalizeJson(value: unknown): RepositoryMapJsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(normalizeJson);
  }
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, normalizeJson(child)]),
    );
  }
  return null;
}

function sortedRelationships(
  relationships: ReadonlyArray<RepositoryMapRelationship>,
): RepositoryMapRelationship[] {
  return [...relationships].sort(
    (a, b) =>
      a.kind.localeCompare(b.kind) ||
      a.fromNodeId.localeCompare(b.fromNodeId) ||
      a.toNodeId.localeCompare(b.toNodeId) ||
      a.id.localeCompare(b.id),
  );
}

function sortedFlows(flows: ReadonlyArray<RepositoryMap["flows"][number]>): RepositoryMap["flows"] {
  return [...flows].sort((a, b) => a.id.localeCompare(b.id));
}

function sortedCoverage(coverage: ReadonlyArray<RepositoryMapCoverage>): RepositoryMapCoverage[] {
  return [...coverage].sort(
    (a, b) =>
      a.area.localeCompare(b.area) ||
      a.producer.localeCompare(b.producer) ||
      a.producerVersion.localeCompare(b.producerVersion),
  );
}

function compareNodes(a: RepositoryMapNode, b: RepositoryMapNode): number {
  return (
    (a.repoPath ?? "").localeCompare(b.repoPath ?? "") ||
    a.label.localeCompare(b.label) ||
    a.kind.localeCompare(b.kind) ||
    a.id.localeCompare(b.id)
  );
}

function compareFactGaps(a: RepositoryMapFactGap, b: RepositoryMapFactGap): number {
  return (
    a.source.localeCompare(b.source) ||
    (a.area ?? "").localeCompare(b.area ?? "") ||
    a.label.localeCompare(b.label) ||
    a.id.localeCompare(b.id)
  );
}
