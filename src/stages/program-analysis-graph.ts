import type { Manifest } from "../domain/manifest.js";
import type { RunId } from "../domain/run.js";
import type {
  GraphCoverage,
  GraphCoverageState,
  LineRange,
  SecurityFlow,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../domain/security-graph.js";
import {
  securityFlowId,
  securityGraphEdgeId,
  securityGraphId,
  securityGraphNodeId,
  validateSecurityGraph,
} from "../domain/security-graph.js";
import type {
  ProgramAnalysisExtractionArtifact,
  ProgramAnalysisExtractionKind,
} from "../ports/program-analysis-backend.js";

export interface ComposeProgramAnalysisGraphInput {
  readonly runId: RunId;
  readonly snapshotId: string;
  readonly graphVersion: string;
  readonly manifest: Manifest;
  readonly artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>;
  readonly createdAt: string;
}

type AtomObject = Readonly<Record<string, unknown>>;

interface ObservedEntity {
  readonly fullName: string;
  readonly symbol: string;
  readonly repoPath: string;
  readonly lineRange: LineRange;
  readonly slice: AtomObject;
  readonly evidenceId: string;
  readonly producerVersion: string;
}

interface BoundaryHint {
  readonly boundaryType: string;
  readonly routeOrName: string;
  readonly method?: string;
  readonly sourceName?: string;
}

interface FlowBoundaryObservation {
  readonly fullName: string;
  readonly repoPath: string;
  readonly lineRange: LineRange;
  readonly sourceName: string;
  readonly evidenceId: string;
  readonly producerVersion: string;
}

interface GraphBuilder {
  readonly nodes: SecurityGraphNode[];
  readonly edges: SecurityGraphEdge[];
  readonly nodesByStableKey: Map<string, SecurityGraphNode>;
  readonly codeByFullName: Map<string, SecurityGraphNode>;
  readonly codeBySymbol: Map<string, SecurityGraphNode[]>;
  readonly edgesByStableKey: Map<string, SecurityGraphEdge>;
}

const PRODUCER = "atom";
const DEFAULT_CONFIDENCE = 0.9;
const SINK_NAMES = new Set([
  "fetch",
  "axios",
  "axios.get",
  "http.get",
  "https.get",
  "child_process.exec",
  "exec",
  "eval",
]);

export function composeProgramAnalysisGraph(
  input: ComposeProgramAnalysisGraphInput,
): SecurityGraph {
  const manifestPaths = new Set(input.manifest.files.map((file) => file.path));
  const artifactsByKind = artifactsByExtractionKind(input.artifacts);
  const usageArtifacts = [
    ...artifactsOfKind(artifactsByKind, "entities"),
    ...artifactsOfKind(artifactsByKind, "boundaries"),
    ...artifactsOfKind(artifactsByKind, "call_edges"),
    ...artifactsOfKind(artifactsByKind, "component_usage"),
  ];
  const flowArtifacts = artifactsOfKind(artifactsByKind, "flows");
  const reachabilityArtifacts = [
    ...artifactsOfKind(artifactsByKind, "call_edges"),
    ...artifactsOfKind(artifactsByKind, "component_usage"),
    ...flowArtifacts,
  ];
  const builder = graphBuilder();
  const observedEntities: ObservedEntity[] = [];

  for (const artifact of usageArtifacts) {
    observedEntities.push(...readObservedEntities(artifact, manifestPaths));
  }

  for (const entity of observedEntities) {
    const node = addCodeEntity(builder, input.graphVersion, entity);
    builder.codeByFullName.set(entity.fullName, node);
    addSymbolTarget(builder, entity.symbol, node);
  }

  for (const entity of observedEntities) {
    const owner = builder.codeByFullName.get(entity.fullName);
    if (owner === undefined) {
      continue;
    }
    addBoundaryHint(builder, input.graphVersion, entity, owner);
  }

  for (const observation of readFlowBoundaryObservations(reachabilityArtifacts, manifestPaths)) {
    addFlowBoundaryObservation(builder, input.graphVersion, observation);
  }

  for (const entity of observedEntities) {
    const owner = builder.codeByFullName.get(entity.fullName);
    if (owner === undefined) {
      continue;
    }
    addObservedCalls(builder, input.graphVersion, entity, owner);
  }

  const flows = buildFlows(input.graphVersion, builder);
  const graph: SecurityGraph = {
    id: securityGraphId(input.snapshotId, input.graphVersion),
    runId: input.runId,
    snapshotId: input.snapshotId,
    graphVersion: input.graphVersion,
    nodes: builder.nodes,
    edges: builder.edges,
    flows,
    coverage: buildCoverage({
      producerVersion: producerVersion(input.artifacts),
      entityCount: observedEntities.length,
      boundaryCount: countNodes(builder, "Boundary"),
      callEdgeCount: countEdges(builder, "calls"),
      flowArtifactCount: flowArtifacts.length,
      flowCount: flows.length,
    }),
    createdAt: input.createdAt,
  };

  const evidenceIds = new Set(input.artifacts.map((artifact) => artifact.sliceArtifact.blobSha256));
  return validateSecurityGraph(graph, { manifestPaths, evidenceIds });
}

function artifactsByExtractionKind(
  artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>,
): ReadonlyMap<ProgramAnalysisExtractionKind, ProgramAnalysisExtractionArtifact[]> {
  const byKind = new Map<ProgramAnalysisExtractionKind, ProgramAnalysisExtractionArtifact[]>();
  for (const artifact of artifacts) {
    const current = byKind.get(artifact.kind) ?? [];
    current.push(artifact);
    byKind.set(artifact.kind, current);
  }
  return byKind;
}

function artifactsOfKind(
  artifacts: ReadonlyMap<ProgramAnalysisExtractionKind, ProgramAnalysisExtractionArtifact[]>,
  kind: ProgramAnalysisExtractionKind,
): ReadonlyArray<ProgramAnalysisExtractionArtifact> {
  return artifacts.get(kind) ?? [];
}

function graphBuilder(): GraphBuilder {
  return {
    nodes: [],
    edges: [],
    nodesByStableKey: new Map(),
    codeByFullName: new Map(),
    codeBySymbol: new Map(),
    edgesByStableKey: new Map(),
  };
}

function readObservedEntities(
  artifact: ProgramAnalysisExtractionArtifact,
  manifestPaths: ReadonlySet<string>,
): ObservedEntity[] {
  const root = asObject(artifact.parsed);
  const objectSlices = asObjectArray(root.objectSlices);
  const observed: ObservedEntity[] = [];

  for (const slice of objectSlices) {
    const fullName = stringValue(slice.fullName);
    const repoPath = stringValue(slice.fileName);
    const lineNumber = positiveInteger(slice.lineNumber);
    if (fullName === undefined || repoPath === undefined || lineNumber === undefined) {
      continue;
    }
    if (!isSafeManifestPath(repoPath, manifestPaths)) {
      continue;
    }
    observed.push({
      fullName,
      symbol: symbolFromFullName(fullName),
      repoPath,
      lineRange: { startLine: lineNumber, endLine: lineNumber },
      slice,
      evidenceId: artifact.sliceArtifact.blobSha256,
      producerVersion: artifact.backendVersion,
    });
  }

  return observed;
}

function readFlowBoundaryObservations(
  artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>,
  manifestPaths: ReadonlySet<string>,
): FlowBoundaryObservation[] {
  return artifacts.flatMap((artifact) => {
    const observations: FlowBoundaryObservation[] = [];
    for (const flowRecord of asObjectArray(artifact.parsed)) {
      for (const flow of asObjectArray(flowRecord.flows)) {
        const label = stringValue(flow.label);
        const tags = stringValue(flow.tags);
        const repoPath = stringValue(flow.parentFileName);
        const methodName = stringValue(flow.parentMethodName);
        const parentClassName = stringValue(flow.parentClassName);
        const lineNumber = positiveInteger(flow.lineNumber);
        const sourceName = stringValue(flow.name) ?? stringValue(flow.code);
        if (
          label !== "METHOD_PARAMETER_IN" ||
          tags?.includes("framework-input") !== true ||
          repoPath === undefined ||
          methodName === undefined ||
          lineNumber === undefined ||
          sourceName === undefined ||
          !isSafeManifestPath(repoPath, manifestPaths)
        ) {
          continue;
        }
        observations.push({
          fullName:
            parentClassName === undefined
              ? `${repoPath}::program:${methodName}`
              : `${parentClassName}:${methodName}`,
          repoPath,
          lineRange: { startLine: lineNumber, endLine: lineNumber },
          sourceName,
          evidenceId: artifact.sliceArtifact.blobSha256,
          producerVersion: artifact.backendVersion,
        });
      }
    }
    return observations;
  });
}

function addCodeEntity(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
): SecurityGraphNode {
  return addNode(builder, graphVersion, {
    kind: "CodeEntity",
    stableKey: `CodeEntity:${entity.fullName}:${entity.repoPath}:${entity.lineRange.startLine}`,
    label: entity.symbol,
    repoPath: entity.repoPath,
    lineRange: entity.lineRange,
    symbol: entity.fullName,
    properties: {
      fullName: entity.fullName,
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
}

function addBoundaryHint(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
  owner: SecurityGraphNode,
): void {
  const hint = boundaryHint(entity.slice.boundary);
  if (hint === undefined) {
    return;
  }

  const boundary = addNode(builder, graphVersion, {
    kind: "Boundary",
    stableKey: `Boundary:${hint.boundaryType}:${hint.method ?? ""}:${hint.routeOrName}:${entity.fullName}`,
    label: hint.routeOrName,
    repoPath: entity.repoPath,
    lineRange: entity.lineRange,
    symbol: entity.fullName,
    properties: {
      boundaryType: hint.boundaryType,
      routeOrName: hint.routeOrName,
      ...(hint.method === undefined ? {} : { method: hint.method }),
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
  const source = addNode(builder, graphVersion, {
    kind: "Source",
    stableKey: `Source:${boundary.stableKey}:${hint.sourceName ?? "request"}`,
    label: hint.sourceName ?? "request input",
    repoPath: entity.repoPath,
    lineRange: entity.lineRange,
    symbol: hint.sourceName ?? "request",
    properties: {
      sourceType: "external_input",
      boundaryNodeId: boundary.id,
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });

  addEdge(builder, graphVersion, {
    kind: "receives",
    stableKey: `receives:${source.id}:${boundary.id}`,
    fromNodeId: source.id,
    toNodeId: boundary.id,
    properties: {},
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
  addEdge(builder, graphVersion, {
    kind: "registers",
    stableKey: `registers:${boundary.id}:${owner.id}`,
    fromNodeId: boundary.id,
    toNodeId: owner.id,
    properties: {},
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
}

function addFlowBoundaryObservation(
  builder: GraphBuilder,
  graphVersion: string,
  observation: FlowBoundaryObservation,
): void {
  const owner = findBoundaryOwner(builder, observation);
  if (owner === undefined || hasRegisteredBoundary(builder, owner.id)) {
    return;
  }

  const boundary = addNode(builder, graphVersion, {
    kind: "Boundary",
    stableKey: `Boundary:framework-input::${owner.symbol ?? owner.label}`,
    label: observationLabel(observation),
    repoPath: observation.repoPath,
    lineRange: observation.lineRange,
    ...(owner.symbol === undefined ? {} : { symbol: owner.symbol }),
    properties: {
      boundaryType: "framework-input",
      routeOrName: observationLabel(observation),
    },
    evidenceIds: [observation.evidenceId],
    producerVersion: observation.producerVersion,
  });
  const source = addNode(builder, graphVersion, {
    kind: "Source",
    stableKey: `Source:${boundary.stableKey}:${observation.sourceName}`,
    label: observation.sourceName,
    repoPath: observation.repoPath,
    lineRange: observation.lineRange,
    symbol: observation.sourceName,
    properties: {
      sourceType: "external_input",
      boundaryNodeId: boundary.id,
    },
    evidenceIds: [observation.evidenceId],
    producerVersion: observation.producerVersion,
  });

  addEdge(builder, graphVersion, {
    kind: "receives",
    stableKey: `receives:${source.id}:${boundary.id}`,
    fromNodeId: source.id,
    toNodeId: boundary.id,
    properties: {},
    evidenceIds: [observation.evidenceId],
    producerVersion: observation.producerVersion,
  });
  addEdge(builder, graphVersion, {
    kind: "registers",
    stableKey: `registers:${boundary.id}:${owner.id}`,
    fromNodeId: boundary.id,
    toNodeId: owner.id,
    properties: {},
    evidenceIds: [observation.evidenceId],
    producerVersion: observation.producerVersion,
  });
}

function addObservedCalls(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
  owner: SecurityGraphNode,
): void {
  for (const usage of asObjectArray(entity.slice.usages)) {
    const target = asObject(usage.targetObj);
    const name = stringValue(target.resolvedMethod) ?? stringValue(target.name);
    if (name === undefined || stringValue(target.label) !== "CALL") {
      continue;
    }
    const targetNode =
      findTargetCodeEntity(builder, name) ??
      addSinkIfKnown(builder, graphVersion, entity, target, name);
    if (targetNode === undefined) {
      continue;
    }
    addEdge(builder, graphVersion, {
      kind: "calls",
      stableKey: `calls:${owner.id}:${targetNode.id}:${entity.repoPath}:${positiveInteger(target.lineNumber) ?? entity.lineRange.startLine}`,
      fromNodeId: owner.id,
      toNodeId: targetNode.id,
      properties: {
        callName: name,
      },
      evidenceIds: [entity.evidenceId],
      producerVersion: entity.producerVersion,
    });
  }
}

function findTargetCodeEntity(builder: GraphBuilder, name: string): SecurityGraphNode | undefined {
  const exactTarget = builder.codeByFullName.get(name);
  if (exactTarget !== undefined) {
    return exactTarget;
  }
  const symbolTargets = builder.codeBySymbol.get(symbolFromFullName(name)) ?? [];
  return symbolTargets.length === 1 ? symbolTargets[0] : undefined;
}

function findBoundaryOwner(
  builder: GraphBuilder,
  observation: FlowBoundaryObservation,
): SecurityGraphNode | undefined {
  const exactTarget = builder.codeByFullName.get(observation.fullName);
  if (exactTarget !== undefined) {
    return exactTarget;
  }
  const symbolTargets = builder.codeBySymbol.get(symbolFromFullName(observation.fullName)) ?? [];
  const sameFileTargets = symbolTargets.filter((node) => node.repoPath === observation.repoPath);
  return sameFileTargets.length === 1 ? sameFileTargets[0] : undefined;
}

function hasRegisteredBoundary(builder: GraphBuilder, ownerId: string): boolean {
  return builder.edges.some(
    (edge) =>
      edge.kind === "registers" &&
      edge.toNodeId === ownerId &&
      builder.nodes.find((node) => node.id === edge.fromNodeId)?.kind === "Boundary",
  );
}

function addSymbolTarget(builder: GraphBuilder, symbol: string, node: SecurityGraphNode): void {
  const current = builder.codeBySymbol.get(symbol) ?? [];
  if (current.some((target) => target.id === node.id)) {
    return;
  }
  builder.codeBySymbol.set(symbol, [...current, node]);
}

function addSinkIfKnown(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
  target: AtomObject,
  name: string,
): SecurityGraphNode | undefined {
  const normalized = normalizeCallName(name);
  if (!SINK_NAMES.has(normalized)) {
    return undefined;
  }
  const lineNumber = positiveInteger(target.lineNumber) ?? entity.lineRange.startLine;
  return addNode(builder, graphVersion, {
    kind: "Sink",
    stableKey: `Sink:${normalized}:${entity.fullName}:${entity.repoPath}:${lineNumber}`,
    label: normalized,
    repoPath: entity.repoPath,
    lineRange: { startLine: lineNumber, endLine: lineNumber },
    symbol: normalized,
    properties: {
      sinkType: sinkType(normalized),
      callName: name,
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
}

function buildFlows(graphVersion: string, builder: GraphBuilder): SecurityFlow[] {
  const sources = builder.nodes.filter((node) => node.kind === "Source");
  const sinks = new Set(
    builder.nodes.filter((node) => node.kind === "Sink").map((node) => node.id),
  );
  const outgoing = new Map<string, SecurityGraphEdge[]>();
  for (const edge of builder.edges) {
    if (!["receives", "registers", "calls", "flows_to"].includes(edge.kind)) {
      continue;
    }
    const current = outgoing.get(edge.fromNodeId) ?? [];
    current.push(edge);
    outgoing.set(edge.fromNodeId, current);
  }

  const flows: SecurityFlow[] = [];
  for (const source of sources) {
    const path = firstPathToSink(source.id, sinks, outgoing);
    if (path === undefined) {
      continue;
    }
    const sinkId = path.at(-1)?.toNodeId;
    if (sinkId === undefined) {
      continue;
    }
    const stableKey = `flow:${source.id}:${sinkId}:${path.map((edge) => edge.id).join(">")}`;
    flows.push({
      id: securityFlowId(graphVersion, stableKey),
      sourceNodeId: source.id,
      sinkNodeId: sinkId,
      pathEdgeIds: path.map((edge) => edge.id),
      controlNodeIds: [],
      coverageState: "checked",
      confidence: DEFAULT_CONFIDENCE,
      evidenceIds: unique(path.flatMap((edge) => edge.evidenceIds)),
    });
  }

  return flows;
}

function firstPathToSink(
  startNodeId: string,
  sinkIds: ReadonlySet<string>,
  outgoing: ReadonlyMap<string, ReadonlyArray<SecurityGraphEdge>>,
): SecurityGraphEdge[] | undefined {
  const queue: Array<{ readonly nodeId: string; readonly path: ReadonlyArray<SecurityGraphEdge> }> =
    [{ nodeId: startNodeId, path: [] }];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined || visited.has(current.nodeId)) {
      continue;
    }
    visited.add(current.nodeId);
    if (sinkIds.has(current.nodeId) && current.path.length > 0) {
      return [...current.path];
    }
    for (const edge of outgoing.get(current.nodeId) ?? []) {
      queue.push({ nodeId: edge.toNodeId, path: [...current.path, edge] });
    }
  }

  return undefined;
}

function addNode(
  builder: GraphBuilder,
  graphVersion: string,
  input: {
    readonly kind: SecurityGraphNode["kind"];
    readonly stableKey: string;
    readonly label: string;
    readonly repoPath?: string;
    readonly lineRange?: LineRange;
    readonly symbol?: string;
    readonly properties: Readonly<Record<string, unknown>>;
    readonly evidenceIds: ReadonlyArray<string>;
    readonly producerVersion: string;
  },
): SecurityGraphNode {
  const existing = builder.nodesByStableKey.get(input.stableKey);
  if (existing !== undefined) {
    return existing;
  }
  const node: SecurityGraphNode = {
    id: securityGraphNodeId(graphVersion, input.stableKey),
    kind: input.kind,
    stableKey: input.stableKey,
    label: input.label,
    properties: input.properties,
    evidenceIds: input.evidenceIds,
    producer: PRODUCER,
    producerVersion: input.producerVersion,
    confidence: DEFAULT_CONFIDENCE,
    coverageState: "checked",
    ...(input.repoPath === undefined ? {} : { repoPath: input.repoPath }),
    ...(input.lineRange === undefined ? {} : { lineRange: input.lineRange }),
    ...(input.symbol === undefined ? {} : { symbol: input.symbol }),
  };
  builder.nodes.push(node);
  builder.nodesByStableKey.set(node.stableKey, node);
  return node;
}

function addEdge(
  builder: GraphBuilder,
  graphVersion: string,
  input: {
    readonly kind: SecurityGraphEdge["kind"];
    readonly stableKey: string;
    readonly fromNodeId: string;
    readonly toNodeId: string;
    readonly properties: Readonly<Record<string, unknown>>;
    readonly evidenceIds: ReadonlyArray<string>;
    readonly producerVersion: string;
  },
): SecurityGraphEdge {
  const existing = builder.edgesByStableKey.get(input.stableKey);
  if (existing !== undefined) {
    return existing;
  }
  const edge: SecurityGraphEdge = {
    id: securityGraphEdgeId(graphVersion, input.stableKey),
    kind: input.kind,
    stableKey: input.stableKey,
    fromNodeId: input.fromNodeId,
    toNodeId: input.toNodeId,
    properties: input.properties,
    evidenceIds: input.evidenceIds,
    producer: PRODUCER,
    producerVersion: input.producerVersion,
    confidence: DEFAULT_CONFIDENCE,
    coverageState: "checked",
  };
  builder.edges.push(edge);
  builder.edgesByStableKey.set(edge.stableKey, edge);
  return edge;
}

function buildCoverage(input: {
  readonly producerVersion: string;
  readonly entityCount: number;
  readonly boundaryCount: number;
  readonly callEdgeCount: number;
  readonly flowArtifactCount: number;
  readonly flowCount: number;
}): GraphCoverage[] {
  return [
    coverage(
      "boundaries",
      input.boundaryCount > 0 ? "checked" : "partial",
      input.boundaryCount,
      input.entityCount,
      input.producerVersion,
    ),
    coverage(
      "call_graph",
      input.callEdgeCount > 0 ? "checked" : "partial",
      input.callEdgeCount,
      input.entityCount,
      input.producerVersion,
    ),
    coverage(
      "data_flow",
      input.flowCount > 0 ? "checked" : input.flowArtifactCount > 0 ? "partial" : "skipped",
      input.flowCount,
      Math.max(input.boundaryCount, input.flowCount, 1),
      input.producerVersion,
    ),
  ];
}

function coverage(
  area: GraphCoverage["area"],
  state: GraphCoverageState,
  coveredCount: number,
  totalCount: number,
  producerVersion: string,
): GraphCoverage {
  return {
    area,
    state,
    coveredCount,
    totalCount,
    producer: PRODUCER,
    producerVersion,
    ...(state === "checked"
      ? {}
      : { reason: `${area} coverage is incomplete from current Atom artifacts.` }),
  };
}

function producerVersion(artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>): string {
  return artifacts[0]?.backendVersion ?? "atom@unknown";
}

function countNodes(builder: GraphBuilder, kind: SecurityGraphNode["kind"]): number {
  return builder.nodes.filter((node) => node.kind === kind).length;
}

function countEdges(builder: GraphBuilder, kind: SecurityGraphEdge["kind"]): number {
  return builder.edges.filter((edge) => edge.kind === kind).length;
}

function boundaryHint(value: unknown): BoundaryHint | undefined {
  const hint = asObject(value);
  const boundaryType = stringValue(hint.boundaryType);
  const routeOrName = stringValue(hint.routeOrName);
  const method = stringValue(hint.method);
  const sourceName = stringValue(hint.sourceName);
  if (boundaryType === undefined || routeOrName === undefined) {
    return undefined;
  }
  return {
    boundaryType,
    routeOrName,
    ...(method === undefined ? {} : { method }),
    ...(sourceName === undefined ? {} : { sourceName }),
  };
}

function observationLabel(observation: FlowBoundaryObservation): string {
  return symbolFromFullName(observation.fullName);
}

function asObject(value: unknown): AtomObject {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as AtomObject)
    : {};
}

function asObjectArray(value: unknown): AtomObject[] {
  return Array.isArray(value)
    ? value.map(asObject).filter((item) => Object.keys(item).length > 0)
    : [];
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

function positiveInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : undefined;
}

function isSafeManifestPath(repoPath: string, manifestPaths: ReadonlySet<string>): boolean {
  return (
    manifestPaths.has(repoPath) &&
    !repoPath.startsWith("/") &&
    repoPath.split("/").every((part) => part !== "" && part !== "." && part !== "..")
  );
}

function symbolFromFullName(fullName: string): string {
  return fullName.split(":").filter(Boolean).at(-1) ?? fullName;
}

function normalizeCallName(name: string): string {
  return symbolFromFullName(name).replace(/^globalThis\./, "");
}

function sinkType(name: string): string {
  if (name.includes("fetch") || name.includes("http") || name.includes("axios")) {
    return "outbound_http";
  }
  if (name === "eval" || name.includes("exec")) {
    return "code_execution";
  }
  return "dangerous_operation";
}

function unique(values: ReadonlyArray<string>): string[] {
  return [...new Set(values)];
}
