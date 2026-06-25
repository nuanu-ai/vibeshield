import type {
  ComponentReachability,
  ComponentReachabilityLevel,
} from "../domain/component-reachability.js";
import { validateComponentReachability } from "../domain/component-reachability.js";
import type { Manifest } from "../domain/manifest.js";
import type {
  LineRange,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../domain/security-graph.js";
import {
  securityGraphEdgeId,
  securityGraphNodeId,
  validateSecurityGraph,
} from "../domain/security-graph.js";

export interface ComponentUsageObservation {
  readonly packageName: string;
  readonly version?: string;
  readonly repoPath: string;
  readonly symbol?: string;
  readonly usageKind: "imported" | "used";
  readonly evidenceIds: ReadonlyArray<string>;
  readonly lineRange?: LineRange;
  readonly affectedSymbol?: string;
}

export interface ComponentDependencyObservation {
  readonly sourcePackageName: string;
  readonly packageName: string;
  readonly version?: string;
  readonly manifestPath: string;
  readonly relationship?: string;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly lineRange?: LineRange;
}

export interface ComposeComponentReachabilityInput {
  readonly graph: SecurityGraph;
  readonly manifest: Manifest;
  readonly observations?: ReadonlyArray<ComponentUsageObservation>;
  readonly dependencyObservations?: ReadonlyArray<ComponentDependencyObservation>;
  readonly maxPathLength?: number;
}

export interface ComponentReachabilityResult {
  readonly graph: SecurityGraph;
  readonly reachability: ReadonlyArray<ComponentReachability>;
}

const PRODUCER = "component-reachability";
const DEFAULT_CONFIDENCE = 0.9;
const DEFAULT_MAX_PATH_LENGTH = 12;

export function composeComponentReachability(
  input: ComposeComponentReachabilityInput,
): ComponentReachabilityResult {
  const manifestPaths = new Set(input.manifest.files.map((file) => file.path));
  const nodes = [...input.graph.nodes];
  const edges = [...input.graph.edges];
  const nodeKeys = new Set(nodes.map((node) => node.stableKey));
  const edgeKeys = new Set(edges.map((edge) => edge.stableKey));

  for (const observation of input.observations ?? []) {
    if (observation.evidenceIds.length === 0) {
      throw new Error(`component usage observation for ${observation.packageName} has no evidence`);
    }
    if (!manifestPaths.has(observation.repoPath)) {
      continue;
    }
    const componentNodes = findComponentNodes(nodes, observation.packageName);
    if (componentNodes.length === 0) {
      continue;
    }
    const codeNode =
      findCodeNode(nodes, observation) ??
      addComponentUsageCodeNode(nodes, nodeKeys, input.graph.graphVersion, observation);
    const kind = observation.usageKind === "imported" ? "imports" : "uses";
    for (const componentNode of componentNodes) {
      const stableKey = [
        "component_usage",
        kind,
        codeNode.id,
        componentNode.id,
        observation.repoPath,
        observation.lineRange?.startLine ?? 0,
        observation.packageName,
        observation.affectedSymbol ?? "",
      ].join(":");
      if (edgeKeys.has(stableKey)) {
        continue;
      }
      edges.push({
        id: securityGraphEdgeId(input.graph.graphVersion, stableKey),
        kind,
        stableKey,
        fromNodeId: codeNode.id,
        toNodeId: componentNode.id,
        properties: {
          packageName: observation.packageName,
          usageKind: observation.usageKind,
          ...(observation.version === undefined ? {} : { version: observation.version }),
          ...(observation.affectedSymbol === undefined
            ? {}
            : { affectedSymbol: observation.affectedSymbol }),
        },
        evidenceIds: observation.evidenceIds,
        producer: PRODUCER,
        producerVersion: input.graph.graphVersion,
        confidence: DEFAULT_CONFIDENCE,
        coverageState: "checked",
      });
      edgeKeys.add(stableKey);
    }
  }

  for (const observation of input.dependencyObservations ?? []) {
    if (observation.evidenceIds.length === 0) {
      throw new Error(
        `component dependency observation for ${observation.packageName} has no evidence`,
      );
    }
    if (!manifestPaths.has(observation.manifestPath)) {
      continue;
    }
    const componentNodes = findComponentNodes(nodes, observation.packageName);
    if (componentNodes.length === 0) {
      continue;
    }
    const manifestNode = addDependencyManifestNode(
      nodes,
      nodeKeys,
      input.graph.graphVersion,
      observation,
    );
    for (const componentNode of componentNodes) {
      const stableKey = [
        "component_dependency",
        "depends_on",
        manifestNode.id,
        componentNode.id,
        observation.manifestPath,
        observation.sourcePackageName,
        observation.packageName,
      ].join(":");
      if (edgeKeys.has(stableKey)) {
        continue;
      }
      edges.push({
        id: securityGraphEdgeId(input.graph.graphVersion, stableKey),
        kind: "depends_on",
        stableKey,
        fromNodeId: manifestNode.id,
        toNodeId: componentNode.id,
        properties: {
          packageName: observation.packageName,
          sourcePackageName: observation.sourcePackageName,
          relationship: observation.relationship ?? "dependency_graph",
          ...(observation.version === undefined ? {} : { version: observation.version }),
        },
        evidenceIds: observation.evidenceIds,
        producer: PRODUCER,
        producerVersion: input.graph.graphVersion,
        confidence: DEFAULT_CONFIDENCE,
        coverageState: "checked",
      });
      edgeKeys.add(stableKey);
    }
  }

  const graphWithoutDependencyCoverage = validateSecurityGraph(
    {
      ...input.graph,
      nodes,
      edges,
    },
    {
      manifestPaths: input.manifest.files.map((file) => file.path),
      evidenceIds: [
        ...collectGraphEvidenceIds(input.graph),
        ...(input.observations ?? []).flatMap((observation) => observation.evidenceIds),
        ...(input.dependencyObservations ?? []).flatMap((observation) => observation.evidenceIds),
      ],
    },
  );
  const reachability = validateComponentReachability(
    componentReachability(
      graphWithoutDependencyCoverage,
      input.maxPathLength ?? DEFAULT_MAX_PATH_LENGTH,
    ),
  );
  const graph = validateSecurityGraph(
    {
      ...graphWithoutDependencyCoverage,
      coverage: withDependencyUsageCoverage(graphWithoutDependencyCoverage, reachability),
    },
    {
      manifestPaths: input.manifest.files.map((file) => file.path),
      evidenceIds: [
        ...collectGraphEvidenceIds(graphWithoutDependencyCoverage),
        ...(input.observations ?? []).flatMap((observation) => observation.evidenceIds),
        ...(input.dependencyObservations ?? []).flatMap((observation) => observation.evidenceIds),
      ],
    },
  );

  return {
    graph,
    reachability,
  };
}

function componentReachability(
  graph: SecurityGraph,
  maxPathLength: number,
): ComponentReachability[] {
  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const pathGraph = boundaryPathGraph(graph.edges);
  const starts = graph.nodes
    .filter((node) => node.kind === "Source" || node.kind === "Boundary")
    .map((node) => node.id);

  return graph.nodes
    .filter((node) => node.kind === "Component")
    .map((component) => {
      const incomingUsage = graph.edges.filter(
        (edge) =>
          edge.toNodeId === component.id && (edge.kind === "imports" || edge.kind === "uses"),
      );
      const incomingDependencies = graph.edges.filter(
        (edge) =>
          edge.toNodeId === component.id &&
          edge.kind === "depends_on" &&
          edge.producer === PRODUCER,
      );
      const usageOrDependency = [...incomingUsage, ...incomingDependencies];
      const reachableUsage = usageOrDependency
        .map((edge) => ({
          edge,
          path: firstPathTo(edge.fromNodeId, starts, pathGraph, maxPathLength),
        }))
        .find((item) => item.path !== undefined);
      const affectedUsage = reachableUsage?.edge.properties.affectedSymbol;
      const useEdge = incomingUsage.find((edge) => edge.kind === "uses");
      const importEdge = incomingUsage.find((edge) => edge.kind === "imports");
      const dependencyEdge = incomingDependencies[0];
      const level = levelFor({
        reachable: reachableUsage !== undefined,
        affectedSymbolReachable: typeof affectedUsage === "string",
        hasUse: useEdge !== undefined,
        hasImport: importEdge !== undefined,
        hasDependencyGraph: dependencyEdge !== undefined,
      });
      const pathEdgeIds =
        reachableUsage?.path === undefined
          ? useEdge?.id === undefined
            ? importEdge?.id === undefined
              ? dependencyEdge?.id === undefined
                ? []
                : [dependencyEdge.id]
              : [importEdge.id]
            : [useEdge.id]
          : [...reachableUsage.path.map((edge) => edge.id), reachableUsage.edge.id];
      const affectedSymbol = firstString(
        incomingUsage.map((edge) => edge.properties.affectedSymbol),
      );
      const version = versionFor(component, usageOrDependency);

      return {
        componentNodeId: component.id,
        packageName: packageNameFor(component),
        ...(version === undefined ? {} : { version }),
        findingIds: findingIdsFor(component, graph.edges, nodesById),
        level,
        pathEdgeIds,
        ...(affectedSymbol === undefined ? {} : { affectedSymbol }),
        affectedSymbolReachability: level === "affected_symbol_reachable" ? "reachable" : "unknown",
        evidenceIds: unique([
          ...component.evidenceIds,
          ...usageOrDependency.flatMap((edge) => edge.evidenceIds),
          ...(reachableUsage?.path ?? []).flatMap((edge) => edge.evidenceIds),
        ]),
        coverageState: "checked",
      };
    });
}

function levelFor(input: {
  readonly reachable: boolean;
  readonly affectedSymbolReachable: boolean;
  readonly hasUse: boolean;
  readonly hasImport: boolean;
  readonly hasDependencyGraph: boolean;
}): ComponentReachabilityLevel {
  if (input.affectedSymbolReachable) {
    return "affected_symbol_reachable";
  }
  if (input.reachable) {
    return "reachable_from_boundary";
  }
  if (input.hasUse) {
    return "used";
  }
  if (input.hasImport) {
    return "imported";
  }
  if (input.hasDependencyGraph) {
    return "dependency_graph_reachable";
  }
  return "present";
}

function findCodeNode(
  nodes: ReadonlyArray<SecurityGraphNode>,
  observation: ComponentUsageObservation,
): SecurityGraphNode | undefined {
  const candidates = nodes.filter(
    (node) =>
      node.kind === "CodeEntity" &&
      node.repoPath === observation.repoPath &&
      (observation.symbol === undefined ||
        node.symbol === observation.symbol ||
        node.label === observation.symbol ||
        node.properties.fullName === observation.symbol),
  );
  if (observation.symbol !== undefined) {
    return candidates.length === 1 ? candidates[0] : undefined;
  }
  const programCandidates = candidates.filter((node) => isFileLevelProgramNode(node));
  if (programCandidates.length === 1) {
    return programCandidates[0];
  }
  return candidates.length === 1 ? candidates[0] : undefined;
}

function addComponentUsageCodeNode(
  nodes: SecurityGraphNode[],
  nodeKeys: Set<string>,
  graphVersion: string,
  observation: ComponentUsageObservation,
): SecurityGraphNode {
  const stableKey = [
    "ComponentUsage",
    observation.repoPath,
    observation.lineRange?.startLine ?? 0,
    observation.packageName,
    observation.usageKind,
  ].join(":");
  const existing = nodes.find((node) => node.stableKey === stableKey);
  if (existing !== undefined) {
    return existing;
  }
  const node: SecurityGraphNode = {
    id: securityGraphNodeId(graphVersion, stableKey),
    kind: "CodeEntity",
    stableKey,
    label: `${observation.usageKind} ${observation.packageName}`,
    repoPath: observation.repoPath,
    ...(observation.lineRange === undefined ? {} : { lineRange: observation.lineRange }),
    symbol: observation.packageName,
    properties: {
      recordType: "component_usage",
      packageName: observation.packageName,
      usageKind: observation.usageKind,
      ...(observation.version === undefined ? {} : { version: observation.version }),
      ...(observation.affectedSymbol === undefined
        ? {}
        : { affectedSymbol: observation.affectedSymbol }),
    },
    evidenceIds: observation.evidenceIds,
    producer: PRODUCER,
    producerVersion: graphVersion,
    confidence: DEFAULT_CONFIDENCE,
    coverageState: "checked",
  };
  if (!nodeKeys.has(stableKey)) {
    nodes.push(node);
    nodeKeys.add(stableKey);
  }
  return node;
}

function addDependencyManifestNode(
  nodes: SecurityGraphNode[],
  nodeKeys: Set<string>,
  graphVersion: string,
  observation: ComponentDependencyObservation,
): SecurityGraphNode {
  const stableKey = [
    "DependencyManifest",
    observation.manifestPath,
    observation.sourcePackageName,
  ].join(":");
  const existing = nodes.find((node) => node.stableKey === stableKey);
  if (existing !== undefined) {
    return existing;
  }
  const node: SecurityGraphNode = {
    id: securityGraphNodeId(graphVersion, stableKey),
    kind: "CodeEntity",
    stableKey,
    label: `${observation.sourcePackageName} dependency graph`,
    repoPath: observation.manifestPath,
    lineRange: observation.lineRange ?? { startLine: 1, endLine: 1 },
    symbol: observation.sourcePackageName,
    properties: {
      recordType: "dependency_manifest",
      sourcePackageName: observation.sourcePackageName,
      manifestPath: observation.manifestPath,
    },
    evidenceIds: observation.evidenceIds,
    producer: PRODUCER,
    producerVersion: graphVersion,
    confidence: DEFAULT_CONFIDENCE,
    coverageState: "checked",
  };
  if (!nodeKeys.has(stableKey)) {
    nodes.push(node);
    nodeKeys.add(stableKey);
  }
  return node;
}

function isFileLevelProgramNode(node: SecurityGraphNode): boolean {
  return (
    node.symbol?.endsWith("::program") === true ||
    node.label === "<global>" ||
    node.label === "program" ||
    (typeof node.properties.fullName === "string" && node.properties.fullName.endsWith("::program"))
  );
}

function findComponentNodes(
  nodes: ReadonlyArray<SecurityGraphNode>,
  packageName: string,
): SecurityGraphNode[] {
  return nodes.filter(
    (node) =>
      node.kind === "Component" &&
      [node.properties.packageName, node.properties.ruleId, node.symbol, node.label].some((value) =>
        packageNamesMatch(value, packageName),
      ),
  );
}

function packageNamesMatch(candidate: unknown, observedPackageName: string): boolean {
  if (typeof candidate !== "string" || candidate.length === 0) {
    return false;
  }
  return (
    candidate === observedPackageName ||
    candidate.endsWith(`/${observedPackageName}`) ||
    observedPackageName.endsWith(`/${candidate}`)
  );
}

function boundaryPathGraph(
  edges: ReadonlyArray<SecurityGraphEdge>,
): ReadonlyMap<string, SecurityGraphEdge[]> {
  const outgoing = new Map<string, SecurityGraphEdge[]>();
  for (const edge of edges) {
    if (!["receives", "registers", "calls", "imports", "uses", "depends_on"].includes(edge.kind)) {
      continue;
    }
    const current = outgoing.get(edge.fromNodeId) ?? [];
    current.push(edge);
    outgoing.set(edge.fromNodeId, current);
  }
  return outgoing;
}

function firstPathTo(
  targetNodeId: string,
  starts: ReadonlyArray<string>,
  outgoing: ReadonlyMap<string, ReadonlyArray<SecurityGraphEdge>>,
  maxPathLength: number,
): SecurityGraphEdge[] | undefined {
  const queue: Array<{ readonly nodeId: string; readonly path: ReadonlyArray<SecurityGraphEdge> }> =
    starts.map((nodeId) => ({ nodeId, path: [] }));
  const visited = new Set<string>();

  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined || visited.has(current.nodeId)) {
      continue;
    }
    visited.add(current.nodeId);
    if (current.nodeId === targetNodeId) {
      return [...current.path];
    }
    if (current.path.length >= maxPathLength) {
      continue;
    }
    for (const edge of outgoing.get(current.nodeId) ?? []) {
      queue.push({ nodeId: edge.toNodeId, path: [...current.path, edge] });
    }
  }
  return undefined;
}

function findingIdsFor(
  component: SecurityGraphNode,
  edges: ReadonlyArray<SecurityGraphEdge>,
  nodesById: ReadonlyMap<string, SecurityGraphNode>,
): string[] {
  return unique(
    edges
      .filter((edge) => edge.kind === "affects" && edge.toNodeId === component.id)
      .flatMap((edge) => {
        const source = nodesById.get(edge.fromNodeId);
        return typeof source?.properties.findingId === "string"
          ? [source.properties.findingId]
          : [];
      }),
  );
}

function packageNameFor(component: SecurityGraphNode): string {
  return (
    firstString([component.properties.packageName, component.symbol, component.label]) ??
    component.id
  );
}

function versionFor(
  component: SecurityGraphNode,
  usageEdges: ReadonlyArray<SecurityGraphEdge>,
): string | undefined {
  return firstString([
    component.properties.version,
    ...usageEdges.map((edge) => edge.properties.version),
  ]);
}

function firstString(values: ReadonlyArray<unknown>): string | undefined {
  return values.find((value): value is string => typeof value === "string" && value.length > 0);
}

function collectGraphEvidenceIds(graph: SecurityGraph): string[] {
  return unique([
    ...graph.nodes.flatMap((node) => node.evidenceIds),
    ...graph.edges.flatMap((edge) => edge.evidenceIds),
    ...graph.flows.flatMap((flow) => flow.evidenceIds),
  ]);
}

function withDependencyUsageCoverage(
  graph: SecurityGraph,
  reachability: ReadonlyArray<ComponentReachability>,
): SecurityGraph["coverage"] {
  const producer = PRODUCER;
  const components = graph.nodes.filter((node) => node.kind === "Component");
  const observed = reachability.filter((record) => record.level !== "present");
  const coverage = {
    area: "dependency_usage" as const,
    state: "checked" as const,
    coveredCount: observed.length,
    totalCount: components.length,
    producer,
    producerVersion: graph.graphVersion,
  };
  return [
    ...graph.coverage.filter(
      (entry) => !(entry.area === coverage.area && entry.producer === coverage.producer),
    ),
    coverage,
  ];
}

function unique(values: ReadonlyArray<string>): string[] {
  return [...new Set(values)];
}
