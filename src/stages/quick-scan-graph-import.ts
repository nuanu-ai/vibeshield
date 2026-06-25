import type { Evidence } from "../domain/evidence.js";
import type { Finding, FindingCluster } from "../domain/finding.js";
import type { Manifest } from "../domain/manifest.js";
import type { RunId } from "../domain/run.js";
import type {
  LineRange,
  SecurityFlow,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../domain/security-graph.js";
import {
  securityGraphEdgeId,
  securityGraphId,
  securityGraphNodeId,
  validateSecurityGraph,
} from "../domain/security-graph.js";

export interface ComposeQuickScanGraphInput {
  readonly runId: RunId;
  readonly snapshotId: string;
  readonly graphVersion: string;
  readonly manifest: Manifest;
  readonly evidence: ReadonlyArray<Evidence>;
  readonly findings: ReadonlyArray<Finding>;
  readonly clusters?: ReadonlyArray<FindingCluster>;
  readonly createdAt: string;
  readonly baseGraph?: SecurityGraph;
}

interface GraphBuilder {
  readonly nodes: SecurityGraphNode[];
  readonly edges: SecurityGraphEdge[];
  readonly flows: SecurityFlow[];
  readonly nodesByStableKey: Map<string, SecurityGraphNode>;
  readonly edgesByStableKey: Map<string, SecurityGraphEdge>;
}

const PRODUCER = "quick-scan";
const DEFAULT_CONFIDENCE = 1;

export function composeQuickScanGraph(input: ComposeQuickScanGraphInput): SecurityGraph {
  const manifestPaths = new Set(input.manifest.files.map((file) => file.path));
  const evidenceIds = new Set(input.evidence.map((item) => item.id));
  const builder = graphBuilder(input.baseGraph);

  if (input.baseGraph !== undefined) {
    assertBaseGraph(input);
    collectBaseEvidenceIds(input.baseGraph, evidenceIds);
  }

  const findingNodes = new Map<string, SecurityGraphNode>();
  for (const finding of input.findings) {
    const findingNode = addFindingNode(builder, input.graphVersion, finding);
    findingNodes.set(finding.id, findingNode);
    addLocationNodes(builder, input.graphVersion, finding, findingNode);
    const subject = addSubjectNode(builder, input.graphVersion, finding);
    addEdge(builder, input.graphVersion, {
      kind: "affects",
      stableKey: `affects:${findingNode.id}:${subject.id}`,
      fromNodeId: findingNode.id,
      toNodeId: subject.id,
      properties: {
        findingId: finding.id,
        category: finding.category,
      },
      evidenceIds: finding.evidenceIds,
      producerVersion: input.graphVersion,
    });
  }

  for (const cluster of input.clusters ?? []) {
    addCluster(builder, input.graphVersion, cluster, findingNodes, input.findings);
  }

  const graph: SecurityGraph = {
    id: input.baseGraph?.id ?? securityGraphId(input.snapshotId, input.graphVersion),
    runId: input.runId,
    snapshotId: input.snapshotId,
    graphVersion: input.graphVersion,
    nodes: builder.nodes,
    edges: builder.edges,
    flows: builder.flows,
    coverage: input.baseGraph?.coverage ?? [],
    createdAt: input.createdAt,
  };

  return validateSecurityGraph(graph, { manifestPaths, evidenceIds });
}

function graphBuilder(baseGraph: SecurityGraph | undefined): GraphBuilder {
  const nodes = [...(baseGraph?.nodes ?? [])];
  const edges = [...(baseGraph?.edges ?? [])];
  return {
    nodes,
    edges,
    flows: [...(baseGraph?.flows ?? [])],
    nodesByStableKey: new Map(nodes.map((node) => [node.stableKey, node])),
    edgesByStableKey: new Map(edges.map((edge) => [edge.stableKey, edge])),
  };
}

function assertBaseGraph(input: ComposeQuickScanGraphInput): void {
  const base = input.baseGraph;
  if (base === undefined) {
    return;
  }
  if (base.runId !== input.runId) {
    throw new Error(`base graph runId mismatch: ${base.runId}`);
  }
  if (base.snapshotId !== input.snapshotId) {
    throw new Error(`base graph snapshotId mismatch: ${base.snapshotId}`);
  }
  if (base.graphVersion !== input.graphVersion) {
    throw new Error(`base graph graphVersion mismatch: ${base.graphVersion}`);
  }
}

function addFindingNode(
  builder: GraphBuilder,
  graphVersion: string,
  finding: Finding,
): SecurityGraphNode {
  const location = finding.locations[0];
  return addNode(builder, graphVersion, {
    kind: "Finding",
    stableKey: `QuickScanFinding:${finding.id}`,
    label: `${finding.category}:${finding.ruleId}`,
    ...(location === undefined
      ? {}
      : {
          repoPath: location.filePath,
          lineRange: { startLine: location.startLine, endLine: location.endLine },
        }),
    symbol: finding.id,
    properties: {
      recordType: "finding",
      findingId: finding.id,
      sourceTool: finding.sourceTool,
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      fingerprint: finding.fingerprint,
      ...(finding.remediationKey === undefined ? {} : { remediationKey: finding.remediationKey }),
    },
    evidenceIds: finding.evidenceIds,
    producerVersion: graphVersion,
  });
}

function addLocationNodes(
  builder: GraphBuilder,
  graphVersion: string,
  finding: Finding,
  findingNode: SecurityGraphNode,
): void {
  for (const location of finding.locations) {
    const fileNode = addNode(builder, graphVersion, {
      kind: "Resource",
      stableKey: `QuickScanFile:${location.filePath}`,
      label: location.filePath,
      repoPath: location.filePath,
      symbol: location.filePath,
      properties: {
        resourceType: "file",
        filePath: location.filePath,
      },
      evidenceIds: finding.evidenceIds,
      producerVersion: graphVersion,
    });
    addEdge(builder, graphVersion, {
      kind: "located_in",
      stableKey: `located_in:${findingNode.id}:${fileNode.id}:${location.startLine}:${location.endLine}`,
      fromNodeId: findingNode.id,
      toNodeId: fileNode.id,
      properties: {
        filePath: location.filePath,
        startLine: location.startLine,
        endLine: location.endLine,
      },
      evidenceIds: finding.evidenceIds,
      producerVersion: graphVersion,
    });
  }
}

function addSubjectNode(
  builder: GraphBuilder,
  graphVersion: string,
  finding: Finding,
): SecurityGraphNode {
  const location = finding.locations[0];
  const subject = subjectFor(finding);
  const metadata = componentMetadataFor(finding);
  return addNode(builder, graphVersion, {
    kind: subject.kind,
    stableKey: `QuickScanSubject:${finding.category}:${finding.id}`,
    label: subject.label,
    ...(location === undefined
      ? {}
      : {
          repoPath: location.filePath,
          lineRange: { startLine: location.startLine, endLine: location.endLine },
        }),
    symbol: subject.symbol,
    properties: {
      recordType: subject.recordType,
      findingId: finding.id,
      category: finding.category,
      sourceTool: finding.sourceTool,
      ruleId: finding.ruleId,
      ...metadata,
    },
    evidenceIds: finding.evidenceIds,
    producerVersion: graphVersion,
  });
}

function subjectFor(finding: Finding): {
  readonly kind: SecurityGraphNode["kind"];
  readonly recordType: string;
  readonly label: string;
  readonly symbol: string;
} {
  switch (finding.category) {
    case "secret":
      return {
        kind: "Secret",
        recordType: "secret",
        label: finding.ruleId,
        symbol: finding.ruleId,
      };
    case "dependency":
    case "sbom":
      return {
        kind: "Component",
        recordType: "component",
        label: componentPackageName(finding) ?? finding.ruleId,
        symbol: componentPackageName(finding) ?? finding.ruleId,
      };
    case "github-action":
      return {
        kind: "BuildStep",
        recordType: "build_step",
        label: finding.ruleId,
        symbol: finding.ruleId,
      };
    case "iac":
      return {
        kind: "InfraResource",
        recordType: "infra_resource",
        label: finding.ruleId,
        symbol: finding.ruleId,
      };
    case "code-pattern":
      return {
        kind: "CodeEntity",
        recordType: "code_pattern",
        label: finding.ruleId,
        symbol: finding.ruleId,
      };
  }
}

function componentMetadataFor(finding: Finding): Readonly<Record<string, string>> {
  if (finding.category !== "dependency" && finding.category !== "sbom") {
    return {};
  }
  const metadata: Record<string, string> = {};
  const packageName = componentPackageName(finding);
  if (packageName !== undefined) {
    metadata.packageName = packageName;
  }
  if (finding.metadata?.installedVersion !== undefined) {
    metadata.version = finding.metadata.installedVersion;
  }
  if (finding.metadata?.fixedVersion !== undefined) {
    metadata.fixedVersion = finding.metadata.fixedVersion;
  }
  return metadata;
}

function componentPackageName(finding: Finding): string | undefined {
  const packageName = finding.metadata?.packageName;
  return packageName === undefined || packageName.trim() === "" ? undefined : packageName;
}

function addCluster(
  builder: GraphBuilder,
  graphVersion: string,
  cluster: FindingCluster,
  findingNodes: ReadonlyMap<string, SecurityGraphNode>,
  findings: ReadonlyArray<Finding>,
): void {
  const evidenceIds = unique(
    cluster.findingIds.flatMap((findingId) => {
      const finding = findings.find((item) => item.id === findingId);
      return finding?.evidenceIds ?? [];
    }),
  );
  const clusterNode = addNode(builder, graphVersion, {
    kind: "Finding",
    stableKey: `QuickScanFindingCluster:${cluster.id}`,
    label: `${cluster.category} cluster`,
    symbol: cluster.id,
    properties: {
      recordType: "finding_cluster",
      clusterId: cluster.id,
      category: cluster.category,
      findingIds: cluster.findingIds,
      maxSeverity: cluster.maxSeverity,
    },
    evidenceIds,
    producerVersion: graphVersion,
  });

  for (const findingId of cluster.findingIds) {
    const findingNode = findingNodes.get(findingId);
    if (findingNode === undefined) {
      throw new Error(`finding cluster ${cluster.id} references missing finding: ${findingId}`);
    }
    const memberEvidenceIds =
      findings.find((finding) => finding.id === findingId)?.evidenceIds ?? [];
    addEdge(builder, graphVersion, {
      kind: "supported_by",
      stableKey: `supported_by:${clusterNode.id}:${findingNode.id}`,
      fromNodeId: clusterNode.id,
      toNodeId: findingNode.id,
      properties: {
        clusterId: cluster.id,
        findingId,
      },
      evidenceIds: memberEvidenceIds,
      producerVersion: graphVersion,
    });
  }
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

function collectBaseEvidenceIds(graph: SecurityGraph, evidenceIds: Set<string>): void {
  for (const node of graph.nodes) {
    for (const evidenceId of node.evidenceIds) {
      evidenceIds.add(evidenceId);
    }
  }
  for (const edge of graph.edges) {
    for (const evidenceId of edge.evidenceIds) {
      evidenceIds.add(evidenceId);
    }
  }
  for (const flow of graph.flows) {
    for (const evidenceId of flow.evidenceIds) {
      evidenceIds.add(evidenceId);
    }
  }
}

function unique(values: ReadonlyArray<string>): string[] {
  return [...new Set(values)];
}
