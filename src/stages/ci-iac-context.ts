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

export interface CiWorkflowObservation {
  readonly workflowPath: string;
  readonly name: string;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly lineRange?: LineRange;
  readonly findingIds?: ReadonlyArray<string>;
  readonly triggers?: ReadonlyArray<CiTriggerObservation>;
  readonly steps?: ReadonlyArray<CiStepObservation>;
  readonly tokenPermissions?: ReadonlyArray<CiTokenPermissionObservation>;
  readonly artifacts?: ReadonlyArray<CiArtifactObservation>;
}

export interface CiTriggerObservation {
  readonly event: string;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly lineRange?: LineRange;
}

export interface CiStepObservation {
  readonly id: string;
  readonly name: string;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly lineRange?: LineRange;
  readonly uses?: string;
  readonly run?: string;
  readonly pinned?: boolean;
  readonly findingIds?: ReadonlyArray<string>;
}

export interface CiTokenPermissionObservation {
  readonly scope: string;
  readonly access: "none" | "read" | "write";
  readonly evidenceIds: ReadonlyArray<string>;
  readonly lineRange?: LineRange;
  readonly stepId?: string;
}

export interface CiArtifactObservation {
  readonly name: string;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly lineRange?: LineRange;
  readonly stepId?: string;
  readonly path?: string;
}

export interface IacResourceObservation {
  readonly repoPath: string;
  readonly resourceType: string;
  readonly name: string;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly lineRange?: LineRange;
  readonly public?: boolean;
  readonly findingIds?: ReadonlyArray<string>;
}

export interface ComposeCiIacContextInput {
  readonly graph: SecurityGraph;
  readonly manifest: Manifest;
  readonly workflows?: ReadonlyArray<CiWorkflowObservation>;
  readonly iacResources?: ReadonlyArray<IacResourceObservation>;
}

interface GraphBuilder {
  readonly nodes: SecurityGraphNode[];
  readonly edges: SecurityGraphEdge[];
  readonly nodesByStableKey: Map<string, SecurityGraphNode>;
  readonly edgesByStableKey: Map<string, SecurityGraphEdge>;
}

const PRODUCER = "ci-iac-context";
const DEFAULT_CONFIDENCE = 0.9;

export function composeCiIacContext(input: ComposeCiIacContextInput): SecurityGraph {
  const builder = graphBuilder(input.graph);

  for (const workflow of input.workflows ?? []) {
    assertEvidence(workflow.evidenceIds, `workflow ${workflow.workflowPath}`);
    addWorkflow(builder, input.graph.graphVersion, workflow);
  }

  for (const resource of input.iacResources ?? []) {
    assertEvidence(resource.evidenceIds, `IaC resource ${resource.name}`);
    addIacResource(builder, input.graph.graphVersion, resource);
  }

  return validateSecurityGraph(
    {
      ...input.graph,
      nodes: builder.nodes,
      edges: builder.edges,
      coverage: withCiIacCoverage(input.graph, input.workflows ?? [], input.iacResources ?? []),
    },
    {
      manifestPaths: input.manifest.files.map((file) => file.path),
      evidenceIds: [
        ...collectGraphEvidenceIds(input.graph),
        ...collectObservationEvidenceIds(input.workflows ?? [], input.iacResources ?? []),
      ],
    },
  );
}

function graphBuilder(graph: SecurityGraph): GraphBuilder {
  return {
    nodes: [...graph.nodes],
    edges: [...graph.edges],
    nodesByStableKey: new Map(graph.nodes.map((node) => [node.stableKey, node])),
    edgesByStableKey: new Map(graph.edges.map((edge) => [edge.stableKey, edge])),
  };
}

function addWorkflow(
  builder: GraphBuilder,
  graphVersion: string,
  workflow: CiWorkflowObservation,
): void {
  const workflowNode = addNode(builder, graphVersion, {
    kind: "BuildStep",
    stableKey: `CIWorkflow:${workflow.workflowPath}:${workflow.name}`,
    label: workflow.name,
    repoPath: workflow.workflowPath,
    ...(workflow.lineRange === undefined ? {} : { lineRange: workflow.lineRange }),
    symbol: workflow.name,
    properties: {
      recordType: "workflow",
      workflowPath: workflow.workflowPath,
      name: workflow.name,
    },
    evidenceIds: workflow.evidenceIds,
  });
  addFindingSupport(
    builder,
    graphVersion,
    workflow.findingIds ?? [],
    workflowNode,
    workflow.evidenceIds,
  );

  const stepNodes = new Map<string, SecurityGraphNode>();
  for (const trigger of workflow.triggers ?? []) {
    assertEvidence(trigger.evidenceIds, `workflow trigger ${trigger.event}`);
    const triggerNode = addNode(builder, graphVersion, {
      kind: "BuildStep",
      stableKey: `CITrigger:${workflow.workflowPath}:${trigger.event}`,
      label: trigger.event,
      repoPath: workflow.workflowPath,
      ...(trigger.lineRange === undefined ? {} : { lineRange: trigger.lineRange }),
      symbol: trigger.event,
      properties: {
        recordType: "workflow_trigger",
        event: trigger.event,
      },
      evidenceIds: trigger.evidenceIds,
    });
    addEdge(builder, graphVersion, "contains", workflowNode, triggerNode, {}, trigger.evidenceIds);
  }

  for (const step of workflow.steps ?? []) {
    assertEvidence(step.evidenceIds, `workflow step ${step.id}`);
    const stepNode = addNode(builder, graphVersion, {
      kind: "BuildStep",
      stableKey: `CIStep:${workflow.workflowPath}:${step.id}`,
      label: step.name,
      repoPath: workflow.workflowPath,
      ...(step.lineRange === undefined ? {} : { lineRange: step.lineRange }),
      symbol: step.id,
      properties: {
        recordType: "workflow_step",
        stepId: step.id,
        name: step.name,
        ...(step.uses === undefined ? {} : { uses: step.uses }),
        ...(step.run === undefined ? {} : { run: step.run }),
        ...(step.pinned === undefined ? {} : { pinned: step.pinned }),
      },
      evidenceIds: step.evidenceIds,
    });
    stepNodes.set(step.id, stepNode);
    addEdge(builder, graphVersion, "contains", workflowNode, stepNode, {}, step.evidenceIds);
    addFindingSupport(builder, graphVersion, step.findingIds ?? [], stepNode, step.evidenceIds);
  }

  for (const token of workflow.tokenPermissions ?? []) {
    assertEvidence(token.evidenceIds, `workflow token ${token.scope}`);
    const tokenNode = addNode(builder, graphVersion, {
      kind: "Resource",
      stableKey: `CIToken:${workflow.workflowPath}:${token.stepId ?? "workflow"}:${token.scope}:${token.access}`,
      label: `${token.scope}:${token.access}`,
      repoPath: workflow.workflowPath,
      ...(token.lineRange === undefined ? {} : { lineRange: token.lineRange }),
      symbol: token.scope,
      properties: {
        resourceType: "token_permission",
        scope: token.scope,
        access: token.access,
      },
      evidenceIds: token.evidenceIds,
    });
    const owner =
      token.stepId === undefined
        ? workflowNode
        : requiredStepNode(stepNodes, token.stepId, `workflow token ${token.scope}`);
    addEdge(builder, graphVersion, "depends_on", owner, tokenNode, {}, token.evidenceIds);
  }

  for (const artifact of workflow.artifacts ?? []) {
    assertEvidence(artifact.evidenceIds, `workflow artifact ${artifact.name}`);
    const artifactNode = addNode(builder, graphVersion, {
      kind: "Resource",
      stableKey: `CIArtifact:${workflow.workflowPath}:${artifact.stepId ?? "workflow"}:${artifact.name}`,
      label: artifact.name,
      repoPath: workflow.workflowPath,
      ...(artifact.lineRange === undefined ? {} : { lineRange: artifact.lineRange }),
      symbol: artifact.name,
      properties: {
        resourceType: "artifact",
        name: artifact.name,
        ...(artifact.path === undefined ? {} : { path: artifact.path }),
      },
      evidenceIds: artifact.evidenceIds,
    });
    const owner =
      artifact.stepId === undefined
        ? workflowNode
        : requiredStepNode(stepNodes, artifact.stepId, `workflow artifact ${artifact.name}`);
    addEdge(builder, graphVersion, "writes", owner, artifactNode, {}, artifact.evidenceIds);
  }
}

function requiredStepNode(
  stepNodes: ReadonlyMap<string, SecurityGraphNode>,
  stepId: string,
  label: string,
): SecurityGraphNode {
  const node = stepNodes.get(stepId);
  if (node === undefined) {
    throw new Error(`${label} references missing workflow step: ${stepId}`);
  }
  return node;
}

function addIacResource(
  builder: GraphBuilder,
  graphVersion: string,
  resource: IacResourceObservation,
): void {
  const resourceNode = addNode(builder, graphVersion, {
    kind: "InfraResource",
    stableKey: `IaCResource:${resource.repoPath}:${resource.resourceType}:${resource.name}`,
    label: resource.name,
    repoPath: resource.repoPath,
    ...(resource.lineRange === undefined ? {} : { lineRange: resource.lineRange }),
    symbol: resource.name,
    properties: {
      resourceType: resource.resourceType,
      name: resource.name,
      public: resource.public === true,
    },
    evidenceIds: resource.evidenceIds,
  });
  addFindingSupport(
    builder,
    graphVersion,
    resource.findingIds ?? [],
    resourceNode,
    resource.evidenceIds,
  );

  if (resource.public === true) {
    const publicNode = addNode(builder, graphVersion, {
      kind: "ExternalService",
      stableKey: "ExternalService:public-internet",
      label: "public internet",
      symbol: "public-internet",
      properties: {
        serviceType: "public_internet",
      },
      evidenceIds: resource.evidenceIds,
    });
    addEdge(builder, graphVersion, "exposes", resourceNode, publicNode, {}, resource.evidenceIds);
  }
}

function addFindingSupport(
  builder: GraphBuilder,
  graphVersion: string,
  findingIds: ReadonlyArray<string>,
  target: SecurityGraphNode,
  evidenceIds: ReadonlyArray<string>,
): void {
  for (const findingId of findingIds) {
    const finding = builder.nodes.find(
      (node) => node.kind === "Finding" && node.properties.findingId === findingId,
    );
    if (finding === undefined) {
      throw new Error(`CI/IaC context references missing finding: ${findingId}`);
    }
    addEdge(builder, graphVersion, "supported_by", finding, target, { findingId }, evidenceIds);
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
    producerVersion: graphVersion,
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
  kind: SecurityGraphEdge["kind"],
  from: SecurityGraphNode,
  to: SecurityGraphNode,
  properties: Readonly<Record<string, unknown>>,
  evidenceIds: ReadonlyArray<string>,
): SecurityGraphEdge {
  const stableKey = `${kind}:${from.id}:${to.id}`;
  const existing = builder.edgesByStableKey.get(stableKey);
  if (existing !== undefined) {
    return existing;
  }
  const edge: SecurityGraphEdge = {
    id: securityGraphEdgeId(graphVersion, stableKey),
    kind,
    stableKey,
    fromNodeId: from.id,
    toNodeId: to.id,
    properties,
    evidenceIds,
    producer: PRODUCER,
    producerVersion: graphVersion,
    confidence: DEFAULT_CONFIDENCE,
    coverageState: "checked",
  };
  builder.edges.push(edge);
  builder.edgesByStableKey.set(edge.stableKey, edge);
  return edge;
}

function assertEvidence(evidenceIds: ReadonlyArray<string>, label: string): void {
  if (evidenceIds.length === 0) {
    throw new Error(`${label} has no evidence`);
  }
}

function collectObservationEvidenceIds(
  workflows: ReadonlyArray<CiWorkflowObservation>,
  resources: ReadonlyArray<IacResourceObservation>,
): string[] {
  return unique([
    ...workflows.flatMap((workflow) => [
      ...workflow.evidenceIds,
      ...(workflow.triggers ?? []).flatMap((trigger) => trigger.evidenceIds),
      ...(workflow.steps ?? []).flatMap((step) => step.evidenceIds),
      ...(workflow.tokenPermissions ?? []).flatMap((token) => token.evidenceIds),
      ...(workflow.artifacts ?? []).flatMap((artifact) => artifact.evidenceIds),
    ]),
    ...resources.flatMap((resource) => resource.evidenceIds),
  ]);
}

function collectGraphEvidenceIds(graph: SecurityGraph): string[] {
  return unique([
    ...graph.nodes.flatMap((node) => node.evidenceIds),
    ...graph.edges.flatMap((edge) => edge.evidenceIds),
    ...graph.flows.flatMap((flow) => flow.evidenceIds),
  ]);
}

function withCiIacCoverage(
  graph: SecurityGraph,
  workflows: ReadonlyArray<CiWorkflowObservation>,
  resources: ReadonlyArray<IacResourceObservation>,
): SecurityGraph["coverage"] {
  const coverage = {
    area: "ci_iac" as const,
    state: "checked" as const,
    coveredCount: workflows.length + resources.length,
    totalCount: workflows.length + resources.length,
    producer: PRODUCER,
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
