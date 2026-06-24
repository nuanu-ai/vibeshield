import {
  type ComponentReachability,
  validateComponentReachability,
} from "../domain/component-reachability.js";
import type { Finding } from "../domain/finding.js";
import type {
  FindingContextAssessment,
  FindingContextStatus,
} from "../domain/finding-context-assessment.js";
import { validateFindingContextAssessments } from "../domain/finding-context-assessment.js";
import type {
  GraphCoverageState,
  SecurityFlow,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../domain/security-graph.js";

export interface FindingHypothesisLink {
  readonly findingId: string;
  readonly hypothesisId: string;
  readonly reason?: string;
  readonly graphNodeIds?: ReadonlyArray<string>;
  readonly graphEdgeIds?: ReadonlyArray<string>;
}

export interface AssessFindingContextInput {
  readonly findings: ReadonlyArray<Finding>;
  readonly graph: SecurityGraph;
  readonly componentReachability?: ReadonlyArray<ComponentReachability>;
  readonly hypothesisLinks?: ReadonlyArray<FindingHypothesisLink>;
}

interface FindingContextFacts {
  readonly finding: Finding;
  readonly findingNode: SecurityGraphNode;
  readonly contradiction: GraphContext | undefined;
  readonly hypothesis: HypothesisContext | undefined;
  readonly corroboration: GraphContext | undefined;
  readonly weakening: GraphContext | undefined;
}

interface GraphContext {
  readonly graphNodeIds: ReadonlyArray<string>;
  readonly graphEdgeIds: ReadonlyArray<string>;
  readonly coverageStates: ReadonlyArray<GraphCoverageState>;
  readonly reason: string;
}

interface HypothesisContext {
  readonly hypothesisIds: ReadonlyArray<string>;
  readonly graphNodeIds: ReadonlyArray<string>;
  readonly graphEdgeIds: ReadonlyArray<string>;
  readonly reason: string;
}

const CORROBORATING_COMPONENT_LEVELS = new Set<ComponentReachability["level"]>([
  "imported",
  "used",
  "reachable_from_boundary",
  "affected_symbol_reachable",
]);

export function assessFindingContext(input: AssessFindingContextInput): FindingContextAssessment[] {
  assertUniqueInputFindings(input.findings);
  const nodesById = new Map(input.graph.nodes.map((node) => [node.id, node]));
  const edgesById = new Map(input.graph.edges.map((edge) => [edge.id, edge]));
  const graphNodeIds = new Set(nodesById.keys());
  const graphEdgeIds = new Set(edgesById.keys());
  const hypothesisIds = new Set((input.hypothesisLinks ?? []).map((link) => link.hypothesisId));
  const findingIds = new Set(input.findings.map((finding) => finding.id));
  const findingNodes = findingNodeMap(input.graph.nodes);
  const hypothesisLinks = hypothesisLinkMap(input.hypothesisLinks ?? [], findingIds, input.graph);
  const componentReachability = componentReachabilityMap(
    validateComponentReachability(input.componentReachability ?? []),
    input.graph,
    findingIds,
  );

  const records = input.findings.map((finding) => {
    const findingNode = findingNodes.get(finding.id);
    if (findingNode === undefined) {
      throw new Error(`finding context missing graph finding node: ${finding.id}`);
    }
    return assessmentFor({
      finding,
      findingNode,
      contradiction: contradictionFor(input.graph, findingNode.id),
      hypothesis: hypothesisFor(hypothesisLinks.get(finding.id) ?? []),
      corroboration: corroborationFor(input.graph, componentReachability.get(finding.id) ?? [], {
        findingNode,
      }),
      weakening: weakeningFor(input.graph, componentReachability.get(finding.id) ?? [], {
        findingNode,
      }),
    });
  });

  return validateFindingContextAssessments(records, {
    findingIds,
    graphNodeIds,
    graphEdgeIds,
    hypothesisIds,
  });
}

function assessmentFor(facts: FindingContextFacts): FindingContextAssessment {
  const status = statusFor(facts);
  switch (status) {
    case "contradicted":
      return graphAssessment(facts.finding.id, status, facts.contradiction);
    case "linked_to_hypothesis":
      return {
        findingId: facts.finding.id,
        status,
        graphNodeIds: facts.hypothesis?.graphNodeIds ?? [],
        graphEdgeIds: facts.hypothesis?.graphEdgeIds ?? [],
        hypothesisIds: facts.hypothesis?.hypothesisIds ?? [],
        reason: facts.hypothesis?.reason ?? "linked to deterministic hypothesis context",
        coverageState: "checked",
      };
    case "corroborated":
      return graphAssessment(facts.finding.id, status, facts.corroboration);
    case "weakened":
      return graphAssessment(facts.finding.id, status, facts.weakening);
    case "standalone":
      return {
        findingId: facts.finding.id,
        status,
        graphNodeIds: [],
        graphEdgeIds: [],
        hypothesisIds: [],
        reason: "no qualifying graph, reachability, or hypothesis context found",
        coverageState: "checked",
      };
  }
}

function graphAssessment(
  findingId: string,
  status: Exclude<FindingContextStatus, "standalone" | "linked_to_hypothesis">,
  context: GraphContext | undefined,
): FindingContextAssessment {
  return {
    findingId,
    status,
    graphNodeIds: context?.graphNodeIds ?? [],
    graphEdgeIds: context?.graphEdgeIds ?? [],
    hypothesisIds: [],
    reason: context?.reason ?? `${status} by graph context`,
    coverageState: strongestCoverageState(context?.coverageStates ?? ["checked"]),
  };
}

function statusFor(facts: FindingContextFacts): FindingContextStatus {
  if (facts.contradiction !== undefined) {
    return "contradicted";
  }
  if (facts.hypothesis !== undefined) {
    return "linked_to_hypothesis";
  }
  if (facts.corroboration !== undefined) {
    return "corroborated";
  }
  if (facts.weakening !== undefined) {
    return "weakened";
  }
  return "standalone";
}

function findingNodeMap(nodes: ReadonlyArray<SecurityGraphNode>): Map<string, SecurityGraphNode> {
  const out = new Map<string, SecurityGraphNode>();
  for (const node of nodes) {
    if (node.kind !== "Finding" || typeof node.properties.findingId !== "string") {
      continue;
    }
    if (node.properties.recordType !== "finding") {
      continue;
    }
    if (out.has(node.properties.findingId)) {
      throw new Error(
        `finding context graph has duplicate finding node: ${node.properties.findingId}`,
      );
    }
    out.set(node.properties.findingId, node);
  }
  return out;
}

function subjectNodeIdsFor(
  edges: ReadonlyArray<SecurityGraphEdge>,
  findingNodeId: string,
): ReadonlySet<string> {
  return new Set(
    edges
      .filter((edge) => edge.kind === "affects" && edge.fromNodeId === findingNodeId)
      .map((edge) => edge.toNodeId),
  );
}

function contradictionFor(graph: SecurityGraph, findingNodeId: string): GraphContext | undefined {
  const subjectNodeIds = subjectNodeIdsFor(graph.edges, findingNodeId);
  const roots = new Set([findingNodeId, ...subjectNodeIds]);
  const contradictionEdges = graph.edges.filter(
    (edge) =>
      edge.kind === "contradicted_by" && (roots.has(edge.fromNodeId) || roots.has(edge.toNodeId)),
  );
  if (contradictionEdges.length === 0) {
    return undefined;
  }
  return {
    graphNodeIds: endpointNodeIds(contradictionEdges),
    graphEdgeIds: contradictionEdges.map((edge) => edge.id),
    coverageStates: contradictionEdges.map((edge) => edge.coverageState),
    reason: "explicit graph contradiction is attached to the finding context",
  };
}

function corroborationFor(
  graph: SecurityGraph,
  reachability: ReadonlyArray<ComponentReachability>,
  input: {
    readonly findingNode: SecurityGraphNode;
  },
): GraphContext | undefined {
  const supported = supportedContextFor(graph, input.findingNode.id);
  if (supported !== undefined) {
    return supported;
  }

  const flow = flowContextFor(graph, input.findingNode.id);
  if (flow !== undefined) {
    return flow;
  }

  const component = componentReachabilityContextFor(reachability, "corroborated");
  if (component !== undefined) {
    return component;
  }

  return undefined;
}

function weakeningFor(
  graph: SecurityGraph,
  reachability: ReadonlyArray<ComponentReachability>,
  input: { readonly findingNode: SecurityGraphNode },
): GraphContext | undefined {
  const component = componentReachabilityContextFor(reachability, "weakened");
  if (component !== undefined) {
    return component;
  }

  return protectedContextFor(graph, input.findingNode.id);
}

function supportedContextFor(
  graph: SecurityGraph,
  findingNodeId: string,
): GraphContext | undefined {
  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const edges = graph.edges.filter((edge) => {
    const target = nodesById.get(edge.toNodeId);
    return (
      edge.kind === "supported_by" &&
      edge.fromNodeId === findingNodeId &&
      target !== undefined &&
      target.kind !== "Finding"
    );
  });
  if (edges.length === 0) {
    return undefined;
  }
  return {
    graphNodeIds: endpointNodeIds(edges),
    graphEdgeIds: edges.map((edge) => edge.id),
    coverageStates: edges.map((edge) => edge.coverageState),
    reason: "finding is supported by explicit graph context",
  };
}

function flowContextFor(graph: SecurityGraph, findingNodeId: string): GraphContext | undefined {
  const subjectNodeIds = subjectNodeIdsFor(graph.edges, findingNodeId);
  if (subjectNodeIds.size === 0) {
    return undefined;
  }
  const edgesById = new Map(graph.edges.map((edge) => [edge.id, edge]));
  for (const flow of graph.flows) {
    if (flow.coverageState !== "checked") {
      continue;
    }
    const pathEdges = flow.pathEdgeIds.flatMap((edgeId) => {
      const edge = edgesById.get(edgeId);
      return edge === undefined ? [] : [edge];
    });
    if (!flowTouchesSubjects(flow, pathEdges, subjectNodeIds)) {
      continue;
    }
    return {
      graphNodeIds: uniqueSorted([
        ...subjectNodeIds,
        flow.sourceNodeId,
        flow.sinkNodeId,
        ...flow.controlNodeIds,
      ]),
      graphEdgeIds: uniqueSorted(pathEdges.map((edge) => edge.id)),
      coverageStates: [flow.coverageState, ...pathEdges.map((edge) => edge.coverageState)],
      reason: "finding subject appears on a checked security-flow path",
    };
  }
  return undefined;
}

function flowTouchesSubjects(
  flow: SecurityFlow,
  pathEdges: ReadonlyArray<SecurityGraphEdge>,
  subjectNodeIds: ReadonlySet<string>,
): boolean {
  if (
    subjectNodeIds.has(flow.sourceNodeId) ||
    subjectNodeIds.has(flow.sinkNodeId) ||
    flow.controlNodeIds.some((nodeId) => subjectNodeIds.has(nodeId))
  ) {
    return true;
  }
  return pathEdges.some(
    (edge) => subjectNodeIds.has(edge.fromNodeId) || subjectNodeIds.has(edge.toNodeId),
  );
}

function componentReachabilityContextFor(
  reachability: ReadonlyArray<ComponentReachability>,
  mode: "corroborated" | "weakened",
): GraphContext | undefined {
  const matching =
    mode === "corroborated"
      ? reachability.filter((record) => CORROBORATING_COMPONENT_LEVELS.has(record.level))
      : reachability.filter(
          (record) => record.level === "present" && record.coverageState === "checked",
        );
  if (matching.length === 0) {
    return undefined;
  }
  return {
    graphNodeIds: uniqueSorted(matching.map((record) => record.componentNodeId)),
    graphEdgeIds: uniqueSorted(matching.flatMap((record) => record.pathEdgeIds)),
    coverageStates: matching.map((record) => record.coverageState),
    reason:
      mode === "corroborated"
        ? "component reachability corroborates the dependency finding"
        : "component is present but no import, use, or boundary reachability was observed",
  };
}

function protectedContextFor(
  graph: SecurityGraph,
  findingNodeId: string,
): GraphContext | undefined {
  const subjectNodeIds = subjectNodeIdsFor(graph.edges, findingNodeId);
  const roots = new Set([findingNodeId, ...subjectNodeIds]);
  const edges = graph.edges.filter(
    (edge) =>
      edge.kind === "protected_by" && (roots.has(edge.fromNodeId) || roots.has(edge.toNodeId)),
  );
  if (edges.length === 0) {
    return undefined;
  }
  return {
    graphNodeIds: endpointNodeIds(edges),
    graphEdgeIds: edges.map((edge) => edge.id),
    coverageStates: edges.map((edge) => edge.coverageState),
    reason: "finding subject has explicit protective-control context",
  };
}

function hypothesisLinkMap(
  links: ReadonlyArray<FindingHypothesisLink>,
  findingIds: ReadonlySet<string>,
  graph: SecurityGraph,
): Map<string, FindingHypothesisLink[]> {
  const graphNodeIds = new Set(graph.nodes.map((node) => node.id));
  const graphEdgeIds = new Set(graph.edges.map((edge) => edge.id));
  const out = new Map<string, FindingHypothesisLink[]>();

  for (const link of links) {
    if (!findingIds.has(link.findingId)) {
      throw new Error(`hypothesis link references missing finding: ${link.findingId}`);
    }
    if (link.hypothesisId.trim() === "") {
      throw new Error(`hypothesis link for ${link.findingId} has empty hypothesis id`);
    }
    for (const nodeId of link.graphNodeIds ?? []) {
      if (!graphNodeIds.has(nodeId)) {
        throw new Error(
          `hypothesis link ${link.hypothesisId} references unknown graph node: ${nodeId}`,
        );
      }
    }
    for (const edgeId of link.graphEdgeIds ?? []) {
      if (!graphEdgeIds.has(edgeId)) {
        throw new Error(
          `hypothesis link ${link.hypothesisId} references unknown graph edge: ${edgeId}`,
        );
      }
    }
    const current = out.get(link.findingId) ?? [];
    current.push(link);
    out.set(link.findingId, current);
  }

  return out;
}

function hypothesisFor(links: ReadonlyArray<FindingHypothesisLink>): HypothesisContext | undefined {
  if (links.length === 0) {
    return undefined;
  }
  return {
    hypothesisIds: uniqueSorted(links.map((link) => link.hypothesisId)),
    graphNodeIds: uniqueSorted(links.flatMap((link) => link.graphNodeIds ?? [])),
    graphEdgeIds: uniqueSorted(links.flatMap((link) => link.graphEdgeIds ?? [])),
    reason:
      firstString(links.map((link) => link.reason)) ?? "linked to deterministic hypothesis context",
  };
}

function componentReachabilityMap(
  records: ReadonlyArray<ComponentReachability>,
  graph: SecurityGraph,
  findingIds: ReadonlySet<string>,
): Map<string, ComponentReachability[]> {
  const graphNodeIds = new Set(graph.nodes.map((node) => node.id));
  const graphEdgeIds = new Set(graph.edges.map((edge) => edge.id));
  const out = new Map<string, ComponentReachability[]>();

  for (const record of records) {
    if (!graphNodeIds.has(record.componentNodeId)) {
      throw new Error(
        `component reachability references unknown graph node: ${record.componentNodeId}`,
      );
    }
    for (const edgeId of record.pathEdgeIds) {
      if (!graphEdgeIds.has(edgeId)) {
        throw new Error(`component reachability references unknown graph edge: ${edgeId}`);
      }
    }
    for (const findingId of record.findingIds) {
      if (!findingIds.has(findingId)) {
        throw new Error(`component reachability references missing finding: ${findingId}`);
      }
      const current = out.get(findingId) ?? [];
      current.push(record);
      out.set(findingId, current);
    }
  }

  return out;
}

function endpointNodeIds(edges: ReadonlyArray<SecurityGraphEdge>): string[] {
  return uniqueSorted(edges.flatMap((edge) => [edge.fromNodeId, edge.toNodeId]));
}

function assertUniqueInputFindings(findings: ReadonlyArray<Finding>): void {
  const seen = new Set<string>();
  for (const finding of findings) {
    if (seen.has(finding.id)) {
      throw new Error(`duplicate finding id: ${finding.id}`);
    }
    seen.add(finding.id);
  }
}

function strongestCoverageState(states: ReadonlyArray<GraphCoverageState>): GraphCoverageState {
  for (const state of ["failed", "degraded", "partial", "skipped", "checked"] as const) {
    if (states.includes(state)) {
      return state;
    }
  }
  return "checked";
}

function firstString(values: ReadonlyArray<string | undefined>): string | undefined {
  return values.find((value) => value !== undefined && value.trim() !== "");
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}
