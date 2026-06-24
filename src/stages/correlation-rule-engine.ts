import {
  type FindingContextAssessment,
  validateFindingContextAssessments,
} from "../domain/finding-context-assessment.js";
import {
  type HypothesisCandidate,
  hypothesisCandidateId,
  validateHypothesisCandidates,
} from "../domain/hypothesis-candidate.js";
import type {
  GraphCoverageState,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphEdgeKind,
  SecurityGraphNode,
  SecurityGraphNodeKind,
} from "../domain/security-graph.js";

export interface CorrelationRuleDefinition {
  readonly id: string;
  readonly family: string;
  readonly title: string;
  readonly source: CorrelationNodeSelector;
  readonly target: CorrelationNodeSelector;
  readonly path: CorrelationPathDefinition;
  readonly requiredValidation: ReadonlyArray<string>;
  readonly coverageRefs?: ReadonlyArray<string>;
}

export interface CorrelationNodeSelector {
  readonly kinds?: ReadonlyArray<SecurityGraphNodeKind>;
  readonly stableKeys?: ReadonlyArray<string>;
  readonly coverageStates?: ReadonlyArray<GraphCoverageState>;
  readonly propertyEquals?: Readonly<Record<string, string | number | boolean>>;
}

export interface CorrelationPathDefinition {
  readonly allowedEdgeKinds: ReadonlyArray<SecurityGraphEdgeKind>;
  readonly requiredEdgeKinds?: ReadonlyArray<SecurityGraphEdgeKind>;
  readonly maxPathLength: number;
}

export interface CorrelateGraphRulesInput {
  readonly graph: SecurityGraph;
  readonly findingContexts?: ReadonlyArray<FindingContextAssessment>;
  readonly rules: ReadonlyArray<CorrelationRuleDefinition>;
  readonly maxCandidatesPerRule?: number;
}

interface SearchPath {
  readonly startNodeId: string;
  readonly endNodeId: string;
  readonly edgeIds: ReadonlyArray<string>;
  readonly nodeIds: ReadonlyArray<string>;
}

const DEFAULT_MAX_CANDIDATES_PER_RULE = 25;
const CONTRADICTION_EDGE_KINDS = new Set<SecurityGraphEdgeKind>([
  "protected_by",
  "contradicted_by",
]);

export function correlateGraphRules(input: CorrelateGraphRulesInput): HypothesisCandidate[] {
  assertPositiveInteger(
    input.maxCandidatesPerRule ?? DEFAULT_MAX_CANDIDATES_PER_RULE,
    "maxCandidatesPerRule",
  );
  const rules = input.rules.map(validateRule);
  const graphNodeIds = new Set(input.graph.nodes.map((node) => node.id));
  const graphEdgeIds = new Set(input.graph.edges.map((edge) => edge.id));
  const findingContexts = validateFindingContextAssessments(input.findingContexts ?? [], {
    graphNodeIds,
    graphEdgeIds,
  });
  const findingIds = new Set(findingContexts.map((context) => context.findingId));
  const candidates: HypothesisCandidate[] = [];

  for (const rule of rules) {
    const ruleCandidates: HypothesisCandidate[] = [];
    for (const path of pathsForRule(input.graph, rule)) {
      ruleCandidates.push(candidateForPath(input.graph, findingContexts, rule, path));
      if (
        ruleCandidates.length >= (input.maxCandidatesPerRule ?? DEFAULT_MAX_CANDIDATES_PER_RULE)
      ) {
        break;
      }
    }
    candidates.push(...ruleCandidates);
  }

  return validateHypothesisCandidates(candidates, { findingIds, graphNodeIds, graphEdgeIds });
}

function validateRule(rule: CorrelationRuleDefinition): CorrelationRuleDefinition {
  assertNonEmpty(rule.id, "correlation rule id");
  assertNonEmpty(rule.family, `correlation rule ${rule.id} family`);
  assertNonEmpty(rule.title, `correlation rule ${rule.id} title`);
  assertSelector(rule.source, `correlation rule ${rule.id} source`);
  assertSelector(rule.target, `correlation rule ${rule.id} target`);
  assertNonEmptyList(rule.path.allowedEdgeKinds, `correlation rule ${rule.id} allowedEdgeKinds`);
  assertPositiveInteger(rule.path.maxPathLength, `correlation rule ${rule.id} maxPathLength`);
  assertNonEmptyList(rule.requiredValidation, `correlation rule ${rule.id} requiredValidation`);

  const allowedEdgeKinds = new Set(rule.path.allowedEdgeKinds);
  for (const edgeKind of rule.path.requiredEdgeKinds ?? []) {
    if (!allowedEdgeKinds.has(edgeKind)) {
      throw new Error(`correlation rule ${rule.id} required edge kind is not allowed: ${edgeKind}`);
    }
  }
  return rule;
}

function pathsForRule(
  graph: SecurityGraph,
  rule: CorrelationRuleDefinition,
): ReadonlyArray<SearchPath> {
  const nodes = sortedNodes(graph.nodes);
  const starts = nodes.filter((node) => matchesSelector(node, rule.source));
  const targets = new Set(
    nodes.filter((node) => matchesSelector(node, rule.target)).map((node) => node.id),
  );
  const outgoing = outgoingEdges(graph.edges, new Set(rule.path.allowedEdgeKinds));
  const paths: SearchPath[] = [];

  for (const start of starts) {
    const queue: SearchPath[] = [
      { startNodeId: start.id, endNodeId: start.id, edgeIds: [], nodeIds: [start.id] },
    ];
    while (queue.length > 0) {
      const current = queue.shift();
      if (current === undefined) {
        continue;
      }
      if (
        current.edgeIds.length > 0 &&
        targets.has(current.endNodeId) &&
        hasRequiredEdgeKinds(current.edgeIds, graph.edges, rule.path.requiredEdgeKinds ?? [])
      ) {
        paths.push(current);
      }
      if (current.edgeIds.length >= rule.path.maxPathLength) {
        continue;
      }
      for (const edge of outgoing.get(current.endNodeId) ?? []) {
        if (current.nodeIds.includes(edge.toNodeId)) {
          continue;
        }
        queue.push({
          startNodeId: current.startNodeId,
          endNodeId: edge.toNodeId,
          edgeIds: [...current.edgeIds, edge.id],
          nodeIds: [...current.nodeIds, edge.toNodeId],
        });
      }
    }
  }

  return paths.sort(compareSearchPath);
}

function candidateForPath(
  graph: SecurityGraph,
  contexts: ReadonlyArray<FindingContextAssessment>,
  rule: CorrelationRuleDefinition,
  path: SearchPath,
): HypothesisCandidate {
  const edgesById = new Map(graph.edges.map((edge) => [edge.id, edge]));
  const supportEdges = path.edgeIds.flatMap((edgeId) => {
    const edge = edgesById.get(edgeId);
    return edge === undefined ? [] : [edge];
  });
  const supportingNodeIds = uniqueSorted([
    ...path.nodeIds,
    ...supportEdges.flatMap((edge) => [edge.fromNodeId, edge.toNodeId]),
  ]);
  const supportingEdgeIds = uniqueSorted(supportEdges.map((edge) => edge.id));
  const contradictionEdges = contradictionEdgesFor(graph.edges, supportingNodeIds);
  const contradictingNodeIds = endpointNodeIds(contradictionEdges);
  const contradictingEdgeIds = uniqueSorted(contradictionEdges.map((edge) => edge.id));
  const findingIds = linkedFindingIds(contexts, supportingNodeIds, supportingEdgeIds);

  return {
    id: hypothesisCandidateId(graph.graphVersion, rule.id, [
      path.startNodeId,
      path.endNodeId,
      ...supportingEdgeIds,
    ]),
    ruleId: rule.id,
    family: rule.family,
    title: rule.title,
    findingIds,
    supportingNodeIds,
    supportingEdgeIds,
    contradictingNodeIds,
    contradictingEdgeIds,
    coverageRefs: coverageRefsFor(graph, rule),
    requiredValidation: uniqueSorted(rule.requiredValidation),
    candidateReason: candidateReason(graph.nodes, rule, path, supportEdges.length),
  };
}

function linkedFindingIds(
  contexts: ReadonlyArray<FindingContextAssessment>,
  supportingNodeIds: ReadonlyArray<string>,
  supportingEdgeIds: ReadonlyArray<string>,
): string[] {
  const nodeIds = new Set(supportingNodeIds);
  const edgeIds = new Set(supportingEdgeIds);
  return uniqueSorted(
    contexts
      .filter((context) => context.status !== "standalone")
      .filter(
        (context) =>
          context.graphNodeIds.some((nodeId) => nodeIds.has(nodeId)) ||
          context.graphEdgeIds.some((edgeId) => edgeIds.has(edgeId)),
      )
      .map((context) => context.findingId),
  );
}

function contradictionEdgesFor(
  edges: ReadonlyArray<SecurityGraphEdge>,
  supportingNodeIds: ReadonlyArray<string>,
): SecurityGraphEdge[] {
  const nodeIds = new Set(supportingNodeIds);
  return sortedEdges(
    edges.filter(
      (edge) =>
        CONTRADICTION_EDGE_KINDS.has(edge.kind) &&
        (nodeIds.has(edge.fromNodeId) || nodeIds.has(edge.toNodeId)),
    ),
  );
}

function matchesSelector(node: SecurityGraphNode, selector: CorrelationNodeSelector): boolean {
  if (selector.kinds !== undefined && !selector.kinds.includes(node.kind)) {
    return false;
  }
  if (selector.stableKeys !== undefined && !selector.stableKeys.includes(node.stableKey)) {
    return false;
  }
  if (
    selector.coverageStates !== undefined &&
    !selector.coverageStates.includes(node.coverageState)
  ) {
    return false;
  }
  for (const [key, expected] of Object.entries(selector.propertyEquals ?? {})) {
    if (node.properties[key] !== expected) {
      return false;
    }
  }
  return true;
}

function outgoingEdges(
  edges: ReadonlyArray<SecurityGraphEdge>,
  allowedKinds: ReadonlySet<SecurityGraphEdgeKind>,
): ReadonlyMap<string, ReadonlyArray<SecurityGraphEdge>> {
  const out = new Map<string, SecurityGraphEdge[]>();
  for (const edge of sortedEdges(edges)) {
    if (!allowedKinds.has(edge.kind)) {
      continue;
    }
    const current = out.get(edge.fromNodeId) ?? [];
    current.push(edge);
    out.set(edge.fromNodeId, current);
  }
  return out;
}

function hasRequiredEdgeKinds(
  edgeIds: ReadonlyArray<string>,
  edges: ReadonlyArray<SecurityGraphEdge>,
  requiredKinds: ReadonlyArray<SecurityGraphEdgeKind>,
): boolean {
  if (requiredKinds.length === 0) {
    return true;
  }
  const edgesById = new Map(edges.map((edge) => [edge.id, edge]));
  const seenKinds = new Set(
    edgeIds.flatMap((edgeId) => {
      const edge = edgesById.get(edgeId);
      return edge === undefined ? [] : [edge.kind];
    }),
  );
  return requiredKinds.every((kind) => seenKinds.has(kind));
}

function coverageRefsFor(
  graph: SecurityGraph,
  rule: CorrelationRuleDefinition,
): ReadonlyArray<string> {
  return uniqueSorted([
    ...(rule.coverageRefs ?? []),
    ...graph.coverage.map((coverage) => `${coverage.area}:${coverage.state}`),
    ...(graph.coverage.length === 0 ? ["graph:coverage-unavailable"] : []),
  ]);
}

function candidateReason(
  nodes: ReadonlyArray<SecurityGraphNode>,
  rule: CorrelationRuleDefinition,
  path: SearchPath,
  edgeCount: number,
): string {
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  const start = nodesById.get(path.startNodeId)?.label ?? path.startNodeId;
  const end = nodesById.get(path.endNodeId)?.label ?? path.endNodeId;
  return `${rule.title}: ${start} reaches ${end} across ${edgeCount} graph edges`;
}

function endpointNodeIds(edges: ReadonlyArray<SecurityGraphEdge>): string[] {
  return uniqueSorted(edges.flatMap((edge) => [edge.fromNodeId, edge.toNodeId]));
}

function compareSearchPath(a: SearchPath, b: SearchPath): number {
  return (
    a.startNodeId.localeCompare(b.startNodeId) ||
    a.endNodeId.localeCompare(b.endNodeId) ||
    a.edgeIds.join("\0").localeCompare(b.edgeIds.join("\0"))
  );
}

function sortedNodes(nodes: ReadonlyArray<SecurityGraphNode>): SecurityGraphNode[] {
  return [...nodes].sort(
    (a, b) => a.stableKey.localeCompare(b.stableKey) || a.id.localeCompare(b.id),
  );
}

function sortedEdges(edges: ReadonlyArray<SecurityGraphEdge>): SecurityGraphEdge[] {
  return [...edges].sort(
    (a, b) => a.stableKey.localeCompare(b.stableKey) || a.id.localeCompare(b.id),
  );
}

function assertSelector(selector: CorrelationNodeSelector, label: string): void {
  if (
    selector.kinds === undefined &&
    selector.stableKeys === undefined &&
    selector.coverageStates === undefined &&
    selector.propertyEquals === undefined
  ) {
    throw new Error(`${label} selector must constrain at least one field`);
  }
  if (selector.kinds !== undefined) {
    assertNonEmptyList(selector.kinds, `${label} kinds`);
  }
  if (selector.stableKeys !== undefined) {
    assertNonEmptyList(selector.stableKeys, `${label} stableKeys`);
  }
  if (selector.coverageStates !== undefined) {
    assertNonEmptyList(selector.coverageStates, `${label} coverageStates`);
  }
  const propertyKeys = Object.keys(selector.propertyEquals ?? {});
  if (selector.propertyEquals !== undefined && propertyKeys.length === 0) {
    throw new Error(`${label} propertyEquals must constrain at least one property`);
  }
  for (const key of propertyKeys) {
    assertNonEmpty(key, `${label} propertyEquals key`);
  }
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
}

function assertNonEmpty(value: string, label: string): void {
  if (value.trim() === "") {
    throw new Error(`${label} is required`);
  }
}

function assertNonEmptyList(values: ReadonlyArray<string>, label: string): void {
  if (values.length === 0) {
    throw new Error(`${label} are required`);
  }
  for (const value of values) {
    assertNonEmpty(value, label);
  }
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}
