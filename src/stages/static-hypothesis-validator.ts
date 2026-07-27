import { createHash } from "node:crypto";
import type { Evidence } from "../domain/evidence.js";
import {
  type HypothesisCandidate,
  validateHypothesisCandidates,
} from "../domain/hypothesis-candidate.js";
import type {
  SecurityFlow,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../domain/security-graph.js";
import { securityGraphStableId } from "../domain/security-graph.js";
import type {
  StaticHypothesis,
  StaticHypothesisCoverageState,
  StaticHypothesisPromotion,
  StaticHypothesisPromotionReason,
  StaticHypothesisStatus,
} from "../domain/static-hypothesis.js";
import {
  staticHypothesisId,
  validateStaticHypothesisRecords,
} from "../domain/static-hypothesis.js";

export interface ValidateStaticHypothesesInput {
  readonly graph: SecurityGraph;
  readonly candidates: ReadonlyArray<HypothesisCandidate>;
  readonly evidence: ReadonlyArray<Evidence>;
  /** Paths in the immutable manifest for the snapshot being validated. */
  readonly manifestPaths: ReadonlySet<string> | ReadonlyArray<string>;
}

/**
 * Stable semantic sink classes eligible for owner-facing static promotion.
 * Generic reachability remains a candidate in report.json, never a deploy blocker.
 */
export const SECURITY_RELEVANT_SINK_TYPES = new Set([
  "access_control",
  "anti_automation_bypass",
  "authentication_bypass",
  "client_side_trust",
  "code_execution",
  "coupon_encoding_trust",
  "credential_trust",
  "cross_site_scripting",
  "csrf_state_change",
  "deserialization",
  "file_system",
  "file_upload_validation",
  "hidden_content_exposure",
  "jwt_token_trust",
  "llm_tool_trust",
  "log_disclosure",
  "log_injection",
  "no_sql_execution",
  "password_reset_trust",
  "redirect",
  "security_misconfiguration",
  "server_side_request",
  "session_cookie_trust",
  "smart_contract_reentrancy",
  "sql_execution",
  "template_render",
  "two_factor_token_trust",
  "xml_processing",
]);

interface ValidationIndex {
  readonly graph: SecurityGraph;
  readonly nodesById: ReadonlyMap<string, SecurityGraphNode>;
  readonly edgesById: ReadonlyMap<string, SecurityGraphEdge>;
  readonly evidenceById: ReadonlyMap<string, Evidence>;
  readonly manifestPaths: ReadonlySet<string>;
}

interface PromotionDecision {
  readonly status: StaticHypothesisStatus;
  readonly coverageState: StaticHypothesisCoverageState;
  readonly promotion: StaticHypothesisPromotion;
  readonly supportingEvidenceIds: ReadonlyArray<string>;
  readonly contradictingEvidenceIds: ReadonlyArray<string>;
}

type ControlAssessment = StaticHypothesisPromotion["control"];

export function validateStaticHypotheses(input: ValidateStaticHypothesesInput): StaticHypothesis[] {
  const graphNodeIds = new Set(input.graph.nodes.map((node) => node.id));
  const graphEdgeIds = new Set(input.graph.edges.map((edge) => edge.id));
  const candidates = validateHypothesisCandidates(input.candidates, { graphNodeIds, graphEdgeIds });
  const index: ValidationIndex = {
    graph: input.graph,
    nodesById: new Map(input.graph.nodes.map((node) => [node.id, node])),
    edgesById: new Map(input.graph.edges.map((edge) => [edge.id, edge])),
    evidenceById: new Map(input.evidence.map((record) => [record.id, record])),
    manifestPaths:
      input.manifestPaths instanceof Set
        ? new Set(input.manifestPaths)
        : new Set(input.manifestPaths),
  };

  return validateStaticHypothesisRecords(
    candidates.map((candidate) => staticHypothesisFor(candidate, index)),
    { candidateIds: candidates.map((candidate) => candidate.id) },
  );
}

function staticHypothesisFor(
  candidate: HypothesisCandidate,
  index: ValidationIndex,
): StaticHypothesis {
  const decision = promotionDecision(candidate, index);
  return {
    id: staticHypothesisId(index.graph.graphVersion, candidate.id),
    candidateId: candidate.id,
    status: decision.status,
    staticConfidence: confidenceFor(decision),
    title: candidate.title,
    pathSummary: pathSummaryFor(candidate, decision),
    supportingEvidenceIds: decision.supportingEvidenceIds,
    contradictingEvidenceIds: decision.contradictingEvidenceIds,
    coverageState: decision.coverageState,
    runtimeValidationRequired: decision.status !== "statically_contradicted",
    promotion: decision.promotion,
  };
}

function promotionDecision(
  candidate: HypothesisCandidate,
  index: ValidationIndex,
): PromotionDecision {
  const candidateNodes = candidate.supportingNodeIds.flatMap((nodeId) => {
    const node = index.nodesById.get(nodeId);
    return node === undefined ? [] : [node];
  });
  const source = candidateNodes.find(isExternalSource);
  const sinks = candidateNodes.filter((node) => node.kind === "Sink");
  const typedSink = sinks.find((node) => {
    const sinkType = stringProperty(node.properties.sinkType);
    return sinkType !== undefined && SECURITY_RELEVANT_SINK_TYPES.has(sinkType);
  });
  const untypedSink = sinks[0];
  const sink = typedSink ?? untypedSink;
  const sinkType = sink === undefined ? undefined : stringProperty(sink.properties.sinkType);
  const flow = matchingFlow(candidate, source, sink, index);
  const coverageState = coverageStateFor(candidate, flow, index);
  const reasons: StaticHypothesisPromotionReason[] = [];

  if (source === undefined) {
    reasons.push("missing_external_source");
  } else {
    reasons.push("external_source_observed");
  }
  if (sink === undefined) {
    reasons.push("generic_or_untyped_sink");
  } else if (typedSink === undefined) {
    reasons.push("generic_or_untyped_sink");
  } else {
    reasons.push("typed_security_sink_observed");
  }
  if (flow === undefined) {
    reasons.push(
      hasStructuralPath(candidate, index) ? "structural_path_only" : "missing_security_flow",
    );
  } else {
    reasons.push("connected_security_flow_observed");
  }
  if (candidateCoverageIncomplete(candidate)) {
    reasons.push("candidate_coverage_incomplete");
  }
  if (flow !== undefined && flowCoverageIncomplete(flow, index)) {
    reasons.push("security_flow_coverage_incomplete");
  }
  const controlCoverageState = graphCoverageState(index.graph, "control_flow");
  if (controlCoverageState !== "checked") {
    reasons.push("control_coverage_incomplete");
  }

  const evidenceCurrent =
    source !== undefined &&
    sink !== undefined &&
    flow !== undefined &&
    currentNodeEvidence(source, index) &&
    currentNodeEvidence(sink, index) &&
    flow.pathEdgeIds.every((edgeId) => {
      const edge = index.edgesById.get(edgeId);
      return edge !== undefined && currentEdgeEvidence(edge, index);
    });
  reasons.push(
    evidenceCurrent
      ? "current_line_pinned_evidence_observed"
      : "missing_current_line_pinned_evidence",
  );

  const control =
    controlCoverageState !== "checked"
      ? "ambiguous"
      : flow === undefined || sink === undefined || sinkType === undefined
        ? "absent"
        : controlAssessment(flow, sink, sinkType, index);
  if (control === "effective") {
    reasons.push("effective_control_dominates_sink");
  } else if (control === "ambiguous") {
    reasons.push("control_effect_ambiguous");
  } else {
    reasons.push("matching_control_not_observed");
  }

  const basePromotionSatisfied =
    source !== undefined &&
    typedSink !== undefined &&
    flow !== undefined &&
    coverageState === "checked" &&
    evidenceCurrent;
  const status: StaticHypothesisStatus =
    basePromotionSatisfied && control === "effective"
      ? "statically_contradicted"
      : basePromotionSatisfied && control !== "ambiguous"
        ? "statically_supported"
        : "inconclusive";
  const pathEvidenceIds =
    flow === undefined
      ? []
      : uniqueSorted([
          ...(source?.evidenceIds ?? []),
          ...(sink?.evidenceIds ?? []),
          ...flow.evidenceIds,
          ...flow.pathEdgeIds.flatMap((edgeId) => index.edgesById.get(edgeId)?.evidenceIds ?? []),
        ]).filter((evidenceId) => currentEvidenceRecord(evidenceId, index) !== undefined);
  const controlEvidenceIds =
    control === "effective" && flow !== undefined && sink !== undefined
      ? effectiveControlEvidenceIds(flow, sink, sinkType ?? "", index)
      : [];
  const rootCauseKey =
    sink === undefined || sinkType === undefined
      ? undefined
      : securityGraphStableId("static_root_cause", [candidate.family, sinkType, sink.stableKey]);
  const promotion: StaticHypothesisPromotion = {
    publishable: status === "statically_supported",
    source: source === undefined ? "missing_or_untyped" : "external_input",
    sink:
      sink === undefined
        ? "missing"
        : typedSink === undefined
          ? "generic_or_untyped"
          : "typed_security_sink",
    path:
      flow === undefined
        ? hasStructuralPath(candidate, index)
          ? "structural_only"
          : "missing"
        : "connected_security_flow",
    control,
    evidence: evidenceCurrent ? "current_line_pinned" : "missing_or_stale",
    ...(rootCauseKey === undefined ? {} : { rootCauseKey }),
    reasons: uniqueSorted(reasons),
  };
  return {
    status,
    coverageState,
    promotion,
    supportingEvidenceIds: status === "statically_supported" ? pathEvidenceIds : [],
    contradictingEvidenceIds: status === "statically_contradicted" ? controlEvidenceIds : [],
  };
}

function matchingFlow(
  candidate: HypothesisCandidate,
  source: SecurityGraphNode | undefined,
  sink: SecurityGraphNode | undefined,
  index: ValidationIndex,
): SecurityFlow | undefined {
  if (source === undefined || sink === undefined) {
    return undefined;
  }
  const candidateEdges = new Set(candidate.supportingEdgeIds);
  return [...index.graph.flows]
    .sort((a, b) => a.id.localeCompare(b.id))
    .find(
      (flow) =>
        flow.sourceNodeId === source.id &&
        flow.sinkNodeId === sink.id &&
        flow.pathEdgeIds.length > 0 &&
        flow.pathEdgeIds.every((edgeId) => candidateEdges.has(edgeId)),
    );
}

function controlAssessment(
  flow: SecurityFlow,
  sink: SecurityGraphNode,
  sinkType: string,
  index: ValidationIndex,
): ControlAssessment {
  if (flow.controlNodeIds.length === 0) {
    return "absent";
  }
  let ambiguous = false;
  for (const controlId of [...flow.controlNodeIds].sort()) {
    const control = index.nodesById.get(controlId);
    if (control?.kind !== "Control") {
      ambiguous = true;
      continue;
    }
    const protectsSinkType = stringProperty(control.properties.protectsSinkType);
    if (protectsSinkType !== undefined && protectsSinkType !== sinkType) {
      continue;
    }
    if (control.properties.controlEffect !== "blocks_untrusted" || protectsSinkType === undefined) {
      ambiguous = true;
      continue;
    }
    const relation = effectiveControlRelation(sink, control, index);
    if (
      relation !== undefined &&
      currentNodeEvidence(control, index) &&
      currentEdgeEvidence(relation, index)
    ) {
      return "effective";
    }
    ambiguous = true;
  }
  return ambiguous ? "ambiguous" : "irrelevant";
}

function effectiveControlEvidenceIds(
  flow: SecurityFlow,
  sink: SecurityGraphNode,
  sinkType: string,
  index: ValidationIndex,
): string[] {
  for (const controlId of [...flow.controlNodeIds].sort()) {
    const control = index.nodesById.get(controlId);
    if (
      control?.kind !== "Control" ||
      control.properties.controlEffect !== "blocks_untrusted" ||
      control.properties.protectsSinkType !== sinkType
    ) {
      continue;
    }
    const relation = effectiveControlRelation(sink, control, index);
    if (relation !== undefined) {
      return uniqueSorted([...control.evidenceIds, ...relation.evidenceIds]).filter(
        (evidenceId) => currentEvidenceRecord(evidenceId, index) !== undefined,
      );
    }
  }
  return [];
}

function effectiveControlRelation(
  sink: SecurityGraphNode,
  control: SecurityGraphNode,
  index: ValidationIndex,
): SecurityGraphEdge | undefined {
  return [...index.graph.edges]
    .sort((a, b) => a.id.localeCompare(b.id))
    .find(
      (edge) =>
        edge.kind === "protected_by" &&
        edge.fromNodeId === sink.id &&
        edge.toNodeId === control.id &&
        edge.properties.relation === "dominates_sink",
    );
}

function currentNodeEvidence(node: SecurityGraphNode, index: ValidationIndex): boolean {
  if (node.repoPath === undefined || node.lineRange === undefined) {
    return false;
  }
  return node.evidenceIds.some((evidenceId) => {
    const evidence = currentEvidenceRecord(evidenceId, index);
    return evidence !== undefined && evidenceOverlapsNode(evidence, node);
  });
}

function currentEdgeEvidence(edge: SecurityGraphEdge, index: ValidationIndex): boolean {
  const endpoints = [index.nodesById.get(edge.fromNodeId), index.nodesById.get(edge.toNodeId)];
  return edge.evidenceIds.some((evidenceId) => {
    const evidence = currentEvidenceRecord(evidenceId, index);
    return (
      evidence !== undefined &&
      endpoints.some((node) => node !== undefined && evidenceOverlapsNode(evidence, node))
    );
  });
}

function currentEvidenceRecord(evidenceId: string, index: ValidationIndex): Evidence | undefined {
  const evidence = index.evidenceById.get(evidenceId);
  if (
    evidence === undefined ||
    !index.manifestPaths.has(evidence.filePath) ||
    sha256(evidence.snippet) !== evidence.snippetHash
  ) {
    return undefined;
  }
  return evidence;
}

function evidenceOverlapsNode(evidence: Evidence, node: SecurityGraphNode): boolean {
  return (
    node.repoPath !== undefined &&
    node.lineRange !== undefined &&
    evidence.filePath === node.repoPath &&
    evidence.startLine <= node.lineRange.endLine &&
    evidence.endLine >= node.lineRange.startLine
  );
}

function coverageStateFor(
  candidate: HypothesisCandidate,
  flow: SecurityFlow | undefined,
  index: ValidationIndex,
): StaticHypothesisCoverageState {
  const states: StaticHypothesisCoverageState[] = [
    ...candidate.coverageRefs.flatMap(coverageStateFromRef),
    graphCoverageState(index.graph, "control_flow"),
    ...(flow === undefined ? [] : [flow.coverageState]),
    ...(flow?.pathEdgeIds.flatMap((edgeId) => {
      const edge = index.edgesById.get(edgeId);
      return edge === undefined ? ["failed" as const] : [edge.coverageState];
    }) ?? []),
  ];
  for (const state of ["failed", "degraded", "partial", "skipped"] as const) {
    if (states.includes(state)) {
      return state;
    }
  }
  return "checked";
}

function graphCoverageState(
  graph: SecurityGraph,
  area: SecurityGraph["coverage"][number]["area"],
): StaticHypothesisCoverageState {
  const states = graph.coverage.filter((entry) => entry.area === area).map((entry) => entry.state);
  if (states.length === 0) {
    return "skipped";
  }
  for (const state of ["failed", "degraded", "partial", "skipped"] as const) {
    if (states.includes(state)) {
      return state;
    }
  }
  return "checked";
}

function coverageStateFromRef(value: string): StaticHypothesisCoverageState[] {
  for (const state of ["failed", "degraded", "partial", "skipped", "checked"] as const) {
    if (value.endsWith(`:${state}`)) {
      return [state];
    }
  }
  return value.includes("coverage-unavailable") ? ["skipped"] : [];
}

function candidateCoverageIncomplete(candidate: HypothesisCandidate): boolean {
  return candidate.coverageRefs.some((ref) => /(failed|degraded|partial|skipped)$/.test(ref));
}

function flowCoverageIncomplete(flow: SecurityFlow, index: ValidationIndex): boolean {
  return (
    flow.coverageState !== "checked" ||
    flow.pathEdgeIds.some((edgeId) => index.edgesById.get(edgeId)?.coverageState !== "checked")
  );
}

function hasStructuralPath(candidate: HypothesisCandidate, index: ValidationIndex): boolean {
  return candidate.supportingEdgeIds.some((edgeId) => index.edgesById.has(edgeId));
}

function isExternalSource(node: SecurityGraphNode): boolean {
  return (
    node.kind === "Boundary" ||
    (node.kind === "Source" && node.properties.sourceType === "external_input")
  );
}

function confidenceFor(decision: PromotionDecision): number {
  switch (decision.status) {
    case "statically_supported":
      return 0.9;
    case "statically_contradicted":
      return 0.1;
    case "candidate":
      return 0.4;
    case "inconclusive":
      return decision.coverageState === "failed" ? 0.1 : 0.25;
  }
}

function pathSummaryFor(candidate: HypothesisCandidate, decision: PromotionDecision): string {
  switch (decision.status) {
    case "statically_supported":
      return `A typed external-input-to-security-sink flow with current line-pinned evidence supports "${candidate.title}"; no effective sink-matched guard was observed. Runtime validation is still required.`;
    case "statically_contradicted":
      return `A current, value-matched control dominates the exact sink for "${candidate.title}" and blocks static promotion.`;
    case "inconclusive":
      return `Static promotion for "${candidate.title}" is inconclusive: ${decision.promotion.reasons.join(", ")}. The raw candidate remains available for inspection.`;
    case "candidate":
      return `Graph references exist for "${candidate.title}", but the promotion contract was not evaluated.`;
  }
}

function stringProperty(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function uniqueSorted<T extends string>(values: Iterable<T>): T[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}
