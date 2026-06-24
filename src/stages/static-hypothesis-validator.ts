import {
  type HypothesisCandidate,
  validateHypothesisCandidates,
} from "../domain/hypothesis-candidate.js";
import type { SecurityGraph } from "../domain/security-graph.js";
import type {
  StaticHypothesis,
  StaticHypothesisCoverageState,
  StaticHypothesisStatus,
} from "../domain/static-hypothesis.js";
import {
  staticHypothesisId,
  validateStaticHypothesisRecords,
} from "../domain/static-hypothesis.js";

export interface ValidateStaticHypothesesInput {
  readonly graph: SecurityGraph;
  readonly candidates: ReadonlyArray<HypothesisCandidate>;
}

export function validateStaticHypotheses(input: ValidateStaticHypothesesInput): StaticHypothesis[] {
  const graphNodeIds = new Set(input.graph.nodes.map((node) => node.id));
  const graphEdgeIds = new Set(input.graph.edges.map((edge) => edge.id));
  const candidates = validateHypothesisCandidates(input.candidates, { graphNodeIds, graphEdgeIds });
  const nodeEvidence = new Map(input.graph.nodes.map((node) => [node.id, node.evidenceIds]));
  const edgeEvidence = new Map(input.graph.edges.map((edge) => [edge.id, edge.evidenceIds]));

  return validateStaticHypothesisRecords(
    candidates.map((candidate) =>
      staticHypothesisFor(candidate, input.graph.graphVersion, nodeEvidence, edgeEvidence),
    ),
    { candidateIds: candidates.map((candidate) => candidate.id) },
  );
}

function staticHypothesisFor(
  candidate: HypothesisCandidate,
  graphVersion: string,
  nodeEvidence: ReadonlyMap<string, ReadonlyArray<string>>,
  edgeEvidence: ReadonlyMap<string, ReadonlyArray<string>>,
): StaticHypothesis {
  const coverageState = coverageStateFor(candidate.coverageRefs);
  const status = statusFor(candidate, coverageState);
  const supportingEvidenceIds = evidenceIdsFor(
    candidate.supportingNodeIds,
    candidate.supportingEdgeIds,
    nodeEvidence,
    edgeEvidence,
  );
  const contradictingEvidenceIds = evidenceIdsFor(
    candidate.contradictingNodeIds,
    candidate.contradictingEdgeIds,
    nodeEvidence,
    edgeEvidence,
  );

  return {
    id: staticHypothesisId(graphVersion, candidate.id),
    candidateId: candidate.id,
    status,
    staticConfidence: staticConfidenceFor(candidate, status, coverageState),
    title: candidate.title,
    pathSummary: pathSummaryFor(candidate, status, coverageState),
    supportingEvidenceIds,
    contradictingEvidenceIds,
    coverageState,
    runtimeValidationRequired: status !== "statically_contradicted",
  };
}

function statusFor(
  candidate: HypothesisCandidate,
  coverageState: StaticHypothesisCoverageState,
): StaticHypothesisStatus {
  if (candidate.contradictingNodeIds.length > 0 || candidate.contradictingEdgeIds.length > 0) {
    return "statically_contradicted";
  }
  if (coverageState !== "checked") {
    return "inconclusive";
  }
  if (candidate.supportingEdgeIds.length === 0) {
    return "candidate";
  }
  return "statically_supported";
}

function staticConfidenceFor(
  candidate: HypothesisCandidate,
  status: StaticHypothesisStatus,
  coverageState: StaticHypothesisCoverageState,
): number {
  switch (status) {
    case "statically_contradicted":
      return 0.1;
    case "inconclusive":
      return coverageState === "failed" ? 0.15 : 0.25;
    case "candidate":
      return 0.5;
    case "statically_supported":
      return clamp(
        0.65 +
          candidate.supportingEdgeIds.length * 0.05 +
          candidate.supportingNodeIds.length * 0.01 +
          candidate.findingIds.length * 0.04,
      );
  }
}

function pathSummaryFor(
  candidate: HypothesisCandidate,
  status: StaticHypothesisStatus,
  coverageState: StaticHypothesisCoverageState,
): string {
  switch (status) {
    case "statically_supported":
      return `Static graph evidence supports "${candidate.title}" across ${candidate.supportingEdgeIds.length} graph edges; runtime validation is still required.`;
    case "statically_contradicted":
      return `Observed graph controls or contradictions block static support for "${candidate.title}".`;
    case "inconclusive":
      return `Static support for "${candidate.title}" is inconclusive because graph coverage is ${coverageState}; destination allowlist was not observed on the analyzed path.`;
    case "candidate":
      return `Candidate graph references exist for "${candidate.title}", but there is no supporting path edge strong enough for static support.`;
  }
}

function evidenceIdsFor(
  nodeIds: ReadonlyArray<string>,
  edgeIds: ReadonlyArray<string>,
  nodeEvidence: ReadonlyMap<string, ReadonlyArray<string>>,
  edgeEvidence: ReadonlyMap<string, ReadonlyArray<string>>,
): string[] {
  return uniqueSorted([
    ...nodeIds.flatMap((nodeId) => nodeEvidence.get(nodeId) ?? []),
    ...edgeIds.flatMap((edgeId) => edgeEvidence.get(edgeId) ?? []),
  ]);
}

function coverageStateFor(coverageRefs: ReadonlyArray<string>): StaticHypothesisCoverageState {
  for (const state of ["failed", "degraded", "partial", "skipped"] as const) {
    if (coverageRefs.some((ref) => ref.endsWith(`:${state}`))) {
      return state;
    }
  }
  if (coverageRefs.some((ref) => ref.includes("coverage-unavailable"))) {
    return "skipped";
  }
  return "checked";
}

function clamp(value: number): number {
  return Math.min(0.95, Math.max(0, Number(value.toFixed(4))));
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}
