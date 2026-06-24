import type { Evidence } from "../domain/evidence.js";
import type { Finding } from "../domain/finding.js";
import type { HypothesisCandidate } from "../domain/hypothesis-candidate.js";
import { validateHypothesisCandidates } from "../domain/hypothesis-candidate.js";
import {
  type HypothesisEnrichment,
  hypothesisEnrichmentId,
  validateHypothesisEnrichments,
} from "../domain/hypothesis-enrichment.js";
import type {
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../domain/security-graph.js";
import type { StaticHypothesis } from "../domain/static-hypothesis.js";
import { validateStaticHypothesisRecords } from "../domain/static-hypothesis.js";
import type { ValidationRecipe } from "../domain/validation-recipe.js";
import { validateValidationRecipes } from "../domain/validation-recipe.js";
import type {
  ModelHypothesisEnrichBatchInput,
  ModelHypothesisEnrichInput,
  ModelHypothesisEnrichment,
  ModelHypothesisEvidenceSnippetInput,
  ModelHypothesisGraphRefInput,
  ModelHypothesisValidationRecipeInput,
  ModelProvider,
} from "../ports/model-provider.js";

export interface EnrichStaticHypothesesInput {
  readonly repositoryName: string;
  readonly model: ModelProvider;
  readonly staticHypotheses: ReadonlyArray<StaticHypothesis>;
  readonly candidates: ReadonlyArray<HypothesisCandidate>;
  readonly graph: SecurityGraph;
  readonly validationRecipes?: ReadonlyArray<ValidationRecipe>;
  readonly findings?: ReadonlyArray<Finding>;
  readonly evidence?: ReadonlyArray<Evidence>;
  readonly maxHypotheses?: number;
}

const DEFAULT_MAX_HYPOTHESES = 5;
const MAX_GRAPH_REFS_PER_HYPOTHESIS = 20;
const MAX_EVIDENCE_SNIPPETS_PER_HYPOTHESIS = 12;
const MODEL_SNIPPET_CHAR_LIMIT = 500;

const PROHIBITED_MODEL_FIELDS = new Set([
  "id",
  "source",
  "candidateId",
  "candidate_id",
  "family",
  "ruleId",
  "rule_id",
  "status",
  "staticStatus",
  "static_status",
  "staticConfidence",
  "static_confidence",
  "priority",
  "priorityScore",
  "priority_score",
  "verdict",
  "verdictImpact",
  "verdict_impact",
  "runtimeValidationRequired",
  "runtime_validation_required",
  "findingIds",
  "finding_ids",
  "supportingNodeIds",
  "supporting_node_ids",
  "supportingEdgeIds",
  "supporting_edge_ids",
  "contradictingNodeIds",
  "contradicting_node_ids",
  "contradictingEdgeIds",
  "contradicting_edge_ids",
  "coverageState",
  "coverage_state",
  "coverageRefs",
  "coverage_refs",
  "requiredValidation",
  "required_validation",
  "graphRefs",
  "graph_refs",
  "path",
  "paths",
]);

export async function enrichStaticHypotheses(
  input: EnrichStaticHypothesesInput,
): Promise<HypothesisEnrichment[]> {
  const maxHypotheses = positiveInt(input.maxHypotheses ?? DEFAULT_MAX_HYPOTHESES, "maxHypotheses");
  const graphNodeIds = new Set(input.graph.nodes.map((node) => node.id));
  const graphEdgeIds = new Set(input.graph.edges.map((edge) => edge.id));
  const candidates = validateHypothesisCandidates(input.candidates, { graphNodeIds, graphEdgeIds });
  const candidateById = new Map(candidates.map((candidate) => [candidate.id, candidate]));
  const staticHypotheses = selectHypotheses(
    validateStaticHypothesisRecords(input.staticHypotheses, {
      candidateIds: candidates.map((candidate) => candidate.id),
    }),
    maxHypotheses,
  );
  const validationRecipes = validateValidationRecipes(input.validationRecipes ?? [], {
    hypothesisIds: input.staticHypotheses.map((hypothesis) => hypothesis.id),
  });
  const recipesByHypothesisId = new Map(
    validationRecipes.map((recipe) => [recipe.hypothesisId, recipe]),
  );
  const nodesById = new Map(input.graph.nodes.map((node) => [node.id, node]));
  const evidenceById = new Map((input.evidence ?? []).map((evidence) => [evidence.id, evidence]));
  const fallback = validateHypothesisEnrichments(
    staticHypotheses.map((hypothesis) =>
      fallbackEnrichment(hypothesis, candidateById, recipesByHypothesisId, nodesById, evidenceById),
    ),
    { hypothesisIds: staticHypotheses.map((hypothesis) => hypothesis.id) },
  );

  if (fallback.length === 0 || !(await modelIsAvailable(input.model))) {
    return fallback;
  }

  const modelInput = modelInputFor({
    repositoryName: input.repositoryName,
    staticHypotheses,
    candidateById,
    graph: input.graph,
    validationRecipes: recipesByHypothesisId,
    findings: input.findings ?? [],
    evidence: input.evidence ?? [],
    catalogEnrichments: new Map(fallback.map((record) => [record.hypothesisId, record])),
  });
  const modelOutput = await input.model.enrichHypotheses(modelInput).catch(() => null);
  const modelEnrichments = validateModelOutput(modelOutput, fallback);
  if (modelEnrichments === null) {
    return fallback;
  }

  return validateHypothesisEnrichments(
    fallback.map((catalogRecord) => {
      const modelRecord = modelEnrichments.get(catalogRecord.hypothesisId);
      if (modelRecord === undefined) {
        throw new Error(`missing model enrichment for hypothesis ${catalogRecord.hypothesisId}`);
      }
      return {
        ...catalogRecord,
        source: "model",
        attackDescription: modelRecord.attackDescription,
        assumptions: modelRecord.assumptions,
        impact: modelRecord.impact,
        remediation: modelRecord.remediation,
        agentPrompt: modelRecord.agentPrompt,
        acceptanceCriteria: modelRecord.acceptanceCriteria,
        validationRecipeText: modelRecord.validationRecipeText,
      };
    }),
    { hypothesisIds: staticHypotheses.map((hypothesis) => hypothesis.id) },
  );
}

function modelInputFor(input: {
  readonly repositoryName: string;
  readonly staticHypotheses: ReadonlyArray<StaticHypothesis>;
  readonly candidateById: ReadonlyMap<string, HypothesisCandidate>;
  readonly graph: SecurityGraph;
  readonly validationRecipes: ReadonlyMap<string, ValidationRecipe>;
  readonly findings: ReadonlyArray<Finding>;
  readonly evidence: ReadonlyArray<Evidence>;
  readonly catalogEnrichments: ReadonlyMap<string, HypothesisEnrichment>;
}): ModelHypothesisEnrichBatchInput {
  const nodesById = new Map(input.graph.nodes.map((node) => [node.id, node]));
  const edgesById = new Map(input.graph.edges.map((edge) => [edge.id, edge]));
  const findingsById = new Map(input.findings.map((finding) => [finding.id, finding]));
  const evidenceById = new Map(input.evidence.map((evidence) => [evidence.id, evidence]));

  return {
    repositoryName: input.repositoryName,
    hypotheses: input.staticHypotheses.map((hypothesis) => {
      const candidate = requiredCandidate(hypothesis, input.candidateById);
      const catalogEnrichment = input.catalogEnrichments.get(hypothesis.id);
      if (catalogEnrichment === undefined) {
        throw new Error(`missing catalog enrichment for hypothesis ${hypothesis.id}`);
      }
      return modelHypothesisInput(
        hypothesis,
        candidate,
        nodesById,
        edgesById,
        findingsById,
        evidenceById,
        input.validationRecipes.get(hypothesis.id),
        catalogEnrichment,
      );
    }),
  };
}

function modelHypothesisInput(
  hypothesis: StaticHypothesis,
  candidate: HypothesisCandidate,
  nodesById: ReadonlyMap<string, SecurityGraphNode>,
  edgesById: ReadonlyMap<string, SecurityGraphEdge>,
  findingsById: ReadonlyMap<string, Finding>,
  evidenceById: ReadonlyMap<string, Evidence>,
  validationRecipe: ValidationRecipe | undefined,
  catalogEnrichment: HypothesisEnrichment,
): ModelHypothesisEnrichInput {
  return {
    hypothesisId: hypothesis.id,
    candidateId: candidate.id,
    family: candidate.family,
    ruleId: candidate.ruleId,
    title: hypothesis.title,
    status: hypothesis.status,
    staticConfidence: hypothesis.staticConfidence,
    pathSummary: hypothesis.pathSummary,
    runtimeValidationRequired: hypothesis.runtimeValidationRequired,
    candidateReason: candidate.candidateReason,
    findingIds: uniqueSorted(candidate.findingIds),
    supportingNodeIds: uniqueSorted(candidate.supportingNodeIds),
    supportingEdgeIds: uniqueSorted(candidate.supportingEdgeIds),
    contradictingNodeIds: uniqueSorted(candidate.contradictingNodeIds),
    contradictingEdgeIds: uniqueSorted(candidate.contradictingEdgeIds),
    coverageState: hypothesis.coverageState,
    coverageRefs: uniqueSorted(candidate.coverageRefs),
    requiredValidation: uniqueSorted(candidate.requiredValidation),
    graphRefs: graphRefsFor(candidate, nodesById, edgesById),
    observedControls: observedControlsFor(candidate, nodesById, edgesById),
    coverageGaps: coverageGapsFor(hypothesis, candidate),
    evidenceSnippets: evidenceSnippetsFor(hypothesis, candidate, findingsById, evidenceById),
    validationRecipe:
      validationRecipe === undefined ? null : modelValidationRecipeInput(validationRecipe),
    catalogEnrichment: toModelEnrichment(catalogEnrichment),
  };
}

function fallbackEnrichment(
  hypothesis: StaticHypothesis,
  candidateById: ReadonlyMap<string, HypothesisCandidate>,
  recipesByHypothesisId: ReadonlyMap<string, ValidationRecipe>,
  nodesById: ReadonlyMap<string, SecurityGraphNode>,
  evidenceById: ReadonlyMap<string, Evidence>,
): HypothesisEnrichment {
  const candidate = requiredCandidate(hypothesis, candidateById);
  const recipe = recipesByHypothesisId.get(hypothesis.id);
  const location = locateHypothesis(hypothesis, candidate, nodesById, evidenceById);

  return {
    id: hypothesisEnrichmentId(hypothesis.id),
    hypothesisId: hypothesis.id,
    source: "catalog",
    attackDescription: `${familyCopy(candidate).concern}${locationSentence(location)}`,
    assumptions: assumptionsText(hypothesis, candidate),
    impact: impactText(candidate.family, hypothesis),
    remediation: remediationText(candidate, location),
    agentPrompt: agentPrompt(candidate, location),
    acceptanceCriteria: acceptanceCriteria(recipe),
    validationRecipeText: validationRecipeText(recipe),
  };
}

function validateModelOutput(
  modelOutput: ReadonlyArray<ModelHypothesisEnrichment> | null,
  fallback: ReadonlyArray<HypothesisEnrichment>,
): Map<string, ModelHypothesisEnrichment> | null {
  if (modelOutput === null || modelOutput.length !== fallback.length) {
    return null;
  }
  const expectedIds = new Set(fallback.map((record) => record.hypothesisId));
  const seenIds = new Set<string>();
  const out = new Map<string, ModelHypothesisEnrichment>();

  for (const record of modelOutput) {
    if (!isRecord(record) || hasProhibitedFields(record)) {
      return null;
    }
    if (!expectedIds.has(record.hypothesisId) || seenIds.has(record.hypothesisId)) {
      return null;
    }
    const sanitized = sanitizeModelEnrichment(record);
    if (sanitized === null) {
      return null;
    }
    seenIds.add(record.hypothesisId);
    out.set(record.hypothesisId, sanitized);
  }

  return seenIds.size === expectedIds.size ? out : null;
}

function sanitizeModelEnrichment(
  record: ModelHypothesisEnrichment,
): ModelHypothesisEnrichment | null {
  const sanitized = {
    hypothesisId: requiredNonEmpty(record.hypothesisId),
    attackDescription: sanitizeModelText(record.attackDescription),
    assumptions: sanitizeModelTextArray(record.assumptions),
    impact: sanitizeModelText(record.impact),
    remediation: sanitizeModelText(record.remediation),
    agentPrompt: sanitizeModelText(record.agentPrompt),
    acceptanceCriteria: sanitizeModelTextArray(record.acceptanceCriteria),
    validationRecipeText: sanitizeModelText(record.validationRecipeText),
  };
  if (
    sanitized.hypothesisId === null ||
    sanitized.attackDescription === null ||
    sanitized.assumptions === null ||
    sanitized.impact === null ||
    sanitized.remediation === null ||
    sanitized.agentPrompt === null ||
    sanitized.acceptanceCriteria === null ||
    sanitized.validationRecipeText === null
  ) {
    return null;
  }

  return {
    hypothesisId: sanitized.hypothesisId,
    attackDescription: sanitized.attackDescription,
    assumptions: sanitized.assumptions,
    impact: sanitized.impact,
    remediation: sanitized.remediation,
    agentPrompt: sanitized.agentPrompt,
    acceptanceCriteria: sanitized.acceptanceCriteria,
    validationRecipeText: sanitized.validationRecipeText,
  };
}

function selectHypotheses(
  hypotheses: ReadonlyArray<StaticHypothesis>,
  maxHypotheses: number,
): StaticHypothesis[] {
  return [...hypotheses]
    .sort(
      (a, b) =>
        statusRank(b.status) - statusRank(a.status) ||
        b.staticConfidence - a.staticConfidence ||
        a.id.localeCompare(b.id),
    )
    .slice(0, maxHypotheses);
}

function statusRank(status: StaticHypothesis["status"]): number {
  switch (status) {
    case "statically_supported":
      return 3;
    case "candidate":
      return 2;
    case "inconclusive":
      return 1;
    case "statically_contradicted":
      return 0;
  }
}

function graphRefsFor(
  candidate: HypothesisCandidate,
  nodesById: ReadonlyMap<string, SecurityGraphNode>,
  edgesById: ReadonlyMap<string, SecurityGraphEdge>,
): ModelHypothesisGraphRefInput[] {
  return [
    ...uniqueSorted([...candidate.supportingNodeIds, ...candidate.contradictingNodeIds]).flatMap(
      (nodeId) => {
        const node = nodesById.get(nodeId);
        return node === undefined ? [] : [nodeRef(node)];
      },
    ),
    ...uniqueSorted([...candidate.supportingEdgeIds, ...candidate.contradictingEdgeIds]).flatMap(
      (edgeId) => {
        const edge = edgesById.get(edgeId);
        return edge === undefined ? [] : [edgeRef(edge)];
      },
    ),
  ].slice(0, MAX_GRAPH_REFS_PER_HYPOTHESIS);
}

function observedControlsFor(
  candidate: HypothesisCandidate,
  nodesById: ReadonlyMap<string, SecurityGraphNode>,
  edgesById: ReadonlyMap<string, SecurityGraphEdge>,
): ModelHypothesisGraphRefInput[] {
  return graphRefsFor(candidate, nodesById, edgesById).filter((ref) => {
    if (ref.refType === "node") {
      return ref.kind === "Control";
    }
    return ref.kind === "protected_by" || ref.kind === "contradicted_by";
  });
}

function nodeRef(node: SecurityGraphNode): ModelHypothesisGraphRefInput {
  return {
    refType: "node",
    id: node.id,
    kind: node.kind,
    label: node.label,
    ...(node.repoPath === undefined ? {} : { repoPath: node.repoPath }),
    ...(node.lineRange === undefined ? {} : { lineRange: node.lineRange }),
  };
}

function edgeRef(edge: SecurityGraphEdge): ModelHypothesisGraphRefInput {
  return {
    refType: "edge",
    id: edge.id,
    kind: edge.kind,
    fromNodeId: edge.fromNodeId,
    toNodeId: edge.toNodeId,
  };
}

function coverageGapsFor(hypothesis: StaticHypothesis, candidate: HypothesisCandidate): string[] {
  return uniqueSorted([
    ...candidate.coverageRefs.filter((ref) => !ref.endsWith(":checked")),
    ...(hypothesis.coverageState === "checked"
      ? []
      : [`static_coverage:${hypothesis.coverageState}`]),
    ...(hypothesis.status === "inconclusive" ? [hypothesis.pathSummary] : []),
  ]);
}

function evidenceSnippetsFor(
  hypothesis: StaticHypothesis,
  candidate: HypothesisCandidate,
  findingsById: ReadonlyMap<string, Finding>,
  evidenceById: ReadonlyMap<string, Evidence>,
): ModelHypothesisEvidenceSnippetInput[] {
  const evidenceIds = uniqueStable([
    ...hypothesis.supportingEvidenceIds,
    ...hypothesis.contradictingEvidenceIds,
    ...candidate.findingIds.flatMap((findingId) => findingsById.get(findingId)?.evidenceIds ?? []),
  ]);

  return evidenceIds
    .flatMap((evidenceId) => {
      const evidence = evidenceById.get(evidenceId);
      return evidence === undefined ? [] : [modelEvidenceSnippet(evidence)];
    })
    .slice(0, MAX_EVIDENCE_SNIPPETS_PER_HYPOTHESIS);
}

function modelEvidenceSnippet(evidence: Evidence): ModelHypothesisEvidenceSnippetInput {
  return {
    evidenceId: evidence.id,
    tool: evidence.tool,
    filePath: evidence.filePath,
    startLine: evidence.startLine,
    endLine: evidence.endLine,
    snippet: truncateForModel(redactSecrets(evidence.snippet)),
  };
}

function modelValidationRecipeInput(
  recipe: ValidationRecipe,
): ModelHypothesisValidationRecipeInput {
  return {
    recipeId: recipe.id,
    requiredFixtures: recipe.requiredFixtures,
    steps: recipe.steps,
    expectedResult: recipe.expectedResult,
    safetyNotes: recipe.safetyNotes,
    knownGaps: recipe.knownGaps,
  };
}

function validationRecipeText(recipe: ValidationRecipe | undefined): string {
  if (recipe === undefined) {
    return "No runtime validation recipe was generated for this hypothesis.";
  }
  return [
    `Required fixtures: ${recipe.requiredFixtures.join(", ")}.`,
    `Steps: ${recipe.steps.join(" ")}`,
    `Expected result: ${recipe.expectedResult}`,
    `Safety notes: ${recipe.safetyNotes.join(" ")}`,
    ...(recipe.knownGaps.length === 0 ? [] : [`Known gaps: ${recipe.knownGaps.join(" ")}`]),
  ].join("\n");
}

function toModelEnrichment(record: HypothesisEnrichment): ModelHypothesisEnrichment {
  return {
    hypothesisId: record.hypothesisId,
    attackDescription: record.attackDescription,
    assumptions: record.assumptions,
    impact: record.impact,
    remediation: record.remediation,
    agentPrompt: record.agentPrompt,
    acceptanceCriteria: record.acceptanceCriteria,
    validationRecipeText: record.validationRecipeText,
  };
}

function impactText(family: string, hypothesis: StaticHypothesis): string {
  switch (family) {
    case "external_input_to_dangerous_operation":
      return "User-controlled input may reach a dangerous operation unless a validated control blocks this path.";
    case "sast_reachable_path":
      return "A direct static finding appears reachable from analyzed application entry points.";
    case "dependency_usage_path":
      return "A vulnerable component is connected to observed code usage and may matter more than a presence-only dependency finding.";
    case "ci_supply_chain_path":
      return "Build automation may reach mutable or privileged resources and could affect release integrity.";
    case "secret_impact_chain":
      return "A secret context may reach a privileged integration or exposed resource, increasing operational impact.";
    default:
      return `Static graph evidence produced ${hypothesis.status} support for this hypothesis.`;
  }
}

interface HypothesisLocation {
  readonly source?: string | undefined;
  readonly sink?: string | undefined;
  readonly spots: ReadonlyArray<string>;
}

interface FamilyCopy {
  readonly concern: string;
  readonly fix: string;
}

const FAMILY_COPY: Readonly<Record<string, FamilyCopy>> = {
  external_input_to_dangerous_operation: {
    concern:
      "Untrusted input can reach a sensitive operation in this project without a validated check in between.",
    fix: "Validate, escape, or allowlist the untrusted value before it reaches that operation — or confirm an existing check already covers this case.",
  },
  sast_reachable_path: {
    concern: "A scanner flagged code that looks reachable from how this app is entered.",
    fix: "Fix the flagged code and make sure nothing else reachable still hits the same unsafe pattern.",
  },
  dependency_usage_path: {
    concern:
      "A vulnerable dependency is actually used by this code, not just listed in the manifest.",
    fix: "Upgrade or replace the affected dependency, or stop calling the vulnerable API at these call sites.",
  },
  ci_supply_chain_path: {
    concern: "A build or CI step can reach privileged or mutable resources.",
    fix: "Pin the step and cut its privileges so it cannot reach resources it should not touch during a release.",
  },
  secret_impact_chain: {
    concern: "A secret is connected to a privileged integration or an exposed resource.",
    fix: "Scope the secret down and make sure it cannot reach the exposed resource without a control in front of it.",
  },
};

function familyCopy(candidate: HypothesisCandidate): FamilyCopy {
  return (
    FAMILY_COPY[candidate.family] ?? {
      concern: candidate.title,
      fix: "Add or verify a control that breaks this path.",
    }
  );
}

function assumptionsText(hypothesis: StaticHypothesis, candidate: HypothesisCandidate): string[] {
  return [
    `Static analysis supports this path with about ${Math.round(
      hypothesis.staticConfidence * 100,
    )}% confidence; it has not been confirmed by running the app.`,
    candidate.findingIds.length === 0
      ? "No Quick Scan finding is directly linked to this path."
      : "A Quick Scan finding is linked to this path.",
  ];
}

function remediationText(candidate: HypothesisCandidate, location: HypothesisLocation): string {
  const { fix } = familyCopy(candidate);
  const where =
    location.spots.length === 0 ? "" : ` Focus on ${location.spots.slice(0, 4).join(", ")}.`;
  return `${fix}${where}`;
}

function agentPrompt(candidate: HypothesisCandidate, location: HypothesisLocation): string {
  const { concern, fix } = familyCopy(candidate);
  return [
    `${concern}${locationSentence(location)}`,
    fix,
    "This was found by static analysis, which did not run your app — confirm the path is real, make the change, then re-check that it closes the path.",
  ].join(" ");
}

function acceptanceCriteria(recipe: ValidationRecipe | undefined): string[] {
  return [
    "The untrusted path is blocked by a validated control, or shown not to be reachable.",
    "The change is checked against the real code, not just this report.",
    recipe === undefined
      ? "Runtime confirmation is still open — treat this path as unproven until the running app is exercised."
      : `Runtime confirmation can later use these fixtures: ${recipe.requiredFixtures.join(", ")}.`,
  ];
}

function locateHypothesis(
  hypothesis: StaticHypothesis,
  candidate: HypothesisCandidate,
  nodesById: ReadonlyMap<string, SecurityGraphNode>,
  evidenceById: ReadonlyMap<string, Evidence>,
): HypothesisLocation {
  const nodes = candidate.supportingNodeIds.flatMap((id) => {
    const node = nodesById.get(id);
    return node === undefined ? [] : [node];
  });
  const source = nodeLocation(
    nodes.find((node) => node.kind === "Source" || node.kind === "Boundary"),
  );
  const sink = nodeLocation(nodes.find((node) => node.kind === "Sink"));
  const spots = uniqueStable([
    ...nodes.flatMap((node) => {
      const value = nodeLocation(node);
      return value === undefined ? [] : [value];
    }),
    ...hypothesis.supportingEvidenceIds.flatMap((id) => {
      const evidence = evidenceById.get(id);
      return evidence === undefined ? [] : [`${evidence.filePath}:${evidence.startLine}`];
    }),
  ]);
  return { source, sink, spots };
}

function nodeLocation(node: SecurityGraphNode | undefined): string | undefined {
  if (node === undefined || node.repoPath === undefined) {
    return undefined;
  }
  if (node.lineRange === undefined) {
    return node.repoPath;
  }
  const { startLine, endLine } = node.lineRange;
  const lines = startLine === endLine ? `${startLine}` : `${startLine}-${endLine}`;
  return `${node.repoPath}:${lines}`;
}

function locationSentence(location: HypothesisLocation): string {
  if (
    location.source !== undefined &&
    location.sink !== undefined &&
    location.source !== location.sink
  ) {
    return ` It starts at ${location.source} and reaches ${location.sink}.`;
  }
  if (location.sink !== undefined) {
    return ` The operation is at ${location.sink}.`;
  }
  if (location.source !== undefined) {
    return ` It starts at ${location.source}.`;
  }
  if (location.spots.length > 0) {
    return ` Relevant code: ${location.spots.slice(0, 4).join(", ")}.`;
  }
  return "";
}

function requiredCandidate(
  hypothesis: StaticHypothesis,
  candidateById: ReadonlyMap<string, HypothesisCandidate>,
): HypothesisCandidate {
  const candidate = candidateById.get(hypothesis.candidateId);
  if (candidate === undefined) {
    throw new Error(
      `staticHypothesis ${hypothesis.id} references unknown candidate: ${hypothesis.candidateId}`,
    );
  }
  return candidate;
}

async function modelIsAvailable(model: ModelProvider): Promise<boolean> {
  return await model.isAvailable().catch(() => false);
}

function hasProhibitedFields(record: Readonly<Record<string, unknown>>): boolean {
  return Object.keys(record).some((field) => PROHIBITED_MODEL_FIELDS.has(field));
}

function sanitizeModelTextArray(values: ReadonlyArray<string>): string[] | null {
  if (!Array.isArray(values) || values.length === 0) {
    return null;
  }
  const sanitized = values.map(sanitizeModelText);
  if (sanitized.some((value) => value === null)) {
    return null;
  }
  return sanitized as string[];
}

function sanitizeModelText(value: string): string | null {
  const nonEmpty = requiredNonEmpty(value);
  if (nonEmpty === null) {
    return null;
  }
  const redacted = redactSecrets(nonEmpty);
  return modelTextIsSafe(redacted) ? redacted : null;
}

function requiredNonEmpty(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function modelTextIsSafe(value: string): boolean {
  if (/(^|[\s"'`(])(?:\/(?:tmp|work|Users|home|root|etc|var)\b|[A-Za-z]:\\|\.\.)/.test(value)) {
    return false;
  }
  return !/\b(?:confirmed|exploited|proved|proven)\b/i.test(value);
}

function redactSecrets(text: string): string {
  return text
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "***REDACTED***")
    .replace(/\b(?:sk|ghp|github_pat|AKIA|AIza)[A-Za-z0-9_-]{12,}\b/g, "***REDACTED***")
    .replace(
      /\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|passwd|pwd)\s*[:=]\s*["']?)[^"',\s\\]{8,}/gi,
      "$1***REDACTED***",
    );
}

function truncateForModel(value: string): string {
  if (value.length <= MODEL_SNIPPET_CHAR_LIMIT) {
    return value;
  }
  return `${value.slice(0, MODEL_SNIPPET_CHAR_LIMIT)}... [truncated]`;
}

function positiveInt(value: number, label: string): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function uniqueStable(values: ReadonlyArray<string>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    if (!seen.has(value)) {
      seen.add(value);
      out.push(value);
    }
  }
  return out;
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
