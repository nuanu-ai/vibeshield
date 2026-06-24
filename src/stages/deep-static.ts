import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { AtomProgramAnalysisBackend } from "../adapters/atom-program-analysis-backend.js";
import type { DeepActionGroup } from "../domain/action-group.js";
import type { ComponentReachability } from "../domain/component-reachability.js";
import type { DeepCoverage } from "../domain/deep-coverage.js";
import type { Finding, FindingCluster } from "../domain/finding.js";
import type { FindingContextAssessment } from "../domain/finding-context-assessment.js";
import type { HypothesisCandidate } from "../domain/hypothesis-candidate.js";
import type { HypothesisEnrichment } from "../domain/hypothesis-enrichment.js";
import type { Manifest } from "../domain/manifest.js";
import type { RepositoryMap } from "../domain/repository-map.js";
import type { ArtifactRef, StageId } from "../domain/run.js";
import type { SecurityGraph } from "../domain/security-graph.js";
import { securityGraphId, validateSecurityGraph } from "../domain/security-graph.js";
import type { StaticHypothesis } from "../domain/static-hypothesis.js";
import type { ValidationRecipe } from "../domain/validation-recipe.js";
import type { StageContext, StageDefinition, StageResult } from "../pipeline/stage-definition.js";
import type {
  ProgramAnalysisExtractionArtifact,
  ProgramAnalysisFailure,
  ProgramAnalysisModelRef,
} from "../ports/program-analysis-backend.js";
import { composeComponentReachability } from "./component-reachability.js";
import { groupDeepActions } from "./deep-action-grouping.js";
import { composeDeepCoverage } from "./deep-coverage.js";
import { assessFindingContext, type FindingHypothesisLink } from "./finding-context-assessment.js";
import { enrichStaticHypotheses } from "./hypothesis-enrichment.js";
import { composeProgramAnalysisGraph } from "./program-analysis-graph.js";
import { composeQuickScanGraph } from "./quick-scan-graph-import.js";
import { renderRepositoryMap } from "./repository-map.js";
import { correlateStage2Hypotheses } from "./stage2-hypothesis-rules.js";
import { validateStaticHypotheses } from "./static-hypothesis-validator.js";
import { composeValidationRecipes } from "./validation-recipes.js";

export const DEEP_STATIC_STAGE_ID = "deep.static.compose";

const GRAPH_VERSION = "deep-static-v1";
const encoder = new TextEncoder();

export interface DeepStaticData {
  readonly securityGraph: SecurityGraph;
  readonly deepCoverage: DeepCoverage;
  readonly findingContextAssessments: ReadonlyArray<FindingContextAssessment>;
  readonly hypothesisCandidates: ReadonlyArray<HypothesisCandidate>;
  readonly staticHypotheses: ReadonlyArray<StaticHypothesis>;
  readonly validationRecipes: ReadonlyArray<ValidationRecipe>;
  readonly deepActionGroups: ReadonlyArray<DeepActionGroup>;
  readonly repositoryMap: RepositoryMap;
  readonly repositoryMapArtifactRef: ArtifactRef;
  readonly repositoryMapPath: string;
  readonly limitations: ReadonlyArray<string>;
}

interface SourceResolveData {
  readonly sourceDir: string;
}

interface ManifestData {
  readonly manifest: Manifest;
}

interface NormalizeData {
  readonly evidence: FindingEvidence[];
  readonly findings: Finding[];
}

interface FindingEvidence {
  readonly id: string;
  readonly rawArtifactBlobSha256: string;
  readonly filePath: string;
  readonly startLine: number;
  readonly endLine: number;
  readonly snippet: string;
  readonly snippetHash: string;
  readonly tool: string;
}

interface CorrelateData {
  readonly clusters: ReadonlyArray<FindingCluster>;
}

interface ActionsData {
  readonly candidates: ReadonlyArray<{
    readonly id: string;
    readonly remediationKey: string;
    readonly priorityScore: number;
    readonly findingIds: ReadonlyArray<string>;
    readonly evidenceIds: ReadonlyArray<string>;
    readonly affectedFiles: ReadonlyArray<string>;
    readonly verdictImpact: "blocks-deploy" | "degrades" | "informational";
  }>;
}

export function deepStaticStage(): StageDefinition {
  return {
    id: DEEP_STATIC_STAGE_ID,
    version: "1",
    dependencies: [
      "source.resolve",
      "snapshot.manifest",
      "findings.normalize",
      "findings.correlate",
      "actions.rank",
    ],
    inputs: [],
    outputs: ["repository-map.json"],
    required: true,
    run: async (ctx) => {
      const data = await composeDeepStaticData(ctx);
      return success(data as unknown as Readonly<Record<string, unknown>>, [
        data.repositoryMapArtifactRef,
      ]);
    },
  };
}

export const HYPOTHESIS_ENRICH_STAGE_ID = "hypotheses.enrich";

export interface HypothesisEnrichData {
  readonly hypothesisEnrichments: ReadonlyArray<HypothesisEnrichment>;
}

/**
 * LLM enrichment of the deterministic Deep Static hypotheses. Runs after every
 * scan and the deterministic graph build so the report-copy step is the last
 * thing in the pipeline. Degrades to no enrichment rather than failing the run.
 */
export function hypothesisEnrichStage(): StageDefinition {
  return {
    id: HYPOTHESIS_ENRICH_STAGE_ID,
    version: "1",
    dependencies: ["snapshot.manifest", "findings.normalize", DEEP_STATIC_STAGE_ID],
    inputs: [],
    outputs: [],
    required: true,
    run: async (ctx) => {
      const { manifest } = readInput<ManifestData>(ctx, "snapshot.manifest");
      const { evidence, findings } = readInput<NormalizeData>(ctx, "findings.normalize");
      const deep = readInput<DeepStaticData>(ctx, DEEP_STATIC_STAGE_ID);
      const hypothesisEnrichments = await enrichHypothesesOrDegrade({
        ctx,
        manifest,
        evidence,
        findings,
        graph: deep.securityGraph,
        candidates: deep.hypothesisCandidates,
        staticHypotheses: deep.staticHypotheses,
        validationRecipes: deep.validationRecipes,
      });
      return success({ hypothesisEnrichments } satisfies HypothesisEnrichData);
    },
  };
}

async function enrichHypothesesOrDegrade(input: {
  readonly ctx: StageContext;
  readonly manifest: Manifest;
  readonly evidence: ReadonlyArray<FindingEvidence>;
  readonly findings: ReadonlyArray<Finding>;
  readonly graph: SecurityGraph;
  readonly candidates: ReadonlyArray<HypothesisCandidate>;
  readonly staticHypotheses: ReadonlyArray<StaticHypothesis>;
  readonly validationRecipes: ReadonlyArray<ValidationRecipe>;
}): Promise<HypothesisEnrichment[]> {
  if (input.staticHypotheses.length === 0) {
    return [];
  }
  try {
    return await enrichStaticHypotheses({
      repositoryName: repositoryName(input.manifest),
      model: input.ctx.model,
      staticHypotheses: input.staticHypotheses,
      candidates: input.candidates,
      graph: input.graph,
      validationRecipes: input.validationRecipes,
      findings: input.findings,
      evidence: input.evidence,
    });
  } catch {
    return [];
  }
}

async function composeDeepStaticData(ctx: StageContext): Promise<DeepStaticData> {
  const createdAt = new Date().toISOString();
  const { sourceDir } = readInput<SourceResolveData>(ctx, "source.resolve");
  const { manifest } = readInput<ManifestData>(ctx, "snapshot.manifest");
  const { evidence, findings } = readInput<NormalizeData>(ctx, "findings.normalize");
  const { clusters } = readInput<CorrelateData>(ctx, "findings.correlate");
  const { candidates: directActions } = readInput<ActionsData>(ctx, "actions.rank");
  const snapshotId = manifest.sourceHash;
  const backend = new AtomProgramAnalysisBackend({
    session: ctx.session,
    artifacts: ctx.artifacts,
  });
  const backendFailures: ProgramAnalysisFailure[] = [];
  const compositionFailures: ProgramAnalysisFailure[] = [];

  let model: ProgramAnalysisModelRef | undefined;
  let programGraph: SecurityGraph | undefined;

  try {
    model = await backend.buildModel({ sourceDir, manifest });
    const artifacts = await extractProgramArtifacts(backend, model);
    programGraph = composeProgramAnalysisGraph({
      runId: ctx.runId,
      snapshotId,
      graphVersion: GRAPH_VERSION,
      manifest,
      artifacts,
      createdAt,
    });
  } catch (error) {
    backendFailures.push({
      area: "model",
      reason: publicReason("Deep Static program analysis failed", error),
    });
  }

  const backendCoverage = backend.reportCoverage({
    manifest,
    ...(model === undefined ? {} : { model }),
    ...(backendFailures.length === 0 ? {} : { failures: backendFailures }),
  });

  const graph = composeGraphOrFallback({
    ctx,
    manifest,
    evidence,
    findings,
    clusters,
    createdAt,
    baseGraph: programGraph,
    failures: compositionFailures,
  });
  const reachability = composeReachabilityOrDegrade({
    graph,
    manifest,
    failures: compositionFailures,
  });

  const correlated = await correlateOrDegrade({
    ctx,
    manifest,
    evidence,
    findings,
    graph: reachability.graph,
    componentReachability: reachability.componentReachability,
    directActions,
    failures: compositionFailures,
  });

  const repositoryMap = renderRepositoryMap(reachability.graph);
  const repositoryMapPath = path.join(ctx.runDir, "repository-map.json");
  await mkdir(ctx.runDir, { recursive: true });
  const repositoryMapBytes = jsonBytes(repositoryMap);
  await writeFile(repositoryMapPath, repositoryMapBytes);
  const repositoryMapBlob = await ctx.artifacts.store(repositoryMapBytes);
  const repositoryMapArtifactRef = artifactRef(
    repositoryMapBlob.sha256,
    "repository-map.json",
    repositoryMapBlob.bytes,
  );

  const deepCoverage = composeDeepCoverage({
    runId: ctx.runId,
    snapshotId,
    manifest,
    backendCoverage,
    graphCoverage: reachability.graph.coverage,
    failures: compositionFailures,
    createdAt,
  });

  return {
    securityGraph: reachability.graph,
    deepCoverage,
    findingContextAssessments: correlated.findingContextAssessments,
    hypothesisCandidates: correlated.hypothesisCandidates,
    staticHypotheses: correlated.staticHypotheses,
    validationRecipes: correlated.validationRecipes,
    deepActionGroups: correlated.deepActionGroups,
    repositoryMap,
    repositoryMapArtifactRef,
    repositoryMapPath,
    limitations: limitationsFrom(deepCoverage),
  };
}

async function extractProgramArtifacts(
  backend: AtomProgramAnalysisBackend,
  model: ProgramAnalysisModelRef,
): Promise<ProgramAnalysisExtractionArtifact[]> {
  return [
    await backend.extractEntities(model),
    await backend.extractBoundaries(model),
    await backend.extractCallEdges(model),
    await backend.extractFlows(model),
    await backend.extractComponentUsage(model),
  ];
}

function composeGraphOrFallback(input: {
  readonly ctx: StageContext;
  readonly manifest: Manifest;
  readonly evidence: ReadonlyArray<FindingEvidence>;
  readonly findings: ReadonlyArray<Finding>;
  readonly clusters: CorrelateData["clusters"];
  readonly createdAt: string;
  readonly baseGraph: SecurityGraph | undefined;
  readonly failures: ProgramAnalysisFailure[];
}): SecurityGraph {
  try {
    return composeQuickScanGraph({
      runId: input.ctx.runId,
      snapshotId: input.manifest.sourceHash,
      graphVersion: GRAPH_VERSION,
      manifest: input.manifest,
      evidence: input.evidence,
      findings: input.findings,
      clusters: input.clusters,
      createdAt: input.createdAt,
      ...(input.baseGraph === undefined ? {} : { baseGraph: input.baseGraph }),
    });
  } catch (error) {
    input.failures.push({
      area: "entities",
      reason: publicReason("Deep Static graph composition failed", error),
    });
    return validateSecurityGraph(
      {
        id: securityGraphId(input.manifest.sourceHash, GRAPH_VERSION),
        runId: input.ctx.runId,
        snapshotId: input.manifest.sourceHash,
        graphVersion: GRAPH_VERSION,
        nodes: [],
        edges: [],
        flows: [],
        coverage: [],
        createdAt: input.createdAt,
      },
      { manifestPaths: input.manifest.files.map((file) => file.path), evidenceIds: [] },
    );
  }
}

function composeReachabilityOrDegrade(input: {
  readonly graph: SecurityGraph;
  readonly manifest: Manifest;
  readonly failures: ProgramAnalysisFailure[];
}): {
  readonly graph: SecurityGraph;
  readonly componentReachability: ReadonlyArray<ComponentReachability>;
} {
  try {
    const result = composeComponentReachability({
      graph: input.graph,
      manifest: input.manifest,
    });
    return { graph: result.graph, componentReachability: result.reachability };
  } catch (error) {
    input.failures.push({
      area: "component_usage",
      reason: publicReason("Deep Static component reachability failed", error),
    });
    return { graph: input.graph, componentReachability: [] };
  }
}

async function correlateOrDegrade(input: {
  readonly ctx: StageContext;
  readonly manifest: Manifest;
  readonly evidence: ReadonlyArray<FindingEvidence>;
  readonly findings: ReadonlyArray<Finding>;
  readonly graph: SecurityGraph;
  readonly componentReachability: ReadonlyArray<ComponentReachability>;
  readonly directActions: ActionsData["candidates"];
  readonly failures: ProgramAnalysisFailure[];
}): Promise<
  Omit<
    DeepStaticData,
    | "securityGraph"
    | "deepCoverage"
    | "repositoryMap"
    | "repositoryMapArtifactRef"
    | "repositoryMapPath"
    | "limitations"
  >
> {
  try {
    const firstPassContexts = findingContextOrStandalone(
      input.findings,
      input.graph,
      [],
      input.componentReachability,
    );
    const hypothesisCandidates = correlateStage2Hypotheses({
      graph: input.graph,
      findingContexts: firstPassContexts,
      maxCandidatesPerRule: 5,
    });
    const staticHypotheses = validateStaticHypotheses({
      graph: input.graph,
      candidates: hypothesisCandidates,
    });
    const findingContextAssessments = findingContextOrStandalone(
      input.findings,
      input.graph,
      hypothesisLinks(hypothesisCandidates, staticHypotheses),
      input.componentReachability,
    );
    const validationRecipes = composeValidationRecipes({
      staticHypotheses,
      candidates: hypothesisCandidates,
    });
    const deepActionGroups = groupDeepActions({
      directActions: input.directActions,
      staticHypotheses,
      candidates: hypothesisCandidates,
      findingContexts: findingContextAssessments,
    });
    return {
      findingContextAssessments,
      hypothesisCandidates,
      staticHypotheses,
      validationRecipes,
      deepActionGroups,
    };
  } catch (error) {
    input.failures.push({
      area: "model",
      reason: publicReason("Deep Static hypothesis composition failed", error),
    });
    return {
      findingContextAssessments: standaloneContexts(input.findings),
      hypothesisCandidates: [],
      staticHypotheses: [],
      validationRecipes: [],
      deepActionGroups: groupDeepActions({
        directActions: input.directActions,
        staticHypotheses: [],
        candidates: [],
        findingContexts: [],
      }),
    };
  }
}

function findingContextOrStandalone(
  findings: ReadonlyArray<Finding>,
  graph: SecurityGraph,
  links: ReadonlyArray<FindingHypothesisLink>,
  componentReachability: ReadonlyArray<ComponentReachability> = [],
): FindingContextAssessment[] {
  try {
    return assessFindingContext({
      findings,
      graph,
      hypothesisLinks: links,
      componentReachability,
    });
  } catch {
    return standaloneContexts(findings);
  }
}

function standaloneContexts(findings: ReadonlyArray<Finding>): FindingContextAssessment[] {
  return findings
    .map((finding) => ({
      findingId: finding.id,
      status: "standalone" as const,
      graphNodeIds: [],
      graphEdgeIds: [],
      hypothesisIds: [],
      reason: "Deep Static graph context was unavailable for this finding.",
      coverageState: "failed" as const,
    }))
    .sort((a, b) => a.findingId.localeCompare(b.findingId));
}

function hypothesisLinks(
  candidates: ReadonlyArray<HypothesisCandidate>,
  hypotheses: ReadonlyArray<StaticHypothesis>,
): FindingHypothesisLink[] {
  const candidateById = new Map(candidates.map((candidate) => [candidate.id, candidate]));
  return hypotheses
    .filter((hypothesis) => hypothesis.status !== "statically_contradicted")
    .flatMap((hypothesis) => {
      const candidate = candidateById.get(hypothesis.candidateId);
      if (candidate === undefined) {
        return [];
      }
      return candidate.findingIds.map((findingId) => ({
        findingId,
        hypothesisId: hypothesis.id,
        graphNodeIds: candidate.supportingNodeIds,
        graphEdgeIds: candidate.supportingEdgeIds,
        reason: `Finding shares deterministic static candidate ${candidate.id}.`,
      }));
    });
}

function limitationsFrom(coverage: DeepCoverage): string[] {
  return coverage.entries
    .filter((entry) => entry.state !== "checked")
    .map(
      (entry) =>
        `Deep Static ${entry.area} coverage is ${entry.state}${
          entry.reason === undefined ? "." : `: ${entry.reason}`
        }`,
    );
}

function repositoryName(manifest: Manifest): string {
  if (manifest.origin.kind === "github") {
    const url = new URL(manifest.origin.url);
    return (
      url.pathname
        .replace(/\.git$/, "")
        .split("/")
        .filter(Boolean)
        .at(-1) ?? "repository"
    );
  }
  return path.basename(manifest.origin.path) || "repository";
}

function publicReason(prefix: string, error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return `${prefix}: ${message}`;
}

function success(
  data: Readonly<Record<string, unknown>>,
  outputs: ArtifactRef[] = [],
): StageResult {
  return { status: "success", outputs, data };
}

function readInput<T>(ctx: StageContext, stageId: StageId): T {
  const data = ctx.inputs.get(stageId);
  if (data === undefined) {
    throw new Error(`Missing stage input: ${stageId}`);
  }
  return data as unknown as T;
}

function artifactRef(blobSha256: string, role: ArtifactRef["role"], bytes: number): ArtifactRef {
  return { blobSha256, role, bytes };
}

function jsonBytes(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value, null, 2));
}
