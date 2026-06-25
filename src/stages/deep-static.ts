import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { JoernProgramAnalysisBackend } from "../adapters/joern-program-analysis-backend.js";
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
import type {
  LineRange,
  SecurityGraph,
  SecurityGraphValidationContext,
} from "../domain/security-graph.js";
import { securityGraphId, validateSecurityGraph } from "../domain/security-graph.js";
import type { StaticHypothesis } from "../domain/static-hypothesis.js";
import type { ValidationRecipe } from "../domain/validation-recipe.js";
import type { StageContext, StageDefinition, StageResult } from "../pipeline/stage-definition.js";
import type {
  ProgramAnalysisCoverageArea,
  ProgramAnalysisExtractionArtifact,
  ProgramAnalysisExtractionKind,
  ProgramAnalysisFailure,
  ProgramAnalysisModelRef,
} from "../ports/program-analysis-backend.js";
import {
  type CiArtifactObservation,
  type CiStepObservation,
  type CiTokenPermissionObservation,
  type CiTriggerObservation,
  type CiWorkflowObservation,
  composeCiIacContext,
  type IacResourceObservation,
} from "./ci-iac-context.js";
import {
  type ComponentDependencyObservation,
  type ComponentUsageObservation,
  composeComponentReachability,
} from "./component-reachability.js";
import {
  type ContentResourceObservation,
  composeContentResourceContext,
  contentResourceObservationsFromPath,
  contentResourceObservationsFromText,
  isContentResourceTextPath,
} from "./content-resource-context.js";
import { groupDeepActions } from "./deep-action-grouping.js";
import { composeDeepCoverage } from "./deep-coverage.js";
import { assessFindingContext, type FindingHypothesisLink } from "./finding-context-assessment.js";
import { enrichStaticHypotheses } from "./hypothesis-enrichment.js";
import {
  JOERN_BOUNDARIES_SLICE_PATH,
  JOERN_CALL_EDGES_SLICE_PATH,
  JOERN_COMPONENT_USAGE_SLICE_PATH,
} from "./paths.js";
import { composeProgramAnalysisGraph } from "./program-analysis-graph.js";
import { composeQuickScanGraph } from "./quick-scan-graph-import.js";
import { renderRepositoryMap } from "./repository-map.js";
import {
  composeSmartContractContext,
  isSolidityPath,
  type SmartContractRiskObservation,
  smartContractRiskObservationsFromText,
} from "./smart-contract-context.js";
import { correlateStage2Hypotheses } from "./stage2-hypothesis-rules.js";
import { validateStaticHypotheses } from "./static-hypothesis-validator.js";
import { composeValidationRecipes } from "./validation-recipes.js";

export const DEEP_STATIC_STAGE_ID = "deep.static.compose";

const GRAPH_VERSION = "deep-static-v1";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

interface ProgramArtifactExtractionResult {
  readonly artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>;
  readonly failures: ReadonlyArray<ProgramAnalysisFailure>;
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
      onModelProgress: (progress) => {
        emitHypothesisEnrichProgress(input.ctx, progress);
      },
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
  const backend = new JoernProgramAnalysisBackend({
    session: ctx.session,
    artifacts: ctx.artifacts,
    events: ctx.events,
  });
  const backendFailures: ProgramAnalysisFailure[] = [];
  const compositionFailures: ProgramAnalysisFailure[] = [];

  let model: ProgramAnalysisModelRef | undefined;
  let programGraph: SecurityGraph | undefined;
  let programArtifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact> = [];

  try {
    model = await backend.buildModel({ sourceDir, manifest });
  } catch (error) {
    backendFailures.push({
      area: "model",
      reason: publicReason("Deep Static program analysis failed", error),
    });
  }
  if (model !== undefined) {
    const extracted = await extractProgramArtifacts(backend, model);
    programArtifacts = extracted.artifacts;
    backendFailures.push(...extracted.failures);
    if (extracted.artifacts.length > 0) {
      emitDeepProgress(ctx, "Assembling the security graph");
      try {
        programGraph = composeProgramAnalysisGraph({
          runId: ctx.runId,
          snapshotId,
          graphVersion: GRAPH_VERSION,
          manifest,
          artifacts: extracted.artifacts,
          createdAt,
        });
      } catch (error) {
        compositionFailures.push({
          area: "model",
          reason: publicReason("Deep Static graph assembly failed", error),
        });
      }
    }
  }

  const backendCoverage = backend
    .reportCoverage({
      manifest,
      ...(model === undefined ? {} : { model }),
      ...(backendFailures.length === 0 ? {} : { failures: backendFailures }),
    })
    .concat(componentUsageCoverage(programArtifacts));

  const graph = composeGraphOrFallback({
    ctx,
    sourceDir,
    manifest,
    evidence,
    findings,
    clusters,
    createdAt,
    baseGraph: programGraph,
    failures: compositionFailures,
  });
  const graphWithCiIac = await composeCiIacOrDegrade({
    ctx,
    sourceDir,
    manifest,
    findings,
    graph,
    failures: compositionFailures,
  });
  emitDeepProgress(ctx, "Checking hidden content and assets");
  const graphWithContentResources = await composeContentResourcesOrDegrade({
    ctx,
    sourceDir,
    manifest,
    graph: graphWithCiIac,
    failures: compositionFailures,
  });
  emitDeepProgress(ctx, "Checking smart contracts");
  const graphWithSmartContracts = await composeSmartContractsOrDegrade({
    ctx,
    sourceDir,
    manifest,
    graph: graphWithContentResources,
    failures: compositionFailures,
  });
  emitDeepProgress(ctx, "Checking reachability");
  const dependencyObservations = await componentDependencyObservationsFromEvidence({
    ctx,
    manifest,
    evidence,
    findings,
    failures: compositionFailures,
  });
  const reachability = composeReachabilityOrDegrade({
    graph: graphWithSmartContracts,
    manifest,
    artifacts: programArtifacts,
    dependencyObservations,
    failures: compositionFailures,
  });

  emitDeepProgress(ctx, "Looking for likely attack paths");
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

  emitDeepProgress(ctx, "Writing the Deep Static map");
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
  await persistDeepStaticState({
    ctx,
    manifest,
    evidence,
    graph: reachability.graph,
    artifacts: programArtifacts,
    deepCoverage,
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

async function persistDeepStaticState(input: {
  readonly ctx: StageContext;
  readonly manifest: Manifest;
  readonly evidence: ReadonlyArray<FindingEvidence>;
  readonly graph: SecurityGraph;
  readonly artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>;
  readonly deepCoverage: DeepCoverage;
}): Promise<void> {
  await input.ctx.state.recordSecurityGraph(
    input.graph,
    securityGraphValidationContext(input.manifest, input.evidence, input.artifacts, input.graph),
  );
  await input.ctx.state.recordDeepCoverage(input.deepCoverage);
}

function securityGraphValidationContext(
  manifest: Manifest,
  evidence: ReadonlyArray<FindingEvidence>,
  artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>,
  graph: SecurityGraph,
): SecurityGraphValidationContext {
  return {
    manifestPaths: manifest.files.map((file) => file.path),
    evidenceIds: uniqueStrings([
      ...evidence.map((item) => item.id),
      ...artifacts.map((artifact) => artifact.sliceArtifact.blobSha256),
      ...graph.nodes.flatMap((node) => node.evidenceIds),
      ...graph.edges.flatMap((edge) => edge.evidenceIds),
      ...graph.flows.flatMap((flow) => flow.evidenceIds),
    ]),
  };
}

async function extractProgramArtifacts(
  backend: JoernProgramAnalysisBackend,
  model: ProgramAnalysisModelRef,
): Promise<ProgramArtifactExtractionResult> {
  const artifacts: ProgramAnalysisExtractionArtifact[] = [];
  const failures: ProgramAnalysisFailure[] = [];
  const reusedUsageArtifacts: ReadonlyArray<{
    readonly kind: ProgramAnalysisExtractionKind;
    readonly area: ProgramAnalysisCoverageArea;
    readonly slicePath: string;
  }> = [
    { kind: "boundaries", area: "boundaries", slicePath: JOERN_BOUNDARIES_SLICE_PATH },
    { kind: "call_edges", area: "call_edges", slicePath: JOERN_CALL_EDGES_SLICE_PATH },
    {
      kind: "component_usage",
      area: "component_usage",
      slicePath: JOERN_COMPONENT_USAGE_SLICE_PATH,
    },
  ];

  try {
    const usageArtifact = await backend.extractEntities(model);
    artifacts.push(
      usageArtifact,
      ...reusedUsageArtifacts.map((artifact) =>
        reuseUsageArtifact(usageArtifact, artifact.kind, artifact.slicePath),
      ),
    );
  } catch (error) {
    for (const extraction of [
      { kind: "entities", area: "entities" },
      ...reusedUsageArtifacts,
    ] as const) {
      failures.push({
        area: extraction.area,
        reason: publicReason(`Deep Static ${extraction.kind} extraction failed`, error),
      });
    }
  }

  try {
    artifacts.push(await backend.extractFlows(model));
  } catch (error) {
    failures.push({
      area: "flows",
      reason: publicReason("Deep Static flows extraction failed", error),
    });
  }

  return { artifacts, failures };
}

function reuseUsageArtifact(
  artifact: ProgramAnalysisExtractionArtifact,
  kind: ProgramAnalysisExtractionKind,
  slicePath: string,
): ProgramAnalysisExtractionArtifact {
  return {
    ...artifact,
    kind,
    slicePath,
  };
}

function emitDeepProgress(ctx: StageContext, label: string): void {
  ctx.events.emit({
    type: "scan-progress",
    stageId: DEEP_STATIC_STAGE_ID,
    message: label,
    details: {
      publicLabel: label,
      source: "deep-static",
    },
    timestamp: new Date().toISOString(),
  });
}

function emitHypothesisEnrichProgress(
  ctx: StageContext,
  progress: {
    readonly completed: number;
    readonly total: number;
    readonly completedBatches: number;
    readonly totalBatches: number;
  },
): void {
  const label = `Explaining likely attack paths ${progress.completedBatches}/${progress.totalBatches} batches (${progress.completed}/${progress.total} hypotheses)`;
  ctx.events.emit({
    type: "scan-progress",
    stageId: HYPOTHESIS_ENRICH_STAGE_ID,
    message: label,
    details: {
      publicLabel: label,
      source: "model",
      completed: progress.completed,
      total: progress.total,
      completedBatches: progress.completedBatches,
      totalBatches: progress.totalBatches,
    },
    timestamp: new Date().toISOString(),
  });
}

function composeGraphOrFallback(input: {
  readonly ctx: StageContext;
  readonly sourceDir: string;
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

async function composeCiIacOrDegrade(input: {
  readonly ctx: StageContext;
  readonly sourceDir: string;
  readonly manifest: Manifest;
  readonly findings: ReadonlyArray<Finding>;
  readonly graph: SecurityGraph;
  readonly failures: ProgramAnalysisFailure[];
}): Promise<SecurityGraph> {
  try {
    const observations = await ciIacObservationsFromSnapshot(input);
    return composeCiIacContext({
      graph: input.graph,
      manifest: input.manifest,
      workflows: observations.workflows,
      iacResources: observations.iacResources,
    });
  } catch (error) {
    input.failures.push({
      area: "ci_iac",
      reason: publicReason("Deep Static CI/IaC context projection failed", error),
    });
    return input.graph;
  }
}

async function composeContentResourcesOrDegrade(input: {
  readonly ctx: StageContext;
  readonly sourceDir: string;
  readonly manifest: Manifest;
  readonly graph: SecurityGraph;
  readonly failures: ProgramAnalysisFailure[];
}): Promise<SecurityGraph> {
  try {
    const scan = await contentResourceObservationsFromSnapshot(input);
    return composeContentResourceContext({
      graph: input.graph,
      manifest: input.manifest,
      observations: scan.observations,
      scannedFileCount: scan.scannedFileCount,
    });
  } catch (error) {
    input.failures.push({
      area: "content_assets",
      reason: publicReason("Deep Static content/resource projection failed", error),
    });
    return input.graph;
  }
}

async function composeSmartContractsOrDegrade(input: {
  readonly ctx: StageContext;
  readonly sourceDir: string;
  readonly manifest: Manifest;
  readonly graph: SecurityGraph;
  readonly failures: ProgramAnalysisFailure[];
}): Promise<SecurityGraph> {
  try {
    const scan = await smartContractRiskObservationsFromSnapshot(input);
    return composeSmartContractContext({
      graph: input.graph,
      manifest: input.manifest,
      observations: scan.observations,
      scannedFileCount: scan.scannedFileCount,
    });
  } catch (error) {
    input.failures.push({
      area: "smart_contracts",
      reason: publicReason("Deep Static smart-contract projection failed", error),
    });
    return input.graph;
  }
}

async function smartContractRiskObservationsFromSnapshot(input: {
  readonly ctx: StageContext;
  readonly sourceDir: string;
  readonly manifest: Manifest;
}): Promise<{
  readonly observations: ReadonlyArray<SmartContractRiskObservation>;
  readonly scannedFileCount: number;
}> {
  const observations: SmartContractRiskObservation[] = [];
  let scannedFileCount = 0;

  for (const file of input.manifest.files) {
    if (!isSolidityPath(file.path)) {
      continue;
    }
    scannedFileCount += 1;
    const text = await readSnapshotText(input.ctx, input.sourceDir, file.path);
    observations.push(...smartContractRiskObservationsFromText(file.path, text));
  }

  return { observations, scannedFileCount };
}

async function contentResourceObservationsFromSnapshot(input: {
  readonly ctx: StageContext;
  readonly sourceDir: string;
  readonly manifest: Manifest;
}): Promise<{
  readonly observations: ReadonlyArray<ContentResourceObservation>;
  readonly scannedFileCount: number;
}> {
  const observations: ContentResourceObservation[] = [];
  let scannedFileCount = 0;

  for (const file of input.manifest.files) {
    const pathObservations = contentResourceObservationsFromPath(file);
    const scanText = isContentResourceTextPath(file.path) && !isGeneratedContentPath(file.path);
    if (pathObservations.length > 0 || scanText) {
      scannedFileCount += 1;
    }
    observations.push(...pathObservations);
    if (!scanText) {
      continue;
    }
    const text = await readSnapshotText(input.ctx, input.sourceDir, file.path);
    observations.push(...contentResourceObservationsFromText(file.path, text));
  }

  return { observations, scannedFileCount };
}

async function ciIacObservationsFromSnapshot(input: {
  readonly ctx: StageContext;
  readonly sourceDir: string;
  readonly manifest: Manifest;
  readonly findings: ReadonlyArray<Finding>;
}): Promise<{
  readonly workflows: ReadonlyArray<CiWorkflowObservation>;
  readonly iacResources: ReadonlyArray<IacResourceObservation>;
}> {
  const findingsByPath = findingsByLocationPath(input.findings);
  const workflows: CiWorkflowObservation[] = [];
  const iacResources: IacResourceObservation[] = [];

  for (const file of input.manifest.files) {
    if (isGithubActionsWorkflow(file.path)) {
      const text = await readSnapshotText(input.ctx, input.sourceDir, file.path);
      workflows.push(workflowObservationFromText(file.path, text, findingsByPath));
      continue;
    }
    if (isIacFile(file.path)) {
      const text = await readSnapshotText(input.ctx, input.sourceDir, file.path);
      iacResources.push(...iacResourceObservationsFromText(file.path, text, findingsByPath));
    }
  }

  return { workflows, iacResources };
}

async function readSnapshotText(
  ctx: StageContext,
  sourceDir: string,
  repoPath: string,
): Promise<string> {
  const bytes = await ctx.session.read(`${sourceDir}/${repoPath}`);
  return new TextDecoder().decode(bytes);
}

function isGeneratedContentPath(repoPath: string): boolean {
  return /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb|dist|build|coverage|vendor)\b/i.test(
    repoPath,
  );
}

function workflowObservationFromText(
  workflowPath: string,
  text: string,
  findingsByPath: ReadonlyMap<string, ReadonlyArray<Finding>>,
): CiWorkflowObservation {
  const lines = text.split(/\r?\n/);
  const evidenceIds = [ciIacEvidenceId("workflow", workflowPath, text)];
  const steps = workflowSteps(workflowPath, lines);
  return {
    workflowPath,
    name: workflowName(workflowPath, lines),
    evidenceIds,
    lineRange: { startLine: 1, endLine: Math.max(lines.length, 1) },
    findingIds: findingIdsForPath(findingsByPath, workflowPath, "github-action"),
    triggers: workflowTriggers(workflowPath, lines),
    steps,
    tokenPermissions: workflowTokenPermissions(workflowPath, lines, steps),
    artifacts: workflowArtifacts(workflowPath, lines, steps),
  };
}

function workflowName(workflowPath: string, lines: ReadonlyArray<string>): string {
  const explicit = lines
    .map((line) => line.match(/^\s*name\s*:\s*(.+?)\s*$/)?.[1])
    .find((value): value is string => value !== undefined);
  return stripYamlScalar(explicit) ?? path.posix.basename(workflowPath).replace(/\.ya?ml$/i, "");
}

function workflowTriggers(
  workflowPath: string,
  lines: ReadonlyArray<string>,
): CiTriggerObservation[] {
  const triggers = new Map<string, CiTriggerObservation>();
  const knownEvents = new Set([
    "branch_protection_rule",
    "check_run",
    "check_suite",
    "create",
    "delete",
    "deployment",
    "deployment_status",
    "discussion",
    "fork",
    "gollum",
    "issue_comment",
    "issues",
    "label",
    "merge_group",
    "milestone",
    "page_build",
    "project",
    "project_card",
    "project_column",
    "public",
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
    "pull_request_target",
    "push",
    "registry_package",
    "release",
    "repository_dispatch",
    "schedule",
    "status",
    "watch",
    "workflow_call",
    "workflow_dispatch",
    "workflow_run",
  ]);

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const onInline = line.match(/^\s*on\s*:\s*(.+?)\s*$/);
    if (onInline !== null) {
      const value = stripYamlScalar(onInline[1]) ?? "";
      const values =
        value.startsWith("[") && value.endsWith("]")
          ? value
              .slice(1, -1)
              .split(",")
              .map((item) => stripYamlScalar(item))
          : [value];
      for (const event of values) {
        if (event !== undefined && knownEvents.has(event)) {
          triggers.set(event, {
            event,
            evidenceIds: [ciIacEvidenceId("workflow-trigger", workflowPath, line)],
            lineRange: { startLine: lineNumber, endLine: lineNumber },
          });
        }
      }
    }
    const blockEvent = line.match(/^\s{2,}([A-Za-z_][\w-]*)\s*:/)?.[1];
    if (blockEvent !== undefined && knownEvents.has(blockEvent)) {
      triggers.set(blockEvent, {
        event: blockEvent,
        evidenceIds: [ciIacEvidenceId("workflow-trigger", workflowPath, line)],
        lineRange: { startLine: lineNumber, endLine: lineNumber },
      });
    }
  });

  return [...triggers.values()].sort((a, b) => a.event.localeCompare(b.event));
}

function workflowSteps(workflowPath: string, lines: ReadonlyArray<string>): CiStepObservation[] {
  return lines.flatMap((line, index) => {
    const lineNumber = index + 1;
    const uses = yamlValue(line, "uses");
    const run = yamlValue(line, "run");
    if (uses === undefined && run === undefined) {
      return [];
    }
    const value = uses ?? run ?? "step";
    const name = stepName(lines, index) ?? value;
    return [
      {
        id: `${lineNumber}-${slug(value)}`,
        name,
        evidenceIds: [ciIacEvidenceId("workflow-step", workflowPath, line)],
        lineRange: { startLine: lineNumber, endLine: lineNumber },
        ...(uses === undefined ? {} : { uses, pinned: isPinnedAction(uses) }),
        ...(run === undefined ? {} : { run }),
      },
    ];
  });
}

function workflowTokenPermissions(
  workflowPath: string,
  lines: ReadonlyArray<string>,
  steps: ReadonlyArray<CiStepObservation>,
): CiTokenPermissionObservation[] {
  const firstStepId = steps[0]?.id;
  return lines.flatMap((line, index) => {
    const match = line.match(
      /^\s*(actions|attestations|checks|contents|deployments|discussions|id-token|issues|packages|pages|pull-requests|repository-projects|security-events|statuses)\s*:\s*(read|write|none)\b/i,
    );
    if (match === null) {
      return [];
    }
    const lineNumber = index + 1;
    const scope = match[1];
    const access = match[2];
    if (scope === undefined || access === undefined) {
      return [];
    }
    return [
      {
        scope: scope.toLowerCase(),
        access: access.toLowerCase() as "none" | "read" | "write",
        evidenceIds: [ciIacEvidenceId("workflow-token", workflowPath, line)],
        lineRange: { startLine: lineNumber, endLine: lineNumber },
        ...(firstStepId === undefined ? {} : { stepId: firstStepId }),
      },
    ];
  });
}

function workflowArtifacts(
  _workflowPath: string,
  lines: ReadonlyArray<string>,
  steps: ReadonlyArray<CiStepObservation>,
): CiArtifactObservation[] {
  return steps.flatMap((step) => {
    if (step.uses?.toLowerCase().includes("actions/upload-artifact") !== true) {
      return [];
    }
    const startIndex = Math.max(0, (step.lineRange?.startLine ?? 1) - 1);
    const block = lines.slice(startIndex, Math.min(lines.length, startIndex + 12));
    const name =
      firstYamlValue(block, "name") ?? firstYamlValue(block, "path") ?? `artifact-${step.id}`;
    const artifactPath = firstYamlValue(block, "path");
    return [
      {
        stepId: step.id,
        name,
        evidenceIds: step.evidenceIds,
        ...(step.lineRange === undefined ? {} : { lineRange: step.lineRange }),
        ...(artifactPath === undefined ? {} : { path: artifactPath }),
      },
    ];
  });
}

function iacResourceObservationsFromText(
  repoPath: string,
  text: string,
  findingsByPath: ReadonlyMap<string, ReadonlyArray<Finding>>,
): IacResourceObservation[] {
  if (/\.tf(vars)?$/i.test(repoPath)) {
    return terraformResourceObservations(repoPath, text, findingsByPath);
  }
  if (/\.(ya?ml|json)$/i.test(repoPath)) {
    return yamlIacResourceObservations(repoPath, text, findingsByPath);
  }
  return genericIacResourceObservation(repoPath, text, findingsByPath);
}

function terraformResourceObservations(
  repoPath: string,
  text: string,
  findingsByPath: ReadonlyMap<string, ReadonlyArray<Finding>>,
): IacResourceObservation[] {
  const matches = [...text.matchAll(/resource\s+"([^"]+)"\s+"([^"]+)"/g)];
  if (matches.length === 0) {
    return genericIacResourceObservation(repoPath, text, findingsByPath);
  }
  return matches.map((match, index) => {
    const resourceType = match[1];
    const name = match[2];
    if (resourceType === undefined || name === undefined) {
      throw new Error(`invalid Terraform resource match in ${repoPath}`);
    }
    const start = match.index ?? 0;
    const end = matches[index + 1]?.index ?? text.length;
    const block = text.slice(start, end);
    const line = lineNumberForOffset(text, start);
    return {
      repoPath,
      resourceType,
      name,
      evidenceIds: [ciIacEvidenceId("iac-resource", repoPath, match[0])],
      lineRange: { startLine: line, endLine: line },
      public: looksPublicIac(block),
      findingIds: findingIdsForPath(findingsByPath, repoPath, "iac"),
    };
  });
}

function yamlIacResourceObservations(
  repoPath: string,
  text: string,
  findingsByPath: ReadonlyMap<string, ReadonlyArray<Finding>>,
): IacResourceObservation[] {
  const lines = text.split(/\r?\n/);
  const kindLine = lines.findIndex((line) => /^\s*kind\s*:/.test(line));
  if (kindLine < 0) {
    return genericIacResourceObservation(repoPath, text, findingsByPath);
  }
  const kind = yamlValue(lines[kindLine] ?? "", "kind") ?? "yaml-resource";
  const name = firstYamlValue(lines, "name") ?? path.posix.basename(repoPath);
  return [
    {
      repoPath,
      resourceType: kind,
      name,
      evidenceIds: [ciIacEvidenceId("iac-resource", repoPath, lines[kindLine] ?? kind)],
      lineRange: { startLine: kindLine + 1, endLine: kindLine + 1 },
      public: looksPublicIac(text),
      findingIds: findingIdsForPath(findingsByPath, repoPath, "iac"),
    },
  ];
}

function genericIacResourceObservation(
  repoPath: string,
  text: string,
  findingsByPath: ReadonlyMap<string, ReadonlyArray<Finding>>,
): IacResourceObservation[] {
  if (!looksPublicIac(text) && findingIdsForPath(findingsByPath, repoPath, "iac").length === 0) {
    return [];
  }
  return [
    {
      repoPath,
      resourceType: path.posix.basename(repoPath).toLowerCase(),
      name: path.posix.basename(repoPath),
      evidenceIds: [ciIacEvidenceId("iac-resource", repoPath, text.slice(0, 200))],
      lineRange: { startLine: 1, endLine: 1 },
      public: looksPublicIac(text),
      findingIds: findingIdsForPath(findingsByPath, repoPath, "iac"),
    },
  ];
}

function findingsByLocationPath(
  findings: ReadonlyArray<Finding>,
): ReadonlyMap<string, ReadonlyArray<Finding>> {
  const byPath = new Map<string, Finding[]>();
  for (const finding of findings) {
    for (const location of finding.locations) {
      const current = byPath.get(location.filePath) ?? [];
      current.push(finding);
      byPath.set(location.filePath, current);
    }
  }
  return byPath;
}

function findingIdsForPath(
  findingsByPath: ReadonlyMap<string, ReadonlyArray<Finding>>,
  repoPath: string,
  category: Finding["category"],
): string[] {
  return (findingsByPath.get(repoPath) ?? [])
    .filter((finding) => finding.category === category)
    .map((finding) => finding.id)
    .sort();
}

function isGithubActionsWorkflow(filePath: string): boolean {
  return /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(filePath);
}

function isIacFile(filePath: string): boolean {
  if (isGithubActionsWorkflow(filePath)) {
    return false;
  }
  const base = path.posix.basename(filePath);
  const lowerPath = filePath.toLowerCase();
  return (
    /^dockerfile([.-].*)?$/i.test(base) ||
    /^(docker-)?compose([.-].*)?\.ya?ml$/i.test(base) ||
    /\.(tf|tfvars)$/i.test(base) ||
    ((base === "Chart.yaml" || /^values([.-].*)?\.ya?ml$/i.test(base)) &&
      (lowerPath.includes("/helm/") || lowerPath.includes("/charts/"))) ||
    (/\.(ya?ml|json)$/i.test(base) &&
      (lowerPath.startsWith("k8s/") ||
        lowerPath.startsWith("kubernetes/") ||
        lowerPath.includes("/k8s/") ||
        lowerPath.includes("/kubernetes/")))
  );
}

function firstYamlValue(lines: ReadonlyArray<string>, key: string): string | undefined {
  return lines.map((line) => yamlValue(line, key)).find((value) => value !== undefined);
}

function yamlValue(line: string, key: string): string | undefined {
  const match = line.match(new RegExp(`^\\s*-?\\s*${escapeRegExp(key)}\\s*:\\s*(.+?)\\s*$`));
  return stripYamlScalar(match?.[1]);
}

function stepName(lines: ReadonlyArray<string>, index: number): string | undefined {
  for (let current = index; current >= Math.max(0, index - 4); current -= 1) {
    const name = yamlValue(lines[current] ?? "", "name");
    if (name !== undefined) {
      return name;
    }
  }
  return undefined;
}

function stripYamlScalar(value: string | undefined): string | undefined {
  const stripped = value
    ?.trim()
    .replace(/^["']|["']$/g, "")
    .replace(/\s+#.*$/, "");
  return stripped === undefined || stripped === "" || stripped === "{}" ? undefined : stripped;
}

function isPinnedAction(uses: string): boolean {
  return /@[0-9a-f]{40}$/i.test(uses);
}

function looksPublicIac(text: string): boolean {
  return /0\.0\.0\.0\/0|::\/0|public-read|public_read|LoadBalancer|Ingress|internet-facing/i.test(
    text,
  );
}

function lineNumberForOffset(text: string, offset: number): number {
  return text.slice(0, offset).split(/\r?\n/).length;
}

function ciIacEvidenceId(kind: string, repoPath: string, body: string): string {
  return `ci_iac_${createHash("sha256")
    .update([kind, repoPath, body].join("\0"))
    .digest("hex")
    .slice(0, 16)}`;
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function composeReachabilityOrDegrade(input: {
  readonly graph: SecurityGraph;
  readonly manifest: Manifest;
  readonly artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>;
  readonly dependencyObservations: ReadonlyArray<ComponentDependencyObservation>;
  readonly failures: ProgramAnalysisFailure[];
}): {
  readonly graph: SecurityGraph;
  readonly componentReachability: ReadonlyArray<ComponentReachability>;
} {
  try {
    const result = composeComponentReachability({
      graph: input.graph,
      manifest: input.manifest,
      observations: componentUsageObservationsFromArtifacts(input.artifacts),
      dependencyObservations: input.dependencyObservations,
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

function componentUsageCoverage(
  artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>,
): ReturnType<JoernProgramAnalysisBackend["reportCoverage"]> {
  const artifact = artifacts.find((item) => item.kind === "component_usage");
  if (artifact === undefined) {
    return [];
  }
  const count = componentUsageObservationsFromArtifacts([artifact]).length;
  return [
    {
      area: "component_usage",
      state: "checked",
      producer: "joern",
      producerVersion: artifact.backendVersion,
      coveredCount: count,
      totalCount: count,
    },
  ];
}

function componentUsageObservationsFromArtifacts(
  artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>,
): ComponentUsageObservation[] {
  return artifacts
    .filter((artifact) => artifact.kind === "component_usage")
    .flatMap((artifact) => {
      const root = recordValue(artifact.parsed);
      if (root === undefined) {
        return [];
      }
      return recordArray(root.componentUsages).flatMap((record) => {
        const packageName = stringValue(record.packageName);
        const repoPath = stringValue(record.repoPath);
        const usageKind = stringValue(record.usageKind);
        const lineRange = lineRangeValue(record.lineRange);
        if (
          packageName === undefined ||
          repoPath === undefined ||
          lineRange === undefined ||
          (usageKind !== "imported" && usageKind !== "used")
        ) {
          return [];
        }
        return [
          {
            packageName,
            repoPath,
            usageKind,
            evidenceIds: [artifact.sliceArtifact.blobSha256],
            lineRange,
          },
        ];
      });
    });
}

async function componentDependencyObservationsFromEvidence(input: {
  readonly ctx: StageContext;
  readonly manifest: Manifest;
  readonly evidence: ReadonlyArray<FindingEvidence>;
  readonly findings: ReadonlyArray<Finding>;
  readonly failures: ProgramAnalysisFailure[];
}): Promise<ComponentDependencyObservation[]> {
  const trivyEvidenceByRaw = new Map<string, FindingEvidence[]>();
  for (const item of input.evidence) {
    if (item.tool !== "trivy") {
      continue;
    }
    const current = trivyEvidenceByRaw.get(item.rawArtifactBlobSha256) ?? [];
    current.push(item);
    trivyEvidenceByRaw.set(item.rawArtifactBlobSha256, current);
  }
  if (trivyEvidenceByRaw.size === 0) {
    return [];
  }

  const evidenceIdsByPackage = findingEvidenceIdsByPackage(input.findings);
  const observations: ComponentDependencyObservation[] = [];
  const seen = new Set<string>();

  for (const [rawArtifactBlobSha256, rawEvidence] of trivyEvidenceByRaw) {
    let parsed: unknown;
    try {
      const bytes = await input.ctx.artifacts.read(rawArtifactBlobSha256);
      parsed = JSON.parse(decoder.decode(bytes)) as unknown;
    } catch (error) {
      input.failures.push({
        area: "component_usage",
        reason: publicReason("Deep Static package dependency graph read failed", error),
      });
      continue;
    }

    for (const observation of componentDependencyObservationsFromTrivyRaw({
      raw: parsed,
      manifestPaths: packageManifestPaths(input.manifest),
      fallbackEvidenceIds: rawEvidence.map((item) => item.id),
      evidenceIdsByPackage,
    })) {
      const key = [
        observation.manifestPath,
        observation.sourcePackageName,
        observation.packageName,
        observation.relationship ?? "",
      ].join("\0");
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      observations.push(observation);
    }
  }

  return observations;
}

function componentDependencyObservationsFromTrivyRaw(input: {
  readonly raw: unknown;
  readonly manifestPaths: ReadonlyArray<string>;
  readonly fallbackEvidenceIds: ReadonlyArray<string>;
  readonly evidenceIdsByPackage: ReadonlyMap<string, ReadonlyArray<string>>;
}): ComponentDependencyObservation[] {
  const root = recordValue(input.raw);
  if (root === undefined) {
    return [];
  }
  const observations: ComponentDependencyObservation[] = [];

  for (const result of recordArray(root.Results)) {
    const manifestPath = trivyDependencyManifestPath(result, input.manifestPaths);
    const packages = recordArray(result.Packages);
    if (manifestPath === undefined || packages.length === 0) {
      continue;
    }
    const packagesById = trivyPackagesById(packages);
    for (const pkg of packages) {
      const sourcePackageName =
        stringValue(pkg.Name) ?? packageNameFromPackageId(stringValue(pkg.ID));
      const dependsOn = stringArray(pkg.DependsOn);
      if (sourcePackageName === undefined || dependsOn.length === 0) {
        continue;
      }
      const relationship = stringValue(pkg.Relationship);
      for (const dependencyId of dependsOn) {
        const dependency = packagesById.get(dependencyId);
        const packageName = dependency?.name ?? packageNameFromPackageId(dependencyId);
        if (packageName === undefined) {
          continue;
        }
        observations.push({
          sourcePackageName,
          packageName,
          manifestPath,
          ...(dependency?.version === undefined ? {} : { version: dependency.version }),
          ...(relationship === undefined ? {} : { relationship }),
          evidenceIds: evidenceIdsForPackage(
            packageName,
            input.evidenceIdsByPackage,
            input.fallbackEvidenceIds,
          ),
          lineRange: { startLine: 1, endLine: 1 },
        });
      }
    }
  }

  return observations;
}

function packageManifestPaths(manifest: Manifest): string[] {
  return manifest.files
    .map((file) => file.path)
    .filter((file) =>
      /(^|\/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|pom\.xml|build\.gradle|build\.gradle\.kts|go\.(mod|sum)|requirements\.txt|poetry\.lock|Pipfile\.lock|pyproject\.toml)$/i.test(
        file,
      ),
    );
}

function trivyDependencyManifestPath(
  result: Readonly<Record<string, unknown>>,
  manifestPaths: ReadonlyArray<string>,
): string | undefined {
  const target = normalizeTrivyTarget(stringValue(result.Target));
  if (target !== undefined && manifestPaths.includes(target)) {
    return target;
  }
  const ecosystem = trivyResultPackageEcosystem(result);
  if (ecosystem === "maven") {
    return firstManifestPath(manifestPaths, ["pom.xml", "build.gradle", "build.gradle.kts"]);
  }
  if (ecosystem === "npm") {
    return firstManifestPath(manifestPaths, [
      "package-lock.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "package.json",
    ]);
  }
  if (ecosystem === "golang") {
    return firstManifestPath(manifestPaths, ["go.sum", "go.mod"]);
  }
  if (ecosystem === "pypi") {
    return firstManifestPath(manifestPaths, [
      "requirements.txt",
      "poetry.lock",
      "Pipfile.lock",
      "pyproject.toml",
    ]);
  }
  return manifestPaths[0];
}

function trivyResultPackageEcosystem(
  result: Readonly<Record<string, unknown>>,
): string | undefined {
  for (const pkg of recordArray(result.Packages)) {
    const identifier = recordValue(pkg.Identifier) ?? recordValue(pkg.PkgIdentifier);
    const purl = stringValue(identifier?.PURL);
    const ecosystem = purl?.match(/^pkg:([^/]+)\//)?.[1]?.toLowerCase();
    if (ecosystem !== undefined) {
      return ecosystem;
    }
  }
  return undefined;
}

function firstManifestPath(
  manifestPaths: ReadonlyArray<string>,
  names: ReadonlyArray<string>,
): string | undefined {
  for (const name of names) {
    const matched = manifestPaths.find((file) => file === name || file.endsWith(`/${name}`));
    if (matched !== undefined) {
      return matched;
    }
  }
  return undefined;
}

function trivyPackagesById(
  packages: ReadonlyArray<Readonly<Record<string, unknown>>>,
): Map<string, { readonly name: string; readonly version?: string }> {
  const out = new Map<string, { readonly name: string; readonly version?: string }>();
  for (const pkg of packages) {
    const id = stringValue(pkg.ID);
    if (id === undefined) {
      continue;
    }
    const name = stringValue(pkg.Name) ?? packageNameFromPackageId(id);
    if (name === undefined) {
      continue;
    }
    const version = stringValue(pkg.Version);
    out.set(id, {
      name,
      ...(version === undefined ? {} : { version }),
    });
  }
  return out;
}

function findingEvidenceIdsByPackage(
  findings: ReadonlyArray<Finding>,
): Map<string, ReadonlyArray<string>> {
  const out = new Map<string, string[]>();
  for (const finding of findings) {
    if (finding.sourceTool !== "trivy") {
      continue;
    }
    const packageName = finding.metadata?.packageName;
    if (packageName === undefined || packageName.trim() === "") {
      continue;
    }
    const current = out.get(packageName) ?? [];
    current.push(...finding.evidenceIds);
    out.set(packageName, uniqueStrings(current));
  }
  return out;
}

function evidenceIdsForPackage(
  packageName: string,
  evidenceIdsByPackage: ReadonlyMap<string, ReadonlyArray<string>>,
  fallbackEvidenceIds: ReadonlyArray<string>,
): ReadonlyArray<string> {
  const exact = evidenceIdsByPackage.get(packageName);
  if (exact !== undefined && exact.length > 0) {
    return exact;
  }
  for (const [candidate, evidenceIds] of evidenceIdsByPackage) {
    if (
      evidenceIds.length > 0 &&
      (candidate.endsWith(`/${packageName}`) || packageName.endsWith(`/${candidate}`))
    ) {
      return evidenceIds;
    }
  }
  return fallbackEvidenceIds;
}

function packageNameFromPackageId(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const at = value.lastIndexOf("@");
  if (at > 0) {
    return value.slice(0, at);
  }
  return value.trim() === "" ? undefined : value;
}

function normalizeTrivyTarget(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const normalized = value
    .replace(/\\/g, "/")
    .replace(/^\/work\/source\//, "")
    .replace(/^\.\//, "");
  return normalized === "" || normalized.startsWith("../") || path.isAbsolute(normalized)
    ? undefined
    : normalized;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.flatMap((item) => {
        const text = stringValue(item);
        return text === undefined ? [] : [text];
      })
    : [];
}

function uniqueStrings(values: ReadonlyArray<string>): string[] {
  return [...new Set(values)];
}

function recordValue(value: unknown): Readonly<Record<string, unknown>> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Readonly<Record<string, unknown>>)
    : undefined;
}

function recordArray(value: unknown): ReadonlyArray<Readonly<Record<string, unknown>>> {
  return Array.isArray(value)
    ? value.flatMap((item) => {
        const record = recordValue(item);
        return record === undefined ? [] : [record];
      })
    : [];
}

function lineRangeValue(value: unknown): LineRange | undefined {
  const record = recordValue(value);
  if (record === undefined) {
    return undefined;
  }
  const startLine = positiveInteger(record.startLine);
  const endLine = positiveInteger(record.endLine);
  if (startLine === undefined) {
    return undefined;
  }
  return { startLine, endLine: endLine ?? startLine };
}

function positiveInteger(value: unknown): number | undefined {
  return Number.isInteger(value) && typeof value === "number" && value > 0 ? value : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
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
