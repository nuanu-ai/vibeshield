import { readFile } from "node:fs/promises";
import path from "node:path";
import type {
  AuthConfigSecretsArtifact,
  CoverageStructureArtifact,
  DataFlowsArtifact,
  EntrypointsArtifact,
  InventoryArtifact,
  OperationSinksArtifact,
  PiContextPackArtifact,
  RepositoryMapArtifact,
  StackBuildDepsArtifact,
  StorageIntegrationsInfraArtifact,
  TrustBoundariesArtifact,
} from "../artifacts/contracts.js";
import type { ArtifactStore } from "../artifacts/store.js";
import { errorMessage, ScanStageError } from "../run/errors.js";
import { relativeArtifactPath } from "../run/file-io.js";
import { redactDeep } from "../run/redaction.js";
import type { RunJobState, RunStage } from "../run/types.js";
import type {
  RuntimeJobProgressEvent,
  RuntimeJobResult,
  SandboxSession,
} from "../sandbox/types.js";

const defaultPiModel = "moonshotai/kimi-k2.7-code";
const defaultPiProvider = "openrouter";
const collectorTools = ["read", "grep", "find", "ls", "write"];

const repoMapPaths = {
  authConfigSecrets: "outputs/repo-map/auth-config-secrets.json",
  coverageStructure: "outputs/repo-map/coverage-structure.json",
  dataFlows: "outputs/repo-map/data-flows.json",
  entrypoints: "outputs/repo-map/entrypoints.json",
  operationSinks: "outputs/repo-map/operation-sinks.json",
  repositoryMap: "outputs/repository-map.json",
  stackBuildDeps: "outputs/repo-map/stack-build-deps.json",
  storageIntegrationsInfra: "outputs/repo-map/storage-integrations-infra.json",
  trustBoundaries: "outputs/repo-map/trust-boundaries.json",
} as const;

type PiStructuredArtifact =
  | AuthConfigSecretsArtifact
  | CoverageStructureArtifact
  | DataFlowsArtifact
  | EntrypointsArtifact
  | OperationSinksArtifact
  | RepositoryMapArtifact
  | StackBuildDepsArtifact
  | StorageIntegrationsInfraArtifact
  | TrustBoundariesArtifact;

type PiStageValidationStage =
  | "auth-config-secrets-validation"
  | "coverage-structure-validation"
  | "data-flows-validation"
  | "entrypoints-validation"
  | "operation-sinks-validation"
  | "repository-map-validation"
  | "stack-build-deps-validation"
  | "storage-integrations-infra-validation"
  | "trust-boundaries-validation";

interface RunPiRepositoryMappingInput {
  contextPack: PiContextPackArtifact;
  contextPath: string;
  existing?: Partial<{
    authConfigSecrets: ExistingPiArtifact<AuthConfigSecretsArtifact>;
    coverageStructure: ExistingPiArtifact<CoverageStructureArtifact>;
    dataFlows: ExistingPiArtifact<DataFlowsArtifact>;
    entrypoints: ExistingPiArtifact<EntrypointsArtifact>;
    operationSinks: ExistingPiArtifact<OperationSinksArtifact>;
    repositoryMap: ExistingPiArtifact<RepositoryMapArtifact>;
    stackBuildDeps: ExistingPiArtifact<StackBuildDepsArtifact>;
    storageIntegrationsInfra: ExistingPiArtifact<StorageIntegrationsInfraArtifact>;
    trustBoundaries: ExistingPiArtifact<TrustBoundariesArtifact>;
  }>;
  generatedAt: string;
  inventory: InventoryArtifact;
  onJobFinished?: (jobState: RunJobState) => unknown | Promise<unknown>;
  onProgress?: (event: RuntimeJobProgressEvent) => unknown | Promise<unknown>;
  outputsDir: string;
  runDir: string;
  sandbox: SandboxSession;
  store: ArtifactStore;
}

interface ExistingPiArtifact<TArtifact extends PiStructuredArtifact> {
  artifact: TArtifact;
  artifactPath: string;
}

export interface RunPiRepositoryMappingResult {
  authConfigSecrets: AuthConfigSecretsArtifact;
  authConfigSecretsPath: string;
  coverageStructure: CoverageStructureArtifact;
  coverageStructurePath: string;
  dataFlows: DataFlowsArtifact;
  dataFlowsPath: string;
  entrypoints: EntrypointsArtifact;
  entrypointsPath: string;
  jobStates: RunJobState[];
  operationSinks: OperationSinksArtifact;
  operationSinksPath: string;
  repositoryMap: RepositoryMapArtifact;
  repositoryMapPath: string;
  stackBuildDeps: StackBuildDepsArtifact;
  stackBuildDepsPath: string;
  storageIntegrationsInfra: StorageIntegrationsInfraArtifact;
  storageIntegrationsInfraPath: string;
  trustBoundaries: TrustBoundariesArtifact;
  trustBoundariesPath: string;
}

interface PiStageInput<TArtifact extends PiStructuredArtifact> {
  artifactId: TArtifact["kind"];
  artifactRelativePath: string;
  contextArtifactLabel: string;
  contextPack: unknown;
  generatedAt: string;
  input: RunPiRepositoryMappingInput;
  jobName: string;
  kind: TArtifact["kind"];
  outputBaseName: TArtifact["kind"];
  prompt: string;
  step: TArtifact["kind"];
  tools?: string[];
  validateSchema: (artifact: TArtifact) => void;
  validationStage: PiStageValidationStage;
}

interface PiStageResult<TArtifact extends PiStructuredArtifact> {
  artifact: TArtifact;
  artifactPath: string;
  jobState: RunJobState;
}

export async function runPiRepositoryMapping(
  input: RunPiRepositoryMappingInput,
): Promise<RunPiRepositoryMappingResult> {
  const jobStates: RunJobState[] = [];
  const onJobFinished = async (jobState: RunJobState) => {
    jobStates.push(jobState);
    await input.onJobFinished?.(jobState);
  };
  const stageInput = { ...input, onJobFinished };

  const coverageStructure =
    input.existing?.coverageStructure ??
    (await runPiStage<CoverageStructureArtifact>({
      artifactId: "coverage-structure",
      artifactRelativePath: repoMapPaths.coverageStructure,
      contextArtifactLabel: input.contextPath,
      contextPack: input.contextPack,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-coverage-structure",
      kind: "coverage-structure",
      outputBaseName: "coverage-structure",
      prompt: buildCoverageStructurePrompt(input.contextPack),
      step: "coverage-structure",
      validateSchema: (artifact) => validateCoverageStructureArtifact({ artifact }),
      validationStage: "coverage-structure-validation",
    }));

  const stackBuildDeps =
    input.existing?.stackBuildDeps ??
    (await runPiStage<StackBuildDepsArtifact>({
      artifactId: "stack-build-deps",
      artifactRelativePath: repoMapPaths.stackBuildDeps,
      contextArtifactLabel: input.contextPath,
      contextPack: input.contextPack,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-stack-deps",
      kind: "stack-build-deps",
      outputBaseName: "stack-build-deps",
      prompt: buildStackBuildDepsPrompt(input.contextPack),
      step: "stack-build-deps",
      validateSchema: (artifact) => validateStackBuildDepsArtifact({ artifact }),
      validationStage: "stack-build-deps-validation",
    }));

  const entrypoints =
    input.existing?.entrypoints ??
    (await runPiStage<EntrypointsArtifact>({
      artifactId: "entrypoints",
      artifactRelativePath: repoMapPaths.entrypoints,
      contextArtifactLabel: input.contextPath,
      contextPack: input.contextPack,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-entrypoints",
      kind: "entrypoints",
      outputBaseName: "entrypoints",
      prompt: buildEntrypointsPrompt(input.contextPack),
      step: "entrypoints",
      validateSchema: (artifact) => validateEntrypointsArtifact({ artifact }),
      validationStage: "entrypoints-validation",
    }));

  const authConfigContext = {
    inputs: {
      entrypoints: entrypoints.artifact,
    },
    inventory: input.contextPack.inventory,
    repo: input.contextPack.repo,
  };
  const authConfigSecrets =
    input.existing?.authConfigSecrets ??
    (await runPiStage<AuthConfigSecretsArtifact>({
      artifactId: "auth-config-secrets",
      artifactRelativePath: repoMapPaths.authConfigSecrets,
      contextArtifactLabel: `${input.contextPath}, ${entrypoints.artifactPath}`,
      contextPack: authConfigContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-auth-config-secrets",
      kind: "auth-config-secrets",
      outputBaseName: "auth-config-secrets",
      prompt: buildAuthConfigSecretsPrompt(authConfigContext),
      step: "auth-config-secrets",
      validateSchema: (artifact) => validateAuthConfigSecretsArtifact({ artifact }),
      validationStage: "auth-config-secrets-validation",
    }));

  const storageIntegrationsInfra =
    input.existing?.storageIntegrationsInfra ??
    (await runPiStage<StorageIntegrationsInfraArtifact>({
      artifactId: "storage-integrations-infra",
      artifactRelativePath: repoMapPaths.storageIntegrationsInfra,
      contextArtifactLabel: input.contextPath,
      contextPack: input.contextPack,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-storage-integrations-infra",
      kind: "storage-integrations-infra",
      outputBaseName: "storage-integrations-infra",
      prompt: buildStorageIntegrationsInfraPrompt(input.contextPack),
      step: "storage-integrations-infra",
      validateSchema: (artifact) => validateStorageIntegrationsInfraArtifact({ artifact }),
      validationStage: "storage-integrations-infra-validation",
    }));

  const operationSinks =
    input.existing?.operationSinks ??
    (await runPiStage<OperationSinksArtifact>({
      artifactId: "operation-sinks",
      artifactRelativePath: repoMapPaths.operationSinks,
      contextArtifactLabel: input.contextPath,
      contextPack: input.contextPack,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-operation-sinks",
      kind: "operation-sinks",
      outputBaseName: "operation-sinks",
      prompt: buildOperationSinksPrompt(input.contextPack),
      step: "operation-sinks",
      validateSchema: (artifact) => validateOperationSinksArtifact({ artifact }),
      validationStage: "operation-sinks-validation",
    }));

  const dataFlowContext = {
    inputs: {
      entrypoints: entrypoints.artifact,
      operation_sinks: operationSinks.artifact,
    },
    repo: input.contextPack.repo,
  };
  const dataFlows =
    input.existing?.dataFlows ??
    (await runPiStage<DataFlowsArtifact>({
      artifactId: "data-flows",
      artifactRelativePath: repoMapPaths.dataFlows,
      contextArtifactLabel: `${entrypoints.artifactPath}, ${operationSinks.artifactPath}`,
      contextPack: dataFlowContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-data-flows",
      kind: "data-flows",
      outputBaseName: "data-flows",
      prompt: buildDataFlowsPrompt(dataFlowContext),
      step: "data-flows",
      validateSchema: (artifact) => validateDataFlowsArtifact({ artifact }),
      validationStage: "data-flows-validation",
    }));

  const priorMapArtifacts = {
    artifacts: {
      auth_config_secrets: piHandoffArtifact(authConfigSecrets.artifact),
      data_flows: piHandoffArtifact(dataFlows.artifact),
      entrypoints: piHandoffArtifact(entrypoints.artifact),
      operation_sinks: piHandoffArtifact(operationSinks.artifact),
      storage_integrations_infra: piHandoffArtifact(storageIntegrationsInfra.artifact),
    },
    paths: priorMapArtifactPaths(),
    repo: input.contextPack.repo,
  };
  const trustBoundaries =
    input.existing?.trustBoundaries ??
    (await runPiStage<TrustBoundariesArtifact>({
      artifactId: "trust-boundaries",
      artifactRelativePath: repoMapPaths.trustBoundaries,
      contextArtifactLabel: [
        coverageStructure.artifactPath,
        stackBuildDeps.artifactPath,
        entrypoints.artifactPath,
        authConfigSecrets.artifactPath,
        storageIntegrationsInfra.artifactPath,
        operationSinks.artifactPath,
        dataFlows.artifactPath,
      ].join(", "),
      contextPack: priorMapArtifacts,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-trust-boundaries",
      kind: "trust-boundaries",
      outputBaseName: "trust-boundaries",
      prompt: buildTrustBoundariesPrompt(priorMapArtifacts),
      step: "trust-boundaries",
      validateSchema: (artifact) => validateTrustBoundariesArtifact({ artifact }),
      validationStage: "trust-boundaries-validation",
    }));

  const repositoryMapContext = {
    artifacts: {
      auth_config_secrets: piHandoffArtifact(authConfigSecrets.artifact),
      coverage_structure: piHandoffArtifact(coverageStructure.artifact),
      data_flows: piHandoffArtifact(dataFlows.artifact),
      entrypoints: piHandoffArtifact(entrypoints.artifact),
      operation_sinks: piHandoffArtifact(operationSinks.artifact),
      stack_build_deps: piHandoffArtifact(stackBuildDeps.artifact),
      storage_integrations_infra: piHandoffArtifact(storageIntegrationsInfra.artifact),
      trust_boundaries: piHandoffArtifact(trustBoundaries.artifact),
    },
    paths: allMapArtifactPaths(),
    repo: input.contextPack.repo,
  };
  const repositoryMap =
    input.existing?.repositoryMap ??
    (await runPiStage<RepositoryMapArtifact>({
      artifactId: "repository-map",
      artifactRelativePath: repoMapPaths.repositoryMap,
      contextArtifactLabel: [
        coverageStructure.artifactPath,
        stackBuildDeps.artifactPath,
        entrypoints.artifactPath,
        authConfigSecrets.artifactPath,
        storageIntegrationsInfra.artifactPath,
        operationSinks.artifactPath,
        dataFlows.artifactPath,
        trustBoundaries.artifactPath,
      ].join(", "),
      contextPack: repositoryMapContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-repository-map",
      kind: "repository-map",
      outputBaseName: "repository-map",
      prompt: buildRepositoryMapPrompt(repositoryMapContext),
      step: "repository-map",
      validateSchema: (artifact) => validateRepositoryMapArtifact({ artifact }),
      validationStage: "repository-map-validation",
    }));

  return {
    authConfigSecrets: authConfigSecrets.artifact,
    authConfigSecretsPath: authConfigSecrets.artifactPath,
    coverageStructure: coverageStructure.artifact,
    coverageStructurePath: coverageStructure.artifactPath,
    dataFlows: dataFlows.artifact,
    dataFlowsPath: dataFlows.artifactPath,
    entrypoints: entrypoints.artifact,
    entrypointsPath: entrypoints.artifactPath,
    jobStates,
    operationSinks: operationSinks.artifact,
    operationSinksPath: operationSinks.artifactPath,
    repositoryMap: repositoryMap.artifact,
    repositoryMapPath: repositoryMap.artifactPath,
    stackBuildDeps: stackBuildDeps.artifact,
    stackBuildDepsPath: stackBuildDeps.artifactPath,
    storageIntegrationsInfra: storageIntegrationsInfra.artifact,
    storageIntegrationsInfraPath: storageIntegrationsInfra.artifactPath,
    trustBoundaries: trustBoundaries.artifact,
    trustBoundariesPath: trustBoundaries.artifactPath,
  };
}

async function runPiStage<TArtifact extends PiStructuredArtifact>(
  stage: PiStageInput<TArtifact>,
): Promise<PiStageResult<TArtifact>> {
  const heartbeat = startPiStageHeartbeat(stage);
  const result = await stage.input.sandbox
    .runJob({
      generatedAt: stage.generatedAt,
      kind: "pi-repository-mapping",
      name: stage.jobName,
      ...(stage.input.onProgress === undefined ? {} : { onProgress: stage.input.onProgress }),
      pi: {
        artifactSubdir: stage.outputBaseName,
        attempt: 1,
        contextPack: stage.contextPack,
        inputContextArtifact: stage.contextArtifactLabel,
        model: defaultPiModel,
        outputFile: piAgentOutputFile(stage.outputBaseName),
        outputBaseName: stage.outputBaseName,
        prompt: withPiOutputFileInstruction({
          outputFile: piAgentOutputFile(stage.outputBaseName),
          prompt: stage.prompt,
        }),
        provider: defaultPiProvider,
        step: stage.step,
        tools: stage.tools ?? collectorTools,
      },
      stage: "pi",
    })
    .finally(() => heartbeat.stop());

  const artifactPaths = await pullRuntimeArtifacts({
    jobName: stage.jobName,
    outputsDir: stage.input.outputsDir,
    result,
    runDir: stage.input.runDir,
    sandbox: stage.input.sandbox,
  });
  const jobState = toRunJobState(stage.jobName, result, artifactPaths);

  try {
    assertPiJobCompleted(result, stage.step);
    const artifact = await readPiStructuredArtifact(stage, result, artifactPaths);
    stage.validateSchema(artifact);

    const artifactPath = await stage.input.store.writeJson({
      data: artifact,
      id: stage.artifactId,
      kind: stage.kind,
      relativePath: stage.artifactRelativePath,
    });
    jobState.artifacts.push(artifactPath);
    await stage.input.onJobFinished?.(jobState);

    return {
      artifact,
      artifactPath,
      jobState,
    };
  } catch (error) {
    jobState.status = "failed";
    jobState.finished_at = new Date().toISOString();
    jobState.diagnostics =
      error instanceof ScanStageError
        ? error.diagnostics.length > 0
          ? error.diagnostics
          : [error.message]
        : [errorMessage(error)];
    await stage.input.onJobFinished?.(jobState);
    throw error;
  }
}

function startPiStageHeartbeat<TArtifact extends PiStructuredArtifact>(
  stage: PiStageInput<TArtifact>,
): { stop: () => Promise<void> } {
  if (stage.input.onProgress === undefined) {
    return { stop: async () => undefined };
  }

  let progressQueue: Promise<unknown> = Promise.resolve();
  const timer = setInterval(() => {
    progressQueue = progressQueue.then(() =>
      Promise.resolve(
        stage.input.onProgress?.({
          details: { heartbeat_source: "host", step: stage.step },
          job: stage.jobName,
          message: `${stage.step} collector: still running in Daytona sandbox.`,
          type: "pi.host.heartbeat",
        }),
      ).catch(() => undefined),
    );
  }, 60_000);
  timer.unref();

  return {
    stop: async () => {
      clearInterval(timer);
      await progressQueue;
    },
  };
}

function piHandoffArtifact(artifact: PiStructuredArtifact): unknown {
  return stripHandoffMetadata(artifact);
}

function piAgentOutputFile(outputBaseName: PiStructuredArtifact["kind"]): string {
  return `.vibeshield-pi-output/${outputBaseName}.json`;
}

function withPiOutputFileInstruction(input: { outputFile: string; prompt: string }): string {
  return `${input.prompt}

Output file contract:
- The JSON artifact MUST be written to this file using the write tool: ${input.outputFile}
- This file is the primary result consumed by VibeShield.
- Write exactly one JSON object to the file.
- Do not write markdown fences or explanatory text to the file.
- Do not modify any repository file other than this output file.`;
}

function stripHandoffMetadata(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => stripHandoffMetadata(item));
  }
  if (value === null || typeof value !== "object") {
    return value;
  }

  const output: Record<string, unknown> = {};
  for (const [key, childValue] of Object.entries(value)) {
    if (key === "metadata") {
      continue;
    }
    output[key] = stripHandoffMetadata(childValue);
  }
  return output;
}

function assertPiJobCompleted(result: RuntimeJobResult, step: string): void {
  if (result.status !== "failed") {
    return;
  }

  throw new ScanStageError({
    diagnostics: result.diagnostics,
    message: result.diagnostics.join("\n") || `Pi ${step} failed.`,
    stage: "pi",
    userMessage: `VibeShield stopped while running Pi ${step}.`,
  });
}

async function readPiStructuredArtifact<TArtifact extends PiStructuredArtifact>(
  stage: PiStageInput<TArtifact>,
  result: RuntimeJobResult,
  artifactPaths: string[],
): Promise<TArtifact> {
  const rawOutputPath =
    artifactPaths.find((artifact) =>
      artifact.endsWith(`pi/${stage.outputBaseName}/${stage.outputBaseName}.raw.redacted.txt`),
    ) ?? `outputs/pi/${stage.outputBaseName}/${stage.outputBaseName}.raw.redacted.txt`;
  const metadataPath = artifactPaths.find((artifact) =>
    artifact.endsWith(`pi/${stage.outputBaseName}/metadata.json`),
  );

  const rawOutput = await readFile(path.join(stage.input.runDir, rawOutputPath), "utf8");
  const parsed = parseJsonObjectFromText(rawOutput, stage.validationStage, stage.step);
  const metadata = metadataPath
    ? await readJsonIfPresent<Record<string, unknown>>(
        path.join(stage.input.runDir, metadataPath),
        stage.step,
      )
    : {};

  return withRuntimeMetadata<TArtifact>({
    contextPath: stage.contextArtifactLabel,
    generatedAt: stage.generatedAt,
    kind: stage.kind,
    metadata,
    parsed,
    repo: stage.input.contextPack.repo,
    result,
    step: stage.step,
  });
}

export function validateCoverageStructureArtifact(input: {
  artifact: CoverageStructureArtifact;
}): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "coverage-structure", errors);
  requireArrayProperty(artifact, "repository_structure", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateStackBuildDepsArtifact(input: { artifact: StackBuildDepsArtifact }): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "stack-build-deps", errors);
  requireArrayProperty(artifact, "stack", errors);
  requireArrayProperty(artifact, "dependencies", errors);
  requireObjectProperty(artifact, "build", errors);
  requireArrayProperty(artifact.build, "commands", errors);
  requireArrayProperty(artifact.build, "manifests", errors);
  requireArrayProperty(artifact.build, "lockfiles", errors);
  requireOptionalArrayProperty(artifact, "ci", errors);
  requireOptionalArrayProperty(artifact, "dependency_notes", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateEntrypointsArtifact(input: { artifact: EntrypointsArtifact }): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "entrypoints", errors);
  requireArrayProperty(artifact, "entrypoints", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateAuthConfigSecretsArtifact(input: {
  artifact: AuthConfigSecretsArtifact;
}): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "auth-config-secrets", errors);
  requireArrayProperty(artifact, "auth", errors);
  requireArrayProperty(artifact, "config", errors);
  requireOptionalArrayProperty(artifact, "entrypoint_access", errors);
  requireOptionalArrayProperty(artifact, "secret_locations", errors);
  requireOptionalArrayProperty(artifact, "secret_references", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateStorageIntegrationsInfraArtifact(input: {
  artifact: StorageIntegrationsInfraArtifact;
}): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "storage-integrations-infra", errors);
  requireArrayProperty(artifact, "storage", errors);
  requireArrayProperty(artifact, "integrations", errors);
  requireArrayProperty(artifact, "infra", errors);
  requireOptionalArrayProperty(artifact, "ci", errors);
  requireOptionalArrayProperty(artifact, "infrastructure", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateOperationSinksArtifact(input: { artifact: OperationSinksArtifact }): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "operation-sinks", errors);
  requireArrayProperty(artifact, "operation_sinks", errors);
  requireOptionalArrayProperty(artifact, "sinks", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateDataFlowsArtifact(input: { artifact: DataFlowsArtifact }): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "data-flows", errors);
  requireArrayProperty(artifact, "flows", errors);
  requireObjectProperty(artifact, "inputs", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateTrustBoundariesArtifact(input: {
  artifact: TrustBoundariesArtifact;
}): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "trust-boundaries", errors);
  requireArrayProperty(artifact, "boundaries", errors);
  requireOptionalObjectProperty(artifact, "inputs", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateRepositoryMapArtifact(input: { artifact: RepositoryMapArtifact }): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "repository-map", errors);
  requireObjectProperty(artifact, "summary", errors);
  requireArrayProperty(artifact, "sections", errors);
  requireOptionalObjectProperty(artifact, "inputs", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

function buildCoverageStructurePrompt(contextPack: PiContextPackArtifact): string {
  return `${factsOnlyPreamble()}

Task:
Create the coverage-structure section artifact. This artifact answers assignment sections 0 and 2:
- coverage and completeness;
- shallow repository structure.

Collect only observable facts:
- repository size and language LOC from Stage input inventory only;
- top-level tree, 1-2 levels deep;
- meaningful source/test/config/infra/docs/dependency areas and their purpose;
- directories reviewed;
- directories excluded or not covered and why;
- places without access or without enough evidence.

Depth bounds:
- Use inventory and focused file reads only.
- Do not treat README, docs, examples, or marketing copy as truth about code behavior. They may be cited only as documentation files.
- Do not perform exhaustive directory traversal when inventory already gives the structure.
- Do not inspect every source file.
- Do not list individual files except as representative evidence for a directory role.

Write ONLY valid JSON matching coverage-structure:
{
  "kind": "coverage-structure",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "repo_size": { "file_count": 0, "total_loc": 0, "source": "inventory" },
  "language_summary": [
    { "language": "string", "file_count": 0, "loc": 0, "source": "inventory" }
  ],
  "top_level_tree": [
    { "path": "relative/path", "depth": 1, "kind": "source|test|config|docs|infra|generated|dependency|other", "role": "directory purpose", "evidence": ["relative/path:line"] }
  ],
  "reviewed_directories": [
    { "path": "relative/path", "reason": "why reviewed", "evidence": ["relative/path:line"] }
  ],
  "excluded_directories": [
    { "path": "relative/path", "reason": "vendored|generated|binary|too large|not relevant|not present", "evidence": ["relative/path:line"] }
  ],
  "access_gaps": [
    { "area": "string", "reason": "string", "evidence": ["relative/path:line"] }
  ],
  "repository_structure": [
    { "path": "relative/path", "kind": "source|test|config|docs|infra|generated|dependency|other", "role": "string", "evidence": ["relative/path:line"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path:line"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path:line"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildStackBuildDepsPrompt(contextPack: PiContextPackArtifact): string {
  return `${factsOnlyPreamble()}

Task:
Create the stack-build-deps section artifact. This artifact answers assignment sections 1 and 11:
- stack and build;
- dependency inventory.

Collect only observable facts from manifests and config files:
- languages and their declared or inventory-derived share;
- frameworks and versions;
- runtimes and required versions;
- package managers;
- build systems and declared commands;
- CI/CD workflow files and declared steps;
- manifest files and lock files;
- direct dependencies with declared versions;
- lockfile presence or absence;
- vendored dependency directories as a fact when observable.

Depth bounds:
- Do not install dependencies.
- Do not run package scripts, builds, tests, migrations, or generators.
- Do not infer runtime behavior from dependency names alone.
- Do not expand transitive dependencies manually. If a lockfile exists, record that transitive dependencies are available through it.
- Commands are declarations found in manifests/config, not commands you ran.

Write ONLY valid JSON matching stack-build-deps:
{
  "kind": "stack-build-deps",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "stack": [
    { "id": "stable short id", "kind": "language|runtime|framework|package-manager|build-tool|test-tool|service|dependency|other", "name": "string", "version": "optional string", "required_version": "optional string", "share": "optional inventory share", "role": "string", "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
  ],
  "build": {
    "manifests": [{ "path": "relative/path", "evidence": ["relative/path:line"] }],
    "lockfiles": [{ "path": "relative/path", "evidence": ["relative/path:line"] }],
    "commands": [{ "id": "stable short id", "name": "string", "command": "declared command string", "source": "relative/path", "evidence": ["relative/path:line"] }]
  },
  "ci": [
    { "id": "stable short id", "file": "relative/path", "step": "declared step name", "command": "declared command string", "evidence": ["relative/path:line"] }
  ],
  "dependencies": [
    { "id": "stable short id", "kind": "dependency|framework|service|other", "name": "string", "version": "declared version", "direct": true, "role": "runtime|dev|peer|optional|other", "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
  ],
  "dependency_notes": [
    { "kind": "lockfile_present|lockfile_absent|transitive_available|vendored_dependencies", "path": "optional relative/path", "summary": "short fact", "evidence": ["relative/path:line"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path:line"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path:line"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildEntrypointsPrompt(contextPack: PiContextPackArtifact): string {
  return `${factsOnlyPreamble()}

Task:
Create the entrypoints section artifact. This artifact answers assignment section 3.

Collect externally reachable or externally triggered boundaries only:
- HTTP routes;
- GraphQL resolvers;
- gRPC services/methods;
- CLI commands;
- queue/event/message handlers;
- webhooks;
- cron/scheduled jobs;
- file upload handlers;
- parsers of external formats when they are the invoked boundary.

Depth bounds:
- Stay at boundary level.
- Do not perform line-by-line handler analysis.
- Do not analyze handler bodies beyond what is needed to classify the boundary.
- Do not list internal helper functions, serializers, SDK calls, or transformations as entrypoints.
- Prefer declaration and registration evidence when both are visible.
- Include handler or callback name/path when observable.
- If a framework generates many equivalent routes, group only when necessary and explain the gap in coverage.not_covered.

Write ONLY valid JSON matching entrypoints:
{
  "kind": "entrypoints",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "entrypoints": [
    {
      "id": "stable short id",
      "kind": "http_route|graphql_resolver|grpc_method|cli_command|queue_event_handler|webhook|cron_job|file_upload_handler|external_format_parser|other",
      "name": "string",
      "location": "relative/path",
      "method": "optional string",
      "route": "optional string",
      "handler": "optional handler or callback name",
      "command": "optional string",
      "schedule": "optional string",
      "confidence": "low|medium|high",
      "evidence": ["relative/path:line"]
    }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path:line"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path:line"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildAuthConfigSecretsPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the auth-config-secrets section artifact. This artifact answers assignment sections 4 and 7:
- authentication and authorization;
- secrets and configuration.

Collect only:
- auth mechanisms: session, JWT, OAuth, API key, mTLS, provider config;
- middleware, guards, decorators, authorization checks, role/scope checks;
- where sessions or credentials are stored or checked when observable;
- protected/public/unknown status for entrypoints from inputs.entrypoints;
- config files, environment variable names, config loaders, default values by name only;
- .env files and examples;
- secret-manager references;
- hardcoded secret-like string locations as facts only, never values.

Depth bounds:
- Do not verify auth correctness.
- Do not infer missing authorization.
- Do not rediscover entrypoints. Use inputs.entrypoints for endpoint IDs and status mapping.
- Do not output secret values, connection strings, cookies, tokens, private keys, or passwords. Use only names and set value_redacted true for secret_references.
- Do not root-cause configuration behavior.

Write ONLY valid JSON matching auth-config-secrets:
{
  "kind": "auth-config-secrets",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "auth": [
    { "id": "stable short id", "kind": "auth_config|authorization_rule|identity_provider|middleware|other", "name": "string", "mechanism": "optional session|jwt|oauth|api-key|mtls|other", "location": "relative/path", "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
  ],
  "entrypoint_access": [
    { "entrypoint_id": "id from inputs.entrypoints", "status": "protected|public|unknown", "mechanism": "optional string", "roles_scopes": ["optional role or scope names"], "session_storage": "optional observed storage/check location", "evidence": ["relative/path:line"] }
  ],
  "config": [
    { "id": "stable short id", "kind": "config_source|other", "name": "env/config key name", "location": "relative/path", "value_status": "unset|defaulted|required|example|unknown", "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
  ],
  "secret_references": [
    { "id": "stable short id", "kind": "secret_reference|credential_reference|other", "name": "secret name only", "location": "relative/path", "confidence": "low|medium|high", "value_redacted": true, "evidence": ["relative/path:line"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path:line"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path:line"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildStorageIntegrationsInfraPrompt(contextPack: PiContextPackArtifact): string {
  return `${factsOnlyPreamble()}

Task:
Create the storage-integrations-infra section artifact. This artifact answers assignment sections 9, 10, and 12:
- storage and data model;
- external integrations and network egress;
- infrastructure and deployment.

Collect only map facts:
- databases and their types;
- ORM models, schemas, migrations;
- caches, queues, object/file storage and buckets;
- entities or fields that appear personal/sensitive by schema or field name only;
- external APIs, SDK providers, configured hosts, message brokers;
- Dockerfile facts: base image, user, exposed ports, entrypoint;
- compose/k8s facts: services, ports, mounts, secrets;
- IaC and proxy/server config declarations.

Depth bounds:
- Do not call external services.
- Do not run Docker, Terraform, package scripts, or workflow commands.
- Do not assess exposure, permissions, risk, or misconfiguration.
- Do not trace integration call chains; record declarations and direct client setup at map level.
- Do not infer data sensitivity beyond field/schema names.

Write ONLY valid JSON matching storage-integrations-infra:
{
  "kind": "storage-integrations-infra",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "storage": [
    { "id": "stable short id", "kind": "database|cache|message_queue|object_storage|file_storage|other", "name": "string", "type": "optional string", "location": "relative/path", "role": "string", "fields": ["optional observed field names"], "data_categories": ["optional observed categories by field name"], "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
  ],
  "integrations": [
    { "id": "stable short id", "kind": "external_api|service|message_broker|other", "name": "string", "from": "relative/path", "target": "host/service/sdk when observable", "location": "relative/path", "role": "purpose as declared", "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
  ],
  "infra": [
    { "id": "stable short id", "kind": "dockerfile|compose|kubernetes|iac|proxy|hosting|runtime|service|other", "name": "string", "location": "relative/path", "base_image": "optional string", "user": "optional string", "ports": ["optional observed ports"], "mounts": ["optional observed mounts"], "secrets": ["optional secret names only"], "entrypoint": "optional string", "role": "string", "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path:line"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path:line"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildOperationSinksPrompt(contextPack: PiContextPackArtifact): string {
  return `${factsOnlyPreamble()}

Task:
Create the operation-sinks section artifact. This artifact answers assignment sections 6, 8, and 13:
- operation sink inventory;
- cryptography;
- logging and observability.

Collect observable operation families only. Do not make security claims.

Operation families:
- SQL/ORM/raw query/query builder, including observed query construction style;
- NoSQL queries;
- shell/process execution;
- filesystem operations and path construction;
- path construction from variables;
- deserialization/parsing of external data;
- template rendering;
- redirects;
- outbound HTTP/client SDK URL construction;
- crypto operations, algorithms, modes, key/IV/salt parameters when directly visible;
- password hashing calls;
- TLS configuration calls;
- randomness sources;
- logging/observability calls, destinations, and logged external-input or storage-field names when directly visible.

Depth bounds:
- Stay at operation-family level.
- Do not trace callers, taint, exploitability, severity, impact, or fixes.
- Do not create one item per repeated helper call or log line.
- Do not perform root-cause or full business-logic analysis.
- Cite operation lines or nearby variable construction lines that directly support classification.

Write ONLY valid JSON matching operation-sinks:
{
  "kind": "operation-sinks",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "operation_sinks": [
    {
      "id": "stable short id",
      "kind": "sql_or_orm_query|nosql_query|process_execution|filesystem_operation|path_construction|deserialization_or_parsing|template_rendering|redirect|outbound_http_or_sdk_url|crypto_operation|randomness|logging|other",
      "operation": "observable operation only",
      "location": "relative/path",
      "input_variables": ["optional variable names"],
      "query_construction": "optional parameterized|concatenated|literal|unknown",
      "algorithm": "optional observed crypto/hash algorithm",
      "mode": "optional observed crypto mode",
      "parameters": ["optional observed parameter names only"],
      "destination": "optional logging/egress destination",
      "logged_fields": ["optional observed field or variable names"],
      "confidence": "low|medium|high",
      "evidence": ["relative/path:line"]
    }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path:line"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path:line"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildDataFlowsPrompt(context: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the data-flows section artifact. This artifact answers assignment section 5.
Use only inputs.entrypoints and inputs.operation_sinks from the stage input.

Rules:
- Do not use coverage-structure, stack-build-deps, auth-config-secrets, storage-integrations-infra, trust-boundaries, or repository-map as data-flow inputs.
- Start from externally controlled entrypoints and operation-sink evidence only.
- Read repository files only to confirm a direct or shallow named connection.
- Prefer key externally controlled inputs; do not enumerate every possible variable flow.
- Do not perform exhaustive tracing, line-by-line handler review, callback resolution, framework internals analysis, or root-cause analysis.
- Use "multi-step inferred" only for one or two named function hops with evidence.
- Use "not traced beyond path:line" or "not established" when deeper analysis would be required.
- Every row with a connection across functions or files must set inference true.

Write ONLY valid JSON matching data-flows:
{
  "kind": "data-flows",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "inputs": {
    "entrypoints_artifact": "${repoMapPaths.entrypoints}",
    "operation_sinks_artifact": "${repoMapPaths.operationSinks}"
  },
  "flows": [
    {
      "id": "stable short id",
      "source_entrypoint": "entrypoint id",
      "source_evidence": ["relative/path:line"],
      "intermediate_functions": [{ "name": "string", "evidence": ["relative/path:line"] }],
      "operation_sink": "operation sink id",
      "operation_sink_evidence": ["relative/path:line"],
      "trace_status": "direct observed|multi-step inferred|not traced beyond path:line|not established",
      "breakpoint": null,
      "inference": true
    }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path:line"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path:line"] }]
}

Stage input:
${JSON.stringify(context, null, 2)}`;
}

function buildTrustBoundariesPrompt(context: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the trust-boundaries section artifact. This artifact answers assignment section 14.
Use prior map artifacts only. This is synthesis-only.

Rules:
- Do not call read, grep, find, ls, or any other tool.
- Do not inspect repository files.
- Do not add repository facts that are absent from the supplied prior artifacts.
- Every boundary must set inference true.
- Boundaries are map-level inferences, not vulnerabilities, risks, findings, or audit questions.
- Base boundaries primarily on entrypoints, operation sinks, and data flows. Use storage/integration facts only to name the internal side when already present.
- Use evidence already present in prior artifacts.

Write ONLY valid JSON matching trust-boundaries:
{
  "kind": "trust-boundaries",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "inputs": {
    "coverage_structure_artifact": "${repoMapPaths.coverageStructure}",
    "stack_build_deps_artifact": "${repoMapPaths.stackBuildDeps}",
    "entrypoints_artifact": "${repoMapPaths.entrypoints}",
    "auth_config_secrets_artifact": "${repoMapPaths.authConfigSecrets}",
    "storage_integrations_infra_artifact": "${repoMapPaths.storageIntegrationsInfra}",
    "operation_sinks_artifact": "${repoMapPaths.operationSinks}",
    "data_flows_artifact": "${repoMapPaths.dataFlows}"
  },
  "boundaries": [
    {
      "id": "stable short id",
      "kind": "external_user_to_app|repository_to_ci|runtime_to_external_service|storage|network|process|trust_zone|other",
      "name": "string",
      "description": "map-level boundary inference",
      "confidence": "low|medium|high",
      "source_artifact_ids": ["entrypoints", "operation-sinks"],
      "inference": true,
      "evidence": ["relative/path:line"]
    }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path:line"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "inference": true, "evidence": ["relative/path:line"] }]
}

Stage input:
${JSON.stringify(context, null, 2)}`;
}

function buildRepositoryMapPrompt(context: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the final repository-map artifact from the supplied section artifacts only.

Rules:
- Do not call read, grep, find, ls, or any other tool.
- Do not inspect repository files.
- Do not add new facts, entrypoints, operation sinks, data flows, trust boundaries, or security conclusions.
- Summary is a compact map-level inference and must set inference true.
- Keep this as an index and orientation artifact, not a report and not an audit.

Write ONLY valid JSON matching repository-map:
{
  "kind": "repository-map",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "inputs": {
    "coverage_structure_artifact": "${repoMapPaths.coverageStructure}",
    "stack_build_deps_artifact": "${repoMapPaths.stackBuildDeps}",
    "entrypoints_artifact": "${repoMapPaths.entrypoints}",
    "auth_config_secrets_artifact": "${repoMapPaths.authConfigSecrets}",
    "storage_integrations_infra_artifact": "${repoMapPaths.storageIntegrationsInfra}",
    "operation_sinks_artifact": "${repoMapPaths.operationSinks}",
    "data_flows_artifact": "${repoMapPaths.dataFlows}",
    "trust_boundaries_artifact": "${repoMapPaths.trustBoundaries}"
  },
  "summary": {
    "project_kind": "string",
    "text": "compact map-level orientation",
    "confidence": "low|medium|high",
    "inference": true,
    "evidence": ["relative/path:line"]
  },
  "sections": [
    { "artifact": "coverage-structure", "path": "${repoMapPaths.coverageStructure}", "item_count": 0, "summary": "string", "evidence": ["relative/path:line"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path:line"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "inference": true, "evidence": ["relative/path:line"] }]
}

Stage input:
${JSON.stringify(context, null, 2)}`;
}

function factsOnlyPreamble(): string {
  return `You are a static AppSec repository cartographer in read-only, facts-only mode.

Goal:
Create compact, evidence-backed JSON map artifacts for later human review.
Stay at map level: identify observable repository structure, declared stack, entrypoints, config references, integrations, operation families, shallow data connections, and explicit inference boundaries.

Forbidden:
- Do not look for vulnerabilities.
- Do not assess severity, risk, impact, exploitability, likelihood, CWE, CVE, or fixes.
- Do not write findings, recommendations, root causes, remediation, audit questions, or risk hints.
- Do not perform exhaustive code review, line-by-line handler analysis, full control-flow tracing, framework internals tracing, or root-cause analysis.
- Do not trust README, docs, examples, comments, or marketing text as truth about actual code behavior. Use them only as evidence that documentation exists or claims something.
- Do not run the application, tests, builds, package scripts, migrations, Docker build/run, dependency installation, generators, or network calls.
- Do not modify analyzed repository files.
- You may write only the requested VibeShield JSON output file.

Allowed collector tools:
- read
- grep
- find
- ls
- write, only for the requested VibeShield JSON output file

Evidence rules:
- Every claimed fact must have evidence as relative/path:line or relative/path:start-end.
- Inventory-derived metrics such as repo_size and language_summary use
  source "inventory" and do not need path-line evidence.
- Evidence must point to repository files, not tool calls. Never output evidence
  like "ls: .", "grep: pattern", "read: file", or any other tool invocation.
- For repository layout or coverage claims, cite representative files with
  line evidence. If no file-line evidence exists, record the limitation in
  coverage.not_covered or fact_gaps instead of inventing tool-call evidence.
- If line evidence is unavailable, omit the claim or put the uncertainty in fact_gaps or coverage.not_covered.
- fact_gaps may use "evidence": [] when the missing fact is absence, unknown
  state, or an intentionally uncovered area. Do not invent evidence for gaps.
- If a fact is inferred from multiple artifacts, set inference true where the schema allows it and include the supporting evidence.
- Do not quote large code blocks.
- Do not output full secret, token, private key, cookie, password, or connection string values; use names only or redacted previews.

Output rules:
- Save exactly one JSON object to the output file named at the end of this prompt.
- The saved file is the result consumed by VibeShield.
- Do not wrap JSON in markdown fences.
- Keep output compact. Use short factual phrases, not paragraphs.
- Do not enumerate repeated files, routes, helpers, dependencies, or operation calls exhaustively.
- Group repeated patterns by family and cite representative evidence.
- Do not include raw file inventories, full dependency lists, tool output, or progress logs.
- Include coverage.reviewed, coverage.not_covered, and fact_gaps.`;
}

async function pullRuntimeArtifacts(input: {
  jobName: string;
  outputsDir: string;
  result: RuntimeJobResult;
  runDir: string;
  sandbox: SandboxSession;
}): Promise<string[]> {
  const artifactPaths: string[] = [];

  for (const artifact of input.result.artifacts) {
    const localPath = path.join(input.outputsDir, artifact.relativePath);
    await input.sandbox.pullFile(artifact.sandboxPath, localPath, {
      artifact: artifact.relativePath,
      job: input.jobName,
      stage: "pi",
    });
    artifactPaths.push(relativeArtifactPath(input.runDir, localPath));
  }

  return artifactPaths;
}

function toRunJobState(
  jobName: string,
  result: RuntimeJobResult,
  artifactPaths: string[],
): RunJobState {
  return {
    artifacts: [...artifactPaths],
    diagnostics: result.diagnostics,
    finished_at: result.finishedAt,
    invocation: result.invocation,
    name: jobName,
    observations: result.observations.length,
    ...(result.skippedReason === undefined ? {} : { skipped_reason: result.skippedReason }),
    started_at: result.startedAt,
    status:
      result.status === "completed" ? "success" : result.status === "failed" ? "failed" : "skipped",
    ...(result.version === undefined ? {} : { version: result.version }),
  };
}

function parseJsonObjectFromText(
  text: string,
  validationStage: PiStageValidationStage,
  step: string,
): unknown {
  const trimmed = text.trim();
  if (trimmed === "") {
    throw new ScanStageError({
      diagnostics: [`Pi ${step} output file was empty.`],
      message: `Pi ${step} output file was empty.`,
      stage: asRunStage(validationStage),
      userMessage: `VibeShield rejected Pi ${step} output because the output file was empty.`,
    });
  }

  for (const candidate of jsonCandidates(trimmed)) {
    try {
      return JSON.parse(candidate);
    } catch {
      // Try the next extraction strategy before reporting a validation failure.
    }
  }

  throw new ScanStageError({
    message: `Pi ${step} output was not valid JSON.`,
    stage: asRunStage(validationStage),
    userMessage: `VibeShield rejected Pi ${step} output because it was not valid JSON.`,
  });
}

function jsonCandidates(trimmed: string): string[] {
  const candidates = [trimmed];
  for (const match of trimmed.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)) {
    if (match[1] !== undefined) {
      candidates.push(match[1].trim());
    }
  }

  for (const candidate of balancedJsonObjectCandidates(trimmed)) {
    candidates.push(candidate);
  }

  return Array.from(new Set(candidates));
}

function balancedJsonObjectCandidates(text: string): string[] {
  const candidates: string[] = [];
  for (let start = 0; start < text.length; start += 1) {
    if (text[start] !== "{") {
      continue;
    }

    const end = balancedJsonObjectEnd(text, start);
    if (end !== undefined) {
      candidates.push(text.slice(start, end + 1).trim());
    }
  }

  return candidates;
}

function balancedJsonObjectEnd(text: string, start: number): number | undefined {
  let depth = 0;
  let escaped = false;
  let inString = false;

  for (let index = start; index < text.length; index += 1) {
    const char = text[index];

    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === '"') {
        inString = false;
      }
      continue;
    }

    if (char === '"') {
      inString = true;
      continue;
    }

    if (char === "{") {
      depth += 1;
      continue;
    }

    if (char === "}") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }

  return undefined;
}

async function readJsonIfPresent<T>(filePath: string, step: string): Promise<T> {
  try {
    return JSON.parse(await readFile(filePath, "utf8")) as T;
  } catch (error) {
    throw new ScanStageError({
      cause: error,
      message: `Could not read Pi ${step} metadata: ${errorMessage(error)}`,
      stage: "pi",
      userMessage: `VibeShield could not read Pi ${step} metadata from the sandbox.`,
    });
  }
}

function withRuntimeMetadata<TArtifact extends PiStructuredArtifact>(input: {
  contextPath: string;
  generatedAt: string;
  kind: TArtifact["kind"];
  metadata: Record<string, unknown>;
  parsed: unknown;
  repo: PiContextPackArtifact["repo"];
  result: RuntimeJobResult;
  step: TArtifact["kind"];
}): TArtifact {
  if (input.parsed === null || typeof input.parsed !== "object" || Array.isArray(input.parsed)) {
    throw new ScanStageError({
      message: `Pi ${input.step} output JSON was not an object.`,
      stage: asRunStage(validationStageForKind(input.kind)),
      userMessage: `VibeShield rejected Pi ${input.step} output because it was not a JSON object.`,
    });
  }

  const parsed = redactDeep(input.parsed) as Record<string, unknown>;
  if (!isCoverageShape(parsed.coverage)) {
    parsed.coverage = { not_covered: [], reviewed: [] };
  }
  if (!Array.isArray(parsed.fact_gaps)) {
    parsed.fact_gaps = [];
  }
  normalizeParsedArtifact(input.kind, parsed);
  const metadata = input.metadata as {
    model?: unknown;
    output_bytes?: unknown;
    output_file?: unknown;
    provider?: unknown;
    stderr_bytes?: unknown;
    step?: unknown;
    version?: unknown;
  };

  return {
    ...parsed,
    generated_at: typeof parsed.generated_at === "string" ? parsed.generated_at : input.generatedAt,
    generated_by: "pi",
    kind: input.kind,
    metadata: {
      ...(typeof parsed.metadata === "object" && parsed.metadata !== null ? parsed.metadata : {}),
      pi: {
        input_context_artifact: input.contextPath,
        invocation: input.result.invocation,
        model: typeof metadata.model === "string" ? metadata.model : defaultPiModel,
        ...(typeof metadata.output_bytes === "number"
          ? { output_bytes: metadata.output_bytes }
          : {}),
        ...(typeof metadata.output_file === "string" ? { output_file: metadata.output_file } : {}),
        provider: typeof metadata.provider === "string" ? metadata.provider : defaultPiProvider,
        ...(typeof metadata.stderr_bytes === "number"
          ? { stderr_bytes: metadata.stderr_bytes }
          : {}),
        step: typeof metadata.step === "string" ? metadata.step : input.step,
        ...(typeof metadata.version === "string" && metadata.version !== ""
          ? { version: metadata.version }
          : input.result.version === undefined
            ? {}
            : { version: input.result.version }),
      },
    },
    repo: input.repo,
  } as TArtifact;
}

function validationStageForKind(kind: PiStructuredArtifact["kind"]): PiStageValidationStage {
  switch (kind) {
    case "auth-config-secrets":
      return "auth-config-secrets-validation";
    case "coverage-structure":
      return "coverage-structure-validation";
    case "data-flows":
      return "data-flows-validation";
    case "entrypoints":
      return "entrypoints-validation";
    case "operation-sinks":
      return "operation-sinks-validation";
    case "repository-map":
      return "repository-map-validation";
    case "stack-build-deps":
      return "stack-build-deps-validation";
    case "storage-integrations-infra":
      return "storage-integrations-infra-validation";
    case "trust-boundaries":
      return "trust-boundaries-validation";
  }
}

function normalizeParsedArtifact(
  kind: PiStructuredArtifact["kind"],
  parsed: Record<string, unknown>,
): void {
  if (kind === "entrypoints") {
    for (const entrypoint of optionalArrayField<Record<string, unknown>>(parsed, "entrypoints")) {
      if (typeof entrypoint.route !== "string" && typeof entrypoint.path === "string") {
        entrypoint.route = entrypoint.path;
      }
    }
  }

  if (kind === "auth-config-secrets") {
    for (const auth of optionalArrayField<Record<string, unknown>>(parsed, "auth")) {
      if (typeof auth.kind !== "string") {
        auth.kind =
          typeof auth.mechanism === "string" && auth.mechanism.includes("middleware")
            ? "middleware"
            : "other";
      }
    }
  }

  if (kind === "storage-integrations-infra") {
    const infra = optionalArrayField(parsed, "infra");
    if (infra.length === 0) {
      const infrastructure = optionalArrayField(parsed, "infrastructure");
      if (infrastructure.length > 0) {
        parsed.infra = infrastructure;
      }
    }
  }

  if (kind === "operation-sinks") {
    const operationSinks = optionalArrayField(parsed, "operation_sinks");
    if (operationSinks.length === 0) {
      const sinks = optionalArrayField(parsed, "sinks");
      if (sinks.length > 0) {
        parsed.operation_sinks = sinks;
      }
    }
  }

  if (kind === "data-flows" && !isRecord(parsed.inputs)) {
    parsed.inputs = {
      entrypoints_artifact: repoMapPaths.entrypoints,
      operation_sinks_artifact: repoMapPaths.operationSinks,
    };
  }

  if (kind === "trust-boundaries" && !isRecord(parsed.inputs)) {
    parsed.inputs = priorMapArtifactPaths();
  }
  if (kind === "trust-boundaries") {
    for (const boundary of optionalArrayField<Record<string, unknown>>(parsed, "boundaries")) {
      boundary.flow_ids = Array.isArray(boundary.flow_ids) ? boundary.flow_ids : [];
      boundary.sink_ids = Array.isArray(boundary.sink_ids) ? boundary.sink_ids : [];
      boundary.source_entrypoint_ids = Array.isArray(boundary.source_entrypoint_ids)
        ? boundary.source_entrypoint_ids
        : [];
    }
  }

  if (kind === "repository-map" && !isRecord(parsed.inputs)) {
    parsed.inputs = allMapArtifactPaths();
  }
  if (kind === "repository-map") {
    const sections = optionalArrayField<Record<string, unknown>>(parsed, "sections");
    const hasSelfSection = sections.some((section) => section.path === repoMapPaths.repositoryMap);
    if (!hasSelfSection) {
      parsed.sections = [
        ...sections,
        {
          artifact: "repository-map",
          evidence: [],
          item_count: sections.length,
          path: repoMapPaths.repositoryMap,
          summary: "Final repository map index.",
        },
      ];
    }
  }
}

function validateBasePiArtifact(
  artifact: PiStructuredArtifact,
  kind: PiStructuredArtifact["kind"],
  errors: string[],
): void {
  if (artifact.kind !== kind) {
    errors.push(`${kind} schema kind is missing or invalid.`);
  }
  if (artifact.generated_by !== "pi") {
    errors.push(`${kind} must be generated_by pi.`);
  }
  if (typeof artifact.generated_at !== "string" || artifact.generated_at.trim() === "") {
    errors.push(`${kind}.generated_at must be a string.`);
  }
  if (!isRecord(artifact.repo)) {
    errors.push(`${kind}.repo must be an object.`);
  }
  if (!isRecord(artifact.metadata)) {
    errors.push(`${kind}.metadata must be an object.`);
  }
  if (artifact.coverage !== undefined) {
    requireObjectProperty(artifact, "coverage", errors);
    requireArrayProperty(artifact.coverage, "reviewed", errors);
    requireArrayProperty(artifact.coverage, "not_covered", errors);
  }
  if (artifact.fact_gaps !== undefined && !Array.isArray(artifact.fact_gaps)) {
    errors.push(`${kind}.fact_gaps must be an array.`);
  }
}

function requireArrayProperty(value: unknown, field: string, errors: string[]): void {
  if (!isRecord(value) || !Array.isArray(value[field])) {
    errors.push(`${field} must be an array.`);
  }
}

function requireOptionalArrayProperty(value: unknown, field: string, errors: string[]): void {
  if (!isRecord(value) || value[field] === undefined) {
    return;
  }
  if (!Array.isArray(value[field])) {
    errors.push(`${field} must be an array.`);
  }
}

function requireObjectProperty(value: unknown, field: string, errors: string[]): void {
  if (!isRecord(value) || !isRecord(value[field])) {
    errors.push(`${field} must be an object.`);
  }
}

function requireOptionalObjectProperty(value: unknown, field: string, errors: string[]): void {
  if (!isRecord(value) || value[field] === undefined) {
    return;
  }
  if (!isRecord(value[field])) {
    errors.push(`${field} must be an object.`);
  }
}

function optionalArrayField<T = Record<string, unknown>>(value: unknown, field: string): T[] {
  if (value === null || typeof value !== "object") {
    return [];
  }
  const candidate = (value as Record<string, unknown>)[field];
  return Array.isArray(candidate) ? (candidate as T[]) : [];
}

function isCoverageShape(value: unknown): value is {
  not_covered: unknown[];
  reviewed: unknown[];
} {
  return (
    value !== null &&
    typeof value === "object" &&
    Array.isArray((value as Record<string, unknown>).not_covered) &&
    Array.isArray((value as Record<string, unknown>).reviewed)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function throwIfValidationErrors(
  errors: string[],
  validationStage: PiStageValidationStage,
  kind: string,
): void {
  if (errors.length === 0) {
    return;
  }
  throw new ScanStageError({
    diagnostics: errors,
    message: `Pi ${kind} artifact failed validation.`,
    stage: asRunStage(validationStage),
    userMessage: `VibeShield rejected Pi ${kind} output because it did not match the repository-map contract.`,
  });
}

function asRunStage(stage: PiStageValidationStage): RunStage {
  return stage as RunStage;
}

function priorMapArtifactPaths(): Record<string, string> {
  return {
    auth_config_secrets_artifact: repoMapPaths.authConfigSecrets,
    coverage_structure_artifact: repoMapPaths.coverageStructure,
    data_flows_artifact: repoMapPaths.dataFlows,
    entrypoints_artifact: repoMapPaths.entrypoints,
    operation_sinks_artifact: repoMapPaths.operationSinks,
    stack_build_deps_artifact: repoMapPaths.stackBuildDeps,
    storage_integrations_infra_artifact: repoMapPaths.storageIntegrationsInfra,
  };
}

function allMapArtifactPaths(): Record<string, string> {
  return {
    ...priorMapArtifactPaths(),
    trust_boundaries_artifact: repoMapPaths.trustBoundaries,
  };
}
