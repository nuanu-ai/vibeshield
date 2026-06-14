import { readFile } from "node:fs/promises";
import path from "node:path";
import { jsonrepair } from "jsonrepair";
import type {
  AttackHypothesesArtifact,
  AuthAccessArtifact,
  AuthConfigRecord,
  ConfigSecretsArtifact,
  CoverageStructureArtifact,
  CryptoArtifact,
  DataFlowsArtifact,
  EntrypointsArtifact,
  ExternalIntegrationsEgressArtifact,
  InfraDeployArtifact,
  InventoryArtifact,
  LoggingObservabilityArtifact,
  OperationSinksArtifact,
  PiContextPackArtifact,
  RepositoryMapArtifact,
  StackBuildDepsArtifact,
  StorageDataModelArtifact,
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

const defaultPiModel = "deepseek/deepseek-v4-pro";
const defaultPiProvider = "openrouter";
const defaultPiThinking = "high";
const trustBoundariesPiModel = "openai/gpt-5.3-codex";
const attackHypothesesPiModel = "anthropic/claude-opus-4.8";
const collectorTools = ["read", "grep", "find", "ls"];

const repoMapPaths = {
  attackHypotheses: "outputs/attack-hypotheses.json",
  authAccess: "outputs/repo-map/auth-access.json",
  configSecrets: "outputs/repo-map/config-secrets.json",
  coverageStructure: "outputs/repo-map/coverage-structure.json",
  crypto: "outputs/repo-map/crypto.json",
  dataFlows: "outputs/repo-map/data-flows.json",
  entrypoints: "outputs/repo-map/entrypoints.json",
  externalIntegrationsEgress: "outputs/repo-map/external-integrations-egress.json",
  infraDeploy: "outputs/repo-map/infra-deploy.json",
  loggingObservability: "outputs/repo-map/logging-observability.json",
  operationSinks: "outputs/repo-map/operation-sinks.json",
  repositoryMap: "outputs/repository-map.json",
  stackBuildDeps: "outputs/repo-map/stack-build-deps.json",
  storageDataModel: "outputs/repo-map/storage-data-model.json",
  trustBoundaries: "outputs/repo-map/trust-boundaries.json",
} as const;

type PiStructuredArtifact =
  | AttackHypothesesArtifact
  | AuthAccessArtifact
  | ConfigSecretsArtifact
  | CoverageStructureArtifact
  | CryptoArtifact
  | DataFlowsArtifact
  | EntrypointsArtifact
  | ExternalIntegrationsEgressArtifact
  | InfraDeployArtifact
  | LoggingObservabilityArtifact
  | OperationSinksArtifact
  | RepositoryMapArtifact
  | StackBuildDepsArtifact
  | StorageDataModelArtifact
  | TrustBoundariesArtifact;

type PiStageValidationStage =
  | "attack-hypotheses-validation"
  | "auth-access-validation"
  | "config-secrets-validation"
  | "coverage-structure-validation"
  | "crypto-validation"
  | "data-flows-validation"
  | "entrypoints-validation"
  | "external-integrations-egress-validation"
  | "infra-deploy-validation"
  | "logging-observability-validation"
  | "operation-sinks-validation"
  | "repository-map-validation"
  | "stack-build-deps-validation"
  | "storage-data-model-validation"
  | "trust-boundaries-validation";

interface RunPiRepositoryMappingInput {
  contextPack: PiContextPackArtifact;
  contextPath: string;
  existing?: Partial<{
    attackHypotheses: ExistingPiArtifact<AttackHypothesesArtifact>;
    authAccess: ExistingPiArtifact<AuthAccessArtifact>;
    configSecrets: ExistingPiArtifact<ConfigSecretsArtifact>;
    coverageStructure: ExistingPiArtifact<CoverageStructureArtifact>;
    crypto: ExistingPiArtifact<CryptoArtifact>;
    dataFlows: ExistingPiArtifact<DataFlowsArtifact>;
    entrypoints: ExistingPiArtifact<EntrypointsArtifact>;
    externalIntegrationsEgress: ExistingPiArtifact<ExternalIntegrationsEgressArtifact>;
    infraDeploy: ExistingPiArtifact<InfraDeployArtifact>;
    loggingObservability: ExistingPiArtifact<LoggingObservabilityArtifact>;
    operationSinks: ExistingPiArtifact<OperationSinksArtifact>;
    repositoryMap: ExistingPiArtifact<RepositoryMapArtifact>;
    stackBuildDeps: ExistingPiArtifact<StackBuildDepsArtifact>;
    storageDataModel: ExistingPiArtifact<StorageDataModelArtifact>;
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
  attackHypotheses: AttackHypothesesArtifact;
  attackHypothesesPath: string;
  authAccess: AuthAccessArtifact;
  authAccessPath: string;
  configSecrets: ConfigSecretsArtifact;
  configSecretsPath: string;
  coverageStructure: CoverageStructureArtifact;
  coverageStructurePath: string;
  crypto: CryptoArtifact;
  cryptoPath: string;
  dataFlows: DataFlowsArtifact;
  dataFlowsPath: string;
  entrypoints: EntrypointsArtifact;
  entrypointsPath: string;
  externalIntegrationsEgress: ExternalIntegrationsEgressArtifact;
  externalIntegrationsEgressPath: string;
  infraDeploy: InfraDeployArtifact;
  infraDeployPath: string;
  jobStates: RunJobState[];
  loggingObservability: LoggingObservabilityArtifact;
  loggingObservabilityPath: string;
  operationSinks: OperationSinksArtifact;
  operationSinksPath: string;
  repositoryMap: RepositoryMapArtifact;
  repositoryMapPath: string;
  stackBuildDeps: StackBuildDepsArtifact;
  stackBuildDepsPath: string;
  storageDataModel: StorageDataModelArtifact;
  storageDataModelPath: string;
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
  model?: string;
  outputBaseName: TArtifact["kind"];
  prompt: string;
  step: TArtifact["kind"];
  thinking?: "high" | "low" | "medium" | "xhigh";
  tools?: string[];
  validateSchema: (artifact: TArtifact) => void;
  validationStage: PiStageValidationStage;
}

interface PiStageResult<TArtifact extends PiStructuredArtifact> {
  artifact: TArtifact;
  artifactPath: string;
  jobState: RunJobState;
}

interface ParsedPiJsonObject {
  jsonDelivery: "fenced" | "repaired" | "strict";
  parsed: unknown;
  repairApplied: boolean;
}

const repositoryMapProductIntent =
  "facts-only AppSec repository map for later attack-hypothesis building and manual review";

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
    (await buildDeterministicCoverageStructure({
      generatedAt: input.generatedAt,
      input: stageInput,
    }));

  const stackBuildDepsContext = buildStackBuildDepsContext(input.contextPack);
  const stackBuildDeps =
    input.existing?.stackBuildDeps ??
    (await runPiStage<StackBuildDepsArtifact>({
      artifactId: "stack-build-deps",
      artifactRelativePath: repoMapPaths.stackBuildDeps,
      contextArtifactLabel: input.contextPath,
      contextPack: stackBuildDepsContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-stack-deps",
      kind: "stack-build-deps",
      outputBaseName: "stack-build-deps",
      prompt: buildStackBuildDepsPrompt(stackBuildDepsContext),
      step: "stack-build-deps",
      validateSchema: (artifact) => validateStackBuildDepsArtifact({ artifact }),
      validationStage: "stack-build-deps-validation",
    }));

  const entrypointsContext = buildEntrypointsContext(input.contextPack, stackBuildDeps.artifact);
  const entrypoints =
    input.existing?.entrypoints ??
    (await runPiStage<EntrypointsArtifact>({
      artifactId: "entrypoints",
      artifactRelativePath: repoMapPaths.entrypoints,
      contextArtifactLabel: input.contextPath,
      contextPack: entrypointsContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-entrypoints",
      kind: "entrypoints",
      outputBaseName: "entrypoints",
      prompt: buildEntrypointsPrompt(entrypointsContext),
      step: "entrypoints",
      thinking: "xhigh",
      validateSchema: (artifact) => validateEntrypointsArtifact({ artifact }),
      validationStage: "entrypoints-validation",
    }));

  const configSecretsContext = buildConfigSecretsContext(input.contextPack);
  const configSecrets =
    input.existing?.configSecrets ??
    (await runPiStage<ConfigSecretsArtifact>({
      artifactId: "config-secrets",
      artifactRelativePath: repoMapPaths.configSecrets,
      contextArtifactLabel: input.contextPath,
      contextPack: configSecretsContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-config-secrets",
      kind: "config-secrets",
      outputBaseName: "config-secrets",
      prompt: buildConfigSecretsPrompt(configSecretsContext),
      step: "config-secrets",
      validateSchema: (artifact) => validateConfigSecretsArtifact({ artifact }),
      validationStage: "config-secrets-validation",
    }));

  const authAccessContext = buildAuthAccessContext(
    input.contextPack,
    entrypoints.artifact,
    configSecrets.artifact,
  );
  const authAccess =
    input.existing?.authAccess ??
    (await runPiStage<AuthAccessArtifact>({
      artifactId: "auth-access",
      artifactRelativePath: repoMapPaths.authAccess,
      contextArtifactLabel: `${input.contextPath}, ${entrypoints.artifactPath}, ${configSecrets.artifactPath}`,
      contextPack: authAccessContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-auth-access",
      kind: "auth-access",
      outputBaseName: "auth-access",
      prompt: buildAuthAccessPrompt(authAccessContext),
      step: "auth-access",
      validateSchema: (artifact) => validateAuthAccessArtifact({ artifact }),
      validationStage: "auth-access-validation",
    }));

  const storageDataModelContext = buildStorageDataModelContext(
    input.contextPack,
    configSecrets.artifact,
  );
  const storageDataModel =
    input.existing?.storageDataModel ??
    (await runPiStage<StorageDataModelArtifact>({
      artifactId: "storage-data-model",
      artifactRelativePath: repoMapPaths.storageDataModel,
      contextArtifactLabel: `${input.contextPath}, ${configSecrets.artifactPath}`,
      contextPack: storageDataModelContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-storage-data-model",
      kind: "storage-data-model",
      outputBaseName: "storage-data-model",
      prompt: buildStorageDataModelPrompt(storageDataModelContext),
      step: "storage-data-model",
      validateSchema: (artifact) => validateStorageDataModelArtifact({ artifact }),
      validationStage: "storage-data-model-validation",
    }));

  const externalIntegrationsEgressContext = buildExternalIntegrationsEgressContext(
    input.contextPack,
    configSecrets.artifact,
  );
  const externalIntegrationsEgress =
    input.existing?.externalIntegrationsEgress ??
    (await runPiStage<ExternalIntegrationsEgressArtifact>({
      artifactId: "external-integrations-egress",
      artifactRelativePath: repoMapPaths.externalIntegrationsEgress,
      contextArtifactLabel: `${input.contextPath}, ${configSecrets.artifactPath}`,
      contextPack: externalIntegrationsEgressContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-external-integrations-egress",
      kind: "external-integrations-egress",
      outputBaseName: "external-integrations-egress",
      prompt: buildExternalIntegrationsEgressPrompt(externalIntegrationsEgressContext),
      step: "external-integrations-egress",
      validateSchema: (artifact) => validateExternalIntegrationsEgressArtifact({ artifact }),
      validationStage: "external-integrations-egress-validation",
    }));

  const infraDeployContext = buildInfraDeployContext(input.contextPack);
  const infraDeploy =
    input.existing?.infraDeploy ??
    (await runPiStage<InfraDeployArtifact>({
      artifactId: "infra-deploy",
      artifactRelativePath: repoMapPaths.infraDeploy,
      contextArtifactLabel: input.contextPath,
      contextPack: infraDeployContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-infra-deploy",
      kind: "infra-deploy",
      outputBaseName: "infra-deploy",
      prompt: buildInfraDeployPrompt(infraDeployContext),
      step: "infra-deploy",
      validateSchema: (artifact) => validateInfraDeployArtifact({ artifact }),
      validationStage: "infra-deploy-validation",
    }));

  const operationSinksContext = buildOperationSinksContext(
    input.contextPack,
    stackBuildDeps.artifact,
  );
  const operationSinks =
    input.existing?.operationSinks ??
    (await runPiStage<OperationSinksArtifact>({
      artifactId: "operation-sinks",
      artifactRelativePath: repoMapPaths.operationSinks,
      contextArtifactLabel: input.contextPath,
      contextPack: operationSinksContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-operation-sinks",
      kind: "operation-sinks",
      outputBaseName: "operation-sinks",
      prompt: buildOperationSinksPrompt(operationSinksContext),
      step: "operation-sinks",
      thinking: "xhigh",
      validateSchema: (artifact) => validateOperationSinksArtifact({ artifact }),
      validationStage: "operation-sinks-validation",
    }));

  const cryptoContext = buildCryptoContext(input.contextPack);
  const crypto =
    input.existing?.crypto ??
    (await runPiStage<CryptoArtifact>({
      artifactId: "crypto",
      artifactRelativePath: repoMapPaths.crypto,
      contextArtifactLabel: input.contextPath,
      contextPack: cryptoContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-crypto",
      kind: "crypto",
      outputBaseName: "crypto",
      prompt: buildCryptoPrompt(cryptoContext),
      step: "crypto",
      validateSchema: (artifact) => validateCryptoArtifact({ artifact }),
      validationStage: "crypto-validation",
    }));

  const loggingObservabilityContext = buildLoggingObservabilityContext(
    input.contextPack,
    entrypoints.artifact,
    storageDataModel.artifact,
  );
  const loggingObservability =
    input.existing?.loggingObservability ??
    (await runPiStage<LoggingObservabilityArtifact>({
      artifactId: "logging-observability",
      artifactRelativePath: repoMapPaths.loggingObservability,
      contextArtifactLabel: input.contextPath,
      contextPack: loggingObservabilityContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-logging-observability",
      kind: "logging-observability",
      outputBaseName: "logging-observability",
      prompt: buildLoggingObservabilityPrompt(loggingObservabilityContext),
      step: "logging-observability",
      validateSchema: (artifact) => validateLoggingObservabilityArtifact({ artifact }),
      validationStage: "logging-observability-validation",
    }));

  const dataFlowContext = {
    inputs: {
      entrypoints: piHandoffArtifact(entrypoints.artifact),
      operation_sinks: piHandoffArtifact(operationSinks.artifact),
    },
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
      thinking: "xhigh",
      validateSchema: (artifact) => validateDataFlowsArtifact({ artifact }),
      validationStage: "data-flows-validation",
    }));

  const trustBoundariesContext = buildTrustBoundariesContextMarkdown({
    authAccess: authAccess.artifact,
    dataFlows: dataFlows.artifact,
    entrypoints: entrypoints.artifact,
    externalIntegrationsEgress: externalIntegrationsEgress.artifact,
    infraDeploy: infraDeploy.artifact,
    operationSinks: operationSinks.artifact,
    storageDataModel: storageDataModel.artifact,
  });
  const trustBoundaries =
    input.existing?.trustBoundaries ??
    (await runPiStage<TrustBoundariesArtifact>({
      artifactId: "trust-boundaries",
      artifactRelativePath: repoMapPaths.trustBoundaries,
      contextArtifactLabel: [
        coverageStructure.artifactPath,
        stackBuildDeps.artifactPath,
        entrypoints.artifactPath,
        authAccess.artifactPath,
        configSecrets.artifactPath,
        storageDataModel.artifactPath,
        externalIntegrationsEgress.artifactPath,
        infraDeploy.artifactPath,
        operationSinks.artifactPath,
        crypto.artifactPath,
        loggingObservability.artifactPath,
        dataFlows.artifactPath,
      ].join(", "),
      contextPack: trustBoundariesContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-trust-boundaries",
      kind: "trust-boundaries",
      model: trustBoundariesPiModel,
      outputBaseName: "trust-boundaries",
      prompt: buildTrustBoundariesPrompt(trustBoundariesContext),
      step: "trust-boundaries",
      thinking: "xhigh",
      tools: [],
      validateSchema: (artifact) => validateTrustBoundariesArtifact({ artifact }),
      validationStage: "trust-boundaries-validation",
    }));

  const repositoryMapContext = buildRepositoryMapContextMarkdown({
    authAccess: authAccess.artifact,
    configSecrets: configSecrets.artifact,
    coverageStructure: coverageStructure.artifact,
    crypto: crypto.artifact,
    dataFlows: dataFlows.artifact,
    entrypoints: entrypoints.artifact,
    externalIntegrationsEgress: externalIntegrationsEgress.artifact,
    infraDeploy: infraDeploy.artifact,
    loggingObservability: loggingObservability.artifact,
    operationSinks: operationSinks.artifact,
    stackBuildDeps: stackBuildDeps.artifact,
    storageDataModel: storageDataModel.artifact,
    trustBoundaries: trustBoundaries.artifact,
  });
  const repositoryMap =
    input.existing?.repositoryMap ??
    (await runPiStage<RepositoryMapArtifact>({
      artifactId: "repository-map",
      artifactRelativePath: repoMapPaths.repositoryMap,
      contextArtifactLabel: [
        coverageStructure.artifactPath,
        stackBuildDeps.artifactPath,
        entrypoints.artifactPath,
        authAccess.artifactPath,
        configSecrets.artifactPath,
        storageDataModel.artifactPath,
        externalIntegrationsEgress.artifactPath,
        infraDeploy.artifactPath,
        operationSinks.artifactPath,
        crypto.artifactPath,
        loggingObservability.artifactPath,
        dataFlows.artifactPath,
        trustBoundaries.artifactPath,
      ].join(", "),
      contextPack: repositoryMapContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-repository-map",
      kind: "repository-map",
      model: trustBoundariesPiModel,
      outputBaseName: "repository-map",
      prompt: buildRepositoryMapPrompt(repositoryMapContext),
      step: "repository-map",
      thinking: "xhigh",
      tools: [],
      validateSchema: (artifact) => validateRepositoryMapArtifact({ artifact }),
      validationStage: "repository-map-validation",
    }));

  const attackHypothesesContext = buildAttackHypothesesContextMarkdown({
    repositoryMap: repositoryMap.artifact,
    repositoryMapContext,
  });
  const attackHypotheses =
    input.existing?.attackHypotheses ??
    (await runPiStage<AttackHypothesesArtifact>({
      artifactId: "attack-hypotheses",
      artifactRelativePath: repoMapPaths.attackHypotheses,
      contextArtifactLabel: repositoryMap.artifactPath,
      contextPack: attackHypothesesContext,
      generatedAt: input.generatedAt,
      input: stageInput,
      jobName: "pi-attack-hypotheses",
      kind: "attack-hypotheses",
      model: attackHypothesesPiModel,
      outputBaseName: "attack-hypotheses",
      prompt: buildAttackHypothesesPrompt(attackHypothesesContext),
      step: "attack-hypotheses",
      thinking: "xhigh",
      tools: [],
      validateSchema: (artifact) => validateAttackHypothesesArtifact({ artifact }),
      validationStage: "attack-hypotheses-validation",
    }));

  return {
    attackHypotheses: attackHypotheses.artifact,
    attackHypothesesPath: attackHypotheses.artifactPath,
    authAccess: authAccess.artifact,
    authAccessPath: authAccess.artifactPath,
    configSecrets: configSecrets.artifact,
    configSecretsPath: configSecrets.artifactPath,
    coverageStructure: coverageStructure.artifact,
    coverageStructurePath: coverageStructure.artifactPath,
    crypto: crypto.artifact,
    cryptoPath: crypto.artifactPath,
    dataFlows: dataFlows.artifact,
    dataFlowsPath: dataFlows.artifactPath,
    entrypoints: entrypoints.artifact,
    entrypointsPath: entrypoints.artifactPath,
    externalIntegrationsEgress: externalIntegrationsEgress.artifact,
    externalIntegrationsEgressPath: externalIntegrationsEgress.artifactPath,
    infraDeploy: infraDeploy.artifact,
    infraDeployPath: infraDeploy.artifactPath,
    jobStates,
    loggingObservability: loggingObservability.artifact,
    loggingObservabilityPath: loggingObservability.artifactPath,
    operationSinks: operationSinks.artifact,
    operationSinksPath: operationSinks.artifactPath,
    repositoryMap: repositoryMap.artifact,
    repositoryMapPath: repositoryMap.artifactPath,
    stackBuildDeps: stackBuildDeps.artifact,
    stackBuildDepsPath: stackBuildDeps.artifactPath,
    storageDataModel: storageDataModel.artifact,
    storageDataModelPath: storageDataModel.artifactPath,
    trustBoundaries: trustBoundaries.artifact,
    trustBoundariesPath: trustBoundaries.artifactPath,
  };
}

function buildStackBuildDepsContext(contextPack: PiContextPackArtifact): unknown {
  const inventory = contextPack.inventory;
  return {
    inventory: {
      config_files: inventory.config_files,
      github_actions_workflows: inventory.github_actions_workflows,
      iac_candidates: inventory.iac_candidates,
      infra_files: inventory.infra_files,
      language_summary: inventory.language_summary,
      manifest_files: inventory.manifest_files,
      package_and_lock_files: inventory.package_and_lock_files,
      summary: inventory.summary,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
  };
}

function buildEntrypointsContext(
  contextPack: PiContextPackArtifact,
  stackBuildDeps: StackBuildDepsArtifact,
): unknown {
  const inventory = contextPack.inventory;
  return {
    inputs: {
      stack_build_deps: compactStackBuildDepsForCollectors(stackBuildDeps),
    },
    inventory: {
      config_files: inventory.config_files,
      github_actions_workflows: inventory.github_actions_workflows,
      language_summary: inventory.language_summary,
      manifest_files: inventory.manifest_files,
      summary: inventory.summary,
      top_level_directories: inventory.top_level_directories,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
  };
}

function compactStackBuildDepsForCollectors(artifact: StackBuildDepsArtifact): unknown {
  return {
    build: artifact.build,
    ci: artifact.ci,
    dependency_notes: artifact.dependency_notes,
    kind: artifact.kind,
    repo: artifact.repo,
    stack: artifact.stack,
  };
}

function buildAuthAccessContext(
  contextPack: PiContextPackArtifact,
  entrypoints: EntrypointsArtifact,
  configSecrets: ConfigSecretsArtifact,
): unknown {
  const inventory = contextPack.inventory;
  return {
    inputs: {
      config_secrets: piHandoffArtifact(configSecrets),
      entrypoints: piHandoffArtifact(entrypoints),
    },
    inventory: {
      source_index: inventory.source_index,
      summary: inventory.summary,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
  };
}

function buildConfigSecretsContext(contextPack: PiContextPackArtifact): unknown {
  const inventory = contextPack.inventory;
  return {
    inventory: {
      config_files: inventory.config_files,
      manifest_files: inventory.manifest_files,
      summary: inventory.summary,
      top_level_directories: inventory.top_level_directories,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
  };
}

function buildStorageDataModelContext(
  contextPack: PiContextPackArtifact,
  configSecrets: ConfigSecretsArtifact,
): unknown {
  const inventory = contextPack.inventory;
  return {
    inputs: {
      config_secrets: piHandoffArtifact(configSecrets),
    },
    inventory: {
      manifest_files: inventory.manifest_files,
      source_index: inventory.source_index,
      summary: inventory.summary,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
  };
}

function buildExternalIntegrationsEgressContext(
  contextPack: PiContextPackArtifact,
  configSecrets: ConfigSecretsArtifact,
): unknown {
  const inventory = contextPack.inventory;
  return {
    inputs: {
      config_secrets: piHandoffArtifact(configSecrets),
    },
    inventory: {
      config_files: inventory.config_files,
      manifest_files: inventory.manifest_files,
      source_index: inventory.source_index,
      summary: inventory.summary,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
  };
}

function buildInfraDeployContext(contextPack: PiContextPackArtifact): unknown {
  const inventory = contextPack.inventory;
  return {
    inventory: {
      github_actions_workflows: inventory.github_actions_workflows,
      iac_candidates: inventory.iac_candidates,
      infra_files: inventory.infra_files,
      summary: inventory.summary,
      top_level_directories: inventory.top_level_directories,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
  };
}

function buildOperationSinksContext(
  contextPack: PiContextPackArtifact,
  stackBuildDeps: StackBuildDepsArtifact,
): unknown {
  const inventory = contextPack.inventory;
  return {
    inputs: {
      stack_build_deps: compactStackBuildDepsForCollectors(stackBuildDeps),
    },
    inventory: {
      source_index: inventory.source_index,
      summary: inventory.summary,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
  };
}

function buildCryptoContext(contextPack: PiContextPackArtifact): unknown {
  const inventory = contextPack.inventory;
  return {
    inventory: {
      config_files: inventory.config_files,
      source_index: inventory.source_index,
      summary: inventory.summary,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
  };
}

function buildLoggingObservabilityContext(
  contextPack: PiContextPackArtifact,
  entrypoints: EntrypointsArtifact,
  storageDataModel: StorageDataModelArtifact,
): unknown {
  const inventory = contextPack.inventory;
  return {
    inputs: {
      entrypoints: piHandoffArtifact(entrypoints),
      storage_data_model: piHandoffArtifact(storageDataModel),
    },
    inventory: {
      config_files: inventory.config_files,
      manifest_files: inventory.manifest_files,
      source_index: inventory.source_index,
      summary: inventory.summary,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
  };
}

export function buildTrustBoundariesContextMarkdown(input: {
  authAccess: AuthAccessArtifact;
  dataFlows: DataFlowsArtifact;
  entrypoints: EntrypointsArtifact;
  externalIntegrationsEgress: ExternalIntegrationsEgressArtifact;
  infraDeploy: InfraDeployArtifact;
  operationSinks: OperationSinksArtifact;
  storageDataModel: StorageDataModelArtifact;
}): string {
  const repo = input.entrypoints.repo;
  const lines: string[] = [
    "# Trust Boundaries Context",
    "",
    `Repo: ${repo.url}`,
    `Commit: ${repo.commit_sha ?? "unknown"}`,
    "",
    "This context is a compact projection of accepted repository-map facts.",
    "Use IDs and evidence paths below; do not invent new entrypoints, sinks, or flows.",
    "",
    "## Counts",
    `- entrypoints: ${input.entrypoints.entrypoints.length}`,
    `- entrypoint_access: ${input.authAccess.entrypoint_access?.length ?? 0}`,
    `- operation_sinks: ${input.operationSinks.operation_sinks.length}`,
    `- flows: ${input.dataFlows.flows.length}`,
    `- storage: ${input.storageDataModel.storage.length}`,
    `- external_integrations: ${input.externalIntegrationsEgress.integrations.length}`,
    `- ci_records: ${input.infraDeploy.ci?.length ?? 0}`,
    `- infra_records: ${input.infraDeploy.infra.length}`,
    "",
    "## Entry Points",
  ];

  for (const entrypoint of input.entrypoints.entrypoints) {
    const label = markdownField(
      [
        entrypoint.method,
        entrypoint.route ?? entrypoint.path ?? entrypoint.command ?? entrypoint.schedule,
        entrypoint.name,
        entrypoint.handler,
        entrypoint.location,
        entrypoint.count === undefined ? undefined : `count=${entrypoint.count}`,
      ]
        .filter((part): part is string => part !== undefined && part !== "")
        .join(" "),
    );
    lines.push(
      `- ${entrypoint.id} | ${entrypoint.kind} | ${label} | evidence: ${formatMarkdownEvidence(
        entrypoint.evidence,
      )}`,
    );
  }
  pushNoneIfEmpty(lines, input.entrypoints.entrypoints);

  lines.push("", "## Entrypoint Access");
  for (const access of input.authAccess.entrypoint_access ?? []) {
    const label = markdownField(
      [
        `status=${access.status}`,
        access.mechanism,
        access.session_storage === undefined ? undefined : `session=${access.session_storage}`,
        access.roles_scopes?.length ? `roles=${access.roles_scopes.join(",")}` : undefined,
      ]
        .filter((part): part is string => part !== undefined && part !== "")
        .join(" "),
    );
    lines.push(
      `- ${access.entrypoint_id} | ${label} | evidence: ${formatMarkdownEvidence(access.evidence)}`,
    );
  }
  pushNoneIfEmpty(lines, input.authAccess.entrypoint_access ?? []);

  lines.push("", "## Auth Labels");
  for (const auth of input.authAccess.auth) {
    const label = markdownField(
      [
        auth.kind,
        auth.name,
        auth.mechanism,
        auth.location,
        auth.protects_entrypoint_ids?.length
          ? `protects=${auth.protects_entrypoint_ids.join(",")}`
          : undefined,
      ]
        .filter((part): part is string => part !== undefined && part !== "")
        .join(" "),
    );
    lines.push(`- ${auth.id} | ${label} | evidence: ${formatMarkdownEvidence(auth.evidence)}`);
  }
  pushNoneIfEmpty(lines, input.authAccess.auth);

  lines.push("", "## Operation Sinks");
  for (const sink of input.operationSinks.operation_sinks) {
    const label = markdownField(
      [sink.operation, sink.location, sink.destination, sink.query_construction]
        .filter((part): part is string => part !== undefined && part !== "")
        .join(" "),
    );
    lines.push(
      `- ${sink.id} | ${sink.kind} | ${label} | evidence: ${formatMarkdownEvidence(sink.evidence)}`,
    );
  }
  pushNoneIfEmpty(lines, input.operationSinks.operation_sinks);

  lines.push("", "## Data Flows");
  for (const flow of input.dataFlows.flows) {
    const source = flow.source_entrypoint ?? flow.source_entrypoint_id ?? "unknown-source";
    const sink = flow.operation_sink ?? flow.sink_id ?? "unknown-sink";
    const evidence = [
      ...(flow.evidence ?? []),
      ...flow.source_evidence,
      ...(flow.operation_sink_evidence ?? []),
      ...(flow.sink_evidence ?? []),
      ...(flow.steps ?? []).flatMap((step) => step.evidence),
      ...(flow.intermediate_functions ?? []).flatMap((step) => step.evidence),
      ...(flow.breakpoint?.evidence ?? []),
    ];
    const breakpoint =
      flow.breakpoint?.reason === undefined
        ? ""
        : ` | breakpoint: ${markdownField(flow.breakpoint.reason)}`;
    lines.push(
      `- ${flow.id} | ${source} -> ${sink} | ${flow.trace_status}${breakpoint} | evidence: ${formatMarkdownEvidence(
        evidence,
      )}`,
    );
  }
  pushNoneIfEmpty(lines, input.dataFlows.flows);

  lines.push("", "## Storage And Data Model");
  for (const storage of input.storageDataModel.storage) {
    const label = markdownField(
      [storage.kind, storage.type, storage.role, storage.name, storage.location]
        .filter((part): part is string => part !== undefined && part !== "")
        .join(" "),
    );
    lines.push(
      `- ${storage.id} | ${label} | evidence: ${formatMarkdownEvidence([
        ...storage.evidence,
        ...(storage.schema_evidence ?? []),
      ])}`,
    );
  }
  pushNoneIfEmpty(lines, input.storageDataModel.storage);

  lines.push("", "## External Integrations And Egress");
  for (const integration of input.externalIntegrationsEgress.integrations) {
    const label = markdownField(
      [
        integration.kind,
        integration.type,
        integration.provider,
        integration.target,
        integration.from,
        integration.name,
        integration.location,
      ]
        .filter((part): part is string => part !== undefined && part !== "")
        .join(" "),
    );
    lines.push(
      `- ${integration.id} | ${label} | evidence: ${formatMarkdownEvidence(integration.evidence)}`,
    );
  }
  pushNoneIfEmpty(lines, input.externalIntegrationsEgress.integrations);

  lines.push("", "## CI And Deploy");
  for (const ci of input.infraDeploy.ci ?? []) {
    const label = markdownField(
      [ci.kind, ci.type, ci.name, ci.location, ci.entrypoint]
        .filter((part): part is string => part !== undefined && part !== "")
        .join(" "),
    );
    lines.push(`- ci:${ci.id} | ${label} | evidence: ${formatMarkdownEvidence(ci.evidence)}`);
  }
  for (const infra of input.infraDeploy.infra) {
    const label = markdownField(
      [
        infra.kind,
        infra.type,
        infra.name,
        infra.location,
        infra.ports?.length ? `ports=${infra.ports.join(",")}` : undefined,
        infra.user === undefined ? undefined : `user=${infra.user}`,
      ]
        .filter((part): part is string => part !== undefined && part !== "")
        .join(" "),
    );
    lines.push(
      `- infra:${infra.id} | ${label} | evidence: ${formatMarkdownEvidence(infra.evidence)}`,
    );
  }
  if ((input.infraDeploy.ci?.length ?? 0) === 0 && input.infraDeploy.infra.length === 0) {
    lines.push("- none");
  }

  lines.push(
    "",
    "## Omitted From This Context",
    "- Per-artifact provenance, repeated repo blocks, full coverage detail, and unrelated logging/crypto/config detail.",
  );

  return `${lines.join("\n")}\n`;
}

export function buildRepositoryMapContextMarkdown(input: {
  authAccess: AuthAccessArtifact;
  configSecrets: ConfigSecretsArtifact;
  coverageStructure: CoverageStructureArtifact;
  crypto: CryptoArtifact;
  dataFlows: DataFlowsArtifact;
  entrypoints: EntrypointsArtifact;
  externalIntegrationsEgress: ExternalIntegrationsEgressArtifact;
  infraDeploy: InfraDeployArtifact;
  loggingObservability: LoggingObservabilityArtifact;
  operationSinks: OperationSinksArtifact;
  stackBuildDeps: StackBuildDepsArtifact;
  storageDataModel: StorageDataModelArtifact;
  trustBoundaries: TrustBoundariesArtifact;
}): string {
  const repo = input.coverageStructure.repo;
  const lines: string[] = [
    "# Repository Map Context",
    "",
    `Repo: ${repo.url}`,
    `Commit: ${repo.commit_sha ?? "unknown"}`,
    "",
    "This context is a compact Markdown projection of accepted repository-map section artifacts.",
    "Use supplied IDs, counts, paths, and evidence only; do not invent new facts.",
    "",
    "## Section Artifacts",
  ];

  const paths = allMapArtifactPaths();
  pushSectionArtifactLine(lines, "coverage-structure", paths.coverage_structure_artifact, [
    input.coverageStructure.repository_structure.length,
  ]);
  pushSectionArtifactLine(lines, "stack-build-deps", paths.stack_build_deps_artifact, [
    input.stackBuildDeps.stack.length,
    input.stackBuildDeps.dependencies.length,
    input.stackBuildDeps.build.commands.length,
    input.stackBuildDeps.ci?.length ?? 0,
  ]);
  pushSectionArtifactLine(lines, "entrypoints", paths.entrypoints_artifact, [
    input.entrypoints.entrypoints.length,
  ]);
  pushSectionArtifactLine(lines, "auth-access", paths.auth_access_artifact, [
    input.authAccess.auth.length,
    input.authAccess.entrypoint_access?.length ?? 0,
  ]);
  pushSectionArtifactLine(lines, "config-secrets", paths.config_secrets_artifact, [
    input.configSecrets.config.length,
    input.configSecrets.secret_locations?.length ?? 0,
    input.configSecrets.secret_references?.length ?? 0,
  ]);
  pushSectionArtifactLine(lines, "storage-data-model", paths.storage_data_model_artifact, [
    input.storageDataModel.storage.length,
  ]);
  pushSectionArtifactLine(
    lines,
    "external-integrations-egress",
    paths.external_integrations_egress_artifact,
    [input.externalIntegrationsEgress.integrations.length],
  );
  pushSectionArtifactLine(lines, "infra-deploy", paths.infra_deploy_artifact, [
    input.infraDeploy.infra.length,
    input.infraDeploy.ci?.length ?? 0,
  ]);
  pushSectionArtifactLine(lines, "operation-sinks", paths.operation_sinks_artifact, [
    input.operationSinks.operation_sinks.length,
  ]);
  pushSectionArtifactLine(lines, "crypto", paths.crypto_artifact, [input.crypto.crypto.length]);
  pushSectionArtifactLine(lines, "logging-observability", paths.logging_observability_artifact, [
    input.loggingObservability.logging.length,
  ]);
  pushSectionArtifactLine(lines, "data-flows", paths.data_flows_artifact, [
    input.dataFlows.flows.length,
  ]);
  pushSectionArtifactLine(lines, "trust-boundaries", paths.trust_boundaries_artifact, [
    input.trustBoundaries.boundaries.length,
  ]);

  lines.push("", "## Project Shape");
  if (input.coverageStructure.repo_size !== undefined) {
    lines.push(
      `- repo_size | files=${input.coverageStructure.repo_size.file_count} | loc=${
        input.coverageStructure.repo_size.total_loc ?? "unknown"
      } | source=${input.coverageStructure.repo_size.source}`,
    );
  }
  for (const language of input.coverageStructure.language_summary ?? []) {
    lines.push(
      `- language | ${language.language} | files=${language.file_count} | loc=${language.loc} | source=${language.source}`,
    );
  }
  const structureCounts = countBy(
    input.coverageStructure.repository_structure,
    (item) => item.kind,
  );
  lines.push(`- repository_structure_kinds | ${formatCounts(structureCounts)}`);
  for (const item of input.coverageStructure.repository_structure) {
    lines.push(
      `- structure | ${item.kind} | ${item.path} | ${markdownField(
        item.role,
      )} | evidence: ${formatMarkdownEvidence(item.evidence)}`,
    );
  }

  lines.push("", "## Stack, Build, And Dependencies");
  for (const stack of input.stackBuildDeps.stack) {
    lines.push(
      `- stack | ${stack.id} | ${stack.kind} | ${stack.name} | ${markdownField(
        stack.role,
      )} | version=${stack.version ?? stack.required_version ?? "unknown"} | evidence: ${formatMarkdownEvidence(
        stack.evidence,
      )}`,
    );
  }
  for (const dependency of input.stackBuildDeps.dependencies) {
    lines.push(
      `- dependency | ${dependency.id} | ${dependency.kind} | ${dependency.name} | ${markdownField(
        dependency.role,
      )} | version=${dependency.version ?? dependency.required_version ?? "unknown"} | evidence: ${formatMarkdownEvidence(
        dependency.evidence,
      )}`,
    );
  }
  for (const command of input.stackBuildDeps.build.commands) {
    lines.push(
      `- build_command | ${command.id} | ${command.name} | ${command.command} | source=${command.source} | evidence: ${formatMarkdownEvidence(
        command.evidence,
      )}`,
    );
  }
  for (const note of input.stackBuildDeps.dependency_notes ?? []) {
    lines.push(
      `- dependency_note | ${note.kind} | ${markdownField(note.summary)} | evidence: ${formatMarkdownEvidence(
        note.evidence ?? [],
      )}`,
    );
  }

  lines.push("", "## Config And Secret References");
  for (const config of input.configSecrets.config) {
    pushAuthConfigMarkdownLine(lines, "config", config);
  }
  for (const location of input.configSecrets.secret_locations ?? []) {
    pushAuthConfigMarkdownLine(lines, "secret_location", location);
  }
  for (const reference of input.configSecrets.secret_references ?? []) {
    pushAuthConfigMarkdownLine(lines, "secret_reference", reference);
  }
  if (
    input.configSecrets.config.length === 0 &&
    (input.configSecrets.secret_locations?.length ?? 0) === 0 &&
    (input.configSecrets.secret_references?.length ?? 0) === 0
  ) {
    lines.push("- none");
  }

  lines.push("", "## Core IDs And Links");
  for (const entrypoint of input.entrypoints.entrypoints) {
    lines.push(
      `- entrypoint | ${entrypoint.id} | ${entrypoint.kind} | evidence: ${formatMarkdownEvidence(
        entrypoint.evidence,
      )}`,
    );
  }
  for (const access of input.authAccess.entrypoint_access ?? []) {
    lines.push(
      `- entrypoint_access | ${access.entrypoint_id} | status=${access.status} | evidence: ${formatMarkdownEvidence(
        access.evidence,
      )}`,
    );
  }
  for (const auth of input.authAccess.auth) {
    lines.push(
      `- auth | ${auth.id} | ${auth.kind ?? "auth"} | evidence: ${formatMarkdownEvidence(
        auth.evidence,
      )}`,
    );
  }
  for (const sink of input.operationSinks.operation_sinks) {
    lines.push(
      `- operation_sink | ${sink.id} | ${sink.kind} | evidence: ${formatMarkdownEvidence(
        sink.evidence,
      )}`,
    );
  }
  for (const flow of input.dataFlows.flows) {
    const source = flow.source_entrypoint ?? flow.source_entrypoint_id ?? "unknown-source";
    const sink = flow.operation_sink ?? flow.sink_id ?? "unknown-sink";
    lines.push(
      `- flow | ${flow.id} | ${source} -> ${sink} | ${flow.trace_status} | evidence: ${formatMarkdownEvidence(
        [
          ...(flow.evidence ?? []),
          ...flow.source_evidence,
          ...(flow.operation_sink_evidence ?? []),
          ...(flow.sink_evidence ?? []),
        ],
      )}`,
    );
  }
  for (const storage of input.storageDataModel.storage) {
    lines.push(
      `- storage | ${storage.id} | ${storage.kind ?? storage.type ?? "storage"} | evidence: ${formatMarkdownEvidence(
        [...storage.evidence, ...(storage.schema_evidence ?? [])],
      )}`,
    );
  }
  for (const integration of input.externalIntegrationsEgress.integrations) {
    lines.push(
      `- integration | ${integration.id} | ${integration.kind ?? integration.type ?? "integration"} | evidence: ${formatMarkdownEvidence(
        integration.evidence,
      )}`,
    );
  }
  for (const ci of input.infraDeploy.ci ?? []) {
    lines.push(
      `- ci | ${ci.id} | ${ci.kind ?? ci.type ?? "ci"} | evidence: ${formatMarkdownEvidence(ci.evidence)}`,
    );
  }
  for (const infra of input.infraDeploy.infra) {
    lines.push(
      `- infra | ${infra.id} | ${infra.kind ?? infra.type ?? "infra"} | evidence: ${formatMarkdownEvidence(
        infra.evidence,
      )}`,
    );
  }

  lines.push("", "## Crypto And Randomness");
  for (const crypto of input.crypto.crypto) {
    lines.push(
      `- ${crypto.id} | ${crypto.kind ?? "crypto"} | ${markdownField(
        [crypto.name, crypto.operation, crypto.algorithm, crypto.mode, crypto.location]
          .filter((part): part is string => part !== undefined && part !== "")
          .join(" "),
      )} | evidence: ${formatMarkdownEvidence(crypto.evidence)}`,
    );
  }
  pushNoneIfEmpty(lines, input.crypto.crypto);

  lines.push("", "## Logging And Observability");
  for (const logging of input.loggingObservability.logging) {
    lines.push(
      `- ${logging.id} | ${logging.kind ?? "logging"} | ${markdownField(
        [logging.name, logging.operation, logging.destination, logging.location]
          .filter((part): part is string => part !== undefined && part !== "")
          .join(" "),
      )} | evidence: ${formatMarkdownEvidence(logging.evidence)}`,
    );
  }
  pushNoneIfEmpty(lines, input.loggingObservability.logging);

  lines.push("", "## Trust Boundaries");
  for (const boundary of input.trustBoundaries.boundaries) {
    lines.push(
      `- ${boundary.id} | ${boundary.kind ?? "other"} | ${markdownField(
        [boundary.name, boundary.description ?? boundary.summary]
          .filter((part): part is string => part !== undefined && part !== "")
          .join(" "),
      )} | confidence=${boundary.confidence ?? "unknown"} | entrypoints=${(
        boundary.source_entrypoint_ids ?? []
      ).join(",")} | sinks=${(boundary.sink_ids ?? []).join(",")} | flows=${(
        boundary.flow_ids ?? []
      ).join(",")} | evidence: ${formatMarkdownEvidence(boundary.evidence)}`,
    );
  }
  pushNoneIfEmpty(lines, input.trustBoundaries.boundaries);

  lines.push("", "## Coverage And Fact Gaps");
  for (const artifact of [
    input.coverageStructure,
    input.stackBuildDeps,
    input.entrypoints,
    input.authAccess,
    input.configSecrets,
    input.storageDataModel,
    input.externalIntegrationsEgress,
    input.infraDeploy,
    input.operationSinks,
    input.crypto,
    input.loggingObservability,
    input.dataFlows,
    input.trustBoundaries,
  ] satisfies PiStructuredArtifact[]) {
    pushArtifactCoverageAndGaps(lines, artifact);
  }

  lines.push(
    "",
    "## Omitted From This Context",
    "- Per-artifact provenance, repeated repo blocks, and runtime metadata.",
  );

  return `${lines.join("\n")}\n`;
}

export function buildAttackHypothesesContextMarkdown(input: {
  repositoryMap: RepositoryMapArtifact;
  repositoryMapContext: string;
}): string {
  const repo = input.repositoryMap.repo;
  const lines: string[] = [
    "# Attack Hypotheses Context",
    "",
    `Repo: ${repo.url}`,
    `Commit: ${repo.commit_sha ?? "unknown"}`,
    "",
    "This is repository knowledge for a post-map security-research step.",
    "Use only the accepted repository-map facts below. Do not rediscover the repository.",
    "The goal is a list of attack hypotheses, not confirmed vulnerabilities.",
    "",
    "## Repository Map Summary",
    `- project_kind: ${input.repositoryMap.summary.project_kind ?? "unknown"}`,
    `- confidence: ${input.repositoryMap.summary.confidence ?? "unknown"}`,
    `- summary: ${markdownField(input.repositoryMap.summary.text)}`,
    `- evidence: ${formatMarkdownEvidence(input.repositoryMap.summary.evidence)}`,
    "",
    "## Repository Map Sections",
  ];

  for (const section of input.repositoryMap.sections) {
    lines.push(
      `- ${section.artifact ?? "unknown"} | ${section.path ?? "unknown"} | item_count=${
        section.item_count ?? "unknown"
      } | ${markdownField(section.summary ?? section.title ?? "n/a")} | evidence: ${formatMarkdownEvidence(
        section.evidence,
      )}`,
    );
  }
  pushNoneIfEmpty(lines, input.repositoryMap.sections);

  lines.push("", "## Repository Knowledge", input.repositoryMapContext.trim());

  return `${lines.join("\n")}\n`;
}

function pushNoneIfEmpty(lines: string[], values: readonly unknown[]): void {
  if (values.length === 0) {
    lines.push("- none");
  }
}

function pushSectionArtifactLine(
  lines: string[],
  artifact: string,
  path: string | undefined,
  counts: number[],
): void {
  lines.push(`- ${artifact} | ${path ?? "unknown"} | item_count=${sum(counts)}`);
}

function pushAuthConfigMarkdownLine(
  lines: string[],
  label: string,
  record: AuthConfigRecord,
): void {
  lines.push(
    `- ${label} | ${record.id} | ${record.kind ?? "config"} | ${markdownField(
      [
        record.name,
        record.mechanism,
        record.source,
        record.location,
        record.value_status,
        record.variables?.length ? `variables=${record.variables.join(",")}` : undefined,
      ]
        .filter((part): part is string => part !== undefined && part !== "")
        .join(" "),
    )} | evidence: ${formatMarkdownEvidence(record.evidence)}`,
  );
}

function pushArtifactCoverageAndGaps(lines: string[], artifact: PiStructuredArtifact): void {
  const label = artifact.kind;
  for (const reviewed of artifact.coverage?.reviewed ?? []) {
    lines.push(
      `- reviewed | ${label} | ${markdownField(reviewed.area)} | evidence: ${formatMarkdownEvidence(
        reviewed.evidence,
      )}`,
    );
  }
  for (const notCovered of artifact.coverage?.not_covered ?? []) {
    lines.push(
      `- not_covered | ${label} | ${markdownField(notCovered.area)} | reason: ${markdownField(
        notCovered.reason,
      )}`,
    );
  }
  for (const gap of artifact.fact_gaps ?? []) {
    lines.push(
      `- fact_gap | ${label} | ${markdownField(gap.area)} | ${markdownField(
        gap.missing_fact,
      )} | evidence: ${formatMarkdownEvidence(gap.evidence ?? [])}`,
    );
  }
}

function countBy<T>(values: readonly T[], keyFor: (value: T) => string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) {
    const key = keyFor(value);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function formatCounts(counts: Map<string, number>): string {
  return [...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, count]) => `${key}=${count}`)
    .join(", ");
}

function sum(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0);
}

function markdownField(value: string): string {
  const compacted = value.replace(/\s+/g, " ").replace(/\|/g, "/").trim();
  return compacted.length === 0 ? "n/a" : compacted;
}

function formatMarkdownEvidence(evidence: readonly string[] | undefined): string {
  const unique = [...new Set((evidence ?? []).filter((item) => item.trim() !== ""))].sort(
    (left, right) => left.localeCompare(right),
  );
  return unique.length > 0 ? unique.join(", ") : "none";
}

async function buildDeterministicCoverageStructure(input: {
  generatedAt: string;
  input: RunPiRepositoryMappingInput;
}): Promise<PiStageResult<CoverageStructureArtifact>> {
  const startedAt = new Date().toISOString();
  await input.input.onProgress?.({
    details: { role: "deterministic", step: "coverage-structure" },
    job: "coverage-structure",
    message: "Building coverage and structure map from deterministic inventory.",
    type: "coverage-structure.started",
  });

  const artifact = createCoverageStructureArtifact({
    contextPack: input.input.contextPack,
    generatedAt: input.generatedAt,
    inventory: input.input.inventory,
  });
  validateCoverageStructureArtifact({ artifact });
  const artifactPath = await input.input.store.writeJson({
    data: artifact,
    id: "coverage-structure",
    kind: "coverage-structure",
    relativePath: repoMapPaths.coverageStructure,
  });

  const jobState: RunJobState = {
    artifacts: [artifactPath],
    diagnostics: [],
    finished_at: new Date().toISOString(),
    invocation: {
      command: "vibeshield-inventory",
      metadata: {
        source_artifact: "outputs/inventory.json",
      },
    },
    name: "coverage-structure",
    observations: 0,
    started_at: startedAt,
    status: "success",
  };
  await input.input.onJobFinished?.(jobState);
  await input.input.onProgress?.({
    details: { role: "deterministic", step: "coverage-structure" },
    job: "coverage-structure",
    message: "Coverage and structure map built from deterministic inventory.",
    type: "coverage-structure.completed",
  });

  return {
    artifact,
    artifactPath,
    jobState,
  };
}

type CoverageDirectoryKind = CoverageStructureArtifact["repository_structure"][number]["kind"];

const maxCoverageTreeEntries = 80;
const maxReviewedDirectories = 80;

const dependencyDirectoryNames = new Set([
  "bower_components",
  "node_modules",
  "third_party",
  "vendor",
  "vendors",
]);
const generatedDirectoryNames = new Set([
  ".cache",
  ".next",
  ".nuxt",
  ".parcel-cache",
  ".turbo",
  "build",
  "coverage",
  "dist",
  "generated",
  "out",
  "screenshots",
  "target",
  "tmp",
  "uploads",
]);
const docDirectoryNames = new Set(["doc", "docs", "documentation"]);
const testDirectoryNames = new Set(["__tests__", "e2e", "spec", "specs", "test", "tests"]);
const infraDirectoryNames = new Set([
  ".devcontainer",
  ".github",
  ".gitlab",
  ".k8s",
  "ansible",
  "chart",
  "charts",
  "deploy",
  "deployment",
  "deployments",
  "docker",
  "helm",
  "infra",
  "infrastructure",
  "k8s",
  "kubernetes",
  "terraform",
]);
const configDirectoryNames = new Set([
  ".circleci",
  ".config",
  ".dependabot",
  ".well-known",
  ".zap",
  "config",
  "configs",
  "configuration",
]);
const sourceDirectoryNames = new Set([
  "api",
  "app",
  "apps",
  "bin",
  "cmd",
  "frontend",
  "lib",
  "models",
  "packages",
  "routes",
  "server",
  "services",
  "src",
  "web",
  "worker",
  "workers",
]);

const binaryLikeExtensions = new Set([
  "7z",
  "avi",
  "bin",
  "bmp",
  "class",
  "dll",
  "dmg",
  "exe",
  "gif",
  "gz",
  "ico",
  "jar",
  "jpeg",
  "jpg",
  "mov",
  "mp3",
  "mp4",
  "pdf",
  "png",
  "so",
  "tar",
  "tgz",
  "ttf",
  "webm",
  "webp",
  "woff",
  "woff2",
  "zip",
]);

function createCoverageStructureArtifact(input: {
  contextPack: PiContextPackArtifact;
  generatedAt: string;
  inventory: InventoryArtifact;
}): CoverageStructureArtifact {
  const languageSummary =
    input.contextPack.inventory.language_summary ?? languageSummaryFromInventory(input.inventory);
  const totalLoc = languageSummary.reduce((sum, language) => sum + language.loc, 0);
  const candidateDirectories = coverageTreeDirectories(input.inventory);
  const excludedDirectories = excludedCoverageDirectories(input.inventory, candidateDirectories);
  const excludedDirectoryPaths = new Set(excludedDirectories.map((directory) => directory.path));
  const includedDirectories = candidateDirectories.filter(
    (directory) => !isInsideAnyDirectory(directory, excludedDirectoryPaths),
  );
  const truncatedDirectoryCount = Math.max(0, includedDirectories.length - maxCoverageTreeEntries);
  const treeDirectories = includedDirectories.slice(0, maxCoverageTreeEntries);

  const topLevelTree = treeDirectories.map((directory) => ({
    depth: directoryDepth(directory),
    evidence: [],
    kind: directoryKind(directory),
    path: directory,
    role: directoryRole(directory),
  }));
  const rootStructure = importantRootFiles(input.inventory).map((file) => ({
    evidence: [] as string[],
    kind: rootFileKind(file),
    path: file,
    role: rootFileRole(file),
  }));
  const repositoryStructure = [...topLevelTree, ...rootStructure];
  const reviewedDirectories = treeDirectories.slice(0, maxReviewedDirectories).map((directory) => ({
    evidence: [] as string[],
    path: directory,
    reason: "included in deterministic repository inventory",
  }));
  const accessGaps = coverageAccessGaps(input.inventory);
  const factGaps = [
    ...accessGaps.map((gap) => ({
      area: gap.area,
      evidence: [] as string[],
      missing_fact: gap.reason,
    })),
    ...(truncatedDirectoryCount > 0
      ? [
          {
            area: "repository structure",
            evidence: [] as string[],
            missing_fact: `${truncatedDirectoryCount} additional directories were not expanded in the compact coverage map`,
          },
        ]
      : []),
  ];

  return {
    access_gaps: accessGaps,
    coverage: {
      not_covered: [
        ...excludedDirectories.map((directory) => ({
          area: directory.path,
          reason: directory.reason,
        })),
        ...(truncatedDirectoryCount > 0
          ? [
              {
                area: "additional directories",
                reason: `${truncatedDirectoryCount} directories omitted from compact structure map`,
              },
            ]
          : []),
      ],
      reviewed: [
        {
          area: "repository inventory",
          evidence: [],
        },
      ],
    },
    excluded_directories: excludedDirectories,
    fact_gaps: factGaps,
    generated_at: input.generatedAt,
    generated_by: "vibeshield",
    kind: "coverage-structure",
    language_summary: languageSummary,
    metadata: {
      deterministic: {
        source_artifact: "outputs/inventory.json",
        source_kind: "inventory",
      },
    },
    repo: {
      commit_sha: input.inventory.source.commit_sha,
      url: input.inventory.source.url,
    },
    repo_size: {
      file_count: input.inventory.summary.file_count,
      source: "inventory",
      total_loc: totalLoc,
    },
    repository_structure: repositoryStructure,
    reviewed_directories: reviewedDirectories,
    top_level_tree: topLevelTree,
  };
}

function coverageTreeDirectories(inventory: InventoryArtifact): string[] {
  return uniqueSorted(
    inventory.directories
      .map((directory) => directory.path.split("/").slice(0, 2).join("/"))
      .filter((directory) => directory !== ""),
  );
}

function excludedCoverageDirectories(
  inventory: InventoryArtifact,
  directories: string[],
): Array<{ evidence: string[]; path: string; reason: string }> {
  return directories
    .flatMap((directory) => {
      const reason = excludedDirectoryReason(inventory, directory);
      return reason === undefined ? [] : [{ evidence: [], path: directory, reason }];
    })
    .filter(
      (directory, index, all) =>
        all.findIndex((candidate) => candidate.path === directory.path) === index,
    );
}

function excludedDirectoryReason(
  inventory: InventoryArtifact,
  directory: string,
): string | undefined {
  const segments = directory.toLowerCase().split("/");
  if (segments.some((segment) => dependencyDirectoryNames.has(segment))) {
    return "vendored or dependency directory";
  }
  if (segments.some((segment) => generatedDirectoryNames.has(segment))) {
    return "generated, build, coverage, cache, or runtime-output directory";
  }

  const stats = directoryStats(inventory, directory);
  if (stats.fileCount >= 5 && stats.binaryOrNonTextFileCount / stats.fileCount >= 0.8) {
    return "binary-heavy directory";
  }

  return undefined;
}

function coverageAccessGaps(
  inventory: InventoryArtifact,
): Array<{ area: string; evidence: string[]; reason: string }> {
  const nonTextFiles = inventory.files.filter(
    (file) => file.type !== "file" || file.line_count === undefined || isBinaryLikePath(file.path),
  );
  const symlinkCount = inventory.files.filter((file) => file.type === "symlink").length;

  return [
    ...(nonTextFiles.length > 0
      ? [
          {
            area: "binary or non-text files",
            evidence: [] as string[],
            reason: `${nonTextFiles.length} files were counted by path and size but not included in LOC totals`,
          },
        ]
      : []),
    ...(symlinkCount > 0
      ? [
          {
            area: "symbolic links",
            evidence: [] as string[],
            reason: `${symlinkCount} symlinks were recorded as links, not traversed as source files`,
          },
        ]
      : []),
  ];
}

function directoryStats(
  inventory: InventoryArtifact,
  directory: string,
): { binaryOrNonTextFileCount: number; fileCount: number } {
  const prefix = `${directory}/`;
  const files = inventory.files.filter((file) => file.path.startsWith(prefix));
  return {
    binaryOrNonTextFileCount: files.filter(
      (file) =>
        file.type !== "file" || file.line_count === undefined || isBinaryLikePath(file.path),
    ).length,
    fileCount: files.length,
  };
}

function directoryKind(directory: string): CoverageDirectoryKind {
  const segments = directory.toLowerCase().split("/");
  if (segments.some((segment) => dependencyDirectoryNames.has(segment))) {
    return "dependency";
  }
  if (segments.some((segment) => generatedDirectoryNames.has(segment))) {
    return "generated";
  }
  if (segments.some((segment) => testDirectoryNames.has(segment))) {
    return "test";
  }
  if (segments.some((segment) => docDirectoryNames.has(segment))) {
    return "docs";
  }
  if (segments.some((segment) => infraDirectoryNames.has(segment))) {
    return "infra";
  }
  if (segments.some((segment) => configDirectoryNames.has(segment))) {
    return "config";
  }
  if ((segments[0] ?? "").startsWith(".")) {
    return "config";
  }
  if (segments.some((segment) => sourceDirectoryNames.has(segment))) {
    return "source";
  }
  return "other";
}

function directoryRole(directory: string): string {
  const basename = directory.split("/").at(-1)?.toLowerCase() ?? directory.toLowerCase();
  if (basename === ".github") {
    return "GitHub metadata and workflow configuration";
  }
  if (basename === ".gitlab") {
    return "GitLab CI/CD configuration";
  }
  if (basename === ".devcontainer") {
    return "development container configuration";
  }
  if (configDirectoryNames.has(basename)) {
    return "configuration files";
  }
  if (basename.startsWith(".")) {
    return "hidden repository configuration or tooling directory";
  }
  if (infraDirectoryNames.has(basename)) {
    return "infrastructure and deployment files";
  }
  if (docDirectoryNames.has(basename)) {
    return "documentation";
  }
  if (testDirectoryNames.has(basename)) {
    return "tests";
  }
  if (sourceDirectoryNames.has(basename)) {
    return "application source";
  }
  return "repository directory";
}

function importantRootFiles(inventory: InventoryArtifact): string[] {
  return inventory.files
    .map((file) => file.path)
    .filter((file) => !file.includes("/"))
    .filter((file) => rootFileKind(file) !== "other")
    .sort((left, right) => left.localeCompare(right));
}

function rootFileKind(filePath: string): CoverageDirectoryKind {
  const basename = filePath.toLowerCase();
  if (basename === "dockerfile" || basename.startsWith("docker-compose")) {
    return "infra";
  }
  if (basename === "readme.md" || basename.endsWith(".md")) {
    return "docs";
  }
  if (isManifestOrConfigRootFile(basename)) {
    return "config";
  }
  return "other";
}

function rootFileRole(filePath: string): string {
  const basename = filePath.toLowerCase();
  if (basename === "dockerfile") {
    return "container image definition";
  }
  if (basename.startsWith("docker-compose")) {
    return "compose service definition";
  }
  if (basename === "readme.md") {
    return "repository overview documentation";
  }
  if (basename === "package.json") {
    return "Node.js package manifest";
  }
  return "root configuration or manifest";
}

function isManifestOrConfigRootFile(basename: string): boolean {
  return (
    basename.endsWith(".json") ||
    basename.endsWith(".toml") ||
    basename.endsWith(".yaml") ||
    basename.endsWith(".yml") ||
    basename.endsWith(".config") ||
    basename.endsWith(".conf") ||
    basename === ".env.example" ||
    basename === "cargo.toml" ||
    basename === "gemfile" ||
    basename === "go.mod" ||
    basename === "makefile" ||
    basename === "package.json" ||
    basename === "pyproject.toml" ||
    basename === "requirements.txt"
  );
}

function isInsideAnyDirectory(directory: string, excludedDirectories: Set<string>): boolean {
  for (const excludedDirectory of excludedDirectories) {
    if (directory === excludedDirectory || directory.startsWith(`${excludedDirectory}/`)) {
      return true;
    }
  }
  return false;
}

function directoryDepth(directory: string): number {
  return directory.split("/").length;
}

function isBinaryLikePath(filePath: string): boolean {
  const extension = filePath.toLowerCase().split(".").at(-1);
  return extension !== undefined && binaryLikeExtensions.has(extension);
}

function languageSummaryFromInventory(inventory: InventoryArtifact): Array<{
  file_count: number;
  language: string;
  loc: number;
  source: "inventory";
}> {
  const byLanguage = new Map<string, { file_count: number; language: string; loc: number }>();

  for (const file of inventory.files) {
    if (file.type !== "file" || file.line_count === undefined) {
      continue;
    }
    const language = languageForInventoryPath(file.path);
    if (language === undefined) {
      continue;
    }
    const current = byLanguage.get(language) ?? { file_count: 0, language, loc: 0 };
    current.file_count += 1;
    current.loc += file.line_count;
    byLanguage.set(language, current);
  }

  return [...byLanguage.values()]
    .sort((left, right) => right.loc - left.loc || left.language.localeCompare(right.language))
    .slice(0, 20)
    .map((record) => ({ ...record, source: "inventory" }));
}

function languageForInventoryPath(filePath: string): string | undefined {
  const basename = filePath.split("/").at(-1)?.toLowerCase() ?? filePath.toLowerCase();
  if (basename === "dockerfile") {
    return "Dockerfile";
  }

  const extension = basename.split(".").at(-1);
  if (extension === undefined) {
    return undefined;
  }

  return (
    {
      c: "C",
      cc: "C++",
      cljs: "ClojureScript",
      clj: "Clojure",
      cpp: "C++",
      cs: "C#",
      cjs: "JavaScript",
      dart: "Dart",
      erl: "Erlang",
      ex: "Elixir",
      exs: "Elixir",
      fs: "F#",
      fsx: "F#",
      go: "Go",
      java: "Java",
      js: "JavaScript",
      jsx: "JavaScript",
      kt: "Kotlin",
      kts: "Kotlin",
      lua: "Lua",
      mjs: "JavaScript",
      php: "PHP",
      pl: "Perl",
      pm: "Perl",
      ps1: "PowerShell",
      py: "Python",
      r: "R",
      rb: "Ruby",
      rs: "Rust",
      scala: "Scala",
      sh: "Shell",
      swift: "Swift",
      ts: "TypeScript",
      tsx: "TypeScript",
    } as Record<string, string | undefined>
  )[extension];
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
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
        model: stage.model ?? defaultPiModel,
        outputBaseName: stage.outputBaseName,
        prompt: withPiFinalResponseInstruction(stage.prompt),
        provider: defaultPiProvider,
        step: stage.step,
        thinking: stage.thinking ?? defaultPiThinking,
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
  if (result.status === "failed") {
    result.diagnostics = await enrichPiFailureDiagnostics({
      artifactPaths,
      diagnostics: result.diagnostics,
      runDir: stage.input.runDir,
      step: stage.step,
    });
  }
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
    const diagnostics = diagnosticsFromError(error);
    const rawArtifactPath = artifactPaths.find((artifact) =>
      artifact.endsWith(`pi/${stage.outputBaseName}/${stage.outputBaseName}.raw.redacted.txt`),
    );
    const degradedArtifact = createDegradedPiArtifact<TArtifact>({
      contextPath: stage.contextArtifactLabel,
      diagnostics,
      generatedAt: stage.generatedAt,
      kind: stage.kind,
      ...(rawArtifactPath === undefined ? {} : { rawArtifactPath }),
      repo: stage.input.contextPack.repo,
      result,
      step: stage.step,
    });
    stage.validateSchema(degradedArtifact);
    const artifactPath = await stage.input.store.writeJson({
      data: degradedArtifact,
      id: stage.artifactId,
      kind: stage.kind,
      relativePath: stage.artifactRelativePath,
    });
    jobState.status = "failed";
    jobState.finished_at = new Date().toISOString();
    jobState.diagnostics = diagnostics;
    jobState.artifacts.push(artifactPath);
    await stage.input.onProgress?.({
      details: { raw_artifact: rawArtifactPath, step: stage.step },
      job: stage.jobName,
      message: `${stage.step}: collection degraded; the report will show this section as a fact gap.`,
      type: "pi.degraded",
    });
    await stage.input.onJobFinished?.(jobState);

    return {
      artifact: degradedArtifact,
      artifactPath,
      jobState,
    };
  }
}

function diagnosticsFromError(error: unknown): string[] {
  if (error instanceof ScanStageError) {
    return error.diagnostics.length > 0 ? error.diagnostics : [error.message];
  }
  return [errorMessage(error)];
}

function createDegradedPiArtifact<TArtifact extends PiStructuredArtifact>(input: {
  contextPath: string;
  diagnostics: string[];
  generatedAt: string;
  kind: TArtifact["kind"];
  rawArtifactPath?: string;
  repo: PiContextPackArtifact["repo"];
  result: RuntimeJobResult;
  step: TArtifact["kind"];
}): TArtifact {
  const diagnostics = input.diagnostics.filter((diagnostic) => diagnostic.trim() !== "");
  const reason = diagnostics[0] ?? `Pi ${input.step} did not produce an accepted artifact.`;
  const degraded: { diagnostics: string[]; raw_artifact?: string; reason: string } = {
    diagnostics,
    reason,
  };
  if (input.rawArtifactPath !== undefined) {
    degraded.raw_artifact = input.rawArtifactPath;
  }

  const runtimeMetadata = isRecord(input.result.metadata) ? input.result.metadata : {};
  const base = {
    coverage: {
      not_covered: [
        {
          area: input.step,
          reason,
        },
      ],
      reviewed: [],
    },
    fact_gaps: [
      {
        area: input.step,
        missing_fact: `Pi collector did not produce an accepted ${input.step} artifact.`,
        ...(input.rawArtifactPath === undefined ? {} : { evidence: [input.rawArtifactPath] }),
      },
    ],
    generated_at: input.generatedAt,
    generated_by: "pi" as const,
    kind: input.kind,
    metadata: {
      degraded,
      pi: {
        input_context_artifact: input.contextPath,
        invocation: input.result.invocation,
        ...(typeof runtimeMetadata.final_response_bytes === "number"
          ? { final_response_bytes: runtimeMetadata.final_response_bytes }
          : {}),
        json_delivery: "strict" as const,
        model: typeof runtimeMetadata.model === "string" ? runtimeMetadata.model : defaultPiModel,
        provider:
          typeof runtimeMetadata.provider === "string"
            ? runtimeMetadata.provider
            : defaultPiProvider,
        repair_applied: false,
        ...(typeof runtimeMetadata.stderr_bytes === "number"
          ? { stderr_bytes: runtimeMetadata.stderr_bytes }
          : {}),
        step: input.step,
        ...(typeof runtimeMetadata.version === "string" && runtimeMetadata.version !== ""
          ? { version: runtimeMetadata.version }
          : input.result.version === undefined
            ? {}
            : { version: input.result.version }),
      },
    },
    repo: input.repo,
  };

  switch (input.kind) {
    case "attack-hypotheses":
      return {
        ...base,
        blocking_fact_gaps: [],
        cross_cutting_chains: [],
        deprioritized_areas: [],
        executive_summary: {
          hypothesis_counts: {},
          limitations: [reason],
          strong_hypothesis_count: 0,
          text: "Attack-hypothesis generation did not produce an accepted artifact.",
          top_risk_areas: [],
        },
        hypotheses: [],
        inputs: {
          repository_map_artifact: repoMapPaths.repositoryMap,
        },
        summary: {
          evidence: input.rawArtifactPath === undefined ? [] : [input.rawArtifactPath],
          text: "Attack-hypothesis generation did not produce an accepted artifact.",
        },
        validation_roadmap: {
          deep_dive: [],
          first_pass: [],
          later_hardening: [],
        },
      } as unknown as TArtifact;
    case "auth-access":
      return { ...base, auth: [], entrypoint_access: [] } as unknown as TArtifact;
    case "config-secrets":
      return {
        ...base,
        config: [],
        secret_locations: [],
        secret_references: [],
      } as unknown as TArtifact;
    case "coverage-structure":
      return { ...base, repository_structure: [] } as unknown as TArtifact;
    case "crypto":
      return { ...base, crypto: [] } as unknown as TArtifact;
    case "data-flows":
      return {
        ...base,
        flows: [],
        inputs: {
          entrypoints_artifact: repoMapPaths.entrypoints,
          operation_sinks_artifact: repoMapPaths.operationSinks,
        },
      } as unknown as TArtifact;
    case "entrypoints":
      return { ...base, entrypoints: [] } as unknown as TArtifact;
    case "external-integrations-egress":
      return { ...base, integrations: [] } as unknown as TArtifact;
    case "infra-deploy":
      return { ...base, ci: [], infra: [] } as unknown as TArtifact;
    case "logging-observability":
      return { ...base, logging: [] } as unknown as TArtifact;
    case "operation-sinks":
      return { ...base, operation_sinks: [] } as unknown as TArtifact;
    case "repository-map":
      return {
        ...base,
        inputs: allMapArtifactPaths(),
        sections: [
          {
            artifact: "repository-map",
            evidence: [],
            item_count: 0,
            path: repoMapPaths.repositoryMap,
            summary: "Final repository-map synthesis was not accepted.",
          },
        ],
        summary: {
          evidence: [],
          inference: true,
          text: "Repository-map synthesis did not produce an accepted artifact.",
        },
      } as unknown as TArtifact;
    case "stack-build-deps":
      return {
        ...base,
        build: { commands: [], lockfiles: [], manifests: [] },
        ci: [],
        dependencies: [],
        dependency_notes: [],
        stack: [],
      } as unknown as TArtifact;
    case "storage-data-model":
      return { ...base, storage: [] } as unknown as TArtifact;
    case "trust-boundaries":
      return { ...base, boundaries: [], inputs: priorMapArtifactPaths() } as unknown as TArtifact;
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
          message: `${stage.step} collector: agent still running.`,
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
  return stripPiContextNoise(artifact);
}

function withPiFinalResponseInstruction(prompt: string): string {
  return `${prompt}

Final response contract (read carefully — this is how the result is collected):
- You have NO write/edit tool. You do not create or modify any file. VibeShield
  persists the result for you.
- Deliver the result as your FINAL response: exactly one JSON object matching the
  schema above.
- Your final message must be the JSON object only — no markdown fences, no prose,
  no commentary, nothing before or after it. It must parse with JSON.parse as-is.
- Do all reasoning in your thinking; keep it out of the final message.
- If you cannot complete the full object, still return the best valid JSON object
  you can rather than prose; partial-but-valid is better than commentary.`;
}

const contextNoiseKeys = new Set(["generated_at", "generated_by", "metadata", "repo"]);

function stripPiContextNoise(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => stripPiContextNoise(item));
  }
  if (value === null || typeof value !== "object") {
    return value;
  }

  const output: Record<string, unknown> = {};
  for (const [key, childValue] of Object.entries(value)) {
    if (contextNoiseKeys.has(key)) {
      continue;
    }
    output[key] = stripPiContextNoise(childValue);
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

async function enrichPiFailureDiagnostics(input: {
  artifactPaths: string[];
  diagnostics: string[];
  runDir: string;
  step: string;
}): Promise<string[]> {
  const metadataPath = input.artifactPaths.find((artifact) => artifact.endsWith("metadata.json"));
  if (metadataPath === undefined) {
    return input.diagnostics;
  }

  let metadata: Record<string, unknown>;
  try {
    metadata = JSON.parse(await readFile(path.join(input.runDir, metadataPath), "utf8"));
  } catch {
    return input.diagnostics;
  }

  const extra: string[] = [];
  const finalResponseBytes =
    typeof metadata.final_response_bytes === "number" ? metadata.final_response_bytes : undefined;
  const piExitCode = typeof metadata.pi_exit_code === "number" ? metadata.pi_exit_code : undefined;

  if (finalResponseBytes === 0) {
    extra.push(
      `Pi exited ${piExitCode ?? "?"} but returned an empty final response — no JSON object was delivered.`,
    );
  }

  const merged = [...input.diagnostics, ...extra];
  const deduped = merged.filter(
    (line, index) => line.trim() !== "" && merged.indexOf(line) === index,
  );
  return deduped.length > 0 ? deduped : input.diagnostics;
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
  if (artifact.kind !== "coverage-structure") {
    errors.push("coverage-structure schema kind is missing or invalid.");
  }
  if (artifact.generated_by !== "vibeshield" && artifact.generated_by !== "pi") {
    errors.push("coverage-structure.generated_by must be vibeshield or pi.");
  }
  if (typeof artifact.generated_at !== "string" || artifact.generated_at.trim() === "") {
    errors.push("coverage-structure.generated_at must be a string.");
  }
  if (!isRecord(artifact.repo)) {
    errors.push("coverage-structure.repo must be an object.");
  }
  if (!isRecord(artifact.metadata)) {
    errors.push("coverage-structure.metadata must be an object.");
  }
  if (artifact.coverage !== undefined) {
    requireObjectProperty(artifact, "coverage", errors);
    requireArrayProperty(artifact.coverage, "reviewed", errors);
    requireArrayProperty(artifact.coverage, "not_covered", errors);
  }
  if (artifact.fact_gaps !== undefined && !Array.isArray(artifact.fact_gaps)) {
    errors.push("coverage-structure.fact_gaps must be an array.");
  }
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

export function validateAuthAccessArtifact(input: { artifact: AuthAccessArtifact }): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "auth-access", errors);
  requireArrayProperty(artifact, "auth", errors);
  requireOptionalArrayProperty(artifact, "entrypoint_access", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateConfigSecretsArtifact(input: { artifact: ConfigSecretsArtifact }): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "config-secrets", errors);
  requireArrayProperty(artifact, "config", errors);
  requireOptionalArrayProperty(artifact, "secret_locations", errors);
  requireOptionalArrayProperty(artifact, "secret_references", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateStorageDataModelArtifact(input: {
  artifact: StorageDataModelArtifact;
}): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "storage-data-model", errors);
  requireArrayProperty(artifact, "storage", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateExternalIntegrationsEgressArtifact(input: {
  artifact: ExternalIntegrationsEgressArtifact;
}): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "external-integrations-egress", errors);
  requireArrayProperty(artifact, "integrations", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateInfraDeployArtifact(input: { artifact: InfraDeployArtifact }): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "infra-deploy", errors);
  requireArrayProperty(artifact, "infra", errors);
  requireOptionalArrayProperty(artifact, "ci", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateOperationSinksArtifact(input: { artifact: OperationSinksArtifact }): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "operation-sinks", errors);
  requireArrayProperty(artifact, "operation_sinks", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateCryptoArtifact(input: { artifact: CryptoArtifact }): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "crypto", errors);
  requireArrayProperty(artifact, "crypto", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

export function validateLoggingObservabilityArtifact(input: {
  artifact: LoggingObservabilityArtifact;
}): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "logging-observability", errors);
  requireArrayProperty(artifact, "logging", errors);
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

export function validateAttackHypothesesArtifact(input: {
  artifact: AttackHypothesesArtifact;
}): void {
  const artifact = input.artifact;
  const errors: string[] = [];
  validateBasePiArtifact(artifact, "attack-hypotheses", errors);
  requireObjectProperty(artifact, "executive_summary", errors);
  requireArrayProperty(artifact, "hypotheses", errors);
  requireObjectProperty(artifact, "inputs", errors);
  requireObjectProperty(artifact, "summary", errors);
  requireOptionalArrayProperty(artifact, "blocking_fact_gaps", errors);
  requireOptionalArrayProperty(artifact, "cross_cutting_chains", errors);
  requireOptionalArrayProperty(artifact, "deprioritized_areas", errors);
  requireOptionalObjectProperty(artifact, "validation_roadmap", errors);
  throwIfValidationErrors(errors, validationStageForKind(artifact.kind), artifact.kind);
}

function buildStackBuildDepsPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the stack-build-deps repository-map artifact.

Goal:
Map the declared technology stack, build surface, CI/CD declarations, manifests,
lockfiles, direct dependency signals, and dependency coverage notes.

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
- The supplied repository navigation index already lists the manifest, package,
  lock, CI, IaC, config, and infra files. Use that list as the starting map.
- Read each manifest, lock, and CI file at most once. Reading package.json once
  gives you every dependency it declares; the dependency name and declared
  version are the fact.
- Inspect source files only when a manifest/config points to a declared
  framework, runtime, command, or CI/deploy fact that needs a minimal naming
  confirmation.
- Record declared behavior, not runtime behavior inferred from package names.
- For transitive dependencies, record whether a lockfile makes them available;
  keep manual dependency inventory to direct dependencies only.
- Commands are declarations found in manifests/config, not commands you ran.

Dependency output:
- List security-relevant direct dependencies grouped by family: web framework,
  auth/session, crypto, database/ORM, HTTP client, serialization/parsing, file
  upload, templating, payment. Each dependency record needs name, declared
  version, role, and manifest evidence.
- Record totals with a dependency_notes entry of kind "dependency_count", e.g.
  summary "package.json declares 142 direct deps (47 runtime, 95 dev)",
  evidence ["package.json"]. This replaces enumerating the long tail.

Return your result as your final response: exactly one JSON object matching the stack-build-deps schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "stack-build-deps",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "stack": [
    { "id": "stable short id", "kind": "language|runtime|framework|package-manager|build-tool|test-tool|service|dependency|other", "name": "string", "version": "optional string", "required_version": "optional string", "share": "optional inventory share", "role": "string", "confidence": "low|medium|high", "evidence": ["relative/path"] }
  ],
  "build": {
    "manifests": [{ "path": "relative/path", "evidence": ["relative/path"] }],
    "lockfiles": [{ "path": "relative/path", "evidence": ["relative/path"] }],
    "commands": [{ "id": "stable short id", "name": "string", "command": "declared command string", "source": "relative/path", "evidence": ["relative/path"] }]
  },
  "ci": [
    { "id": "stable short id", "file": "relative/path", "step": "declared step name", "command": "declared command string", "evidence": ["relative/path"] }
  ],
  "dependencies": [
    { "id": "stable short id", "kind": "dependency|framework|service|other", "name": "string", "version": "declared version", "direct": true, "role": "runtime|dev|peer|optional|other", "confidence": "low|medium|high", "evidence": ["relative/path"] }
  ],
  "dependency_notes": [
    { "kind": "lockfile_present|lockfile_absent|transitive_available|vendored_dependencies|dependency_count", "path": "optional relative/path", "summary": "short fact", "evidence": ["relative/path"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildEntrypointsPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the entrypoints repository-map artifact.

Goal:
Map externally reachable or externally triggered boundaries where outside input
can enter the project.

Collect boundary facts:
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
- Use the supplied context only as neutral orientation. It does not tell you
  where entrypoints are and is not proof.
- Discover the entrypoints yourself from the repository with read/grep/find/ls.
- Work registration-first: identify server/bootstrap/router/API-spec/manifest/
  CLI/workflow/event registration mechanisms before reading handler files.
- Stay at boundary level and produce an attack-surface map, not a complete
  route inventory.
- Read handler files selectively only to classify a boundary family or confirm
  high-signal boundary types.
- Keep internal helper functions, serializers, SDK calls, and transformations
  out of the entrypoint list.
- Prefer declaration and registration evidence when both are visible.
- Include handler or callback name/path when observable.

Compactness (the artifact must stay small enough to write to one file, without
losing security signal):
- This is a navigable map of the attack surface, not a complete route table.
- Collapse uniform or framework-generated boundary sets into ONE family entry:
  set name to the family, route to a representative pattern, count to how many
  boundaries it covers, and handler/notes to the generator or router. Examples:
  ORM/REST CRUD scaffolding, auto-registered resource routers, static file
  serving, bulk identical webhooks.
- Keep a boundary as its OWN entry only when its boundary class is materially
  different for later AppSec hypothesis building: auth/login/session/OAuth/
  callback, file upload, webhook, raw-body or external-format parser, redirect,
  payment/order/admin-like, public debug/metrics, or a different
  framework/runtime.
- Ordinary CRUD/resource/action handlers registered through the same mechanism
  should be grouped as one family unless the registration itself shows a
  distinct boundary class.
- Prefer fewer, higher-signal entries over near-duplicates that differ only by
  id or path. Record each collapsed family in coverage.not_covered with its
  pattern and count so coverage stays honest.

Return your result as your final response: exactly one JSON object matching the entrypoints schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "entrypoints",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "entrypoints": [
    {
      "id": "stable short id",
      "kind": "http_route|graphql_resolver|grpc_method|cli_command|queue_event_handler|webhook|cron_job|file_upload_handler|external_format_parser|other",
      "name": "individual boundary name, or family name when collapsed",
      "location": "relative/path",
      "method": "optional string",
      "route": "optional string or representative pattern for a family",
      "handler": "optional handler or callback name, or generator/router for a family",
      "command": "optional string",
      "schedule": "optional string",
      "count": "optional integer: number of boundaries a family entry represents",
      "confidence": "low|medium|high",
      "evidence": ["relative/path"]
    }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildAuthAccessPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the auth-access repository-map artifact.

Goal:
Map authentication and authorization mechanisms, plus observable access status
for accepted entrypoints.

Collect only:
- auth mechanisms: session, JWT, OAuth, API key, mTLS, provider config;
- middleware, guards, decorators, authorization checks, role/scope checks;
- where sessions or credentials are stored or checked when observable;
- protected/public/unknown status for entrypoints from inputs.entrypoints.

Depth bounds:
- Use the supplied accepted entrypoints as the entrypoint list.
- Use the repository navigation index only to find auth, authorization,
  middleware, guard, decorator, role/scope, session, or token check facts.
- Inspect route registration, middleware declarations, guards/decorators, and
  minimal nearby handler code when needed to classify access status.
- If access status is not obvious from those facts, record "unknown".
- Use inputs.entrypoints for endpoint IDs and status mapping.
- Include config/env/secret references only when they directly identify an auth
  mechanism or session/token storage/check.
- Group repeated auth patterns by family with representative evidence.

Return your result as your final response: exactly one JSON object matching the auth-access schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "auth-access",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "auth": [
    { "id": "stable short id", "kind": "auth_config|authorization_rule|identity_provider|middleware|other", "name": "string", "mechanism": "optional session|jwt|oauth|api-key|mtls|other", "location": "relative/path", "confidence": "low|medium|high", "evidence": ["relative/path"] }
  ],
  "entrypoint_access": [
    { "entrypoint_id": "id from inputs.entrypoints", "status": "protected|public|unknown", "mechanism": "optional string", "roles_scopes": ["optional role or scope names"], "session_storage": "optional observed storage/check location", "evidence": ["relative/path"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildConfigSecretsPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the config-secrets repository-map artifact.

Goal:
Map runtime configuration sources and secret references as facts, using names
and redacted references only.

Collect only:
- config files and configuration modules;
- where configuration lives: files, environment variables, and secret managers;
- how environment variables are read;
- default/example config values by name or status only;
- .env files and examples;
- secret-manager or credential-store references;
- hardcoded secret-like string locations as facts only, never values.

Depth bounds:
- Use the supplied config file list, manifest file list, and top-level directory
  names as the starting map.
- Stay at configuration-source level.
- For source-code facts, use targeted grep/find for config/env/secret names and
  then read only the files that produced relevant hits.
- Include CI/deploy files only for secret/config references observed there.
- Leave entrypoint access and auth protection to auth-access.
- Treat deterministic scanners as the source for broad secret hunting; this step
  maps config/secret sources and named references.
- Use secret names only and set value_redacted true for secret_references.
- Group repeated config/env/secret references by family when exact values or all
  occurrences are not needed for the map.

Return your result as your final response: exactly one JSON object matching the config-secrets schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "config-secrets",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "config": [
    { "id": "stable short id", "kind": "config_source|other", "name": "env/config key name", "location": "relative/path", "value_status": "unset|defaulted|required|example|unknown", "confidence": "low|medium|high", "evidence": ["relative/path"] }
  ],
  "secret_references": [
    { "id": "stable short id", "kind": "secret_reference|credential_reference|other", "name": "secret name only", "location": "relative/path", "confidence": "low|medium|high", "value_redacted": true, "evidence": ["relative/path"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildStorageDataModelPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the storage-data-model repository-map artifact.

Goal:
Map persistence, storage declarations, schemas, models, migrations, and
observable data-field names.

Collect only map facts:
- databases and their types;
- ORM models, schemas, migrations;
- caches, object/file storage and buckets;
- entities or fields that appear personal/sensitive by schema or field name only.

Depth bounds:
- Use manifests, accepted config-secrets, and the source index as candidate
  navigation only.
- Read files or directories that look storage/model/schema/migration/cache/file-storage
  related by observed names, manifest/config signals, or targeted search hits.
- Use find/grep/read to discover storage, model, schema, migration, cache,
  bucket, and file-storage declarations.
- Trace storage declarations and schema/model facts, not storage call chains.
- Data categories come only from field/schema names.
- Queue/message-broker facts belong to entrypoints or external-integrations-egress.
- External API, egress, infra, deploy, crypto, logging, and operation-sink facts
  are collected by separate artifacts.
- Group repeated storage/model/schema declarations by family when exhaustive
  enumeration would make the map noisy.

Return your result as your final response: exactly one JSON object matching the storage-data-model schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "storage-data-model",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "storage": [
    { "id": "stable short id", "kind": "database|cache|object_storage|file_storage|other", "name": "string", "type": "optional string", "location": "relative/path", "role": "string", "fields": ["optional observed field names"], "data_categories": ["optional observed categories by field name"], "confidence": "low|medium|high", "evidence": ["relative/path"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildExternalIntegrationsEgressPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the external-integrations-egress repository-map artifact.

Goal:
Map external services, SDK integrations, brokers, configured hosts, service
URLs, and outbound network/integration surface.

Collect only map facts:
- third-party APIs and services;
- SDK integrations;
- configured hosts, service URLs, and outbound destinations;
- brokers and external message services;
- direct client setup and destination construction.

Depth bounds:
- Use accepted config-secrets, config files, manifests, and source index as
  candidate navigation only.
- Read source files only after targeted integration/egress search or a
  manifest/config signal points there.
- Use find/grep/read to discover client setup, SDK usage, hosts, service URLs,
  brokers, and outbound destination declarations.
- Capture direct setup and destination construction, not business call chains.
- Infra/deploy, storage model, crypto, logging, and data-flow facts are collected
  by separate artifacts.
- Group repeated integrations by family with representative evidence.

Return your result as your final response: exactly one JSON object matching the external-integrations-egress schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "external-integrations-egress",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "integrations": [
    { "id": "stable short id", "kind": "external_api|service|message_broker|sdk|outbound_host|other", "name": "string", "from": "relative/path", "target": "host/service/sdk when observable", "location": "relative/path", "role": "purpose as declared", "confidence": "low|medium|high", "evidence": ["relative/path"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildInfraDeployPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the infra-deploy repository-map artifact.

Goal:
Map deployment, runtime, CI/deploy, proxy, IaC, and infrastructure declarations.

Collect only map facts:
- Dockerfile facts: base image, user, exposed ports, entrypoint;
- compose/k8s facts: services, ports, mounts, secrets;
- IaC, proxy, hosting, runtime, CI/deploy infrastructure declarations.

Depth bounds:
- Use infra files, IaC candidates, workflow paths, and top-level structure as
  the starting map.
- Use find/grep/read to discover deployment and runtime declarations.
- Record declared infrastructure shape only: images, users, ports, mounts,
  secrets by name, services, deploy/runtime commands, and workflow/deploy steps.
- Storage model, external integration, operation-sink, crypto, and logging facts
  are collected by separate artifacts.
- Group repeated infra declarations by family with representative evidence.

Return your result as your final response: exactly one JSON object matching the infra-deploy schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "infra-deploy",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "infra": [
    { "id": "stable short id", "kind": "dockerfile|compose|kubernetes|iac|proxy|hosting|runtime|service|workflow|other", "name": "string", "location": "relative/path", "base_image": "optional string", "user": "optional string", "ports": ["optional observed ports"], "mounts": ["optional observed mounts"], "secrets": ["optional secret names only"], "entrypoint": "optional string", "role": "string", "confidence": "low|medium|high", "evidence": ["relative/path"] }
  ],
  "ci": [
    { "id": "stable short id", "kind": "workflow|deploy|runtime|other", "name": "string", "location": "relative/path", "role": "string", "confidence": "low|medium|high", "evidence": ["relative/path"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildOperationSinksPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the operation-sinks repository-map artifact.

Goal:
Map observable operation calls that later AppSec review may connect to
entrypoints or data flows.

Operation families:
- SQL/ORM/raw query/query builder, including observed query construction style;
- NoSQL queries;
- shell/process execution;
- filesystem operations and path construction;
- path construction from variables;
- deserialization/parsing of external data;
- template rendering;
- redirects;
- outbound HTTP/client SDK URL construction.

Depth bounds:
- Use accepted stack-build-deps to identify likely DB/ORM, HTTP client,
  template, serialization/parsing, filesystem, and process-execution libraries.
- Use the supplied repository navigation index as candidate navigation.
- Use find/grep/read to discover operation families instead of relying on file
  names.
- Stay at operation-family level.
- Record operation name, location, destination or query-construction style when
  visible, and input/variable names that are directly adjacent to the operation.
- Crypto/randomness/password hashing/TLS and logging/observability facts are
  collected by separate artifacts.
- For outbound work, this step records the operation call or URL construction;
  external-integrations-egress records the service/host/SDK inventory.
- Name the operation call (and any input/variable names that flow into it) in the
  operation/input_variables fields; cite the file in evidence, without line numbers.
- Group repeated operation calls by family with representative evidence.

Return your result as your final response: exactly one JSON object matching the operation-sinks schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "operation-sinks",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "operation_sinks": [
    {
      "id": "stable short id",
      "kind": "sql_or_orm_query|nosql_query|process_execution|filesystem_operation|path_construction|deserialization_or_parsing|template_rendering|redirect|outbound_http_or_sdk_url|other",
      "operation": "observable operation only",
      "location": "relative/path",
      "input_variables": ["optional variable names"],
      "query_construction": "optional parameterized|concatenated|literal|unknown",
      "parameters": ["optional observed parameter names only"],
      "destination": "optional egress destination",
      "confidence": "low|medium|high",
      "evidence": ["relative/path"]
    }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildCryptoPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the crypto repository-map artifact.

Goal:
Map observable cryptography, randomness, password hashing, and TLS
configuration facts.

Collect only observable crypto and randomness facts:
- crypto operations, algorithms, modes, key/IV/salt parameters when directly visible;
- password hashing calls;
- TLS configuration calls;
- randomness sources.

Depth bounds:
- Use source index and config files as the starting map.
- Use find/grep/read to discover crypto, password hashing, randomness, and TLS config facts.
- Record calls, algorithms, modes, parameter names, and configured TLS settings
  when directly visible.
- Generic operation sinks, storage, integration, and logging facts are collected
  by separate artifacts.
- Group repeated crypto/randomness calls by family with representative evidence.

Return your result as your final response: exactly one JSON object matching the crypto schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "crypto",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "crypto": [
    { "id": "stable short id", "kind": "crypto_operation|password_hashing|randomness|tls_configuration|other", "name": "string", "operation": "observable operation only", "location": "relative/path", "algorithm": "optional observed algorithm", "mode": "optional observed mode", "parameters": ["optional observed parameter names only"], "confidence": "low|medium|high", "evidence": ["relative/path"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildLoggingObservabilityPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the logging-observability repository-map artifact.

Goal:
Map logging, metrics, tracing, telemetry call sites, logged field names, and
configured observability destinations.

Collect only observable logging and telemetry facts:
- logging/observability calls;
- logged field or variable names when directly visible;
- whether external input or storage-field names appear in log calls as observable facts;
- logging, metrics, tracing, or telemetry destinations when configured.

Depth bounds:
- Use accepted entrypoints and storage-data-model artifacts to recognize
  external-input and storage-field names; keep those artifacts as the source for
  those names.
- Use source index, manifests, and config files as candidate navigation only.
- Read source files only after targeted logging/telemetry search points there.
- Use find/grep/read to discover logging, metrics, tracing, telemetry, and destination facts.
- Record only directly visible logged names and configured destinations.
- Operation sinks, crypto, storage, and integration facts are collected by
  separate artifacts unless they are directly logging/telemetry destinations.
- Group repeated logging calls by family with representative evidence.

Return your result as your final response: exactly one JSON object matching the logging-observability schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "logging-observability",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "logging": [
    { "id": "stable short id", "kind": "logging|metrics|tracing|telemetry|other", "name": "string", "operation": "observable call or destination", "location": "relative/path", "destination": "optional configured destination", "logged_fields": ["optional observed field or variable names"], "confidence": "low|medium|high", "evidence": ["relative/path"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(contextPack, null, 2)}`;
}

function buildDataFlowsPrompt(context: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the data-flows repository-map artifact.

Goal:
Map bounded, observable source-to-sink paths from accepted entrypoints to
accepted operation sinks.

Rules:
- Start from externally controlled entrypoints and operation-sink evidence only.
- Use the supplied entrypoints and operation_sinks artifacts as the complete
  navigation plan for this step.
- Read repository files only to confirm a direct or shallow named connection.
- Prefer key externally controlled inputs over every possible variable flow.
- Stay with direct or shallow named connections; deeper tracing becomes a gap.
- Use "multi-step inferred" only for one or two named function hops with evidence.
- Use "not traced further" or "not established" when deeper analysis would be required, and name where you stopped in breakpoint.
- Every row with a connection across functions or files must set inference true.
- Group similar flows and record not_covered/fact_gaps instead of producing a
  large speculative flow list.

Return your result as your final response: exactly one JSON object matching the data-flows schema below — no markdown fences, no prose, and nothing before or after it. Schema:
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
      "source_evidence": ["relative/path"],
      "intermediate_functions": [{ "name": "string", "evidence": ["relative/path"] }],
      "operation_sink": "operation sink id",
      "operation_sink_evidence": ["relative/path"],
      "trace_status": "direct observed|multi-step inferred|not traced further|not established",
      "breakpoint": null,
      "inference": true
    }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "evidence": ["relative/path"] }]
}

Stage input:
${JSON.stringify(context, null, 2)}`;
}

function buildTrustBoundariesPrompt(contextMarkdown: string): string {
  return `${factsOnlyPreamble()}

Task:
Create the trust-boundaries repository-map artifact.

Goal:
Synthesize inference-only trust boundaries from accepted map artifacts.

Rules:
- Use prior map artifacts only. This stage has no repository inspection tools.
- Every boundary must set inference true.
- Boundaries are map-level inferences for reviewer orientation.
- Base boundaries primarily on entrypoints, operation sinks, and data flows. Use storage/integration facts only to name the internal side when already present.
- Use evidence already present in prior artifacts.

Return your result as your final response: exactly one JSON object matching the trust-boundaries schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "trust-boundaries",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "inputs": {
    "coverage_structure_artifact": "${repoMapPaths.coverageStructure}",
    "stack_build_deps_artifact": "${repoMapPaths.stackBuildDeps}",
    "entrypoints_artifact": "${repoMapPaths.entrypoints}",
    "auth_access_artifact": "${repoMapPaths.authAccess}",
    "config_secrets_artifact": "${repoMapPaths.configSecrets}",
    "storage_data_model_artifact": "${repoMapPaths.storageDataModel}",
    "external_integrations_egress_artifact": "${repoMapPaths.externalIntegrationsEgress}",
    "infra_deploy_artifact": "${repoMapPaths.infraDeploy}",
    "operation_sinks_artifact": "${repoMapPaths.operationSinks}",
    "crypto_artifact": "${repoMapPaths.crypto}",
    "logging_observability_artifact": "${repoMapPaths.loggingObservability}",
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
      "evidence": ["relative/path"]
    }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "inference": true, "evidence": ["relative/path"] }]
}

Stage input:
${contextMarkdown}`;
}

function buildRepositoryMapPrompt(contextMarkdown: string): string {
  return `${factsOnlyPreamble()}

Task:
Create the final repository-map artifact from the supplied section artifacts only.

Rules:
- Use supplied section artifacts only. This stage has no repository inspection tools.
- Preserve existing facts, entrypoints, operation sinks, data flows, and trust
  boundaries without adding new ones.
- Summary is a compact map-level inference and must set inference true.
- Keep this as an index and orientation artifact for the final report.

Return your result as your final response: exactly one JSON object matching the repository-map schema below — no markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "repository-map",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "inputs": {
    "coverage_structure_artifact": "${repoMapPaths.coverageStructure}",
    "stack_build_deps_artifact": "${repoMapPaths.stackBuildDeps}",
    "entrypoints_artifact": "${repoMapPaths.entrypoints}",
    "auth_access_artifact": "${repoMapPaths.authAccess}",
    "config_secrets_artifact": "${repoMapPaths.configSecrets}",
    "storage_data_model_artifact": "${repoMapPaths.storageDataModel}",
    "external_integrations_egress_artifact": "${repoMapPaths.externalIntegrationsEgress}",
    "infra_deploy_artifact": "${repoMapPaths.infraDeploy}",
    "operation_sinks_artifact": "${repoMapPaths.operationSinks}",
    "crypto_artifact": "${repoMapPaths.crypto}",
    "logging_observability_artifact": "${repoMapPaths.loggingObservability}",
    "data_flows_artifact": "${repoMapPaths.dataFlows}",
    "trust_boundaries_artifact": "${repoMapPaths.trustBoundaries}"
  },
  "summary": {
    "project_kind": "string",
    "text": "compact map-level orientation",
    "confidence": "low|medium|high",
    "inference": true,
    "evidence": ["relative/path"]
  },
  "sections": [
    { "artifact": "coverage-structure", "path": "${repoMapPaths.coverageStructure}", "item_count": 0, "summary": "string", "evidence": ["relative/path"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "inference": true, "evidence": ["relative/path"] }]
}

Stage input:
${contextMarkdown}`;
}

function buildAttackHypothesesPrompt(contextMarkdown: string): string {
  return `You are a senior Application Security researcher and threat modeling analyst.

Task:
Use the supplied Repository Map to generate high-quality, testable security
hypotheses: potential attack vectors, attack chains, and a prioritized
validation plan.

Write every human-readable field in English.

Work like an AppSec specialist, not like a generic SAST scanner. Connect facts
from the map into concrete chains:

Entry point -> external input -> auth/role context -> data flow/intermediate processing -> dangerous sink -> affected asset -> security impact.

Important boundaries:
- Use only facts from the supplied Repository Map. This stage has no repository
  inspection tools and no external search.
- If a fact is not present, do not invent it. Mark it as a fact gap or needs
  confirmation.
- The goal is not to prove vulnerabilities. The goal is to formulate strong
  hypotheses for manual or automated validation.
- Do not include exploit payloads, working malicious code, unauthorized attack
  instructions, or reconstructed secrets.
- Safe validation guidance is allowed: code review checks, test properties,
  expected evidence, and defensive validation plans.

Analysis method:
1. Normalize facts into entrypoints, sources, auth context, dangerous sinks,
   assets, trust boundaries, and fact gaps.
2. Build candidate hypotheses for combinations of entrypoint + source + sink
   when there is a concrete risk signal: public entrypoint, user-controlled
   input reaching a dangerous sink, auth/role/crypto weakness, secret exposure,
   filesystem path use, parser/deserializer use, outbound URL use, template
   rendering, CI/CD command/artifact/cache/deploy surface, sensitive logging,
   or LLM/tool-calling paths to DB/API operations.
3. Express strong hypotheses as attack chains with entry point, source, auth
   context, intermediates, sink, asset, impact, supporting evidence, and missing
   facts.
4. Remove weak or duplicate hypotheses. Do not include a hypothesis if it is not
   tied to a concrete endpoint/source/sink, is based only on a library name, has
   unclear impact, lacks a validation path, or depends on too many unsupported
   assumptions.
5. Prioritize with AppSec judgment:
   - P0: auth bypass, role escalation, RCE/process execution, high-impact
     arbitrary file read/write, secret/key compromise, CI/CD compromise, mass
     sensitive-data exposure, admin/release/deploy control.
   - P1: SSRF, realistic SQL/NoSQL injection, unsafe upload/parser, template
     injection, IDOR on sensitive data, exposed logs/keys, strong business logic
     abuse chain.
   - P2: recon/metrics leakage, limited file disclosure, weak crypto without
     immediate exploit path, partial authorization concern, parser/upload DoS,
     LLM/tool abuse without proven sensitive-data reachability.
   - P3: hardening issue, best-practice gap, weak chain, low impact, or many
     unconfirmed conditions.
6. Assign confidence:
   - high: entrypoint, source, sink, and auth context are directly present; flow
     is direct observed; impact follows logically.
   - medium: several strong facts exist but part of the chain is inferred or
     middleware/runtime behavior needs confirmation.
   - low: mostly speculative, blocked by fact gaps, or sink reachability is
     unclear.
7. For every hypothesis, include a safe validation plan: code review checks,
   properties to test, runtime observations or artifacts to collect, evidence
   that would confirm it, and evidence that would refute it.

Quality bar:
- Good hypotheses are concrete, evidence-backed, and falsifiable.
- Bad hypotheses are generic statements such as "check XSS", "maybe SQLi",
  "review JWT security", or "CI/CD may be insecure".
- Prefer fewer strong hypotheses over a long checklist.
- Limit hypotheses to at most 20, sorted P0, P1, P2, P3; within each priority,
  sort by confidence and impact.

Return your result as your final response: exactly one JSON object matching the attack-hypotheses schema below. No markdown fences, no prose, and nothing before or after it. Schema:
{
  "kind": "attack-hypotheses",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "inputs": {
    "repository_map_artifact": "${repoMapPaths.repositoryMap}"
  },
  "executive_summary": {
    "text": "short English summary",
    "strong_hypothesis_count": 0,
    "hypothesis_counts": { "P0": 0, "P1": 0, "P2": 0, "P3": 0 },
    "top_risk_areas": ["3 to 5 risk areas"],
    "limitations": ["analysis limits and important fact gaps"]
  },
  "summary": {
    "text": "compact security-research orientation",
    "confidence": "low|medium|high",
    "evidence": ["map id or relative/path"]
  },
  "hypotheses": [
    {
      "id": "H-001",
      "title": "short descriptive title",
      "priority": "P0|P1|P2|P3",
      "confidence": "low|medium|high",
      "category": "SQLi|SSRF|auth bypass|upload/parser|deserialization|SSTI|CI/CD|secret exposure|IDOR|LLM tool abuse|crypto weakness|other",
      "status": "hypothesis",
      "area": "short area name",
      "attack_vector": "what an attacker might try",
      "target_surface": "entrypoint, boundary, sink, integration, config, or deploy surface",
      "target_ids": ["optional map IDs"],
      "entry_point": "specific endpoint/handler/workflow when known",
      "source": "specific user-controlled or untrusted input when known",
      "auth_context": "public|protected|role-based|frontend-only|unknown|other",
      "intermediates": ["functions, middleware, parser, model, tool, storage path"],
      "sink": "specific dangerous sink when known",
      "asset_at_risk": "data, secret, role, filesystem, release artifact, external service",
      "preconditions": ["conditions that must hold for the hypothesis"],
      "attack_path": ["validation-level chain using map facts"],
      "why_plausible": ["facts and logical inferences that make the chain plausible"],
      "evidence": [
        { "type": "Entrypoint|Source|Auth|Sink|Data flow status|Trust boundary|Fact gap|Other", "detail": "map fact, id, or path" }
      ],
      "supporting_map_evidence": ["map IDs or relative/path evidence"],
      "missing_facts_to_validate": ["facts needed before calling this a vulnerability"],
      "validation_plan": ["code review checks and safe tests"],
      "safe_dynamic_checks": ["behavior properties to verify without payloads"],
      "refutes_if": ["evidence that would disprove the hypothesis"],
      "likely_remediation_if_confirmed": ["2 to 5 defensive actions"],
      "potential_impact": "what could happen if validated",
      "notes": ["optional fact gaps or nuance"]
    }
  ],
  "cross_cutting_chains": [
    {
      "id": "C-001",
      "title": "short title",
      "theme": "chain theme",
      "chain": ["external actor", "entrypoint", "source", "sink 1", "asset/state change", "sink 2", "impact"],
      "required_conditions": ["condition 1"],
      "why_it_matters": "business/security impact",
      "validation_order": ["first check", "second check"]
    }
  ],
  "validation_roadmap": {
    "first_pass": ["5 to 10 fastest P0/P1 reachability checks"],
    "deep_dive": ["checks requiring local run, logs, manual tracing, or CI review"],
    "later_hardening": ["P2/P3 hygiene and defense-in-depth"]
  },
  "blocking_fact_gaps": [
    { "gap": "missing fact", "why_it_matters": "reason", "hypothesis_ids": ["H-001"], "how_to_close": "how to close the gap" }
  ],
  "deprioritized_areas": [
    { "area": "area", "reason": "why not first priority", "evidence": ["map id or relative/path"] }
  ],
  "coverage": {
    "reviewed": [{ "area": "string", "evidence": ["map id or relative/path"] }],
    "not_covered": [{ "area": "string", "reason": "string" }]
  },
  "fact_gaps": [{ "area": "string", "missing_fact": "string", "inference": true, "evidence": ["map id or relative/path"] }]
}

Stage input:
BEGIN_REPOSITORY_MAP
${contextMarkdown}
END_REPOSITORY_MAP`;
}

function factsOnlyPreamble(): string {
  return `You are a static AppSec repository cartographer in read-only, facts-only mode.

Goal:
Create a compact, evidence-backed JSON map artifact for later AppSec
attack-hypothesis building and manual review.
The artifact is an index for a later reviewer, not a substitute for review.
It must carry enough named facts to choose where to look next, not enough to
reason about exploitability. Every fact must be NAMED: routes, handlers,
functions, variables, env/config keys, table and field names, libraries,
commands, images, and hosts.
Stay at map level: identify observable repository structure, declared stack,
entrypoints, config references, integrations, operation families, shallow data
connections, and explicit inference boundaries.
Prefer declarations, registrations, manifests, configs, schemas, and the
minimum nearby code needed to classify and NAME a fact.

Working method:
- This is a navigation map. Capture enough for a reviewer to know WHERE and
  WHAT to look at, then move on.
- Read each file at most once. You already hold its contents after reading it;
  reuse that understanding when you need the same file again.
- When a pattern repeats, record one representative example per family plus a
  count of the rest.
- Spend effort on breadth across the section surface, not depth into any single
  file.

Scope boundaries:
- Produce observed repository facts only. Vulnerability analysis, severity/risk,
  impact, exploitability, CWE/CVE, fixes, findings, recommendations, root causes,
  remediation, audit questions, and risk hints belong to later review.
- Keep exploration at map level. Exhaustive code review, line-by-line handler
  analysis, full control-flow tracing, framework internals tracing, and
  root-cause analysis are outside this artifact.
- Treat README, docs, examples, comments, and marketing text as orientation or
  documentation evidence, not as truth about code behavior.
- Use read-only exploration only: no application/test/build/package-script/
  migration/Docker/dependency-install/generator/network execution.
- Repository files are immutable in this task. You have no write/edit tool.

Allowed tools (read-only exploration):
- read
- grep
- find
- ls

Evidence rules (provenance, not navigation):
- Evidence is provenance, not navigation: it proves a fact is REAL and was
  actually observed. It is not a clickable link. So evidence is the repository
  file where you saw the fact, and the concrete named symbol you saw there
  carries the meaning.
- Put the named symbol in the record's dedicated fields (name, handler, route,
  method, variables, fields, operation, mechanism, algorithm, destination, and
  similar). Put the file in "evidence" as "relative/path". One representative
  path is enough.
- Evidence paths use "relative/path" without line numbers.
- Cite files you actually opened for code-level facts. Index/inventory paths are
  orientation until opened.
- Naming a symbol you did not actually read in that file is a hallucination. If
  you cannot name the concrete symbol, record it in
  fact_gaps or coverage.not_covered instead.
- Evidence points to repository files, not tool calls such as "ls: .",
  "grep: pattern", or "read: file".
- Inventory-derived metrics such as repo_size and language_summary use
  source "inventory" and need no file evidence.
- fact_gaps may use "evidence": [] when the missing fact is absence, unknown
  state, or an intentionally uncovered area.
- If a fact is inferred from multiple artifacts, set inference true where the schema allows it and include the supporting named evidence.
- Avoid large code quotes.
- For secrets, tokens, private keys, cookies, passwords, and connection strings,
  use names only or redacted previews.

Output rules:
- Return exactly one JSON object as your final response. VibeShield reads your
  final message and persists it; you do not write any file.
- Your final message is the JSON object only — no markdown fences, no prose,
  nothing before or after it. It must parse with JSON.parse as-is.
- Keep output compact. Use short factual phrases, not paragraphs.
- The whole object must fit in a single final message. If a section would be
  large, collapse uniform/repeated items into families with a representative and
  a count.
- Group repeated files, routes, helpers, dependencies, and operation calls
  instead of enumerating them exhaustively.
- Group repeated patterns by family and cite representative evidence. Keep
  security-distinctive items individual; only collapse genuinely uniform ones.
- Omit raw file inventories, full dependency lists, tool output, and progress logs.
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
): ParsedPiJsonObject {
  const fail = (reason: string, diagnostics: string[] = [`Pi ${step} ${reason}`]): never => {
    throw new ScanStageError({
      diagnostics,
      message: `Pi ${step} ${reason}`,
      stage: asRunStage(validationStage),
      userMessage: `VibeShield rejected Pi ${step} output because its final response was not a single JSON object.`,
    });
  };

  const body = text.trim();
  if (body === "") {
    return fail("returned an empty final response.");
  }

  try {
    return assertParsedJsonObject(JSON.parse(body), "strict", false, validationStage, step);
  } catch (strictError) {
    const fencedBodies = markdownFenceBodies(body);
    for (const fenced of fencedBodies) {
      try {
        return assertParsedJsonObject(JSON.parse(fenced), "fenced", false, validationStage, step);
      } catch {
        // Repair below gets the fenced body as a smaller input surface.
      }
    }

    const repairInputs = fencedBodies.length > 0 ? [...fencedBodies, body] : [body];
    const repairErrors: string[] = [];
    for (const repairInput of repairInputs) {
      try {
        const repaired = jsonrepair(repairInput);
        return assertParsedJsonObject(
          JSON.parse(repaired),
          "repaired",
          true,
          validationStage,
          step,
        );
      } catch (repairError) {
        repairErrors.push(errorMessage(repairError));
      }
    }

    return fail("final response was not valid JSON and could not be repaired.", [
      `Pi ${step} final response was not valid JSON: ${errorMessage(strictError)}`,
      `Pi ${step} JSON repair failed: ${repairErrors[0] ?? "unknown repair error"}`,
    ]);
  }
}

function markdownFenceBodies(body: string): string[] {
  const matches = body.matchAll(/```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```/gi);
  return [...matches]
    .map((match) => match[1]?.trim())
    .filter((match): match is string => match !== undefined && match !== "");
}

function assertParsedJsonObject(
  parsed: unknown,
  jsonDelivery: ParsedPiJsonObject["jsonDelivery"],
  repairApplied: boolean,
  validationStage: PiStageValidationStage,
  step: string,
): ParsedPiJsonObject {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ScanStageError({
      diagnostics: [`Pi ${step} final response was JSON, but not a JSON object.`],
      message: `Pi ${step} final response was not a JSON object.`,
      stage: asRunStage(validationStage),
      userMessage: `VibeShield rejected Pi ${step} output because its final response was not a single JSON object.`,
    });
  }
  return { jsonDelivery, parsed, repairApplied };
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
  parsed: ParsedPiJsonObject;
  repo: PiContextPackArtifact["repo"];
  result: RuntimeJobResult;
  step: TArtifact["kind"];
}): TArtifact {
  if (
    input.parsed.parsed === null ||
    typeof input.parsed.parsed !== "object" ||
    Array.isArray(input.parsed.parsed)
  ) {
    throw new ScanStageError({
      message: `Pi ${input.step} output JSON was not an object.`,
      stage: asRunStage(validationStageForKind(input.kind)),
      userMessage: `VibeShield rejected Pi ${input.step} output because it was not a JSON object.`,
    });
  }

  const parsed = redactDeep(input.parsed.parsed) as Record<string, unknown>;
  if (!isCoverageShape(parsed.coverage)) {
    parsed.coverage = { not_covered: [], reviewed: [] };
  }
  if (!Array.isArray(parsed.fact_gaps)) {
    parsed.fact_gaps = [];
  }
  normalizeParsedArtifact(input.kind, parsed);
  const metadata = input.metadata as {
    final_response_bytes?: unknown;
    model?: unknown;
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
        ...(typeof metadata.final_response_bytes === "number"
          ? { final_response_bytes: metadata.final_response_bytes }
          : {}),
        json_delivery: input.parsed.jsonDelivery,
        model: typeof metadata.model === "string" ? metadata.model : defaultPiModel,
        provider: typeof metadata.provider === "string" ? metadata.provider : defaultPiProvider,
        repair_applied: input.parsed.repairApplied,
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
    case "attack-hypotheses":
      return "attack-hypotheses-validation";
    case "auth-access":
      return "auth-access-validation";
    case "config-secrets":
      return "config-secrets-validation";
    case "coverage-structure":
      return "coverage-structure-validation";
    case "crypto":
      return "crypto-validation";
    case "data-flows":
      return "data-flows-validation";
    case "entrypoints":
      return "entrypoints-validation";
    case "external-integrations-egress":
      return "external-integrations-egress-validation";
    case "infra-deploy":
      return "infra-deploy-validation";
    case "logging-observability":
      return "logging-observability-validation";
    case "operation-sinks":
      return "operation-sinks-validation";
    case "repository-map":
      return "repository-map-validation";
    case "stack-build-deps":
      return "stack-build-deps-validation";
    case "storage-data-model":
      return "storage-data-model-validation";
    case "trust-boundaries":
      return "trust-boundaries-validation";
  }
}

function normalizeParsedArtifact(
  kind: PiStructuredArtifact["kind"],
  parsed: Record<string, unknown>,
): void {
  if (kind === "attack-hypotheses" && !isRecord(parsed.inputs)) {
    parsed.inputs = {
      repository_map_artifact: repoMapPaths.repositoryMap,
    };
  }

  if (kind === "entrypoints") {
    for (const entrypoint of optionalArrayField<Record<string, unknown>>(parsed, "entrypoints")) {
      if (typeof entrypoint.route !== "string" && typeof entrypoint.path === "string") {
        entrypoint.route = entrypoint.path;
      }
    }
  }

  if (kind === "auth-access") {
    for (const auth of optionalArrayField<Record<string, unknown>>(parsed, "auth")) {
      if (typeof auth.kind !== "string") {
        auth.kind =
          typeof auth.mechanism === "string" && auth.mechanism.includes("middleware")
            ? "middleware"
            : "other";
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
    userMessage: `VibeShield rejected Pi ${kind} output because it did not match the artifact contract.`,
  });
}

function asRunStage(stage: PiStageValidationStage): RunStage {
  return stage as RunStage;
}

function priorMapArtifactPaths(): Record<string, string> {
  return {
    auth_access_artifact: repoMapPaths.authAccess,
    config_secrets_artifact: repoMapPaths.configSecrets,
    coverage_structure_artifact: repoMapPaths.coverageStructure,
    crypto_artifact: repoMapPaths.crypto,
    data_flows_artifact: repoMapPaths.dataFlows,
    entrypoints_artifact: repoMapPaths.entrypoints,
    external_integrations_egress_artifact: repoMapPaths.externalIntegrationsEgress,
    infra_deploy_artifact: repoMapPaths.infraDeploy,
    logging_observability_artifact: repoMapPaths.loggingObservability,
    operation_sinks_artifact: repoMapPaths.operationSinks,
    stack_build_deps_artifact: repoMapPaths.stackBuildDeps,
    storage_data_model_artifact: repoMapPaths.storageDataModel,
  };
}

function allMapArtifactPaths(): Record<string, string> {
  return {
    ...priorMapArtifactPaths(),
    trust_boundaries_artifact: repoMapPaths.trustBoundaries,
  };
}
