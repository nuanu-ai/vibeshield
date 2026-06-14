import { readFile } from "node:fs/promises";
import path from "node:path";
import type {
  AuthAccessArtifact,
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

const defaultPiModel = "moonshotai/kimi-k2.7-code";
const defaultPiProvider = "openrouter";
const collectorTools = ["read", "grep", "find", "ls", "write"];

const repoMapPaths = {
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

  const entrypointsContext = buildEntrypointsContext(input.contextPack);
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

  const operationSinksContext = buildOperationSinksContext(input.contextPack);
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

  const loggingObservabilityContext = buildLoggingObservabilityContext(input.contextPack);
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
      validateSchema: (artifact) => validateDataFlowsArtifact({ artifact }),
      validationStage: "data-flows-validation",
    }));

  const priorMapArtifacts = {
    artifacts: {
      auth_access: piHandoffArtifact(authAccess.artifact),
      config_secrets: piHandoffArtifact(configSecrets.artifact),
      crypto: piHandoffArtifact(crypto.artifact),
      data_flows: piHandoffArtifact(dataFlows.artifact),
      entrypoints: piHandoffArtifact(entrypoints.artifact),
      external_integrations_egress: piHandoffArtifact(externalIntegrationsEgress.artifact),
      infra_deploy: piHandoffArtifact(infraDeploy.artifact),
      logging_observability: piHandoffArtifact(loggingObservability.artifact),
      operation_sinks: piHandoffArtifact(operationSinks.artifact),
      storage_data_model: piHandoffArtifact(storageDataModel.artifact),
    },
    paths: priorMapArtifactPaths(),
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
      auth_access: piHandoffArtifact(authAccess.artifact),
      config_secrets: piHandoffArtifact(configSecrets.artifact),
      coverage_structure: piHandoffArtifact(coverageStructure.artifact),
      crypto: piHandoffArtifact(crypto.artifact),
      data_flows: piHandoffArtifact(dataFlows.artifact),
      entrypoints: piHandoffArtifact(entrypoints.artifact),
      external_integrations_egress: piHandoffArtifact(externalIntegrationsEgress.artifact),
      infra_deploy: piHandoffArtifact(infraDeploy.artifact),
      logging_observability: piHandoffArtifact(loggingObservability.artifact),
      operation_sinks: piHandoffArtifact(operationSinks.artifact),
      stack_build_deps: piHandoffArtifact(stackBuildDeps.artifact),
      storage_data_model: piHandoffArtifact(storageDataModel.artifact),
      trust_boundaries: piHandoffArtifact(trustBoundaries.artifact),
    },
    paths: allMapArtifactPaths(),
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
      outputBaseName: "repository-map",
      prompt: buildRepositoryMapPrompt(repositoryMapContext),
      step: "repository-map",
      validateSchema: (artifact) => validateRepositoryMapArtifact({ artifact }),
      validationStage: "repository-map-validation",
    }));

  return {
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

function buildEntrypointsContext(contextPack: PiContextPackArtifact): unknown {
  const inventory = contextPack.inventory;
  return {
    inventory: {
      language_summary: inventory.language_summary,
      manifest_files: inventory.manifest_files,
      source_index: inventory.source_index,
      summary: inventory.summary,
      top_level_directories: inventory.top_level_directories,
    },
    purpose: repositoryMapProductIntent,
    repo: contextPack.repo,
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
      source_index: inventory.source_index,
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
      config_files: inventory.config_files,
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

function buildOperationSinksContext(contextPack: PiContextPackArtifact): unknown {
  const inventory = contextPack.inventory;
  return {
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

function buildLoggingObservabilityContext(contextPack: PiContextPackArtifact): unknown {
  const inventory = contextPack.inventory;
  return {
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

function buildStackBuildDepsPrompt(contextPack: unknown): string {
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
- Use the supplied repository navigation index as the starting map. Prioritize
  manifest, package, lock, CI, IaC, config, and infra paths from that input.
- Do not install dependencies.
- Do not run package scripts, builds, tests, migrations, or generators.
- Do not inspect source files unless a manifest/config points to a declared
  framework, runtime, command, dependency, or CI/deploy fact that needs minimal
  confirmation.
- Do not infer runtime behavior from dependency names alone.
- Do not expand transitive dependencies manually. If a lockfile exists, record that transitive dependencies are available through it.
- Commands are declarations found in manifests/config, not commands you ran.
- Keep direct dependency output compact. Group repetitive dependency families in
  dependency_notes instead of dumping large dependency lists.

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

function buildEntrypointsPrompt(contextPack: unknown): string {
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
- Use the supplied repository navigation index as the starting map, not as proof
  and not as an exhaustive truth source.
- Use find/grep/read to discover boundary declarations and registrations from
  the repository when the index is not enough.
- Stay at boundary level.
- Do not perform line-by-line handler analysis.
- Do not analyze handler bodies beyond what is needed to classify the boundary.
- Do not list internal helper functions, serializers, SDK calls, or transformations as entrypoints.
- Prefer declaration and registration evidence when both are visible.
- Include handler or callback name/path when observable.
- If patterns repeat heavily, group by boundary family with representative
  evidence and explain the unexpanded area in coverage.not_covered.

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

function buildAuthAccessPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the auth-access section artifact. This artifact answers assignment section 4:
- authentication and authorization;
- observable access status for accepted entrypoints.

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
- Do not verify auth correctness.
- Do not infer missing authorization.
- Do not rediscover entrypoints. Use inputs.entrypoints for endpoint IDs and status mapping.
- Do not map general config, env, or secret references unless they directly
  identify an auth mechanism or session/token storage/check.
- Group repeated auth patterns by family with representative evidence.

Write ONLY valid JSON matching auth-access:
{
  "kind": "auth-access",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "auth": [
    { "id": "stable short id", "kind": "auth_config|authorization_rule|identity_provider|middleware|other", "name": "string", "mechanism": "optional session|jwt|oauth|api-key|mtls|other", "location": "relative/path", "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
  ],
  "entrypoint_access": [
    { "entrypoint_id": "id from inputs.entrypoints", "status": "protected|public|unknown", "mechanism": "optional string", "roles_scopes": ["optional role or scope names"], "session_storage": "optional observed storage/check location", "evidence": ["relative/path:line"] }
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

function buildConfigSecretsPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the config-secrets section artifact. This artifact answers assignment section 7:
- secrets and configuration.

Collect only:
- config files and configuration modules;
- environment variable names and config loaders;
- default/example config values by name or status only;
- .env files and examples;
- secret-manager or credential-store references;
- hardcoded secret-like string locations as facts only, never values.

Depth bounds:
- Use the supplied repository navigation index and config/manifest file lists as
  the starting map.
- Stay at configuration-source level.
- Do not classify entrypoint access or auth protection.
- Do not perform broad repo-wide secret hunting; deterministic scanners provide
  concrete secret observations separately.
- Do not output secret values, connection strings, cookies, tokens, private keys, or passwords. Use only names and set value_redacted true for secret_references.
- Do not root-cause configuration behavior.
- Group repeated config/env/secret references by family when exact values or all
  occurrences are not needed for the map.

Write ONLY valid JSON matching config-secrets:
{
  "kind": "config-secrets",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
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

function buildStorageDataModelPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the storage-data-model section artifact. This artifact answers assignment section 9:
- storage and data model.

Collect only map facts:
- databases and their types;
- ORM models, schemas, migrations;
- caches, queues, object/file storage and buckets;
- entities or fields that appear personal/sensitive by schema or field name only.

Depth bounds:
- Use manifests, accepted config-secrets, and the source index as the starting map.
- Use find/grep/read to discover storage, model, schema, migration, cache, queue,
  bucket, and file-storage declarations.
- Do not trace storage call chains.
- Do not infer data sensitivity beyond field/schema names.
- Do not include external API, egress, infra, deploy, crypto, logging, or operation-sink facts.
- Group repeated storage/model/schema declarations by family when exhaustive
  enumeration would make the map noisy.

Write ONLY valid JSON matching storage-data-model:
{
  "kind": "storage-data-model",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "storage": [
    { "id": "stable short id", "kind": "database|cache|message_queue|object_storage|file_storage|other", "name": "string", "type": "optional string", "location": "relative/path", "role": "string", "fields": ["optional observed field names"], "data_categories": ["optional observed categories by field name"], "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
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

function buildExternalIntegrationsEgressPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the external-integrations-egress section artifact. This artifact answers assignment section 10:
- external integrations and network egress.

Collect only map facts:
- third-party APIs and services;
- SDK integrations;
- configured hosts, service URLs, and outbound destinations;
- brokers and external message services;
- direct client setup and destination construction.

Depth bounds:
- Use accepted config-secrets, manifests, and source index as the starting map.
- Use find/grep/read to discover client setup, SDK usage, hosts, service URLs,
  brokers, and outbound destination declarations.
- Do not trace business call chains.
- Do not call external services.
- Do not include infra/deploy, storage model, crypto, logging, or data-flow facts.
- Group repeated integrations by family with representative evidence.

Write ONLY valid JSON matching external-integrations-egress:
{
  "kind": "external-integrations-egress",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "integrations": [
    { "id": "stable short id", "kind": "external_api|service|message_broker|sdk|outbound_host|other", "name": "string", "from": "relative/path", "target": "host/service/sdk when observable", "location": "relative/path", "role": "purpose as declared", "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
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

function buildInfraDeployPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the infra-deploy section artifact. This artifact answers assignment section 12:
- infrastructure and deployment.

Collect only map facts:
- Dockerfile facts: base image, user, exposed ports, entrypoint;
- compose/k8s facts: services, ports, mounts, secrets;
- IaC, proxy, hosting, runtime, CI/deploy infrastructure declarations.

Depth bounds:
- Use infra files, IaC candidates, workflow paths, config files, and top-level
  structure as the starting map.
- Use find/grep/read to discover deployment and runtime declarations.
- Do not run Docker, Terraform, workflows, package scripts, or deploy commands.
- Do not assess exposure, permissions, risk, or misconfiguration.
- Do not include storage model, external integration, operation-sink, crypto, or logging facts.
- Group repeated infra declarations by family with representative evidence.

Write ONLY valid JSON matching infra-deploy:
{
  "kind": "infra-deploy",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "infra": [
    { "id": "stable short id", "kind": "dockerfile|compose|kubernetes|iac|proxy|hosting|runtime|service|workflow|other", "name": "string", "location": "relative/path", "base_image": "optional string", "user": "optional string", "ports": ["optional observed ports"], "mounts": ["optional observed mounts"], "secrets": ["optional secret names only"], "entrypoint": "optional string", "role": "string", "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
  ],
  "ci": [
    { "id": "stable short id", "kind": "workflow|deploy|runtime|other", "name": "string", "location": "relative/path", "role": "string", "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
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

function buildOperationSinksPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the operation-sinks section artifact. This artifact answers assignment section 6:
- operation sink inventory.

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
- outbound HTTP/client SDK URL construction.

Depth bounds:
- Use the supplied repository navigation index as the starting map.
- Use find/grep/read to discover operation families instead of relying on file
  names.
- Stay at operation-family level.
- Do not trace callers, taint, exploitability, severity, impact, or fixes.
- Do not create one item per repeated helper call or log line.
- Do not perform root-cause or full business-logic analysis.
- Do not include crypto, randomness, password hashing, TLS, logging, or observability facts.
- Cite operation lines or nearby variable construction lines that directly support classification.
- Group repeated operation calls by family with representative evidence.

Write ONLY valid JSON matching operation-sinks:
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

function buildCryptoPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the crypto section artifact. This artifact answers assignment section 8:
- cryptography.

Collect only observable crypto and randomness facts:
- crypto operations, algorithms, modes, key/IV/salt parameters when directly visible;
- password hashing calls;
- TLS configuration calls;
- randomness sources.

Depth bounds:
- Use source index and config files as the starting map.
- Use find/grep/read to discover crypto, password hashing, randomness, and TLS config facts.
- Do not assess algorithm strength, correctness, exploitability, severity, impact, or fixes.
- Do not include generic operation sinks, storage, integration, or logging facts.
- Group repeated crypto/randomness calls by family with representative evidence.

Write ONLY valid JSON matching crypto:
{
  "kind": "crypto",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "crypto": [
    { "id": "stable short id", "kind": "crypto_operation|password_hashing|randomness|tls_configuration|other", "name": "string", "operation": "observable operation only", "location": "relative/path", "algorithm": "optional observed algorithm", "mode": "optional observed mode", "parameters": ["optional observed parameter names only"], "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
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

function buildLoggingObservabilityPrompt(contextPack: unknown): string {
  return `${factsOnlyPreamble()}

Task:
Create the logging-observability section artifact. This artifact answers assignment section 13:
- logging and observability.

Collect only observable logging and telemetry facts:
- logging/observability calls;
- logged field or variable names when directly visible;
- whether external input or storage-field names appear in log calls as observable facts;
- logging, metrics, tracing, or telemetry destinations when configured.

Depth bounds:
- Use source index, manifests, and config files as the starting map.
- Use find/grep/read to discover logging, metrics, tracing, telemetry, and destination facts.
- Do not infer runtime log contents.
- Do not judge sensitivity, exposure, risk, severity, impact, or fixes.
- Do not include operation sinks, crypto, storage, or integration facts unless they are directly logging/telemetry destinations.
- Group repeated logging calls by family with representative evidence.

Write ONLY valid JSON matching logging-observability:
{
  "kind": "logging-observability",
  "generated_at": "ISO timestamp",
  "generated_by": "pi",
  "repo": { "url": "string", "commit_sha": "string or null" },
  "logging": [
    { "id": "stable short id", "kind": "logging|metrics|tracing|telemetry|other", "name": "string", "operation": "observable call or destination", "location": "relative/path", "destination": "optional configured destination", "logged_fields": ["optional observed field or variable names"], "confidence": "low|medium|high", "evidence": ["relative/path:line"] }
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
- Do not use coverage-structure, stack-build-deps, auth-access, config-secrets, storage-data-model, external-integrations-egress, infra-deploy, crypto, logging-observability, trust-boundaries, or repository-map as data-flow inputs.
- Start from externally controlled entrypoints and operation-sink evidence only.
- Use the supplied entrypoints and operation_sinks artifacts as the complete
  navigation plan for this step.
- Read repository files only to confirm a direct or shallow named connection.
- Prefer key externally controlled inputs; do not enumerate every possible variable flow.
- Do not perform exhaustive tracing, line-by-line handler review, callback resolution, framework internals analysis, or root-cause analysis.
- Use "multi-step inferred" only for one or two named function hops with evidence.
- Use "not traced beyond path:line" or "not established" when deeper analysis would be required.
- Every row with a connection across functions or files must set inference true.
- Group similar flows and record not_covered/fact_gaps instead of producing a
  large speculative flow list.

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
Create compact, evidence-backed JSON map artifacts for later AppSec
attack-hypothesis building and manual review.
Stay at map level: identify observable repository structure, declared stack,
entrypoints, config references, integrations, operation families, shallow data
connections, and explicit inference boundaries.
Prefer declarations, registrations, manifests, configs, schemas, and the
minimum nearby code needed to classify a fact.

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
    userMessage: `VibeShield rejected Pi ${kind} output because it did not match the repository-map contract.`,
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
