import { randomUUID } from "node:crypto";
import { access, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import type {
  BaselineSummaryArtifact,
  InventoryArtifact,
  PiContextPackArtifact,
} from "../artifacts/contracts.js";
import { ArtifactStore } from "../artifacts/store.js";
import { runDeterministicBaseline } from "../baseline/deterministic-baseline.js";
import { buildPiContextPack } from "../context/step-context-builder.js";
import { runPiRepositoryMapping } from "../pi/repository-map.js";
import { writeFailureReport, writeSuccessReport } from "../report/report.js";
import { createDefaultSandboxProvider } from "../sandbox/default-provider.js";
import type { SandboxProvider, SandboxSession } from "../sandbox/types.js";
import { errorMessage, ScanStageError, toScanStageError } from "./errors.js";
import {
  appendJsonLine,
  ensureDirectory,
  relativeArtifactPath,
  writeJsonAtomic,
} from "./file-io.js";
import { parseGitHubRepoUrl } from "./github-url.js";
import { redactDeep } from "./redaction.js";
import type { RunEvent, RunJobState, RunStepState, ScanRunState } from "./types.js";

export interface RunScanOptions {
  repoUrlInput: string;
  onProgress?: (event: RunEvent) => unknown | Promise<unknown>;
  runsRoot?: string;
  sandboxProvider?: SandboxProvider;
}

export interface RunResumeOptions {
  onProgress?: (event: RunEvent) => unknown | Promise<unknown>;
  runDir: string;
  sandboxProvider?: SandboxProvider;
}

export interface RunScanSuccess {
  exitCode: 0;
  run: ScanRunState;
  runDir: string;
}

export interface RunScanFailure {
  exitCode: 1;
  run?: ScanRunState;
  runDir?: string;
  userMessage: string;
}

export type RunScanResult = RunScanSuccess | RunScanFailure;

export type RunResumeResult = RunScanResult;

type JsonObject = Record<string, unknown>;

type RepoMapRunArtifactKey = keyof NonNullable<ScanRunState["artifacts"]["repo_map"]>;

type RepositoryMapExistingKey =
  | "authAccess"
  | "configSecrets"
  | "coverageStructure"
  | "crypto"
  | "dataFlows"
  | "entrypoints"
  | "externalIntegrationsEgress"
  | "infraDeploy"
  | "loggingObservability"
  | "operationSinks"
  | "repositoryMap"
  | "stackBuildDeps"
  | "storageDataModel"
  | "trustBoundaries";

interface RepositoryMapArtifactDefinition {
  existingKey: RepositoryMapExistingKey;
  resultPathKeys: string[];
  runKey?: RepoMapRunArtifactKey;
  storeIds: string[];
  path: string;
}

interface ExistingRepositoryMapArtifact {
  artifact: JsonObject;
  artifactPath: string;
}

type ExistingRepositoryMapArtifacts = Partial<
  Record<RepositoryMapExistingKey, ExistingRepositoryMapArtifact>
>;

interface NormalizedRepositoryMapResult {
  artifacts: Required<Record<RepositoryMapExistingKey, string>>;
  jobStates: RunJobState[];
}

type RepositoryMapRunner = (input: {
  contextPack: PiContextPackArtifact;
  contextPath: string;
  existing?: ExistingRepositoryMapArtifacts;
  generatedAt: string;
  inventory: InventoryArtifact;
  onJobFinished?: (jobState: RunJobState) => unknown | Promise<unknown>;
  onProgress?: Parameters<NonNullable<SandboxSession["runJob"]>>[0]["onProgress"];
  outputsDir: string;
  runDir: string;
  sandbox: SandboxSession;
  store: ArtifactStore;
}) => Promise<unknown>;

const repositoryMapArtifacts: RepositoryMapArtifactDefinition[] = [
  {
    existingKey: "coverageStructure",
    path: "outputs/repo-map/coverage-structure.json",
    resultPathKeys: ["coverageStructurePath", "coverage_structure_path"],
    runKey: "coverage_structure",
    storeIds: ["repo-map-coverage-structure", "coverage-structure"],
  },
  {
    existingKey: "stackBuildDeps",
    path: "outputs/repo-map/stack-build-deps.json",
    resultPathKeys: ["stackBuildDepsPath", "stack_build_deps_path"],
    runKey: "stack_build_deps",
    storeIds: ["repo-map-stack-build-deps", "stack-build-deps"],
  },
  {
    existingKey: "entrypoints",
    path: "outputs/repo-map/entrypoints.json",
    resultPathKeys: ["entrypointsPath", "entrypoints_path"],
    runKey: "entrypoints",
    storeIds: ["repo-map-entrypoints", "entrypoints"],
  },
  {
    existingKey: "configSecrets",
    path: "outputs/repo-map/config-secrets.json",
    resultPathKeys: ["configSecretsPath", "config_secrets_path"],
    runKey: "config_secrets",
    storeIds: ["repo-map-config-secrets", "config-secrets"],
  },
  {
    existingKey: "authAccess",
    path: "outputs/repo-map/auth-access.json",
    resultPathKeys: ["authAccessPath", "auth_access_path"],
    runKey: "auth_access",
    storeIds: ["repo-map-auth-access", "auth-access"],
  },
  {
    existingKey: "storageDataModel",
    path: "outputs/repo-map/storage-data-model.json",
    resultPathKeys: ["storageDataModelPath", "storage_data_model_path"],
    runKey: "storage_data_model",
    storeIds: ["repo-map-storage-data-model", "storage-data-model"],
  },
  {
    existingKey: "externalIntegrationsEgress",
    path: "outputs/repo-map/external-integrations-egress.json",
    resultPathKeys: ["externalIntegrationsEgressPath", "external_integrations_egress_path"],
    runKey: "external_integrations_egress",
    storeIds: ["repo-map-external-integrations-egress", "external-integrations-egress"],
  },
  {
    existingKey: "infraDeploy",
    path: "outputs/repo-map/infra-deploy.json",
    resultPathKeys: ["infraDeployPath", "infra_deploy_path"],
    runKey: "infra_deploy",
    storeIds: ["repo-map-infra-deploy", "infra-deploy"],
  },
  {
    existingKey: "operationSinks",
    path: "outputs/repo-map/operation-sinks.json",
    resultPathKeys: ["operationSinksPath", "operation_sinks_path"],
    runKey: "operation_sinks",
    storeIds: ["repo-map-operation-sinks", "operation-sinks"],
  },
  {
    existingKey: "crypto",
    path: "outputs/repo-map/crypto.json",
    resultPathKeys: ["cryptoPath", "crypto_path"],
    runKey: "crypto",
    storeIds: ["repo-map-crypto", "crypto"],
  },
  {
    existingKey: "loggingObservability",
    path: "outputs/repo-map/logging-observability.json",
    resultPathKeys: ["loggingObservabilityPath", "logging_observability_path"],
    runKey: "logging_observability",
    storeIds: ["repo-map-logging-observability", "logging-observability"],
  },
  {
    existingKey: "dataFlows",
    path: "outputs/repo-map/data-flows.json",
    resultPathKeys: ["dataFlowsPath", "data_flows_path"],
    runKey: "data_flows",
    storeIds: ["repo-map-data-flows", "data-flows"],
  },
  {
    existingKey: "trustBoundaries",
    path: "outputs/repo-map/trust-boundaries.json",
    resultPathKeys: ["trustBoundariesPath", "trust_boundaries_path"],
    runKey: "trust_boundaries",
    storeIds: ["repo-map-trust-boundaries", "trust-boundaries"],
  },
  {
    existingKey: "repositoryMap",
    path: "outputs/repository-map.json",
    resultPathKeys: ["repositoryMapPath", "repository_map_path"],
    storeIds: ["repository-map", "repo-map"],
  },
];

export async function runScan(options: RunScanOptions): Promise<RunScanResult> {
  const parsed = parseGitHubRepoUrl(options.repoUrlInput);
  if (!parsed.success) {
    return {
      exitCode: 1,
      userMessage: parsed.userMessage,
    };
  }

  const sandboxProvider = options.sandboxProvider ?? createDefaultSandboxProvider();
  const createdAt = new Date();
  const runId = createRunId(createdAt);
  const runsRoot = path.resolve(options.runsRoot ?? path.join(process.cwd(), "runs"));
  const runDir = path.join(runsRoot, runId);
  const outputsDir = path.join(runDir, "outputs");
  const runJsonPath = path.join(runDir, "run.json");
  const eventsPath = path.join(runDir, "events.jsonl");
  const reportPath = path.join(runDir, "report.md");
  const inventoryPath = path.join(outputsDir, "inventory.json");
  const store = new ArtifactStore(runDir, outputsDir);

  await ensureDirectory(outputsDir);

  const run: ScanRunState = {
    artifacts: {
      events: "events.jsonl",
      outputs_dir: "outputs",
    },
    created_at: createdAt.toISOString(),
    current_stage: "create_run",
    run_id: runId,
    source: parsed.repo,
    status: "running",
  };

  const persistRun = async () => writeJsonAtomic(runJsonPath, run);
  const appendEvent = async (event: Omit<RunEvent, "timestamp">) => {
    const eventWithTimestamp: RunEvent = redactDeep({
      ...event,
      timestamp: new Date().toISOString(),
    });
    await appendJsonLine(eventsPath, eventWithTimestamp);
    await options.onProgress?.(eventWithTimestamp);
  };

  await persistRun();
  await appendEvent({
    message: "Created local scan run directory.",
    stage: "create_run",
    type: "run.created",
  });

  let sandbox: SandboxSession | undefined;
  let failure: ScanStageError | undefined;

  try {
    run.current_stage = "create_sandbox";
    await persistRun();
    await appendEvent({
      message: "Creating fresh Daytona sandbox for this scan run.",
      stage: "create_sandbox",
      type: "sandbox.create.started",
    });

    sandbox = await sandboxProvider.createSandbox({
      repo: parsed.repo,
      runId,
    });
    run.sandbox = {
      cleanup: {
        attempted: false,
        deleted: false,
        success: false,
      },
      id: sandbox.id,
      provider: sandbox.providerName,
    };
    await persistRun();
    await appendEvent({
      message: "Sandbox created.",
      sandbox_id: sandbox.id,
      stage: "create_sandbox",
      type: "sandbox.created",
    });

    run.current_stage = "clone";
    await persistRun();
    await appendEvent({
      message: "Cloning repository inside sandbox.",
      sandbox_id: sandbox.id,
      stage: "clone",
      type: "clone.started",
    });
    const cloneResult = await sandbox.cloneRepository(parsed.repo);
    if (cloneResult.commitSha !== null) {
      run.commit_sha = cloneResult.commitSha;
    }
    await persistRun();
    await appendEvent({
      message: "Repository cloned inside sandbox.",
      sandbox_id: sandbox.id,
      stage: "clone",
      type: "clone.completed",
    });

    run.current_stage = "inventory";
    await persistRun();
    await appendEvent({
      message: "Running controlled read-only inventory inside sandbox.",
      sandbox_id: sandbox.id,
      stage: "inventory",
      type: "inventory.started",
    });
    const inventoryArtifact = await sandbox.generateInventory({
      commitSha: cloneResult.commitSha,
      generatedAt: new Date().toISOString(),
      repo: parsed.repo,
    });
    await sandbox.pullFile(inventoryArtifact.sandboxPath, inventoryPath, {
      artifact: inventoryArtifact.relativePath,
      stage: "inventory",
    });
    run.artifacts.inventory = relativeArtifactPath(runDir, inventoryPath);
    store.register({
      id: "inventory",
      kind: "inventory",
      path: run.artifacts.inventory,
    });
    await persistRun();
    await appendEvent({
      artifact: run.artifacts.inventory,
      message: "Inventory artifact copied to local run directory.",
      sandbox_id: sandbox.id,
      stage: "inventory",
      type: "artifact.written",
    });

    const inventory = JSON.parse(await readFile(inventoryPath, "utf8")) as InventoryArtifact;

    run.current_stage = "deterministic-baseline";
    run.steps = run.steps ?? [];
    const baselineStep: RunStepState = {
      diagnostics: [],
      jobs: [],
      name: "deterministic-baseline",
      stage: "deterministic-baseline",
      started_at: new Date().toISOString(),
      status: "running",
    };
    run.steps.push(baselineStep);
    await persistRun();
    await appendEvent({
      message: "Running quick deterministic repository checks.",
      sandbox_id: sandbox.id,
      stage: "deterministic-baseline",
      type: "step.started",
    });

    const activeSandbox = sandbox;
    const baselineResult = await runDeterministicBaseline({
      commitSha: cloneResult.commitSha,
      generatedAt: new Date().toISOString(),
      inventory,
      onProgress: (event) =>
        appendEvent({
          ...(event.job === undefined ? {} : { job: event.job }),
          message: event.message,
          sandbox_id: activeSandbox.id,
          stage: "deterministic-baseline",
          type: event.type,
        }),
      outputsDir,
      runDir,
      sandbox,
      sourceUrl: parsed.repo.url,
      store,
    });
    baselineStep.jobs = baselineResult.jobStates;
    baselineStep.status = "success";
    baselineStep.finished_at = new Date().toISOString();
    run.artifacts.baseline_summary = baselineResult.summaryPath;
    syncKnownArtifacts(run, store);
    await persistRun();
    await appendEvent({
      artifact: baselineResult.summaryPath,
      message: "Baseline check summary written.",
      sandbox_id: sandbox.id,
      stage: "deterministic-baseline",
      type: "artifact.written",
    });

    run.current_stage = "context";
    await persistRun();
    await appendEvent({
      message: "Building curated Pi context pack from validated artifacts.",
      sandbox_id: sandbox.id,
      stage: "context",
      type: "context.started",
    });
    const contextResult = await buildPiContextPack({
      baseline: baselineResult.summary,
      inventory,
      store,
    });
    run.artifacts.pi_context_pack = contextResult.contextPath;
    await persistRun();
    await appendEvent({
      artifact: contextResult.contextPath,
      message: "Pi context pack written.",
      sandbox_id: sandbox.id,
      stage: "context",
      type: "artifact.written",
    });

    run.current_stage = "pi";
    const piStep: RunStepState = {
      diagnostics: [],
      jobs: [],
      name: "pi-repository-mapping",
      stage: "pi",
      started_at: new Date().toISOString(),
      status: "running",
    };
    run.steps.push(piStep);
    await persistRun();
    await appendEvent({
      message: "Building repository map artifacts.",
      sandbox_id: sandbox.id,
      stage: "pi",
      type: "repository-map.started",
    });
    const piResult = await executePiRepositoryMapping({
      contextPack: contextResult.contextPack,
      contextPath: contextResult.contextPath,
      generatedAt: new Date().toISOString(),
      inventory,
      onJobFinished: async (jobState) => {
        upsertRunJob(piStep, jobState);
        await persistRun();
      },
      onProgress: async (event) => {
        if (event.job !== undefined && ensureRunningRunJob(piStep, event.job)) {
          await persistRun();
        }
        await appendEvent({
          ...(event.details === undefined ? {} : { details: event.details }),
          job: event.job,
          message: event.message,
          sandbox_id: activeSandbox.id,
          stage: "pi",
          type: event.type,
        });
      },
      outputsDir,
      runDir,
      sandbox,
      store,
    });
    piStep.jobs = piResult.jobStates;
    piStep.status = "success";
    piStep.finished_at = new Date().toISOString();
    applyRepositoryMapArtifacts(run, piResult);
    await persistRun();
    await appendEvent({
      artifact: piResult.artifacts.repositoryMap,
      message: "Staged Pi repository mapping artifacts accepted by quality gates.",
      sandbox_id: sandbox.id,
      stage: "repository-map-validation",
      type: "artifact.written",
    });

    run.status = "success";
  } catch (error) {
    const stage = run.current_stage;
    failure = toScanStageError(error, stage);
    run.status = "failed";
    syncKnownArtifacts(run, store);
    run.error = {
      diagnostics: failure.diagnostics,
      message: failure.message,
      stage: failure.stage,
      user_message: failure.userMessage,
    };
    markRunningStepFailed(run, failure);
    const failureEvent: Omit<RunEvent, "timestamp"> = {
      diagnostics: failure.diagnostics,
      message: failure.userMessage,
      stage: failure.stage,
      type: "step.failed",
    };
    if (sandbox !== undefined) {
      failureEvent.sandbox_id = sandbox.id;
    }
    await appendEvent(failureEvent);
  }

  if (sandbox !== undefined) {
    if (run.status === "failed") {
      await collectSandboxFailureDiagnostics({
        appendEvent,
        outputsDir,
        persistRun,
        reason: run.error?.message ?? "scan failed",
        run,
        runDir,
        sandbox,
      });
    }

    run.current_stage = "cleanup";
    await persistRun();

    const cleanupResult = await sandbox.delete().catch((error: unknown) => ({
      attempted: true,
      deleted: false,
      error: error instanceof Error ? error.message : String(error),
      success: false,
    }));

    if (run.sandbox !== undefined) {
      run.sandbox.cleanup = cleanupResult;
    }

    await appendEvent({
      message: cleanupResult.success ? "Sandbox deleted." : "Sandbox cleanup failed.",
      sandbox_id: sandbox.id,
      stage: "cleanup",
      type: cleanupResult.success ? "sandbox.deleted" : "sandbox.cleanup_failed",
    });

    if (run.status === "success" && !cleanupResult.success) {
      failure = new ScanStageError({
        message: cleanupResult.error ?? "Sandbox cleanup failed.",
        stage: "cleanup",
        userMessage: "VibeShield completed inventory, but sandbox cleanup failed.",
      });
      run.status = "failed";
      run.error = {
        message: failure.message,
        stage: failure.stage,
        user_message: failure.userMessage,
      };
    }
  }

  run.finished_at = new Date().toISOString();
  run.artifacts.report = "report.md";

  if (run.status === "success") {
    run.current_stage = "report";
    await persistRun();
    await writeSuccessReport({
      reportPath,
      run,
    });
    run.current_stage = "completed";
    await persistRun();
    return {
      exitCode: 0,
      run,
      runDir,
    };
  }

  await writeFailureReport({
    reportPath,
    run,
  });
  await persistRun();

  return {
    exitCode: 1,
    run,
    runDir,
    userMessage: failure?.userMessage ?? run.error?.user_message ?? "VibeShield scan failed.",
  };
}

export async function runResume(options: RunResumeOptions): Promise<RunResumeResult> {
  const runDir = path.resolve(options.runDir);
  const outputsDir = path.join(runDir, "outputs");
  const runJsonPath = path.join(runDir, "run.json");
  const eventsPath = path.join(runDir, "events.jsonl");
  const reportPath = path.join(runDir, "report.md");
  const inventoryPath = path.join(outputsDir, "inventory.json");
  const sandboxProvider = options.sandboxProvider ?? createDefaultSandboxProvider();
  const store = new ArtifactStore(runDir, outputsDir);

  let run: ScanRunState;
  try {
    run = JSON.parse(await readFile(runJsonPath, "utf8")) as ScanRunState;
  } catch (error) {
    return {
      exitCode: 1,
      userMessage: `Could not read run.json for resume: ${errorMessage(error)}`,
    };
  }

  await ensureDirectory(outputsDir);

  const persistRun = async () => writeJsonAtomic(runJsonPath, run);
  const appendEvent = async (event: Omit<RunEvent, "timestamp">) => {
    const eventWithTimestamp: RunEvent = redactDeep({
      ...event,
      timestamp: new Date().toISOString(),
    });
    await appendJsonLine(eventsPath, eventWithTimestamp);
    await options.onProgress?.(eventWithTimestamp);
  };

  let sandbox: SandboxSession | undefined;
  let failure: ScanStageError | undefined;

  normalizeRunForResume(run);
  run.status = "running";
  run.current_stage = "resume";
  delete run.error;
  delete run.finished_at;
  await persistRun();
  await appendEvent({
    message: "Resuming scan from durable local artifacts.",
    stage: "resume",
    type: "resume.started",
  });

  try {
    if (!isValidCommitSha(run.commit_sha)) {
      throw new ScanStageError({
        message: "Cannot resume without a valid commit_sha in run.json.",
        stage: "resume",
        userMessage: "VibeShield cannot resume this run because run.json has no valid commit SHA.",
      });
    }

    await cleanupPreviousSandboxBeforeResume({
      appendEvent,
      run,
      sandboxProvider,
    });

    run.current_stage = "create_sandbox";
    await persistRun();
    await appendEvent({
      message: "Creating fresh Daytona sandbox for resumed scan.",
      stage: "create_sandbox",
      type: "sandbox.create.started",
    });
    sandbox = await sandboxProvider.createSandbox({
      repo: run.source,
      runId: run.run_id,
    });
    run.sandbox = {
      cleanup: {
        attempted: false,
        deleted: false,
        success: false,
      },
      id: sandbox.id,
      provider: sandbox.providerName,
    };
    await persistRun();
    await appendEvent({
      message: "Sandbox created.",
      sandbox_id: sandbox.id,
      stage: "create_sandbox",
      type: "sandbox.created",
    });

    run.current_stage = "clone";
    await persistRun();
    await appendEvent({
      message: "Cloning repository inside sandbox at original commit.",
      sandbox_id: sandbox.id,
      stage: "clone",
      type: "clone.started",
    });
    const cloneResult = await sandbox.cloneRepository(run.source, { commitSha: run.commit_sha });
    if (cloneResult.commitSha !== run.commit_sha) {
      throw new ScanStageError({
        message: `Resume checkout mismatch: expected ${run.commit_sha}, got ${cloneResult.commitSha ?? "unknown"}.`,
        stage: "clone",
        userMessage: "VibeShield could not checkout the original commit for resume.",
      });
    }
    await appendEvent({
      message: "Repository cloned at original commit inside sandbox.",
      sandbox_id: sandbox.id,
      stage: "clone",
      type: "clone.completed",
    });

    let inventory = await readExistingArtifact<InventoryArtifact>(runDir, run.artifacts.inventory);
    if (inventory !== undefined) {
      const inventoryArtifactPath = run.artifacts.inventory ?? "outputs/inventory.json";
      store.register({
        id: "inventory",
        kind: "inventory",
        path: inventoryArtifactPath,
      });
      await appendEvent({
        artifact: inventoryArtifactPath,
        message: "Reusing accepted inventory artifact.",
        sandbox_id: sandbox.id,
        stage: "inventory",
        type: "resume.artifact_reused",
      });
    } else {
      run.current_stage = "inventory";
      await persistRun();
      await appendEvent({
        message: "Inventory artifact missing; rebuilding inventory inside sandbox.",
        sandbox_id: sandbox.id,
        stage: "inventory",
        type: "inventory.started",
      });
      const inventoryArtifact = await sandbox.generateInventory({
        commitSha: cloneResult.commitSha,
        generatedAt: new Date().toISOString(),
        repo: run.source,
      });
      await sandbox.pullFile(inventoryArtifact.sandboxPath, inventoryPath, {
        artifact: inventoryArtifact.relativePath,
        stage: "inventory",
      });
      run.artifacts.inventory = relativeArtifactPath(runDir, inventoryPath);
      store.register({
        id: "inventory",
        kind: "inventory",
        path: run.artifacts.inventory,
      });
      inventory = JSON.parse(await readFile(inventoryPath, "utf8")) as InventoryArtifact;
    }

    let baseline = await readExistingArtifact<BaselineSummaryArtifact>(
      runDir,
      run.artifacts.baseline_summary,
    );
    if (baseline !== undefined && run.artifacts.baseline_summary !== undefined) {
      store.register({
        id: "baseline-summary",
        kind: "baseline-summary",
        path: run.artifacts.baseline_summary,
      });
      if (run.artifacts.baseline_tool_availability !== undefined) {
        store.register({
          id: "baseline-tool-availability",
          kind: "tool-availability",
          path: run.artifacts.baseline_tool_availability,
        });
      }
      await appendEvent({
        artifact: run.artifacts.baseline_summary,
        message: "Reusing accepted baseline check summary.",
        sandbox_id: sandbox.id,
        stage: "deterministic-baseline",
        type: "resume.artifact_reused",
      });
    } else {
      run.current_stage = "deterministic-baseline";
      const baselineStep: RunStepState = {
        diagnostics: [],
        jobs: [],
        name: "deterministic-baseline",
        stage: "deterministic-baseline",
        started_at: new Date().toISOString(),
        status: "running",
      };
      run.steps = run.steps ?? [];
      run.steps.push(baselineStep);
      await persistRun();
      await appendEvent({
        message: "Running quick deterministic repository checks.",
        sandbox_id: sandbox.id,
        stage: "deterministic-baseline",
        type: "step.started",
      });
      const activeSandbox = sandbox;
      const baselineResult = await runDeterministicBaseline({
        commitSha: cloneResult.commitSha,
        generatedAt: new Date().toISOString(),
        inventory,
        onProgress: (event) =>
          appendEvent({
            ...(event.job === undefined ? {} : { job: event.job }),
            message: event.message,
            sandbox_id: activeSandbox.id,
            stage: "deterministic-baseline",
            type: event.type,
          }),
        outputsDir,
        runDir,
        sandbox,
        sourceUrl: run.source.url,
        store,
      });
      baselineStep.jobs = baselineResult.jobStates;
      baselineStep.status = "success";
      baselineStep.finished_at = new Date().toISOString();
      run.artifacts.baseline_summary = baselineResult.summaryPath;
      syncKnownArtifacts(run, store);
      baseline = baselineResult.summary;
      await appendEvent({
        artifact: baselineResult.summaryPath,
        message: "Baseline check summary written.",
        sandbox_id: sandbox.id,
        stage: "deterministic-baseline",
        type: "artifact.written",
      });
    }

    let contextPack = await readExistingArtifact<PiContextPackArtifact>(
      runDir,
      run.artifacts.pi_context_pack,
    );
    if (contextPack !== undefined && run.artifacts.pi_context_pack !== undefined) {
      store.register({
        id: "pi-context-pack",
        kind: "pi-context-pack",
        path: run.artifacts.pi_context_pack,
      });
      await appendEvent({
        artifact: run.artifacts.pi_context_pack,
        message: "Reusing accepted Pi context pack.",
        sandbox_id: sandbox.id,
        stage: "context",
        type: "resume.artifact_reused",
      });
    } else {
      run.current_stage = "context";
      await persistRun();
      const contextResult = await buildPiContextPack({
        baseline,
        inventory,
        store,
      });
      contextPack = contextResult.contextPack;
      run.artifacts.pi_context_pack = contextResult.contextPath;
    }

    const existingPi = await readExistingRepositoryMapArtifacts(runDir, run);
    const needsPi = !hasCompleteRepositoryMapArtifacts(existingPi);

    if (needsPi) {
      const reusablePi = leadingExistingRepositoryMapArtifacts(existingPi);
      clearRepositoryMapArtifactsAfterFirstMissing(run, existingPi);
      run.current_stage = "pi";
      const piStep: RunStepState = {
        diagnostics: [],
        jobs: [],
        name: "pi-repository-mapping",
        stage: "pi",
        started_at: new Date().toISOString(),
        status: "running",
      };
      run.steps = run.steps ?? [];
      run.steps.push(piStep);
      await persistRun();
      await appendEvent({
        message: "Continuing repository map from first missing artifact.",
        sandbox_id: sandbox.id,
        stage: "pi",
        type: "repository-map.started",
      });
      const activeSandbox = sandbox;
      const piResult = await executePiRepositoryMapping({
        contextPack,
        contextPath: run.artifacts.pi_context_pack ?? "outputs/pi-context-pack.json",
        existing: reusablePi,
        generatedAt: new Date().toISOString(),
        inventory,
        onJobFinished: async (jobState) => {
          upsertRunJob(piStep, jobState);
          await persistRun();
        },
        onProgress: async (event) => {
          if (event.job !== undefined && ensureRunningRunJob(piStep, event.job)) {
            await persistRun();
          }
          await appendEvent({
            ...(event.details === undefined ? {} : { details: event.details }),
            job: event.job,
            message: event.message,
            sandbox_id: activeSandbox.id,
            stage: "pi",
            type: event.type,
          });
        },
        outputsDir,
        runDir,
        sandbox,
        store,
      });
      piStep.jobs = piResult.jobStates;
      piStep.status = "success";
      piStep.finished_at = new Date().toISOString();
      applyRepositoryMapArtifacts(run, piResult);
    } else {
      applyCompleteExistingRepositoryMapArtifacts(run, existingPi);
      await appendEvent({
        message: "All repository map artifacts already accepted; only report will be regenerated.",
        sandbox_id: sandbox.id,
        stage: "pi",
        type: "repository-map.reused",
      });
    }

    run.status = "success";
  } catch (error) {
    const stage = run.current_stage;
    failure = toScanStageError(error, stage);
    run.status = "failed";
    syncKnownArtifacts(run, store);
    run.error = {
      diagnostics: failure.diagnostics,
      message: failure.message,
      stage: failure.stage,
      user_message: failure.userMessage,
    };
    markRunningStepFailed(run, failure);
    const failureEvent: Omit<RunEvent, "timestamp"> = {
      diagnostics: failure.diagnostics,
      message: failure.userMessage,
      stage: failure.stage,
      type: "step.failed",
    };
    if (sandbox !== undefined) {
      failureEvent.sandbox_id = sandbox.id;
    }
    await appendEvent(failureEvent);
  }

  if (sandbox !== undefined) {
    if (run.status === "failed") {
      await collectSandboxFailureDiagnostics({
        appendEvent,
        outputsDir,
        persistRun,
        reason: run.error?.message ?? "resume failed",
        run,
        runDir,
        sandbox,
      });
    }

    run.current_stage = "cleanup";
    await persistRun();
    const cleanupResult = await sandbox.delete().catch((error: unknown) => ({
      attempted: true,
      deleted: false,
      error: errorMessage(error),
      success: false,
    }));
    if (run.sandbox !== undefined) {
      run.sandbox.cleanup = cleanupResult;
    }
    await appendEvent({
      message: cleanupResult.success ? "Sandbox deleted." : "Sandbox cleanup failed.",
      sandbox_id: sandbox.id,
      stage: "cleanup",
      type: cleanupResult.success ? "sandbox.deleted" : "sandbox.cleanup_failed",
    });
    if (run.status === "success" && !cleanupResult.success) {
      failure = new ScanStageError({
        message: cleanupResult.error ?? "Sandbox cleanup failed.",
        stage: "cleanup",
        userMessage: "VibeShield completed resume, but sandbox cleanup failed.",
      });
      run.status = "failed";
      run.error = {
        message: failure.message,
        stage: failure.stage,
        user_message: failure.userMessage,
      };
    }
  }

  run.finished_at = new Date().toISOString();
  run.artifacts.report = "report.md";

  if (run.status === "success") {
    run.current_stage = "report";
    await persistRun();
    await writeSuccessReport({ reportPath, run });
    run.current_stage = "completed";
    await persistRun();
    return {
      exitCode: 0,
      run,
      runDir,
    };
  }

  await writeFailureReport({ reportPath, run });
  await persistRun();

  return {
    exitCode: 1,
    run,
    runDir,
    userMessage: failure?.userMessage ?? run.error?.user_message ?? "VibeShield resume failed.",
  };
}

async function cleanupPreviousSandboxBeforeResume(input: {
  appendEvent: (event: Omit<RunEvent, "timestamp">) => Promise<void>;
  run: ScanRunState;
  sandboxProvider: SandboxProvider;
}): Promise<void> {
  const previousSandbox = input.run.sandbox;
  if (previousSandbox === undefined) {
    return;
  }

  await input.appendEvent({
    message: "Checking previous sandbox before resume.",
    sandbox_id: previousSandbox.id,
    stage: "resume",
    type: "resume.previous_sandbox_cleanup.started",
  });

  if (input.sandboxProvider.deleteSandboxById === undefined) {
    await input.appendEvent({
      diagnostics: ["Sandbox provider does not support deleteSandboxById."],
      message:
        "Previous sandbox cleanup is not supported by this provider; continuing with a fresh sandbox.",
      sandbox_id: previousSandbox.id,
      stage: "resume",
      type: "resume.previous_sandbox_cleanup.skipped",
    });
    return;
  }

  const cleanup = await input.sandboxProvider.deleteSandboxById(previousSandbox.id);
  await input.appendEvent({
    ...(cleanup.error === undefined ? {} : { diagnostics: [cleanup.error] }),
    message: cleanup.success
      ? "Previous sandbox cleanup completed."
      : "Previous sandbox cleanup failed or sandbox was not found; continuing with a fresh sandbox.",
    sandbox_id: previousSandbox.id,
    stage: "resume",
    type: cleanup.success
      ? "resume.previous_sandbox_cleanup.completed"
      : "resume.previous_sandbox_cleanup.failed",
  });
}

function normalizeRunForResume(run: ScanRunState): void {
  run.steps = (run.steps ?? []).filter((step) => step.status === "success");
}

async function collectSandboxFailureDiagnostics(input: {
  appendEvent: (event: Omit<RunEvent, "timestamp">) => Promise<void>;
  outputsDir: string;
  persistRun: () => Promise<void>;
  reason: string;
  run: ScanRunState;
  runDir: string;
  sandbox: SandboxSession;
}): Promise<void> {
  if (input.sandbox.collectDiagnostics === undefined) {
    await input.appendEvent({
      diagnostics: ["Sandbox provider does not support failure diagnostics collection."],
      message: "Sandbox failure diagnostics collection is not supported by this provider.",
      sandbox_id: input.sandbox.id,
      stage: "cleanup",
      type: "sandbox.diagnostics.skipped",
    });
    return;
  }

  await input.appendEvent({
    message: "Collecting sandbox failure diagnostics before cleanup.",
    sandbox_id: input.sandbox.id,
    stage: "cleanup",
    type: "sandbox.diagnostics.started",
  });

  try {
    const result = await input.sandbox.collectDiagnostics({ reason: input.reason });
    const artifactPaths: string[] = [];
    for (const artifact of result.artifacts) {
      const localPath = path.join(input.outputsDir, artifact.relativePath);
      await mkdir(path.dirname(localPath), { recursive: true });
      await input.sandbox.pullFile(artifact.sandboxPath, localPath, {
        artifact: artifact.relativePath,
        stage: "cleanup",
      });
      artifactPaths.push(relativeArtifactPath(input.runDir, localPath));
    }

    input.run.artifacts.diagnostics = [
      ...new Set([...(input.run.artifacts.diagnostics ?? []), ...artifactPaths]),
    ];
    await input.persistRun();
    await input.appendEvent({
      ...(result.diagnostics.length === 0 ? {} : { diagnostics: result.diagnostics }),
      ...(artifactPaths[0] === undefined ? {} : { artifact: artifactPaths[0] }),
      message: "Sandbox failure diagnostics collected.",
      sandbox_id: input.sandbox.id,
      stage: "cleanup",
      type: "sandbox.diagnostics.collected",
    });
  } catch (error) {
    await input.appendEvent({
      diagnostics: [errorMessage(error)],
      message: "Sandbox failure diagnostics collection failed; preserving original scan error.",
      sandbox_id: input.sandbox.id,
      stage: "cleanup",
      type: "sandbox.diagnostics.failed",
    });
  }
}

async function executePiRepositoryMapping(input: {
  contextPack: PiContextPackArtifact;
  contextPath: string;
  existing?: ExistingRepositoryMapArtifacts;
  generatedAt: string;
  inventory: InventoryArtifact;
  onJobFinished?: (jobState: RunJobState) => unknown | Promise<unknown>;
  onProgress?: Parameters<RepositoryMapRunner>[0]["onProgress"];
  outputsDir: string;
  runDir: string;
  sandbox: SandboxSession;
  store: ArtifactStore;
}): Promise<NormalizedRepositoryMapResult> {
  const runner = runPiRepositoryMapping as unknown as RepositoryMapRunner;
  const result = await runner(input);
  return normalizeRepositoryMapResult(result);
}

async function readExistingRepositoryMapArtifacts(
  runDir: string,
  run: ScanRunState,
): Promise<ExistingRepositoryMapArtifacts> {
  const existing: ExistingRepositoryMapArtifacts = {};

  for (const definition of repositoryMapArtifacts) {
    const recordedPath = repositoryMapArtifactPathForRun(run, definition);
    const artifactPath = recordedPath ?? definition.path;
    const artifact = await readExistingArtifact<JsonObject>(runDir, artifactPath);
    if (artifact !== undefined) {
      existing[definition.existingKey] = {
        artifact,
        artifactPath,
      };
    }
  }

  return existing;
}

function hasCompleteRepositoryMapArtifacts(input: ExistingRepositoryMapArtifacts): boolean {
  return repositoryMapArtifacts.every((definition) => input[definition.existingKey] !== undefined);
}

function leadingExistingRepositoryMapArtifacts(
  input: ExistingRepositoryMapArtifacts,
): ExistingRepositoryMapArtifacts {
  const reusable: ExistingRepositoryMapArtifacts = {};

  for (const definition of repositoryMapArtifacts) {
    const existing = input[definition.existingKey];
    if (existing === undefined) {
      break;
    }
    reusable[definition.existingKey] = existing;
  }

  return reusable;
}

function clearRepositoryMapArtifactsAfterFirstMissing(
  run: ScanRunState,
  input: ExistingRepositoryMapArtifacts,
): void {
  const firstMissingIndex = repositoryMapArtifacts.findIndex(
    (definition) => input[definition.existingKey] === undefined,
  );
  if (firstMissingIndex === -1) {
    return;
  }

  for (const definition of repositoryMapArtifacts.slice(firstMissingIndex)) {
    if (definition.runKey === undefined) {
      delete run.artifacts.repository_map;
      continue;
    }
    if (run.artifacts.repo_map !== undefined) {
      delete run.artifacts.repo_map[definition.runKey];
    }
  }

  if (run.artifacts.repo_map !== undefined && Object.keys(run.artifacts.repo_map).length === 0) {
    delete run.artifacts.repo_map;
  }
}

function applyCompleteExistingRepositoryMapArtifacts(
  run: ScanRunState,
  input: ExistingRepositoryMapArtifacts,
): void {
  if (!hasCompleteRepositoryMapArtifacts(input)) {
    throw new ScanStageError({
      message: "Resume expected all repository map artifacts to exist.",
      stage: "resume",
      userMessage:
        "VibeShield could not resume because accepted repository map artifacts are incomplete.",
    });
  }

  for (const definition of repositoryMapArtifacts) {
    const existing = input[definition.existingKey];
    if (existing === undefined) {
      continue;
    }
    if (definition.runKey === undefined) {
      run.artifacts.repository_map = existing.artifactPath;
    } else {
      run.artifacts.repo_map = run.artifacts.repo_map ?? {};
      run.artifacts.repo_map[definition.runKey] = existing.artifactPath;
    }
  }
}

function applyRepositoryMapArtifacts(
  run: ScanRunState,
  result: NormalizedRepositoryMapResult,
): void {
  for (const definition of repositoryMapArtifacts) {
    const artifactPath = result.artifacts[definition.existingKey];
    if (definition.runKey === undefined) {
      run.artifacts.repository_map = artifactPath;
      continue;
    }
    run.artifacts.repo_map = run.artifacts.repo_map ?? {};
    run.artifacts.repo_map[definition.runKey] = artifactPath;
  }
}

function normalizeRepositoryMapResult(result: unknown): NormalizedRepositoryMapResult {
  if (result === null || typeof result !== "object") {
    throw new ScanStageError({
      message: "Pi repository mapping returned an invalid result.",
      stage: "pi",
      userMessage: "VibeShield could not read Pi repository mapping artifacts.",
    });
  }

  const resultRecord = result as Record<string, unknown>;
  const artifacts = {} as Required<Record<RepositoryMapExistingKey, string>>;
  const missing: string[] = [];

  for (const definition of repositoryMapArtifacts) {
    const artifactPath = extractRepositoryMapResultPath(resultRecord, definition);
    if (artifactPath === undefined) {
      missing.push(definition.path);
      continue;
    }
    artifacts[definition.existingKey] = artifactPath;
  }

  if (missing.length > 0) {
    throw new ScanStageError({
      diagnostics: missing.map((artifact) => `Missing Pi artifact path: ${artifact}`),
      message: `Pi repository mapping result was missing artifact paths: ${missing.join(", ")}.`,
      stage: "pi",
      userMessage:
        "VibeShield could not accept Pi repository mapping output because artifact paths were incomplete.",
    });
  }

  const jobStates = Array.isArray(resultRecord.jobStates)
    ? (resultRecord.jobStates as RunJobState[])
    : [];

  return {
    artifacts,
    jobStates,
  };
}

function extractRepositoryMapResultPath(
  result: Record<string, unknown>,
  definition: RepositoryMapArtifactDefinition,
): string | undefined {
  for (const key of definition.resultPathKeys) {
    const value = pathFromUnknown(result[key]);
    if (value !== undefined) {
      return value;
    }
  }

  for (const containerKey of ["artifacts", "paths", "repoMap", "repo_map", "sectionPaths"]) {
    const container = result[containerKey];
    if (container === null || typeof container !== "object" || Array.isArray(container)) {
      continue;
    }
    const record = container as Record<string, unknown>;
    for (const key of [
      definition.existingKey,
      definition.runKey,
      ...definition.resultPathKeys,
    ].filter((key): key is string => key !== undefined)) {
      const value = pathFromUnknown(record[key]);
      if (value !== undefined) {
        return value;
      }
    }
  }

  const nestedValue = pathFromUnknown(result[definition.existingKey]);
  return nestedValue ?? pathFromUnknown(result[definition.runKey ?? definition.existingKey]);
}

function pathFromUnknown(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim() !== "") {
    return value;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }

  const record = value as Record<string, unknown>;
  for (const key of ["artifactPath", "artifact_path", "path"]) {
    const candidate = record[key];
    if (typeof candidate === "string" && candidate.trim() !== "") {
      return candidate;
    }
  }

  return undefined;
}

function repositoryMapArtifactPathForRun(
  run: ScanRunState,
  definition: RepositoryMapArtifactDefinition,
): string | undefined {
  if (definition.runKey === undefined) {
    return run.artifacts.repository_map;
  }
  return run.artifacts.repo_map?.[definition.runKey];
}

async function readExistingArtifact<T>(
  runDir: string,
  relativePath: string | undefined,
): Promise<T | undefined> {
  if (relativePath === undefined) {
    return undefined;
  }

  const absolutePath = path.join(runDir, relativePath);
  try {
    await access(absolutePath);
    return JSON.parse(await readFile(absolutePath, "utf8")) as T;
  } catch {
    return undefined;
  }
}

function isValidCommitSha(value: string | undefined): value is string {
  return typeof value === "string" && /^[0-9a-f]{40}$/i.test(value);
}

function createRunId(date: Date): string {
  const timestamp = date.toISOString().replaceAll("-", "").replaceAll(":", "").replace(".", "");
  return `run_${timestamp}_${randomUUID().slice(0, 8)}`;
}

function markRunningStepFailed(run: ScanRunState, failure: ScanStageError): void {
  const runningStep = run.steps?.find((step) => step.status === "running");
  if (runningStep === undefined) {
    return;
  }

  runningStep.status = "failed";
  runningStep.finished_at = new Date().toISOString();
  runningStep.diagnostics =
    failure.diagnostics.length > 0 ? failure.diagnostics : [failure.message];
  for (const job of runningStep.jobs) {
    if (job.status !== "running") {
      continue;
    }
    job.status = "failed";
    job.finished_at = runningStep.finished_at;
    job.diagnostics = runningStep.diagnostics;
  }
}

function ensureRunningRunJob(step: RunStepState, jobName: string): boolean {
  if (step.jobs.some((job) => job.name === jobName)) {
    return false;
  }

  step.jobs.push({
    artifacts: [],
    diagnostics: [],
    name: jobName,
    observations: 0,
    started_at: new Date().toISOString(),
    status: "running",
  });
  return true;
}

function upsertRunJob(step: RunStepState, jobState: RunJobState): void {
  const existingIndex = step.jobs.findIndex((job) => job.name === jobState.name);
  if (existingIndex === -1) {
    step.jobs.push(jobState);
    return;
  }
  step.jobs[existingIndex] = jobState;
}

function syncKnownArtifacts(run: ScanRunState, store: ArtifactStore): void {
  const baseline = store.get("baseline-summary");
  if (baseline !== undefined) {
    run.artifacts.baseline_summary = baseline.path;
  }
  const baselineToolAvailability = store.get("baseline-tool-availability");
  if (baselineToolAvailability !== undefined) {
    run.artifacts.baseline_tool_availability = baselineToolAvailability.path;
  }
  const context = store.get("pi-context-pack");
  if (context !== undefined) {
    run.artifacts.pi_context_pack = context.path;
  }
  for (const definition of repositoryMapArtifacts) {
    const artifact = firstStoredArtifact(store, definition.storeIds);
    if (artifact === undefined) {
      continue;
    }
    if (definition.runKey === undefined) {
      run.artifacts.repository_map = artifact.path;
    } else {
      run.artifacts.repo_map = run.artifacts.repo_map ?? {};
      run.artifacts.repo_map[definition.runKey] = artifact.path;
    }
  }
}

function firstStoredArtifact(
  store: ArtifactStore,
  ids: string[],
): ReturnType<ArtifactStore["get"]> {
  for (const id of ids) {
    const artifact = store.get(id);
    if (artifact !== undefined) {
      return artifact;
    }
  }
  return undefined;
}
