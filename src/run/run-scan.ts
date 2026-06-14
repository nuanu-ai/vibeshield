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
import {
  type RunPiRepositoryMappingStep,
  runPiRepositoryMapping,
  runPiRepositoryMappingStep,
} from "../pi/repository-map.js";
import { writeFinalReport } from "../report/report.js";
import { createDefaultSandboxProvider } from "../sandbox/default-provider.js";
import type { SandboxProvider, SandboxSession } from "../sandbox/types.js";
import { errorMessage, ScanStageError, toScanStageError } from "./errors.js";
import {
  appendJsonLine,
  ensureDirectory,
  relativeArtifactPath,
  writeJsonAtomic,
} from "./file-io.js";
import {
  localRepoSnapshotsEqual,
  resolveLocalRepoSource,
  resolveScanSource,
  type SourceReference,
} from "./github-url.js";
import { redactDeep } from "./redaction.js";
import type { RunResumeFromStep } from "./resume-steps.js";
import type { RunEvent, RunJobState, RunStepState, ScanRunState } from "./types.js";

export interface RunScanOptions {
  onProgress?: (event: RunEvent) => unknown | Promise<unknown>;
  sourceInput: string;
  runsRoot?: string;
  sandboxProvider?: SandboxProvider;
}

export interface RunResumeOptions {
  fromStep?: RunResumeFromStep;
  onProgress?: (event: RunEvent) => unknown | Promise<unknown>;
  onlyStep?: RunResumeFromStep;
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

const attackHypothesesArtifactPath = "outputs/attack-hypotheses.json";
const finalReportMarkdownArtifactPath = "final-report.md";
const finalReportPdfArtifactPath = "final-report.pdf";

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
> & {
  attackHypotheses?: ExistingRepositoryMapArtifact;
};

interface NormalizedRepositoryMapResult {
  artifacts: Required<Record<RepositoryMapExistingKey, string>>;
  attackHypothesesPath: string;
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

type PiStepExistingInput = NonNullable<
  Parameters<typeof runPiRepositoryMappingStep>[0]["existing"]
>;

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

const repositoryMapStepOrder: RunPiRepositoryMappingStep[] = [
  "coverage-structure",
  "stack-build-deps",
  "entrypoints",
  "config-secrets",
  "auth-access",
  "storage-data-model",
  "external-integrations-egress",
  "infra-deploy",
  "operation-sinks",
  "crypto",
  "logging-observability",
  "data-flows",
  "trust-boundaries",
  "repository-map",
  "attack-hypotheses",
];

export async function runScan(options: RunScanOptions): Promise<RunScanResult> {
  const resolved = await resolveScanSource(options.sourceInput);
  if (!resolved.success) {
    return {
      exitCode: 1,
      userMessage: resolved.userMessage,
    };
  }

  const source = resolved.source;
  const sandboxProvider = options.sandboxProvider ?? createDefaultSandboxProvider();
  const createdAt = new Date();
  const runId = createRunId(createdAt);
  const runsRoot = path.resolve(options.runsRoot ?? path.join(process.cwd(), "runs"));
  const runDir = path.join(runsRoot, runId);
  const outputsDir = path.join(runDir, "outputs");
  const runJsonPath = path.join(runDir, "run.json");
  const eventsPath = path.join(runDir, "events.jsonl");
  const finalReportMarkdownPath = path.join(runDir, finalReportMarkdownArtifactPath);
  const finalReportPdfPath = path.join(runDir, finalReportPdfArtifactPath);
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
    source,
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
      repo: source,
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
      message: materializeStartedMessage(source),
      sandbox_id: sandbox.id,
      stage: "clone",
      type: "clone.started",
    });
    const materializeResult = await sandbox.materializeRepository(source);
    if (materializeResult.commitSha !== null) {
      run.commit_sha = materializeResult.commitSha;
    }
    await persistRun();
    await appendEvent({
      message: materializeCompletedMessage(source),
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
      commitSha: materializeResult.commitSha,
      generatedAt: new Date().toISOString(),
      repo: source,
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
      commitSha: materializeResult.commitSha,
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
      sourceUrl: source.url,
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

  if (run.status === "success") {
    run.finished_at = new Date().toISOString();
    run.current_stage = "final-report";
    await persistRun();
    await appendEvent({
      message: "Rendering owner-facing final report.",
      stage: "final-report",
      type: "final-report.started",
    });
    const finalReport = await writeFinalReport({
      markdownPath: finalReportMarkdownPath,
      pdfPath: finalReportPdfPath,
      run,
    });
    run.artifacts.final_report_markdown = finalReport.markdownPath;
    run.artifacts.final_report_pdf = finalReport.pdfPath;
    await appendEvent({
      artifact: finalReport.pdfPath,
      message: "Final report rendered.",
      stage: "final-report",
      type: "artifact.written",
    });
    run.current_stage = "completed";
    await persistRun();
    return {
      exitCode: 0,
      run,
      runDir,
    };
  }

  run.finished_at = new Date().toISOString();
  await persistRun();

  return {
    exitCode: 1,
    run,
    runDir,
    userMessage: failure?.userMessage ?? run.error?.user_message ?? "VibeShield scan failed.",
  };
}

export async function runResume(options: RunResumeOptions): Promise<RunResumeResult> {
  if (options.fromStep !== undefined && options.onlyStep !== undefined) {
    return {
      exitCode: 1,
      userMessage: "--from and --only cannot be used together.",
    };
  }

  const runDir = path.resolve(options.runDir);
  const outputsDir = path.join(runDir, "outputs");
  const runJsonPath = path.join(runDir, "run.json");
  const eventsPath = path.join(runDir, "events.jsonl");
  const finalReportMarkdownPath = path.join(runDir, finalReportMarkdownArtifactPath);
  const finalReportPdfPath = path.join(runDir, finalReportPdfArtifactPath);
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

  if (options.onlyStep !== undefined) {
    return runResumeOnlyStep({
      appendEvent,
      finalReportMarkdownPath,
      finalReportPdfPath,
      inventoryPath,
      onlyStep: options.onlyStep,
      outputsDir,
      persistRun,
      run,
      runDir,
      sandboxProvider,
      store,
    });
  }

  let sandbox: SandboxSession | undefined;
  let failure: ScanStageError | undefined;
  const previousResumeStatus = run.status;

  normalizeRunForResume(run);
  if (options.fromStep !== undefined) {
    clearRunArtifactsFromStep(run, options.fromStep);
  }
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
  if (options.fromStep !== undefined) {
    await appendEvent({
      details: { from_step: options.fromStep },
      message: `Rerunning pipeline from ${options.fromStep}.`,
      stage: "resume",
      type: "resume.from_step",
    });
  }

  if (options.fromStep === "final-report") {
    try {
      if (previousResumeStatus !== "success") {
        throw new ScanStageError({
          message: `Cannot rerun final-report for a run with status ${previousResumeStatus}.`,
          stage: "resume",
          userMessage:
            "Cannot rerun final-report because the previous run did not complete successfully. " +
            "Run vibeshield resume <run-dir> from an upstream step first.",
        });
      }
      await requireAnyFinalReportInput({ run, runDir, step: options.fromStep });
      run.current_stage = "final-report";
      await persistRun();
      await appendEvent({
        message: "Rendering owner-facing final report.",
        stage: "final-report",
        type: "final-report.started",
      });
      const finalReport = await writeFinalReport({
        markdownPath: finalReportMarkdownPath,
        pdfPath: finalReportPdfPath,
        run,
      });
      run.artifacts.final_report_markdown = finalReport.markdownPath;
      run.artifacts.final_report_pdf = finalReport.pdfPath;
      await appendEvent({
        artifact: finalReport.pdfPath,
        message: "Final report rendered.",
        stage: "final-report",
        type: "artifact.written",
      });
      run.status = "success";
      run.finished_at = new Date().toISOString();
      run.current_stage = "completed";
      await persistRun();
      return {
        exitCode: 0,
        run,
        runDir,
      };
    } catch (error) {
      failure = toScanStageError(error, run.current_stage);
      run.status = "failed";
      run.error = {
        diagnostics: failure.diagnostics,
        message: failure.message,
        stage: failure.stage,
        user_message: failure.userMessage,
      };
      await appendEvent({
        diagnostics: failure.diagnostics,
        message: failure.userMessage,
        stage: failure.stage,
        type: "step.failed",
      });
      run.finished_at = new Date().toISOString();
      await persistRun();
      return {
        exitCode: 1,
        run,
        runDir,
        userMessage: failure.userMessage,
      };
    }
  }

  try {
    await validateSourceForResume(run);

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
      message: materializeResumeStartedMessage(run.source),
      sandbox_id: sandbox.id,
      stage: "clone",
      type: "clone.started",
    });
    const materializeOptions =
      run.source.type === "github" && run.commit_sha !== undefined
        ? { commitSha: run.commit_sha }
        : {};
    const materializeResult = await sandbox.materializeRepository(run.source, materializeOptions);
    if (run.source.type === "github" && materializeResult.commitSha !== run.commit_sha) {
      throw new ScanStageError({
        message: `Resume checkout mismatch: expected ${run.commit_sha}, got ${materializeResult.commitSha ?? "unknown"}.`,
        stage: "clone",
        userMessage: "VibeShield could not checkout the original commit for resume.",
      });
    }
    await appendEvent({
      message: materializeResumeCompletedMessage(run.source),
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
        commitSha: materializeResult.commitSha,
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
        commitSha: materializeResult.commitSha,
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

    const existingPiArtifacts = await readExistingRepositoryMapArtifacts(runDir, run);
    const resumePiFromStep =
      options.fromStep === undefined ? undefined : repositoryMapStepForResumeStep(options.fromStep);

    if (resumePiFromStep !== undefined) {
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
        message: `Rerunning repository map from ${resumePiFromStep} with available prior artifacts.`,
        sandbox_id: sandbox.id,
        stage: "pi",
        type: "repository-map.started",
      });
      const activeSandbox = sandbox;
      await executePiRepositoryMappingFromStep({
        contextPack,
        contextPath: run.artifacts.pi_context_pack ?? "outputs/pi-context-pack.json",
        existing: repositoryMapArtifactsBeforeStep(existingPiArtifacts, resumePiFromStep),
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
        startStep: resumePiFromStep,
        store,
        onStepArtifact: async (step, artifactPath) => {
          applyRepositoryMapStepArtifact(run, step, artifactPath);
          await persistRun();
        },
      });
      piStep.status = "success";
      piStep.finished_at = new Date().toISOString();
    } else {
      const existingPi = dropExistingRepositoryMapArtifactsFromStep(
        existingPiArtifacts,
        options.fromStep,
      );
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
          message:
            "All repository map artifacts already accepted; only report will be regenerated.",
          sandbox_id: sandbox.id,
          stage: "pi",
          type: "repository-map.reused",
        });
      }
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

  if (run.status === "success") {
    run.finished_at = new Date().toISOString();
    run.current_stage = "final-report";
    await persistRun();
    await appendEvent({
      message: "Rendering owner-facing final report.",
      stage: "final-report",
      type: "final-report.started",
    });
    const finalReport = await writeFinalReport({
      markdownPath: finalReportMarkdownPath,
      pdfPath: finalReportPdfPath,
      run,
    });
    run.artifacts.final_report_markdown = finalReport.markdownPath;
    run.artifacts.final_report_pdf = finalReport.pdfPath;
    await appendEvent({
      artifact: finalReport.pdfPath,
      message: "Final report rendered.",
      stage: "final-report",
      type: "artifact.written",
    });
    run.current_stage = "completed";
    await persistRun();
    return {
      exitCode: 0,
      run,
      runDir,
    };
  }

  run.finished_at = new Date().toISOString();
  await persistRun();

  return {
    exitCode: 1,
    run,
    runDir,
    userMessage: failure?.userMessage ?? run.error?.user_message ?? "VibeShield resume failed.",
  };
}

async function runResumeOnlyStep(input: {
  appendEvent: (event: Omit<RunEvent, "timestamp">) => Promise<void>;
  finalReportMarkdownPath: string;
  finalReportPdfPath: string;
  inventoryPath: string;
  onlyStep: RunResumeFromStep;
  outputsDir: string;
  persistRun: () => Promise<void>;
  run: ScanRunState;
  runDir: string;
  sandboxProvider: SandboxProvider;
  store: ArtifactStore;
}): Promise<RunResumeResult> {
  const {
    appendEvent,
    finalReportMarkdownPath,
    finalReportPdfPath,
    inventoryPath,
    onlyStep,
    outputsDir,
    persistRun,
    run,
    runDir,
    sandboxProvider,
    store,
  } = input;

  const previousStatus = run.status;
  const previousError = run.error;
  const previousFinishedAt = run.finished_at;
  const previousCurrentStage = run.current_stage;

  let sandbox: SandboxSession | undefined;
  let failure: ScanStageError | undefined;
  let selectedStepCompleted = false;

  run.status = "running";
  run.current_stage = "resume";
  delete run.error;
  delete run.finished_at;
  await persistRun();
  await appendEvent({
    details: { step: onlyStep },
    message: `Rerunning only ${onlyStep}.`,
    stage: "resume",
    type: "resume.only_step.started",
  });

  try {
    switch (onlyStep) {
      case "inventory": {
        await validateSourceForResume(run);
        await cleanupPreviousSandboxBeforeResume({ appendEvent, run, sandboxProvider });
        sandbox = await createResumeSandbox({
          appendEvent,
          message: "Creating fresh Daytona sandbox for one-step inventory rerun.",
          persistRun,
          run,
          sandboxProvider,
        });
        const materializeResult = await materializeRepositoryForResume({
          appendEvent,
          persistRun,
          run,
          sandbox,
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
          commitSha: materializeResult.commitSha,
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
        await appendEvent({
          artifact: run.artifacts.inventory,
          message: "Inventory artifact copied to local run directory.",
          sandbox_id: sandbox.id,
          stage: "inventory",
          type: "artifact.written",
        });
        break;
      }
      case "deterministic-baseline": {
        const inventory = await requireExistingRunArtifact<InventoryArtifact>({
          label: "inventory",
          runDir,
          step: onlyStep,
          path: run.artifacts.inventory,
        });
        await validateSourceForResume(run);
        await cleanupPreviousSandboxBeforeResume({ appendEvent, run, sandboxProvider });
        sandbox = await createResumeSandbox({
          appendEvent,
          message: "Creating fresh Daytona sandbox for one-step baseline rerun.",
          persistRun,
          run,
          sandboxProvider,
        });
        const materializeResult = await materializeRepositoryForResume({
          appendEvent,
          persistRun,
          run,
          sandbox,
        });

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
          commitSha: materializeResult.commitSha,
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
        await appendEvent({
          artifact: baselineResult.summaryPath,
          message: "Baseline check summary written.",
          sandbox_id: sandbox.id,
          stage: "deterministic-baseline",
          type: "artifact.written",
        });
        break;
      }
      case "context": {
        const inventory = await requireExistingRunArtifact<InventoryArtifact>({
          label: "inventory",
          runDir,
          step: onlyStep,
          path: run.artifacts.inventory,
        });
        const baseline = await requireExistingRunArtifact<BaselineSummaryArtifact>({
          label: "baseline-summary",
          runDir,
          step: onlyStep,
          path: run.artifacts.baseline_summary,
        });
        run.current_stage = "context";
        await persistRun();
        await appendEvent({
          message: "Building curated Pi context pack from validated artifacts.",
          stage: "context",
          type: "context.started",
        });
        const contextResult = await buildPiContextPack({
          baseline,
          inventory,
          store,
        });
        run.artifacts.pi_context_pack = contextResult.contextPath;
        await appendEvent({
          artifact: contextResult.contextPath,
          message: "Pi context pack written.",
          stage: "context",
          type: "artifact.written",
        });
        break;
      }
      case "final-report": {
        if (previousStatus !== "success") {
          throw new ScanStageError({
            message: `Cannot rerun final-report for a run with status ${previousStatus}.`,
            stage: "resume",
            userMessage:
              "Cannot rerun final-report with --only because the previous run did not complete successfully. " +
              "Run vibeshield resume <run-dir> --from final-report after the upstream artifacts are accepted.",
          });
        }
        await requireAnyFinalReportInput({ run, runDir, step: onlyStep });
        run.current_stage = "final-report";
        await persistRun();
        await appendEvent({
          message: "Rendering owner-facing final report.",
          stage: "final-report",
          type: "final-report.started",
        });
        const finalReport = await writeFinalReport({
          markdownPath: finalReportMarkdownPath,
          pdfPath: finalReportPdfPath,
          run,
        });
        run.artifacts.final_report_markdown = finalReport.markdownPath;
        run.artifacts.final_report_pdf = finalReport.pdfPath;
        await appendEvent({
          artifact: finalReport.pdfPath,
          message: "Final report rendered.",
          stage: "final-report",
          type: "artifact.written",
        });
        break;
      }
      default: {
        const piStepName = repositoryMapStepForResumeStep(onlyStep);
        if (piStepName === undefined) {
          throw new ScanStageError({
            message: `Unsupported single-step resume target: ${onlyStep}.`,
            stage: "resume",
            userMessage: `VibeShield cannot rerun ${onlyStep} as a single step.`,
          });
        }
        const inventory = await requireExistingRunArtifact<InventoryArtifact>({
          label: "inventory",
          runDir,
          step: onlyStep,
          path: run.artifacts.inventory,
        });
        const contextPack = await requireExistingRunArtifact<PiContextPackArtifact>({
          label: "pi-context-pack",
          runDir,
          step: onlyStep,
          path: run.artifacts.pi_context_pack,
        });
        await validateSourceForResume(run);
        await cleanupPreviousSandboxBeforeResume({ appendEvent, run, sandboxProvider });
        sandbox = await createResumeSandbox({
          appendEvent,
          message: `Creating fresh Daytona sandbox for one-step ${onlyStep} rerun.`,
          persistRun,
          run,
          sandboxProvider,
        });
        await materializeRepositoryForResume({
          appendEvent,
          persistRun,
          run,
          sandbox,
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
        run.steps = run.steps ?? [];
        run.steps.push(piStep);
        await persistRun();
        await appendEvent({
          message: `Rerunning repository map step ${onlyStep}.`,
          sandbox_id: sandbox.id,
          stage: "pi",
          type: "repository-map.started",
        });
        const activeSandbox = sandbox;
        const existingPi = repositoryMapArtifactsBeforeStep(
          await readExistingRepositoryMapArtifacts(runDir, run),
          piStepName,
        ) as unknown as PiStepExistingInput;
        const piResult = await runPiRepositoryMappingStep({
          contextPack,
          contextPath: run.artifacts.pi_context_pack ?? "outputs/pi-context-pack.json",
          existing: existingPi,
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
          step: piStepName,
          store,
        });
        applyRepositoryMapStepArtifact(run, piStepName, piResult.artifactPath);
        piStep.status = "success";
        piStep.finished_at = new Date().toISOString();
        break;
      }
    }

    selectedStepCompleted = true;
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
        reason: run.error?.message ?? "single-step resume failed",
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
    if (failure === undefined && !cleanupResult.success) {
      failure = new ScanStageError({
        message: cleanupResult.error ?? "Sandbox cleanup failed.",
        stage: "cleanup",
        userMessage: "VibeShield completed the selected step, but sandbox cleanup failed.",
      });
      run.status = "failed";
      run.error = {
        message: failure.message,
        stage: failure.stage,
        user_message: failure.userMessage,
      };
    }
  }

  if (failure !== undefined) {
    run.finished_at = new Date().toISOString();
    await persistRun();
    return {
      exitCode: 1,
      run,
      runDir,
      userMessage: failure.userMessage,
    };
  }

  await appendEvent({
    details: { step: onlyStep },
    message: `Single step ${onlyStep} completed.`,
    stage: "resume",
    type: "resume.only_step.completed",
  });

  if (previousStatus === "success") {
    run.status = "success";
    run.current_stage = "completed";
    run.finished_at = new Date().toISOString();
    delete run.error;
  } else {
    run.status = previousStatus;
    run.current_stage = previousCurrentStage;
    if (previousError === undefined) {
      delete run.error;
    } else {
      run.error = previousError;
    }
    if (previousFinishedAt === undefined) {
      delete run.finished_at;
    } else {
      run.finished_at = previousFinishedAt;
    }
  }

  if (!selectedStepCompleted) {
    throw new Error("Invariant violation: selected step did not complete and no failure was set.");
  }

  await persistRun();
  return {
    exitCode: 0,
    run,
    runDir,
  };
}

async function createResumeSandbox(input: {
  appendEvent: (event: Omit<RunEvent, "timestamp">) => Promise<void>;
  message: string;
  persistRun: () => Promise<void>;
  run: ScanRunState;
  sandboxProvider: SandboxProvider;
}): Promise<SandboxSession> {
  input.run.current_stage = "create_sandbox";
  await input.persistRun();
  await input.appendEvent({
    message: input.message,
    stage: "create_sandbox",
    type: "sandbox.create.started",
  });

  const sandbox = await input.sandboxProvider.createSandbox({
    repo: input.run.source,
    runId: input.run.run_id,
  });
  input.run.sandbox = {
    cleanup: {
      attempted: false,
      deleted: false,
      success: false,
    },
    id: sandbox.id,
    provider: sandbox.providerName,
  };
  await input.persistRun();
  await input.appendEvent({
    message: "Sandbox created.",
    sandbox_id: sandbox.id,
    stage: "create_sandbox",
    type: "sandbox.created",
  });

  return sandbox;
}

async function materializeRepositoryForResume(input: {
  appendEvent: (event: Omit<RunEvent, "timestamp">) => Promise<void>;
  persistRun: () => Promise<void>;
  run: ScanRunState;
  sandbox: SandboxSession;
}): Promise<{ commitSha: string | null; repoPath: string }> {
  input.run.current_stage = "clone";
  await input.persistRun();
  await input.appendEvent({
    message: materializeResumeStartedMessage(input.run.source),
    sandbox_id: input.sandbox.id,
    stage: "clone",
    type: "clone.started",
  });
  const materializeOptions =
    input.run.source.type === "github" && input.run.commit_sha !== undefined
      ? { commitSha: input.run.commit_sha }
      : {};
  const materializeResult = await input.sandbox.materializeRepository(
    input.run.source,
    materializeOptions,
  );
  if (input.run.source.type === "github" && materializeResult.commitSha !== input.run.commit_sha) {
    throw new ScanStageError({
      message: `Resume checkout mismatch: expected ${input.run.commit_sha}, got ${
        materializeResult.commitSha ?? "unknown"
      }.`,
      stage: "clone",
      userMessage: "VibeShield could not checkout the original commit for resume.",
    });
  }
  await input.appendEvent({
    message: materializeResumeCompletedMessage(input.run.source),
    sandbox_id: input.sandbox.id,
    stage: "clone",
    type: "clone.completed",
  });
  return materializeResult;
}

async function requireExistingRunArtifact<T>(input: {
  label: string;
  path: string | undefined;
  runDir: string;
  step: RunResumeFromStep;
}): Promise<T> {
  const artifact = await readExistingArtifact<T>(input.runDir, input.path);
  if (artifact !== undefined) {
    return artifact;
  }

  throw new ScanStageError({
    message: `Cannot rerun ${input.step} without existing ${input.label} artifact.`,
    stage: "resume",
    userMessage:
      `Cannot rerun ${input.step} because the ${input.label} artifact is missing. ` +
      `Run vibeshield resume <run-dir> --from ${input.step} when upstream repair is needed.`,
  });
}

async function requireAnyFinalReportInput(input: {
  run: ScanRunState;
  runDir: string;
  step: RunResumeFromStep;
}): Promise<void> {
  const [baseline, repositoryMap, attackHypotheses] = await Promise.all([
    readExistingArtifact<BaselineSummaryArtifact>(
      input.runDir,
      input.run.artifacts.baseline_summary,
    ),
    readExistingArtifact<JsonObject>(input.runDir, input.run.artifacts.repository_map),
    readExistingArtifact<JsonObject>(input.runDir, input.run.artifacts.attack_hypotheses),
  ]);
  if (baseline !== undefined || repositoryMap !== undefined || attackHypotheses !== undefined) {
    return;
  }

  throw new ScanStageError({
    message: "Cannot render final report without any existing report input artifacts.",
    stage: "resume",
    userMessage:
      `Cannot rerun ${input.step} because no previous report input artifacts exist. ` +
      "Run vibeshield resume <run-dir> --from inventory when upstream repair is needed.",
  });
}

async function executePiRepositoryMappingFromStep(input: {
  contextPack: PiContextPackArtifact;
  contextPath: string;
  existing: ExistingRepositoryMapArtifacts;
  generatedAt: string;
  inventory: InventoryArtifact;
  onJobFinished?: (jobState: RunJobState) => unknown | Promise<unknown>;
  onProgress?: Parameters<RepositoryMapRunner>[0]["onProgress"];
  onStepArtifact?: (
    step: RunPiRepositoryMappingStep,
    artifactPath: string,
  ) => unknown | Promise<unknown>;
  outputsDir: string;
  runDir: string;
  sandbox: SandboxSession;
  startStep: RunPiRepositoryMappingStep;
  store: ArtifactStore;
}): Promise<void> {
  const startIndex = repositoryMapStepOrder.indexOf(input.startStep);
  if (startIndex === -1) {
    throw new ScanStageError({
      message: `Unknown repository-map step: ${input.startStep}.`,
      stage: "pi",
      userMessage: `VibeShield cannot rerun unknown repository-map step ${input.startStep}.`,
    });
  }

  const existing = { ...input.existing };
  for (const step of repositoryMapStepOrder.slice(startIndex)) {
    const runnerInput = {
      contextPack: input.contextPack,
      contextPath: input.contextPath,
      existing: existing as unknown as PiStepExistingInput,
      generatedAt: input.generatedAt,
      inventory: input.inventory,
      ...(input.onJobFinished === undefined ? {} : { onJobFinished: input.onJobFinished }),
      ...(input.onProgress === undefined ? {} : { onProgress: input.onProgress }),
      outputsDir: input.outputsDir,
      runDir: input.runDir,
      sandbox: input.sandbox,
      step,
      store: input.store,
    };
    const result = await runPiRepositoryMappingStep({
      ...runnerInput,
    });
    setExistingRepositoryMapArtifact(existing, step, {
      artifact: result.artifact as unknown as JsonObject,
      artifactPath: result.artifactPath,
    });
    await input.onStepArtifact?.(step, result.artifactPath);
  }
}

function repositoryMapArtifactsBeforeStep(
  input: ExistingRepositoryMapArtifacts,
  step: RunPiRepositoryMappingStep,
): ExistingRepositoryMapArtifacts {
  const existing: ExistingRepositoryMapArtifacts = {};
  const stepIndex = repositoryMapStepOrder.indexOf(step);
  if (stepIndex <= 0) {
    return existing;
  }

  for (const priorStep of repositoryMapStepOrder.slice(0, stepIndex)) {
    const key = repositoryMapArtifactKeyForPiStep(priorStep);
    const artifact = input[key];
    if (artifact !== undefined) {
      existing[key] = artifact;
    }
  }

  return existing;
}

function setExistingRepositoryMapArtifact(
  input: ExistingRepositoryMapArtifacts,
  step: RunPiRepositoryMappingStep,
  artifact: ExistingRepositoryMapArtifact,
): void {
  const key = repositoryMapArtifactKeyForPiStep(step);
  input[key] = artifact;
}

function applyRepositoryMapStepArtifact(
  run: ScanRunState,
  step: RunPiRepositoryMappingStep,
  artifactPath: string,
): void {
  const key = repositoryMapArtifactKeyForPiStep(step);
  if (key === "attackHypotheses") {
    run.artifacts.attack_hypotheses = artifactPath;
    return;
  }

  const definition = repositoryMapArtifacts.find((candidate) => candidate.existingKey === key);
  if (definition === undefined) {
    return;
  }
  if (definition.runKey === undefined) {
    run.artifacts.repository_map = artifactPath;
    return;
  }
  run.artifacts.repo_map = run.artifacts.repo_map ?? {};
  run.artifacts.repo_map[definition.runKey] = artifactPath;
}

function repositoryMapStepForResumeStep(
  step: RunResumeFromStep,
): RunPiRepositoryMappingStep | undefined {
  return repositoryMapStepOrder.includes(step as RunPiRepositoryMappingStep)
    ? (step as RunPiRepositoryMappingStep)
    : undefined;
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

async function validateSourceForResume(run: ScanRunState): Promise<void> {
  if (run.source.type === "github") {
    if (!isValidCommitSha(run.commit_sha)) {
      throw new ScanStageError({
        message: "Cannot resume without a valid commit_sha in run.json.",
        stage: "resume",
        userMessage: "VibeShield cannot resume this run because run.json has no valid commit SHA.",
      });
    }
    return;
  }

  const refreshed = await resolveLocalRepoSource(run.source.path);
  if (!refreshed.success) {
    throw new ScanStageError({
      message: refreshed.userMessage,
      stage: "resume",
      userMessage: refreshed.userMessage,
    });
  }
  if (refreshed.source.type !== "local") {
    throw new ScanStageError({
      message: "Local run source resolved to a non-local source during resume.",
      stage: "resume",
      userMessage: "VibeShield cannot resume this local run because its source path is invalid.",
    });
  }

  if (!localRepoSnapshotsEqual(run.source.snapshot, refreshed.source.snapshot)) {
    throw new ScanStageError({
      diagnostics: [
        `Original files: ${run.source.snapshot.file_count}; current files: ${refreshed.source.snapshot.file_count}.`,
      ],
      message: "Local repository snapshot changed since this run was created.",
      stage: "resume",
      userMessage:
        "VibeShield cannot resume this local run because the Git-filtered local repository snapshot changed. Start a new scan instead.",
    });
  }
}

function normalizeRunForResume(run: ScanRunState): void {
  run.steps = (run.steps ?? []).filter((step) => step.status === "success");
}

function clearRunArtifactsFromStep(run: ScanRunState, fromStep: RunResumeFromStep): void {
  clearFinalReportRunArtifacts(run);
  if (fromStep === "final-report") {
    return;
  }
  if (fromStep === "inventory") {
    delete run.artifacts.inventory;
  }
  if (fromStep === "inventory" || fromStep === "deterministic-baseline") {
    delete run.artifacts.baseline_summary;
    delete run.artifacts.baseline_tool_availability;
  }
  if (fromStep === "inventory" || fromStep === "deterministic-baseline" || fromStep === "context") {
    delete run.artifacts.pi_context_pack;
    clearAllRepositoryMapRunArtifacts(run);
    return;
  }

  clearRepositoryMapRunArtifactsFromStep(run, fromStep);
}

function clearAllRepositoryMapRunArtifacts(run: ScanRunState): void {
  delete run.artifacts.repo_map;
  delete run.artifacts.repository_map;
  delete run.artifacts.attack_hypotheses;
  clearFinalReportRunArtifacts(run);
}

function clearFinalReportRunArtifacts(run: ScanRunState): void {
  delete run.artifacts.final_report_markdown;
  delete run.artifacts.final_report_pdf;
}

function clearRepositoryMapRunArtifactsFromStep(
  run: ScanRunState,
  fromStep: RunResumeFromStep,
): void {
  const artifactKey = repositoryMapArtifactKeyForResumeStep(fromStep);
  if (artifactKey === undefined) {
    return;
  }
  if (artifactKey === "attackHypotheses") {
    delete run.artifacts.attack_hypotheses;
    clearFinalReportRunArtifacts(run);
    return;
  }

  const firstIndex = repositoryMapArtifacts.findIndex(
    (definition) => definition.existingKey === artifactKey,
  );
  if (firstIndex === -1) {
    return;
  }

  for (const definition of repositoryMapArtifacts.slice(firstIndex)) {
    if (definition.runKey === undefined) {
      delete run.artifacts.repository_map;
    } else {
      delete run.artifacts.repo_map?.[definition.runKey];
    }
  }
  if (run.artifacts.repo_map !== undefined && Object.keys(run.artifacts.repo_map).length === 0) {
    delete run.artifacts.repo_map;
  }
  delete run.artifacts.attack_hypotheses;
  clearFinalReportRunArtifacts(run);
}

function dropExistingRepositoryMapArtifactsFromStep(
  input: ExistingRepositoryMapArtifacts,
  fromStep: RunResumeFromStep | undefined,
): ExistingRepositoryMapArtifacts {
  if (fromStep === undefined) {
    return input;
  }
  if (fromStep === "final-report") {
    return input;
  }
  if (fromStep === "inventory" || fromStep === "deterministic-baseline" || fromStep === "context") {
    return {};
  }

  const artifactKey = repositoryMapArtifactKeyForResumeStep(fromStep);
  if (artifactKey === undefined) {
    return input;
  }
  if (artifactKey === "attackHypotheses") {
    const { attackHypotheses: _ignored, ...rest } = input;
    return rest;
  }

  const firstIndex = repositoryMapArtifacts.findIndex(
    (definition) => definition.existingKey === artifactKey,
  );
  if (firstIndex === -1) {
    return input;
  }

  const reusable: ExistingRepositoryMapArtifacts = {};
  for (const definition of repositoryMapArtifacts.slice(0, firstIndex)) {
    const existing = input[definition.existingKey];
    if (existing !== undefined) {
      reusable[definition.existingKey] = existing;
    }
  }
  return reusable;
}

function repositoryMapArtifactKeyForResumeStep(
  fromStep: RunResumeFromStep,
): RepositoryMapExistingKey | "attackHypotheses" | undefined {
  switch (fromStep) {
    case "attack-hypotheses":
      return "attackHypotheses";
    case "auth-access":
      return "authAccess";
    case "config-secrets":
      return "configSecrets";
    case "coverage-structure":
      return "coverageStructure";
    case "crypto":
      return "crypto";
    case "data-flows":
      return "dataFlows";
    case "entrypoints":
      return "entrypoints";
    case "external-integrations-egress":
      return "externalIntegrationsEgress";
    case "infra-deploy":
      return "infraDeploy";
    case "logging-observability":
      return "loggingObservability";
    case "operation-sinks":
      return "operationSinks";
    case "repository-map":
      return "repositoryMap";
    case "stack-build-deps":
      return "stackBuildDeps";
    case "storage-data-model":
      return "storageDataModel";
    case "trust-boundaries":
      return "trustBoundaries";
    case "context":
    case "deterministic-baseline":
    case "final-report":
    case "inventory":
      return undefined;
  }
}

function repositoryMapArtifactKeyForPiStep(
  step: RunPiRepositoryMappingStep,
): RepositoryMapExistingKey | "attackHypotheses" {
  switch (step) {
    case "attack-hypotheses":
      return "attackHypotheses";
    case "auth-access":
      return "authAccess";
    case "config-secrets":
      return "configSecrets";
    case "coverage-structure":
      return "coverageStructure";
    case "crypto":
      return "crypto";
    case "data-flows":
      return "dataFlows";
    case "entrypoints":
      return "entrypoints";
    case "external-integrations-egress":
      return "externalIntegrationsEgress";
    case "infra-deploy":
      return "infraDeploy";
    case "logging-observability":
      return "loggingObservability";
    case "operation-sinks":
      return "operationSinks";
    case "repository-map":
      return "repositoryMap";
    case "stack-build-deps":
      return "stackBuildDeps";
    case "storage-data-model":
      return "storageDataModel";
    case "trust-boundaries":
      return "trustBoundaries";
  }
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

  const attackHypothesesPath = run.artifacts.attack_hypotheses ?? attackHypothesesArtifactPath;
  const attackHypotheses = await readExistingArtifact<JsonObject>(runDir, attackHypothesesPath);
  if (attackHypotheses !== undefined) {
    existing.attackHypotheses = {
      artifact: attackHypotheses,
      artifactPath: attackHypothesesPath,
    };
  }

  return existing;
}

function hasCompleteRepositoryMapArtifacts(input: ExistingRepositoryMapArtifacts): boolean {
  return (
    repositoryMapArtifacts.every((definition) => input[definition.existingKey] !== undefined) &&
    input.attackHypotheses !== undefined
  );
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
  if (
    repositoryMapArtifacts.every((definition) => reusable[definition.existingKey] !== undefined)
  ) {
    if (input.attackHypotheses !== undefined) {
      reusable.attackHypotheses = input.attackHypotheses;
    }
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
    if (input.attackHypotheses === undefined) {
      delete run.artifacts.attack_hypotheses;
    }
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

  delete run.artifacts.attack_hypotheses;

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
  if (input.attackHypotheses !== undefined) {
    run.artifacts.attack_hypotheses = input.attackHypotheses.artifactPath;
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
  run.artifacts.attack_hypotheses = result.attackHypothesesPath;
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

  const attackHypothesesPath =
    pathFromUnknown(resultRecord.attackHypothesesPath) ??
    pathFromUnknown(resultRecord.attack_hypotheses_path) ??
    pathFromUnknown(resultRecord.attackHypotheses) ??
    pathFromUnknown(resultRecord.attack_hypotheses);
  if (attackHypothesesPath === undefined) {
    missing.push(attackHypothesesArtifactPath);
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
    attackHypothesesPath: attackHypothesesPath ?? attackHypothesesArtifactPath,
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

function materializeStartedMessage(source: SourceReference): string {
  return source.type === "github"
    ? "Cloning repository inside sandbox."
    : "Copying Git-filtered local repository snapshot into sandbox.";
}

function materializeCompletedMessage(source: SourceReference): string {
  return source.type === "github"
    ? "Repository cloned inside sandbox."
    : "Local repository snapshot copied inside sandbox.";
}

function materializeResumeStartedMessage(source: SourceReference): string {
  return source.type === "github"
    ? "Cloning repository inside sandbox at original commit."
    : "Copying unchanged local repository snapshot into sandbox.";
}

function materializeResumeCompletedMessage(source: SourceReference): string {
  return source.type === "github"
    ? "Repository cloned at original commit inside sandbox."
    : "Unchanged local repository snapshot copied inside sandbox.";
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
  const attackHypotheses = store.get("attack-hypotheses");
  if (attackHypotheses !== undefined) {
    run.artifacts.attack_hypotheses = attackHypotheses.path;
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
