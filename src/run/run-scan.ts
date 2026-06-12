import { randomUUID } from "node:crypto";
import { copyFile, readFile } from "node:fs/promises";
import path from "node:path";
import type { InventoryArtifact } from "../artifacts/contracts.js";
import { ArtifactStore } from "../artifacts/store.js";
import { runDeterministicBaseline } from "../baseline/deterministic-baseline.js";
import { buildPiContextPack } from "../context/step-context-builder.js";
import { runProjectUnderstanding } from "../pi/project-understanding.js";
import { writeFailureReport, writeSuccessReport } from "../report/report.js";
import { createDefaultSandboxProvider } from "../sandbox/default-provider.js";
import type { SandboxProvider, SandboxSession } from "../sandbox/types.js";
import { ScanStageError, toScanStageError } from "./errors.js";
import {
  appendJsonLine,
  ensureDirectory,
  relativeArtifactPath,
  writeJsonAtomic,
} from "./file-io.js";
import { parseGitHubRepoUrl } from "./github-url.js";
import { redactDeep } from "./redaction.js";
import type { RunEvent, RunStepState, ScanRunState } from "./types.js";

export interface RunScanOptions {
  repoUrlInput: string;
  onProgress?: (event: RunEvent) => unknown | Promise<unknown>;
  runsRoot?: string;
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
  const inventoryPath = path.join(outputsDir, "inventory.v1.json");
  const legacyInventoryPath = path.join(outputsDir, "repo-inventory.json");
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
    await copyFile(inventoryPath, legacyInventoryPath);
    run.artifacts.inventory = relativeArtifactPath(runDir, inventoryPath);
    run.artifacts.inventory_legacy = relativeArtifactPath(runDir, legacyInventoryPath);
    store.register({
      id: "inventory",
      kind: "inventory.v1",
      path: run.artifacts.inventory,
      version: 1,
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
      message: "Starting deterministic baseline step.",
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
      message: "Deterministic baseline summary written.",
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
      name: "pi-project-understanding",
      stage: "pi",
      started_at: new Date().toISOString(),
      status: "running",
    };
    run.steps.push(piStep);
    await persistRun();
    await appendEvent({
      message: "Running Pi project-understanding from curated context pack.",
      sandbox_id: sandbox.id,
      stage: "pi",
      type: "pi.started",
    });
    const piResult = await runProjectUnderstanding({
      contextPack: contextResult.contextPack,
      contextPath: contextResult.contextPath,
      generatedAt: new Date().toISOString(),
      inventory,
      outputsDir,
      runDir,
      sandbox,
      store,
    });
    piStep.jobs = [piResult.jobState];
    piStep.status = "success";
    piStep.finished_at = new Date().toISOString();
    run.artifacts.project_understanding = piResult.projectUnderstandingPath;
    run.artifacts.pi_progress = piResult.progressPath;
    run.artifacts.pi_raw_output = piResult.rawOutputPath;
    run.artifacts.pi_stderr = piResult.stderrPath;
    await persistRun();
    await appendEvent({
      artifact: piResult.projectUnderstandingPath,
      message: "Project understanding artifact accepted by quality gate.",
      sandbox_id: sandbox.id,
      stage: "project-understanding-validation",
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
  const projectUnderstanding = store.get("project-understanding");
  if (projectUnderstanding !== undefined) {
    run.artifacts.project_understanding = projectUnderstanding.path;
  }
}
