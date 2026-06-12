import { randomUUID } from "node:crypto";
import path from "node:path";
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
import type { RunEvent, ScanRunState } from "./types.js";

export interface RunScanOptions {
  repoUrlInput: string;
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
  const inventoryPath = path.join(outputsDir, "repo-inventory.json");

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
  const appendEvent = async (event: Omit<RunEvent, "timestamp">) =>
    appendJsonLine(eventsPath, {
      ...event,
      timestamp: new Date().toISOString(),
    });

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
    await sandbox.pullFile(inventoryArtifact.sandboxPath, inventoryPath);
    run.artifacts.inventory = relativeArtifactPath(runDir, inventoryPath);
    await persistRun();
    await appendEvent({
      artifact: run.artifacts.inventory,
      message: "Inventory artifact copied to local run directory.",
      sandbox_id: sandbox.id,
      stage: "inventory",
      type: "artifact.written",
    });

    run.status = "success";
  } catch (error) {
    const stage = run.current_stage;
    failure = toScanStageError(error, stage);
    run.status = "failed";
    run.error = {
      message: failure.message,
      stage: failure.stage,
      user_message: failure.userMessage,
    };
    const failureEvent: Omit<RunEvent, "timestamp"> = {
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
    run.current_stage = "completed";
    await writeSuccessReport({
      inventoryPath: run.artifacts.inventory ?? "outputs/repo-inventory.json",
      reportPath,
      run,
    });
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
