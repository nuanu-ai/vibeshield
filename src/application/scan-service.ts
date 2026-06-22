/**
 * ScanService — the application entry point for `vibeshield scan`.
 *
 * Wires ports together, hands the scan thread to the stage runner, and returns
 * the terminal SecurityAssessment. Has no knowledge of how sandboxes boot,
 * how state is stored, or how reports render.
 */

import { randomUUID } from "node:crypto";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import type { SourceInput } from "../domain/run.js";
import type { SecurityAssessment } from "../domain/security-assessment.js";
import { runStages } from "../pipeline/runner.js";
import type { ArtifactStore } from "../ports/artifact-store.js";
import type { EventSink } from "../ports/event-sink.js";
import type { ModelProvider } from "../ports/model-provider.js";
import type { SandboxRuntime } from "../ports/sandbox-runtime.js";
import type { StateStore } from "../ports/state-store.js";
import { DEFAULT_TOOLCHAIN_IMAGE } from "../stages/paths.js";
import { quickScanStages, readReportData } from "../stages/quick-scan.js";

export interface ScanDeps {
  readonly sandbox: SandboxRuntime;
  readonly state: StateStore;
  readonly artifacts: ArtifactStore;
  readonly events: EventSink;
  readonly model: ModelProvider;
}

export interface ScanRequest {
  readonly source: SourceInput;
  readonly runRoot: string;
  readonly toolchainImage?: string;
}

export interface ScanOutcome {
  readonly assessment: SecurityAssessment;
  readonly runId: string;
  readonly reportPaths: Readonly<Record<string, string>>;
}

/** Run the current deterministic Quick Scan end to end. */
export async function runScan(deps: ScanDeps, request: ScanRequest): Promise<ScanOutcome> {
  const createdAt = new Date().toISOString();
  const runId = newRunId(createdAt);
  const runDir = path.join(request.runRoot, runId);
  const imageTag = request.toolchainImage ?? DEFAULT_TOOLCHAIN_IMAGE;
  await mkdir(runDir, { recursive: true });

  deps.events.emit({
    type: "run-started",
    message: `Starting VibeShield scan ${runId}`,
    details: { source: request.source },
    timestamp: createdAt,
  });

  await deps.state.createRun({
    id: runId,
    source: request.source,
    createdAt,
    status: "running",
    attempts: new Map(),
    staleStages: new Set(),
  });

  const availability = await deps.sandbox.isAvailable();
  if (!availability.available) {
    const finishedAt = new Date().toISOString();
    await deps.state.finishRun(runId, "failed", finishedAt);
    const reason = availability.reason ?? "sandbox runtime is unavailable";
    deps.events.emit({
      type: "error",
      message: reason,
      timestamp: finishedAt,
    });
    throw new Error(reason);
  }

  const sandboxName = sandboxNameFor(runId);
  const session = await deps.sandbox.create({ name: sandboxName, imageTag });
  try {
    const data = await runStages({
      runId,
      runDir,
      source: request.source,
      toolchainImageTag: imageTag,
      stages: quickScanStages(),
      session,
      state: deps.state,
      artifacts: deps.artifacts,
      events: deps.events,
      model: deps.model,
    });
    const report = readReportData(data);
    const finishedAt = new Date().toISOString();
    await deps.state.finishRun(runId, "success", finishedAt);
    deps.events.emit({
      type: "run-finished",
      message: `Finished VibeShield scan ${runId}`,
      details: { verdict: report.assessment.verdict },
      timestamp: finishedAt,
    });
    return { assessment: report.assessment, runId, reportPaths: report.reportPaths };
  } catch (error) {
    const finishedAt = new Date().toISOString();
    await deps.state.finishRun(runId, "failed", finishedAt);
    deps.events.emit({
      type: "run-finished",
      message: error instanceof Error ? error.message : String(error),
      details: { status: "failed" },
      timestamp: finishedAt,
    });
    throw error;
  } finally {
    await session.destroy();
    await deps.sandbox.destroy(sandboxName);
  }
}

function newRunId(createdAt: string): string {
  const timestamp = createdAt.replace(/[-:.TZ]/g, "").slice(0, 14);
  return `${timestamp}-${randomUUID().slice(0, 8)}`;
}

function sandboxNameFor(runId: string): string {
  return `vibeshield-${runId}`.replace(/[^a-zA-Z0-9-]/g, "-");
}
