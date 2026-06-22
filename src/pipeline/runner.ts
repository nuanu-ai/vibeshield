import type { SourceInput, StageAttempt, StageId } from "../domain/run.js";
import type { ArtifactStore } from "../ports/artifact-store.js";
import type { EventSink } from "../ports/event-sink.js";
import type { ModelProvider } from "../ports/model-provider.js";
import type { SandboxSession } from "../ports/sandbox-runtime.js";
import type { StateStore } from "../ports/state-store.js";
import { StageRegistry } from "./registry.js";
import type { StageContext, StageDefinition, StageResult } from "./stage-definition.js";

export interface RunStagesOptions {
  readonly runId: string;
  readonly runDir: string;
  readonly source: SourceInput;
  readonly toolchainImageTag: string;
  readonly stages: ReadonlyArray<StageDefinition>;
  readonly session: SandboxSession;
  readonly state: StateStore;
  readonly artifacts: ArtifactStore;
  readonly events: EventSink;
  readonly model: ModelProvider;
}

export async function runStages(
  opts: RunStagesOptions,
): Promise<Map<StageId, Readonly<Record<string, unknown>>>> {
  const registry = new StageRegistry();
  for (const stage of opts.stages) {
    registry.register(stage);
  }

  const stageData = new Map<StageId, Readonly<Record<string, unknown>>>();
  for (const stage of registry.ordered()) {
    const run = await opts.state.loadRun(opts.runId);
    const previousAttempt = run?.attempts.get(stage.id)?.attempt ?? 0;
    const startedAt = now();
    const ctx = contextFor(opts, stage, stageData);

    opts.events.emit({
      type: "stage-started",
      stageId: stage.id,
      message: `Starting ${stage.id}`,
      timestamp: startedAt,
    });

    try {
      const result = await runStageWithTimeout(stage, ctx);
      await validate(stage, result, ctx);
      const finishedAt = now();
      const attempt = toAttempt(stage, result, previousAttempt + 1, startedAt, finishedAt);
      await opts.state.recordAttempt(opts.runId, attempt);
      if (result.outputs.length > 0) {
        await opts.state.recordArtifacts(opts.runId, result.outputs);
      }
      if (result.status === "success") {
        stageData.set(stage.id, result.data ?? {});
        opts.events.emit({
          type: "stage-finished",
          stageId: stage.id,
          message: `Finished ${stage.id}`,
          details: { outputs: result.outputs.map((a) => a.role) },
          timestamp: finishedAt,
        });
        continue;
      }
      opts.events.emit({
        type: "stage-failed",
        stageId: stage.id,
        message: result.error ?? `${stage.id} failed`,
        timestamp: finishedAt,
      });
      if (stage.required) {
        throw new RecordedStageFailure(result.error ?? `${stage.id} failed`);
      }
    } catch (error) {
      if (error instanceof RecordedStageFailure) {
        throw error;
      }
      const finishedAt = now();
      const message = error instanceof Error ? error.message : String(error);
      await opts.state.recordAttempt(opts.runId, {
        attempt: previousAttempt + 1,
        stageId: stage.id,
        stageVersion: stage.version,
        startedAt,
        finishedAt,
        status: "failed",
        error: message,
        outputs: [],
      });
      opts.events.emit({
        type: "stage-failed",
        stageId: stage.id,
        message,
        timestamp: finishedAt,
      });
      if (stage.required) {
        throw error;
      }
    }
  }
  return stageData;
}

function contextFor(
  opts: RunStagesOptions,
  stage: StageDefinition,
  stageData: ReadonlyMap<StageId, Readonly<Record<string, unknown>>>,
): StageContext {
  const inputs = new Map<StageId, Readonly<Record<string, unknown>>>();
  for (const dep of stage.dependencies) {
    const data = stageData.get(dep);
    if (data === undefined) {
      throw new Error(`Stage ${stage.id} dependency ${dep} has no committed data`);
    }
    inputs.set(dep, data);
  }
  return {
    runId: opts.runId,
    runDir: opts.runDir,
    source: opts.source,
    toolchainImageTag: opts.toolchainImageTag,
    inputs,
    session: opts.session,
    state: opts.state,
    artifacts: opts.artifacts,
    events: opts.events,
    model: opts.model,
  };
}

async function runStageWithTimeout(
  stage: StageDefinition,
  ctx: StageContext,
): Promise<StageResult> {
  if (stage.timeoutMs === undefined) {
    return await stage.run(ctx);
  }

  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      stage.run(ctx),
      new Promise<StageResult>((_, reject) => {
        timeout = setTimeout(() => {
          reject(new Error(`Stage ${stage.id} timed out after ${stage.timeoutMs}ms`));
        }, stage.timeoutMs);
        timeout.unref();
      }),
    ]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

async function validate(
  stage: StageDefinition,
  result: StageResult,
  ctx: StageContext,
): Promise<void> {
  for (const validator of stage.validators ?? []) {
    await validator(result, ctx);
  }
}

function toAttempt(
  stage: StageDefinition,
  result: StageResult,
  attempt: number,
  startedAt: string,
  finishedAt: string,
): StageAttempt {
  return {
    attempt,
    stageId: stage.id,
    stageVersion: stage.version,
    startedAt,
    finishedAt,
    status: result.status,
    ...(result.error !== undefined ? { error: result.error } : {}),
    outputs: result.outputs,
    ...(result.data !== undefined ? { data: result.data } : {}),
  };
}

function now(): string {
  return new Date().toISOString();
}

class RecordedStageFailure extends Error {}
