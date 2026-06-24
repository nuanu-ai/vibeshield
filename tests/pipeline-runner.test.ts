import { describe, expect, it } from "vitest";
import type { DeepCoverage } from "../src/domain/deep-coverage.js";
import type { ArtifactRef, Run, RunId, StageAttempt, StageId } from "../src/domain/run.js";
import type {
  SecurityGraph,
  SecurityGraphValidationContext,
} from "../src/domain/security-graph.js";
import { runStages } from "../src/pipeline/runner.js";
import type { StageDefinition } from "../src/pipeline/stage-definition.js";
import type { StoredBlob } from "../src/ports/artifact-store.js";
import type { ScanEvent } from "../src/ports/event-sink.js";
import type {
  ModelEnhanceBatchInput,
  ModelHypothesisEnrichBatchInput,
  ModelHypothesisEnrichment,
} from "../src/ports/model-provider.js";
import type { ExecResult } from "../src/ports/sandbox-runtime.js";

describe("runStages", () => {
  it("records a failed attempt when a required stage times out", async () => {
    const state = new MemoryStateStore();
    await state.createRun({
      id: "run-1",
      source: { kind: "local", path: "/tmp/repo" },
      createdAt: "2026-01-01T00:00:00.000Z",
      status: "running",
      attempts: new Map(),
      staleStages: new Set(),
    });
    const events = new CollectingEvents();
    const stage: StageDefinition = {
      id: "scan.hangs",
      version: "1",
      dependencies: [],
      inputs: [],
      outputs: [],
      required: true,
      timeoutMs: 1,
      run: async () => await new Promise<never>(() => {}),
    };

    await expect(
      runStages({
        runId: "run-1",
        runDir: "/tmp/vibeshield-run",
        source: { kind: "local", path: "/tmp/repo" },
        toolchainImageTag: "test-toolchain:latest",
        stages: [stage],
        session: new NoopSession(),
        state,
        artifacts: new MemoryArtifacts(),
        events,
        model: new NoopModel(),
      }),
    ).rejects.toThrow("Stage scan.hangs timed out after 1ms");

    const run = await state.loadRun("run-1");
    expect(run?.attempts.get("scan.hangs")).toMatchObject({
      stageId: "scan.hangs",
      status: "failed",
      error: "Stage scan.hangs timed out after 1ms",
    });
    expect(events.events.find((event) => event.type === "stage-failed")).toMatchObject({
      type: "stage-failed",
      stageId: "scan.hangs",
      message: "Stage scan.hangs timed out after 1ms",
    });
  });
});

class MemoryStateStore {
  private readonly runs = new Map<RunId, Run>();

  async createRun(run: Run): Promise<void> {
    this.runs.set(run.id, run);
  }

  async loadRun(id: RunId): Promise<Run | null> {
    return this.runs.get(id) ?? null;
  }

  async recordAttempt(runId: RunId, attempt: StageAttempt): Promise<void> {
    const run = this.runs.get(runId);
    if (run === undefined) {
      throw new Error(`missing run ${runId}`);
    }
    const attempts = new Map(run.attempts);
    attempts.set(attempt.stageId, attempt);
    this.runs.set(runId, { ...run, attempts });
  }

  async markStale(runId: RunId, stageIds: ReadonlyArray<StageId>): Promise<void> {
    const run = this.runs.get(runId);
    if (run === undefined) {
      throw new Error(`missing run ${runId}`);
    }
    this.runs.set(runId, { ...run, staleStages: new Set([...run.staleStages, ...stageIds]) });
  }

  async recordArtifacts(_runId: RunId, _artifacts: ReadonlyArray<ArtifactRef>): Promise<void> {}

  async recordSecurityGraph(
    _graph: SecurityGraph,
    _validationContext: SecurityGraphValidationContext,
  ): Promise<void> {}

  async loadSecurityGraph(_runId: RunId, _graphId: string): Promise<SecurityGraph | null> {
    return null;
  }

  async recordDeepCoverage(_coverage: DeepCoverage): Promise<void> {}

  async loadDeepCoverage(_runId: RunId): Promise<DeepCoverage | null> {
    return null;
  }

  async finishRun(id: RunId, status: Run["status"], finishedAt: string): Promise<void> {
    const run = this.runs.get(id);
    if (run === undefined) {
      throw new Error(`missing run ${id}`);
    }
    this.runs.set(id, { ...run, status, finishedAt });
  }
}

class MemoryArtifacts {
  private readonly blobs = new Map<string, Uint8Array>();

  async store(data: Uint8Array): Promise<StoredBlob> {
    const sha256 = `blob-${this.blobs.size + 1}`;
    this.blobs.set(sha256, data);
    return { sha256, bytes: data.byteLength };
  }

  async read(sha256: string): Promise<Uint8Array> {
    const blob = this.blobs.get(sha256);
    if (blob === undefined) {
      throw new Error(`missing blob ${sha256}`);
    }
    return blob;
  }

  async exists(sha256: string): Promise<boolean> {
    return this.blobs.has(sha256);
  }
}

class CollectingEvents {
  readonly events: ScanEvent[] = [];

  emit(event: ScanEvent): void {
    this.events.push(event);
  }
}

class NoopModel {
  async isAvailable(): Promise<boolean> {
    return false;
  }

  async enhance(_input: ModelEnhanceBatchInput): Promise<null> {
    return null;
  }

  async enrichHypotheses(
    _input: ModelHypothesisEnrichBatchInput,
  ): Promise<ReadonlyArray<ModelHypothesisEnrichment> | null> {
    return null;
  }
}

class NoopSession {
  readonly id = "noop";

  async exec(_command: string[]): Promise<ExecResult> {
    return { exitCode: 0, stdout: "", stderr: "" };
  }

  async upload(_localPath: string, _guestPath: string): Promise<void> {}

  async uploadBytes(_guestPath: string, _data: Uint8Array): Promise<void> {}

  async download(_guestPath: string): Promise<Uint8Array> {
    return new Uint8Array();
  }

  async read(_guestPath: string): Promise<Uint8Array> {
    return new Uint8Array();
  }

  async destroy(): Promise<void> {}
}
