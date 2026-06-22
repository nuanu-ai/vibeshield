/**
 * ScanService — the application entry point for `vibeshield scan`.
 *
 * Wires ports together, hands the scan thread to the stage runner, and returns
 * the terminal SecurityAssessment. Has no knowledge of how sandboxes boot,
 * how state is stored, or how reports render.
 */

import type { SourceInput } from "../domain/run.js";
import type { SecurityAssessment } from "../domain/security-assessment.js";
import type { ArtifactStore } from "../ports/artifact-store.js";
import type { EventSink } from "../ports/event-sink.js";
import type { ModelProvider } from "../ports/model-provider.js";
import type { SandboxRuntime } from "../ports/sandbox-runtime.js";
import type { StateStore } from "../ports/state-store.js";

export interface ScanDeps {
  readonly sandbox: SandboxRuntime;
  readonly state: StateStore;
  readonly artifacts: ArtifactStore;
  readonly events: EventSink;
  readonly model: ModelProvider;
}

export interface ScanRequest {
  readonly source: SourceInput;
}

export interface ScanOutcome {
  readonly assessment: SecurityAssessment;
  readonly runId: string;
}

/**
 * Run a full scan end to end. The actual stage execution lives in the pipeline
 * runner; this is the composition root. Stub until the runner lands.
 */
export async function runScan(_deps: ScanDeps, _request: ScanRequest): Promise<ScanOutcome> {
  throw new Error("runScan: not implemented yet (stage runner pending)");
}
