/**
 * StageDefinition — the contract the registry builds a DAG from.
 *
 * A stage is one step in the scan thread: it declares what artifacts it needs
 * and what it produces, plus validators that run on its output. The registry
 * resolves dependencies, detects cycles, runs stages, and marks descendants
 * stale when a stage is rerun.
 */

import type { ArtifactRef, SourceInput, StageId } from "../domain/run.js";
import type { ArtifactStore } from "../ports/artifact-store.js";
import type { EventSink } from "../ports/event-sink.js";
import type { ModelProvider } from "../ports/model-provider.js";
import type { SandboxSession } from "../ports/sandbox-runtime.js";
import type { StateStore } from "../ports/state-store.js";

/** Outcome of one stage execution. */
export interface StageResult {
  readonly status: "failed" | "success";
  readonly error?: string;
  /** Output artifact refs produced by this run of the stage. */
  readonly outputs: ReadonlyArray<ArtifactRef>;
  /**
   * Arbitrary JSON the stage wants persisted alongside its attempt. The runner
   * hands it back to downstream stages as input.
   */
  readonly data?: Readonly<Record<string, unknown>>;
}

/**
 * Context handed to a stage's run function. Inputs are the committed data from
 * completed dependencies, keyed by stage id.
 */
export interface StageContext {
  readonly runId: string;
  readonly runDir: string;
  readonly source: SourceInput;
  readonly toolchainImageTag: string;
  readonly inputs: ReadonlyMap<StageId, Readonly<Record<string, unknown>>>;
  readonly session: SandboxSession;
  readonly state: StateStore;
  readonly artifacts: ArtifactStore;
  readonly events: EventSink;
  readonly model: ModelProvider;
}

export type StageRun = (ctx: StageContext) => Promise<StageResult>;

/** Validator that runs on a stage's committed output. Throws on violation. */
export type StageValidator = (result: StageResult, ctx: StageContext) => void | Promise<void>;

export interface StageDefinition {
  readonly id: StageId;
  /** Schema/version of this stage's logic; bumps invalidate cached attempts. */
  readonly version: string;
  readonly dependencies: ReadonlyArray<StageId>;
  /** Artifact roles this stage consumes (declared, used for planning). */
  readonly inputs: ReadonlyArray<string>;
  /** Artifact roles this stage produces. */
  readonly outputs: ReadonlyArray<string>;
  readonly run: StageRun;
  readonly validators?: ReadonlyArray<StageValidator>;
  readonly timeoutMs?: number;
  /** Whether a failure blocks the run (degrades vs. fails the verdict). */
  readonly required: boolean;
  /** Cache key inputs; changing them invalidates prior attempts. */
  readonly cacheKey?: ReadonlyArray<string>;
}
