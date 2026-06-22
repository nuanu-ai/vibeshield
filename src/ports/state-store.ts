/**
 * StateStore port — the authoritative source of truth for run state.
 *
 * Production adapter is SQLite. State is rebuilt from here, never from files
 * on disk. Reruns add a new attempt; old attempts are kept.
 */

import type { ArtifactRef, Run, RunId, StageAttempt, StageId } from "../domain/run.js";

export interface StateStore {
  /** Create a run row. */
  createRun(run: Run): Promise<void>;
  /** Load a run with its latest attempts and stale set. */
  loadRun(id: RunId): Promise<Run | null>;
  /** Record a stage attempt (success or failure). Adds to history, never overwrites. */
  recordAttempt(runId: RunId, attempt: StageAttempt): Promise<void>;
  /** Mark these stages stale in a run (a dependency reran). */
  markStale(runId: RunId, stageIds: ReadonlyArray<StageId>): Promise<void>;
  /** Persist artifact refs known to a run. */
  recordArtifacts(runId: RunId, artifacts: ReadonlyArray<ArtifactRef>): Promise<void>;
  /** Set terminal run status + finishedAt. */
  finishRun(id: RunId, status: Run["status"], finishedAt: string): Promise<void>;
}
