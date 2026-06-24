/**
 * StateStore port — the authoritative source of truth for run state.
 *
 * Production adapter is SQLite. State is rebuilt from here, never from files
 * on disk. Reruns add a new attempt; old attempts are kept.
 */

import type { DeepCoverage } from "../domain/deep-coverage.js";
import type { ArtifactRef, Run, RunId, StageAttempt, StageId } from "../domain/run.js";
import type { SecurityGraph, SecurityGraphValidationContext } from "../domain/security-graph.js";

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
  /** Persist the deterministic Deep Static graph projection for a run. */
  recordSecurityGraph(
    graph: SecurityGraph,
    validationContext: SecurityGraphValidationContext,
  ): Promise<void>;
  /** Load a persisted Deep Static graph projection. */
  loadSecurityGraph(runId: RunId, graphId: string): Promise<SecurityGraph | null>;
  /** Persist Deep Static coverage truth for a run. */
  recordDeepCoverage(coverage: DeepCoverage): Promise<void>;
  /** Load persisted Deep Static coverage truth for a run. */
  loadDeepCoverage(runId: RunId): Promise<DeepCoverage | null>;
  /** Set terminal run status + finishedAt. */
  finishRun(id: RunId, status: Run["status"], finishedAt: string): Promise<void>;
}
