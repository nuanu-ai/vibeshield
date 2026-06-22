/**
 * SqliteStateStore — StateStore over a single state.sqlite file.
 *
 * Idempotent migrate on open. Reruns append a new attempt row (never
 * overwrite); loadRun projects the latest attempt per stage plus the stale set
 * back into the Run domain object. State is rebuilt from here, not from files.
 */

import type { DatabaseSync } from "node:sqlite";
import type {
  ArtifactRef,
  Run,
  RunId,
  RunStatus,
  SourceInput,
  StageAttempt,
  StageAttemptStatus,
  StageId,
} from "../domain/run.js";
import type { StateStore } from "../ports/state-store.js";
import { migrate } from "./sqlite-schema.js";

interface AttemptRow {
  stage_id: string;
  attempt: number;
  stage_version: string;
  started_at: string;
  finished_at: string;
  status: string;
  error: string | null;
  outputs_json: string;
  data_json: string | null;
  marked_stale_json: string | null;
}

export class SqliteStateStore implements StateStore {
  constructor(private readonly db: DatabaseSync) {
    migrate(db);
  }

  async createRun(run: Run): Promise<void> {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO runs (id, source_json, created_at, finished_at, status) VALUES (?, ?, ?, ?, ?)",
      )
      .run(run.id, JSON.stringify(run.source), run.createdAt, run.finishedAt ?? null, run.status);
  }

  async loadRun(id: RunId): Promise<Run | null> {
    const runRow = this.db.prepare("SELECT * FROM runs WHERE id = ?").get(id) as
      | { source_json: string; created_at: string; finished_at: string | null; status: string }
      | undefined;
    if (runRow === undefined) {
      return null;
    }
    const attempts = this.loadLatestAttempts(id);
    const staleStages = this.loadStale(id);
    const finishedAt = runRow.finished_at ?? undefined;
    return {
      id,
      source: JSON.parse(runRow.source_json) as SourceInput,
      createdAt: runRow.created_at,
      ...(finishedAt !== undefined ? { finishedAt } : {}),
      status: runRow.status as RunStatus,
      attempts,
      staleStages,
    };
  }

  async recordAttempt(runId: RunId, attempt: StageAttempt): Promise<void> {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO stage_attempts
         (run_id, stage_id, attempt, stage_version, started_at, finished_at, status, error, outputs_json, data_json, marked_stale_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        runId,
        attempt.stageId,
        attempt.attempt,
        attempt.stageVersion,
        attempt.startedAt,
        attempt.finishedAt,
        attempt.status,
        attempt.error ?? null,
        JSON.stringify(attempt.outputs),
        attempt.data ? JSON.stringify(attempt.data) : null,
        attempt.markedStale ? JSON.stringify(attempt.markedStale) : null,
      );
  }

  async markStale(runId: RunId, stageIds: ReadonlyArray<StageId>): Promise<void> {
    const stmt = this.db.prepare(
      "INSERT OR IGNORE INTO stale_stages (run_id, stage_id) VALUES (?, ?)",
    );
    for (const stageId of stageIds) {
      stmt.run(runId, stageId);
    }
  }

  async recordArtifacts(runId: RunId, artifacts: ReadonlyArray<ArtifactRef>): Promise<void> {
    const stmt = this.db.prepare(
      `INSERT OR IGNORE INTO artifacts (run_id, blob_sha256, role, bytes) VALUES (?, ?, ?, ?)`,
    );
    for (const a of artifacts) {
      stmt.run(runId, a.blobSha256, a.role, a.bytes);
    }
  }

  async finishRun(id: RunId, status: RunStatus, finishedAt: string): Promise<void> {
    this.db
      .prepare("UPDATE runs SET status = ?, finished_at = ? WHERE id = ?")
      .run(status, finishedAt, id);
  }

  private loadLatestAttempts(runId: RunId): Map<StageId, StageAttempt> {
    const rows = this.db
      .prepare(
        `WITH ranked AS (
           SELECT *, ROW_NUMBER() OVER (PARTITION BY stage_id ORDER BY attempt DESC) AS rn
           FROM stage_attempts WHERE run_id = ?
         )
         SELECT * FROM ranked WHERE rn = 1`,
      )
      .all(runId) as unknown as AttemptRow[];
    const out = new Map<StageId, StageAttempt>();
    for (const row of rows) {
      const data = row.data_json !== null ? JSON.parse(row.data_json) : undefined;
      const error = row.error ?? undefined;
      const markedStale =
        row.marked_stale_json !== null
          ? (JSON.parse(row.marked_stale_json) as StageId[])
          : undefined;
      out.set(row.stage_id, {
        attempt: row.attempt,
        stageId: row.stage_id,
        stageVersion: row.stage_version,
        startedAt: row.started_at,
        finishedAt: row.finished_at,
        status: row.status as StageAttemptStatus,
        outputs: JSON.parse(row.outputs_json) as ArtifactRef[],
        ...(data !== undefined ? { data } : {}),
        ...(error !== undefined ? { error } : {}),
        ...(markedStale !== undefined ? { markedStale } : {}),
      });
    }
    return out;
  }

  private loadStale(runId: RunId): Set<StageId> {
    const rows = this.db
      .prepare("SELECT stage_id FROM stale_stages WHERE run_id = ?")
      .all(runId) as { stage_id: string }[];
    return new Set(rows.map((r) => r.stage_id));
  }
}
