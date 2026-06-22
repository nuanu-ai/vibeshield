/**
 * SQLite schema for the state store. One source of truth for run state.
 *
 * Tables:
 *   runs             — one row per scan run
 *   stage_attempts   — append-only history; reruns add a new attempt
 *   artifacts        — artifact refs known to a run
 *   stale_stages     — stages invalidated by a dependency rerun
 *
 * Versioned via the user_version pragma. Bump + add migration steps when the
 * shape changes. The runner never reads run state off disk; it loads it here.
 */
import type { DatabaseSync } from "node:sqlite";

const SCHEMA_VERSION = 1;

export function migrate(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS runs (
      id            TEXT PRIMARY KEY,
      source_json   TEXT NOT NULL,
      created_at    TEXT NOT NULL,
      finished_at   TEXT,
      status        TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS stage_attempts (
      run_id        TEXT NOT NULL,
      stage_id      TEXT NOT NULL,
      attempt       INTEGER NOT NULL,
      stage_version TEXT NOT NULL,
      started_at    TEXT NOT NULL,
      finished_at   TEXT NOT NULL,
      status        TEXT NOT NULL,
      error         TEXT,
      outputs_json  TEXT NOT NULL,
      data_json     TEXT,
      marked_stale_json TEXT,
      PRIMARY KEY (run_id, stage_id, attempt),
      FOREIGN KEY (run_id) REFERENCES runs(id)
    );

    CREATE INDEX IF NOT EXISTS idx_attempts_stage
      ON stage_attempts (run_id, stage_id);

    CREATE TABLE IF NOT EXISTS artifacts (
      run_id        TEXT NOT NULL,
      blob_sha256   TEXT NOT NULL,
      role          TEXT NOT NULL,
      bytes         INTEGER NOT NULL,
      PRIMARY KEY (run_id, blob_sha256, role),
      FOREIGN KEY (run_id) REFERENCES runs(id)
    );

    CREATE TABLE IF NOT EXISTS stale_stages (
      run_id        TEXT NOT NULL,
      stage_id      TEXT NOT NULL,
      PRIMARY KEY (run_id, stage_id),
      FOREIGN KEY (run_id) REFERENCES runs(id)
    );
  `);
  db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
}
