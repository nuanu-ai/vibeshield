/**
 * SQLite schema for the state store. One source of truth for run state.
 *
 * Tables:
 *   runs             — one row per scan run
 *   stage_attempts   — append-only history; reruns add a new attempt
 *   artifacts        — artifact refs known to a run
 *   stale_stages     — stages invalidated by a dependency rerun
 *   security_graphs  — Deep Static graph projection metadata
 *   graph_nodes      — deterministic graph nodes
 *   graph_edges      — deterministic graph edges
 *   graph_flows      — bounded graph paths used for static hypotheses
 *   graph_coverage   — Deep Static coverage by analysis area
 *   deep_coverage    — Run-level Deep Static coverage truth for reports
 *
 * Versioned via the user_version pragma. Bump + add migration steps when the
 * shape changes. The runner never reads run state off disk; it loads it here.
 */
import type { DatabaseSync } from "node:sqlite";

const SCHEMA_VERSION = 3;

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

    CREATE TABLE IF NOT EXISTS security_graphs (
      id            TEXT PRIMARY KEY,
      run_id        TEXT NOT NULL,
      snapshot_id   TEXT NOT NULL,
      graph_version TEXT NOT NULL,
      created_at    TEXT NOT NULL,
      FOREIGN KEY (run_id) REFERENCES runs(id)
    );

    CREATE TABLE IF NOT EXISTS graph_nodes (
      graph_id         TEXT NOT NULL,
      id               TEXT NOT NULL,
      kind             TEXT NOT NULL,
      stable_key       TEXT NOT NULL,
      label            TEXT NOT NULL,
      repo_path        TEXT,
      line_start       INTEGER,
      line_end         INTEGER,
      symbol           TEXT,
      properties_json  TEXT NOT NULL,
      evidence_ids_json TEXT NOT NULL,
      producer         TEXT NOT NULL,
      producer_version TEXT NOT NULL,
      confidence       REAL NOT NULL,
      coverage_state   TEXT NOT NULL,
      PRIMARY KEY (graph_id, id),
      UNIQUE (graph_id, stable_key),
      FOREIGN KEY (graph_id) REFERENCES security_graphs(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS graph_edges (
      graph_id         TEXT NOT NULL,
      id               TEXT NOT NULL,
      kind             TEXT NOT NULL,
      stable_key       TEXT NOT NULL,
      from_node_id     TEXT NOT NULL,
      to_node_id       TEXT NOT NULL,
      properties_json  TEXT NOT NULL,
      evidence_ids_json TEXT NOT NULL,
      producer         TEXT NOT NULL,
      producer_version TEXT NOT NULL,
      confidence       REAL NOT NULL,
      coverage_state   TEXT NOT NULL,
      PRIMARY KEY (graph_id, id),
      UNIQUE (graph_id, stable_key),
      FOREIGN KEY (graph_id) REFERENCES security_graphs(id) ON DELETE CASCADE,
      FOREIGN KEY (graph_id, from_node_id) REFERENCES graph_nodes(graph_id, id),
      FOREIGN KEY (graph_id, to_node_id) REFERENCES graph_nodes(graph_id, id)
    );

    CREATE TABLE IF NOT EXISTS graph_flows (
      graph_id          TEXT NOT NULL,
      id                TEXT NOT NULL,
      source_node_id    TEXT NOT NULL,
      sink_node_id      TEXT NOT NULL,
      path_edge_ids_json TEXT NOT NULL,
      control_node_ids_json TEXT NOT NULL,
      coverage_state    TEXT NOT NULL,
      confidence        REAL NOT NULL,
      evidence_ids_json TEXT NOT NULL,
      PRIMARY KEY (graph_id, id),
      FOREIGN KEY (graph_id) REFERENCES security_graphs(id) ON DELETE CASCADE,
      FOREIGN KEY (graph_id, source_node_id) REFERENCES graph_nodes(graph_id, id),
      FOREIGN KEY (graph_id, sink_node_id) REFERENCES graph_nodes(graph_id, id)
    );

    CREATE TABLE IF NOT EXISTS graph_coverage (
      graph_id         TEXT NOT NULL,
      area             TEXT NOT NULL,
      state            TEXT NOT NULL,
      covered_count    INTEGER,
      total_count      INTEGER,
      reason           TEXT,
      producer         TEXT NOT NULL,
      producer_version TEXT NOT NULL,
      PRIMARY KEY (graph_id, area, producer),
      FOREIGN KEY (graph_id) REFERENCES security_graphs(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS deep_coverage (
      run_id           TEXT NOT NULL,
      snapshot_id      TEXT NOT NULL,
      area             TEXT NOT NULL,
      state            TEXT NOT NULL,
      covered_count    INTEGER,
      total_count      INTEGER,
      reason           TEXT,
      producer         TEXT NOT NULL,
      producer_version TEXT NOT NULL,
      created_at       TEXT NOT NULL,
      PRIMARY KEY (run_id, area, producer),
      FOREIGN KEY (run_id) REFERENCES runs(id)
    );
  `);
  db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
}
