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
import {
  type GraphCoverage,
  type GraphCoverageArea,
  type GraphCoverageState,
  type LineRange,
  type SecurityFlow,
  type SecurityGraph,
  type SecurityGraphEdge,
  type SecurityGraphEdgeKind,
  type SecurityGraphNode,
  type SecurityGraphNodeKind,
  type SecurityGraphValidationContext,
  sortSecurityGraph,
  validateSecurityGraph,
} from "../domain/security-graph.js";
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

interface GraphRow {
  id: string;
  run_id: string;
  snapshot_id: string;
  graph_version: string;
  created_at: string;
}

interface GraphNodeRow {
  id: string;
  kind: string;
  stable_key: string;
  label: string;
  repo_path: string | null;
  line_start: number | null;
  line_end: number | null;
  symbol: string | null;
  properties_json: string;
  evidence_ids_json: string;
  producer: string;
  producer_version: string;
  confidence: number;
  coverage_state: string;
}

interface GraphEdgeRow {
  id: string;
  kind: string;
  stable_key: string;
  from_node_id: string;
  to_node_id: string;
  properties_json: string;
  evidence_ids_json: string;
  producer: string;
  producer_version: string;
  confidence: number;
  coverage_state: string;
}

interface GraphFlowRow {
  id: string;
  source_node_id: string;
  sink_node_id: string;
  path_edge_ids_json: string;
  control_node_ids_json: string;
  coverage_state: string;
  confidence: number;
  evidence_ids_json: string;
}

interface GraphCoverageRow {
  area: string;
  state: string;
  covered_count: number | null;
  total_count: number | null;
  reason: string | null;
  producer: string;
  producer_version: string;
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

  async recordSecurityGraph(
    graph: SecurityGraph,
    validationContext: SecurityGraphValidationContext,
  ): Promise<void> {
    const normalized = validateSecurityGraph(graph, validationContext);
    if (normalized.runId !== graph.runId) {
      throw new Error(`security graph runId mismatch: ${normalized.runId}`);
    }
    this.db.exec("BEGIN");
    try {
      this.deleteSecurityGraphRows(normalized.id);
      this.db
        .prepare(
          `INSERT INTO security_graphs (id, run_id, snapshot_id, graph_version, created_at)
           VALUES (?, ?, ?, ?, ?)`,
        )
        .run(
          normalized.id,
          normalized.runId,
          normalized.snapshotId,
          normalized.graphVersion,
          normalized.createdAt,
        );
      this.insertGraphNodes(normalized.id, normalized.nodes);
      this.insertGraphEdges(normalized.id, normalized.edges);
      this.insertGraphFlows(normalized.id, normalized.flows);
      this.insertGraphCoverage(normalized.id, normalized.coverage);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  async loadSecurityGraph(runId: RunId, graphId: string): Promise<SecurityGraph | null> {
    const graphRow = this.db
      .prepare("SELECT * FROM security_graphs WHERE run_id = ? AND id = ?")
      .get(runId, graphId) as GraphRow | undefined;
    if (graphRow === undefined) {
      return null;
    }
    return sortSecurityGraph({
      id: graphRow.id,
      runId: graphRow.run_id,
      snapshotId: graphRow.snapshot_id,
      graphVersion: graphRow.graph_version,
      nodes: this.loadGraphNodes(graphId),
      edges: this.loadGraphEdges(graphId),
      flows: this.loadGraphFlows(graphId),
      coverage: this.loadGraphCoverage(graphId),
      createdAt: graphRow.created_at,
    });
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

  private deleteSecurityGraphRows(graphId: string): void {
    this.db.prepare("DELETE FROM graph_coverage WHERE graph_id = ?").run(graphId);
    this.db.prepare("DELETE FROM graph_flows WHERE graph_id = ?").run(graphId);
    this.db.prepare("DELETE FROM graph_edges WHERE graph_id = ?").run(graphId);
    this.db.prepare("DELETE FROM graph_nodes WHERE graph_id = ?").run(graphId);
    this.db.prepare("DELETE FROM security_graphs WHERE id = ?").run(graphId);
  }

  private insertGraphNodes(graphId: string, nodes: ReadonlyArray<SecurityGraphNode>): void {
    const stmt = this.db.prepare(
      `INSERT INTO graph_nodes
       (graph_id, id, kind, stable_key, label, repo_path, line_start, line_end, symbol,
        properties_json, evidence_ids_json, producer, producer_version, confidence, coverage_state)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const node of nodes) {
      stmt.run(
        graphId,
        node.id,
        node.kind,
        node.stableKey,
        node.label,
        node.repoPath ?? null,
        node.lineRange?.startLine ?? null,
        node.lineRange?.endLine ?? null,
        node.symbol ?? null,
        JSON.stringify(node.properties),
        JSON.stringify(node.evidenceIds),
        node.producer,
        node.producerVersion,
        node.confidence,
        node.coverageState,
      );
    }
  }

  private insertGraphEdges(graphId: string, edges: ReadonlyArray<SecurityGraphEdge>): void {
    const stmt = this.db.prepare(
      `INSERT INTO graph_edges
       (graph_id, id, kind, stable_key, from_node_id, to_node_id, properties_json,
        evidence_ids_json, producer, producer_version, confidence, coverage_state)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const edge of edges) {
      stmt.run(
        graphId,
        edge.id,
        edge.kind,
        edge.stableKey,
        edge.fromNodeId,
        edge.toNodeId,
        JSON.stringify(edge.properties),
        JSON.stringify(edge.evidenceIds),
        edge.producer,
        edge.producerVersion,
        edge.confidence,
        edge.coverageState,
      );
    }
  }

  private insertGraphFlows(graphId: string, flows: ReadonlyArray<SecurityFlow>): void {
    const stmt = this.db.prepare(
      `INSERT INTO graph_flows
       (graph_id, id, source_node_id, sink_node_id, path_edge_ids_json,
        control_node_ids_json, coverage_state, confidence, evidence_ids_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const flow of flows) {
      stmt.run(
        graphId,
        flow.id,
        flow.sourceNodeId,
        flow.sinkNodeId,
        JSON.stringify(flow.pathEdgeIds),
        JSON.stringify(flow.controlNodeIds),
        flow.coverageState,
        flow.confidence,
        JSON.stringify(flow.evidenceIds),
      );
    }
  }

  private insertGraphCoverage(graphId: string, coverage: ReadonlyArray<GraphCoverage>): void {
    const stmt = this.db.prepare(
      `INSERT INTO graph_coverage
       (graph_id, area, state, covered_count, total_count, reason, producer, producer_version)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const entry of coverage) {
      stmt.run(
        graphId,
        entry.area,
        entry.state,
        entry.coveredCount ?? null,
        entry.totalCount ?? null,
        entry.reason ?? null,
        entry.producer,
        entry.producerVersion,
      );
    }
  }

  private loadGraphNodes(graphId: string): SecurityGraphNode[] {
    const rows = this.db
      .prepare("SELECT * FROM graph_nodes WHERE graph_id = ? ORDER BY id")
      .all(graphId) as unknown as GraphNodeRow[];
    return rows.map((row) => {
      const lineRange = lineRangeFrom(row.line_start, row.line_end);
      return {
        id: row.id,
        kind: row.kind as SecurityGraphNodeKind,
        stableKey: row.stable_key,
        label: row.label,
        ...(row.repo_path !== null ? { repoPath: row.repo_path } : {}),
        ...(lineRange !== undefined ? { lineRange } : {}),
        ...(row.symbol !== null ? { symbol: row.symbol } : {}),
        properties: JSON.parse(row.properties_json) as Record<string, unknown>,
        evidenceIds: JSON.parse(row.evidence_ids_json) as string[],
        producer: row.producer,
        producerVersion: row.producer_version,
        confidence: row.confidence,
        coverageState: row.coverage_state as GraphCoverageState,
      };
    });
  }

  private loadGraphEdges(graphId: string): SecurityGraphEdge[] {
    const rows = this.db
      .prepare("SELECT * FROM graph_edges WHERE graph_id = ? ORDER BY id")
      .all(graphId) as unknown as GraphEdgeRow[];
    return rows.map((row) => ({
      id: row.id,
      kind: row.kind as SecurityGraphEdgeKind,
      stableKey: row.stable_key,
      fromNodeId: row.from_node_id,
      toNodeId: row.to_node_id,
      properties: JSON.parse(row.properties_json) as Record<string, unknown>,
      evidenceIds: JSON.parse(row.evidence_ids_json) as string[],
      producer: row.producer,
      producerVersion: row.producer_version,
      confidence: row.confidence,
      coverageState: row.coverage_state as GraphCoverageState,
    }));
  }

  private loadGraphFlows(graphId: string): SecurityFlow[] {
    const rows = this.db
      .prepare("SELECT * FROM graph_flows WHERE graph_id = ? ORDER BY id")
      .all(graphId) as unknown as GraphFlowRow[];
    return rows.map((row) => ({
      id: row.id,
      sourceNodeId: row.source_node_id,
      sinkNodeId: row.sink_node_id,
      pathEdgeIds: JSON.parse(row.path_edge_ids_json) as string[],
      controlNodeIds: JSON.parse(row.control_node_ids_json) as string[],
      coverageState: row.coverage_state as GraphCoverageState,
      confidence: row.confidence,
      evidenceIds: JSON.parse(row.evidence_ids_json) as string[],
    }));
  }

  private loadGraphCoverage(graphId: string): GraphCoverage[] {
    const rows = this.db
      .prepare("SELECT * FROM graph_coverage WHERE graph_id = ? ORDER BY area, producer")
      .all(graphId) as unknown as GraphCoverageRow[];
    return rows.map((row) => ({
      area: row.area as GraphCoverageArea,
      state: row.state as GraphCoverageState,
      ...(row.covered_count !== null ? { coveredCount: row.covered_count } : {}),
      ...(row.total_count !== null ? { totalCount: row.total_count } : {}),
      ...(row.reason !== null ? { reason: row.reason } : {}),
      producer: row.producer,
      producerVersion: row.producer_version,
    }));
  }
}

function lineRangeFrom(startLine: number | null, endLine: number | null): LineRange | undefined {
  if (startLine === null && endLine === null) {
    return undefined;
  }
  if (startLine === null || endLine === null) {
    throw new Error("graph node line range is partially persisted");
  }
  return { startLine, endLine };
}
