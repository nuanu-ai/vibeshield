import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteStateStore } from "../src/adapters/sqlite-state-store.js";
import type { DeepCoverage } from "../src/domain/deep-coverage.js";
import type { Run, StageAttempt } from "../src/domain/run.js";
import {
  type SecurityGraph,
  securityFlowId,
  securityGraphEdgeId,
  securityGraphId,
  securityGraphNodeId,
  sortSecurityGraph,
} from "../src/domain/security-graph.js";

describe("SqliteStateStore", () => {
  let dir: string;
  let db: DatabaseSync;
  let store: SqliteStateStore;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), "vsstate-"));
    db = new DatabaseSync(path.join(dir, "state.sqlite"));
    store = new SqliteStateStore(db);
  });

  afterEach(async () => {
    db.close();
    await rm(dir, { recursive: true, force: true });
  });

  function makeRun(): Run {
    return {
      id: "run-1",
      source: { kind: "github", url: "https://github.com/o/r" },
      createdAt: "2026-01-01T00:00:00Z",
      status: "running",
      attempts: new Map(),
      staleStages: new Set(),
    };
  }

  function makeAttempt(over: Partial<StageAttempt> = {}): StageAttempt {
    return {
      attempt: 1,
      stageId: "secrets",
      stageVersion: "1",
      startedAt: "2026-01-01T00:00:01Z",
      finishedAt: "2026-01-01T00:00:02Z",
      status: "success",
      outputs: [],
      ...over,
    };
  }

  it("persists and reloads a run with its source", async () => {
    await store.createRun(makeRun());
    const loaded = await store.loadRun("run-1");
    expect(loaded?.id).toBe("run-1");
    expect(loaded?.source).toEqual({ kind: "github", url: "https://github.com/o/r" });
    expect(loaded?.status).toBe("running");
  });

  it("returns null for an unknown run", async () => {
    expect(await store.loadRun("nope")).toBeNull();
  });

  it("records an attempt and projects the latest one back", async () => {
    await store.createRun(makeRun());
    await store.recordAttempt(
      "run-1",
      makeAttempt({ attempt: 1, status: "failed", error: "boom" }),
    );
    await store.recordAttempt("run-1", makeAttempt({ attempt: 2, status: "success" }));
    const loaded = await store.loadRun("run-1");
    const latest = loaded?.attempts.get("secrets");
    expect(latest?.attempt).toBe(2);
    expect(latest?.status).toBe("success");
    expect(latest?.error).toBeUndefined();
  });

  it("keeps history: rerun adds an attempt, never overwrites", async () => {
    await store.createRun(makeRun());
    await store.recordAttempt("run-1", makeAttempt({ attempt: 1 }));
    await store.recordAttempt("run-1", makeAttempt({ attempt: 2 }));
    const rows = db.prepare("SELECT attempt FROM stage_attempts WHERE run_id = ?").all("run-1") as {
      attempt: number;
    }[];
    expect(rows.map((r) => r.attempt).sort()).toEqual([1, 2]);
  });

  it("marks stages stale and surfaces them in the stale set", async () => {
    await store.createRun(makeRun());
    await store.markStale("run-1", ["report", "actions"]);
    const loaded = await store.loadRun("run-1");
    expect(loaded?.staleStages.has("report")).toBe(true);
    expect(loaded?.staleStages.has("actions")).toBe(true);
  });

  it("records artifact refs without duplicating", async () => {
    await store.createRun(makeRun());
    const art = { blobSha256: "abc", role: "scanner.raw" as const, bytes: 10 };
    await store.recordArtifacts("run-1", [art, art]);
    expect(await store.loadRun("run-1")).toBeTruthy();
  });

  it("finishes a run with terminal status and timestamp", async () => {
    await store.createRun(makeRun());
    await store.finishRun("run-1", "success", "2026-01-01T00:10:00Z");
    const loaded = await store.loadRun("run-1");
    expect(loaded?.status).toBe("success");
    expect(loaded?.finishedAt).toBe("2026-01-01T00:10:00Z");
  });

  it("creates graph projection tables during migration", () => {
    const rows = db
      .prepare(
        `SELECT name FROM sqlite_master
         WHERE type = 'table'
           AND name IN ('security_graphs', 'graph_nodes', 'graph_edges', 'graph_flows', 'graph_coverage', 'deep_coverage')
         ORDER BY name`,
      )
      .all() as { name: string }[];

    expect(rows.map((row) => row.name)).toEqual([
      "deep_coverage",
      "graph_coverage",
      "graph_edges",
      "graph_flows",
      "graph_nodes",
      "security_graphs",
    ]);
  });

  it("persists and reloads a security graph projection", async () => {
    await store.createRun(makeRun());
    const graph = makeSecurityGraph();

    await store.recordSecurityGraph(graph, graphValidationContext());

    await expect(store.loadSecurityGraph("run-1", graph.id)).resolves.toEqual(
      sortSecurityGraph(graph),
    );
  });

  it("replaces an existing security graph projection without stale rows", async () => {
    await store.createRun(makeRun());
    const graph = makeSecurityGraph();
    const replacement = makeSecurityGraph({
      coverage: [
        {
          area: "boundaries",
          state: "partial",
          coveredCount: 1,
          totalCount: 2,
          reason: "one route parser failed",
          producer: "test-fixture",
          producerVersion: "2",
        },
      ],
    });

    await store.recordSecurityGraph(graph, graphValidationContext());
    await store.recordSecurityGraph(replacement, graphValidationContext());

    await expect(store.loadSecurityGraph("run-1", graph.id)).resolves.toEqual(
      sortSecurityGraph(replacement),
    );
    expect(db.prepare("SELECT COUNT(*) AS count FROM graph_coverage").get()).toEqual({
      count: 1,
    });
  });

  it("rejects invalid security graphs before persistence", async () => {
    await store.createRun(makeRun());
    const graph = makeSecurityGraph({
      nodes: [{ ...boundaryNode(), evidenceIds: ["missing-ev"] }, sinkNode()],
    });

    await expect(store.recordSecurityGraph(graph, graphValidationContext())).rejects.toThrow(
      /missing evidence id: missing-ev/,
    );

    const rows = db.prepare("SELECT id FROM security_graphs").all();
    expect(rows).toEqual([]);
  });

  it("persists and reloads deepCoverage for a run", async () => {
    await store.createRun(makeRun());
    const coverage = makeDeepCoverage();

    await store.recordDeepCoverage(coverage);

    await expect(store.loadDeepCoverage("run-1")).resolves.toEqual(coverage);
  });

  it("replaces deepCoverage rows for the same run deterministically", async () => {
    await store.createRun(makeRun());
    await store.recordDeepCoverage(makeDeepCoverage());
    const replacement = makeDeepCoverage({
      entries: [
        {
          area: "model",
          state: "failed",
          reason: "Atom process exited 137",
          producer: "atom",
          producerVersion: "atom@2.5.6",
        },
      ],
    });

    await store.recordDeepCoverage(replacement);

    await expect(store.loadDeepCoverage("run-1")).resolves.toEqual(replacement);
    expect(db.prepare("SELECT COUNT(*) AS count FROM deep_coverage").get()).toEqual({
      count: 1,
    });
  });
});

function graphValidationContext() {
  return {
    manifestPaths: new Set(["src/routes/upload.ts", "src/lib/fetch.ts"]),
    evidenceIds: new Set(["ev-route", "ev-sink"]),
  };
}

function makeSecurityGraph(overrides: Partial<SecurityGraph> = {}): SecurityGraph {
  return {
    id: securityGraphId("snapshot-1", "1"),
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: "1",
    nodes: [boundaryNode(), sinkNode()],
    edges: [callEdge()],
    flows: [flow()],
    coverage: [
      {
        area: "boundaries",
        state: "checked",
        coveredCount: 1,
        totalCount: 1,
        producer: "test-fixture",
        producerVersion: "1",
      },
    ],
    createdAt: "2026-06-24T09:00:00Z",
    ...overrides,
  };
}

function makeDeepCoverage(overrides: Partial<DeepCoverage> = {}): DeepCoverage {
  return {
    runId: "run-1",
    snapshotId: "snapshot-1",
    createdAt: "2026-06-24T10:00:00Z",
    entries: [
      {
        area: "boundaries",
        state: "checked",
        coveredCount: 1,
        totalCount: 1,
        producer: "atom",
        producerVersion: "atom@2.5.6",
      },
    ],
    ...overrides,
  };
}

function boundaryNode() {
  const stableKey = "Boundary:http:POST /upload:src/routes/upload.ts:10:uploadHandler";
  return {
    id: securityGraphNodeId("1", stableKey),
    kind: "Boundary" as const,
    stableKey,
    label: "POST /upload",
    repoPath: "src/routes/upload.ts",
    lineRange: { startLine: 10, endLine: 12 },
    symbol: "uploadHandler",
    properties: { boundaryType: "HTTP route", method: "POST" },
    evidenceIds: ["ev-route"],
    producer: "test-fixture",
    producerVersion: "1",
    confidence: 1,
    coverageState: "checked" as const,
  };
}

function sinkNode() {
  const stableKey = "Sink:http-client:src/lib/fetch.ts:4:fetchUrl";
  return {
    id: securityGraphNodeId("1", stableKey),
    kind: "Sink" as const,
    stableKey,
    label: "fetchUrl",
    repoPath: "src/lib/fetch.ts",
    lineRange: { startLine: 4, endLine: 4 },
    symbol: "fetchUrl",
    properties: { sinkType: "outbound_http" },
    evidenceIds: ["ev-sink"],
    producer: "test-fixture",
    producerVersion: "1",
    confidence: 0.95,
    coverageState: "checked" as const,
  };
}

function callEdge() {
  const stableKey = `calls:${boundaryNode().id}:${sinkNode().id}:src/routes/upload.ts:12`;
  return {
    id: securityGraphEdgeId("1", stableKey),
    kind: "calls" as const,
    stableKey,
    fromNodeId: boundaryNode().id,
    toNodeId: sinkNode().id,
    properties: { callsite: "src/routes/upload.ts:12" },
    evidenceIds: ["ev-route"],
    producer: "test-fixture",
    producerVersion: "1",
    confidence: 0.9,
    coverageState: "checked" as const,
  };
}

function flow() {
  const stableKey = `flow:${boundaryNode().id}:${sinkNode().id}:${callEdge().id}`;
  return {
    id: securityFlowId("1", stableKey),
    sourceNodeId: boundaryNode().id,
    sinkNodeId: sinkNode().id,
    pathEdgeIds: [callEdge().id],
    controlNodeIds: [],
    coverageState: "checked" as const,
    confidence: 0.9,
    evidenceIds: ["ev-route", "ev-sink"],
  };
}
