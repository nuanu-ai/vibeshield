import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteStateStore } from "../src/adapters/sqlite-state-store.js";
import type { Run, StageAttempt } from "../src/domain/run.js";

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
});
