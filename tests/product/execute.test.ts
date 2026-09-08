import { getEventListeners } from "node:events";
import { afterEach, expect, it, vi } from "vitest";
import { createExecutor } from "../../src/scan/execute.js";
import { createScanDeadline, createStageDeadline, deadlineFor } from "../../src/web/clock.js";
import { CleanupError } from "../../src/web/jobs.js";
import {
  ControlledSandbox,
  deferred,
  fixtureProvenance,
  fixtureSnapshot,
  ManualClock,
  privateText,
} from "../support/controlled-sandbox.js";

afterEach(() => vi.useRealTimers());
it("acquires once and sequentially composes all five real adapters into a normalized report", async () => {
  const sandbox = new ControlledSandbox();
  sandbox.releaseAll();
  const events: string[] = [];
  const execution = createExecutor(sandbox, fixtureProvenance)(
    { id: "ordered", url: fixtureSnapshot.url },
    new AbortController().signal,
    (event) => {
      if (event.status === "running") events.push(event.stage);
    },
  );
  await expect(execution).resolves.toMatchObject({
    repository: { commit: "a".repeat(40) },
    issues: expect.any(Array),
  });
  const report = await execution;
  expect(report.issues).toHaveLength(5);
  expect(sandbox.created).toHaveLength(1);
  expect(
    sandbox.invocations.filter((call) =>
      call.command.includes("/usr/local/bin/vibeshield-acquire"),
    ),
  ).toHaveLength(1);
  expect(sandbox.started).toEqual(["gitleaks", "opengrep", "osv", "trivy", "zizmor"]);
  expect(events).toEqual([
    "prepare",
    "acquire",
    "gitleaks",
    "opengrep",
    "osv",
    "trivy",
    "zizmor",
    "report",
    "cleanup",
  ]);
  expect(report.provenance.advisoryData).toEqual([
    ...fixtureProvenance.advisoryData,
    { source: "OSV", retrievedAt: "2026-09-07T12:00:00.000Z", stale: false },
  ]);
  expect(fixtureProvenance.advisoryData).toHaveLength(1);
  expect(JSON.stringify(report)).not.toMatch(
    new RegExp(`${privateText}|securityGraph|modelMetadata|rawCredential|codeFlows|snippet`),
  );
  expect(sandbox.sessions.size).toBe(0);
});
it("emits structured operator lifecycle without repository or sandbox output", async () => {
  const sandbox = new ControlledSandbox();
  sandbox.releaseAll();
  const diagnostics: unknown[] = [];
  await createExecutor(sandbox, fixtureProvenance, (event) => diagnostics.push(event))(
    { id: "observable-success", url: fixtureSnapshot.url },
    new AbortController().signal,
    () => {},
  );
  expect(
    diagnostics
      .filter(
        (event): event is { event: string; stage: string; status: string } =>
          typeof event === "object" && event !== null && "stage" in event && "status" in event,
      )
      .map((event) => `${event.stage}:${event.status}`),
  ).toEqual([
    "prepare:running",
    "prepare:completed",
    "acquire:running",
    "acquire:completed",
    "gitleaks:running",
    "gitleaks:completed",
    "opengrep:running",
    "opengrep:completed",
    "osv:running",
    "osv:completed",
    "trivy:running",
    "trivy:completed",
    "zizmor:running",
    "zizmor:completed",
    "report:running",
    "report:completed",
    "cleanup:running",
    "cleanup:completed",
  ]);
  expect(diagnostics.at(-1)).toEqual({
    event: "scan_finished",
    scanId: "observable-success",
    status: "completed",
  });
  expect(JSON.stringify(diagnostics)).not.toContain(fixtureSnapshot.url);
  expect(JSON.stringify(diagnostics)).not.toContain(privateText);
});
it("reports a safe acquisition failure category without diagnostic output", async () => {
  const sandbox = new ControlledSandbox();
  sandbox.acquisitionFails = true;
  sandbox.acquisitionStderr = `VIBESHIELD_ACQUIRE_FAILURE=file_limit\n${privateText}`;
  const diagnostics: unknown[] = [];
  await expect(
    createExecutor(sandbox, fixtureProvenance, (event) => diagnostics.push(event))(
      { id: "observable-failure", url: fixtureSnapshot.url },
      new AbortController().signal,
      () => {},
    ),
  ).rejects.toThrow("Scan failed before a report could be prepared");
  expect(diagnostics).toContainEqual({
    event: "scan_stage",
    scanId: "observable-failure",
    stage: "acquire",
    status: "failed",
    reason: "file_limit",
  });
  expect(diagnostics.at(-1)).toEqual({
    event: "scan_finished",
    scanId: "observable-failure",
    status: "failed",
  });
  expect(JSON.stringify(diagnostics)).not.toContain(privateText);
});
it("distinguishes sandbox transport failure from timeout without diagnostic output", async () => {
  const sandbox = new ControlledSandbox();
  sandbox.beforeRead = async (path) => {
    if (path.endsWith("snapshot.json")) throw new Error(privateText);
  };
  const diagnostics: unknown[] = [];
  await expect(
    createExecutor(sandbox, fixtureProvenance, (event) => diagnostics.push(event))(
      { id: "transport-failure", url: fixtureSnapshot.url },
      new AbortController().signal,
      () => {},
    ),
  ).rejects.toThrow("Scan failed before a report could be prepared");
  expect(diagnostics).toContainEqual({
    event: "scan_stage",
    scanId: "transport-failure",
    stage: "acquire",
    status: "failed",
    reason: "sandbox_failed",
  });
  expect(JSON.stringify(diagnostics)).not.toContain("overall_timeout");
  expect(JSON.stringify(diagnostics)).not.toContain(privateText);
});
it("classifies an explicit early cancellation separately from a deadline", async () => {
  const sandbox = new ControlledSandbox();
  const controller = new AbortController();
  controller.abort();
  const diagnostics: unknown[] = [];
  await expect(
    createExecutor(sandbox, fixtureProvenance, (event) => diagnostics.push(event))(
      { id: "cancelled", url: fixtureSnapshot.url },
      controller.signal,
      () => {},
    ),
  ).rejects.toThrow("Scan failed before a report could be prepared");
  expect(diagnostics).toContainEqual({
    event: "scan_stage",
    scanId: "cancelled",
    stage: "prepare",
    status: "failed",
    reason: "cancelled",
  });
  expect(JSON.stringify(diagnostics)).not.toContain("overall_timeout");
});
it("preserves cancellation while acquisition is active", async () => {
  const sandbox = new ControlledSandbox();
  const controller = new AbortController();
  sandbox.beforeRead = async (path) => {
    if (path.endsWith("snapshot.json")) {
      controller.abort();
      throw new Error(privateText);
    }
  };
  const diagnostics: unknown[] = [];
  await expect(
    createExecutor(sandbox, fixtureProvenance, (event) => diagnostics.push(event))(
      { id: "active-cancellation", url: fixtureSnapshot.url },
      controller.signal,
      () => {},
    ),
  ).rejects.toThrow("Scan failed before a report could be prepared");
  expect(diagnostics).toContainEqual({
    event: "scan_stage",
    scanId: "active-cancellation",
    stage: "acquire",
    status: "failed",
    reason: "cancelled",
  });
  expect(JSON.stringify(diagnostics)).not.toContain("sandbox_failed");
});
it("adds a bounded reason when a scanner returns failed coverage", async () => {
  const sandbox = new ControlledSandbox();
  sandbox.fail("osv");
  sandbox.releaseAll();
  const diagnostics: unknown[] = [];
  await createExecutor(sandbox, fixtureProvenance, (event) => diagnostics.push(event))(
    { id: "scanner-coverage-failure", url: fixtureSnapshot.url },
    new AbortController().signal,
    () => {},
  );
  expect(diagnostics).toContainEqual({
    event: "scan_stage",
    scanId: "scanner-coverage-failure",
    stage: "osv",
    status: "failed",
    reason: "scanner_failed",
  });
  expect(JSON.stringify(diagnostics)).not.toContain(privateText);
});
it("isolates stage cancellation and disposes its signal registration, timer and parent listener", () => {
  const clock = new ManualClock();
  const overall = createScanDeadline(clock);
  const stage = createStageDeadline(overall);
  expect(deadlineFor(stage.signal)).toBe(stage);
  expect(getEventListeners(overall.signal, "abort")).toHaveLength(1);
  clock.advance(119_999);
  expect(stage.signal.aborted).toBe(false);
  clock.advance(1);
  expect(stage.signal.aborted).toBe(true);
  expect(overall.signal.aborted).toBe(false);
  stage.dispose();
  expect(deadlineFor(stage.signal)).toBeUndefined();
  expect(getEventListeners(overall.signal, "abort")).toHaveLength(0);
  expect(clock.pending()).toBe(1);
  const next = createStageDeadline(overall);
  overall.abort();
  expect(next.signal.aborted).toBe(true);
  next.dispose();
  overall.dispose();
  expect(clock.pending()).toBe(0);
});
it("does not resolve a report until sandbox deletion is verified", async () => {
  const sandbox = new ControlledSandbox();
  sandbox.releaseAll();
  sandbox.cleanupGate = deferred();
  let settled = false;
  const execution = createExecutor(sandbox, fixtureProvenance)(
    { id: "cleanup", url: fixtureSnapshot.url },
    new AbortController().signal,
    () => {},
  ).finally(() => {
    settled = true;
  });
  void execution.catch(() => {});
  await vi.waitFor(() => expect(sandbox.destroyed).toHaveLength(1));
  expect(settled).toBe(false);
  expect(sandbox.sessions.size).toBe(1);
  sandbox.cleanupGate.resolve();
  await execution;
  expect(sandbox.sessions.size).toBe(0);
});
it("enforces its own ten-minute system-clock deadline when called without a JobStore", async () => {
  vi.useFakeTimers();
  const sandbox = new ControlledSandbox();
  let outcome = "pending";
  const execution = createExecutor(sandbox, fixtureProvenance)(
    { id: "standalone", url: fixtureSnapshot.url },
    new AbortController().signal,
    () => {},
  ).then(
    (report) => {
      outcome = report.incomplete ? "incomplete" : "clean";
    },
    () => {
      outcome = "failed";
    },
  );
  await vi.advanceTimersByTimeAsync(0);
  expect(sandbox.started).toEqual(["gitleaks"]);
  await vi.advanceTimersByTimeAsync(599_999);
  expect(outcome).toBe("pending");
  await vi.advanceTimersByTimeAsync(1);
  expect(outcome).toBe("incomplete");
  await execution;
  expect(outcome).toBe("incomplete");
  expect(sandbox.sessions.size).toBe(0);
  expect(vi.getTimerCount()).toBe(0);
});
it.each([
  "source",
  "timestamp",
  "invalid-day",
  "failure",
])("omits invalid OSV provenance: %s", async (kind) => {
  const sandbox = new ControlledSandbox();
  const value = sandbox.outputs.get("osv") as {
    advisoryData: { source: string; retrievedAt: string };
    exitCode: number;
  };
  if (kind === "source") value.advisoryData.source = privateText;
  if (kind === "timestamp") value.advisoryData.retrievedAt = "not-a-date";
  if (kind === "invalid-day") value.advisoryData.retrievedAt = "2026-02-30T12:00:00.000Z";
  if (kind === "failure") value.exitCode = 129;
  sandbox.releaseAll();
  const result = await createExecutor(sandbox, fixtureProvenance)(
    { id: `provenance-${kind}`, url: fixtureSnapshot.url },
    new AbortController().signal,
    () => {},
  );
  expect(result.provenance.advisoryData).toEqual(fixtureProvenance.advisoryData);
});
it("throws CleanupError instead of success when deletion cannot be established", async () => {
  const sandbox = new ControlledSandbox();
  sandbox.releaseAll();
  sandbox.cleanupFails = true;
  await expect(
    createExecutor(sandbox, fixtureProvenance)(
      { id: "cleanup-failure", url: fixtureSnapshot.url },
      new AbortController().signal,
      () => {},
    ),
  ).rejects.toBeInstanceOf(CleanupError);
});
it("does not remove an unrelated same-name resource when creation refuses ownership", async () => {
  const sandbox = new ControlledSandbox();
  await sandbox.create({ name: "vibeshield-web-collision", imageTag: "unrelated" });
  sandbox.create = async () => {
    throw new Error("Sandbox name is already in use");
  };
  await expect(
    createExecutor(sandbox, fixtureProvenance)(
      { id: "collision", url: fixtureSnapshot.url },
      new AbortController().signal,
      () => {},
    ),
  ).rejects.toThrow();
  expect(sandbox.sessions.has("vibeshield-web-collision")).toBe(true);
  expect(sandbox.destroyed).toEqual([]);
  await sandbox.cleanup();
});
it("waits for pending creation on abort, then verifies deletion before settling", async () => {
  const sandbox = new ControlledSandbox();
  const create = sandbox.create.bind(sandbox);
  const pending = deferred();
  let creating = false;
  sandbox.create = async (options) => {
    creating = true;
    const session = await create(options);
    await pending.promise;
    return session;
  };
  const controller = new AbortController();
  let settled = false;
  const execution = createExecutor(sandbox, fixtureProvenance)(
    { id: "pending-creation", url: fixtureSnapshot.url },
    controller.signal,
    () => {},
  ).then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  await vi.waitFor(() => expect(creating).toBe(true));
  controller.abort();
  expect(settled).toBe(false);
  pending.resolve();
  await execution;
  expect(sandbox.sessions.size).toBe(0);
  expect(sandbox.started).toEqual([]);
});
