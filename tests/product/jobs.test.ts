import { expect, it, vi } from "vitest";
import { createExecutor } from "../../src/scan/execute.js";
import { deadlineFor } from "../../src/web/clock.js";
import { BusyError, CleanupError, createJobs } from "../../src/web/jobs.js";
import {
  ControlledSandbox,
  deferred,
  engines,
  fixtureProvenance,
  fixtureSnapshot,
  ManualClock,
  privateText,
} from "../support/controlled-sandbox.js";

function setup(guestTimeouts = false) {
  const clock = new ManualClock();
  const sandbox = new ControlledSandbox(guestTimeouts ? clock : undefined);
  const jobs = createJobs({
    execute: createExecutor(sandbox, fixtureProvenance),
    cleanup: () => sandbox.cleanup(),
    clock,
  });
  return { sandbox, clock, jobs };
}
async function completed(jobs: ReturnType<typeof createJobs>, id: string) {
  await vi.waitFor(() => expect(jobs.get(id)?.status).toBe("completed"));
  const report = jobs.get(id)?.report;
  expect(report).toBeDefined();
  if (!report) throw new Error("Missing completed report");
  return report;
}

it("reserves the one slot synchronously before any work can await", async () => {
  const sandbox = new ControlledSandbox();
  const jobs = createJobs({
    execute: createExecutor(sandbox, fixtureProvenance),
    cleanup: () => sandbox.cleanup(),
    clock: new ManualClock(),
  });
  const first = jobs.start(fixtureSnapshot.url);
  expect(jobs.get(first.id)?.status).toBe("running");
  expect(jobs.busy()).toBe(true);
  expect(() => jobs.start(fixtureSnapshot.url)).toThrow(BusyError);
  sandbox.releaseAll();
  await jobs.shutdown();
});
it("waits for each scanner completion before starting the next and exposes real progress", async () => {
  const { jobs, sandbox } = setup();
  const { id } = jobs.start(fixtureSnapshot.url);
  for (const [index, engine] of engines.entries()) {
    await vi.waitFor(() => expect(sandbox.started.at(-1)).toBe(engine));
    expect(sandbox.started).toHaveLength(index + 1);
    expect(jobs.get(id)?.stages).toContainEqual(
      expect.objectContaining({ stage: engine, status: "running" }),
    );
    sandbox.release(engine);
  }
  await completed(jobs, id);
  expect(jobs.busy()).toBe(false);
  await jobs.shutdown();
});
it("limits both Gitleaks commands to one cumulative two-minute scanner budget", async () => {
  const { jobs, sandbox, clock } = setup();
  sandbox.beforeExport = (key) => {
    if (key.startsWith("gitleaks-")) clock.jump(119_999);
  };
  sandbox.releaseAll();
  const { id } = jobs.start(fixtureSnapshot.url);
  const report = await completed(jobs, id);
  expect(report.coverage).toContainEqual(
    expect.objectContaining({ scanner: "gitleaks", status: "failed" }),
  );
  expect(report.issues).toHaveLength(4);
  expect(
    sandbox.invocations.find(
      (call) => call.command[2] === "gitleaks" && call.command[3] === "history",
    )?.timeoutMs,
  ).toBe(1);
  expect(sandbox.started).toEqual(["gitleaks", "opengrep", "osv", "trivy", "zizmor"]);
  expect(sandbox.created[0]?.signal?.aborted).toBe(false);
  await jobs.shutdown();
  expect(clock.pending()).toBe(0);
});
it("stops the active guest command at the scanner deadline and continues in the same sandbox", async () => {
  const { jobs, sandbox, clock } = setup(true);
  for (const engine of ["gitleaks", "osv", "trivy", "zizmor"] as const) sandbox.release(engine);
  const { id } = jobs.start(fixtureSnapshot.url);
  await vi.waitFor(() => expect(sandbox.started.at(-1)).toBe("opengrep"));
  clock.advance(119_999);
  expect(jobs.get(id)?.status).toBe("running");
  expect(sandbox.started).toEqual(["gitleaks", "opengrep"]);
  clock.advance(1);
  const report = await completed(jobs, id);
  expect(report.issues).toHaveLength(4);
  expect(report.coverage).toContainEqual(
    expect.objectContaining({ scanner: "opengrep", status: "failed" }),
  );
  expect(sandbox.created).toHaveLength(1);
  expect(sandbox.created[0]?.signal?.aborted).toBe(false);
  expect(sandbox.started).toEqual(["gitleaks", "opengrep", "osv", "trivy", "zizmor"]);
  expect(clock.pending()).toBe(1);
  await jobs.shutdown();
  expect(clock.pending()).toBe(0);
});
it("clips the last scanner budget to the remaining overall deadline", async () => {
  const { jobs, sandbox, clock } = setup(true);
  let acquisitionDelayed = false;
  sandbox.beforeRead = async (path) => {
    if (path.endsWith("snapshot.json") && !acquisitionDelayed) {
      acquisitionDelayed = true;
      clock.jump(119_999);
    }
  };
  sandbox.beforeExport = (key) => {
    if (["gitleaks-current", "opengrep", "osv", "trivy"].includes(key)) clock.jump(119_999);
  };
  for (const engine of ["gitleaks", "opengrep", "osv", "trivy"] as const) sandbox.release(engine);
  const { id } = jobs.start(fixtureSnapshot.url);
  await vi.waitFor(() => expect(sandbox.started.at(-1)).toBe("zizmor"));
  expect(
    sandbox.invocations.find((call) => call.command[1] === "/usr/local/bin/vibeshield-zizmor")
      ?.timeoutMs,
  ).toBe(5);
  clock.advance(5);
  const report = await completed(jobs, id);
  expect(report.issues).toHaveLength(4);
  expect(sandbox.created[0]?.signal?.aborted).toBe(true);
  expect(sandbox.sessions.size).toBe(0);
  await jobs.shutdown();
  expect(clock.pending()).toBe(0);
});
it.each([
  119_999, 120_000,
])("uses the exact two-minute scanner boundary at %i ms", async (duration) => {
  const { jobs, sandbox, clock } = setup();
  sandbox.beforeExport = (key) => {
    if (key === "opengrep") clock.jump(duration);
  };
  sandbox.releaseAll();
  const { id } = jobs.start(fixtureSnapshot.url);
  const report = await completed(jobs, id);
  expect(report.coverage).toContainEqual(
    expect.objectContaining({
      scanner: "opengrep",
      status: duration === 119_999 ? "checked" : "failed",
    }),
  );
  expect(report.issues).toHaveLength(duration === 119_999 ? 5 : 4);
  expect(sandbox.started).toEqual(["gitleaks", "opengrep", "osv", "trivy", "zizmor"]);
  expect(sandbox.created[0]?.signal?.aborted).toBe(false);
  await jobs.shutdown();
});
it("does not start the next Gitleaks subcommand after a delayed scanner deadline callback", async () => {
  const { jobs, sandbox, clock } = setup();
  sandbox.beforeRead = async (path) => {
    if (path.endsWith("gitleaks-current.json")) clock.jump(120_000);
  };
  sandbox.releaseAll();
  const { id } = jobs.start(fixtureSnapshot.url);
  const report = await completed(jobs, id);
  expect(
    sandbox.invocations
      .filter((call) => call.command[2] === "gitleaks")
      .map((call) => call.command[3]),
  ).toEqual(["current"]);
  expect(report.coverage).toContainEqual(
    expect.objectContaining({ scanner: "gitleaks", status: "failed" }),
  );
  expect(sandbox.started.at(-1)).toBe("zizmor");
  await jobs.shutdown();
});
it.each([
  "error",
  "malformed",
  "timeout",
])("keeps other issues and continues after an OSV %s", async (failure) => {
  const { jobs, sandbox } = setup();
  if (failure === "error") sandbox.fail("osv");
  if (failure === "malformed") sandbox.outputs.set("osv", "{broken");
  if (failure === "timeout") sandbox.failures.set("osv", 124);
  sandbox.releaseAll();
  const { id } = jobs.start(fixtureSnapshot.url);
  const report = await completed(jobs, id);
  expect(report.issues).toHaveLength(4);
  expect(report.incomplete).toBe(true);
  expect(report.coverage).toContainEqual(
    expect.objectContaining({ scanner: "osv", status: "failed" }),
  );
  expect(sandbox.started).toEqual(["gitleaks", "opengrep", "osv", "trivy", "zizmor"]);
  expect(JSON.stringify(jobs.get(id))).not.toContain(privateText);
  await jobs.shutdown();
});
it.each([
  "acquisition",
  "manifest",
  "unavailable",
])("fails before scanners for fatal %s and releases only cleaned resources", async (failure) => {
  const { jobs, sandbox } = setup();
  if (failure === "acquisition") sandbox.acquisitionFails = true;
  if (failure === "manifest") sandbox.snapshot.commit = "malformed";
  if (failure === "unavailable") sandbox.setAvailability({ available: false, reason: privateText });
  const { id } = jobs.start(fixtureSnapshot.url);
  await vi.waitFor(() => expect(jobs.get(id)?.status).toBe("failed"));
  expect(sandbox.started).toEqual([]);
  expect(sandbox.sessions.size).toBe(0);
  expect(jobs.busy()).toBe(false);
  expect(jobs.get(id)?.report).toBeUndefined();
  expect(JSON.stringify(jobs.get(id))).not.toContain(privateText);
  await jobs.shutdown();
});
it("aborts at exactly ten cumulative minutes, preserving completed findings and marking every remaining engine incomplete", async () => {
  const { jobs, sandbox, clock } = setup();
  const { id } = jobs.start(fixtureSnapshot.url);
  sandbox.release("gitleaks");
  await vi.waitFor(() => expect(sandbox.started.at(-1)).toBe("opengrep"));
  clock.advance(599_999);
  expect(jobs.get(id)?.status).toBe("running");
  clock.advance(1);
  const report = await completed(jobs, id);
  expect(report.issues).toHaveLength(1);
  expect(report.incomplete).toBe(true);
  expect(report.coverage.filter((c) => c.status === "failed").map((c) => c.scanner)).toEqual([
    "opengrep",
    "osv",
    "trivy",
    "zizmor",
  ]);
  expect(sandbox.started).toEqual(["gitleaks", "opengrep"]);
  expect(sandbox.sessions.size).toBe(0);
  expect(jobs.busy()).toBe(false);
  await jobs.shutdown();
  expect(clock.pending()).toBe(0);
});
it("rechecks cumulative time when a completion arrives before a delayed deadline callback", async () => {
  const { jobs, sandbox, clock } = setup();
  const { id } = jobs.start(fixtureSnapshot.url);
  for (const engine of ["gitleaks", "opengrep", "osv", "trivy"] as const) {
    await vi.waitFor(() => expect(sandbox.started.at(-1)).toBe(engine));
    clock.jump(119_999);
    sandbox.release(engine);
  }
  await vi.waitFor(() => expect(sandbox.started.at(-1)).toBe("zizmor"));
  clock.jump(120_004);
  sandbox.release("zizmor");
  const report = await completed(jobs, id);
  expect(report.issues).toHaveLength(4);
  expect(report.coverage).toContainEqual(
    expect.objectContaining({ scanner: "zizmor", status: "failed" }),
  );
  expect(sandbox.sessions.size).toBe(0);
  await jobs.shutdown();
});
it("rechecks deadline after export reads so no next scanner starts after an event-loop stall", async () => {
  const { jobs, sandbox, clock } = setup();
  sandbox.beforeRead = async (path) => {
    if (path.endsWith("opengrep.json")) clock.jump(600_000);
  };
  sandbox.releaseAll();
  const { id } = jobs.start(fixtureSnapshot.url);
  const report = await completed(jobs, id);
  expect(sandbox.started).toEqual(["gitleaks", "opengrep"]);
  expect(report.issues).toHaveLength(1);
  expect(report.coverage.filter((c) => c.status === "failed").map((c) => c.scanner)).toEqual([
    "opengrep",
    "osv",
    "trivy",
    "zizmor",
  ]);
  await jobs.shutdown();
});
it("aborts an opaque executor using the injected clock even without lifecycle events", async () => {
  const clock = new ManualClock();
  let signal: AbortSignal | undefined;
  const jobs = createJobs({
    clock,
    cleanup: async () => {},
    execute: async (_request, current) => {
      signal = current;
      await new Promise<void>((_resolve, reject) =>
        current.addEventListener("abort", () => reject(new Error(privateText)), { once: true }),
      );
      throw new Error("unreachable");
    },
  });
  const { id } = jobs.start(fixtureSnapshot.url);
  expect(signal?.aborted).toBe(false);
  expect(signal && deadlineFor(signal)).toBeDefined();
  clock.advance(599_999);
  expect(signal?.aborted).toBe(false);
  clock.advance(1);
  expect(signal?.aborted).toBe(true);
  await vi.waitFor(() => expect(jobs.get(id)?.status).toBe("failed"));
  expect(signal && deadlineFor(signal)).toBeUndefined();
  expect(JSON.stringify(jobs.get(id))).not.toContain(privateText);
  await jobs.shutdown();
});
it("keeps failed creation cleanup visible and busy until operator reconciliation", async () => {
  const { jobs, sandbox } = setup();
  sandbox.create = async () => {
    throw new AggregateError(
      [new Error(privateText)],
      "Sandbox creation failed and cleanup failed",
    );
  };
  const { id } = jobs.start(fixtureSnapshot.url);
  await vi.waitFor(() => expect(jobs.get(id)?.status).toBe("cleanup-failed"));
  expect(jobs.busy()).toBe(true);
  expect(sandbox.destroyed).toEqual([]);
  await jobs.retryCleanup();
  expect(jobs.get(id)?.status).toBe("failed");
  expect(jobs.busy()).toBe(false);
  await jobs.shutdown();
});
it("stops a stalled export read at the deadline and cleans the sandbox", async () => {
  const { jobs, sandbox, clock } = setup();
  const stalled = deferred();
  let reading = false;
  sandbox.beforeRead = async (path) => {
    if (path.endsWith("opengrep.json")) {
      reading = true;
      await stalled.promise;
    }
  };
  sandbox.releaseAll();
  const { id } = jobs.start(fixtureSnapshot.url);
  await vi.waitFor(() => expect(reading).toBe(true));
  clock.advance(600_000);
  const report = await completed(jobs, id);
  expect(report.issues).toHaveLength(1);
  expect(sandbox.sessions.size).toBe(0);
  stalled.resolve();
  await jobs.shutdown();
});
it("stops remaining engines when sandbox transport fails while keeping prior findings", async () => {
  const { jobs, sandbox } = setup();
  sandbox.beforeExport = (key) => {
    if (key === "opengrep") throw new Error(privateText);
  };
  sandbox.releaseAll();
  const { id } = jobs.start(fixtureSnapshot.url);
  const report = await completed(jobs, id);
  expect(sandbox.started).toEqual(["gitleaks", "opengrep"]);
  expect(report.issues).toHaveLength(1);
  expect(report.coverage.filter((c) => c.status === "failed").map((c) => c.scanner)).toEqual([
    "opengrep",
    "osv",
    "trivy",
    "zizmor",
  ]);
  expect(sandbox.sessions.size).toBe(0);
  await jobs.shutdown();
});
it("keeps cleanup-failed admission closed through failed retries and publishes saved findings after verified retry", async () => {
  const clock = new ManualClock();
  const sandbox = new ControlledSandbox();
  const diagnostics: unknown[] = [];
  const jobs = createJobs({
    execute: createExecutor(sandbox, fixtureProvenance, (event) => diagnostics.push(event), false),
    cleanup: () => sandbox.cleanup(),
    clock,
    lifecycle: (event) => diagnostics.push(event),
  });
  sandbox.cleanupFails = true;
  sandbox.releaseAll();
  const { id } = jobs.start(fixtureSnapshot.url);
  await vi.waitFor(() => expect(jobs.get(id)?.status).toBe("cleanup-failed"));
  expect(jobs.busy()).toBe(true);
  expect(jobs.get(id)?.finishedAt).toBeUndefined();
  expect(jobs.get(id)?.report).toBeUndefined();
  expect(() => jobs.start(fixtureSnapshot.url)).toThrow(BusyError);
  await expect(jobs.retryCleanup()).rejects.toBeInstanceOf(CleanupError);
  expect(jobs.busy()).toBe(true);
  sandbox.cleanupFails = false;
  sandbox.cleanupGate = deferred();
  const retry = jobs.retryCleanup();
  expect(jobs.busy()).toBe(true);
  sandbox.cleanupGate.resolve();
  await retry;
  expect((await completed(jobs, id)).issues).toHaveLength(5);
  expect(jobs.get(id)?.finishedAt).toBe(clock.now());
  expect(jobs.busy()).toBe(false);
  expect(sandbox.sessions.size).toBe(0);
  expect(diagnostics).toContainEqual({
    event: "scan_stage",
    scanId: id,
    stage: "cleanup",
    status: "completed",
  });
  expect(diagnostics.at(-1)).toEqual({
    event: "scan_finished",
    scanId: id,
    status: "completed",
  });
  expect(
    diagnostics.filter(
      (event) =>
        typeof event === "object" &&
        event !== null &&
        "event" in event &&
        event.event === "scan_finished",
    ),
  ).toHaveLength(1);
  await jobs.shutdown();
});
it("keeps exhausted cleanup retries nonterminal until reconciliation finishes", async () => {
  const clock = new ManualClock();
  const sandbox = new ControlledSandbox();
  const diagnostics: unknown[] = [];
  const jobs = createJobs({
    execute: createExecutor(sandbox, fixtureProvenance, (event) => diagnostics.push(event), false),
    cleanup: () => sandbox.cleanup(),
    clock,
    lifecycle: (event) => diagnostics.push(event),
  });
  sandbox.cleanupFails = true;
  sandbox.releaseAll();
  const { id } = jobs.start(fixtureSnapshot.url);
  await vi.waitFor(() => expect(jobs.get(id)?.status).toBe("cleanup-failed"));
  for (const [index, destroyed] of [2, 3, 4].entries()) {
    clock.advance(5000);
    await vi.waitFor(() => expect(sandbox.destroyed).toHaveLength(destroyed));
    if (index < 2) await vi.waitFor(() => expect(clock.pending()).toBe(1));
  }
  await vi.waitFor(() =>
    expect(
      diagnostics.filter(
        (event) =>
          typeof event === "object" &&
          event !== null &&
          "event" in event &&
          event.event === "scan_stage" &&
          "stage" in event &&
          event.stage === "cleanup" &&
          "status" in event &&
          event.status === "failed",
      ),
    ).toHaveLength(4),
  );
  expect(
    diagnostics.filter(
      (event) =>
        typeof event === "object" &&
        event !== null &&
        "event" in event &&
        event.event === "scan_finished",
    ),
  ).toHaveLength(0);
  sandbox.cleanupFails = false;
  await jobs.retryCleanup();
  expect(diagnostics.at(-1)).toEqual({ event: "scan_finished", scanId: id, status: "completed" });
  expect(
    diagnostics.filter(
      (event) =>
        typeof event === "object" &&
        event !== null &&
        "event" in event &&
        event.event === "scan_finished",
    ),
  ).toHaveLength(1);
  await jobs.shutdown();
});
it("shutdown aborts work, waits for deletion, closes admission and cancels expiry timers", async () => {
  const { jobs, sandbox, clock } = setup();
  const { id } = jobs.start(fixtureSnapshot.url);
  await vi.waitFor(() => expect(sandbox.started).toEqual(["gitleaks"]));
  sandbox.cleanupGate = deferred();
  let settled = false;
  const shutdown = jobs.shutdown().then(() => {
    settled = true;
  });
  expect(() => jobs.start(fixtureSnapshot.url)).toThrow(BusyError);
  await vi.waitFor(() => expect(sandbox.destroyed.length).toBeGreaterThan(0));
  expect(settled).toBe(false);
  sandbox.cleanupGate.resolve();
  await shutdown;
  expect(jobs.get(id)?.status).not.toBe("running");
  expect(sandbox.sessions.size).toBe(0);
  expect(clock.pending()).toBe(0);
});
it("reports shutdown cleanup failure and permits an explicit operator recovery", async () => {
  const { jobs, sandbox } = setup();
  sandbox.releaseAll();
  sandbox.cleanupFails = true;
  const { id } = jobs.start(fixtureSnapshot.url);
  await vi.waitFor(() => expect(jobs.get(id)?.status).toBe("cleanup-failed"));
  await expect(jobs.shutdown()).rejects.toBeInstanceOf(CleanupError);
  sandbox.cleanupFails = false;
  await jobs.retryCleanup();
  await jobs.shutdown();
  expect(sandbox.sessions.size).toBe(0);
  expect(() => jobs.start(fixtureSnapshot.url)).toThrow(BusyError);
});
it("expires exactly one hour after completion and also rechecks expiry when timers are delayed", async () => {
  for (const delayed of [false, true]) {
    const { jobs, sandbox, clock } = setup();
    sandbox.releaseAll();
    const { id } = jobs.start(fixtureSnapshot.url);
    await completed(jobs, id);
    clock.advance(3_599_999);
    expect(jobs.get(id)?.status).toBe("completed");
    if (delayed) clock.jump(1);
    else clock.advance(1);
    expect(jobs.get(id)).toBeUndefined();
    await jobs.shutdown();
    expect(clock.pending()).toBe(0);
  }
});
it("evicts only the oldest completed report at 21 reports and a new store has no previous jobs", async () => {
  const { jobs, sandbox, clock } = setup();
  sandbox.releaseAll();
  const ids: string[] = [];
  for (let i = 0; i < 21; i += 1) {
    const { id } = jobs.start(fixtureSnapshot.url);
    ids.push(id);
    await completed(jobs, id);
    clock.advance(1);
  }
  expect(new Set(ids).size).toBe(21);
  expect(ids.map((id) => jobs.get(id)).filter(Boolean)).toHaveLength(20);
  expect(jobs.get(ids[0] ?? "")).toBeUndefined();
  expect(jobs.get(ids[1] ?? "")?.status).toBe("completed");
  expect(clock.pending()).toBe(20);
  await jobs.shutdown();
  expect(clock.pending()).toBe(0);
  const restarted = setup();
  expect(restarted.jobs.get(ids[20] ?? "")).toBeUndefined();
  expect(restarted.jobs.busy()).toBe(false);
  await restarted.jobs.shutdown();
});
