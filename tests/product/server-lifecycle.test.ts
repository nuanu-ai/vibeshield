import { execFile, spawn } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, expect, it } from "vitest";
import { createExecutor } from "../../src/scan/execute.js";
import { createService } from "../../src/server.js";
import { BusyError, createJobs } from "../../src/web/jobs.js";
import {
  ControlledSandbox,
  deferred,
  fixtureProvenance,
  ManualClock,
  privateText,
} from "../support/controlled-sandbox.js";

const dispose: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const cleanup of dispose.splice(0)) await cleanup();
});
async function service() {
  const sandbox = new ControlledSandbox();
  const clock = new ManualClock();
  const jobs = createJobs({
    execute: createExecutor(sandbox, fixtureProvenance),
    cleanup: () => sandbox.cleanup(),
    clock,
  });
  const application = createService(jobs);
  await new Promise<void>((resolve) => application.server.listen(0, "127.0.0.1", resolve));
  const port = (application.server.address() as { port: number }).port;
  dispose.push(async () => {
    sandbox.cleanupFails = false;
    sandbox.cleanupGate?.resolve();
    sandbox.releaseAll();
    await jobs.retryCleanup();
    await jobs.shutdown();
    application.server.closeAllConnections();
    await new Promise<void>((resolve) => application.server.close(() => resolve()));
    expect(sandbox.sessions.size).toBe(0);
    expect(clock.pending()).toBe(0);
  });
  return { sandbox, jobs, clock, ...application, port };
}

// Removing admission closure, skipping the await, or leaving a request connection
// open breaks observable shutdown rather than just the shape of a helper.
it("shutdown closes admission immediately, waits for active cleanup, then closes unfinished HTTP connections", async () => {
  const app = await service();
  // Stall the export boundary: FakeSandboxSession aborts its own command by
  // deleting its in-memory session, which bypasses this runtime cleanup gate.
  const read = deferred();
  let reading = false;
  app.sandbox.beforeRead = async (path) => {
    if (path.endsWith("snapshot.json")) {
      reading = true;
      await read.promise;
    }
  };
  dispose.unshift(async () => {
    read.resolve();
  });
  app.jobs.start("https://github.com/owner/repo");
  await expect.poll(() => reading).toBe(true);
  const socket = connect(app.port, "127.0.0.1");
  socket.on("error", () => {});
  dispose.unshift(async () => {
    socket.destroy();
  });
  await new Promise<void>((resolve) => socket.once("connect", resolve));
  socket.write(
    `POST /scans HTTP/1.1\r\nHost: 127.0.0.1:${app.port}\r\nContent-Length: 100\r\n\r\n`,
  );
  app.sandbox.cleanupGate = deferred();
  let settled = false;
  const stopping = app.shutdown().then(() => {
    settled = true;
  });
  expect(() => app.jobs.start("https://github.com/owner/another")).toThrow(BusyError);
  await expect.poll(() => app.sandbox.destroyed.length).toBe(1);
  expect(settled).toBe(false);
  expect(app.sandbox.sessions.size).toBe(1);
  app.sandbox.cleanupGate.resolve();
  await stopping;
  read.resolve();
  await expect.poll(() => socket.destroyed).toBe(true);
  expect(app.server.listening).toBe(false);
  expect(app.sandbox.sessions.size).toBe(0);
  expect(app.clock.pending()).toBe(0);
  expect(() => app.jobs.start("https://github.com/owner/another")).toThrow(BusyError);
  await app.shutdown();
});

it("shutdown rejects unverifiable cleanup, closes HTTP and retains owned resources for reconciliation", async () => {
  const app = await service();
  app.sandbox.cleanupFails = true;
  app.sandbox.releaseAll();
  const { id } = app.jobs.start("https://github.com/owner/repo");
  await expect.poll(() => app.jobs.get(id)?.status).toBe("cleanup-failed");
  await expect(app.shutdown()).rejects.toThrow(/cleanup/i);
  expect(app.server.listening).toBe(false);
  expect(app.sandbox.sessions.size).toBe(1);
  expect(app.clock.pending()).toBe(0);
  app.clock.advance(60_000);
  expect(app.sandbox.destroyed).toHaveLength(1);
});

// Importing the library must not validate executable configuration, register
// signal handlers, reconcile resources, or start a listener.
it("imports server lifecycle without starting the executable or adding process handlers", async () => {
  const result = await promisify(execFile)(
    process.execPath,
    [
      "--import",
      "tsx",
      "--input-type=module",
      "-e",
      `const before = [process.listenerCount('SIGTERM'), process.listenerCount('SIGINT')];
       await import('./src/server.ts');
       console.log(JSON.stringify({ before, after: [process.listenerCount('SIGTERM'), process.listenerCount('SIGINT')] }));`,
    ],
    { env: { ...process.env, HOST: "invalid-executable-only-host" }, timeout: 5000 },
  ).then(
    (value) => ({ ...value, code: 0 }),
    (error: { code: number; stdout: string; stderr: string }) => error,
  );
  expect(result.code, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  const counts = JSON.parse(result.stdout);
  expect(counts.after).toEqual(counts.before);
});

// Replace only the external SDK's list operation; the executable, production
// runtime construction, ownership checks, JobStore, HTTP, and signal handler run.
it.each([
  "SIGTERM",
  "SIGINT",
] as const)("the executable exits nonzero on %s cleanup failure and preserves the owned marker", async (signal) => {
  const ownerDir = await realpath(await mkdtemp(join(tmpdir(), "vibeshield-task10-")));
  dispose.push(() => rm(ownerDir, { recursive: true, force: true }));
  const reserve = createServer();
  await new Promise<void>((resolve) => reserve.listen(0, "127.0.0.1", resolve));
  const port = (reserve.address() as { port: number }).port;
  await new Promise<void>((resolve) => reserve.close(() => resolve()));
  const sdk = `let calls=0; export const isInstalled=()=>false; export const MiB=n=>n;
    export const Sandbox={list: async()=>{if (++calls > 1) throw new Error(${JSON.stringify(privateText)}); return [];}};`;
  const url = `data:text/javascript,${encodeURIComponent(sdk)}`;
  const hook = `import { registerHooks } from 'node:module'; registerHooks({resolve(specifier, context, next){return specifier === 'microsandbox' ? { url: ${JSON.stringify(url)}, shortCircuit: true } : next(specifier, context);}});`;
  const child = spawn(
    process.execPath,
    [
      "--import",
      "tsx",
      "--import",
      `data:text/javascript,${encodeURIComponent(hook)}`,
      "src/server.ts",
    ],
    {
      env: {
        ...process.env,
        HOST: "127.0.0.1",
        PORT: String(port),
        VIBESHIELD_OWNER_DIR: ownerDir,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const exited = new Promise<number | null>((resolve) => child.once("close", resolve));
  dispose.unshift(async () => {
    if (child.exitCode === null) child.kill("SIGKILL");
    await exited;
  });
  await expect.poll(() => stdout || stderr, { timeout: 5000 }).toContain("VibeShield listening");
  const base = `http://127.0.0.1:${port}`;
  for (const path of ["advance", "fail", "restart", "reset", "release-all"]) {
    expect((await fetch(`${base}/__test/${path}`, { method: "POST" })).status).toBe(404);
  }
  const marker = join(ownerDir, "vibeshield-web-owned.json");
  const contents = JSON.stringify({
    name: "vibeshield-web-owned",
    token: "12345678-1234-1234-1234-123456789012",
  });
  await writeFile(marker, contents, { mode: 0o600 });
  child.kill(signal);
  await expect.poll(() => child.exitCode, { timeout: 5000 }).toBe(1);
  expect(await exited).toBe(1);
  expect(stderr).toMatch(/cleanup.*verified.*Operator reconciliation/is);
  expect(stderr).not.toContain(privateText);
  expect(await readFile(marker, "utf8")).toBe(contents);
  await expect(fetch(base)).rejects.toThrow();
});
