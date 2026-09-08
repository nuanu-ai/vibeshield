import type { Server } from "node:http";
import { afterEach, beforeEach, expect, it } from "vitest";
import { createExecutor } from "../../src/scan/execute.js";
import { createJobs } from "../../src/web/jobs.js";
import { createWebServer } from "../../src/web/server.js";
import {
  ControlledSandbox,
  deferred,
  fixtureProvenance,
  ManualClock,
  privateText,
  rawOsv,
} from "../support/controlled-sandbox.js";

let sandbox: ControlledSandbox;
let clock: ManualClock;
let jobs: ReturnType<typeof createJobs>;
let server: Server;
let base: string;
let diagnostics: string[];
beforeEach(async () => {
  sandbox = new ControlledSandbox();
  clock = new ManualClock();
  diagnostics = [];
  jobs = createJobs({
    execute: createExecutor(sandbox, fixtureProvenance),
    cleanup: () => sandbox.cleanup(),
    clock,
    diagnostic: (message: string) => diagnostics.push(message),
  });
  server = createWebServer(jobs);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterEach(async () => {
  sandbox.cleanupFails = false;
  sandbox.cleanupGate?.resolve();
  sandbox.releaseAll();
  await jobs.retryCleanup();
  await jobs.shutdown();
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  expect(sandbox.sessions.size).toBe(0);
  expect(clock.pending()).toBe(0);
});
function get(path: string) {
  return fetch(base + path, { redirect: "manual" });
}
function submit(repository = "https://github.com/owner/repo") {
  return fetch(`${base}/scans`, {
    method: "POST",
    headers: { origin: base, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ repository }),
    redirect: "manual",
  });
}
async function start() {
  const response = await submit();
  expect(response.status).toBe(303);
  const path = response.headers.get("location");
  expect(path).toMatch(/^\/scans\/[a-f0-9-]+$/);
  return path as string;
}
async function status(path: string) {
  const response = await get(`${path}/status`);
  expect(response.status).toBe(200);
  return response.json() as Promise<{ status: string; reportReady: boolean }>;
}
async function complete(path: string) {
  await expect.poll(async () => (await status(path)).reportReady).toBe(true);
  const response = await get(`${path}/report`);
  expect(response.status).toBe(200);
  return response.text();
}

// Removing automatic cleanup recovery keeps the user busy indefinitely; clearing
// admission before deletion lets a second scan accumulate temporary resources.
it("keeps cleanup failure busy until a bounded maintenance retry verifies deletion", async () => {
  sandbox.cleanupFails = true;
  sandbox.releaseAll();
  const path = await start();
  await expect.poll(async () => (await status(path)).status).toBe("cleanup-failed");
  expect((await submit()).status).toBe(409);
  await expect.poll(() => sandbox.destroyed.length).toBe(2);
  expect(await (await get("/")).text()).toMatch(/cleanup.*pending/i);
  expect((await get(`${path}/report`)).status).toBe(200);
  expect(sandbox.sessions.size).toBe(1);
  sandbox.cleanupFails = false;
  sandbox.cleanupGate = deferred();
  clock.advance(5000);
  await expect.poll(() => sandbox.destroyed.length).toBe(3);
  clock.advance(60_000);
  expect(sandbox.destroyed).toHaveLength(3);
  expect((await submit()).status).toBe(409);
  sandbox.cleanupGate.resolve();
  expect(await complete(path)).toContain("Exposed credential");
  expect(sandbox.sessions.size).toBe(0);
  expect((await submit()).status).toBe(303);
  expect(diagnostics.length).toBeGreaterThan(0);
  expect(diagnostics.join(" ")).not.toContain(privateText);
  expect(JSON.stringify(await status(path))).not.toMatch(
    /operator|retry attempt|synthetic-credential/,
  );
});

// An unlimited retry loop masks a persistent operator fault and never becomes idle.
it("exhausts three maintenance attempts without releasing admission or leaking diagnostics", async () => {
  sandbox.cleanupFails = true;
  sandbox.releaseAll();
  const path = await start();
  await expect.poll(async () => (await status(path)).status).toBe("cleanup-failed");
  for (const count of [2, 3, 4]) {
    clock.advance(5000);
    await expect.poll(() => sandbox.destroyed.length).toBe(count);
    await expect.poll(() => diagnostics.length).toBeGreaterThanOrEqual(count);
  }
  clock.advance(86_400_000);
  expect(sandbox.destroyed).toHaveLength(4);
  expect(clock.pending()).toBe(0);
  expect((await submit()).status).toBe(409);
  const state = await status(path);
  expect(state).toMatchObject({ status: "cleanup-failed", reportReady: true });
  expect(JSON.stringify(state)).not.toMatch(/operator|retry attempt|synthetic-credential/);
  expect(diagnostics.join(" ")).toMatch(/operator/i);
  expect(diagnostics.join(" ")).not.toContain(privateText);
});

it("keeps other issues visible when OSV exports malformed JSON", async () => {
  sandbox.outputs.set("osv", "{broken");
  sandbox.releaseAll();
  const path = await start();
  const html = await complete(path);
  expect(html.match(/<details data-issue/g)).toHaveLength(4);
  expect(html).toContain("Exposed credential");
  expect(html).toContain("Scan incomplete");
  expect(html).toMatch(/osv · package-lock\.json<\/strong><span>failed/);
  expect(html).not.toMatch(/No important problems found|\{broken/);
  expect(await status(path)).toMatchObject({
    reportReady: true,
    stages: expect.arrayContaining([expect.objectContaining({ stage: "osv", status: "failed" })]),
  });
});

it.each([
  "acquisition",
  "runtime",
])("shows a sanitized fatal %s page without a clean report and admits the next scan", async (failure) => {
  if (failure === "acquisition") sandbox.acquisitionFails = true;
  else sandbox.setAvailability({ available: false, reason: privateText });
  const path = await start();
  await expect.poll(async () => (await status(path)).status).toBe("failed");
  const html = await (await get(path)).text();
  expect(html).toMatch(/role="alert">[^<]+/);
  expect(html).toContain('href="/"');
  expect(html).not.toMatch(/No important problems found|synthetic-credential/);
  expect((await get(`${path}/report`)).headers.get("location")).toBe(path);
  expect(await status(path)).toMatchObject({ reportReady: false });
  expect(sandbox.sessions.size).toBe(0);
  expect((await submit()).status).toBe(303);
});

it("times out stalled work but publishes completed findings only after cleanup", async () => {
  const path = await start();
  sandbox.release("gitleaks");
  await expect.poll(() => sandbox.started.at(-1)).toBe("opengrep");
  sandbox.cleanupGate = deferred();
  clock.advance(600_000);
  await expect.poll(() => sandbox.destroyed.length).toBe(1);
  expect((await submit()).status).toBe(409);
  expect(await status(path)).toMatchObject({ reportReady: false });
  sandbox.cleanupGate.resolve();
  const html = await complete(path);
  expect(html.match(/<details data-issue/g)).toHaveLength(1);
  expect(html).toContain("Exposed credential");
  expect(html).toContain("Scan incomplete");
  expect(html).toContain("overall deadline exceeded");
  expect(sandbox.sessions.size).toBe(0);
  expect((await submit()).status).toBe(303);
});

it("expires a report at one hour with a new-scan link on every old job URL", async () => {
  sandbox.releaseAll();
  const path = await start();
  await complete(path);
  clock.advance(3_599_999);
  expect((await get(`${path}/report`)).status).toBe(200);
  clock.advance(1);
  for (const suffix of ["", "/status", "/report"]) {
    const response = await get(path + suffix);
    expect(response.status).toBe(404);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const html = await response.text();
    expect(html).toContain("This result is no longer available");
    expect(html).toContain('href="/"');
    expect(html).not.toContain("Exposed credential");
  }
});

it("evicts the oldest of 21 completed reports while the other 20 remain reachable", async () => {
  sandbox.releaseAll();
  const paths: string[] = [];
  for (let index = 0; index < 21; index += 1) {
    const path = await start();
    paths.push(path);
    await complete(path);
    clock.advance(1);
  }
  const statuses = await Promise.all(
    paths.map(async (path) => (await get(`${path}/report`)).status),
  );
  expect(statuses).toEqual([404, ...Array(20).fill(200)]);
  expect(await (await get(`${paths[0]}/report`)).text()).toContain('href="/"');
});

it("renders a repository-controlled issue title as text through the real scanner pipeline", async () => {
  const output = rawOsv();
  const advisory = output.output.results[0]?.packages[0]?.vulnerabilities[0];
  if (!advisory) throw new Error("Missing raw advisory fixture");
  advisory.summary = '<img src=x onerror=alert(1)> & "quoted"';
  sandbox.outputs.set("osv", output);
  sandbox.releaseAll();
  const path = await start();
  const html = await complete(path);
  expect(html).toContain("&lt;img src=x onerror=alert(1)&gt; &amp; &quot;quoted&quot;");
  expect(html).not.toMatch(/<img|<script(?! src="\/assets\/app\.js")/);
});

it("keeps an unexpected coordinator failure out of the 500 response", async () => {
  const now = clock.now.bind(clock);
  clock.now = () => {
    throw new Error(privateText);
  };
  let response: Response;
  try {
    response = await submit();
  } finally {
    clock.now = now;
  }
  expect(response.status).toBe(500);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
  const html = await response.text();
  expect(html).toMatch(/role="alert">[^<]+/);
  expect(html).not.toContain(privateText);
  expect(sandbox.created).toHaveLength(0);
});

// The person who waited for this scan gets their report; the leaked sandbox is
// an operator problem and keeps admission closed on its own.
it("serves the finished report while cleanup is still pending", async () => {
  sandbox.cleanupFails = true;
  sandbox.releaseAll();
  const path = await start();
  await expect.poll(async () => (await status(path)).status).toBe("cleanup-failed");
  expect(await status(path)).toMatchObject({ reportReady: true });
  const response = await get(`${path}/report`);
  expect(response.status).toBe(200);
  expect(await response.text()).toContain("Exposed credential");
  expect((await submit()).status).toBe(409);
});

// Background attempts stop so the process can go idle. Without a retry driven by
// a waiting person the service stays closed until an operator restarts it.
it("reopens admission after a refused submission retries the pending cleanup", async () => {
  sandbox.cleanupFails = true;
  sandbox.releaseAll();
  const path = await start();
  await expect.poll(async () => (await status(path)).status).toBe("cleanup-failed");
  for (const count of [2, 3, 4]) {
    clock.advance(5000);
    await expect.poll(() => sandbox.destroyed.length).toBe(count);
  }
  clock.advance(86_400_000);
  expect(clock.pending()).toBe(0);
  const stillBroken = await submit();
  expect(stillBroken.status).toBe(409);
  await expect.poll(() => sandbox.destroyed.length).toBe(5);
  expect((await status(path)).status).toBe("cleanup-failed");
  sandbox.cleanupFails = false;
  const refused = await submit();
  expect(refused.status).toBe(409);
  expect(await refused.text()).toMatch(/again/i);
  await expect.poll(async () => (await status(path)).status).toBe("completed");
  expect((await submit()).status).toBe(303);
});

// One generic sentence for every failure leaves the person with nothing to act
// on, even though the executor already knows which one happened.
it("tells apart a repository it cannot read from a scan environment that is down", async () => {
  const alertOf = (html: string) => /role="alert"[^>]*>([^<]+)</.exec(html)?.[1]?.trim() ?? "";
  sandbox.acquisitionFails = true;
  const first = await start();
  await expect.poll(async () => (await status(first)).status).toBe("failed");
  const repository = alertOf(await (await get(first)).text());
  expect(repository).toMatch(/repo/i);

  sandbox.acquisitionFails = false;
  sandbox.setAvailability({ available: false, reason: privateText });
  const second = await start();
  await expect.poll(async () => (await status(second)).status).toBe("failed");
  const environment = alertOf(await (await get(second)).text());
  expect(environment).not.toMatch(/repo/i);
  expect(environment).not.toContain(privateText);
  expect(environment).not.toBe(repository);
});
