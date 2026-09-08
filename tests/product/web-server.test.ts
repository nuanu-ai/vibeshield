import { request as httpRequest, type Server } from "node:http";
import { afterEach, beforeEach, expect, it } from "vitest";
import { createExecutor } from "../../src/scan/execute.js";
import { createJobs, type JobStore } from "../../src/web/jobs.js";
import { createWebServer } from "../../src/web/server.js";
import {
  ControlledSandbox,
  fixtureProvenance,
  ManualClock,
  privateText,
} from "../support/controlled-sandbox.js";

let server: Server;
let jobs: JobStore;
let sandbox: ControlledSandbox;
let base: string;
let port: number;
beforeEach(async () => {
  sandbox = new ControlledSandbox();
  jobs = createJobs({
    execute: createExecutor(sandbox, fixtureProvenance),
    cleanup: () => sandbox.cleanup(),
    clock: new ManualClock(),
  });
  server = createWebServer(jobs);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as { port: number }).port;
  base = `http://127.0.0.1:${port}`;
});
afterEach(async () => {
  sandbox.releaseAll();
  await jobs.shutdown();
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
});
function raw(
  path: string,
  options: {
    method?: string;
    body?: string;
    headers?: Record<string, string | string[]>;
    chunked?: boolean;
  } = {},
) {
  return new Promise<{
    status: number;
    headers: import("node:http").IncomingHttpHeaders;
    text: string;
  }>((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method: options.method ?? "GET",
        headers: Object.entries({
          host: `127.0.0.1:${port}`,
          origin: base,
          "content-type": "application/x-www-form-urlencoded",
          ...options.headers,
        }).flatMap(([name, value]) =>
          Array.isArray(value) ? value.flatMap((item) => [name, item]) : [name, value],
        ),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            text: Buffer.concat(chunks).toString(),
          }),
        );
      },
    );
    req.on("error", reject);
    if (options.chunked && options.body) {
      req.write(options.body.slice(0, 4096));
      req.write(options.body.slice(4096));
    } else if (options.body) req.write(options.body);
    req.end();
  });
}
async function start() {
  return raw("/scans", {
    method: "POST",
    body: "repository=https%3A%2F%2Fgithub.com%2Fowner%2Frepo",
  });
}

// Removing the public projection or accidentally serializing Job leaks the report here.
it("redirects submissions and reports only public progress, with all security headers", async () => {
  const accepted = await start();
  expect(accepted.status).toBe(303);
  const path = accepted.headers.location;
  if (!path) throw new Error("Submission did not redirect");
  expect((await raw(`${path}/report`)).headers.location).toBe(path);
  const pending = await raw(`${path}/status`);
  expect(JSON.parse(pending.text)).toMatchObject({ status: "running", reportReady: false });
  sandbox.releaseAll();
  await expect.poll(() => jobs.get(path.split("/")[2] ?? "")?.status).toBe("completed");
  const complete = await raw(`${path}/status`);
  expect(Object.keys(JSON.parse(complete.text)).sort()).toEqual([
    "reportReady",
    "stages",
    "status",
  ]);
  expect(complete.text).not.toMatch(
    new RegExp(
      `${privateText}|repository|provenance|issues|evidence|prompt|rawCredential|modelMetadata`,
    ),
  );
  expect((await raw(`${path}/report`)).text).toContain("Exposed credential");
  for (const url of [
    "/",
    "/assets/app.js",
    "/assets/app.css",
    path,
    `${path}/status`,
    `${path}/report`,
    "/unknown",
  ]) {
    const response = await raw(url);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    const policy = response.headers["content-security-policy"];
    expect(typeof policy).toBe("string");
    if (typeof policy !== "string") throw new Error("Missing singular CSP header");
    expect(policy.split("; ")).toEqual([
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "connect-src 'self'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ]);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  }
});
it("maps invalid, duplicate and unknown requests to 400, 409, 404 and 405", async () => {
  for (const value of [
    "/tmp/project",
    "https://github.com/a/b/tree/main",
    "https://github.com@evil.test/a/b",
    "https://github.com/a/%62",
  ]) {
    expect(
      (
        await raw("/scans", {
          method: "POST",
          body: new URLSearchParams({ repository: value }).toString(),
        })
      ).status,
    ).toBe(400);
  }
  expect(
    (
      await raw("/scans", {
        method: "POST",
        body: "repository=https://github.com/a/b&repository=https://github.com/a/c",
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await raw("/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      })
    ).status,
  ).toBe(400);
  expect((await start()).status).toBe(303);
  expect((await start()).status).toBe(303);
  expect((await start()).status).toBe(409);
  for (const path of [
    "/",
    "/scans",
    "/assets/app.js",
    "/assets/app.css",
    "/scans/00000000-0000-0000-0000-000000000000/status",
  ]) {
    const response = await raw(path, { method: "PUT" });
    expect(response.status).toBe(405);
    expect(response.headers.allow).toBe(path === "/scans" ? "POST" : "GET");
  }
  expect((await raw("/scans/00000000-0000-0000-0000-000000000000")).status).toBe(404);
});
it("bounds the encoded body at exactly 8192 bytes even with chunked transfer", async () => {
  const prefix = "repository=https://github.com/owner/";
  const body = prefix + "a".repeat(8192 - prefix.length);
  expect((await raw("/scans", { method: "POST", body: `${body}a`, chunked: true })).status).toBe(
    413,
  );
  expect(jobs.busy()).toBe(false);
  expect((await raw("/scans", { method: "POST", body, chunked: true })).status).toBe(303);
});
it("rejects hostile hosts and origins before starting work", async () => {
  const body = "repository=https://github.com/owner/repo";
  for (const host of [
    `evil.test:${port}`,
    `127.0.0.1:${port + 1}`,
    `127.0.0.1.evil.test:${port}`,
    `evil.test@127.0.0.1:${port}`,
    `127.0.0.1:${port},evil.test`,
  ]) {
    expect(
      (await raw("/scans", { method: "POST", body, headers: { host, origin: `http://${host}` } }))
        .status,
    ).toBe(400);
  }
  for (const origin of ["https://evil.test", "null", `${base}/`, "", `http://localhost:${port}`]) {
    expect((await raw("/scans", { method: "POST", body, headers: { origin } })).status).toBe(400);
  }
  expect(
    (await raw("/scans", { method: "POST", body, headers: { "sec-fetch-site": "cross-site" } }))
      .status,
  ).toBe(400);
  expect(jobs.busy()).toBe(false);
  expect((await raw("/", { headers: { host: `localhost:${port}` } })).status).toBe(200);
  expect(
    (
      await raw("/scans", {
        method: "POST",
        body,
        headers: { host: `localhost:${port}`, origin: `http://localhost:${port}` },
      })
    ).status,
  ).toBe(303);
});
it("accepts an explicitly bound local interface without allowing arbitrary Host names", async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await new Promise<void>((resolve) => server.listen(0, "0.0.0.0", resolve));
  port = (server.address() as { port: number }).port;
  base = `http://127.0.0.1:${port}`;
  expect((await raw("/")).status).toBe(200);
  expect((await raw("/", { headers: { host: `rebind.evil:${port}` } })).status).toBe(400);
});
it.each([
  ["::ffff:192.168.88.134", "192.168.88.134", "http://192.168.88.134"],
  ["::ffff:c0a8:5886", "192.168.88.134", "http://192.168.88.134"],
  ["::ffff:192.168.88.134", "[::ffff:c0a8:5886]", "http://[::ffff:c0a8:5886]"],
  ["::ffff:127.0.0.1", "[::ffff:7f00:1]", "http://[::ffff:7f00:1]"],
  ["2001:0db8:0000:0000:0000:0000:0000:0001", "[2001:db8::1]", "http://[2001:db8::1]"],
  ["2001:db8::1", "[2001:0DB8:0000:0000:0000:0000:0000:0001]", "http://[2001:db8::1]"],
])("accepts equivalent receiving IP literals on a dual-stack bind: %s / %s", async (localAddress, host, origin) => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await new Promise<void>((resolve) => server.listen(0, "::", resolve));
  port = (server.address() as { port: number }).port;
  // Control only the kernel-supplied receiving-address boundary. The actual
  // server binds :: and receives IPv4 requests through Node's HTTP parser.
  server.on("connection", (socket) => {
    expect(socket.localAddress).toMatch(/^::ffff:/);
    Object.defineProperty(socket, "localAddress", { value: localAddress });
  });
  expect((await raw("/", { headers: { host: `${host}:${port}` } })).status).toBe(200);
  expect(
    (
      await raw("/scans", {
        method: "POST",
        body: "repository=https://github.com/owner/repo",
        headers: { host: `${host}:${port}`, origin: `${origin}:${port}` },
      })
    ).status,
  ).toBe(303);
});
it("normalizes only IP literals and never trusts a different host, port, duplicate or forwarded authority", async () => {
  server.prependListener("request", (request) => {
    Object.defineProperty(request.socket, "localAddress", {
      value: "::ffff:192.168.88.134",
      configurable: true,
    });
  });
  for (const host of [
    `evil.test:${port}`,
    `192.168.88.135:${port}`,
    `192.168.88.134:${port + 1}`,
    `[::ffff:c0a8:5887]:${port}`,
    `[2001:db8::1]:${port}`,
    `[::192.168.88.134]:${port}`,
    `[192.168.88.134]:${port}`,
    `192.168.88.134.evil.test:${port}`,
    `evil.test@192.168.88.134:${port}`,
    `192.168.88.134:${port}/`,
    `192.168.88.134:${port}?x`,
    `192.168.88.134:${port}#x`,
    `0xc0a85886:${port}`,
    `3232258182:${port}`,
    `0300.0250.0130.0206:${port}`,
    `[::ffff:192.168.88.134%25en0]:${port}`,
  ]) {
    expect(
      (
        await raw("/", {
          headers: {
            host,
            "x-forwarded-host": `192.168.88.134:${port}`,
            forwarded: `host="192.168.88.134:${port}"`,
          },
        })
      ).status,
    ).toBe(400);
  }
  expect(
    (await raw("/", { headers: { host: [`192.168.88.134:${port}`, `192.168.88.134:${port}`] } }))
      .status,
  ).toBe(400);
  expect(
    (
      await raw("/scans", {
        method: "POST",
        body: "repository=https://github.com/owner/repo",
        headers: {
          host: `[::ffff:c0a8:5886]:${port}`,
          origin: `http://192.168.88.134:${port}`,
        },
      })
    ).status,
  ).toBe(400);
  expect(jobs.busy()).toBe(false);
});
it("rejects encoded or ambiguous paths and never mounts browser control or cleanup routes", async () => {
  for (const path of [
    "/%2e/",
    "/scans/../",
    "//",
    "/?query",
    "/assets/%61pp.js",
    "/assets/app.js?x",
    "/assets\\app.js",
    `http://127.0.0.1:${port}/`,
    "/scans/%30/status",
    "/scans/00000000-0000-0000-0000-000000000000/",
  ]) {
    expect((await raw(path)).status).toBe(404);
  }
  for (const path of [
    "/__test/reset",
    "/__test/release-all",
    "/__test/fail",
    "/__test/advance",
    "/__test/restart",
    "/cleanup",
    "/retry-cleanup",
  ]) {
    expect((await raw(path, { method: "POST" })).status).toBe(404);
  }
});
