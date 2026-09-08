import { pathToFileURL } from "node:url";
import { createExecutor } from "../../src/scan/execute.js";
import { createJobs } from "../../src/web/jobs.js";
import { createWebServer } from "../../src/web/server.js";
import {
  ControlledSandbox,
  engines,
  fixtureProvenance,
  ManualClock,
  rawOsv,
} from "./controlled-sandbox.js";

function fixture() {
  const sandbox = new ControlledSandbox();
  const osv = rawOsv();
  const packages = osv.output.results[0]?.packages;
  const original = packages?.[0];
  const advisory = original?.vulnerabilities[0];
  if (!packages || !original || !advisory) throw new Error("Incomplete OSV fixture");
  advisory.summary = '<img src=x onerror=alert(1)> & "quoted"';
  for (const name of ["extra-package-one", "extra-package-two"]) {
    const next = structuredClone(original);
    next.package.name = name;
    const vulnerability = next.vulnerabilities[0];
    const affected = vulnerability?.affected[0];
    if (!vulnerability || !affected) throw new Error("Incomplete OSV fixture");
    affected.package.name = name;
    vulnerability.summary = `Known vulnerable ${name}`;
    packages.push(next);
  }
  sandbox.outputs.set("osv", osv);
  const clock = new ManualClock();
  const jobs = createJobs({
    execute: createExecutor(sandbox, fixtureProvenance),
    cleanup: () => sandbox.cleanup(),
    clock,
  });
  return { sandbox, clock, jobs };
}
export function createBrowserFixture() {
  let state = fixture();
  const server = createWebServer({
    start: (url) => state.jobs.start(url),
    get: (id) => state.jobs.get(id),
    busy: () => state.jobs.busy(),
    full: () => state.jobs.full(),
    shutdown: () => state.jobs.shutdown(),
    retryCleanup: () => state.jobs.retryCleanup(),
  });
  const route = server.listeners("request")[0];
  if (!route) throw new Error("Missing HTTP route handler");
  server.removeAllListeners("request");
  server.on("request", (request, response) => {
    void (async () => {
      if (request.method === "POST" && request.url === "/__test/release-all") {
        state.sandbox.releaseAll();
        response.end();
      } else if (
        request.method === "POST" &&
        ["/__test/reset", "/__test/restart"].includes(request.url ?? "")
      ) {
        state.sandbox.releaseAll();
        await state.jobs.shutdown();
        state = fixture();
        response.end();
      } else if (
        request.method === "POST" &&
        ["/__test/advance", "/__test/fail"].includes(request.url ?? "")
      ) {
        let data: Record<string, unknown>;
        try {
          let body = "";
          for await (const chunk of request) {
            body += String(chunk);
            if (Buffer.byteLength(body) > 8192) throw new Error("Control body too large");
          }
          data = JSON.parse(body);
          if (!data || typeof data !== "object") throw new Error("Invalid control");
        } catch {
          response.writeHead(400).end();
          return;
        }
        if (request.url === "/__test/advance") {
          if (typeof data.ms !== "number" || !Number.isSafeInteger(data.ms) || data.ms < 0) {
            response.writeHead(400).end();
            return;
          }
          state.clock.advance(data.ms);
        } else {
          const scanner = engines.find((id) => id === data.scanner);
          if (!scanner) {
            response.writeHead(400).end();
            return;
          }
          state.sandbox.fail(scanner);
        }
        response.end();
      } else {
        route.call(server, request, response);
      }
    })().catch(() => response.writeHead(500).end());
  });
  async function stop() {
    state.sandbox.releaseAll();
    await state.jobs.shutdown();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  return {
    server,
    shutdown: stop,
    get sandbox() {
      return state.sandbox;
    },
    get clock() {
      return state.clock;
    },
    get jobs() {
      return state.jobs;
    },
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const app = createBrowserFixture();
  app.server.listen(4317, "127.0.0.1");
  process.once("SIGTERM", () => void app.shutdown());
  process.once("SIGINT", () => void app.shutdown());
}
