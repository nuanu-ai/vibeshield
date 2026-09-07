import { createExecutor } from "../../src/scan/execute.js";
import { createJobs } from "../../src/web/jobs.js";
import { createWebServer } from "../../src/web/server.js";
import { ControlledSandbox, fixtureProvenance, ManualClock, rawOsv } from "./controlled-sandbox.js";

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
let state = fixture();
const server = createWebServer({
  start: (url) => state.jobs.start(url),
  get: (id) => state.jobs.get(id),
  busy: () => state.jobs.busy(),
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
    } else if (request.method === "POST" && request.url === "/__test/reset") {
      state.sandbox.releaseAll();
      await state.jobs.shutdown();
      state = fixture();
      response.end();
    } else {
      route.call(server, request, response);
    }
  })().catch(() => response.writeHead(500).end());
});
server.listen(4317, "127.0.0.1");
async function stop() {
  state.sandbox.releaseAll();
  await state.jobs.shutdown();
  server.closeAllConnections();
  server.close();
}
process.once("SIGTERM", () => void stop());
process.once("SIGINT", () => void stop());
