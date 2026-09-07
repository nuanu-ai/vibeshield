import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { MicrosandboxRuntime } from "./adapters/microsandbox/runtime.js";
import { reconcileOwnedRuntime } from "./adapters/runtime-ownership.js";
import type { Provenance } from "./scan/contracts.js";
import { createExecutor } from "./scan/execute.js";
import { LIMITS } from "./scan/limits.js";
import { osvPolicy, trivyPolicy, zizmorPolicy } from "./scan/policy.js";
import { systemClock } from "./web/clock.js";
import { createJobs, type JobStore } from "./web/jobs.js";
import { createWebServer } from "./web/server.js";

export function createService(jobs: JobStore) {
  const server = createWebServer(jobs);
  let stopping: Promise<void> | undefined;
  return {
    server,
    shutdown(): Promise<void> {
      stopping ??= (async () => {
        const closed = new Promise<void>((resolve) => server.close(() => resolve()));
        try {
          // Admission closes synchronously; active work must finish verified
          // deletion before unfinished HTTP connections are closed.
          await jobs.shutdown();
        } finally {
          server.closeAllConnections();
          await closed;
        }
      })();
      return stopping;
    },
  };
}

let stopService = () => Promise.resolve();
export function shutdown(): Promise<void> {
  return stopService();
}

async function main() {
  const host = process.env.HOST ?? "127.0.0.1";
  const portText = process.env.PORT ?? "3000";
  if (
    (host !== "localhost" && isIP(host) === 0) ||
    !/^\d{1,5}$/.test(portText) ||
    Number(portText) < 1 ||
    Number(portText) > 65535
  ) {
    throw new Error("HOST must be an IP address or localhost; PORT must be between 1 and 65535.");
  }
  const port = Number(portText);
  const ownerDir =
    process.env.VIBESHIELD_OWNER_DIR ??
    join(homedir(), ".local", "state", "vibeshield", "runtime-ownership");
  const image = process.env.VIBESHIELD_TOOLCHAIN_TAG ?? "vibeshield-toolchain:latest";
  const runtime = new MicrosandboxRuntime({
    ownerDir,
    imageTag: image,
    cpus: LIMITS.cpus,
    memoryMib: LIMITS.memoryMib,
  });
  const rules = JSON.parse(
    await readFile(new URL("../toolchain/rules/manifest.json", import.meta.url), "utf8"),
  ) as { revision: string };
  const provenance: Provenance = {
    image,
    tools: {
      gitleaks: "8.30.1",
      opengrep: "1.25.0",
      osv: osvPolicy.version,
      trivy: trivyPolicy.version,
      zizmor: zizmorPolicy.version,
    },
    rulesRevision: rules.revision,
    advisoryData: [
      {
        source: "Trivy checks",
        retrievedAt: new Date(trivyPolicy.bundle.reviewedAt).toISOString(),
        revision: trivyPolicy.bundle.revision,
        stale:
          Date.now() - Date.parse(trivyPolicy.bundle.reviewedAt) > 30 * 86400_000 ||
          Date.now() < Date.parse(trivyPolicy.bundle.reviewedAt),
      },
    ],
  };
  const cleanup = () => reconcileOwnedRuntime(runtime, ownerDir);
  const jobs = createJobs({
    execute: createExecutor(runtime, provenance),
    cleanup,
    clock: systemClock,
    diagnostic: (message) => console.error(message),
  });
  const service = createService(jobs);
  const server = service.server;
  let stopping = false;
  stopService = () => {
    stopping = true;
    return service.shutdown();
  };
  const stop = () => {
    void shutdown().catch(() => {
      console.error("Shutdown cleanup could not be verified. Operator reconciliation is required.");
      process.exitCode = 1;
    });
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  try {
    await cleanup();
    if (!stopping) {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          resolve();
        });
      });
      console.log(
        `VibeShield listening on http://${host.includes(":") ? `[${host}]` : host}:${port}`,
      );
    }
  } catch {
    console.error(
      "The web service could not start. Check the bind address and owned sandbox cleanup.",
    );
    process.exitCode = 1;
    await shutdown().catch(() =>
      console.error("Startup cleanup could not be verified. Operator reconciliation is required."),
    );
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
