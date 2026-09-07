import { setTimeout } from "node:timers/promises";
import { Sandbox } from "microsandbox";
import { expect, it } from "vitest";
import { reconcileOwnedRuntime } from "../../src/adapters/runtime-ownership.js";
import { createExecutor } from "../../src/scan/execute.js";
import { systemClock } from "../../src/web/clock.js";
import { createJobs } from "../../src/web/jobs.js";
import { createWebServer } from "../../src/web/server.js";
import {
  assertOwnedCleanup,
  liveRuntime,
  ownerDirectory,
  saveEvidence,
  verifyLivePrerequisites,
} from "../support/live-runtime.js";

it("submits a public GitHub URL through the real web/executor/runtime composition to a report", async () => {
  const repository =
    process.env.VIBESHIELD_ACCEPTANCE_REPO ?? "https://github.com/juice-shop/juice-shop";
  const provenance = await verifyLivePrerequisites();
  const runtime = liveRuntime();
  const cleanup = () => reconcileOwnedRuntime(runtime, ownerDirectory);
  await cleanup();
  const jobs = createJobs({
    execute: createExecutor(runtime, provenance),
    cleanup,
    clock: systemClock,
  });
  const server = createWebServer(jobs);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const started = Date.now();
  let id: string | undefined;
  try {
    expect((await fetch(base)).status).toBe(200);
    const submitted = await fetch(`${base}/scans`, {
      method: "POST",
      redirect: "manual",
      headers: { origin: base, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ repository }),
    });
    expect(submitted.status).toBe(303);
    const path = submitted.headers.get("location");
    expect(path).toMatch(/^\/scans\/[a-f0-9-]+$/);
    id = path?.split("/").at(-1);
    expect(id).toBeTruthy();
    const reloaded = await fetch(base + path);
    expect(reloaded.status).toBe(200);
    expect(reloaded.headers.get("cache-control")).toBe("no-store");
    const stages = new Set<string>();
    while (Date.now() - started < 660000) {
      const response = await fetch(`${base}${path}/status`);
      expect(response.status).toBe(200);
      const status = (await response.json()) as {
        status: string;
        reportReady: boolean;
        stages: { stage: string; status: string }[];
      };
      for (const stage of status.stages)
        if (stage.status === "running" || stage.status === "completed") stages.add(stage.stage);
      if (status.reportReady || status.status !== "running") break;
      await setTimeout(1000);
    }
    const job = jobs.get(id as string);
    await saveEvidence("public-web", {
      repository,
      durationMs: Date.now() - started,
      status: job?.status,
      stages: job?.stages,
      error: job?.error,
      report: job?.report,
    });
    expect(
      job?.status,
      "public acquisition/real engines must complete; see public-web evidence",
    ).toBe("completed");
    expect(job?.report?.repository.url).toBe(repository.replace(/\.git$/, ""));
    expect(job?.report?.repository.commit).toMatch(/^[a-f0-9]{40}$/);
    expect(stages.has("acquire")).toBe(true);
    for (const engine of ["gitleaks", "opengrep", "osv", "trivy", "zizmor"])
      expect(job?.report?.coverage.some((coverage) => coverage.scanner === engine)).toBe(true);
    expect(
      job?.report?.coverage.filter((coverage) => coverage.status === "failed"),
      "a failed actual engine cannot satisfy public acceptance",
    ).toEqual([]);
    expect(job?.report?.coverage).toContainEqual(
      expect.objectContaining({ scanner: "gitleaks", area: "current", status: "checked" }),
    );
    expect(job?.stages.find((stage) => stage.stage === "cleanup")?.status).toBe("completed");
    expect(
      (await Sandbox.list()).some((resource) => resource.name === `vibeshield-web-${id}`),
    ).toBe(false);
    const response = await fetch(`${base}${path}/report`, { redirect: "manual" });
    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain(job?.report?.repository.commit);
    expect(html).toContain(provenance.image);
    if (job?.report?.issues.length) {
      expect(html).toContain("Copy prompt");
      expect(html).toContain("data-prompt");
    }
    expect(jobs.busy()).toBe(false);
  } finally {
    if (id) {
      const job = jobs.get(id);
      await saveEvidence("public-web-final", {
        repository,
        durationMs: Date.now() - started,
        status: job?.status,
        stages: job?.stages,
        error: job?.error,
        report: job?.report,
      });
    }
    await jobs.shutdown();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await assertOwnedCleanup();
  }
});
