/**
 * Live Deep Static Gate 1 acceptance smoke.
 *
 * Skipped by default because it boots a real Microsandbox VM. Run explicitly:
 *   pnpm toolchain:prepare
 *   VIBESHIELD_LIVE_DEEP_STATIC_GATE1=1 pnpm exec vitest run tests/deep-static-gate1.smoke.test.ts
 */
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { FilesystemBlobs } from "../src/adapters/filesystem-blobs.js";
import { MicrosandboxRuntime } from "../src/adapters/microsandbox/runtime.js";
import { NullModelProvider } from "../src/adapters/null-model-provider.js";
import { SqliteStateStore } from "../src/adapters/sqlite-state-store.js";
import { ensureStateRoot } from "../src/adapters/state-root.js";
import { runScan } from "../src/application/scan-service.js";
import type { RepositoryMap } from "../src/domain/repository-map.js";
import type { ScanEvent } from "../src/ports/event-sink.js";

const execFileP = promisify(execFile);
const TOOLCHAIN_TAG = process.env.VIBESHIELD_TOOLCHAIN_TAG ?? "vibeshield-toolchain:latest";
const describeLive =
  process.env.VIBESHIELD_LIVE_DEEP_STATIC_GATE1 === "1" ? describe : describe.skip;

describeLive("Deep Static Gate 1 (live)", () => {
  it("proves a real Joern boundary-to-sink path in Microsandbox", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "vibeshield-gate1-"));
    const fixtureDir = path.join(root, "fixture");
    const stateRoot = path.join(root, "state");
    const dbPath = path.join(stateRoot, "state.sqlite");
    let db: DatabaseSync | undefined;

    try {
      await writeGate1Fixture(fixtureDir);
      await ensureStateRoot(stateRoot);
      db = new DatabaseSync(dbPath);
      const events: ScanEvent[] = [];
      const runtime = new MicrosandboxRuntime({ imageTag: TOOLCHAIN_TAG });
      const availability = await runtime.isAvailable();
      if (!availability.available) {
        console.warn("skipped:", availability.reason);
        return;
      }

      const outcome = await runScan(
        {
          sandbox: runtime,
          state: new SqliteStateStore(db),
          artifacts: new FilesystemBlobs(stateRoot),
          events: { emit: (event) => events.push(event) },
          model: new NullModelProvider(),
        },
        {
          source: { kind: "local", path: fixtureDir },
          runRoot: path.join(stateRoot, "runs"),
          toolchainImage: TOOLCHAIN_TAG,
          deep: true,
        },
      );

      expect(events.some((event) => event.stageId === "deep.static.compose")).toBe(true);
      expect(
        outcome.assessment.staticHypotheses?.some(
          (hypothesis) =>
            hypothesis.status !== "statically_contradicted" &&
            hypothesis.title === "External input reaches a dangerous operation",
        ),
      ).toBe(true);
      expect(
        outcome.assessment.deepCoverage?.some(
          (entry) => entry.area === "boundaries" && entry.state === "checked",
        ),
      ).toBe(true);
      expect(
        outcome.assessment.deepCoverage?.some(
          (entry) => entry.area === "call_graph" && entry.state === "checked",
        ),
      ).toBe(true);
      expect(
        outcome.assessment.deepCoverage?.some(
          (entry) => entry.area === "data_flow" && entry.state === "checked",
        ),
      ).toBe(true);

      const reportJson = JSON.parse(await readFile(outcome.reportPaths.json ?? "", "utf8")) as {
        assessment: {
          staticHypotheses?: Array<{ title: string; status: string }>;
          deepCoverage?: Array<{ area: string; state: string }>;
        };
      };
      expect(reportJson.assessment.staticHypotheses).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            title: "External input reaches a dangerous operation",
            status: "statically_supported",
          }),
        ]),
      );

      const reportHtml = await readFile(outcome.reportPaths.html ?? "", "utf8");
      expect(reportHtml).toContain("Likely attack paths");
      expect(reportHtml).toContain("External input reaches a dangerous operation");

      const repositoryMap = JSON.parse(
        await readFile(outcome.reportPaths.repositoryMap ?? "", "utf8"),
      ) as RepositoryMap;
      expect(repositoryMap.boundaries).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            label: "proxyHandler",
            properties: expect.objectContaining({ boundaryType: "framework-input" }),
          }),
        ]),
      );
      expect(repositoryMap.relationships).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            kind: "calls",
            fromLabel: "proxyHandler",
            toLabel: "fetchUrl",
          }),
          expect.objectContaining({ kind: "calls", fromLabel: "fetchUrl", toLabel: "fetch" }),
        ]),
      );
      expect(repositoryMap.flows.length).toBeGreaterThan(0);

      const blobTexts = await readBlobTexts(path.join(stateRoot, "blobs", "sha256"));
      expect(blobTexts.some((text) => text.includes('"objectSlices"'))).toBe(true);
      expect(blobTexts.some((text) => text.includes("framework-input"))).toBe(true);
    } finally {
      db?.close();
      await rm(root, { recursive: true, force: true });
    }
  }, 180_000);
});

async function writeGate1Fixture(dest: string): Promise<void> {
  await mkdir(path.join(dest, "src", "routes"), { recursive: true });
  await mkdir(path.join(dest, "src", "lib"), { recursive: true });
  await writeFile(
    path.join(dest, "README.md"),
    ["# Deep Static Gate 1 Fixture", "", "A tiny fixture for boundary-to-sink proof.", ""].join(
      "\n",
    ),
  );
  await writeFile(
    path.join(dest, "src", "routes", "proxy.js"),
    [
      "const { fetchUrl } = require('../lib/fetcher');",
      "",
      "function proxyHandler(req) {",
      "  return fetchUrl(req.query.url);",
      "}",
      "",
      "module.exports = { proxyHandler };",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(dest, "src", "lib", "fetcher.js"),
    [
      "async function fetchUrl(url) {",
      "  return fetch(url);",
      "}",
      "",
      "module.exports = { fetchUrl };",
      "",
    ].join("\n"),
  );
  await git(dest, ["init", "-q", "--initial-branch=main"]);
  await git(dest, ["config", "user.email", "fixture@vibeshield.test"]);
  await git(dest, ["config", "user.name", "VibeShield Fixture"]);
  await git(dest, ["config", "commit.gpgsign", "false"]);
  await git(dest, ["add", "-A"]);
  await git(dest, ["commit", "-q", "-m", "fixture: deep static boundary path"]);
}

async function git(cwd: string, args: string[]): Promise<void> {
  await execFileP("git", args, { cwd });
}

async function readBlobTexts(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true }).catch(() => []);
  const texts: string[] = [];
  for (const entry of entries) {
    const abs = path.join(root, entry.name);
    if (entry.isDirectory()) {
      texts.push(...(await readBlobTexts(abs)));
    } else if (entry.isFile()) {
      texts.push(await readFile(abs, "utf8").catch(() => ""));
    }
  }
  return texts;
}
