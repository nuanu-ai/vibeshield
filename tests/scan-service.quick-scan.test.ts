import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type FakeExecHandler, FakeSandboxRuntime } from "../src/adapters/fake-sandbox.js";
import { FilesystemBlobs } from "../src/adapters/filesystem-blobs.js";
import { NullModelProvider } from "../src/adapters/null-model-provider.js";
import { SqliteStateStore } from "../src/adapters/sqlite-state-store.js";
import { runScan } from "../src/application/scan-service.js";
import type { Manifest } from "../src/domain/manifest.js";
import type { ScanEvent } from "../src/ports/event-sink.js";
import {
  GITLEAKS_REPORT_PATH,
  MANIFEST_PATH,
  MANIFEST_SCRIPT_PATH,
  SOURCE_DIR,
} from "../src/stages/paths.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PLANTED_SECRET = ["sk", "live", "26SGeL0ZOrD23wxj6X4Q5np2Ua0eJZ7m"].join("_");
let db: DatabaseSync;

describe("runScan quick scan vertical slice", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), "vibeshield-quick-scan-"));
    db = new DatabaseSync(path.join(dir, "state.sqlite"));
  });

  afterEach(async () => {
    db.close();
    await rm(dir, { recursive: true, force: true });
  });

  it("turns a real-shaped gitleaks finding into a redacted critical action and reports", async () => {
    const source = await writeLocalFixture(dir);
    const blobs = new FilesystemBlobs(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(manifestFor(source.path), [
        {
          RuleID: "stripe-access-token",
          Description: "Stripe Access Token",
          File: "src/config.ts",
          StartLine: 3,
          EndLine: 3,
          Secret: PLANTED_SECRET,
          Match: `stripeSecret: "${PLANTED_SECRET}"`,
          Fingerprint: "src/config.ts:stripe-access-token:3",
        },
      ]),
    });

    const outcome = await runScan(deps(sandbox, blobs), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    expect(outcome.assessment.verdict).toBe("critical-fix-needed");
    expect(outcome.assessment.findings).toHaveLength(1);
    expect(outcome.assessment.evidence[0]?.filePath).toBe("src/config.ts");
    expect(outcome.assessment.evidence[0]?.startLine).toBe(3);
    expect(outcome.assessment.rankedActions[0]?.remediation.agentPrompt).toContain(
      "src/config.ts:3",
    );
    expect(outcome.assessment.rankedActions[0]?.remediation.agentPrompt).not.toContain(
      PLANTED_SECRET,
    );

    const rawHash = outcome.assessment.evidence[0]?.rawArtifactBlobSha256;
    expect(rawHash).toBeDefined();
    const raw = decoder.decode(await blobs.read(rawHash ?? ""));
    expect(raw).toContain("***REDACTED***");
    expect(raw).not.toContain(PLANTED_SECRET);

    const reportPath = outcome.reportPaths.json;
    expect(reportPath).toBeDefined();
    const report = JSON.parse(await readFile(reportPath ?? "", "utf8")) as {
      assessment: { verdict: string; rankedActions: unknown[] };
    };
    expect(report.assessment.verdict).toBe("critical-fix-needed");
    expect(report.assessment.rankedActions).toHaveLength(1);

    expect(sandbox.invocations.map((i) => i.command)).toContainEqual([
      "gitleaks",
      "detect",
      "--source",
      SOURCE_DIR,
      "--no-git",
      "--report-format",
      "json",
      "--report-path",
      GITLEAKS_REPORT_PATH,
      "--redact=100",
      "--no-banner",
    ]);
  });

  it("rejects scanner evidence that is not inside the snapshot manifest", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(manifestFor(source.path), [
        {
          RuleID: "stripe-access-token",
          File: "not-in-manifest.ts",
          StartLine: 1,
          EndLine: 1,
          Secret: PLANTED_SECRET,
          Match: `token = "${PLANTED_SECRET}"`,
        },
      ]),
    });

    await expect(
      runScan(deps(sandbox, new FilesystemBlobs(dir)), {
        source,
        runRoot: path.join(dir, "runs"),
        toolchainImage: "test-toolchain:latest",
      }),
    ).rejects.toThrow("outside the snapshot");
  });

  it("fails before sandbox creation when the runtime is unavailable", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      available: { available: false, reason: "toolchain image missing" },
    });

    await expect(
      runScan(deps(sandbox, new FilesystemBlobs(dir)), {
        source,
        runRoot: path.join(dir, "runs"),
        toolchainImage: "test-toolchain:latest",
      }),
    ).rejects.toThrow("toolchain image missing");
    expect(sandbox.sessions.size).toBe(0);
  });
});

function deps(sandbox: FakeSandboxRuntime, blobs: FilesystemBlobs) {
  return {
    sandbox,
    state: new SqliteStateStore(db),
    artifacts: blobs,
    events: new CollectingEvents(),
    model: new NullModelProvider(),
  };
}

function fakeQuickScanExec(manifest: Manifest, gitleaksRecords: unknown[]): FakeExecHandler {
  return (command, session) => {
    const bin = command[0];
    if (bin === "mkdir" || bin === "rm" || bin === "tar" || bin === "git") {
      return { exitCode: 0, stdout: "", stderr: "" };
    }
    if (bin === "node" && command[1] === MANIFEST_SCRIPT_PATH) {
      session.files.set(MANIFEST_PATH, jsonBytes(manifest));
      return { exitCode: 0, stdout: "", stderr: "" };
    }
    if (bin === "gitleaks" && command[1] === "version") {
      return { exitCode: 0, stdout: "8.30.1\n", stderr: "" };
    }
    if (bin === "gitleaks") {
      session.files.set(GITLEAKS_REPORT_PATH, jsonBytes(gitleaksRecords));
      return { exitCode: gitleaksRecords.length > 0 ? 1 : 0, stdout: "", stderr: "" };
    }
    return { exitCode: 0, stdout: "", stderr: "" };
  };
}

async function writeLocalFixture(root: string) {
  const sourcePath = path.join(root, "fixture");
  await mkdir(path.join(sourcePath, "src"), { recursive: true });
  await writeFile(path.join(sourcePath, "README.md"), "# Fixture\n");
  await writeFile(
    path.join(sourcePath, "src", "config.ts"),
    ["export const config = {", `  stripeSecret: "${PLANTED_SECRET}",`, "};", ""].join("\n"),
  );
  return { kind: "local" as const, path: sourcePath };
}

function manifestFor(localPath: string): Manifest {
  return {
    origin: { kind: "local", path: localPath },
    commitSha: null,
    sourceHash: "fixture-source-hash",
    files: [
      { path: "README.md", size: 10, sha256: "readme-sha" },
      { path: "src/config.ts", size: 80, sha256: "config-sha" },
    ],
    exclusions: [],
    toolchain: {
      imageTag: "test-toolchain:latest",
      tools: [{ tool: "gitleaks", version: "8.30.1" }],
    },
    createdAt: "2026-01-01T00:00:00.000Z",
  };
}

function jsonBytes(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value, null, 2));
}

class CollectingEvents {
  readonly events: ScanEvent[] = [];

  emit(event: ScanEvent): void {
    this.events.push(event);
  }
}
