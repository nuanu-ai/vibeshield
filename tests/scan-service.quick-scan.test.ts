import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type FakeExecHandler, FakeSandboxRuntime } from "../src/adapters/fake-sandbox.js";
import { FilesystemBlobs } from "../src/adapters/filesystem-blobs.js";
import { NullModelProvider } from "../src/adapters/null-model-provider.js";
import { SqliteStateStore } from "../src/adapters/sqlite-state-store.js";
import { runScan } from "../src/application/scan-service.js";
import type { RemediationAction } from "../src/domain/action.js";
import type { Manifest } from "../src/domain/manifest.js";
import type { ScanEvent } from "../src/ports/event-sink.js";
import type { ModelEnhanceBatchInput, ModelProvider } from "../src/ports/model-provider.js";
import {
  GITLEAKS_REPORT_PATH,
  MANIFEST_PATH,
  MANIFEST_SCRIPT_PATH,
  OPENGREP_REPORT_PATH,
  SOURCE_DIR,
  TRIVY_CACHE_DIR,
} from "../src/stages/paths.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const execFileP = promisify(execFile);
const PLANTED_SECRET = ["sk", "live", "26SGeL0ZOrD23wxj6X4Q5np2Ua0eJZ7m"].join("_");
const TRIVY_DB_UPDATED_AT = "2026-06-22T09:00:00.000Z";
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
    expect(coverageByCheck(outcome.assessment.coverage).get("github-actions.actionlint")).toEqual({
      check: "github-actions.actionlint",
      status: "skipped",
      reason: "no GitHub Actions workflows found",
    });
    expect(coverageByCheck(outcome.assessment.coverage).get("github-actions.zizmor")).toEqual({
      check: "github-actions.zizmor",
      status: "skipped",
      reason: "no GitHub Actions workflows found",
    });

    const rawHash = outcome.assessment.evidence[0]?.rawArtifactBlobSha256;
    expect(rawHash).toBeDefined();
    const raw = decoder.decode(await blobs.read(rawHash ?? ""));
    expect(raw).toContain("***REDACTED***");
    expect(raw).not.toContain(PLANTED_SECRET);

    const reportPath = outcome.reportPaths.json;
    expect(reportPath).toBeDefined();
    const report = JSON.parse(await readFile(reportPath ?? "", "utf8")) as {
      assessment: {
        verdict: string;
        rankedActions: unknown[];
        coverage: Array<{ check: string; status: string; reason?: string }>;
      };
    };
    expect(report.assessment.verdict).toBe("critical-fix-needed");
    expect(report.assessment.rankedActions).toHaveLength(1);
    expect("deepCoverage" in outcome.assessment).toBe(false);
    expect("deepCoverage" in report.assessment).toBe(false);
    expect(coverageByCheck(report.assessment.coverage).get("github-actions.actionlint")).toEqual({
      check: "github-actions.actionlint",
      status: "skipped",
      reason: "no GitHub Actions workflows found",
    });

    const html = await readFile(outcome.reportPaths.html ?? "", "utf8");
    expect(html).toContain("Prompt for your coding agent");
    expect(html).toContain("Copy this whole block into your coding agent");
    expect(html).toContain("Why now:");
    expect(html).toContain("<dt>Where</dt>");
    expect(html).toContain("src/config.ts:3");
    expect(html).toContain("environment-based configuration");
    expect(html).not.toContain("VibeShield finding");

    const markdown = await readFile(outcome.reportPaths.markdown ?? "", "utf8");
    expect(markdown).toContain("**Prompt for your coding agent**");
    expect(markdown).toContain("Copy this whole block into your coding agent");
    expect(markdown).toContain("**Why now:**");
    expect(markdown).toContain("**Where:** src/config.ts:3");

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

  it("runs applicable workflow checks and records checked coverage", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          { path: "README.md", size: 10, sha256: "readme-sha" },
          { path: ".github/workflows/ci.yml", size: 80, sha256: "workflow-sha" },
        ]),
        [],
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    const coverage = coverageByCheck(outcome.assessment.coverage);
    expect(outcome.assessment.verdict).toBe("looks-ok-for-now");
    expect(coverage.get("secrets.gitleaks")).toEqual({
      check: "secrets.gitleaks",
      status: "checked",
    });
    expect(coverage.get("github-actions.actionlint")).toEqual({
      check: "github-actions.actionlint",
      status: "checked",
    });
    expect(coverage.get("github-actions.zizmor")).toEqual({
      check: "github-actions.zizmor",
      status: "checked",
    });
    expect(sandbox.invocations.map((i) => i.command[0])).toContain("actionlint");
    expect(sandbox.invocations.map((i) => i.command[0])).toContain("zizmor");
  });

  it("turns a workflow scanner finding into a deterministic action", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          { path: "README.md", size: 10, sha256: "readme-sha" },
          { path: ".github/workflows/ci.yml", size: 80, sha256: "workflow-sha" },
        ]),
        [],
        {
          actionlint: {
            exitCode: 1,
            stdout: JSON.stringify([
              {
                Message: 'property "branches" is not defined',
                Kind: "syntax-check",
                Filepath: "source/.github/workflows/ci.yml",
                Line: 7,
              },
            ]),
            stderr: "",
          },
        },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    expect(outcome.assessment.verdict).toBe("not-ready-to-deploy");
    expect(outcome.assessment.findings[0]).toMatchObject({
      sourceTool: "actionlint",
      category: "github-action",
      ruleId: "syntax-check",
    });
    expect(outcome.assessment.findingClusters).toHaveLength(1);
    expect(outcome.assessment.rankedActions[0]?.remediation.title).toBe(
      "Harden the GitHub Actions workflow",
    );
    expect(outcome.assessment.rankedActions[0]?.remediation.agentPrompt).toContain(
      ".github/workflows/ci.yml:7",
    );
  });

  it("maps scanner file URIs back to manifest paths", async () => {
    const source = await writeLocalFixture(dir);
    const workflowPath = ".github/workflows/ci workflow.yml";
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [{ path: workflowPath, size: 80, sha256: "workflow-sha" }]),
        [],
        {
          actionlint: {
            exitCode: 1,
            stdout: JSON.stringify([
              {
                Message: "workflow warning",
                Kind: "syntax-check",
                Filepath: "file:///work/source/.github/workflows/ci%20workflow.yml",
                Line: 9,
              },
            ]),
            stderr: "",
          },
        },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    expect(outcome.assessment.findings[0]?.locations[0]).toEqual({
      filePath: workflowPath,
      startLine: 9,
      endLine: 9,
    });
  });

  it("runs every applicable scanner from the inventory plan", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          { path: "src/app.ts", size: 20, sha256: "app-sha" },
          { path: "package.json", size: 40, sha256: "package-sha" },
          { path: ".github/workflows/ci.yml", size: 80, sha256: "workflow-sha" },
          { path: "Dockerfile", size: 30, sha256: "dockerfile-sha" },
        ]),
        [],
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    const coverage = coverageByCheck(outcome.assessment.coverage);
    expect(outcome.assessment.verdict).toBe("looks-ok-for-now");
    expect(outcome.assessment.toolchain.imageTag).toBe("test-toolchain:latest");
    expect(outcome.assessment.toolchain.tools.find((tool) => tool.tool === "trivy")).toMatchObject({
      tool: "trivy",
      dbDate: TRIVY_DB_UPDATED_AT,
      dbStale: false,
    });
    for (const check of [
      "secrets.gitleaks",
      "code-patterns.opengrep",
      "sbom.syft",
      "dependencies.trivy",
      "github-actions.actionlint",
      "github-actions.zizmor",
      "iac.trivy-config",
    ]) {
      expect(coverage.get(check)).toEqual({ check, status: "checked" });
    }
    expect(sandbox.invocations.map((i) => i.command[0])).toEqual(
      expect.arrayContaining(["gitleaks", "opengrep", "syft", "trivy", "actionlint", "zizmor"]),
    );
    expect(sandbox.invocations.filter((i) => i.command[0] === "trivy")).toHaveLength(3);
    expect(
      sandbox.invocations.findIndex((i) => i.command[0] === "trivy" && i.command[1] === "image"),
    ).toBeLessThan(
      sandbox.invocations.findIndex((i) => i.command[0] === "trivy" && i.command[1] === "fs"),
    );
  });

  it("blocks a green verdict when the Trivy DB refresh cannot prove freshness", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          { path: "README.md", size: 10, sha256: "readme-sha" },
          { path: "package.json", size: 40, sha256: "package-sha" },
        ]),
        [],
        {
          trivyRefresh: { exitCode: 1, stdout: "", stderr: "network unavailable", metadata: null },
        },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    expect(outcome.assessment.verdict).toBe("scan-incomplete");
    expect(outcome.assessment.toolchain.tools.find((tool) => tool.tool === "trivy")).toMatchObject({
      tool: "trivy",
      dbStale: true,
    });
    expect(coverageByCheck(outcome.assessment.coverage).get("dependencies.trivy")).toEqual({
      check: "dependencies.trivy",
      status: "degraded",
      reason: "trivy database freshness is stale; refresh failed before scan",
    });
  });

  it("keeps a useful fix pack when one applicable scanner fails", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          { path: "README.md", size: 10, sha256: "readme-sha" },
          { path: "src/config.ts", size: 80, sha256: "config-sha" },
          { path: ".github/workflows/ci.yml", size: 80, sha256: "workflow-sha" },
        ]),
        [
          {
            RuleID: "stripe-access-token",
            File: "src/config.ts",
            StartLine: 3,
            EndLine: 3,
            Secret: PLANTED_SECRET,
            Match: `stripeSecret: "${PLANTED_SECRET}"`,
            Fingerprint: "src/config.ts:stripe-access-token:3",
          },
        ],
        { actionlint: { exitCode: 2, stdout: "", stderr: "invalid workflow syntax" } },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    const coverage = coverageByCheck(outcome.assessment.coverage);
    expect(outcome.assessment.verdict).toBe("critical-fix-needed");
    expect(outcome.assessment.rankedActions[0]?.remediation.agentPrompt).toContain(
      "src/config.ts:3",
    );
    expect(coverage.get("github-actions.actionlint")).toEqual({
      check: "github-actions.actionlint",
      status: "failed",
      reason: "exit 2; stderr: invalid workflow syntax",
    });
  });

  it("repairs malformed scanner JSON and redacts raw output before normalization", async () => {
    const source = await writeLocalFixture(dir);
    const blobs = new FilesystemBlobs(dir);
    const leakedToken = ["sk", "live", "repairBoundaryToken123456789"].join("_");
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          { path: "README.md", size: 10, sha256: "readme-sha" },
          { path: ".github/workflows/ci.yml", size: 80, sha256: "workflow-sha" },
        ]),
        [],
        {
          actionlint: {
            exitCode: 1,
            stdout: `[{Message:'uses token ${leakedToken}', Kind:'secret-leak', Filepath:'.github/workflows/ci.yml', Line:7,}]`,
            stderr: "",
          },
        },
      ),
    });

    const outcome = await runScan(deps(sandbox, blobs), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    const finding = outcome.assessment.findings.find(
      (item) => item.sourceTool === "actionlint" && item.ruleId === "secret-leak",
    );
    const evidence = outcome.assessment.evidence.find((ev) => ev.tool === "actionlint");
    expect(outcome.assessment.verdict).toBe("not-ready-to-deploy");
    expect(finding).toBeDefined();
    expect(evidence?.snippet).toContain("***REDACTED***");
    expect(outcome.assessment.rankedActions[0]?.remediation.agentPrompt).not.toContain(leakedToken);
    const rawHash = evidence?.rawArtifactBlobSha256;
    expect(rawHash).toBeDefined();
    const raw = decoder.decode(await blobs.read(rawHash ?? ""));
    expect(raw).toContain("***REDACTED***");
    expect(raw).not.toContain(leakedToken);
  });

  it("turns unrepairable scanner JSON into failed coverage without losing other actions", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          { path: "README.md", size: 10, sha256: "readme-sha" },
          { path: "src/config.ts", size: 80, sha256: "config-sha" },
          { path: ".github/workflows/ci.yml", size: 80, sha256: "workflow-sha" },
        ]),
        [
          {
            RuleID: "stripe-access-token",
            File: "src/config.ts",
            StartLine: 3,
            EndLine: 3,
            Secret: PLANTED_SECRET,
            Match: `stripeSecret: "${PLANTED_SECRET}"`,
            Fingerprint: "src/config.ts:stripe-access-token:3",
          },
        ],
        { actionlint: { exitCode: 0, stdout: "not json at all", stderr: "" } },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    expect(outcome.assessment.verdict).toBe("critical-fix-needed");
    expect(outcome.assessment.rankedActions[0]?.remediation.title).toBe(
      "Remove the committed secret",
    );
    expect(
      coverageByCheck(outcome.assessment.coverage).get("github-actions.actionlint"),
    ).toMatchObject({
      check: "github-actions.actionlint",
      status: "failed",
    });
    expect(
      coverageByCheck(outcome.assessment.coverage).get("github-actions.actionlint")?.reason,
    ).toContain("scanner JSON root is not an array or object");
  });

  it("keeps remediation prompts scoped to each action's own findings", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          { path: "src/config.ts", size: 80, sha256: "config-sha" },
          { path: ".github/workflows/ci.yml", size: 80, sha256: "workflow-sha" },
        ]),
        [
          {
            RuleID: "stripe-access-token",
            File: "src/config.ts",
            StartLine: 3,
            EndLine: 3,
            Secret: PLANTED_SECRET,
            Match: `stripeSecret: "${PLANTED_SECRET}"`,
            Fingerprint: "src/config.ts:stripe-access-token:3",
          },
        ],
        {
          actionlint: {
            exitCode: 1,
            stdout: JSON.stringify([
              {
                Message: 'property "branches" is not defined',
                Kind: "workflow-syntax",
                Filepath: ".github/workflows/ci.yml",
                Line: 7,
              },
            ]),
            stderr: "",
          },
        },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    const promptByTitle = new Map(
      outcome.assessment.rankedActions.map((action) => [
        action.remediation.title,
        action.remediation.agentPrompt,
      ]),
    );
    expect(promptByTitle.get("Remove the committed secret")).toContain("stripe-access-token");
    expect(promptByTitle.get("Remove the committed secret")).not.toContain("workflow-syntax");
    expect(promptByTitle.get("Harden the GitHub Actions workflow")).toContain("workflow-syntax");
    expect(promptByTitle.get("Harden the GitHub Actions workflow")).not.toContain(
      "stripe-access-token",
    );
  });

  it("enhances remediation copy without changing deterministic verdict, findings, or candidates", async () => {
    const source = await writeLocalFixture(dir);
    const manifest = manifestFor(source.path, [
      { path: "src/config.ts", size: 80, sha256: "config-sha" },
      { path: ".github/workflows/ci.yml", size: 80, sha256: "workflow-sha" },
    ]);
    const baselineSandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifest,
        [
          {
            RuleID: "stripe-access-token",
            File: "src/config.ts",
            StartLine: 3,
            EndLine: 3,
            Secret: PLANTED_SECRET,
            Match: `stripeSecret: "${PLANTED_SECRET}"`,
            Fingerprint: "src/config.ts:stripe-access-token:3",
          },
        ],
        {
          actionlint: {
            exitCode: 1,
            stdout: JSON.stringify([
              {
                Message: 'property "branches" is not defined',
                Kind: "workflow-syntax",
                Filepath: ".github/workflows/ci.yml",
                Line: 7,
              },
            ]),
            stderr: "",
          },
        },
      ),
    });
    const enhancedModel = new FakeModelProvider((input) =>
      input.actions.map((action) => ({
        ...action.catalogRemediation,
        title: `AI: ${action.catalogRemediation.title}`,
        risk: `Clearer risk: ${action.catalogRemediation.risk}`,
        whyFixNow: `Clearer urgency: ${action.catalogRemediation.whyFixNow}`,
        agentPrompt: [
          `AI prompt for ${action.candidateId}`,
          ...action.affectedFiles.map((file) => `Allowed file: ${file}.`),
        ].join("\n"),
        fromCatalog: false,
      })),
    );
    const enhancedSandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifest,
        [
          {
            RuleID: "stripe-access-token",
            File: "src/config.ts",
            StartLine: 3,
            EndLine: 3,
            Secret: PLANTED_SECRET,
            Match: `stripeSecret: "${PLANTED_SECRET}"`,
            Fingerprint: "src/config.ts:stripe-access-token:3",
          },
        ],
        {
          actionlint: {
            exitCode: 1,
            stdout: JSON.stringify([
              {
                Message: 'property "branches" is not defined',
                Kind: "workflow-syntax",
                Filepath: ".github/workflows/ci.yml",
                Line: 7,
              },
            ]),
            stderr: "",
          },
        },
      ),
    });

    const baseline = await runScan(deps(baselineSandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });
    const enhanced = await runScan(deps(enhancedSandbox, new FilesystemBlobs(dir), enhancedModel), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    expect(enhancedModel.inputs).toHaveLength(1);
    expect(enhancedModel.inputs[0]?.actions).toHaveLength(2);
    expect(enhanced.assessment.verdict).toBe(baseline.assessment.verdict);
    expect(enhanced.assessment.findings.map((finding) => finding.id)).toEqual(
      baseline.assessment.findings.map((finding) => finding.id),
    );
    expect(enhanced.assessment.rankedActions.map((action) => action.candidate)).toEqual(
      baseline.assessment.rankedActions.map((action) => action.candidate),
    );
    expect(
      enhanced.assessment.rankedActions.every((action) => !action.remediation.fromCatalog),
    ).toBe(true);
    expect(enhanced.assessment.rankedActions[0]?.remediation.title).toMatch(/^AI:/);
  });

  it("caps model remediation input while preserving deterministic findings", async () => {
    const source = await writeLocalFixture(dir);
    const files = Array.from({ length: 35 }, (_, index) => ({
      path: `src/secret-${String(index).padStart(2, "0")}.ts`,
      size: 100,
      sha256: `secret-${index}-sha`,
    }));
    const model = new FakeModelProvider(() => null);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(manifestFor(source.path, files), manySecretRecords(35)),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir), model), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    const action = model.inputs[0]?.actions[0];
    expect(action).toBeDefined();
    expect(model.inputs[0]?.actions).toHaveLength(1);
    expect(action?.findings).toHaveLength(10);
    expect(action?.affectedFiles).toHaveLength(20);
    expect(action?.summary).toMatchObject({
      totalFindings: 35,
      includedFindings: 10,
      omittedFindings: 25,
      totalAffectedFiles: 35,
      includedAffectedFiles: 20,
      omittedAffectedFiles: 15,
      rules: [{ value: "stripe-access-token", count: 35 }],
      tools: [{ value: "gitleaks", count: 35 }],
      severities: [{ value: "critical", count: 35 }],
    });
    expect(action?.findings[0]?.filePath).toBe("src/secret-00.ts");
    expect(action?.findings.some((finding) => finding.filePath === "src/secret-34.ts")).toBe(false);
    expect(action?.affectedFiles).not.toContain("src/secret-34.ts");
    expect(action?.findings[0]?.snippet).toContain("[truncated]");
    expect(action?.findings[0]?.snippet.length ?? 0).toBeLessThanOrEqual(520);
    expect(outcome.assessment.findings).toHaveLength(35);
    expect(outcome.assessment.rankedActions[0]?.candidate.findingIds).toHaveLength(35);
  });

  it("falls back to catalog remediation when the model returns invalid ids or paths", async () => {
    const source = await writeLocalFixture(dir);
    const badModel = new FakeModelProvider((input) =>
      input.actions.map((action, index) => ({
        ...action.catalogRemediation,
        candidateId: index === 0 ? "unknown-candidate" : action.candidateId,
        agentPrompt: "Edit /tmp/host-secret.txt",
        fromCatalog: false,
      })),
    );
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(manifestFor(source.path), [
        {
          RuleID: "stripe-access-token",
          File: "src/config.ts",
          StartLine: 3,
          EndLine: 3,
          Secret: PLANTED_SECRET,
          Match: `stripeSecret: "${PLANTED_SECRET}"`,
          Fingerprint: "src/config.ts:stripe-access-token:3",
        },
      ]),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir), badModel), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    expect(badModel.inputs).toHaveLength(1);
    expect(outcome.assessment.verdict).toBe("critical-fix-needed");
    expect(outcome.assessment.rankedActions[0]?.remediation).toMatchObject({
      title: "Remove the committed secret",
      fromCatalog: true,
    });
    expect(outcome.assessment.rankedActions[0]?.remediation.agentPrompt).not.toContain("/tmp");
  });

  it("blocks a green verdict when required scanner coverage is lost", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          { path: "README.md", size: 10, sha256: "readme-sha" },
          { path: ".github/workflows/ci.yml", size: 80, sha256: "workflow-sha" },
        ]),
        [],
        { actionlint: { exitCode: 2, stdout: "", stderr: "actionlint crashed" } },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    expect(outcome.assessment.verdict).toBe("scan-incomplete");
    expect(outcome.assessment.rankedActions).toHaveLength(0);
    expect(coverageByCheck(outcome.assessment.coverage).get("github-actions.actionlint")).toEqual({
      check: "github-actions.actionlint",
      status: "failed",
      reason: "exit 2; stderr: actionlint crashed",
    });
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

function deps(
  sandbox: FakeSandboxRuntime,
  blobs: FilesystemBlobs,
  model: ModelProvider = new NullModelProvider(),
) {
  return {
    sandbox,
    state: new SqliteStateStore(db),
    artifacts: blobs,
    events: new CollectingEvents(),
    model,
  };
}

interface FakeScannerOverrides {
  readonly actionlint?: {
    readonly exitCode: number;
    readonly stdout: string;
    readonly stderr: string;
  };
  readonly zizmor?: { readonly exitCode: number; readonly stdout: string; readonly stderr: string };
  readonly trivyRefresh?: {
    readonly exitCode: number;
    readonly stdout: string;
    readonly stderr: string;
    readonly metadata?: Record<string, unknown> | null;
  };
}

function fakeQuickScanExec(
  manifest: Manifest,
  gitleaksRecords: unknown[],
  overrides: FakeScannerOverrides = {},
): FakeExecHandler {
  return (command, session) => {
    const bin = command[0];
    if (bin === "mkdir" || bin === "rm" || bin === "tar" || bin === "git") {
      return { exitCode: 0, stdout: "", stderr: "" };
    }
    if (bin === "node" && command[1] === MANIFEST_SCRIPT_PATH) {
      session.files.set(
        MANIFEST_PATH,
        jsonBytes(manifestWithToolchainArgs(manifest, command, session)),
      );
      return { exitCode: 0, stdout: "", stderr: "" };
    }
    if (bin === "gitleaks" && command[1] === "version") {
      return { exitCode: 0, stdout: "8.30.1\n", stderr: "" };
    }
    if (bin === "gitleaks") {
      session.files.set(GITLEAKS_REPORT_PATH, jsonBytes(gitleaksRecords));
      return { exitCode: gitleaksRecords.length > 0 ? 1 : 0, stdout: "", stderr: "" };
    }
    if (bin === "opengrep") {
      session.files.set(
        OPENGREP_REPORT_PATH,
        jsonBytes({ version: "2.1.0", runs: [{ results: [] }] }),
      );
      return { exitCode: 0, stdout: "", stderr: "" };
    }
    if (bin === "trivy" && command[1] === "image") {
      const override = overrides.trivyRefresh;
      const metadata =
        override?.metadata === undefined ? { UpdatedAt: TRIVY_DB_UPDATED_AT } : override.metadata;
      if (metadata !== null) {
        session.files.set(`${TRIVY_CACHE_DIR}/db/metadata.json`, jsonBytes(metadata));
      }
      return override ?? { exitCode: 0, stdout: "", stderr: "" };
    }
    if (bin === "actionlint" && command[1] !== "-version") {
      return overrides.actionlint ?? { exitCode: 0, stdout: "[]", stderr: "" };
    }
    if (bin === "zizmor" && command[1] !== "--version") {
      return overrides.zizmor ?? { exitCode: 0, stdout: "[]", stderr: "" };
    }
    return { exitCode: 0, stdout: "", stderr: "" };
  };
}

function manySecretRecords(count: number): unknown[] {
  return Array.from({ length: count }, (_, index) => {
    const file = `src/secret-${String(index).padStart(2, "0")}.ts`;
    return {
      RuleID: "stripe-access-token",
      File: file,
      StartLine: index + 1,
      EndLine: index + 1,
      Secret: PLANTED_SECRET,
      Match: `stripeSecret: "${PLANTED_SECRET}" ${"x".repeat(800)}`,
      Fingerprint: `${file}:stripe-access-token:${index + 1}`,
    };
  });
}

function manifestWithToolchainArgs(
  manifest: Manifest,
  command: string[],
  session: Parameters<FakeExecHandler>[1],
): Manifest {
  const imageTag = command[6] ?? manifest.toolchain.imageTag;
  const freshness = readFakeJson<ToolchainFreshness>(session, command[7]);
  const freshnessByTool = new Map((freshness?.tools ?? []).map((tool) => [tool.tool, tool]));
  const tools = manifest.toolchain.tools.map((tool) => ({
    ...tool,
    ...freshnessByTool.get(tool.tool),
  }));
  for (const tool of freshness?.tools ?? []) {
    if (!tools.some((existing) => existing.tool === tool.tool)) {
      tools.push({ version: "unknown", ...tool });
    }
  }
  return { ...manifest, toolchain: { imageTag, tools } };
}

interface ToolchainFreshness {
  readonly tools: ReadonlyArray<{
    readonly tool: string;
    readonly dbDate?: string;
    readonly dbStale?: boolean;
  }>;
}

function readFakeJson<T>(
  session: Parameters<FakeExecHandler>[1],
  path: string | undefined,
): T | undefined {
  if (path === undefined) {
    return undefined;
  }
  const bytes = session.files.get(path);
  if (bytes === undefined) {
    return undefined;
  }
  return JSON.parse(decoder.decode(bytes)) as T;
}

async function writeLocalFixture(root: string) {
  const sourcePath = path.join(root, "fixture");
  await mkdir(path.join(sourcePath, "src"), { recursive: true });
  await writeFile(path.join(sourcePath, "README.md"), "# Fixture\n");
  await writeFile(
    path.join(sourcePath, "src", "config.ts"),
    ["export const config = {", `  stripeSecret: "${PLANTED_SECRET}",`, "};", ""].join("\n"),
  );
  await initGitFixture(sourcePath);
  return { kind: "local" as const, path: sourcePath };
}

async function initGitFixture(sourcePath: string): Promise<void> {
  await execFileP("git", ["init"], { cwd: sourcePath });
  await execFileP("git", ["config", "user.email", "vibeshield-test@example.com"], {
    cwd: sourcePath,
  });
  await execFileP("git", ["config", "user.name", "VibeShield Test"], { cwd: sourcePath });
  await execFileP("git", ["add", "."], { cwd: sourcePath });
  await execFileP("git", ["commit", "-m", "fixture"], { cwd: sourcePath });
}

function manifestFor(localPath: string, files = defaultManifestFiles()): Manifest {
  return {
    origin: { kind: "local", path: localPath },
    commitSha: null,
    sourceHash: "fixture-source-hash",
    files,
    exclusions: [],
    toolchain: {
      imageTag: "test-toolchain:latest",
      tools: [
        { tool: "gitleaks", version: "8.30.1" },
        { tool: "opengrep", version: "1.23.0" },
        { tool: "syft", version: "1.38.0" },
        { tool: "trivy", version: "0.71.2" },
        { tool: "actionlint", version: "1.7.12" },
        { tool: "zizmor", version: "1.26.1" },
      ],
    },
    createdAt: "2026-01-01T00:00:00.000Z",
  };
}

function defaultManifestFiles(): Manifest["files"] {
  return [
    { path: "README.md", size: 10, sha256: "readme-sha" },
    { path: "src/config.ts", size: 80, sha256: "config-sha" },
  ];
}

function jsonBytes(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value, null, 2));
}

function coverageByCheck<T extends { check: string }>(coverage: ReadonlyArray<T>): Map<string, T> {
  return new Map(coverage.map((entry) => [entry.check, entry]));
}

class CollectingEvents {
  readonly events: ScanEvent[] = [];

  emit(event: ScanEvent): void {
    this.events.push(event);
  }
}

class FakeModelProvider implements ModelProvider {
  readonly inputs: ModelEnhanceBatchInput[] = [];

  constructor(
    private readonly responder: (
      input: ModelEnhanceBatchInput,
    ) => ReadonlyArray<RemediationAction> | null,
  ) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async enhance(input: ModelEnhanceBatchInput): Promise<ReadonlyArray<RemediationAction> | null> {
    this.inputs.push(input);
    return this.responder(input);
  }
}
