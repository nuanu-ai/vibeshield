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
import type { SecurityAssessment } from "../src/domain/security-assessment.js";
import type { ScanEvent } from "../src/ports/event-sink.js";
import type {
  ModelEnhanceBatchInput,
  ModelHypothesisEnrichBatchInput,
  ModelHypothesisEnrichment,
  ModelProvider,
} from "../src/ports/model-provider.js";
import {
  GITLEAKS_REPORT_PATH,
  JOERN_ENTITIES_SLICE_PATH,
  JOERN_FLOWS_SLICE_PATH,
  JOERN_MODEL_PATH,
  MANIFEST_PATH,
  MANIFEST_SCRIPT_PATH,
  OPENGREP_REPORT_PATH,
  OSV_VULN_REPORT_PATH,
  SOURCE_DIR,
  TRIVY_CACHE_DIR,
  TRIVY_VULN_REPORT_PATH,
} from "../src/stages/paths.js";
import { renderRepositoryMap } from "../src/stages/repository-map.js";

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
    expect(sandbox.invocations.map((i) => i.command[0])).not.toContain("joern-parse");
  });

  it("writes deep reports and repository-map.json when deep scan is requested", async () => {
    const source = await writeLocalFixture(dir);
    const blobs = new FilesystemBlobs(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, deepManifestFiles()),
        [
          {
            RuleID: "stripe-access-token",
            Description: "Stripe Access Token",
            File: "src/routes/upload.ts",
            StartLine: 10,
            EndLine: 10,
            Secret: PLANTED_SECRET,
            Match: `stripeSecret: "${PLANTED_SECRET}"`,
            Fingerprint: "src/routes/upload.ts:stripe-access-token:10",
          },
        ],
        { joern: { mode: "success" } },
      ),
    });

    const outcome = await runScan(deps(sandbox, blobs), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
      deep: true,
    });

    expect(sandbox.invocations.map((i) => i.command[0])).toContain("joern-parse");
    expect(outcome.reportPaths.repositoryMap).toBeDefined();
    expect(outcome.assessment.repositoryMapArtifactRef).toMatchObject({
      role: "repository-map.json",
    });
    expect(outcome.assessment.deepCoverage?.some((entry) => entry.area === "call_graph")).toBe(
      true,
    );
    expect(
      outcome.assessment.staticHypotheses?.some(
        (hypothesis) => hypothesis.status === "statically_supported",
      ),
    ).toBe(true);

    const report = JSON.parse(await readFile(outcome.reportPaths.json ?? "", "utf8")) as {
      assessment: {
        repositoryMapArtifactRef?: { role: string };
        hypothesisCandidates?: Array<{ id: string; family: string }>;
        staticHypotheses?: Array<{ id: string; status: string }>;
      };
    };
    expect(report.assessment.repositoryMapArtifactRef?.role).toBe("repository-map.json");
    expect(report.assessment.hypothesisCandidates?.[0]?.id).toMatch(/^hypothesis_candidate_/);
    expect(report.assessment.staticHypotheses?.[0]?.id).toMatch(/^static_hypothesis_/);

    const repositoryMap = JSON.parse(
      await readFile(outcome.reportPaths.repositoryMap ?? "", "utf8"),
    ) as { graph: { id: string }; boundaries: unknown[]; relationships: unknown[] };
    expect(repositoryMap.boundaries).toHaveLength(1);
    expect(repositoryMap.relationships.length).toBeGreaterThan(0);

    await rm(outcome.reportPaths.repositoryMap ?? "");
    const state = new SqliteStateStore(db);
    const persistedGraph = await state.loadSecurityGraph(outcome.runId, repositoryMap.graph.id);
    if (persistedGraph === null) {
      throw new Error("expected persisted security graph");
    }
    expect(persistedGraph.id).toBe(repositoryMap.graph.id);
    expect(persistedGraph.nodes.length).toBeGreaterThan(0);
    expect(persistedGraph.edges.length).toBeGreaterThan(0);
    expect(renderRepositoryMap(persistedGraph)).toEqual(repositoryMap);
    const persistedCoverage = await state.loadDeepCoverage(outcome.runId);
    expect(persistedCoverage).toMatchObject({
      runId: outcome.runId,
      snapshotId: "fixture-source-hash",
    });
    expect(persistedCoverage?.entries.some((entry) => entry.area === "call_graph")).toBe(true);

    const markdown = await readFile(outcome.reportPaths.markdown ?? "", "utf8");
    expect(markdown).toContain("## Likely attack paths");
    expect(markdown).toContain("## What was checked");
  });

  it("raises the verdict when Deep Static finds supported attack paths without quick findings", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(manifestFor(source.path, deepManifestFiles()), [], {
        joern: { mode: "success" },
      }),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
      deep: true,
    });

    expect(outcome.assessment.findings).toHaveLength(0);
    expect(
      outcome.assessment.staticHypotheses?.some(
        (hypothesis) => hypothesis.status === "statically_supported",
      ),
    ).toBe(true);
    expect(outcome.assessment.verdict).toBe("not-ready-to-deploy");

    const markdown = await readFile(outcome.reportPaths.markdown ?? "", "utf8");
    expect(markdown).toContain("**Verdict:** Not ready to deploy");
    expect(markdown).toContain("1 likely attack path");
  });

  it("uses the Deep Static deploy verdict without dropping critical Quick Scan evidence", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, deepManifestFiles()),
        [
          {
            RuleID: "stripe-access-token",
            Description: "Stripe Access Token",
            File: "src/routes/upload.ts",
            StartLine: 10,
            EndLine: 10,
            Secret: PLANTED_SECRET,
            Match: `stripeSecret: "${PLANTED_SECRET}"`,
            Fingerprint: "src/routes/upload.ts:stripe-access-token:10",
          },
        ],
        { joern: { mode: "success" } },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
      deep: true,
    });

    expect(outcome.assessment.verdict).toBe("not-ready-to-deploy");
    expect(outcome.assessment.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: "stripe-access-token",
          severity: "critical",
        }),
      ]),
    );
    expect(
      outcome.assessment.staticHypotheses?.some(
        (hypothesis) => hypothesis.status === "statically_supported",
      ),
    ).toBe(true);
    expect(outcome.assessment.rankedActions[0]?.remediation.title).toBe(
      "Remove the committed secret",
    );
  });

  it("adds package dependency graph context without mutating Quick Scan findings", async () => {
    const source = await writeLocalFixture(dir);
    const blobs = new FilesystemBlobs(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, gate2ManifestFiles()),
        [
          {
            RuleID: "stripe-access-token",
            Description: "Stripe Access Token",
            File: "src/routes/upload.ts",
            StartLine: 10,
            EndLine: 10,
            Secret: PLANTED_SECRET,
            Match: `stripeSecret: "${PLANTED_SECRET}"`,
            Fingerprint: "src/routes/upload.ts:stripe-access-token:10",
          },
        ],
        {
          joern: { mode: "success" },
          trivyVuln: trivyDependencyReport(),
        },
      ),
    });

    const outcome = await runScan(deps(sandbox, blobs), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
      deep: true,
    });

    const secretFinding = outcome.assessment.findings.find(
      (finding) => finding.category === "secret",
    );
    const dependencyFinding = outcome.assessment.findings.find(
      (finding) => finding.category === "dependency",
    );
    expect(secretFinding).toMatchObject({
      sourceTool: "gitleaks",
      ruleId: "stripe-access-token",
      severity: "critical",
      remediationKey: "live-secret-in-source",
    });
    expect(dependencyFinding).toMatchObject({
      sourceTool: "trivy",
      ruleId: "CVE-2024-1234",
      category: "dependency",
      severity: "high",
      remediationKey: "dependency-vulnerability",
    });
    expect(outcome.assessment.rankedActions.map((action) => action.remediation.title)).toEqual([
      "Remove the committed secret",
      "Review the vulnerable dependency",
    ]);
    expect(outcome.assessment.rankedActions.map((action) => action.candidate.findingIds)).toEqual([
      [secretFinding?.id],
      [dependencyFinding?.id],
    ]);

    const dependencyContext = outcome.assessment.findingContextAssessments?.find(
      (context) => context.findingId === dependencyFinding?.id,
    );
    expect(dependencyContext).toMatchObject({
      status: "linked_to_hypothesis",
      coverageState: "checked",
    });
    expect(dependencyContext?.reason).toContain("shares deterministic static candidate");
    expect(dependencyContext?.graphNodeIds.length).toBeGreaterThan(0);
    expect(dependencyContext?.graphEdgeIds.length).toBeGreaterThan(0);
    expect(dependencyContext?.hypothesisIds.length).toBeGreaterThan(0);
    expect(
      outcome.assessment.staticHypotheses?.some(
        (hypothesis) =>
          hypothesis.title ===
          "Vulnerable component is imported, used, or reachable in the dependency graph",
      ),
    ).toBe(true);

    const report = JSON.parse(await readFile(outcome.reportPaths.json ?? "", "utf8")) as {
      assessment: {
        findings: Array<{ id: string; category: string; ruleId: string; severity: string }>;
        findingContextAssessments?: Array<{
          findingId: string;
          status: string;
          reason: string;
        }>;
        rankedActions: Array<{ candidate: { findingIds: string[] } }>;
      };
    };
    expect(report.assessment.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: secretFinding?.id,
          category: "secret",
          ruleId: "stripe-access-token",
          severity: "critical",
        }),
        expect.objectContaining({
          id: dependencyFinding?.id,
          category: "dependency",
          ruleId: "CVE-2024-1234",
          severity: "high",
        }),
      ]),
    );
    expect(report.assessment.findingContextAssessments).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          findingId: dependencyFinding?.id,
          status: "linked_to_hypothesis",
        }),
      ]),
    );
    expect(report.assessment.rankedActions.map((action) => action.candidate.findingIds)).toEqual([
      [secretFinding?.id],
      [dependencyFinding?.id],
    ]);
  });

  it("turns OSV package manifest matches into dependency findings", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(manifestFor(source.path, gate2ManifestFiles()), [], {
        osvVuln: {
          results: [
            {
              target: "package.json",
              packageName: "jsonwebtoken",
              ecosystem: "npm",
              version: "0.4.0",
              dependencyScope: "dependencies",
              vulns: [{ id: "GHSA-xxxx-yyyy-zzzz", modified: "2026-06-01T00:00:00Z" }],
            },
          ],
        },
      }),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    const dependencyFinding = outcome.assessment.findings.find(
      (finding) => finding.sourceTool === "osv",
    );
    expect(dependencyFinding).toMatchObject({
      sourceTool: "osv",
      ruleId: "GHSA-xxxx-yyyy-zzzz",
      category: "dependency",
      severity: "medium",
      metadata: {
        packageName: "jsonwebtoken",
        installedVersion: "0.4.0",
      },
      remediationKey: "dependency-vulnerability",
    });
    expect(dependencyFinding?.locations).toEqual([
      { filePath: "package.json", startLine: 1, endLine: 1 },
    ]);
  });

  it("maps Trivy SBOM language targets back to dependency manifests", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [{ path: "pom.xml", size: 120, sha256: "pom-sha" }]),
        [],
        { trivyVuln: trivyMavenSbomReport() },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    const dependencyFinding = outcome.assessment.findings.find(
      (finding) => finding.ruleId === "CVE-2013-7285",
    );
    expect(dependencyFinding).toMatchObject({
      sourceTool: "trivy",
      category: "dependency",
      severity: "critical",
      metadata: {
        packageName: "com.thoughtworks.xstream:xstream",
        installedVersion: "1.4.5",
      },
    });
    expect(dependencyFinding?.locations).toEqual([
      { filePath: "pom.xml", startLine: 1, endLine: 1 },
    ]);
  });

  it("uses Trivy SBOM package graph evidence for dependency reachability", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          ...gate2ManifestFiles(),
          { path: "pom.xml", size: 120, sha256: "pom-sha" },
        ]),
        [],
        { joern: { mode: "success" }, trivyVuln: trivyMavenSbomReport() },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
      deep: true,
    });

    const dependencyFinding = outcome.assessment.findings.find(
      (finding) => finding.ruleId === "CVE-2013-7285",
    );
    const dependencyContext = outcome.assessment.findingContextAssessments?.find(
      (context) => context.findingId === dependencyFinding?.id,
    );

    expect(dependencyContext).toMatchObject({
      status: "linked_to_hypothesis",
      coverageState: "checked",
    });
    expect(dependencyContext?.hypothesisIds.length).toBeGreaterThan(0);
    expect(
      outcome.assessment.deepCoverage?.find((area) => area.area === "dependency_usage"),
    ).toMatchObject({
      state: "checked",
      coveredCount: 1,
      totalCount: 1,
    });
  });

  it("uses Trivy package-list evidence when a Go SBOM omits dependency edges", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          ...deepManifestFiles(),
          { path: "go.mod", size: 120, sha256: "gomod-sha" },
          { path: "go.sum", size: 300, sha256: "gosum-sha" },
        ]),
        [],
        { joern: { mode: "success" }, trivyVuln: trivyGoPackageListReport() },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
      deep: true,
    });

    const dependencyFinding = outcome.assessment.findings.find(
      (finding) => finding.ruleId === "CVE-2024-24786",
    );
    const dependencyContext = outcome.assessment.findingContextAssessments?.find(
      (context) => context.findingId === dependencyFinding?.id,
    );

    expect(dependencyFinding).toMatchObject({
      metadata: {
        packageName: "google.golang.org/protobuf",
        installedVersion: "v1.24.0",
      },
      locations: [{ filePath: "go.sum", startLine: 1, endLine: 1 }],
    });
    expect(dependencyContext).toMatchObject({
      status: "linked_to_hypothesis",
      coverageState: "checked",
    });
    expect(
      outcome.assessment.deepCoverage?.find((area) => area.area === "dependency_usage"),
    ).toMatchObject({
      state: "checked",
      coveredCount: 1,
      totalCount: 1,
    });
  });

  it("keeps deterministic Deep Static facts stable when model enrichment is enabled", async () => {
    const source = await writeLocalFixture(dir);
    const modelOff = await runGate4DeepScan(dir, source, new NullModelProvider());
    const model = new FakeModelProvider(
      () => null,
      (input) =>
        input.hypotheses.map((hypothesis) => modelHypothesisOutput(hypothesis.hypothesisId)),
    );
    const modelOn = await runGate4DeepScan(dir, source, model);

    expect(model.hypothesisInputs.map((input) => input.hypotheses.length)).toEqual([1]);
    expect(deepDeterministicProjection(modelOn.assessment)).toEqual(
      deepDeterministicProjection(modelOff.assessment),
    );
    expect(
      modelOff.assessment.hypothesisEnrichments?.every((item) => item.source === "catalog"),
    ).toBe(true);
    expect(modelOn.assessment.hypothesisEnrichments?.every((item) => item.source === "model")).toBe(
      true,
    );
    expect(modelOn.assessment.hypothesisEnrichments?.[0]?.attackDescription).toContain(
      "Model attack description",
    );

    const report = JSON.parse(await readFile(modelOn.reportPaths.json ?? "", "utf8")) as {
      assessment: SecurityAssessment;
    };
    expect(deepDeterministicProjection(report.assessment)).toEqual(
      deepDeterministicProjection(modelOff.assessment),
    );
    expect(report.assessment.hypothesisEnrichments?.[0]).toMatchObject({
      source: "model",
      attackDescription: expect.stringContaining("Model attack description"),
    });

    const markdown = await readFile(modelOn.reportPaths.markdown ?? "", "utf8");
    expect(markdown).toContain("## Fix these first");
    expect(markdown).toContain("## Likely attack paths");
    expect(markdown).toContain("## What was checked");
    expect(markdown).toContain("Model attack description");

    const html = await readFile(modelOn.reportPaths.html ?? "", "utf8");
    expect(html).toContain("<h2>Fix these first</h2>");
    expect(html).toContain("<h2>Likely attack paths</h2>");
    expect(html).toContain("What was checked");
    expect(html).toContain("Model attack description");
  });

  it("falls back to deterministic hypothesis enrichment for invalid model output", async () => {
    const source = await writeLocalFixture(dir);
    const model = new FakeModelProvider(
      () => null,
      (input) =>
        input.hypotheses.map((hypothesis) => ({
          ...modelHypothesisOutput(hypothesis.hypothesisId),
          attackDescription: "Runtime confirmed exploit.",
        })),
    );

    const outcome = await runGate4DeepScan(dir, source, model);

    expect(model.hypothesisInputs.map((input) => input.hypotheses.length)).toEqual([1]);
    expect(outcome.assessment.staticHypotheses?.length).toBeGreaterThan(0);
    expect(
      outcome.assessment.hypothesisEnrichments?.every((item) => item.source === "catalog"),
    ).toBe(true);
    expect(outcome.assessment.hypothesisEnrichments?.[0]?.attackDescription).not.toContain(
      "Runtime confirmed exploit",
    );
  });

  it("keeps the Quick Scan Fix Pack when Deep Static backend analysis fails", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path),
        [
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
        ],
        { joern: { mode: "fail" } },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
      deep: true,
    });

    expect(outcome.assessment.verdict).toBe("critical-fix-needed");
    expect(outcome.assessment.rankedActions).toHaveLength(1);
    expect(outcome.reportPaths.repositoryMap).toBeDefined();
    expect(
      outcome.assessment.deepCoverage?.some(
        (entry) =>
          entry.state === "failed" && entry.reason?.includes("Deep Static program analysis failed"),
      ),
    ).toBe(true);
    expect(
      outcome.assessment.staticHypotheses?.some(
        (hypothesis) => hypothesis.status === "statically_supported",
      ),
    ).toBe(false);
  });

  it("keeps partial Deep Static results when Joern data-flow extraction times out", async () => {
    const source = await writeLocalFixture(dir);
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, deepManifestFiles()),
        [
          {
            RuleID: "stripe-access-token",
            Description: "Stripe Access Token",
            File: "src/routes/upload.ts",
            StartLine: 10,
            EndLine: 10,
            Secret: PLANTED_SECRET,
            Match: `stripeSecret: "${PLANTED_SECRET}"`,
            Fingerprint: "src/routes/upload.ts:stripe-access-token:10",
          },
        ],
        { joern: { mode: "data-flow-timeout" } },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
      deep: true,
    });

    expect(outcome.assessment.verdict).toBe("not-ready-to-deploy");
    expect(outcome.reportPaths.repositoryMap).toBeDefined();
    expect(
      sandbox.invocations.some(
        (i) =>
          i.command[0] === "vibeshield-joern-extract" &&
          valueAfter(i.command, "--kind") === "flows",
      ),
    ).toBe(true);
    expect(
      sandbox.invocations.filter(
        (i) =>
          i.command[0] === "vibeshield-joern-extract" &&
          valueAfter(i.command, "-o") === JOERN_ENTITIES_SLICE_PATH,
      ),
    ).toHaveLength(1);
    const joernInvocations = sandbox.invocations.filter(
      (i) => i.command[0] === "joern-parse" || i.command[0] === "vibeshield-joern-extract",
    );
    expect(
      joernInvocations
        .filter((i) => valueAfter(i.command, "--kind") === "flows")
        .every((i) => i.timeoutMs === 60_000),
    ).toBe(true);
    expect(
      joernInvocations
        .filter((i) => valueAfter(i.command, "--kind") !== "flows")
        .every((i) => i.timeoutMs === 300_000),
    ).toBe(true);
    expect(
      outcome.assessment.deepCoverage?.some(
        (entry) =>
          entry.area === "data_flow" &&
          entry.state === "failed" &&
          entry.reason?.includes("Joern flows command timed out after 1m"),
      ),
    ).toBe(true);
    expect(
      outcome.assessment.deepCoverage?.some(
        (entry) => entry.area === "call_graph" && entry.state !== "failed",
      ),
    ).toBe(true);

    const markdown = await readFile(outcome.reportPaths.markdown ?? "", "utf8");
    expect(markdown).toContain("## Fix these first");
    expect(markdown).toContain("## What was checked");
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
      "dependencies.osv",
      "github-actions.actionlint",
      "github-actions.zizmor",
      "iac.trivy-config",
    ]) {
      expect(coverage.get(check)).toEqual({ check, status: "checked" });
    }
    expect(sandbox.invocations.map((i) => i.command[0])).toEqual(
      expect.arrayContaining([
        "gitleaks",
        "opengrep",
        "syft",
        "trivy",
        "vibeshield-osv-scan",
        "actionlint",
        "zizmor",
      ]),
    );
    expect(sandbox.invocations.filter((i) => i.command[0] === "trivy")).toHaveLength(3);
    expect(
      sandbox.invocations.findIndex((i) => i.command[0] === "trivy" && i.command[1] === "image"),
    ).toBeLessThan(
      sandbox.invocations.findIndex((i) => i.command[0] === "trivy" && i.command[1] === "sbom"),
    );
    expect(
      sandbox.invocations.find(
        (i) => i.command[0] === "vibeshield-osv-scan" && i.command.includes("--source"),
      )?.env,
    ).toEqual({ NODE_OPTIONS: "--dns-result-order=ipv4first" });
  });

  it("suppresses packaged SyntaxHighlighter eval noise without disabling app eval findings", async () => {
    const source = await writeLocalFixture(dir);
    const syntaxHighlighterPath = "template/Karma Shop-doc/syntax-highlighter/scripts/shCore.js";
    const minifiedLibraryPath = "public/static/js/libs/underscore-min.js";
    const sandbox = new FakeSandboxRuntime({
      exec: fakeQuickScanExec(
        manifestFor(source.path, [
          { path: "README.md", size: 10, sha256: "readme-sha" },
          { path: "src/app.js", size: 40, sha256: "app-sha" },
          { path: "src/factory.js", size: 40, sha256: "factory-sha" },
          { path: syntaxHighlighterPath, size: 120, sha256: "syntax-highlighter-sha" },
          { path: minifiedLibraryPath, size: 120, sha256: "minified-library-sha" },
        ]),
        [],
        {
          opengrepSarif: sarifReport([
            sarifResult("vibeshield.javascript-eval", "src/app.js", 4),
            sarifResult("vibeshield.javascript-function-constructor", "src/factory.js", 7),
            sarifResult("vibeshield.javascript-eval", syntaxHighlighterPath, 17),
            sarifResult("vibeshield.javascript-function-constructor", minifiedLibraryPath, 6),
          ]),
        },
      ),
    });

    const outcome = await runScan(deps(sandbox, new FilesystemBlobs(dir)), {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    const evalFindings = outcome.assessment.findings.filter(
      (finding) =>
        finding.ruleId === "vibeshield.javascript-eval" ||
        finding.ruleId === "vibeshield.javascript-function-constructor",
    );
    expect(evalFindings.map((finding) => finding.locations[0]?.filePath)).toEqual([
      "src/app.js",
      "src/factory.js",
    ]);
    expect(coverageByCheck(outcome.assessment.coverage).get("code-patterns.opengrep")).toEqual({
      check: "code-patterns.opengrep",
      status: "checked",
    });
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
    const enhancedDeps = deps(enhancedSandbox, new FilesystemBlobs(dir), enhancedModel);
    const enhanced = await runScan(enhancedDeps, {
      source,
      runRoot: path.join(dir, "runs"),
      toolchainImage: "test-toolchain:latest",
    });

    expect(enhancedModel.inputs).toHaveLength(2);
    expect(enhancedModel.inputs.every((input) => input.actions.length === 1)).toBe(true);
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
    expect(
      enhancedDeps.events.events
        .filter((event) => event.type === "scan-progress")
        .filter((event) => event.stageId === "remediation.generate")
        .map((event) => event.details?.publicLabel),
    ).toEqual(["Writing fixes 0/2", "Writing fixes 1/2", "Writing fixes 2/2"]);
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

async function runGate4DeepScan(
  root: string,
  source: Awaited<ReturnType<typeof writeLocalFixture>>,
  model: ModelProvider,
) {
  const sandbox = new FakeSandboxRuntime({
    exec: fakeQuickScanExec(
      manifestFor(source.path, deepManifestFiles()),
      [
        {
          RuleID: "stripe-access-token",
          Description: "Stripe Access Token",
          File: "src/routes/upload.ts",
          StartLine: 10,
          EndLine: 10,
          Secret: PLANTED_SECRET,
          Match: `stripeSecret: "${PLANTED_SECRET}"`,
          Fingerprint: "src/routes/upload.ts:stripe-access-token:10",
        },
      ],
      { joern: { mode: "success" } },
    ),
  });
  return runScan(deps(sandbox, new FilesystemBlobs(root), model), {
    source,
    runRoot: path.join(root, "runs"),
    toolchainImage: "test-toolchain:latest",
    deep: true,
  });
}

function modelHypothesisOutput(hypothesisId: string): ModelHypothesisEnrichment {
  return {
    hypothesisId,
    attackDescription: `Model attack description for ${hypothesisId}.`,
    assumptions: ["Model assumption from supplied static graph refs."],
    impact: "Model impact explanation.",
    remediation: "Model remediation guidance.",
    agentPrompt: `Model prompt for ${hypothesisId}.`,
    acceptanceCriteria: ["Model acceptance criterion."],
    validationRecipeText: "Model validation recipe text.",
  };
}

function deepDeterministicProjection(assessment: SecurityAssessment) {
  return {
    verdict: assessment.verdict,
    findings: assessment.findings.map((finding) => ({
      id: finding.id,
      sourceTool: finding.sourceTool,
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      fingerprint: finding.fingerprint,
      evidenceIds: [...finding.evidenceIds],
      locations: finding.locations.map((location) => ({ ...location })),
      remediationKey: finding.remediationKey,
    })),
    rankedActions: assessment.rankedActions.map((action) => ({
      candidate: action.candidate,
    })),
    findingContextAssessments: (assessment.findingContextAssessments ?? []).map((context) => ({
      findingId: context.findingId,
      status: context.status,
      graphNodeIds: [...context.graphNodeIds],
      graphEdgeIds: [...context.graphEdgeIds],
      hypothesisIds: [...context.hypothesisIds],
      coverageState: context.coverageState,
    })),
    hypothesisCandidates: (assessment.hypothesisCandidates ?? []).map((candidate) => ({
      id: candidate.id,
      ruleId: candidate.ruleId,
      family: candidate.family,
      title: candidate.title,
      findingIds: [...candidate.findingIds],
      supportingNodeIds: [...candidate.supportingNodeIds],
      supportingEdgeIds: [...candidate.supportingEdgeIds],
      contradictingNodeIds: [...candidate.contradictingNodeIds],
      contradictingEdgeIds: [...candidate.contradictingEdgeIds],
      coverageRefs: [...candidate.coverageRefs],
      requiredValidation: [...candidate.requiredValidation],
    })),
    staticHypotheses: (assessment.staticHypotheses ?? []).map((hypothesis) => ({
      id: hypothesis.id,
      candidateId: hypothesis.candidateId,
      status: hypothesis.status,
      staticConfidence: hypothesis.staticConfidence,
      title: hypothesis.title,
      supportingEvidenceIds: [...hypothesis.supportingEvidenceIds],
      contradictingEvidenceIds: [...hypothesis.contradictingEvidenceIds],
      coverageState: hypothesis.coverageState,
      runtimeValidationRequired: hypothesis.runtimeValidationRequired,
    })),
    validationRecipes: (assessment.validationRecipes ?? []).map((recipe) => ({
      id: recipe.id,
      hypothesisId: recipe.hypothesisId,
      requiredFixtures: [...recipe.requiredFixtures],
      expectedResult: recipe.expectedResult,
    })),
    deepActionGroups: (assessment.deepActionGroups ?? []).map((group) => ({
      id: group.id,
      leadKind: group.leadKind,
      remediationKey: group.remediationKey,
      priorityScore: group.priorityScore,
      verdictImpact: group.verdictImpact,
      directActionIds: [...group.directActionIds],
      findingIds: [...group.findingIds],
      hypothesisIds: [...group.hypothesisIds],
      evidenceIds: [...group.evidenceIds],
      affectedFiles: [...group.affectedFiles],
    })),
    repositoryMapArtifactRole: assessment.repositoryMapArtifactRef?.role,
  };
}

interface FakeScannerOverrides {
  readonly opengrepSarif?: unknown;
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
  readonly trivyVuln?: unknown;
  readonly osvVuln?: unknown;
  readonly joern?: {
    readonly mode: "success" | "fail" | "data-flow-timeout";
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
    if (bin === "vibeshield-osv-scan" && command[1] === "--help") {
      return { exitCode: 0, stdout: "usage: vibeshield-osv-scan\n", stderr: "" };
    }
    if (bin === "gitleaks") {
      session.files.set(GITLEAKS_REPORT_PATH, jsonBytes(gitleaksRecords));
      return { exitCode: gitleaksRecords.length > 0 ? 1 : 0, stdout: "", stderr: "" };
    }
    if (bin === "opengrep") {
      session.files.set(
        OPENGREP_REPORT_PATH,
        jsonBytes(overrides.opengrepSarif ?? { version: "2.1.0", runs: [{ results: [] }] }),
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
    if (bin === "trivy" && command[1] === "sbom" && command.includes("vuln")) {
      if (overrides.trivyVuln !== undefined) {
        session.files.set(TRIVY_VULN_REPORT_PATH, jsonBytes(overrides.trivyVuln));
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    }
    if (bin === "vibeshield-osv-scan") {
      session.files.set(OSV_VULN_REPORT_PATH, jsonBytes(overrides.osvVuln ?? { results: [] }));
      return { exitCode: 0, stdout: "", stderr: "" };
    }
    if (bin === "actionlint" && command[1] !== "-version") {
      return overrides.actionlint ?? { exitCode: 0, stdout: "[]", stderr: "" };
    }
    if (bin === "zizmor" && command[1] !== "--version") {
      return overrides.zizmor ?? { exitCode: 0, stdout: "[]", stderr: "" };
    }
    if (bin === "joern-parse" && overrides.joern !== undefined) {
      if (overrides.joern.mode === "fail") {
        return { exitCode: 2, stdout: "", stderr: "joern crashed" };
      }
      writeJoernOutput(command, session);
      return { exitCode: 0, stdout: "", stderr: "" };
    }
    if (bin === "vibeshield-joern-extract" && overrides.joern !== undefined) {
      if (
        overrides.joern.mode === "data-flow-timeout" &&
        valueAfter(command, "--kind") === "flows"
      ) {
        return { exitCode: 124, stdout: "", stderr: "" };
      }
      writeJoernOutput(command, session);
      return { exitCode: 0, stdout: "", stderr: "" };
    }
    return { exitCode: 0, stdout: "", stderr: "" };
  };
}

function writeJoernOutput(command: string[], session: Parameters<FakeExecHandler>[1]): void {
  if (command[0] === "joern-parse") {
    session.files.set(JOERN_MODEL_PATH, encoder.encode("fake joern cpg"));
    return;
  }
  const slicePath = valueAfter(command, "-o");
  if (slicePath === undefined) {
    return;
  }
  const slices =
    slicePath === JOERN_FLOWS_SLICE_PATH
      ? { graph: { nodes: [], edges: [] }, paths: [["source", "sink"]] }
      : positiveJoernSlices();
  session.files.set(slicePath, jsonBytes(slices));
}

function valueAfter(command: ReadonlyArray<string>, flag: string): string | undefined {
  const index = command.indexOf(flag);
  return index < 0 ? undefined : command[index + 1];
}

function positiveJoernSlices() {
  return {
    objectSlices: [
      {
        fullName: "src/routes/upload.ts::program:uploadHandler",
        fileName: "src/routes/upload.ts",
        lineNumber: 10,
        boundary: {
          boundaryType: "HTTP route",
          routeOrName: "POST /upload",
          method: "POST",
          sourceName: "req.query.url",
        },
        usages: [
          {
            targetObj: {
              name: "fetchUrl",
              resolvedMethod: "src/lib/fetch.ts::program:fetchUrl",
              label: "CALL",
              lineNumber: 12,
            },
          },
        ],
      },
      {
        fullName: "src/lib/fetch.ts::program:fetchUrl",
        fileName: "src/lib/fetch.ts",
        lineNumber: 3,
        usages: [
          {
            targetObj: {
              name: "readFile",
              resolvedMethod: "fs.readFile",
              isExternal: true,
              code: "fs.readFile(filePath)",
              label: "CALL",
              lineNumber: 4,
            },
          },
        ],
      },
    ],
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
  await execFileP("git", ["config", "commit.gpgsign", "false"], { cwd: sourcePath });
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

function sarifReport(results: ReadonlyArray<unknown>): unknown {
  return { version: "2.1.0", runs: [{ results }] };
}

function sarifResult(ruleId: string, filePath: string, startLine: number): unknown {
  return {
    ruleId,
    level: "warning",
    message: { text: "Avoid eval on application-controlled data." },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: filePath },
          region: { startLine },
        },
      },
    ],
  };
}

function deepManifestFiles(): Manifest["files"] {
  return [
    { path: "README.md", size: 10, sha256: "readme-sha" },
    { path: "src/routes/upload.ts", size: 120, sha256: "route-sha" },
    { path: "src/lib/fetch.ts", size: 90, sha256: "fetch-sha" },
  ];
}

function gate2ManifestFiles(): Manifest["files"] {
  return [...deepManifestFiles(), { path: "package.json", size: 60, sha256: "package-sha" }];
}

function trivyDependencyReport() {
  return {
    Results: [
      {
        Target: "package.json",
        Packages: [
          {
            ID: "fixture-app",
            Name: "fixture-app",
            Relationship: "root",
            DependsOn: ["lodash@4.17.20"],
          },
          {
            ID: "lodash@4.17.20",
            Name: "lodash",
            Version: "4.17.20",
            Relationship: "direct",
          },
        ],
        Vulnerabilities: [
          {
            VulnerabilityID: "CVE-2024-1234",
            PkgName: "lodash",
            InstalledVersion: "4.17.20",
            FixedVersion: "4.17.21",
            Severity: "HIGH",
            Title: "lodash prototype pollution",
            Description: "fixture vulnerability",
          },
        ],
      },
    ],
  };
}

function trivyMavenSbomReport() {
  return {
    Results: [
      {
        Target: "Java",
        Class: "lang-pkgs",
        Type: "jar",
        Packages: [
          {
            ID: "org.owasp.webgoat:webgoat:2026.2-SNAPSHOT",
            Name: "org.owasp.webgoat:webgoat",
            Identifier: {
              PURL: "pkg:maven/org.owasp.webgoat/webgoat@2026.2-SNAPSHOT",
            },
            Version: "2026.2-SNAPSHOT",
            DependsOn: ["com.thoughtworks.xstream:xstream:1.4.5"],
          },
          {
            ID: "com.thoughtworks.xstream:xstream:1.4.5",
            Name: "com.thoughtworks.xstream:xstream",
            Identifier: {
              PURL: "pkg:maven/com.thoughtworks.xstream/xstream@1.4.5",
            },
            Version: "1.4.5",
          },
        ],
        Vulnerabilities: [
          {
            VulnerabilityID: "CVE-2013-7285",
            PkgName: "com.thoughtworks.xstream:xstream",
            PkgIdentifier: {
              PURL: "pkg:maven/com.thoughtworks.xstream/xstream@1.4.5",
            },
            InstalledVersion: "1.4.5",
            FixedVersion: "1.4.7",
            Severity: "CRITICAL",
            Title: "XStream remote code execution",
          },
        ],
      },
    ],
  };
}

function trivyGoPackageListReport() {
  return {
    Results: [
      {
        Target: "",
        Class: "lang-pkgs",
        Type: "gobinary",
        Packages: [
          {
            ID: "google.golang.org/protobuf@v1.24.0",
            Name: "google.golang.org/protobuf",
            Identifier: {
              PURL: "pkg:golang/google.golang.org/protobuf@v1.24.0",
            },
            Version: "v1.24.0",
          },
        ],
        Vulnerabilities: [
          {
            VulnerabilityID: "CVE-2024-24786",
            PkgName: "google.golang.org/protobuf",
            PkgIdentifier: {
              PURL: "pkg:golang/google.golang.org/protobuf@v1.24.0",
            },
            InstalledVersion: "v1.24.0",
            FixedVersion: "1.33.0",
            Severity: "HIGH",
            Title: "protobuf protojson denial of service",
          },
        ],
      },
    ],
  };
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
  readonly hypothesisInputs: ModelHypothesisEnrichBatchInput[] = [];

  constructor(
    private readonly responder: (
      input: ModelEnhanceBatchInput,
    ) => ReadonlyArray<RemediationAction> | null,
    private readonly hypothesisResponder: (
      input: ModelHypothesisEnrichBatchInput,
    ) => ReadonlyArray<ModelHypothesisEnrichment> | null = () => null,
  ) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async enhance(input: ModelEnhanceBatchInput): Promise<ReadonlyArray<RemediationAction> | null> {
    this.inputs.push(input);
    return this.responder(input);
  }

  async enrichHypotheses(
    input: ModelHypothesisEnrichBatchInput,
  ): Promise<ReadonlyArray<ModelHypothesisEnrichment> | null> {
    this.hypothesisInputs.push(input);
    return this.hypothesisResponder(input);
  }
}
