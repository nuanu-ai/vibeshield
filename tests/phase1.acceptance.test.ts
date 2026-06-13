import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type {
  BaselineSummaryArtifact,
  DataFlowsArtifact,
  EntryPointsArtifact,
  InventoryArtifact,
  PiSemanticEvaluationArtifact,
  ProjectUnderstandingArtifact,
  SensitiveSinksArtifact,
} from "../src/artifacts/contracts.js";
import { ArtifactStore } from "../src/artifacts/store.js";
import { runCli } from "../src/cli/run-cli.js";
import { buildPiContextPack } from "../src/context/step-context-builder.js";
import {
  validateDataFlowsArtifact,
  validateEntryPointsArtifact,
  validateProjectUnderstanding,
  validateSensitiveSinksArtifact,
} from "../src/pi/project-understanding.js";
import { runScan } from "../src/run/run-scan.js";
import type { RunEvent } from "../src/run/types.js";
import { FakeDaytonaSandboxProvider } from "../src/sandbox/fake-daytona.js";

const execFileAsync = promisify(execFile);
const tempRoots: string[] = [];
const fixtureUrl = "https://github.com/vibeshield/phase-one-fixture";
const minimalFixtureUrl = "https://github.com/vibeshield/phase-one-minimal-fixture";

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("Phase 1 acceptance", () => {
  it("TP1.1 produces staged repository mapping artifacts, baseline summary, context pack, and report", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);

    await expectPath(path.join(runDir, "outputs", "inventory.v1.json"));
    await expectPath(path.join(runDir, "outputs", "baseline-summary.v1.json"));
    await expectPath(path.join(runDir, "outputs", "baseline", "syft-sbom.json"));
    await expectPath(path.join(runDir, "outputs", "pi-context-pack.v1.json"));
    await expectPath(path.join(runDir, "outputs", "entry-points.v1.json"));
    await expectPath(path.join(runDir, "outputs", "entry-points-semantic-evaluation.v1.json"));
    await expectPath(path.join(runDir, "outputs", "sensitive-sinks.v1.json"));
    await expectPath(path.join(runDir, "outputs", "sensitive-sinks-semantic-evaluation.v1.json"));
    await expectPath(path.join(runDir, "outputs", "data-flows.v1.json"));
    await expectPath(path.join(runDir, "outputs", "data-flows-semantic-evaluation.v1.json"));
    await expectPath(path.join(runDir, "outputs", "project-understanding.v1.json"));
    await expectPath(
      path.join(runDir, "outputs", "project-understanding-semantic-evaluation.v1.json"),
    );
    await expectPath(path.join(runDir, "outputs", "pi", "entry-points", "progress.jsonl"));
    await expectPath(path.join(runDir, "outputs", "pi", "sensitive-sinks", "progress.jsonl"));
    await expectPath(path.join(runDir, "outputs", "pi", "data-flows", "progress.jsonl"));
    await expectPath(path.join(runDir, "outputs", "pi", "project-understanding", "progress.jsonl"));

    const entryPointsMetadata = await readJson<{
      invocation: { metadata?: { tools?: string[] } };
    }>(path.join(runDir, "outputs", "pi", "entry-points", "metadata.json"));
    expect(entryPointsMetadata.invocation.metadata?.tools).toEqual(["read", "grep", "find", "ls"]);

    const entryPointsEvaluatorMetadata = await readJson<{
      invocation: { metadata?: { tools?: string[] } };
    }>(path.join(runDir, "outputs", "pi", "entry-points-semantic-evaluation", "metadata.json"));
    expect(entryPointsEvaluatorMetadata.invocation.metadata?.tools).toEqual([
      "read",
      "grep",
      "find",
      "ls",
    ]);

    const entryPoints = await readJson<EntryPointsArtifact>(
      path.join(runDir, "outputs", "entry-points.v1.json"),
    );
    expect(entryPoints.entry_points.map((entry) => entry.kind)).toEqual(
      expect.arrayContaining(["http_route", "cli_command", "cron_job", "external_format_parser"]),
    );
    expect(entryPoints.entry_points.find((entry) => entry.id === "ep-http")?.evidence).toContain(
      "src/server.ts:5",
    );

    const sensitiveSinks = await readJson<SensitiveSinksArtifact>(
      path.join(runDir, "outputs", "sensitive-sinks.v1.json"),
    );
    expect(sensitiveSinks.sinks.map((sink) => sink.kind)).toEqual(
      expect.arrayContaining([
        "sql_or_orm_query",
        "filesystem_operation",
        "outbound_http_or_sdk_url",
        "logging",
      ]),
    );

    const dataFlows = await readJson<DataFlowsArtifact>(
      path.join(runDir, "outputs", "data-flows.v1.json"),
    );
    expect(dataFlows.flows.map((flow) => flow.trace_status)).toEqual(
      expect.arrayContaining([
        "direct observed",
        "multi-step inferred",
        "not traced beyond path:line",
        "not established",
      ]),
    );

    const project = await readJson<ProjectUnderstandingArtifact>(
      path.join(runDir, "outputs", "project-understanding.v1.json"),
    );
    expect(project.kind).toBe("project-understanding.v1");
    expect(project.entry_point_groups.flatMap((group) => group.entry_point_ids)).toContain(
      "ep-http",
    );
    expect(project.sensitive_sink_groups.flatMap((group) => group.sensitive_sink_ids)).toContain(
      "sink-db",
    );
    expect(project.data_flow_groups.flatMap((group) => group.flow_ids)).toContain("flow-direct");
    expect(project.fact_gaps.length).toBeGreaterThan(0);

    await expectPath(path.join(runDir, "report.md"));
  });

  it("TP1.1 retries a Pi stage when semantic evaluator rejects the candidate", async () => {
    let collectorAttempts = 0;
    let evaluatorAttempts = 0;
    const progressEvents: RunEvent[] = [];
    const rejectionReason = "Evidence points to an import, not the route declaration.";
    const baseEntryPoints = fakeEntryPoints();
    const baseEntryPoint = baseEntryPoints.entry_points[0];
    if (baseEntryPoint === undefined) {
      throw new Error("Fixture entry-points output must include at least one entry point.");
    }
    const rejectedEntryPoints: EntryPointsArtifact = {
      ...baseEntryPoints,
      entry_points: [
        {
          ...baseEntryPoint,
          evidence: ["src/server.ts:1"],
          id: "ep-http-wrong-evidence",
        },
      ],
    };
    const { provider } = await createProvider({
      piOutputs: {
        "entry-points.v1": () => {
          collectorAttempts += 1;
          return collectorAttempts === 1 ? rejectedEntryPoints : fakeEntryPoints();
        },
        "entry-points.v1:semantic-evaluation": () => {
          evaluatorAttempts += 1;
          return evaluatorAttempts === 1
            ? fakeSemanticEvaluation({
                accepted: false,
                attempt_count: evaluatorAttempts,
                issues: [
                  {
                    evidence: ["src/server.ts:1", "src/server.ts:5"],
                    item_id: "ep-http-wrong-evidence",
                    reason: rejectionReason,
                    required_change: "Use the route declaration line.",
                  },
                ],
                stage: "entry-points.v1",
                summary: "Rejecting candidate until route evidence is corrected.",
              })
            : fakeSemanticEvaluation({
                accepted: true,
                attempt_count: evaluatorAttempts,
                stage: "entry-points.v1",
                summary: "Corrected entry-points candidate accepted.",
              });
        },
      },
    });

    const result = await runScan({
      onProgress: (event) => progressEvents.push(event),
      repoUrlInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    expect(collectorAttempts).toBe(2);
    expect(evaluatorAttempts).toBe(2);
    const retryEvent = progressEvents.find(
      (event) =>
        event.stage === "pi" &&
        event.job === "pi-entry-points" &&
        event.type === "pi.semantic_evaluation.rejected",
    );
    expect(retryEvent).toBeDefined();
    expect(retryEvent?.details).toMatchObject({
      attempt: 1,
      next_attempt: 2,
      reason: rejectionReason.replace(/[.!?]+$/u, ""),
      step: "entry-points.v1",
    });
    expect(retryEvent?.message).toContain(rejectionReason.replace(/[.!?]+$/u, ""));

    const runDir = expectRunDir(result);
    const entryPoints = await readJson<EntryPointsArtifact>(
      path.join(runDir, "outputs", "entry-points.v1.json"),
    );
    expect(entryPoints.entry_points.map((entry) => entry.id)).toContain("ep-http");

    const verdict = await readJson<PiSemanticEvaluationArtifact>(
      path.join(runDir, "outputs", "entry-points-semantic-evaluation.v1.json"),
    );
    expect(verdict.accepted).toBe(true);
    expect(verdict.attempt_count).toBe(2);
    expect(verdict.summary).toContain("accepted");
  });

  it("TP1.1 treats semantic evaluator feedback as retryable rejection", async () => {
    let collectorAttempts = 0;
    let evaluatorAttempts = 0;
    const firstCandidate = fakeSensitiveSinks();
    const firstSink = firstCandidate.sinks[0];
    if (firstSink === undefined) {
      throw new Error("Fixture sensitive-sinks output must include at least one sink.");
    }

    const overclaimedCandidate: SensitiveSinksArtifact = {
      ...firstCandidate,
      sinks: [
        {
          ...firstSink,
          id: "sink-overclaim",
          kind: "path_construction",
          operation: "parameter default treated as path construction",
        },
      ],
    };

    const { provider } = await createProvider({
      piOutputs: {
        "sensitive-sinks.v1": () => {
          collectorAttempts += 1;
          return collectorAttempts === 1 ? overclaimedCandidate : fakeSensitiveSinks();
        },
        "sensitive-sinks.v1:semantic-evaluation": () => {
          evaluatorAttempts += 1;
          return evaluatorAttempts === 1
            ? {
                rawText: JSON.stringify({
                  accepted: true,
                  issues: [],
                  missing_coverage: [],
                  overclaims: ["sink-overclaim is an overclaim; evidence shows no path build."],
                  summary: "Candidate needs revision despite the accepted flag.",
                }),
              }
            : fakeSemanticEvaluation({
                accepted: true,
                attempt_count: evaluatorAttempts,
                stage: "sensitive-sinks.v1",
                summary: "Corrected sensitive-sinks candidate accepted.",
              });
        },
      },
    });

    const result = await runScan({
      repoUrlInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    expect(collectorAttempts).toBe(2);
    expect(evaluatorAttempts).toBe(2);

    const verdict = await readJson<PiSemanticEvaluationArtifact>(
      path.join(expectRunDir(result), "outputs", "sensitive-sinks-semantic-evaluation.v1.json"),
    );
    expect(verdict.accepted).toBe(true);
    expect(verdict.attempt_count).toBe(2);
  });

  it("TP1.8 emits concise Pi lifecycle progress without duplicate start events", async () => {
    const { provider } = await createProvider();
    const piEvents: Array<{ job: string | undefined; type: string }> = [];

    const result = await runScan({
      onProgress: (event) => {
        if (event.stage === "pi") {
          piEvents.push({ job: event.job, type: event.type });
        }
      },
      repoUrlInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    expect(
      piEvents.filter(
        (event) => event.job === "pi-entry-points" && event.type === "runner.started",
      ),
    ).toHaveLength(1);
    expect(
      piEvents.some((event) => event.job === "pi-entry-points" && event.type === "pi.starting"),
    ).toBe(false);
  });

  it("TP1.2 keeps untrusted checkout work inside a fresh sandbox and preserves failure diagnostics", async () => {
    const { provider, sandboxRoot } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    expect(provider.createdSandboxIds).toHaveLength(1);
    expect(provider.liveSandboxIds).toHaveLength(0);
    expect(await pathExists(path.join(runDir, "package.json"))).toBe(false);
    expect(await pathExists(path.join(runDir, ".git"))).toBe(false);

    const session = provider.sessions[0];
    expect(session?.repoPath.startsWith(sandboxRoot)).toBe(true);
    expect(session?.repoPath.startsWith(runDir)).toBe(false);
    expect(session?.commands.some((command) => command.stage === "deterministic-baseline")).toBe(
      true,
    );
    expect(session?.commands.some((command) => command.stage === "pi")).toBe(true);

    const failedProvider = (await createProvider({ failAt: "pi" })).provider;
    const failed = await runScan({
      repoUrlInput: fixtureUrl,
      runsRoot,
      sandboxProvider: failedProvider,
    });

    expect(failed.exitCode).toBe(1);
    const failedRunDir = expectRunDir(failed);
    const failedRun = await readJson<{
      artifacts: { baseline_summary?: string; pi_context_pack?: string };
      error: { stage: string; user_message: string };
      sandbox: { cleanup: { deleted: boolean; success: boolean } };
      status: string;
    }>(path.join(failedRunDir, "run.json"));
    expect(failedRun.status).toBe("failed");
    expect(failedRun.error.stage).toBe("pi");
    expect(failedRun.error.user_message).toContain("Pi");
    expect(failedRun.artifacts.baseline_summary).toBe("outputs/baseline-summary.v1.json");
    expect(failedRun.artifacts.pi_context_pack).toBe("outputs/pi-context-pack.v1.json");
    expect(failedRun.sandbox.cleanup).toMatchObject({ deleted: true, success: true });
  });

  it("TP1.3 routes baseline tools in order and records normalized conditional skips", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });
    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);

    const baseline = await readJson<BaselineSummaryArtifact>(
      path.join(runDir, "outputs", "baseline-summary.v1.json"),
    );
    expect(baseline.summary.tool_order).toEqual([
      "syft",
      "trivy",
      "gitleaks",
      "actionlint",
      "zizmor",
      "checkov",
    ]);
    expect(baseline.tools.map((tool) => tool.tool)).toEqual(baseline.summary.tool_order);
    expect(baseline.tools.find((tool) => tool.tool === "syft")?.artifacts).toContain(
      "outputs/baseline/syft-sbom.json",
    );
    await expectPath(path.join(runDir, "outputs", "baseline", "tool-availability.v1.json"));
    expect(
      baseline.tools.find((tool) => tool.tool === "trivy")?.invocation.args?.join(" "),
    ).toContain("sbom");
    expect(baseline.tools.find((tool) => tool.tool === "actionlint")?.status).toBe("completed");
    expect(baseline.tools.find((tool) => tool.tool === "checkov")?.status).toBe("completed");

    const minimal = await createProvider({ minimal: true });
    const minimalResult = await runScan({
      repoUrlInput: minimalFixtureUrl,
      runsRoot,
      sandboxProvider: minimal.provider,
    });
    expect(minimalResult.exitCode).toBe(0);
    const minimalRunDir = expectRunDir(minimalResult);
    const minimalBaseline = await readJson<BaselineSummaryArtifact>(
      path.join(minimalRunDir, "outputs", "baseline-summary.v1.json"),
    );
    expect(minimalBaseline.tools.find((tool) => tool.tool === "actionlint")?.status).toBe(
      "skipped",
    );
    expect(minimalBaseline.tools.find((tool) => tool.tool === "zizmor")?.skipped_reason).toContain(
      "No GitHub Actions",
    );
    expect(minimalBaseline.tools.find((tool) => tool.tool === "checkov")?.skipped_reason).toContain(
      "No IaC",
    );
  });

  it("AC1.4 records unavailable required baseline tools and still completes project understanding", async () => {
    const { provider } = await createProvider({ unavailableTools: ["syft"] });
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    const run = await readJson<{
      artifacts: {
        baseline_summary?: string;
        baseline_tool_availability?: string;
        project_understanding?: string;
      };
      status: string;
    }>(path.join(runDir, "run.json"));
    expect(run.status).toBe("success");
    expect(run.artifacts.project_understanding).toBe("outputs/project-understanding.v1.json");
    expect(run.artifacts.baseline_summary).toBe("outputs/baseline-summary.v1.json");
    expect(run.artifacts.baseline_tool_availability).toBe(
      "outputs/baseline/tool-availability.v1.json",
    );

    const availability = await readJson<{
      tools: Array<{ status: string; tool: string }>;
    }>(path.join(runDir, "outputs", "baseline", "tool-availability.v1.json"));
    expect(availability.tools.find((tool) => tool.tool === "syft")?.status).toBe("failed");

    const baseline = await readJson<BaselineSummaryArtifact>(
      path.join(runDir, "outputs", "baseline-summary.v1.json"),
    );
    expect(baseline.tools.find((tool) => tool.tool === "syft")?.status).toBe("failed");
    expect(baseline.tools.find((tool) => tool.tool === "trivy")?.status).toBe("completed");
  });

  it("AC1.4 still allows conditional no-surface skips when conditional tools are unavailable", async () => {
    const minimal = await createProvider({
      minimal: true,
      unavailableTools: ["actionlint", "zizmor", "checkov"],
    });
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({
      repoUrlInput: minimalFixtureUrl,
      runsRoot,
      sandboxProvider: minimal.provider,
    });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    const availability = await readJson<{
      tools: Array<{ skipped_reason?: string; status: string; tool: string }>;
    }>(path.join(runDir, "outputs", "baseline", "tool-availability.v1.json"));
    expect(availability.tools.find((tool) => tool.tool === "actionlint")?.status).toBe(
      "not_required",
    );
    expect(availability.tools.find((tool) => tool.tool === "zizmor")?.skipped_reason).toContain(
      "No GitHub Actions",
    );
    expect(availability.tools.find((tool) => tool.tool === "checkov")?.skipped_reason).toContain(
      "No IaC",
    );
  });

  it("AC1.4 records missing conditional tooling with a detected surface without stopping the run", async () => {
    const { provider } = await createProvider({ unavailableTools: ["checkov"] });
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    const run = await readJson<{ artifacts: { project_understanding?: string }; status: string }>(
      path.join(runDir, "run.json"),
    );
    expect(run.status).toBe("success");
    expect(run.artifacts.project_understanding).toBe("outputs/project-understanding.v1.json");

    const baseline = await readJson<BaselineSummaryArtifact>(
      path.join(runDir, "outputs", "baseline-summary.v1.json"),
    );
    const checkov = baseline.tools.find((tool) => tool.tool === "checkov");
    expect(checkov?.status).toBe("failed");
    expect(checkov?.diagnostics.join("\n")).toContain("checkov");
  });

  it("TP1.4 builds curated Pi context from validated artifacts and fails before Pi on invalid input", async () => {
    const root = await createTempRoot("vibeshield-context-");
    const store = new ArtifactStore(root, path.join(root, "outputs"));
    const inventory = fakeInventory();
    const baseline = fakeBaselineSummary();

    await store.writeJson({
      data: inventory,
      id: "inventory",
      kind: "inventory.v1",
      relativePath: "outputs/inventory.v1.json",
      version: 1,
    });
    await store.writeJson({
      data: baseline,
      id: "baseline-summary",
      kind: "baseline-summary.v1",
      relativePath: "outputs/baseline-summary.v1.json",
      version: 1,
    });
    store.register({
      id: "raw-scanner-dump",
      kind: "diagnostic-log",
      path: "outputs/baseline/gitleaks/raw.json",
    });

    const { contextPack, contextPath } = await buildPiContextPack({
      baseline,
      inventory,
      store,
    });

    expect(contextPath).toBe("outputs/pi-context-pack.v1.json");
    expect(Object.keys(contextPack).sort()).toEqual(["budget", "inventory", "repo"]);
    expect(JSON.stringify(contextPack)).not.toContain("sk-test-secret-value");
    expect(JSON.stringify(contextPack)).not.toContain("raw-scanner-dump");
    expect(JSON.stringify(contextPack)).not.toContain("baseline-summary");
    expect(JSON.stringify(contextPack)).not.toContain("gitleaks");
    expect(contextPack.inventory.candidate_entrypoints).toContain("src/server.ts");

    await expect(
      buildPiContextPack({
        baseline,
        inventory: { ...inventory, kind: "wrong" } as unknown as InventoryArtifact,
        store,
      }),
    ).rejects.toMatchObject({ stage: "context" });
  });

  it("TP1.5 accepts only evidence-backed staged Pi artifacts", () => {
    const entryPoints = fakeEntryPoints();
    const sensitiveSinks = fakeSensitiveSinks();
    const dataFlows = fakeDataFlows();
    const projectUnderstanding = fakeProjectUnderstanding();
    const budget = fakePiBudget();
    const inventory = fakeInventory();

    expect(() =>
      validateEntryPointsArtifact({
        artifact: entryPoints,
        budget,
        inventory,
      }),
    ).not.toThrow();
    expect(() =>
      validateSensitiveSinksArtifact({
        artifact: sensitiveSinks,
        budget,
        inventory,
      }),
    ).not.toThrow();
    expect(() =>
      validateDataFlowsArtifact({
        artifact: dataFlows,
        budget,
        entryPoints,
        inventory,
        sensitiveSinks,
      }),
    ).not.toThrow();
    expect(() =>
      validateProjectUnderstanding({
        artifact: projectUnderstanding,
        budget,
        dataFlows,
        entryPoints,
        inventory,
        sensitiveSinks,
      }),
    ).not.toThrow();
  });

  it("TP1.6 rejects hallucinated paths, invalid JSON, raw secrets, and over-budget output", async () => {
    const budget = fakePiBudget();
    const inventory = fakeInventory();
    const entryPoints = fakeEntryPoints();
    const firstEntryPoint = entryPoints.entry_points[0];
    if (firstEntryPoint === undefined) {
      throw new Error("Expected fake entry point fixture to contain at least one entry.");
    }
    const sensitiveSinks = fakeSensitiveSinks();
    const firstSensitiveSink = sensitiveSinks.sinks[0];
    if (firstSensitiveSink === undefined) {
      throw new Error("Expected fake sensitive sink fixture to contain at least one sink.");
    }
    const dataFlows = fakeDataFlows();

    expect(() =>
      validateEntryPointsArtifact({
        artifact: {
          ...entryPoints,
          entry_points: [
            {
              ...firstEntryPoint,
              evidence: ["src/not-real.ts:1"],
              location: "src/not-real.ts",
            },
          ],
        },
        budget,
        inventory,
      }),
    ).toThrow(/Evidence path/);

    expect(() =>
      validateProjectUnderstanding({
        artifact: {
          ...fakeProjectUnderstanding(),
          summary: {
            confidence: "medium",
            evidence: ["package.json:1"],
            project_kind: "backend-api",
            text: "api_key=sk-test-secret-value",
          },
        },
        budget,
        dataFlows,
        entryPoints,
        inventory,
        sensitiveSinks,
      }),
    ).toThrow(/secret-like/);

    const overBudget = fakeProjectUnderstanding();
    overBudget.fact_gaps = Array.from({ length: 11 }, (_, index) => ({
      area: `Area ${index}`,
      evidence: ["src/routes/api.ts:1"],
      missing_fact: `Missing fact ${index}`,
    }));
    expect(() =>
      validateProjectUnderstanding({
        artifact: overBudget,
        budget,
        dataFlows,
        entryPoints,
        inventory,
        sensitiveSinks,
      }),
    ).toThrow(/fact_gaps exceeds budget/);

    const provider = (
      await createProvider({
        piOutputs: {
          "entry-points.v1": { rawText: "not valid json" },
        },
      })
    ).provider;
    const result = await runScan({
      repoUrlInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });
    expect(result.exitCode).toBe(1);
    const run = await readJson<{
      artifacts: { baseline_summary?: string; entry_points?: string; pi_context_pack?: string };
      error: { stage: string };
      steps: Array<{ jobs: Array<{ artifacts: string[]; name: string }> }>;
    }>(path.join(expectRunDir(result), "run.json"));
    expect(run.error.stage).toBe("entry-points-validation");
    expect(run.artifacts.baseline_summary).toBe("outputs/baseline-summary.v1.json");
    expect(run.artifacts.pi_context_pack).toBe("outputs/pi-context-pack.v1.json");
    expect(run.artifacts.entry_points).toBeUndefined();
    expect(run.steps.at(-1)?.jobs[0]?.name).toBe("pi-entry-points");
    expect(run.steps.at(-1)?.jobs[0]?.artifacts).toContain(
      "outputs/pi/entry-points/entry-points.raw.redacted.txt",
    );

    const semanticFailureProvider = (
      await createProvider({
        piOutputs: {
          "sensitive-sinks.v1:semantic-evaluation": fakeSemanticEvaluation({
            accepted: false,
            issues: [
              {
                evidence: ["src/db.ts:2"],
                item_id: firstSensitiveSink.id,
                reason: "Evaluator could not confirm the candidate sink claim from evidence.",
                required_change: "Revise the sensitive sink artifact with supporting evidence.",
              },
            ],
            stage: "sensitive-sinks.v1",
            summary: "Sensitive sinks candidate rejected by semantic evaluator.",
          }),
        },
      })
    ).provider;
    const semanticFailure = await runScan({
      repoUrlInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: semanticFailureProvider,
    });
    expect(semanticFailure.exitCode).toBe(1);
    const semanticFailureRun = await readJson<{
      artifacts: { entry_points?: string; sensitive_sinks?: string };
      error: { stage: string };
    }>(path.join(expectRunDir(semanticFailure), "run.json"));
    expect(semanticFailureRun.error.stage).toBe("sensitive-sinks-validation");
    expect(semanticFailureRun.artifacts.entry_points).toBe("outputs/entry-points.v1.json");
    expect(semanticFailureRun.artifacts.sensitive_sinks).toBeUndefined();
    await expectPath(
      path.join(
        expectRunDir(semanticFailure),
        "outputs",
        "sensitive-sinks-semantic-evaluation.v1.json",
      ),
    );
  });

  it("TP1.7 builds a human-useful report from artifacts", async () => {
    const { provider } = await createProvider();
    const result = await runScan({
      repoUrlInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    const report = await readFile(path.join(expectRunDir(result), "report.md"), "utf8");
    expect(report).toContain("POST /api/spam");
    expect(report).toContain("src/server.ts:5");
    expect(report).toContain("sql_or_orm_query db.query insert statement");
    expect(report).toContain("ep-http -> sink-db: direct observed");
    expect(report).toContain(
      "Runtime behavior - The route was mapped from source but not executed with a real request.",
    );
    expect(report).toContain("outputs/baseline-summary.v1.json");
    expect(report).toContain("outputs/pi-context-pack.v1.json");
    expect(report).toContain("outputs/entry-points.v1.json");
    expect(report).toContain("outputs/sensitive-sinks.v1.json");
    expect(report).toContain("outputs/data-flows.v1.json");
  });

  it("TP1.8 emits stage-level progress and stores redacted diagnostics", async () => {
    const { provider } = await createProvider({
      projectUnderstandingOutput: () => ({
        ...fakeProjectUnderstanding(),
        summary: {
          ...fakeProjectUnderstanding().summary,
          text: "Repository summary mentions api_key=sk-test-secret-value in a redaction test.",
        },
      }),
    });
    const runsRoot = await createTempRoot("vibeshield-runs-");
    const stdout: string[] = [];
    const stderr: string[] = [];

    const exitCode = await runCli(
      ["scan", fixtureUrl],
      {
        stderr: { write: (chunk: string) => stderr.push(chunk) },
        stdout: { write: (chunk: string) => stdout.push(chunk) },
      },
      { runsRoot, sandboxProvider: provider },
    );

    expect(exitCode).toBe(0);
    expect(stderr.join("")).toBe("");
    expect(stdout.join("")).toContain("[deterministic-baseline]");
    expect(stdout.join("")).toContain("[pi]");
    expect(stdout.join("")).not.toContain("sk-test-secret-value");

    const runDir = stdout.join("").match(/Run directory: (?<runDir>.+)\n/)?.groups?.runDir ?? "";
    const rawPiOutput = await readFile(
      path.join(
        runDir,
        "outputs",
        "pi",
        "project-understanding",
        "project-understanding.raw.redacted.txt",
      ),
      "utf8",
    );
    expect(rawPiOutput).toContain("[REDACTED]");
    expect(rawPiOutput).not.toContain("sk-test-secret-value");
  });

  it("TP1.8 emits concise deterministic baseline lifecycle progress", async () => {
    const fullProvider = (await createProvider()).provider;
    const fullEvents: Array<{ job: string | undefined; type: string }> = [];

    const fullResult = await runScan({
      onProgress: (event) => {
        if (event.stage === "deterministic-baseline") {
          fullEvents.push({ job: event.job, type: event.type });
        }
      },
      repoUrlInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: fullProvider,
    });

    expect(fullResult.exitCode).toBe(0);
    expect(fullEvents.filter((event) => event.job === "trivy").map((event) => event.type)).toEqual([
      "baseline.job.started",
    ]);

    const minimalProvider = (await createProvider({ minimal: true })).provider;
    const minimalEvents: Array<{ job: string | undefined; type: string }> = [];

    const minimalResult = await runScan({
      onProgress: (event) => {
        if (event.stage === "deterministic-baseline") {
          minimalEvents.push({ job: event.job, type: event.type });
        }
      },
      repoUrlInput: minimalFixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: minimalProvider,
    });

    expect(minimalResult.exitCode).toBe(0);
    expect(
      minimalEvents.filter((event) => event.job === "actionlint").map((event) => event.type),
    ).toEqual(["baseline.job.skipped"]);
  });
});

async function createProvider(
  options: {
    failAt?: "baseline" | "clone" | "inventory" | "pi";
    minimal?: boolean;
    piOutputs?: ConstructorParameters<typeof FakeDaytonaSandboxProvider>[0]["piOutputs"];
    projectUnderstandingOutput?: ConstructorParameters<
      typeof FakeDaytonaSandboxProvider
    >[0]["projectUnderstandingOutput"];
    unavailableTools?: ConstructorParameters<
      typeof FakeDaytonaSandboxProvider
    >[0]["unavailableTools"];
  } = {},
) {
  const fixtureRepo = options.minimal
    ? await createMinimalFixtureGitRepo()
    : await createPhase1FixtureGitRepo();
  const sandboxRoot = await createTempRoot("vibeshield-fake-daytona-");
  const providerOptions: ConstructorParameters<typeof FakeDaytonaSandboxProvider>[0] = {
    fixtureRepos: new Map([[options.minimal ? minimalFixtureUrl : fixtureUrl, fixtureRepo]]),
    sandboxRoot,
  };
  const piOutputs = options.minimal
    ? options.piOutputs
    : { ...fixturePiOutputs(), ...(options.piOutputs ?? {}) };
  if (piOutputs !== undefined) {
    providerOptions.piOutputs = piOutputs;
  }
  if (options.failAt !== undefined) {
    providerOptions.failAt = options.failAt;
  }
  if (options.projectUnderstandingOutput !== undefined) {
    providerOptions.projectUnderstandingOutput = options.projectUnderstandingOutput;
    providerOptions.piOutputs = {
      ...(providerOptions.piOutputs ?? {}),
      "project-understanding.v1": options.projectUnderstandingOutput,
    };
  }
  if (options.unavailableTools !== undefined) {
    providerOptions.unavailableTools = options.unavailableTools;
  }
  return {
    fixtureRepo,
    provider: new FakeDaytonaSandboxProvider(providerOptions),
    sandboxRoot,
  };
}

async function createPhase1FixtureGitRepo(): Promise<string> {
  const repoDir = await createTempRoot("vibeshield-phase1-fixture-");
  await mkdir(path.join(repoDir, "src", "jobs"), { recursive: true });
  await mkdir(path.join(repoDir, "src", "parsers"), { recursive: true });
  await mkdir(path.join(repoDir, "src", "routes"), { recursive: true });
  await mkdir(path.join(repoDir, "src", "services"), { recursive: true });
  await mkdir(path.join(repoDir, ".github", "workflows"), { recursive: true });
  await mkdir(path.join(repoDir, "infra"), { recursive: true });
  await writeFile(path.join(repoDir, "README.md"), "# Phase 1 fixture\n");
  await writeFile(
    path.join(repoDir, "package.json"),
    `${JSON.stringify(
      {
        dependencies: { express: "^5.0.0" },
        name: "phase-one-fixture",
        scripts: { build: "node scripts/should-not-run.js" },
      },
      null,
      2,
    )}\n`,
  );
  await writeFile(path.join(repoDir, ".env.example"), "API_BASE_URL=\nSESSION_SECRET=\n");
  await writeFile(
    path.join(repoDir, "src", "server.ts"),
    [
      "import express from 'express';",
      "import { saveMessage } from './db';",
      "const app = express();",
      "app.use(express.json());",
      "app.post('/api/spam', async (req, res) => { await saveMessage(req.body.text); res.json({ ok: true }); });",
      "export { app };",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(repoDir, "src", "cli.ts"),
    [
      "import { Command } from 'commander';",
      "const program = new Command();",
      "program.command('scan').action(() => console.log('scan'));",
      "program.parse();",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(repoDir, "src", "jobs", "cleanup.ts"),
    [
      "import cron from 'node-cron';",
      "import { auditLog } from '../logger';",
      "cron.schedule('0 * * * *', () => auditLog('cleanup'));",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(repoDir, "src", "parsers", "json.ts"),
    ["export function parsePayload(input: string) {", "  return JSON.parse(input);", "}", ""].join(
      "\n",
    ),
  );
  await writeFile(
    path.join(repoDir, "src", "db.ts"),
    [
      "export async function saveMessage(text: string) {",
      "  return db.query('insert into messages values ($1)', [text]);",
      "}",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(repoDir, "src", "files.ts"),
    [
      "import { writeFile } from 'node:fs/promises';",
      "import path from 'node:path';",
      "export async function writeUpload(name: string, body: string) {",
      "  return writeFile(path.join('/tmp/uploads', name), body);",
      "}",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(repoDir, "src", "http.ts"),
    [
      "export async function notifyWebhook(baseUrl: string, id: string) {",
      "  const url = new URL('/hook/' + id, baseUrl);",
      "  return fetch(url);",
      "}",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(repoDir, "src", "logger.ts"),
    ["export function auditLog(value: unknown) {", "  console.log('audit', value);", "}", ""].join(
      "\n",
    ),
  );
  await writeFile(
    path.join(repoDir, "src", "services", "spam.ts"),
    [
      "import { writeUpload } from '../files';",
      "export async function persistSpamReport(name: string, body: string) {",
      "  return writeUpload(name, body);",
      "}",
      "",
    ].join("\n"),
  );
  await writeFile(path.join(repoDir, "src", "routes", "api.ts"), "export const route = '/api';\n");
  await writeFile(
    path.join(repoDir, ".github", "workflows", "ci.yml"),
    "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
  );
  await writeFile(path.join(repoDir, "Dockerfile"), "FROM node:24-alpine\n");
  await writeFile(path.join(repoDir, "infra", "main.tf"), 'resource "null_resource" "demo" {}\n');
  await commitFixture(repoDir);
  return repoDir;
}

async function createMinimalFixtureGitRepo(): Promise<string> {
  const repoDir = await createTempRoot("vibeshield-phase1-minimal-");
  await mkdir(path.join(repoDir, "src"), { recursive: true });
  await writeFile(path.join(repoDir, "README.md"), "# Minimal fixture\n");
  await writeFile(path.join(repoDir, "package.json"), '{"name":"minimal"}\n');
  await writeFile(path.join(repoDir, "src", "app.ts"), "export const app = true;\n");
  await commitFixture(repoDir);
  return repoDir;
}

async function commitFixture(repoDir: string): Promise<void> {
  await execFileAsync("git", ["init"], { cwd: repoDir });
  await execFileAsync("git", ["add", "."], { cwd: repoDir });
  await execFileAsync(
    "git",
    [
      "-c",
      "user.name=VibeShield Test",
      "-c",
      "user.email=vibeshield@example.test",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "-m",
      "fixture",
    ],
    {
      cwd: repoDir,
      env: {
        ...process.env,
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
      },
    },
  );
}

async function createTempRoot(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempRoots.push(dir);
  return dir;
}

async function pathExists(filePath: string): Promise<boolean> {
  try {
    await stat(filePath);
    return true;
  } catch {
    return false;
  }
}

async function expectPath(filePath: string): Promise<void> {
  expect(await pathExists(filePath)).toBe(true);
}

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await readFile(filePath, "utf8")) as T;
}

function expectRunDir(result: { runDir?: string }): string {
  expect(result.runDir).toBeDefined();
  return result.runDir ?? "";
}

function fixturePiOutputs(): NonNullable<
  ConstructorParameters<typeof FakeDaytonaSandboxProvider>[0]["piOutputs"]
> {
  return {
    "data-flows.v1": fakeDataFlows(),
    "entry-points.v1": fakeEntryPoints(),
    "project-understanding.v1": fakeProjectUnderstanding(),
    "sensitive-sinks.v1": fakeSensitiveSinks(),
  };
}

function fakePiBudget() {
  return {
    max_data_flows: 60,
    max_entry_points: 50,
    max_fact_gaps: 10,
    max_important_files: 20,
    max_sensitive_sinks: 80,
  };
}

function fakeInventory(): InventoryArtifact {
  return {
    artifact_version: 1,
    directories: [
      { path: "src" },
      { path: "src/jobs" },
      { path: "src/parsers" },
      { path: "src/routes" },
      { path: "src/services" },
    ],
    files: [
      { line_count: 8, path: "package.json", size_bytes: 100, type: "file" },
      { line_count: 6, path: "src/server.ts", size_bytes: 220, type: "file" },
      { line_count: 4, path: "src/cli.ts", size_bytes: 120, type: "file" },
      { line_count: 3, path: "src/jobs/cleanup.ts", size_bytes: 120, type: "file" },
      { line_count: 3, path: "src/parsers/json.ts", size_bytes: 80, type: "file" },
      { line_count: 3, path: "src/db.ts", size_bytes: 100, type: "file" },
      { line_count: 5, path: "src/files.ts", size_bytes: 140, type: "file" },
      { line_count: 4, path: "src/http.ts", size_bytes: 130, type: "file" },
      { line_count: 3, path: "src/logger.ts", size_bytes: 80, type: "file" },
      { line_count: 4, path: "src/services/spam.ts", size_bytes: 120, type: "file" },
      { line_count: 1, path: "src/routes/api.ts", size_bytes: 30, type: "file" },
      { line_count: 2, path: ".env.example", size_bytes: 24, type: "file" },
    ],
    generated_at: "2026-06-12T00:00:00.000Z",
    generated_by: "vibeshield-phase1",
    kind: "inventory.v1",
    sandbox: {
      id: "fake",
      inventory_location: "inside_sandbox",
    },
    source: {
      commit_sha: "abc123",
      owner: "vibeshield",
      repo: "fixture",
      type: "github",
      url: fixtureUrl,
    },
    summary: {
      directory_count: 5,
      file_count: 11,
      manifest_files: ["package.json"],
      total_file_bytes: 1144,
    },
  };
}

function fakeBaselineSummary(): BaselineSummaryArtifact {
  return {
    artifact_version: 1,
    generated_at: "2026-06-12T00:00:00.000Z",
    kind: "baseline-summary.v1",
    source: {
      commit_sha: "abc123",
      url: fixtureUrl,
    },
    summary: {
      github_actions_workflows: [],
      iac_candidates: [],
      important_paths: ["package.json", "src/server.ts", "src/routes/api.ts"],
      observation_counts: { gitleaks: 1, syft: 1 },
      sbom_artifact: "outputs/baseline/syft-sbom.json",
      tool_order: ["syft", "trivy", "gitleaks", "actionlint", "zizmor", "checkov"],
    },
    tools: [
      {
        artifacts: ["outputs/baseline/syft-sbom.json"],
        diagnostics: ["api_key=sk-test-secret-value"],
        invocation: { command: "syft" },
        observations: [
          {
            confidence: "medium",
            evidence: ["package.json:1"],
            kind: "dependency",
            message: "Dependency manifest present.",
            severity: "info",
          },
        ],
        status: "completed",
        tool: "syft",
        version: "fake",
      },
    ],
  };
}

function fakePiMetadata(step: string): ProjectUnderstandingArtifact["metadata"] {
  return {
    pi: {
      input_context_artifact: "outputs/pi-context-pack.v1.json",
      invocation: { command: "pi", provider: "openrouter" },
      model: "fake",
      provider: "openrouter",
      step,
      version: "fake",
    },
  };
}

function fakeSemanticEvaluation(
  input: Partial<PiSemanticEvaluationArtifact> & {
    accepted: boolean;
    stage: PiSemanticEvaluationArtifact["stage"];
  },
): PiSemanticEvaluationArtifact {
  return {
    accepted: input.accepted,
    artifact_version: 1,
    attempt_count: input.attempt_count ?? 1,
    candidate_kind:
      input.candidate_kind ?? (input.stage as PiSemanticEvaluationArtifact["candidate_kind"]),
    generated_at: input.generated_at ?? "2026-06-12T00:00:00.000Z",
    generated_by: "pi",
    issues: input.issues ?? [],
    kind: "pi-semantic-evaluation.v1",
    missing_coverage: input.missing_coverage ?? [],
    overclaims: input.overclaims ?? [],
    repo: input.repo ?? {
      commit_sha: "abc123",
      url: fixtureUrl,
    },
    stage: input.stage,
    summary:
      input.summary ??
      (input.accepted ? "Fake semantic evaluator accepted." : "Fake semantic evaluator rejected."),
  };
}

function fakeEntryPoints(): EntryPointsArtifact {
  return {
    artifact_version: 1,
    coverage: {
      not_covered: [{ area: "Runtime-registered routes", reason: "Fixture Pi is static only." }],
      reviewed: [
        { area: "HTTP routes", evidence: ["src/server.ts:5"] },
        { area: "CLI commands", evidence: ["src/cli.ts:3"] },
        { area: "Scheduled jobs", evidence: ["src/jobs/cleanup.ts:3"] },
        { area: "External parsers", evidence: ["src/parsers/json.ts:2"] },
      ],
    },
    entry_points: [
      {
        confidence: "high",
        evidence: ["src/server.ts:5"],
        id: "ep-http",
        kind: "http_route",
        location: "src/server.ts",
        method: "POST",
        name: "POST /api/spam",
        route: "/api/spam",
      },
      {
        command: "scan",
        confidence: "high",
        evidence: ["src/cli.ts:3"],
        id: "ep-cli",
        kind: "cli_command",
        location: "src/cli.ts",
        name: "scan command",
      },
      {
        confidence: "high",
        evidence: ["src/jobs/cleanup.ts:3"],
        id: "ep-cron",
        kind: "cron_job",
        location: "src/jobs/cleanup.ts",
        name: "hourly cleanup job",
        schedule: "0 * * * *",
      },
      {
        confidence: "high",
        evidence: ["src/parsers/json.ts:2"],
        id: "ep-parser",
        kind: "external_format_parser",
        location: "src/parsers/json.ts",
        name: "JSON payload parser",
      },
    ],
    generated_at: "2026-06-12T00:00:00.000Z",
    generated_by: "pi",
    kind: "entry-points.v1",
    metadata: fakePiMetadata("entry-points.v1"),
    repo: {
      commit_sha: "abc123",
      url: fixtureUrl,
    },
  };
}

function fakeSensitiveSinks(): SensitiveSinksArtifact {
  return {
    artifact_version: 1,
    coverage: {
      not_covered: [{ area: "Runtime-only operations", reason: "Fixture Pi is static only." }],
      reviewed: [
        { area: "Database operations", evidence: ["src/db.ts:2"] },
        { area: "Filesystem operations", evidence: ["src/files.ts:4"] },
        { area: "Outbound HTTP construction", evidence: ["src/http.ts:3"] },
        { area: "Logging", evidence: ["src/logger.ts:2"] },
      ],
    },
    generated_at: "2026-06-12T00:00:00.000Z",
    generated_by: "pi",
    kind: "sensitive-sinks.v1",
    metadata: fakePiMetadata("sensitive-sinks.v1"),
    repo: {
      commit_sha: "abc123",
      url: fixtureUrl,
    },
    sinks: [
      {
        confidence: "high",
        evidence: ["src/db.ts:2"],
        id: "sink-db",
        input_variables: ["text"],
        kind: "sql_or_orm_query",
        location: "src/db.ts",
        operation: "db.query insert statement",
      },
      {
        confidence: "high",
        evidence: ["src/files.ts:4"],
        id: "sink-fs",
        input_variables: ["name", "body"],
        kind: "filesystem_operation",
        location: "src/files.ts",
        operation: "writeFile path.join write",
      },
      {
        confidence: "high",
        evidence: ["src/http.ts:3"],
        id: "sink-http",
        input_variables: ["baseUrl", "id"],
        kind: "outbound_http_or_sdk_url",
        location: "src/http.ts",
        operation: "fetch URL constructed from variables",
      },
      {
        confidence: "high",
        evidence: ["src/logger.ts:2"],
        id: "sink-log",
        input_variables: ["value"],
        kind: "logging",
        location: "src/logger.ts",
        operation: "console.log audit value",
      },
    ],
  };
}

function fakeDataFlows(): DataFlowsArtifact {
  return {
    artifact_version: 1,
    coverage: {
      not_covered: [{ area: "Runtime request bodies", reason: "Fixture Pi is static only." }],
      reviewed: [
        { area: "HTTP to DB", evidence: ["src/server.ts:5", "src/db.ts:2"] },
        {
          area: "HTTP to filesystem helper",
          evidence: ["src/server.ts:5", "src/services/spam.ts:2", "src/files.ts:4"],
        },
      ],
    },
    flows: [
      {
        id: "flow-direct",
        intermediate_functions: [],
        sink: "sink-db",
        sink_evidence: ["src/db.ts:2"],
        source_entrypoint: "ep-http",
        source_evidence: ["src/server.ts:5"],
        trace_status: "direct observed",
      },
      {
        id: "flow-multi",
        intermediate_functions: [
          { evidence: ["src/services/spam.ts:2"], name: "persistSpamReport" },
        ],
        sink: "sink-fs",
        sink_evidence: ["src/files.ts:4"],
        source_entrypoint: "ep-http",
        source_evidence: ["src/server.ts:5"],
        trace_status: "multi-step inferred",
      },
      {
        breakpoint: { evidence: ["src/cli.ts:3"], reason: "CLI handler target is not followed." },
        id: "flow-break",
        intermediate_functions: [],
        sink: "sink-http",
        sink_evidence: ["src/http.ts:3"],
        source_entrypoint: "ep-cli",
        source_evidence: ["src/cli.ts:3"],
        trace_status: "not traced beyond path:line",
      },
      {
        breakpoint: {
          evidence: ["src/jobs/cleanup.ts:3", "src/logger.ts:2"],
          reason:
            "No data dependency between scheduled job input and logger argument was established.",
        },
        id: "flow-not-established",
        intermediate_functions: [],
        sink: "sink-log",
        sink_evidence: ["src/logger.ts:2"],
        source_entrypoint: "ep-cron",
        source_evidence: ["src/jobs/cleanup.ts:3"],
        trace_status: "not established",
      },
    ],
    generated_at: "2026-06-12T00:00:00.000Z",
    generated_by: "pi",
    inputs: {
      entry_points_artifact: "outputs/entry-points.v1.json",
      sensitive_sinks_artifact: "outputs/sensitive-sinks.v1.json",
    },
    kind: "data-flows.v1",
    metadata: fakePiMetadata("data-flows.v1"),
    repo: {
      commit_sha: "abc123",
      url: fixtureUrl,
    },
  };
}

function fakeProjectUnderstanding(): ProjectUnderstandingArtifact {
  return {
    artifact_version: 1,
    coverage: {
      not_covered: [{ area: "Runtime behavior", reason: "Phase 1 does not execute the app." }],
      reviewed: [{ area: "Prior Pi mapping artifacts", evidence: ["src/server.ts:5"] }],
    },
    data_flow_groups: [
      {
        evidence: ["src/server.ts:5", "src/db.ts:2"],
        flow_ids: ["flow-direct", "flow-multi"],
        name: "HTTP request handling flows",
        summary: "HTTP entrypoints connect to observed DB and filesystem operation sinks.",
        trace_statuses: ["direct observed", "multi-step inferred"],
      },
      {
        evidence: ["src/cli.ts:3", "src/jobs/cleanup.ts:3"],
        flow_ids: ["flow-break", "flow-not-established"],
        name: "Unresolved static traces",
        summary: "Some entrypoint-to-sink relationships remain incomplete in static mapping.",
        trace_statuses: ["not traced beyond path:line", "not established"],
      },
    ],
    entry_point_groups: [
      {
        entry_point_ids: ["ep-http"],
        evidence: ["src/server.ts:5"],
        name: "HTTP API",
        summary: "Express route receives POST /api/spam.",
      },
      {
        entry_point_ids: ["ep-cli", "ep-cron", "ep-parser"],
        evidence: ["src/cli.ts:3", "src/jobs/cleanup.ts:3", "src/parsers/json.ts:2"],
        name: "Non-HTTP entrypoints",
        summary: "CLI, scheduled job, and JSON parser are exposed entry surfaces.",
      },
    ],
    fact_gaps: [
      {
        area: "Runtime behavior",
        evidence: ["src/server.ts:5"],
        missing_fact: "The route was mapped from source but not executed with a real request.",
      },
    ],
    generated_at: "2026-06-12T00:00:00.000Z",
    generated_by: "pi",
    inputs: {
      data_flows_artifact: "outputs/data-flows.v1.json",
      entry_points_artifact: "outputs/entry-points.v1.json",
      sensitive_sinks_artifact: "outputs/sensitive-sinks.v1.json",
    },
    kind: "project-understanding.v1",
    map: {
      components: [
        {
          evidence: ["src/server.ts:5"],
          kind: "backend",
          name: "Express API",
          summary: "HTTP route delegates to application operations.",
        },
      ],
      important_files: [
        {
          evidence: ["package.json:1"],
          path: "package.json",
          reason: "Defines runtime dependencies.",
        },
      ],
    },
    metadata: fakePiMetadata("project-understanding.v1"),
    repo: {
      commit_sha: "abc123",
      url: fixtureUrl,
    },
    sensitive_sink_groups: [
      {
        evidence: ["src/db.ts:2", "src/files.ts:4"],
        name: "Persistence operations",
        sensitive_sink_ids: ["sink-db", "sink-fs"],
        summary: "Database and filesystem operation sinks are present.",
      },
      {
        evidence: ["src/http.ts:3", "src/logger.ts:2"],
        name: "Outbound and diagnostic operations",
        sensitive_sink_ids: ["sink-http", "sink-log"],
        summary: "Outbound URL construction and logging operation sinks are present.",
      },
    ],
    stack: [{ evidence: ["package.json:1"], name: "Node.js", role: "runtime" }],
    summary: {
      confidence: "medium",
      evidence: ["package.json:1"],
      project_kind: "backend-api",
      text: "Fixture Node.js backend API.",
    },
  };
}
