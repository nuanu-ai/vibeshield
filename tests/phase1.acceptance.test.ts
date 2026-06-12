import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type {
  BaselineSummaryArtifact,
  InventoryArtifact,
  ProjectUnderstandingArtifact,
} from "../src/artifacts/contracts.js";
import { ArtifactStore } from "../src/artifacts/store.js";
import { runCli } from "../src/cli/run-cli.js";
import { buildPiContextPack } from "../src/context/step-context-builder.js";
import { validateProjectUnderstanding } from "../src/pi/project-understanding.js";
import { runScan } from "../src/run/run-scan.js";
import { FakeDaytonaSandboxProvider } from "../src/sandbox/fake-daytona.js";

const execFileAsync = promisify(execFile);
const tempRoots: string[] = [];
const fixtureUrl = "https://github.com/vibeshield/phase-one-fixture";
const minimalFixtureUrl = "https://github.com/vibeshield/phase-one-minimal-fixture";

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("Phase 1 acceptance", () => {
  it("TP1.1 produces an inspectable project map, baseline summary, context pack, and report", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);

    await expectPath(path.join(runDir, "outputs", "inventory.v1.json"));
    await expectPath(path.join(runDir, "outputs", "baseline-summary.v1.json"));
    await expectPath(path.join(runDir, "outputs", "baseline", "syft-sbom.json"));
    await expectPath(path.join(runDir, "outputs", "pi-context-pack.v1.json"));
    await expectPath(path.join(runDir, "outputs", "project-understanding.v1.json"));
    await expectPath(path.join(runDir, "outputs", "pi", "progress.jsonl"));

    const project = await readJson<ProjectUnderstandingArtifact>(
      path.join(runDir, "outputs", "project-understanding.v1.json"),
    );
    expect(project.kind).toBe("project-understanding.v1");
    expect(project.map.entrypoints[0]?.evidence[0]).toMatch(/:1$/);
    expect(project.map.observed_surfaces.length).toBeGreaterThan(0);
    expect(project.fact_gaps.length).toBeGreaterThan(0);

    const report = await readFile(path.join(runDir, "report.md"), "utf8");
    expect(report).toContain("Phase 1 project understanding");
    expect(report).toContain("Deterministic baseline overview");
    expect(report).toContain("Entrypoints");
    expect(report).toContain("Fact gaps");
    expect(report).toContain("outputs/project-understanding.v1.json");
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
    expect(Object.keys(contextPack).sort()).toEqual([
      "budget",
      "inventory",
      "output_schema",
      "repo",
    ]);
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

  it("TP1.5 accepts only evidence-backed project-understanding output", () => {
    const artifact = fakeProjectUnderstanding();

    expect(() =>
      validateProjectUnderstanding({
        artifact,
        budget: {
          max_env_entries: 15,
          max_fact_gaps: 10,
          max_important_files: 20,
          max_observed_surfaces: 12,
        },
        inventory: fakeInventory(),
      }),
    ).not.toThrow();
  });

  it("TP1.6 rejects hallucinated paths, invalid JSON shape, raw secrets, and over-budget output", async () => {
    expect(() =>
      validateProjectUnderstanding({
        artifact: {
          ...fakeProjectUnderstanding(),
          map: {
            ...fakeProjectUnderstanding().map,
            entrypoints: [
              {
                evidence: ["src/not-real.ts:1"],
                kind: "server",
                path: "src/not-real.ts",
                summary: "Hallucinated.",
              },
            ],
          },
        },
        budget: {
          max_env_entries: 15,
          max_fact_gaps: 10,
          max_important_files: 20,
          max_observed_surfaces: 12,
        },
        inventory: fakeInventory(),
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
        budget: {
          max_env_entries: 15,
          max_fact_gaps: 10,
          max_important_files: 20,
          max_observed_surfaces: 12,
        },
        inventory: fakeInventory(),
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
        budget: {
          max_env_entries: 15,
          max_fact_gaps: 10,
          max_important_files: 20,
          max_observed_surfaces: 12,
        },
        inventory: fakeInventory(),
      }),
    ).toThrow(/fact_gaps exceeds budget/);

    const provider = (
      await createProvider({
        projectUnderstandingOutput: () => "not a project-understanding object",
      })
    ).provider;
    const result = await runScan({
      repoUrlInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });
    expect(result.exitCode).toBe(1);
    const run = await readJson<{ error: { stage: string } }>(
      path.join(expectRunDir(result), "run.json"),
    );
    expect(run.error.stage).toBe("project-understanding-validation");
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
    expect(report).toContain("Project summary");
    expect(report).toContain("Deterministic baseline overview");
    expect(report).toContain("Entrypoints");
    expect(report).toContain("Important files");
    expect(report).toContain("Observed surfaces");
    expect(report).toContain("Coverage gaps");
    expect(report).toContain("Fact gaps");
    expect(report).toContain("outputs/baseline-summary.v1.json");
    expect(report).toContain("outputs/pi-context-pack.v1.json");
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
      path.join(runDir, "outputs", "pi", "project-understanding.raw.redacted.txt"),
      "utf8",
    );
    expect(rawPiOutput).toContain("[REDACTED]");
    expect(rawPiOutput).not.toContain("sk-test-secret-value");
  });
});

async function createProvider(
  options: {
    failAt?: "baseline" | "clone" | "inventory" | "pi";
    minimal?: boolean;
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
  if (options.failAt !== undefined) {
    providerOptions.failAt = options.failAt;
  }
  if (options.projectUnderstandingOutput !== undefined) {
    providerOptions.projectUnderstandingOutput = options.projectUnderstandingOutput;
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
  await mkdir(path.join(repoDir, "src", "routes"), { recursive: true });
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
  await writeFile(path.join(repoDir, "src", "server.ts"), "import './routes/api';\n");
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

function fakeInventory(): InventoryArtifact {
  return {
    artifact_version: 1,
    directories: [{ path: "src" }, { path: "src/routes" }],
    files: [
      { line_count: 8, path: "package.json", size_bytes: 100, type: "file" },
      { line_count: 1, path: "src/server.ts", size_bytes: 30, type: "file" },
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
      directory_count: 2,
      file_count: 4,
      manifest_files: ["package.json"],
      total_file_bytes: 184,
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

function fakeProjectUnderstanding(): ProjectUnderstandingArtifact {
  return {
    artifact_version: 1,
    coverage: {
      not_covered: [{ area: "Runtime behavior", reason: "Phase 1 does not execute the app." }],
      reviewed: [{ area: "Repository structure", evidence: ["package.json:1"] }],
    },
    env_and_config_surface: [
      {
        evidence: [".env.example:1"],
        name: ".env.example",
        observed_use: "Environment variables are declared for local configuration.",
      },
    ],
    generated_at: "2026-06-12T00:00:00.000Z",
    generated_by: "pi",
    kind: "project-understanding.v1",
    map: {
      entrypoints: [
        {
          evidence: ["src/server.ts:1"],
          kind: "server",
          path: "src/server.ts",
          summary: "Server entrypoint imports API routes.",
        },
      ],
      important_files: [
        {
          evidence: ["package.json:1"],
          path: "package.json",
          reason: "Defines runtime dependencies.",
        },
      ],
      observed_surfaces: [
        {
          evidence: ["src/routes/api.ts:1"],
          kind: "api",
          path: "src/routes/api.ts",
          summary: "API route surface.",
        },
      ],
    },
    metadata: {
      pi: {
        input_context_artifact: "outputs/pi-context-pack.v1.json",
        invocation: { command: "pi", provider: "openrouter" },
        model: "fake",
        provider: "openrouter",
        version: "fake",
      },
    },
    fact_gaps: [
      {
        area: "Runtime behavior",
        evidence: ["src/routes/api.ts:1"],
        missing_fact: "The route was mapped from source but not executed.",
      },
    ],
    repo: {
      commit_sha: "abc123",
      url: fixtureUrl,
    },
    stack: [{ evidence: ["package.json:1"], name: "Node.js", role: "runtime" }],
    summary: {
      confidence: "medium",
      evidence: ["package.json:1"],
      project_kind: "backend-api",
      text: "Fixture Node.js backend API.",
    },
  };
}
