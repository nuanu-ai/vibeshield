import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type {
  AuthConfigSecretsArtifact,
  BaselineSummaryArtifact,
  CoverageStructureArtifact,
  DataFlowsArtifact,
  EntrypointsArtifact,
  InventoryArtifact,
  OperationSinksArtifact,
  RepositoryMapArtifact,
  StackBuildDepsArtifact,
  StorageIntegrationsInfraArtifact,
  TrustBoundariesArtifact,
} from "../src/artifacts/contracts.js";
import { ArtifactStore } from "../src/artifacts/store.js";
import { buildPiContextPack } from "../src/context/step-context-builder.js";
import { runResume, runScan } from "../src/run/run-scan.js";
import { FakeDaytonaSandboxProvider } from "../src/sandbox/fake-daytona.js";

const execFileAsync = promisify(execFile);
type BuildPiContextInput = Parameters<typeof buildPiContextPack>[0];
const tempRoots: string[] = [];
const fixtureUrl = "https://github.com/vibeshield/repository-map-fixture";
const minimalFixtureUrl = "https://github.com/vibeshield/repository-map-minimal-fixture";

const expectedRepoMapArtifacts = [
  "outputs/repo-map/coverage-structure.json",
  "outputs/repo-map/stack-build-deps.json",
  "outputs/repo-map/entrypoints.json",
  "outputs/repo-map/auth-config-secrets.json",
  "outputs/repo-map/storage-integrations-infra.json",
  "outputs/repo-map/operation-sinks.json",
  "outputs/repo-map/data-flows.json",
  "outputs/repo-map/trust-boundaries.json",
  "outputs/repository-map.json",
];

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("AppSec repository map acceptance", () => {
  it("produces complete facts-only repository map artifacts with representative facts", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);

    await expectPath(path.join(runDir, "outputs", "inventory.json"));
    await expectPath(path.join(runDir, "outputs", "baseline-summary.json"));
    await expectPath(path.join(runDir, "outputs", "pi-context-pack.json"));
    for (const artifact of expectedRepoMapArtifacts) {
      await expectPath(path.join(runDir, artifact));
    }

    const entrypoints = await readJson<EntrypointsArtifact>(
      path.join(runDir, "outputs", "repo-map", "entrypoints.json"),
    );
    expect(entrypoints.entrypoints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "entry-http-spam",
          kind: "http_route",
          method: "POST",
          route: "/api/spam",
        }),
      ]),
    );

    const authConfig = await readJson<AuthConfigSecretsArtifact>(
      path.join(runDir, "outputs", "repo-map", "auth-config-secrets.json"),
    );
    expect(authConfig.auth).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "auth-session-middleware",
          kind: "middleware",
        }),
      ]),
    );
    expect(authConfig.config.map((item) => item.name)).toEqual(
      expect.arrayContaining(["API_BASE_URL", "SESSION_SECRET"]),
    );

    const storage = await readJson<StorageIntegrationsInfraArtifact>(
      path.join(runDir, "outputs", "repo-map", "storage-integrations-infra.json"),
    );
    expect(storage.storage.map((item) => item.id)).toEqual(
      expect.arrayContaining(["store-messages-db", "store-upload-filesystem"]),
    );
    expect(storage.integrations.map((item) => item.id)).toContain("integration-webhook-client");
    expect((storage.infra ?? []).map((item) => item.kind)).toEqual(
      expect.arrayContaining(["runtime", "iac", "workflow"]),
    );

    const sinks = await readJson<OperationSinksArtifact>(
      path.join(runDir, "outputs", "repo-map", "operation-sinks.json"),
    );
    expect((sinks.operation_sinks ?? []).map((sink) => sink.kind)).toEqual(
      expect.arrayContaining([
        "crypto_operation",
        "filesystem_operation",
        "logging",
        "outbound_http_or_sdk_url",
        "randomness",
        "sql_or_orm_query",
      ]),
    );

    const dataFlows = await readJson<DataFlowsArtifact>(
      path.join(runDir, "outputs", "repo-map", "data-flows.json"),
    );
    expect(dataFlows.inputs).toMatchObject({
      entrypoints_artifact: "outputs/repo-map/entrypoints.json",
      operation_sinks_artifact: "outputs/repo-map/operation-sinks.json",
    });
    expect(dataFlows.flows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "flow-http-spam-db",
          operation_sink: "sink-db-insert",
          source_entrypoint: "entry-http-spam",
          trace_status: "direct observed",
        }),
      ]),
    );

    const trustBoundaries = await readJson<TrustBoundariesArtifact>(
      path.join(runDir, "outputs", "repo-map", "trust-boundaries.json"),
    );
    expectTrustBoundariesUseKnownFacts({ dataFlows, entrypoints, sinks, trustBoundaries });

    const repositoryMap = await readJson<RepositoryMapArtifact>(
      path.join(runDir, "outputs", "repository-map.json"),
    );
    expect(repositoryMap.sections.map((section) => section.path)).toEqual(
      expect.arrayContaining(expectedRepoMapArtifacts),
    );
  });

  it("renders the original 0-14 repository-map sections and deterministic scanner findings", async () => {
    const { provider } = await createProvider();

    const result = await runScan({
      repoUrlInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    const report = await readFile(path.join(expectRunDir(result), "report.md"), "utf8");
    for (let section = 0; section <= 14; section += 1) {
      expect(report).toMatch(new RegExp(`(^|\\n)#{2,3}\\s+${section}\\.\\s+`));
    }
    expect(report).toContain("CVE-FAKE-0001 in fixture-dependency@1.0.0 fixed in 1.0.1");
    expect(report).toContain("CKV_FAKE_1: Fixture IaC check failed");
    expect(report).toContain("outputs/repo-map/coverage-structure.json");
    expect(report).toContain("outputs/repository-map.json");
  });

  it("keeps untrusted checkout work inside a fresh sandbox and preserves failure diagnostics", async () => {
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
    expect(failedRun.artifacts.baseline_summary).toBe("outputs/baseline-summary.json");
    expect(failedRun.artifacts.pi_context_pack).toBe("outputs/pi-context-pack.json");
    expect(failedRun.sandbox.cleanup).toMatchObject({ deleted: true, success: true });
  });

  it("routes deterministic scanners in order and records findings and conditional skips", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });
    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);

    const baseline = await readJson<BaselineSummaryArtifact>(
      path.join(runDir, "outputs", "baseline-summary.json"),
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
    expect(
      baseline.tools.find((tool) => tool.tool === "trivy")?.invocation.args?.join(" "),
    ).toContain("sbom");
    expect(
      baseline.tools.flatMap((tool) => tool.observations.map((observation) => observation.message)),
    ).toEqual(
      expect.arrayContaining([
        "CVE-FAKE-0001 in fixture-dependency@1.0.0 fixed in 1.0.1",
        "CKV_FAKE_1: Fixture IaC check failed",
      ]),
    );

    const minimal = await createProvider({ minimal: true });
    const minimalResult = await runScan({
      repoUrlInput: minimalFixtureUrl,
      runsRoot,
      sandboxProvider: minimal.provider,
    });
    expect(minimalResult.exitCode).toBe(0);
    const minimalRunDir = expectRunDir(minimalResult);
    const minimalBaseline = await readJson<BaselineSummaryArtifact>(
      path.join(minimalRunDir, "outputs", "baseline-summary.json"),
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

  it("continues to repository mapping when a scanner runtime call fails", async () => {
    const { provider } = await createProvider({ failAt: "baseline" });
    const result = await runScan({
      repoUrlInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    const baseline = await readJson<BaselineSummaryArtifact>(
      path.join(runDir, "outputs", "baseline-summary.json"),
    );
    expect(baseline.tools.find((tool) => tool.tool === "syft")?.status).toBe("failed");
    expect(baseline.tools.find((tool) => tool.tool === "syft")?.diagnostics.join("\n")).toContain(
      "Could not run syft",
    );
    await expectPath(path.join(runDir, "outputs", "repository-map.json"));
    await expectPath(path.join(runDir, "report.md"));
  });

  it("builds curated Pi context from validated artifacts and fails before Pi on invalid input", async () => {
    const root = await createTempRoot("vibeshield-context-");
    const store = new ArtifactStore(root, path.join(root, "outputs"));
    const inventory = fakeInventory();
    const baseline = fakeBaselineSummary();

    await store.writeJson({
      data: inventory,
      id: "inventory",
      kind: "inventory",
      relativePath: "outputs/inventory.json",
    });
    await store.writeJson({
      data: baseline,
      id: "baseline-summary",
      kind: "baseline-summary",
      relativePath: "outputs/baseline-summary.json",
    });
    store.register({
      id: "raw-scanner-dump",
      kind: "diagnostic-log",
      path: "outputs/baseline/gitleaks/raw.json",
    });

    const { contextPack, contextPath } = await buildPiContextPack({
      baseline: baseline as unknown as BuildPiContextInput["baseline"],
      inventory: inventory as unknown as BuildPiContextInput["inventory"],
      store,
    });

    expect(contextPath).toBe("outputs/pi-context-pack.json");
    expect(Object.keys(contextPack).sort()).toEqual(["budget", "inventory", "repo"]);
    expect(JSON.stringify(contextPack)).not.toContain("sk-test-secret-value");
    expect(JSON.stringify(contextPack)).not.toContain("raw-scanner-dump");
    expect(JSON.stringify(contextPack)).not.toContain("baseline-summary");
    expect(JSON.stringify(contextPack)).not.toContain("gitleaks");
    expect(contextPack.inventory.candidate_entrypoints).toContain("src/server.ts");

    await expect(
      buildPiContextPack({
        baseline: baseline as unknown as BuildPiContextInput["baseline"],
        inventory: { ...inventory, kind: "wrong" } as unknown as BuildPiContextInput["inventory"],
        store,
      }),
    ).rejects.toMatchObject({ stage: "context" });
  });

  it("preserves partial map artifacts and resumes from the first missing map section", async () => {
    let dataFlowsAreValid = false;
    const { provider } = await createProvider({
      piOutputs: {
        "data-flows": () =>
          dataFlowsAreValid ? fakeRepoMapDataFlows() : fakeRepoMapDataFlowsWithUnknownIds(),
        "repo-map-data-flows": () =>
          dataFlowsAreValid ? fakeRepoMapDataFlows() : fakeRepoMapDataFlowsWithUnknownIds(),
        "repo-map/data-flows": () =>
          dataFlowsAreValid ? fakeRepoMapDataFlows() : fakeRepoMapDataFlowsWithUnknownIds(),
      },
    });
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const failed = await runScan({
      repoUrlInput: fixtureUrl,
      runsRoot,
      sandboxProvider: provider,
    });

    expect(failed.exitCode).toBe(1);
    const runDir = expectRunDir(failed);
    const failedRunPath = path.join(runDir, "run.json");
    const failedRun = await readJson<{
      artifacts: Record<string, string | undefined>;
      error: { stage: string };
      sandbox: {
        cleanup: {
          attempted: boolean;
          deleted: boolean;
          success: boolean;
        };
        id: string;
      };
    }>(failedRunPath);
    expect(failedRun.error.stage).toContain("data-flows");
    for (const artifact of expectedRepoMapArtifacts.slice(0, 6)) {
      await expectPath(path.join(runDir, artifact));
    }
    expect(await pathExists(path.join(runDir, "outputs", "repo-map", "data-flows.json"))).toBe(
      false,
    );
    expect(await pathExists(path.join(runDir, "outputs", "repository-map.json"))).toBe(false);

    failedRun.sandbox.cleanup = { attempted: false, deleted: false, success: false };
    await writeFile(failedRunPath, `${JSON.stringify(failedRun, null, 2)}\n`, "utf8");
    provider.liveSandboxIds.push(failedRun.sandbox.id);
    dataFlowsAreValid = true;

    const resumed = await runResume({ runDir, sandboxProvider: provider });

    expect(resumed.exitCode).toBe(0);
    expect(provider.staleDeleteCalls).toContain(failedRun.sandbox.id);
    expect(provider.createdSandboxIds).toHaveLength(2);
    expect(provider.liveSandboxIds).toEqual([]);

    const resumedCommands =
      provider.sessions
        .at(-1)
        ?.commands.filter((command) => command.command.startsWith("vibeshield-runtime-job"))
        .map((command) => command.command) ?? [];
    expect(resumedCommands[0]).toContain("data-flows");
    expect(resumedCommands.some((command) => command.includes("coverage-structure"))).toBe(false);
    expect(resumedCommands.some((command) => command.includes("operation-sinks"))).toBe(false);
    await expectPath(path.join(runDir, "outputs", "repo-map", "data-flows.json"));
    await expectPath(path.join(runDir, "outputs", "repository-map.json"));
  });
});

async function createProvider(
  options: {
    failAt?: "baseline" | "clone" | "inventory" | "pi";
    minimal?: boolean;
    piOutputs?: ConstructorParameters<typeof FakeDaytonaSandboxProvider>[0]["piOutputs"];
    unavailableTools?: ConstructorParameters<
      typeof FakeDaytonaSandboxProvider
    >[0]["unavailableTools"];
  } = {},
) {
  const fixtureRepo = options.minimal
    ? await createMinimalFixtureGitRepo()
    : await createRepositoryMapFixtureGitRepo();
  const sandboxRoot = await createTempRoot("vibeshield-fake-daytona-");
  const providerOptions: ConstructorParameters<typeof FakeDaytonaSandboxProvider>[0] = {
    fixtureRepos: new Map([[options.minimal ? minimalFixtureUrl : fixtureUrl, fixtureRepo]]),
    piOutputs: {
      ...(options.minimal ? minimalRepoMapOutputs() : fixtureRepoMapOutputs()),
      ...(options.piOutputs ?? {}),
    },
    sandboxRoot,
  };
  if (options.failAt !== undefined) {
    providerOptions.failAt = options.failAt;
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

async function createRepositoryMapFixtureGitRepo(): Promise<string> {
  const repoDir = await createTempRoot("vibeshield-repository-map-fixture-");
  await mkdir(path.join(repoDir, "src", "jobs"), { recursive: true });
  await mkdir(path.join(repoDir, "src", "parsers"), { recursive: true });
  await mkdir(path.join(repoDir, "src", "routes"), { recursive: true });
  await mkdir(path.join(repoDir, "src", "services"), { recursive: true });
  await mkdir(path.join(repoDir, ".github", "workflows"), { recursive: true });
  await mkdir(path.join(repoDir, "infra"), { recursive: true });
  await writeFile(path.join(repoDir, "README.md"), "# Repository map fixture\n");
  await writeFile(
    path.join(repoDir, "package.json"),
    `${JSON.stringify(
      {
        dependencies: { express: "^5.0.0" },
        name: "repository-map-fixture",
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
      "import { requireSession } from './auth';",
      "import { saveMessage } from './db';",
      "const app = express();",
      "app.post('/api/spam', requireSession, async (req, res) => { await saveMessage(req.body.text); res.json({ ok: true }); });",
      "export { app };",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(repoDir, "src", "auth.ts"),
    [
      "import type { RequestHandler } from 'express';",
      "export const requireSession: RequestHandler = (req, res, next) => { if (!req.headers.cookie) return res.status(401).end(); next(); };",
      "",
    ].join("\n"),
  );
  await writeFile(
    path.join(repoDir, "src", "config.ts"),
    [
      "export const config = { apiBaseUrl: process.env.API_BASE_URL, sessionSecret: process.env.SESSION_SECRET };",
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
    path.join(repoDir, "src", "schema.sql"),
    "create table messages (id serial primary key, text text not null);\n",
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
    path.join(repoDir, "src", "crypto.ts"),
    [
      "import { createHmac, randomBytes } from 'node:crypto';",
      "export const signWebhook = (body: string, secret: string) => createHmac('sha256', secret).update(body).digest('hex');",
      "export const newToken = () => randomBytes(16).toString('hex');",
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
  const repoDir = await createTempRoot("vibeshield-repository-map-minimal-");
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

function fixtureRepoMapOutputs(): NonNullable<
  ConstructorParameters<typeof FakeDaytonaSandboxProvider>[0]["piOutputs"]
> {
  const outputs = {
    "auth-config-secrets": fakeRepoMapAuthConfigSecrets(),
    "coverage-structure": fakeRepoMapCoverageStructure(),
    "data-flows": fakeRepoMapDataFlows(),
    entrypoints: fakeRepoMapEntrypoints(),
    "operation-sinks": fakeRepoMapOperationSinks(),
    "repository-map": fakeRepositoryMap(),
    "stack-build-deps": fakeRepoMapStackBuildDeps(),
    "storage-integrations-infra": fakeRepoMapStorageIntegrationsInfra(),
    "trust-boundaries": fakeRepoMapTrustBoundaries(),
  };

  return {
    ...outputs,
    "repo-map/auth-config-secrets": outputs["auth-config-secrets"],
    "repo-map/coverage-structure": outputs["coverage-structure"],
    "repo-map/data-flows": outputs["data-flows"],
    "repo-map/entrypoints": outputs.entrypoints,
    "repo-map/operation-sinks": outputs["operation-sinks"],
    "repo-map/repository-map": outputs["repository-map"],
    "repo-map/stack-build-deps": outputs["stack-build-deps"],
    "repo-map/storage-integrations-infra": outputs["storage-integrations-infra"],
    "repo-map/trust-boundaries": outputs["trust-boundaries"],
    "repo-map-auth-config-secrets": outputs["auth-config-secrets"],
    "repo-map-coverage-structure": outputs["coverage-structure"],
    "repo-map-data-flows": outputs["data-flows"],
    "repo-map-entrypoints": outputs.entrypoints,
    "repo-map-operation-sinks": outputs["operation-sinks"],
    "repo-map-repository-map": outputs["repository-map"],
    "repo-map-stack-build-deps": outputs["stack-build-deps"],
    "repo-map-storage-integrations-infra": outputs["storage-integrations-infra"],
    "repo-map-trust-boundaries": outputs["trust-boundaries"],
  };
}

function minimalRepoMapOutputs(): NonNullable<
  ConstructorParameters<typeof FakeDaytonaSandboxProvider>[0]["piOutputs"]
> {
  const metadata = fakeRepoMapMetadata("repository-map");
  const minimalMap = {
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "repository-map",
    metadata,
    repo: { commit_sha: "abc123", url: minimalFixtureUrl },
    sections: repoMapSectionTitles().map((title, id) => ({ evidence: ["README.md:1"], id, title })),
    summary: { evidence: ["README.md:1"], text: "Minimal fixture repository map." },
  };

  return {
    "auth-config-secrets": {
      ...minimalSection("auth-config-secrets"),
      auth: [],
      config: [],
      secret_locations: [],
    },
    "coverage-structure": minimalSection("coverage-structure"),
    "data-flows": {
      ...minimalSection("data-flows"),
      flows: [],
      inputs: {
        entrypoints_artifact: "outputs/repo-map/entrypoints.json",
        operation_sinks_artifact: "outputs/repo-map/operation-sinks.json",
      },
    },
    entrypoints: { ...minimalSection("entrypoints"), entrypoints: [] },
    "operation-sinks": { ...minimalSection("operation-sinks"), sinks: [] },
    "repository-map": minimalMap,
    "stack-build-deps": minimalSection("stack-build-deps"),
    "storage-integrations-infra": {
      ...minimalSection("storage-integrations-infra"),
      ci: [],
      infrastructure: [],
      integrations: [],
      storage: [],
    },
    "trust-boundaries": { ...minimalSection("trust-boundaries"), boundaries: [] },
  };
}

function minimalSection(kind: string) {
  return {
    coverage: {
      not_covered: [],
      reviewed: [{ area: "Minimal fixture", evidence: ["README.md:1"] }],
    },
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind,
    metadata: fakeRepoMapMetadata(kind),
    repo: { commit_sha: "abc123", url: minimalFixtureUrl },
  };
}

function fakeInventory(): InventoryArtifact {
  return {
    directories: [
      { path: "src" },
      { path: "src/jobs" },
      { path: "src/parsers" },
      { path: "src/routes" },
      { path: "src/services" },
      { path: "infra" },
    ],
    files: [
      { line_count: 8, path: "package.json", size_bytes: 100, type: "file" },
      { line_count: 6, path: "src/server.ts", size_bytes: 220, type: "file" },
      { line_count: 3, path: "src/auth.ts", size_bytes: 130, type: "file" },
      { line_count: 2, path: "src/config.ts", size_bytes: 110, type: "file" },
      { line_count: 4, path: "src/cli.ts", size_bytes: 120, type: "file" },
      { line_count: 3, path: "src/jobs/cleanup.ts", size_bytes: 120, type: "file" },
      { line_count: 3, path: "src/parsers/json.ts", size_bytes: 80, type: "file" },
      { line_count: 1, path: "src/schema.sql", size_bytes: 70, type: "file" },
      { line_count: 3, path: "src/db.ts", size_bytes: 100, type: "file" },
      { line_count: 5, path: "src/files.ts", size_bytes: 140, type: "file" },
      { line_count: 4, path: "src/http.ts", size_bytes: 130, type: "file" },
      { line_count: 3, path: "src/crypto.ts", size_bytes: 170, type: "file" },
      { line_count: 3, path: "src/logger.ts", size_bytes: 80, type: "file" },
      { line_count: 4, path: "src/services/spam.ts", size_bytes: 120, type: "file" },
      { line_count: 1, path: "src/routes/api.ts", size_bytes: 30, type: "file" },
      { line_count: 2, path: ".env.example", size_bytes: 24, type: "file" },
      { line_count: 1, path: "Dockerfile", size_bytes: 20, type: "file" },
      { line_count: 1, path: "infra/main.tf", size_bytes: 40, type: "file" },
    ],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "vibeshield-inventory",
    kind: "inventory",
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
      directory_count: 6,
      file_count: 18,
      manifest_files: ["package.json"],
      total_file_bytes: 1804,
    },
  };
}

function fakeBaselineSummary(): BaselineSummaryArtifact {
  return {
    generated_at: "2026-06-13T00:00:00.000Z",
    kind: "baseline-summary",
    source: {
      commit_sha: "abc123",
      url: fixtureUrl,
    },
    summary: {
      github_actions_workflows: [".github/workflows/ci.yml"],
      iac_candidates: ["Dockerfile", "infra/main.tf"],
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

function fakeRepoMapCoverageStructure(): CoverageStructureArtifact {
  return {
    coverage: fakeCoverage("Coverage and repository structure", ["src/server.ts:1"]),
    coverage_targets: [
      {
        area: "Application source",
        evidence: ["src/server.ts:1"],
        reason: "Primary source directory reviewed for repository map facts.",
      },
    ],
    fact_gaps: [],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    important_files: [
      {
        evidence: ["package.json:1"],
        path: "package.json",
        reason: "Defines dependencies and scripts.",
      },
      {
        evidence: ["Dockerfile:1"],
        path: "Dockerfile",
        reason: "Defines runtime image.",
      },
    ],
    kind: "coverage-structure",
    metadata: fakeRepoMapMetadata("coverage-structure"),
    repo: fakeRepo(),
    repository_structure: [
      { evidence: ["src/server.ts:1"], kind: "source", path: "src", role: "application source" },
      { evidence: ["infra/main.tf:1"], kind: "infra", path: "infra", role: "infrastructure" },
      { evidence: ["package.json:1"], kind: "dependency", path: "package.json", role: "manifest" },
    ],
  };
}

function fakeRepoMapStackBuildDeps(): StackBuildDepsArtifact {
  return {
    build: {
      commands: [
        {
          command: "node scripts/should-not-run.js",
          evidence: ["package.json:6"],
          id: "build-package-script",
          name: "package build script",
          source: "package.json scripts.build",
        },
      ],
      lockfiles: [],
      manifests: [{ evidence: ["package.json:1"], path: "package.json" }],
    },
    coverage: fakeCoverage("Stack, build, dependencies, and CI", [
      "package.json:1",
      ".github/workflows/ci.yml:1",
      "Dockerfile:1",
    ]),
    dependencies: [
      {
        confidence: "high",
        evidence: ["package.json:4"],
        id: "dep-express",
        kind: "dependency",
        name: "express",
        role: "^5.0.0 runtime dependency",
      },
    ],
    fact_gaps: [],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "stack-build-deps",
    metadata: fakeRepoMapMetadata("stack-build-deps"),
    repo: fakeRepo(),
    stack: [
      {
        confidence: "high",
        evidence: ["src/server.ts:1"],
        id: "stack-typescript",
        kind: "language",
        name: "TypeScript",
        role: "application source",
      },
      {
        confidence: "high",
        evidence: ["Dockerfile:1"],
        id: "runtime-node-24",
        kind: "runtime",
        name: "Node.js",
        role: "24-alpine container runtime",
      },
      {
        confidence: "high",
        evidence: [".github/workflows/ci.yml:1"],
        id: "ci-github-actions",
        kind: "service",
        name: "GitHub Actions",
        role: "CI workflow",
      },
    ],
  };
}

function fakeRepoMapEntrypoints(): EntrypointsArtifact {
  return {
    coverage: fakeCoverage("External entrypoints", [
      "src/server.ts:5",
      "src/cli.ts:3",
      "src/jobs/cleanup.ts:3",
      "src/parsers/json.ts:2",
    ]),
    entrypoints: [
      {
        confidence: "high",
        evidence: ["src/server.ts:5"],
        id: "entry-http-spam",
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
        id: "entry-cli-scan",
        kind: "cli_command",
        location: "src/cli.ts",
        name: "scan command",
      },
      {
        confidence: "high",
        evidence: ["src/jobs/cleanup.ts:3"],
        id: "entry-cron-cleanup",
        kind: "cron_job",
        location: "src/jobs/cleanup.ts",
        name: "hourly cleanup job",
        schedule: "0 * * * *",
      },
      {
        confidence: "high",
        evidence: ["src/parsers/json.ts:2"],
        id: "entry-parser-json",
        kind: "external_format_parser",
        location: "src/parsers/json.ts",
        name: "JSON payload parser",
      },
    ],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "entrypoints",
    metadata: fakeRepoMapMetadata("entrypoints"),
    repo: fakeRepo(),
  };
}

function fakeRepoMapAuthConfigSecrets(): AuthConfigSecretsArtifact {
  return {
    auth: [
      {
        confidence: "high",
        evidence: ["src/auth.ts:2", "src/server.ts:5"],
        id: "auth-session-middleware",
        kind: "middleware",
        location: "src/auth.ts",
        name: "requireSession middleware",
        notes: "Used by entry-http-spam route.",
      },
    ],
    config: [
      {
        confidence: "high",
        evidence: ["src/config.ts:1", ".env.example:1"],
        id: "config-api-base-url",
        kind: "config_source",
        location: "src/config.ts",
        name: "API_BASE_URL",
      },
      {
        confidence: "high",
        evidence: ["src/config.ts:1", ".env.example:2"],
        id: "config-session-secret",
        kind: "config_source",
        location: "src/config.ts",
        name: "SESSION_SECRET",
      },
    ],
    coverage: fakeCoverage("Auth, configuration, and secret locations", [
      "src/auth.ts:2",
      "src/config.ts:1",
      ".env.example:1",
    ]),
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "auth-config-secrets",
    metadata: fakeRepoMapMetadata("auth-config-secrets"),
    repo: fakeRepo(),
    secret_references: [
      {
        confidence: "high",
        evidence: [".env.example:2"],
        id: "secret-session-example",
        kind: "secret_reference",
        location: ".env.example",
        name: "SESSION_SECRET",
        value_redacted: true,
      },
    ],
  };
}

function fakeRepoMapStorageIntegrationsInfra(): StorageIntegrationsInfraArtifact {
  return {
    ci: [
      {
        evidence: [".github/workflows/ci.yml:1"],
        id: "ci-github-actions",
        provider: "GitHub Actions",
      },
    ],
    coverage: fakeCoverage("Storage, integrations, and infrastructure", [
      "src/db.ts:2",
      "src/schema.sql:1",
      "src/http.ts:3",
      "Dockerfile:1",
      "infra/main.tf:1",
    ]),
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    infra: [
      {
        confidence: "high",
        evidence: ["Dockerfile:1"],
        id: "infra-dockerfile",
        kind: "runtime",
        location: "Dockerfile",
        name: "Dockerfile",
        role: "Node.js container runtime",
      },
      {
        confidence: "high",
        evidence: ["infra/main.tf:1"],
        id: "infra-terraform",
        kind: "iac",
        location: "infra/main.tf",
        name: "Terraform demo resource",
        role: "Infrastructure definition",
      },
      {
        confidence: "high",
        evidence: [".github/workflows/ci.yml:1"],
        id: "ci-github-actions",
        kind: "workflow",
        location: ".github/workflows/ci.yml",
        name: "GitHub Actions CI",
        role: "CI workflow",
      },
    ],
    integrations: [
      {
        confidence: "high",
        evidence: ["src/http.ts:3"],
        id: "integration-webhook-client",
        kind: "external_api",
        location: "src/http.ts",
        name: "configured webhook base URL",
        role: "Outbound HTTP client",
      },
    ],
    kind: "storage-integrations-infra",
    metadata: fakeRepoMapMetadata("storage-integrations-infra"),
    repo: fakeRepo(),
    storage: [
      {
        confidence: "high",
        evidence: ["src/db.ts:2", "src/schema.sql:1"],
        id: "store-messages-db",
        kind: "database",
        location: "src/schema.sql",
        name: "messages table",
        role: "SQL data model",
      },
      {
        confidence: "high",
        evidence: ["src/files.ts:4"],
        id: "store-upload-filesystem",
        kind: "file_storage",
        location: "src/files.ts",
        name: "local upload directory",
        role: "Filesystem write target",
      },
    ],
  };
}

function fakeRepoMapOperationSinks(): OperationSinksArtifact {
  return {
    coverage: fakeCoverage("Operation sinks", [
      "src/db.ts:2",
      "src/files.ts:4",
      "src/http.ts:3",
      "src/logger.ts:2",
      "src/crypto.ts:2",
      "src/crypto.ts:3",
    ]),
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "operation-sinks",
    metadata: fakeRepoMapMetadata("operation-sinks"),
    operation_sinks: [
      {
        confidence: "high",
        evidence: ["src/db.ts:2"],
        id: "sink-db-insert",
        input_variables: ["text"],
        kind: "sql_or_orm_query",
        location: "src/db.ts",
        operation: "db.query insert statement",
      },
      {
        confidence: "high",
        evidence: ["src/files.ts:4"],
        id: "sink-filesystem-write",
        input_variables: ["name", "body"],
        kind: "filesystem_operation",
        location: "src/files.ts",
        operation: "writeFile path.join write",
      },
      {
        confidence: "high",
        evidence: ["src/http.ts:3"],
        id: "sink-outbound-webhook",
        input_variables: ["baseUrl", "id"],
        kind: "outbound_http_or_sdk_url",
        location: "src/http.ts",
        operation: "fetch URL constructed from variables",
      },
      {
        confidence: "high",
        evidence: ["src/logger.ts:2"],
        id: "sink-audit-log",
        input_variables: ["value"],
        kind: "logging",
        location: "src/logger.ts",
        operation: "console.log audit value",
      },
      {
        confidence: "high",
        evidence: ["src/crypto.ts:2"],
        id: "sink-crypto-hmac",
        input_variables: ["body", "secret"],
        kind: "crypto_operation",
        location: "src/crypto.ts",
        operation: "createHmac sha256",
      },
      {
        confidence: "high",
        evidence: ["src/crypto.ts:3"],
        id: "sink-random-token",
        kind: "randomness",
        location: "src/crypto.ts",
        operation: "randomBytes token generation",
      },
    ],
    repo: fakeRepo(),
  };
}

function fakeRepoMapDataFlows(): DataFlowsArtifact {
  return {
    coverage: fakeCoverage("Bounded external-input data flows", ["src/server.ts:5", "src/db.ts:2"]),
    flows: [
      {
        breakpoint: null,
        id: "flow-http-spam-db",
        inference: false,
        intermediate_functions: [{ evidence: ["src/db.ts:1"], name: "saveMessage" }],
        operation_sink: "sink-db-insert",
        operation_sink_evidence: ["src/db.ts:2"],
        source_entrypoint: "entry-http-spam",
        source_evidence: ["src/server.ts:5"],
        trace_status: "direct observed",
      },
    ],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    inputs: {
      entrypoints_artifact: "outputs/repo-map/entrypoints.json",
      operation_sinks_artifact: "outputs/repo-map/operation-sinks.json",
    },
    kind: "data-flows",
    metadata: fakeRepoMapMetadata("data-flows"),
    repo: fakeRepo(),
  };
}

function fakeRepoMapDataFlowsWithUnknownIds(): DataFlowsArtifact {
  const artifact = fakeRepoMapDataFlows();
  const firstFlow = artifact.flows[0];
  if (firstFlow === undefined) {
    throw new Error("Expected fake data-flow fixture to contain one flow.");
  }
  artifact.flows[0] = {
    ...firstFlow,
    operation_sink: "sink-invented",
    source_entrypoint: "entry-invented",
  };
  return artifact;
}

function fakeRepoMapTrustBoundaries(): TrustBoundariesArtifact {
  return {
    boundaries: [
      {
        confidence: "medium",
        description:
          "External HTTP request data crosses from a network boundary into application and database handling.",
        evidence: ["src/server.ts:5", "src/auth.ts:2", "src/db.ts:2"],
        flow_ids: ["flow-http-spam-db"],
        id: "boundary-external-http-to-app-db",
        inference: true,
        kind: "external_user_to_app",
        name: "External HTTP to app/database",
        sink_ids: ["sink-db-insert"],
        source_artifact_ids: ["entrypoints", "auth-config-secrets", "data-flows"],
        source_entrypoint_ids: ["entry-http-spam"],
      },
    ],
    coverage: fakeCoverage("Trust-boundary inferences", [
      "src/server.ts:5",
      "src/auth.ts:2",
      "src/db.ts:2",
    ]),
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    inputs: {
      auth_config_secrets_artifact: "outputs/repo-map/auth-config-secrets.json",
      coverage_structure_artifact: "outputs/repo-map/coverage-structure.json",
      data_flows_artifact: "outputs/repo-map/data-flows.json",
      entrypoints_artifact: "outputs/repo-map/entrypoints.json",
      operation_sinks_artifact: "outputs/repo-map/operation-sinks.json",
      stack_build_deps_artifact: "outputs/repo-map/stack-build-deps.json",
      storage_integrations_infra_artifact: "outputs/repo-map/storage-integrations-infra.json",
    },
    kind: "trust-boundaries",
    metadata: fakeRepoMapMetadata("trust-boundaries"),
    repo: fakeRepo(),
  };
}

function fakeRepositoryMap(): RepositoryMapArtifact {
  return {
    coverage: fakeCoverage("Repository map synthesis", ["src/server.ts:5"]),
    fact_gaps: [],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    inputs: {
      auth_config_secrets_artifact: "outputs/repo-map/auth-config-secrets.json",
      coverage_structure_artifact: "outputs/repo-map/coverage-structure.json",
      data_flows_artifact: "outputs/repo-map/data-flows.json",
      entrypoints_artifact: "outputs/repo-map/entrypoints.json",
      operation_sinks_artifact: "outputs/repo-map/operation-sinks.json",
      stack_build_deps_artifact: "outputs/repo-map/stack-build-deps.json",
      storage_integrations_infra_artifact: "outputs/repo-map/storage-integrations-infra.json",
      trust_boundaries_artifact: "outputs/repo-map/trust-boundaries.json",
    },
    kind: "repository-map",
    metadata: fakeRepoMapMetadata("repository-map"),
    repo: fakeRepo(),
    sections: [
      repoMapSection("coverage-structure", "outputs/repo-map/coverage-structure.json", 3),
      repoMapSection("stack-build-deps", "outputs/repo-map/stack-build-deps.json", 4),
      repoMapSection("entrypoints", "outputs/repo-map/entrypoints.json", 4),
      repoMapSection("auth-config-secrets", "outputs/repo-map/auth-config-secrets.json", 4),
      repoMapSection(
        "storage-integrations-infra",
        "outputs/repo-map/storage-integrations-infra.json",
        6,
      ),
      repoMapSection("operation-sinks", "outputs/repo-map/operation-sinks.json", 6),
      repoMapSection("data-flows", "outputs/repo-map/data-flows.json", 1),
      repoMapSection("trust-boundaries", "outputs/repo-map/trust-boundaries.json", 1),
    ],
    summary: {
      confidence: "medium",
      evidence: ["package.json:1", "src/server.ts:5"],
      inference: true,
      project_kind: "backend-api",
      text: "Fixture Node.js repository map assembled from facts-only section artifacts.",
    },
  };
}

function repoMapSection(
  artifact: NonNullable<RepositoryMapArtifact["sections"][number]["artifact"]>,
  artifactPath: string,
  itemCount: number,
): RepositoryMapArtifact["sections"][number] {
  return {
    artifact,
    evidence: ["src/server.ts:5"],
    item_count: itemCount,
    path: artifactPath,
    summary: `${artifact} facts are available.`,
  };
}

function fakeCoverage(area: string, evidence: string[]) {
  return {
    not_covered: [{ area: "Runtime-only behavior", reason: "Fixture Pi is static only." }],
    reviewed: [{ area, evidence }],
  };
}

function fakeRepo() {
  return {
    commit_sha: "abc123",
    url: fixtureUrl,
  };
}

function fakeRepoMapMetadata(step: string) {
  return {
    pi: {
      input_context_artifact: "outputs/pi-context-pack.json",
      invocation: { command: "pi", provider: "openrouter" },
      model: "fake",
      provider: "openrouter",
      step,
      version: "fake",
    },
  };
}

function repoMapSectionTitles(): string[] {
  return [
    "Coverage",
    "Stack and build",
    "Repository structure",
    "Attack surface and entrypoints",
    "Authentication and authorization",
    "Data flows to operation sinks",
    "Operation sink inventory",
    "Secrets and configuration",
    "Cryptography",
    "Storage and data model",
    "External integrations and network egress",
    "Dependencies",
    "Infrastructure and deployment",
    "Logging and observability",
    "Trust boundaries",
  ];
}

function expectTrustBoundariesUseKnownFacts(input: {
  dataFlows: DataFlowsArtifact;
  entrypoints: EntrypointsArtifact;
  sinks: OperationSinksArtifact;
  trustBoundaries: TrustBoundariesArtifact;
}): void {
  const entrypointIds = new Set(input.entrypoints.entrypoints.map((entrypoint) => entrypoint.id));
  const operationSinks = input.sinks.operation_sinks ?? input.sinks.sinks ?? [];
  const sinkIds = new Set(operationSinks.map((sink) => sink.id));
  const flowIds = new Set(input.dataFlows.flows.map((flow) => flow.id));
  const knownSourceArtifacts = new Set([
    "auth-config-secrets",
    "coverage-structure",
    "data-flows",
    "entrypoints",
    "operation-sinks",
    "stack-build-deps",
    "storage-integrations-infra",
  ]);

  for (const flow of input.dataFlows.flows) {
    expect(entrypointIds.has(flow.source_entrypoint ?? flow.source_entrypoint_id ?? "")).toBe(true);
    expect(sinkIds.has(flow.operation_sink ?? flow.sink_id ?? "")).toBe(true);
  }

  for (const boundary of input.trustBoundaries.boundaries) {
    for (const id of boundary.source_entrypoint_ids ?? []) {
      expect(entrypointIds.has(id)).toBe(true);
    }
    for (const id of boundary.sink_ids ?? []) {
      expect(sinkIds.has(id)).toBe(true);
    }
    for (const id of boundary.flow_ids ?? []) {
      expect(flowIds.has(id)).toBe(true);
    }
    for (const artifactId of boundary.source_artifact_ids ?? []) {
      expect(knownSourceArtifacts.has(artifactId)).toBe(true);
    }
    expect(boundary.inference).toBe(true);
  }

  expect(JSON.stringify(input.trustBoundaries)).not.toContain("invented");
}
