import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type {
  AttackHypothesesArtifact,
  AuthAccessArtifact,
  BaselineSummaryArtifact,
  ConfigSecretsArtifact,
  CoverageStructureArtifact,
  CryptoArtifact,
  DataFlowsArtifact,
  EntrypointsArtifact,
  ExternalIntegrationsEgressArtifact,
  InfraDeployArtifact,
  InventoryArtifact,
  LoggingObservabilityArtifact,
  OperationSinksArtifact,
  RepositoryMapArtifact,
  StackBuildDepsArtifact,
  StorageDataModelArtifact,
  TrustBoundariesArtifact,
} from "../src/artifacts/contracts.js";
import { ArtifactStore } from "../src/artifacts/store.js";
import { buildPiContextPack } from "../src/context/step-context-builder.js";
import { runResume, runScan } from "../src/run/run-scan.js";
import { FakeDaytonaSandboxProvider } from "../src/sandbox/fake-daytona.js";
import type { RuntimeJobInput } from "../src/sandbox/types.js";

const execFileAsync = promisify(execFile);
type BuildPiContextInput = Parameters<typeof buildPiContextPack>[0];
const tempRoots: string[] = [];
const fixtureUrl = "https://github.com/vibeshield/repository-map-fixture";
const minimalFixtureUrl = "https://github.com/vibeshield/repository-map-minimal-fixture";

const expectedRepoMapArtifacts = [
  "outputs/repo-map/coverage-structure.json",
  "outputs/repo-map/stack-build-deps.json",
  "outputs/repo-map/entrypoints.json",
  "outputs/repo-map/auth-access.json",
  "outputs/repo-map/config-secrets.json",
  "outputs/repo-map/storage-data-model.json",
  "outputs/repo-map/external-integrations-egress.json",
  "outputs/repo-map/infra-deploy.json",
  "outputs/repo-map/operation-sinks.json",
  "outputs/repo-map/crypto.json",
  "outputs/repo-map/logging-observability.json",
  "outputs/repo-map/data-flows.json",
  "outputs/repo-map/trust-boundaries.json",
  "outputs/repository-map.json",
];
const expectedAcceptedArtifacts = [...expectedRepoMapArtifacts, "outputs/attack-hypotheses.json"];

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("AppSec repository map acceptance", () => {
  it("documents the facts-only repository-map product expectation", async () => {
    const expectationDoc = await readFile(
      path.join(process.cwd(), "docs", "repository-map-expectations.md"),
      "utf8",
    );
    const architecture = await readFile(
      path.join(process.cwd(), "docs", "architecture.md"),
      "utf8",
    );
    const currentSteps = [
      "coverage-structure",
      "stack-build-deps",
      "entrypoints",
      "auth-access",
      "config-secrets",
      "storage-data-model",
      "external-integrations-egress",
      "infra-deploy",
      "operation-sinks",
      "crypto",
      "logging-observability",
      "data-flows",
      "trust-boundaries",
      "repository-map",
      "attack-hypotheses",
    ];

    expect(expectationDoc).toContain("facts-only AppSec repository map");
    expect(expectationDoc).toContain("attack hypotheses");
    for (const step of currentSteps) {
      expect(expectationDoc).toContain(step);
    }
    expect(architecture).toContain("docs/repository-map-expectations.md");
    expect(architecture).toContain("schema-only validation");
  });

  it("produces complete facts-only repository map artifacts with representative facts", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ sourceInput: fixtureUrl, runsRoot, sandboxProvider: provider });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);

    await expectPath(path.join(runDir, "outputs", "inventory.json"));
    await expectPath(path.join(runDir, "outputs", "baseline-summary.json"));
    await expectPath(path.join(runDir, "outputs", "pi-context-pack.json"));
    for (const artifact of expectedAcceptedArtifacts) {
      await expectPath(path.join(runDir, artifact));
    }
    await expectPath(path.join(runDir, "final-report.md"));
    await expectPath(path.join(runDir, "final-report.pdf"));

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

    const authAccess = await readJson<AuthAccessArtifact>(
      path.join(runDir, "outputs", "repo-map", "auth-access.json"),
    );
    expect(authAccess.auth).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "auth-session-middleware",
          kind: "middleware",
        }),
      ]),
    );
    expect(authAccess.entrypoint_access).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          entrypoint_id: "entry-http-spam",
          status: "protected",
        }),
      ]),
    );

    const configSecrets = await readJson<ConfigSecretsArtifact>(
      path.join(runDir, "outputs", "repo-map", "config-secrets.json"),
    );
    expect(configSecrets.config.map((item) => item.name)).toEqual(
      expect.arrayContaining(["API_BASE_URL", "SESSION_SECRET"]),
    );

    const storage = await readJson<StorageDataModelArtifact>(
      path.join(runDir, "outputs", "repo-map", "storage-data-model.json"),
    );
    expect(storage.storage.map((item) => item.id)).toEqual(
      expect.arrayContaining(["store-messages-db", "store-upload-filesystem"]),
    );

    const integrations = await readJson<ExternalIntegrationsEgressArtifact>(
      path.join(runDir, "outputs", "repo-map", "external-integrations-egress.json"),
    );
    expect(integrations.integrations.map((item) => item.id)).toContain(
      "integration-webhook-client",
    );

    const infra = await readJson<InfraDeployArtifact>(
      path.join(runDir, "outputs", "repo-map", "infra-deploy.json"),
    );
    expect([...(infra.infra ?? []), ...(infra.ci ?? [])].map((item) => item.kind)).toEqual(
      expect.arrayContaining(["runtime", "iac", "workflow"]),
    );

    const sinks = await readJson<OperationSinksArtifact>(
      path.join(runDir, "outputs", "repo-map", "operation-sinks.json"),
    );
    expect(sinks.operation_sinks.map((sink) => sink.kind)).toEqual(
      expect.arrayContaining([
        "filesystem_operation",
        "outbound_http_or_sdk_url",
        "sql_or_orm_query",
      ]),
    );

    const crypto = await readJson<CryptoArtifact>(
      path.join(runDir, "outputs", "repo-map", "crypto.json"),
    );
    expect(crypto.crypto.map((item) => item.kind)).toEqual(
      expect.arrayContaining(["crypto_operation", "randomness"]),
    );

    const logging = await readJson<LoggingObservabilityArtifact>(
      path.join(runDir, "outputs", "repo-map", "logging-observability.json"),
    );
    expect(logging.logging.map((item) => item.id)).toContain("log-audit-value");

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

    const attackHypotheses = await readJson<AttackHypothesesArtifact>(
      path.join(runDir, "outputs", "attack-hypotheses.json"),
    );
    expect(attackHypotheses).toMatchObject({
      inputs: { repository_map_artifact: "outputs/repository-map.json" },
      kind: "attack-hypotheses",
      metadata: {
        pi: {
          model: "anthropic/claude-opus-4.8",
          step: "attack-hypotheses",
        },
      },
    });
    expect(attackHypotheses.hypotheses).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "hyp-http-spam-db-input",
          supporting_map_evidence: expect.arrayContaining(["entry-http-spam", "sink-db-insert"]),
        }),
      ]),
    );
  });

  it("renders owner-facing Markdown and PDF final reports with scanner findings and grouped hypotheses", async () => {
    const { provider } = await createProvider();

    const result = await runScan({
      sourceInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    const report = await readFile(path.join(runDir, "final-report.md"), "utf8");
    expect(report).toContain("# Security Report");
    expect(report).toContain("Repository: https://github.com/vibeshield/repository-map-fixture");
    expect(report).toContain("## Status:");
    expect(report).toContain("## Summary");
    expect(report).toContain(
      "One medium-priority hypothesis links external HTTP input to a database write.",
    );
    expect(report).toContain("## Issues to fix");
    expect(report).toContain("## Leads to check");
    expect(report).toContain("Unconfirmed lead");
    expect(report).toContain("Copy for your AI agent:");
    expect(report).toContain("### Medium");
    expect(report).toContain("HTTP request body reaches database write");
    expect(report).toContain("CVE-FAKE-0001 in fixture-dependency@1.0.0 fixed in 1.0.1");
    expect(report).toContain("CKV_FAKE_1: Fixture IaC check failed");
    expect(report).toContain("entry-http-spam");
    expect(report).toContain("sink-db-insert");
    expect(report).toContain("src/server.ts:5");
    expect(report).not.toContain("syft");
    expect(report).not.toContain("trivy");
    expect(report).not.toContain("gitleaks");
    expect(report).not.toContain("actionlint");
    expect(report).not.toContain("zizmor");
    expect(report).not.toContain("checkov");
    expect(report).not.toContain("## 0. Coverage");
    expect(await pathExists(path.join(runDir, "report.md"))).toBe(false);
    expect((await readFile(path.join(runDir, "final-report.pdf"))).subarray(0, 4).toString()).toBe(
      "%PDF",
    );
  });

  it("keeps untrusted checkout work inside a fresh sandbox and preserves failure diagnostics", async () => {
    const { provider, sandboxRoot } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ sourceInput: fixtureUrl, runsRoot, sandboxProvider: provider });

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
      sourceInput: fixtureUrl,
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

    const result = await runScan({ sourceInput: fixtureUrl, runsRoot, sandboxProvider: provider });
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
      sourceInput: minimalFixtureUrl,
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
      sourceInput: fixtureUrl,
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
      "Could not complete dependency inventory collection",
    );
    await expectPath(path.join(runDir, "outputs", "repository-map.json"));
    await expectPath(path.join(runDir, "final-report.md"));
    await expectPath(path.join(runDir, "final-report.pdf"));
  });

  it("continues to repository mapping when scanner tool preparation fails", async () => {
    const { provider } = await createProvider({ failAt: "baseline-prepare" });
    const result = await runScan({
      sourceInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    const baseline = await readJson<BaselineSummaryArtifact>(
      path.join(runDir, "outputs", "baseline-summary.json"),
    );
    expect(baseline.summary.tool_availability_artifact).toBe(
      "outputs/baseline/tool-availability.json",
    );
    expect(baseline.tools.find((tool) => tool.tool === "syft")?.status).toBe("failed");
    expect(baseline.tools.find((tool) => tool.tool === "syft")?.diagnostics.join("\n")).toContain(
      "Dependency inventory collector is not available",
    );
    expect(baseline.tools.find((tool) => tool.tool === "actionlint")?.status).toBe("failed");
    await expectPath(path.join(runDir, "outputs", "baseline", "tool-availability.json"));
    await expectPath(path.join(runDir, "outputs", "repository-map.json"));
    await expectPath(path.join(runDir, "final-report.md"));
    await expectPath(path.join(runDir, "final-report.pdf"));
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
    expect(Object.keys(contextPack).sort()).toEqual(["inventory", "repo"]);
    expect(JSON.stringify(contextPack)).not.toContain("sk-test-secret-value");
    expect(JSON.stringify(contextPack)).not.toContain("raw-scanner-dump");
    expect(JSON.stringify(contextPack)).not.toContain("baseline-summary");
    expect(JSON.stringify(contextPack)).not.toContain("gitleaks");
    expect(contextPack.inventory.config_files).toContain(".env.example");
    expect(contextPack.inventory.source_index).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          directory: "src",
          languages: expect.arrayContaining(["TypeScript"]),
          sample_files: expect.any(Array),
        }),
      ]),
    );
    expect(contextPack.inventory.top_level_directories).toContain("src");

    await expect(
      buildPiContextPack({
        baseline: baseline as unknown as BuildPiContextInput["baseline"],
        inventory: { ...inventory, kind: "wrong" } as unknown as BuildPiContextInput["inventory"],
        store,
      }),
    ).rejects.toMatchObject({ stage: "context" });
  });

  it("passes narrow per-step context to Pi repository-map collectors", async () => {
    const capturedContexts: Record<string, unknown> = {};
    const capturedPi: Record<string, RuntimeJobInput["pi"]> = {};
    const capture =
      (step: string, output: unknown) =>
      (input: RuntimeJobInput): unknown => {
        capturedContexts[step] = input.pi?.contextPack;
        capturedPi[step] = input.pi;
        return output;
      };
    const { provider } = await createProvider({
      piOutputs: {
        "attack-hypotheses": capture("attack-hypotheses", fakeAttackHypotheses()),
        "auth-access": capture("auth-access", fakeRepoMapAuthAccess()),
        "config-secrets": capture("config-secrets", fakeRepoMapConfigSecrets()),
        crypto: capture("crypto", fakeRepoMapCrypto()),
        "data-flows": capture("data-flows", fakeRepoMapDataFlows()),
        entrypoints: capture("entrypoints", fakeRepoMapEntrypoints()),
        "external-integrations-egress": capture(
          "external-integrations-egress",
          fakeRepoMapExternalIntegrationsEgress(),
        ),
        "infra-deploy": capture("infra-deploy", fakeRepoMapInfraDeploy()),
        "logging-observability": capture(
          "logging-observability",
          fakeRepoMapLoggingObservability(),
        ),
        "operation-sinks": capture("operation-sinks", fakeRepoMapOperationSinks()),
        "repository-map": capture("repository-map", fakeRepositoryMap()),
        "stack-build-deps": capture("stack-build-deps", fakeRepoMapStackBuildDeps()),
        "storage-data-model": capture("storage-data-model", fakeRepoMapStorageDataModel()),
        "trust-boundaries": capture("trust-boundaries", fakeRepoMapTrustBoundaries()),
      },
    });

    const result = await runScan({
      sourceInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);

    const stackBuildDeps = expectObjectContext(capturedContexts["stack-build-deps"]);
    expect(stackBuildDeps).toMatchObject({
      inventory: expect.objectContaining({
        config_files: expect.any(Array),
        github_actions_workflows: expect.any(Array),
        iac_candidates: expect.any(Array),
        infra_files: expect.any(Array),
        manifest_files: expect.any(Array),
        package_and_lock_files: expect.any(Array),
      }),
      purpose: expect.stringContaining("facts-only"),
      repo: expect.objectContaining({ url: fixtureUrl }),
    });
    expect(jsonText(stackBuildDeps)).not.toContain("raw-scanner-dump");
    expect(jsonText(stackBuildDeps)).not.toContain("baseline-summary");

    const entrypoints = expectObjectContext(capturedContexts.entrypoints);
    expect(entrypoints).toMatchObject({
      inputs: expect.objectContaining({
        stack_build_deps: expect.objectContaining({
          build: expect.any(Object),
          kind: "stack-build-deps",
          stack: expect.any(Array),
        }),
      }),
      inventory: expect.objectContaining({
        language_summary: expect.any(Array),
        manifest_files: expect.any(Array),
        top_level_directories: expect.any(Array),
      }),
    });

    const authAccess = expectObjectContext(capturedContexts["auth-access"]);
    expect(authAccess).toMatchObject({
      inputs: expect.objectContaining({
        config_secrets: expect.objectContaining({
          config: expect.arrayContaining([expect.objectContaining({ id: "config-api-base-url" })]),
        }),
        entrypoints: expect.objectContaining({
          entrypoints: expect.arrayContaining([expect.objectContaining({ id: "entry-http-spam" })]),
        }),
      }),
      inventory: expect.objectContaining({
        source_index: expect.any(Array),
      }),
    });

    const configSecrets = expectObjectContext(capturedContexts["config-secrets"]);
    expect(configSecrets).toMatchObject({
      inventory: expect.objectContaining({
        config_files: expect.any(Array),
        manifest_files: expect.any(Array),
        top_level_directories: expect.any(Array),
      }),
    });

    const storageDataModel = expectObjectContext(capturedContexts["storage-data-model"]);
    expect(storageDataModel).toMatchObject({
      inputs: expect.objectContaining({
        config_secrets: expect.objectContaining({
          config: expect.any(Array),
        }),
      }),
      inventory: expect.objectContaining({
        manifest_files: expect.any(Array),
        source_index: expect.any(Array),
      }),
    });

    const externalIntegrationsEgress = expectObjectContext(
      capturedContexts["external-integrations-egress"],
    );
    expect(externalIntegrationsEgress).toMatchObject({
      inputs: expect.objectContaining({
        config_secrets: expect.objectContaining({
          secret_references: expect.any(Array),
        }),
      }),
      inventory: expect.objectContaining({
        manifest_files: expect.any(Array),
        source_index: expect.any(Array),
      }),
    });

    const infraDeploy = expectObjectContext(capturedContexts["infra-deploy"]);
    expect(infraDeploy).toMatchObject({
      inventory: expect.objectContaining({
        github_actions_workflows: expect.any(Array),
        iac_candidates: expect.any(Array),
        infra_files: expect.any(Array),
        top_level_directories: expect.any(Array),
      }),
    });

    const operationSinks = expectObjectContext(capturedContexts["operation-sinks"]);
    expect(operationSinks).toMatchObject({
      inputs: expect.objectContaining({
        stack_build_deps: expect.objectContaining({
          build: expect.any(Object),
          kind: "stack-build-deps",
          stack: expect.any(Array),
        }),
      }),
      inventory: expect.objectContaining({
        source_index: expect.any(Array),
      }),
    });

    const crypto = expectObjectContext(capturedContexts.crypto);
    expect(crypto).toMatchObject({
      inventory: expect.objectContaining({
        config_files: expect.any(Array),
        source_index: expect.any(Array),
      }),
    });

    const loggingObservability = expectObjectContext(capturedContexts["logging-observability"]);
    expect(loggingObservability).toMatchObject({
      inputs: expect.objectContaining({
        entrypoints: expect.objectContaining({
          entrypoints: expect.arrayContaining([expect.objectContaining({ id: "entry-http-spam" })]),
        }),
        storage_data_model: expect.objectContaining({
          storage: expect.arrayContaining([expect.objectContaining({ id: "store-messages-db" })]),
        }),
      }),
      inventory: expect.objectContaining({
        config_files: expect.any(Array),
        manifest_files: expect.any(Array),
        source_index: expect.any(Array),
      }),
    });

    const dataFlows = expectObjectContext(capturedContexts["data-flows"]);
    expect(Object.keys(dataFlows).sort()).toEqual(["inputs"]);
    expect(dataFlows).toMatchObject({
      inputs: {
        entrypoints: expect.objectContaining({
          entrypoints: expect.arrayContaining([expect.objectContaining({ id: "entry-http-spam" })]),
        }),
        operation_sinks: expect.objectContaining({
          operation_sinks: expect.arrayContaining([
            expect.objectContaining({ id: "sink-db-insert" }),
          ]),
        }),
      },
    });
    expect(jsonText(dataFlows)).not.toContain('"generated_at"');
    expect(jsonText(dataFlows)).not.toContain('"generated_by"');
    expect(jsonText(dataFlows)).not.toContain('"metadata"');
    expect(jsonText(dataFlows)).not.toContain('"repo"');

    const trustBoundaries = capturedContexts["trust-boundaries"];
    expect(typeof trustBoundaries).toBe("string");
    expect(trustBoundaries).toContain("# Trust Boundaries Context");
    expect(trustBoundaries).toContain("entry-http-spam");
    expect(trustBoundaries).toContain("flow-http-spam-db");
    expect(trustBoundaries).not.toContain("generated_at");
    expect(trustBoundaries).not.toContain("generated_by");
    expect(trustBoundaries).not.toContain('"metadata"');
    expect(trustBoundaries).not.toContain('"coverage"');
    expect(capturedPi["trust-boundaries"]).toMatchObject({
      model: "openai/gpt-5.3-codex",
      thinking: "xhigh",
      tools: [],
    });
    expect(capturedPi.entrypoints).toMatchObject({
      model: "deepseek/deepseek-v4-pro",
    });

    const repositoryMap = capturedContexts["repository-map"];
    expect(typeof repositoryMap).toBe("string");
    expect(repositoryMap).toContain("# Repository Map Context");
    expect(repositoryMap).toContain("coverage-structure");
    expect(repositoryMap).toContain("entry-http-spam");
    expect(repositoryMap).toContain("flow-http-spam-db");
    expect(repositoryMap).toContain("boundary-external-http-to-app-db");
    expect(repositoryMap).not.toContain("generated_at");
    expect(repositoryMap).not.toContain("generated_by");
    expect(repositoryMap).not.toContain('"metadata"');
    expect(repositoryMap).not.toContain('"repo"');
    expect(capturedPi["repository-map"]).toMatchObject({
      model: "openai/gpt-5.3-codex",
      thinking: "xhigh",
      tools: [],
    });

    const attackHypotheses = capturedContexts["attack-hypotheses"];
    expect(typeof attackHypotheses).toBe("string");
    expect(attackHypotheses).toContain("# Attack Hypotheses Context");
    expect(attackHypotheses).toContain("# Repository Knowledge");
    expect(attackHypotheses).toContain("entry-http-spam");
    expect(attackHypotheses).toContain("sink-db-insert");
    expect(attackHypotheses).not.toContain('"metadata"');
    expect(capturedPi["attack-hypotheses"]).toMatchObject({
      model: "anthropic/claude-opus-4.8",
      thinking: "xhigh",
      tools: [],
    });
  });

  it("preserves partial map artifacts and resumes from a fatal Pi runtime failure", async () => {
    const failedProvider = (await createProvider({ failAt: "pi" })).provider;
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const failed = await runScan({
      sourceInput: fixtureUrl,
      runsRoot,
      sandboxProvider: failedProvider,
    });

    expect(failed.exitCode).toBe(1);
    const runDir = expectRunDir(failed);
    const failedRunPath = path.join(runDir, "run.json");
    const failedRun = await readJson<{
      artifacts: Record<string, string | string[] | undefined>;
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
    expect(failedRun.error.stage).toBe("pi");
    await expectPath(path.join(runDir, "outputs", "repo-map", "coverage-structure.json"));
    expect(
      await pathExists(path.join(runDir, "outputs", "repo-map", "stack-build-deps.json")),
    ).toBe(false);
    expect(await pathExists(path.join(runDir, "outputs", "repository-map.json"))).toBe(false);
    expect(await pathExists(path.join(runDir, "outputs", "attack-hypotheses.json"))).toBe(false);
    expect(failedRun.artifacts.diagnostics).toEqual(
      expect.arrayContaining([
        "outputs/diagnostics/sandbox-failure/manifest.json",
        "outputs/diagnostics/sandbox-failure/sandbox-failure.tar.gz",
      ]),
    );
    await expectPath(
      path.join(runDir, "outputs", "diagnostics", "sandbox-failure", "manifest.json"),
    );
    await expectPath(
      path.join(runDir, "outputs", "diagnostics", "sandbox-failure", "sandbox-failure.tar.gz"),
    );

    failedRun.sandbox.cleanup = { attempted: false, deleted: false, success: false };
    await writeFile(failedRunPath, `${JSON.stringify(failedRun, null, 2)}\n`, "utf8");
    const resumeProvider = (await createProvider()).provider;
    resumeProvider.liveSandboxIds.push(failedRun.sandbox.id);

    const resumed = await runResume({ runDir, sandboxProvider: resumeProvider });

    expect(resumed).toMatchObject({ exitCode: 0 });
    expect(resumeProvider.staleDeleteCalls).toContain(failedRun.sandbox.id);
    expect(resumeProvider.createdSandboxIds).toHaveLength(1);
    expect(resumeProvider.liveSandboxIds).toEqual([]);

    const resumedCommands =
      resumeProvider.sessions
        .at(-1)
        ?.commands.filter((command) => command.command.startsWith("vibeshield-runtime-job"))
        .map((command) => command.command) ?? [];
    expect(resumedCommands[0]).toContain("stack-deps");
    expect(resumedCommands.some((command) => command.includes("coverage-structure"))).toBe(false);
    for (const artifact of expectedAcceptedArtifacts) {
      await expectPath(path.join(runDir, artifact));
    }

    const resumedRun = await readJson<{
      steps: Array<{ name: string; status: string }>;
    }>(failedRunPath);
    expect(resumedRun.steps.filter((step) => step.name === "pi-repository-mapping")).toHaveLength(
      1,
    );
    expect(resumedRun.steps.every((step) => step.status === "success")).toBe(true);
  });

  it("reruns only attack hypotheses when resume starts from attack-hypotheses", async () => {
    const initial = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");
    const scanned = await runScan({
      sourceInput: fixtureUrl,
      runsRoot,
      sandboxProvider: initial.provider,
    });

    expect(scanned.exitCode).toBe(0);
    const runDir = expectRunDir(scanned);
    const rerunHypotheses = fakeAttackHypotheses();
    const firstHypothesis = rerunHypotheses.hypotheses[0];
    if (firstHypothesis === undefined) {
      throw new Error("Fake attack hypotheses fixture is empty.");
    }
    rerunHypotheses.hypotheses[0] = {
      ...firstHypothesis,
      id: "hyp-rerun-from-cli",
      title: "Rerun generated attack hypothesis",
    };
    rerunHypotheses.summary = {
      ...rerunHypotheses.summary,
      text: "Rerun attack hypotheses are derived from the existing repository map.",
    };

    const sandboxRoot = await createTempRoot("vibeshield-fake-daytona-rerun-");
    const resumeProvider = new FakeDaytonaSandboxProvider({
      fixtureRepos: new Map([[fixtureUrl, initial.fixtureRepo]]),
      piOutputs: {
        ...fixtureRepoMapOutputs(),
        "attack-hypotheses": rerunHypotheses,
      },
      sandboxRoot,
    });
    const resumed = await runResume({
      fromStep: "attack-hypotheses",
      runDir,
      sandboxProvider: resumeProvider,
    });

    expect(resumed.exitCode).toBe(0);
    const runtimeCommands =
      resumeProvider.sessions
        .at(-1)
        ?.commands.filter((command) => command.command.startsWith("vibeshield-runtime-job"))
        .map((command) => command.command) ?? [];
    expect(runtimeCommands).toHaveLength(1);
    expect(runtimeCommands[0]).toBe(
      "vibeshield-runtime-job pi-repository-mapping pi-attack-hypotheses",
    );

    const attackHypotheses = await readJson<AttackHypothesesArtifact>(
      path.join(runDir, "outputs", "attack-hypotheses.json"),
    );
    expect(attackHypotheses.summary.text).toBe(
      "Rerun attack hypotheses are derived from the existing repository map.",
    );
    expect(attackHypotheses.hypotheses.map((hypothesis) => hypothesis.id)).toContain(
      "hyp-rerun-from-cli",
    );
    await expectPath(path.join(runDir, "outputs", "repository-map.json"));
    expect(await readFile(path.join(runDir, "final-report.md"), "utf8")).toContain(
      "Rerun generated attack hypothesis",
    );
    expect((await readFile(path.join(runDir, "final-report.pdf"))).subarray(0, 4).toString()).toBe(
      "%PDF",
    );
  });

  it("rerenders only final reports when resume starts from final-report", async () => {
    const initial = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");
    const scanned = await runScan({
      sourceInput: fixtureUrl,
      runsRoot,
      sandboxProvider: initial.provider,
    });

    expect(scanned.exitCode).toBe(0);
    const runDir = expectRunDir(scanned);
    await rm(path.join(runDir, "final-report.md"), { force: true });
    await rm(path.join(runDir, "final-report.pdf"), { force: true });

    const sandboxRoot = await createTempRoot("vibeshield-fake-daytona-report-rerun-");
    const resumeProvider = new FakeDaytonaSandboxProvider({
      fixtureRepos: new Map([[fixtureUrl, initial.fixtureRepo]]),
      piOutputs: fixtureRepoMapOutputs(),
      sandboxRoot,
    });
    const resumed = await runResume({
      fromStep: "final-report",
      runDir,
      sandboxProvider: resumeProvider,
    });

    expect(resumed.exitCode).toBe(0);
    const runtimeCommands =
      resumeProvider.sessions
        .at(-1)
        ?.commands.filter((command) => command.command.startsWith("vibeshield-runtime-job"))
        .map((command) => command.command) ?? [];
    expect(runtimeCommands).toHaveLength(0);
    expect(await readFile(path.join(runDir, "final-report.md"), "utf8")).toContain(
      "# Security Report",
    );
    expect((await readFile(path.join(runDir, "final-report.pdf"))).subarray(0, 4).toString()).toBe(
      "%PDF",
    );
  });

  it("records a degraded map section and still writes the final report when Pi output is unusable", async () => {
    const { provider } = await createProvider({
      piOutputs: {
        entrypoints: {
          rawText: "entrypoints were found but no JSON object was produced",
        },
      },
    });

    const result = await runScan({
      sourceInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    const entrypoints = await readJson<EntrypointsArtifact>(
      path.join(runDir, "outputs", "repo-map", "entrypoints.json"),
    );
    expect(entrypoints.entrypoints).toEqual([]);
    expect(entrypoints.metadata).toMatchObject({
      degraded: {
        raw_artifact: "outputs/pi/entrypoints/entrypoints.raw.redacted.txt",
      },
    });
    const report = await readFile(path.join(runDir, "final-report.md"), "utf8");
    expect(report).toContain("# Security Report");
    expect(report).toContain("## Leads to check");
    await expectPath(path.join(runDir, "outputs", "repository-map.json"));
    await expectPath(path.join(runDir, "outputs", "attack-hypotheses.json"));
  });

  it("accepts a single markdown JSON fence around a Pi final response", async () => {
    const fencedEntrypoints = fakeRepoMapEntrypoints();
    const { provider } = await createProvider({
      piOutputs: {
        entrypoints: {
          rawText: `\`\`\`json\n${JSON.stringify(fencedEntrypoints, null, 2)}\n\`\`\``,
        },
      },
    });

    const result = await runScan({
      sourceInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    const entrypoints = await readJson<EntrypointsArtifact>(
      path.join(runDir, "outputs", "repo-map", "entrypoints.json"),
    );
    expect(entrypoints.entrypoints).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: "entry-http-spam" })]),
    );
  });

  it("recovers fenced JSON from a Pi final response with surrounding prose", async () => {
    const fencedConfigSecrets = fakeRepoMapConfigSecrets();
    const { provider } = await createProvider({
      piOutputs: {
        "config-secrets": {
          rawText: `Now I have sufficient evidence.\n\n\`\`\`json\n${JSON.stringify(
            fencedConfigSecrets,
            null,
            2,
          )}\n\`\`\``,
        },
      },
    });

    const result = await runScan({
      sourceInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    const configSecrets = await readJson<ConfigSecretsArtifact>(
      path.join(runDir, "outputs", "repo-map", "config-secrets.json"),
    );
    expect(configSecrets.config).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: "config-api-base-url" })]),
    );
    expect(configSecrets.metadata).toMatchObject({
      pi: {
        json_delivery: "fenced",
        repair_applied: false,
      },
    });
  });

  it("repairs a salvageable Pi JSON final response before schema validation", async () => {
    const rawEntrypoints = `${JSON.stringify(fakeRepoMapEntrypoints(), null, 2).replace(
      /\n}$/,
      ",\n}",
    )}`;
    const { provider } = await createProvider({
      piOutputs: {
        entrypoints: {
          rawText: rawEntrypoints,
        },
      },
    });

    const result = await runScan({
      sourceInput: fixtureUrl,
      runsRoot: await createTempRoot("vibeshield-runs-"),
      sandboxProvider: provider,
    });

    expect(result.exitCode).toBe(0);
    const runDir = expectRunDir(result);
    const entrypoints = await readJson<EntrypointsArtifact>(
      path.join(runDir, "outputs", "repo-map", "entrypoints.json"),
    );
    expect(entrypoints.entrypoints).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: "entry-http-spam" })]),
    );
    expect(entrypoints.metadata).toMatchObject({
      pi: {
        json_delivery: "repaired",
        repair_applied: true,
      },
    });
  });
});

async function createProvider(
  options: {
    failAt?: "baseline" | "baseline-prepare" | "clone" | "inventory" | "pi";
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

function expectObjectContext(value: unknown): Record<string, unknown> {
  expect(value).toBeDefined();
  expect(value).not.toBeNull();
  expect(typeof value).toBe("object");
  expect(Array.isArray(value)).toBe(false);
  return value as Record<string, unknown>;
}

function jsonText(value: unknown): string {
  return JSON.stringify(value);
}

function expectRunDir(result: { runDir?: string }): string {
  expect(result.runDir).toBeDefined();
  return result.runDir ?? "";
}

function fixtureRepoMapOutputs(): NonNullable<
  ConstructorParameters<typeof FakeDaytonaSandboxProvider>[0]["piOutputs"]
> {
  const outputs = {
    "attack-hypotheses": fakeAttackHypotheses(),
    "auth-access": fakeRepoMapAuthAccess(),
    "config-secrets": fakeRepoMapConfigSecrets(),
    "coverage-structure": fakeRepoMapCoverageStructure(),
    crypto: fakeRepoMapCrypto(),
    "data-flows": fakeRepoMapDataFlows(),
    entrypoints: fakeRepoMapEntrypoints(),
    "external-integrations-egress": fakeRepoMapExternalIntegrationsEgress(),
    "infra-deploy": fakeRepoMapInfraDeploy(),
    "logging-observability": fakeRepoMapLoggingObservability(),
    "operation-sinks": fakeRepoMapOperationSinks(),
    "repository-map": fakeRepositoryMap(),
    "stack-build-deps": fakeRepoMapStackBuildDeps(),
    "storage-data-model": fakeRepoMapStorageDataModel(),
    "trust-boundaries": fakeRepoMapTrustBoundaries(),
  };

  return {
    ...outputs,
    "repo-map/attack-hypotheses": outputs["attack-hypotheses"],
    "repo-map/auth-access": outputs["auth-access"],
    "repo-map/config-secrets": outputs["config-secrets"],
    "repo-map/coverage-structure": outputs["coverage-structure"],
    "repo-map/crypto": outputs.crypto,
    "repo-map/data-flows": outputs["data-flows"],
    "repo-map/entrypoints": outputs.entrypoints,
    "repo-map/external-integrations-egress": outputs["external-integrations-egress"],
    "repo-map/infra-deploy": outputs["infra-deploy"],
    "repo-map/logging-observability": outputs["logging-observability"],
    "repo-map/operation-sinks": outputs["operation-sinks"],
    "repo-map/repository-map": outputs["repository-map"],
    "repo-map/stack-build-deps": outputs["stack-build-deps"],
    "repo-map/storage-data-model": outputs["storage-data-model"],
    "repo-map/trust-boundaries": outputs["trust-boundaries"],
    "repo-map-attack-hypotheses": outputs["attack-hypotheses"],
    "repo-map-auth-access": outputs["auth-access"],
    "repo-map-config-secrets": outputs["config-secrets"],
    "repo-map-coverage-structure": outputs["coverage-structure"],
    "repo-map-crypto": outputs.crypto,
    "repo-map-data-flows": outputs["data-flows"],
    "repo-map-entrypoints": outputs.entrypoints,
    "repo-map-external-integrations-egress": outputs["external-integrations-egress"],
    "repo-map-infra-deploy": outputs["infra-deploy"],
    "repo-map-logging-observability": outputs["logging-observability"],
    "repo-map-operation-sinks": outputs["operation-sinks"],
    "repo-map-repository-map": outputs["repository-map"],
    "repo-map-stack-build-deps": outputs["stack-build-deps"],
    "repo-map-storage-data-model": outputs["storage-data-model"],
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
    "attack-hypotheses": {
      ...minimalSection("attack-hypotheses"),
      blocking_fact_gaps: [],
      cross_cutting_chains: [],
      deprioritized_areas: [],
      executive_summary: {
        hypothesis_counts: {},
        limitations: ["Minimal fixture has no mapped attack chain."],
        strong_hypothesis_count: 0,
        text: "No strong attack hypotheses for minimal fixture.",
        top_risk_areas: [],
      },
      hypotheses: [],
      inputs: {
        repository_map_artifact: "outputs/repository-map.json",
      },
      summary: {
        evidence: ["README.md:1"],
        text: "No attack hypotheses for minimal fixture.",
      },
      validation_roadmap: {
        deep_dive: [],
        first_pass: [],
        later_hardening: [],
      },
    },
    "auth-access": {
      ...minimalSection("auth-access"),
      auth: [],
      entrypoint_access: [],
    },
    "config-secrets": {
      ...minimalSection("config-secrets"),
      config: [],
      secret_locations: [],
    },
    "coverage-structure": minimalSection("coverage-structure"),
    crypto: { ...minimalSection("crypto"), crypto: [] },
    "data-flows": {
      ...minimalSection("data-flows"),
      flows: [],
      inputs: {
        entrypoints_artifact: "outputs/repo-map/entrypoints.json",
        operation_sinks_artifact: "outputs/repo-map/operation-sinks.json",
      },
    },
    entrypoints: { ...minimalSection("entrypoints"), entrypoints: [] },
    "external-integrations-egress": {
      ...minimalSection("external-integrations-egress"),
      integrations: [],
    },
    "infra-deploy": {
      ...minimalSection("infra-deploy"),
      ci: [],
      infra: [],
    },
    "logging-observability": {
      ...minimalSection("logging-observability"),
      logging: [],
    },
    "operation-sinks": { ...minimalSection("operation-sinks"), operation_sinks: [] },
    "repository-map": minimalMap,
    "stack-build-deps": {
      ...minimalSection("stack-build-deps"),
      build: { commands: [], lockfiles: [], manifests: [] },
      dependencies: [],
      stack: [],
    },
    "storage-data-model": {
      ...minimalSection("storage-data-model"),
      storage: [],
    },
    "trust-boundaries": { ...minimalSection("trust-boundaries"), boundaries: [] },
  };
}

function minimalSection(kind: string) {
  const section = {
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
  return kind === "coverage-structure" ? { ...section, repository_structure: [] } : section;
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

function fakeRepoMapAuthAccess(): AuthAccessArtifact {
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
    coverage: fakeCoverage("Auth and access control", ["src/auth.ts:2", "src/server.ts:5"]),
    entrypoint_access: [
      {
        entrypoint_id: "entry-http-spam",
        evidence: ["src/server.ts:5", "src/auth.ts:2"],
        mechanism: "session",
        status: "protected",
      },
    ],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "auth-access",
    metadata: fakeRepoMapMetadata("auth-access"),
    repo: fakeRepo(),
  };
}

function fakeRepoMapConfigSecrets(): ConfigSecretsArtifact {
  return {
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
    coverage: fakeCoverage("Configuration and secret references", [
      "src/config.ts:1",
      ".env.example:1",
    ]),
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "config-secrets",
    metadata: fakeRepoMapMetadata("config-secrets"),
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

function fakeRepoMapStorageDataModel(): StorageDataModelArtifact {
  return {
    coverage: fakeCoverage("Storage and data model", ["src/db.ts:2", "src/schema.sql:1"]),
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "storage-data-model",
    metadata: fakeRepoMapMetadata("storage-data-model"),
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

function fakeRepoMapExternalIntegrationsEgress(): ExternalIntegrationsEgressArtifact {
  return {
    coverage: fakeCoverage("External integrations and egress", ["src/http.ts:3"]),
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
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
    kind: "external-integrations-egress",
    metadata: fakeRepoMapMetadata("external-integrations-egress"),
    repo: fakeRepo(),
  };
}

function fakeRepoMapInfraDeploy(): InfraDeployArtifact {
  return {
    ci: [
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
    coverage: fakeCoverage("Infrastructure and deployment", [
      "Dockerfile:1",
      "infra/main.tf:1",
      ".github/workflows/ci.yml:1",
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
    ],
    kind: "infra-deploy",
    metadata: fakeRepoMapMetadata("infra-deploy"),
    repo: fakeRepo(),
  };
}

function fakeRepoMapOperationSinks(): OperationSinksArtifact {
  return {
    coverage: fakeCoverage("Operation sinks", ["src/db.ts:2", "src/files.ts:4", "src/http.ts:3"]),
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
    ],
    repo: fakeRepo(),
  };
}

function fakeRepoMapCrypto(): CryptoArtifact {
  return {
    coverage: fakeCoverage("Crypto and randomness", ["src/crypto.ts:2", "src/crypto.ts:3"]),
    crypto: [
      {
        confidence: "high",
        evidence: ["src/crypto.ts:2"],
        id: "crypto-hmac",
        kind: "crypto_operation",
        location: "src/crypto.ts",
        name: "HMAC signing",
        operation: "createHmac sha256",
      },
      {
        confidence: "high",
        evidence: ["src/crypto.ts:3"],
        id: "crypto-random-token",
        kind: "randomness",
        location: "src/crypto.ts",
        name: "random token generation",
        operation: "randomBytes token generation",
      },
    ],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "crypto",
    metadata: fakeRepoMapMetadata("crypto"),
    repo: fakeRepo(),
  };
}

function fakeRepoMapLoggingObservability(): LoggingObservabilityArtifact {
  return {
    coverage: fakeCoverage("Logging and observability", ["src/logger.ts:2"]),
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "logging-observability",
    logging: [
      {
        confidence: "high",
        evidence: ["src/logger.ts:2"],
        id: "log-audit-value",
        kind: "logging",
        location: "src/logger.ts",
        logged_fields: ["value"],
        name: "audit log",
        operation: "console.log audit value",
      },
    ],
    metadata: fakeRepoMapMetadata("logging-observability"),
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
        source_artifact_ids: ["entrypoints", "auth-access", "data-flows"],
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
      auth_access_artifact: "outputs/repo-map/auth-access.json",
      config_secrets_artifact: "outputs/repo-map/config-secrets.json",
      coverage_structure_artifact: "outputs/repo-map/coverage-structure.json",
      crypto_artifact: "outputs/repo-map/crypto.json",
      data_flows_artifact: "outputs/repo-map/data-flows.json",
      entrypoints_artifact: "outputs/repo-map/entrypoints.json",
      external_integrations_egress_artifact: "outputs/repo-map/external-integrations-egress.json",
      infra_deploy_artifact: "outputs/repo-map/infra-deploy.json",
      logging_observability_artifact: "outputs/repo-map/logging-observability.json",
      operation_sinks_artifact: "outputs/repo-map/operation-sinks.json",
      stack_build_deps_artifact: "outputs/repo-map/stack-build-deps.json",
      storage_data_model_artifact: "outputs/repo-map/storage-data-model.json",
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
      auth_access_artifact: "outputs/repo-map/auth-access.json",
      config_secrets_artifact: "outputs/repo-map/config-secrets.json",
      coverage_structure_artifact: "outputs/repo-map/coverage-structure.json",
      crypto_artifact: "outputs/repo-map/crypto.json",
      data_flows_artifact: "outputs/repo-map/data-flows.json",
      entrypoints_artifact: "outputs/repo-map/entrypoints.json",
      external_integrations_egress_artifact: "outputs/repo-map/external-integrations-egress.json",
      infra_deploy_artifact: "outputs/repo-map/infra-deploy.json",
      logging_observability_artifact: "outputs/repo-map/logging-observability.json",
      operation_sinks_artifact: "outputs/repo-map/operation-sinks.json",
      stack_build_deps_artifact: "outputs/repo-map/stack-build-deps.json",
      storage_data_model_artifact: "outputs/repo-map/storage-data-model.json",
      trust_boundaries_artifact: "outputs/repo-map/trust-boundaries.json",
    },
    kind: "repository-map",
    metadata: fakeRepoMapMetadata("repository-map"),
    repo: fakeRepo(),
    sections: [
      repoMapSection("coverage-structure", "outputs/repo-map/coverage-structure.json", 3),
      repoMapSection("stack-build-deps", "outputs/repo-map/stack-build-deps.json", 4),
      repoMapSection("entrypoints", "outputs/repo-map/entrypoints.json", 4),
      repoMapSection("auth-access", "outputs/repo-map/auth-access.json", 4),
      repoMapSection("config-secrets", "outputs/repo-map/config-secrets.json", 7),
      repoMapSection("storage-data-model", "outputs/repo-map/storage-data-model.json", 2),
      repoMapSection(
        "external-integrations-egress",
        "outputs/repo-map/external-integrations-egress.json",
        1,
      ),
      repoMapSection("infra-deploy", "outputs/repo-map/infra-deploy.json", 3),
      repoMapSection("operation-sinks", "outputs/repo-map/operation-sinks.json", 6),
      repoMapSection("crypto", "outputs/repo-map/crypto.json", 2),
      repoMapSection("logging-observability", "outputs/repo-map/logging-observability.json", 1),
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

function fakeAttackHypotheses(): AttackHypothesesArtifact {
  return {
    blocking_fact_gaps: [],
    coverage: fakeCoverage("Attack hypothesis generation", [
      "entry-http-spam",
      "flow-http-spam-db",
      "sink-db-insert",
    ]),
    cross_cutting_chains: [],
    deprioritized_areas: [],
    executive_summary: {
      hypothesis_counts: { P2: 1 },
      limitations: ["Fixture hypotheses are generated from static map facts only."],
      strong_hypothesis_count: 1,
      text: "One medium-priority hypothesis links external HTTP input to a database write.",
      top_risk_areas: ["HTTP input to database write"],
    },
    fact_gaps: [],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    hypotheses: [
      {
        attack_path: [
          "entry-http-spam accepts external HTTP input",
          "flow-http-spam-db connects the entrypoint to sink-db-insert",
          "sink-db-insert writes request-derived text to the database",
        ],
        attack_vector:
          "Validate whether request-controlled text can reach database insertion without expected normalization or authorization checks.",
        asset_at_risk: "stored message data",
        auth_context: "protected",
        category: "data validation",
        confidence: "medium",
        entry_point: "POST /api/spam",
        evidence: [
          { detail: "entry-http-spam", type: "Entrypoint" },
          { detail: "flow-http-spam-db", type: "Data flow status" },
          { detail: "sink-db-insert", type: "Sink" },
        ],
        id: "hyp-http-spam-db-input",
        intermediates: ["saveMessage"],
        likely_remediation_if_confirmed: [
          "Enforce handler-level validation before persistence.",
          "Keep database operations parameterized.",
        ],
        missing_facts_to_validate: [
          "handler-level validation around req.body.text",
          "database query parameterization details",
          "authorization expectations for the route",
        ],
        notes: [],
        potential_impact:
          "If validated, malformed or unauthorized external input may affect stored message data.",
        preconditions: [
          "attacker can reach POST /api/spam",
          "session middleware allows the attacker or is bypassable",
        ],
        priority: "P2",
        refutes_if: [
          "Request body text is validated before saveMessage.",
          "The route is reachable only by the intended trusted role.",
        ],
        safe_dynamic_checks: [
          "Verify validation behavior for malformed text using non-destructive test cases.",
        ],
        sink: "sink-db-insert",
        source: "req.body.text",
        status: "hypothesis",
        supporting_map_evidence: [
          "entry-http-spam",
          "flow-http-spam-db",
          "sink-db-insert",
          "src/server.ts:5",
          "src/db.ts:2",
        ],
        target_ids: ["entry-http-spam", "flow-http-spam-db", "sink-db-insert"],
        target_surface: "POST /api/spam to database write",
        title: "HTTP request body reaches database write",
        validation_plan: [
          "Review POST /api/spam handler validation before saveMessage.",
          "Review sink-db-insert query construction.",
          "Confirm expected authorization policy for entry-http-spam.",
        ],
        why_plausible: [
          "The map records an HTTP entrypoint for POST /api/spam.",
          "The map records a direct observed flow to sink-db-insert.",
          "The sink writes request-derived text to storage.",
        ],
      },
    ],
    inputs: {
      repository_map_artifact: "outputs/repository-map.json",
    },
    kind: "attack-hypotheses",
    metadata: fakeRepoMapMetadata("attack-hypotheses"),
    repo: fakeRepo(),
    summary: {
      confidence: "medium",
      evidence: ["entry-http-spam", "flow-http-spam-db", "sink-db-insert"],
      text: "Fixture attack hypotheses are derived from accepted repository-map facts.",
    },
    validation_roadmap: {
      deep_dive: ["Trace handler validation and storage constraints."],
      first_pass: ["Review POST /api/spam to sink-db-insert reachability."],
      later_hardening: ["Add regression tests for rejected malformed inputs."],
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
  const operationSinks = input.sinks.operation_sinks;
  const sinkIds = new Set(operationSinks.map((sink) => sink.id));
  const flowIds = new Set(input.dataFlows.flows.map((flow) => flow.id));
  const knownSourceArtifacts = new Set([
    "auth-access",
    "config-secrets",
    "coverage-structure",
    "crypto",
    "data-flows",
    "entrypoints",
    "external-integrations-egress",
    "infra-deploy",
    "logging-observability",
    "operation-sinks",
    "stack-build-deps",
    "storage-data-model",
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
}
