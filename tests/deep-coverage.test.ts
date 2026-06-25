import { describe, expect, it } from "vitest";
import type {
  DeepCoverage,
  DeepCoverageArea,
  DeepCoverageState,
} from "../src/domain/deep-coverage.js";
import { validateDeepCoverage } from "../src/domain/deep-coverage.js";
import type { Manifest } from "../src/domain/manifest.js";
import type { ProgramAnalysisCoverage } from "../src/ports/program-analysis-backend.js";
import { composeDeepCoverage } from "../src/stages/deep-coverage.js";

describe("DeepCoverage validation", () => {
  it("rejects unknown areas, unknown states, invalid counts, and duplicate producers", () => {
    expect(() =>
      validateDeepCoverage(
        coverage({ entries: [{ ...entry(), area: "unknown" as DeepCoverageArea }] }),
      ),
    ).toThrow(/deepCoverage unknown area is invalid: unknown/);

    expect(() =>
      validateDeepCoverage(
        coverage({ entries: [{ ...entry(), state: "unknown" as DeepCoverageState }] }),
      ),
    ).toThrow(/deepCoverage boundaries state is invalid: unknown/);

    expect(() =>
      validateDeepCoverage(coverage({ entries: [{ ...entry(), coveredCount: 2, totalCount: 1 }] })),
    ).toThrow(/coveredCount exceeds totalCount/);

    expect(() => validateDeepCoverage(coverage({ entries: [entry(), entry()] }))).toThrow(
      /deepCoverage entry key is duplicated: boundaries:joern/,
    );
  });
});

describe("composeDeepCoverage", () => {
  it("maps backend and graph coverage into a stable deepCoverage surface", () => {
    const backendCoverage: ProgramAnalysisCoverage[] = [
      {
        area: "language_support",
        state: "partial",
        coveredCount: 1,
        totalCount: 2,
        reason: "Some source languages are not supported by Deep Static v1: ruby=1.",
        producer: "joern",
        producerVersion: "joern@4.0.565",
      },
      { area: "model", state: "checked", producer: "joern", producerVersion: "joern@4.0.565" },
    ];
    const deepCoverage = composeDeepCoverage({
      runId: "run-1",
      snapshotId: "snapshot-1",
      manifest: manifest(),
      backendCoverage,
      graphCoverage: [
        {
          area: "boundaries",
          state: "checked",
          coveredCount: 1,
          totalCount: 1,
          producer: "joern",
          producerVersion: "joern@4.0.565",
        },
        {
          area: "call_graph",
          state: "partial",
          coveredCount: 1,
          totalCount: 2,
          reason: "one call target was ambiguous",
          producer: "joern",
          producerVersion: "joern@4.0.565",
        },
        {
          area: "data_flow",
          state: "checked",
          coveredCount: 1,
          totalCount: 1,
          producer: "joern",
          producerVersion: "joern@4.0.565",
        },
      ],
      createdAt: "2026-06-24T10:00:00Z",
    });

    expect(deepCoverage.entries.map((item) => [item.area, item.state, item.producer])).toEqual([
      ["boundaries", "checked", "joern"],
      ["call_graph", "partial", "joern"],
      ["ci_iac", "skipped", "vibeshield"],
      ["component_usage", "skipped", "vibeshield"],
      ["data_flow", "checked", "joern"],
      ["dependency_usage", "skipped", "vibeshield"],
      ["entities", "skipped", "vibeshield"],
      ["language_support", "partial", "joern"],
      ["model", "checked", "joern"],
    ]);
  });

  it("keeps backend failures and unsupported languages visible as incomplete coverage", () => {
    const backendCoverage: ProgramAnalysisCoverage[] = [
      {
        area: "language_support",
        state: "degraded",
        coveredCount: 0,
        totalCount: 1,
        reason:
          "No supported JS/TS/Java/Python/Go source files found; unsupported source languages: ruby=1.",
        producer: "joern",
        producerVersion: "joern@4.0.565",
      },
      {
        area: "model",
        state: "failed",
        reason: "Joern process exited 137",
        producer: "joern",
        producerVersion: "joern@4.0.565",
      },
    ];
    const deepCoverage = composeDeepCoverage({
      runId: "run-1",
      snapshotId: "snapshot-1",
      manifest: unsupportedManifest(),
      backendCoverage,
      createdAt: "2026-06-24T10:00:00Z",
    });

    const byArea = new Map(deepCoverage.entries.map((item) => [item.area, item]));
    expect(byArea.get("language_support")).toMatchObject({
      state: "degraded",
      reason:
        "No supported JS/TS/Java/Python/Go source files found; unsupported source languages: ruby=1.",
    });
    expect(byArea.get("model")).toMatchObject({
      state: "failed",
      reason: "Joern process exited 137",
    });
    expect(byArea.get("boundaries")).toMatchObject({
      state: "skipped",
      reason: "Boundary graph coverage has not been produced yet.",
    });
  });
});

function coverage(overrides: Partial<DeepCoverage> = {}): DeepCoverage {
  return {
    runId: "run-1",
    snapshotId: "snapshot-1",
    createdAt: "2026-06-24T10:00:00Z",
    entries: [entry()],
    ...overrides,
  };
}

function entry() {
  return {
    area: "boundaries" as const,
    state: "checked" as const,
    coveredCount: 1,
    totalCount: 1,
    producer: "joern",
    producerVersion: "joern@4.0.565",
  };
}

function manifest(): Manifest {
  return {
    origin: { kind: "local", path: "/repo" },
    commitSha: "abc123",
    sourceHash: "snapshot-1",
    files: [
      { path: "src/index.ts", size: 100, sha256: "ts-sha" },
      { path: "src/legacy.rb", size: 80, sha256: "rb-sha" },
    ],
    exclusions: [],
    toolchain: { imageTag: "vibeshield-toolchain:test", tools: [] },
    createdAt: "2026-06-24T10:00:00Z",
  };
}

function unsupportedManifest(): Manifest {
  return {
    ...manifest(),
    files: [{ path: "lib/app.rb", size: 100, sha256: "rb-sha" }],
  };
}
