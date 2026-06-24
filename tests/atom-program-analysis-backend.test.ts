import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AtomProgramAnalysisBackend } from "../src/adapters/atom-program-analysis-backend.js";
import { FakeSandboxSession } from "../src/adapters/fake-sandbox.js";
import type { Manifest } from "../src/domain/manifest.js";
import type { StoredBlob } from "../src/ports/artifact-store.js";
import {
  languageSupportFromManifest,
  type ProgramAnalysisModelRef,
} from "../src/ports/program-analysis-backend.js";
import {
  ATOM_BOUNDARIES_SLICE_PATH,
  ATOM_CALL_EDGES_SLICE_PATH,
  ATOM_COMPONENT_USAGE_SLICE_PATH,
  ATOM_ENTITIES_SLICE_PATH,
  ATOM_FLOWS_SLICE_PATH,
  ATOM_MODEL_PATH,
  SOURCE_DIR,
} from "../src/stages/paths.js";

describe("AtomProgramAnalysisBackend language", () => {
  it("reports supported JS/TS/Python and unsupported source language coverage", () => {
    const support = languageSupportFromManifest(
      manifest(["src/app.ts", "src/worker.js", "tools/audit.py", "cmd/main.go", "README.md"]),
    );

    expect(support.selectedLanguage).toBe("typescript");
    expect(support.supported).toEqual([
      { language: "javascript", fileCount: 1 },
      { language: "python", fileCount: 1 },
      { language: "typescript", fileCount: 1 },
    ]);
    expect(support.unsupported).toEqual([{ language: "go", fileCount: 1 }]);
    expect(support.coverageState).toBe("partial");
    expect(support.reason).toContain("go=1");
  });
});

describe("AtomProgramAnalysisBackend buildModel", () => {
  it("uses documented atom argv and stores raw app.atom bytes in CAS", async () => {
    const artifacts = new MemoryArtifacts();
    const session = new FakeSandboxSession("atom-test", (command, currentSession) => {
      if (command[0] === "atom" && command[1] === "-o") {
        currentSession.files.set(ATOM_MODEL_PATH, bytes("atom-model"));
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const backend = new AtomProgramAnalysisBackend({ session, artifacts });

    const model = await backend.buildModel({
      sourceDir: SOURCE_DIR,
      manifest: manifest(["src/app.ts"]),
    });

    expect(session.invocations[0]?.command).toEqual([
      "atom",
      "-o",
      ATOM_MODEL_PATH,
      "-l",
      "typescript",
      SOURCE_DIR,
    ]);
    expect(model).toMatchObject({
      backend: "atom",
      backendVersion: "atom@2.5.6",
      language: "typescript",
      sourceDir: SOURCE_DIR,
      modelPath: ATOM_MODEL_PATH,
      artifact: { role: "program-analysis.raw", bytes: 10 },
    });
    await expect(artifacts.read(model.artifact.blobSha256)).resolves.toEqual(bytes("atom-model"));
  });
});

describe("AtomProgramAnalysisBackend extract", () => {
  it("runs Atom slice commands, parses JSON, and stores raw slice artifacts", async () => {
    const artifacts = new MemoryArtifacts();
    const session = new FakeSandboxSession("atom-test", (command, currentSession) => {
      const slicePath = valueAfter(command, "-s");
      if (slicePath !== undefined) {
        currentSession.files.set(
          slicePath,
          jsonBytes([{ kind: command[1], fileName: "src/app.ts" }]),
        );
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const backend = new AtomProgramAnalysisBackend({ session, artifacts });
    const model = modelRef();

    const entities = await backend.extractEntities(model);
    const boundaries = await backend.extractBoundaries(model);
    const callEdges = await backend.extractCallEdges(model);
    const flows = await backend.extractFlows(model);
    const componentUsage = await backend.extractComponentUsage(model);

    expect(entities).toMatchObject({
      kind: "entities",
      slicePath: ATOM_ENTITIES_SLICE_PATH,
      sliceArtifact: { role: "program-analysis.slice" },
      parsed: [{ kind: "usages", fileName: "src/app.ts" }],
    });
    expect(boundaries.command[1]).toBe("usages");
    expect(callEdges.command).toEqual([
      "atom",
      "reachables",
      "-o",
      ATOM_MODEL_PATH,
      "-s",
      ATOM_CALL_EDGES_SLICE_PATH,
      "-l",
      "typescript",
      SOURCE_DIR,
    ]);
    expect(flows.command[1]).toBe("data-flow");
    expect(componentUsage.command[1]).toBe("reachables");
    expect(session.invocations.map((item) => item.command.at(5))).toEqual([
      ATOM_ENTITIES_SLICE_PATH,
      ATOM_BOUNDARIES_SLICE_PATH,
      ATOM_CALL_EDGES_SLICE_PATH,
      ATOM_FLOWS_SLICE_PATH,
      ATOM_COMPONENT_USAGE_SLICE_PATH,
    ]);
  });

  it("merges Atom numbered slice shards into one extraction artifact", async () => {
    const artifacts = new MemoryArtifacts();
    const session = new FakeSandboxSession("atom-test", (command, currentSession) => {
      const slicePath = valueAfter(command, "-s");
      if (slicePath !== undefined) {
        currentSession.files.set(slicePath, jsonBytes([{ kind: command[1], id: "primary" }]));
        currentSession.files.set(
          slicePath.replace(/\.json$/, "_1.json"),
          jsonBytes([{ kind: command[1], id: "shard-1" }]),
        );
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const backend = new AtomProgramAnalysisBackend({ session, artifacts });

    const callEdges = await backend.extractCallEdges(modelRef());

    expect(callEdges.parsed).toEqual([
      { kind: "reachables", id: "primary" },
      { kind: "reachables", id: "shard-1" },
    ]);
    await expect(artifacts.read(callEdges.sliceArtifact.blobSha256)).resolves.toEqual(
      jsonBytes([
        { kind: "reachables", id: "primary" },
        { kind: "reachables", id: "shard-1" },
      ]),
    );
  });
});

describe("AtomProgramAnalysisBackend failure", () => {
  it("throws clear backend errors for non-zero exits, missing outputs, and invalid JSON", async () => {
    const nonZero = new AtomProgramAnalysisBackend({
      artifacts: new MemoryArtifacts(),
      session: new FakeSandboxSession("atom-test", () => ({
        exitCode: 127,
        stdout: "",
        stderr: "atom: not found",
      })),
    });

    await expect(
      nonZero.buildModel({ sourceDir: SOURCE_DIR, manifest: manifest(["src/app.ts"]) }),
    ).rejects.toMatchObject({
      code: "atom_exit_nonzero",
      message: "Atom model command failed with exit code 127. stderr: atom: not found",
    });

    const missing = new AtomProgramAnalysisBackend({
      artifacts: new MemoryArtifacts(),
      session: new FakeSandboxSession("atom-test", () => ({ exitCode: 0, stdout: "", stderr: "" })),
    });

    await expect(
      missing.buildModel({ sourceDir: SOURCE_DIR, manifest: manifest(["src/app.ts"]) }),
    ).rejects.toMatchObject({
      code: "atom_output_missing",
    });

    const invalidJson = new AtomProgramAnalysisBackend({
      artifacts: new MemoryArtifacts(),
      session: new FakeSandboxSession("atom-test", (command, currentSession) => {
        const slicePath = valueAfter(command, "-s");
        if (slicePath !== undefined) {
          currentSession.files.set(slicePath, bytes("not-json"));
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      }),
    });

    await expect(invalidJson.extractFlows(modelRef())).rejects.toMatchObject({
      code: "atom_invalid_json",
    });
  });
});

describe("AtomProgramAnalysisBackend coverage", () => {
  it("reports model coverage and backend failures without inventing facts", () => {
    const backend = new AtomProgramAnalysisBackend({
      artifacts: new MemoryArtifacts(),
      session: new FakeSandboxSession("atom-test", () => ({ exitCode: 0, stdout: "", stderr: "" })),
    });

    const coverage = backend.reportCoverage({
      manifest: manifest(["src/app.ts", "cmd/main.go"]),
      model: modelRef(),
      failures: [{ area: "flows", reason: "Atom data-flow command failed with exit code 1." }],
    });

    expect(coverage).toEqual([
      {
        area: "language_support",
        state: "partial",
        producer: "atom",
        producerVersion: "atom@2.5.6",
        coveredCount: 1,
        totalCount: 2,
        reason: "Some source languages are not supported by Deep Static v1: go=1.",
      },
      {
        area: "model",
        state: "checked",
        producer: "atom",
        producerVersion: "atom@2.5.6",
      },
      {
        area: "flows",
        state: "failed",
        producer: "atom",
        producerVersion: "atom@2.5.6",
        reason: "Atom data-flow command failed with exit code 1.",
      },
    ]);
  });
});

class MemoryArtifacts {
  readonly blobs = new Map<string, Uint8Array>();

  async store(data: Uint8Array): Promise<StoredBlob> {
    const sha256 = createHash("sha256").update(data).digest("hex");
    this.blobs.set(sha256, new Uint8Array(data));
    return { sha256, bytes: data.byteLength };
  }

  async read(sha256: string): Promise<Uint8Array> {
    const blob = this.blobs.get(sha256);
    if (blob === undefined) {
      throw new Error(`missing blob ${sha256}`);
    }
    return blob;
  }

  async exists(sha256: string): Promise<boolean> {
    return this.blobs.has(sha256);
  }
}

function modelRef(): ProgramAnalysisModelRef {
  return {
    backend: "atom",
    backendVersion: "atom@2.5.6",
    language: "typescript",
    sourceDir: SOURCE_DIR,
    modelPath: ATOM_MODEL_PATH,
    artifact: { blobSha256: "model-sha", role: "program-analysis.raw", bytes: 10 },
    command: ["atom", "-o", ATOM_MODEL_PATH, "-l", "typescript", SOURCE_DIR],
  };
}

function manifest(paths: string[]): Manifest {
  return {
    origin: { kind: "local", path: "/repo" },
    commitSha: "abc123",
    sourceHash: "source-sha",
    files: paths.map((repoPath, index) => ({
      path: repoPath,
      size: 10 + index,
      sha256: `sha-${index}`,
    })),
    exclusions: [],
    toolchain: {
      imageTag: "vibeshield-toolchain:test",
      tools: [],
    },
    createdAt: "2026-06-24T00:00:00.000Z",
  };
}

function valueAfter(command: ReadonlyArray<string>, flag: string): string | undefined {
  const index = command.indexOf(flag);
  return index < 0 ? undefined : command[index + 1];
}

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function jsonBytes(value: unknown): Uint8Array {
  return bytes(JSON.stringify(value));
}
