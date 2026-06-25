import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { FakeSandboxSession } from "../src/adapters/fake-sandbox.js";
import { JoernProgramAnalysisBackend } from "../src/adapters/joern-program-analysis-backend.js";
import type { Manifest } from "../src/domain/manifest.js";
import type { StoredBlob } from "../src/ports/artifact-store.js";
import type { EventSink, ScanEvent } from "../src/ports/event-sink.js";
import {
  languageSupportFromManifest,
  type ProgramAnalysisModelRef,
} from "../src/ports/program-analysis-backend.js";
import {
  JOERN_BOUNDARIES_SLICE_PATH,
  JOERN_CALL_EDGES_SLICE_PATH,
  JOERN_COMPONENT_USAGE_SLICE_PATH,
  JOERN_ENTITIES_SLICE_PATH,
  JOERN_FLOWS_SLICE_PATH,
  JOERN_MODEL_PATH,
  SOURCE_DIR,
} from "../src/stages/paths.js";

describe("JoernProgramAnalysisBackend language", () => {
  it("reports supported JS/TS/Java/Python/Go coverage", () => {
    const support = languageSupportFromManifest(
      manifest([
        "src/app.ts",
        "src/worker.js",
        "src/main/java/App.java",
        "tools/audit.py",
        "cmd/main.go",
        "README.md",
      ]),
    );

    expect(support.selectedLanguage).toBe("typescript");
    expect(support.supported).toEqual([
      { language: "go", fileCount: 1 },
      { language: "java", fileCount: 1 },
      { language: "javascript", fileCount: 1 },
      { language: "python", fileCount: 1 },
      { language: "typescript", fileCount: 1 },
    ]);
    expect(support.unsupported).toEqual([]);
    expect(support.coverageState).toBe("checked");
  });

  it("selects Java and Go when they are the primary supported source language", () => {
    expect(languageSupportFromManifest(manifest(["src/main/java/App.java"])).selectedLanguage).toBe(
      "java",
    );
    expect(languageSupportFromManifest(manifest(["cmd/server.go"])).selectedLanguage).toBe("go");
  });

  it("selects the dominant backend language instead of frontend assets", () => {
    const support = languageSupportFromManifest(
      manifest([
        "src/main/java/App.java",
        "src/main/java/Lesson.java",
        "src/main/resources/static/app.js",
      ]),
    );

    expect(support.selectedLanguage).toBe("java");
  });

  it("does not let checked-in static JavaScript assets hide a Go backend", () => {
    const assetFiles = Array.from(
      { length: 45 },
      (_, index) => `template/js/vendor/asset-${index}.min.js`,
    );
    const goFiles = [
      "server/main.go",
      "server/router.go",
      "vulnerable/open.go",
      "vulnerable/sql.go",
      "vulnerable/system.go",
      "vulnerable/sql_test.go",
      "vulnerable/system_test.go",
      "vulnerable/shi_test.go",
      "vulnerable/lfi_test.go",
    ];

    const support = languageSupportFromManifest(manifest([...assetFiles, ...goFiles]));

    expect(support.selectedLanguage).toBe("go");
    expect(support.supported).toEqual([
      { language: "go", fileCount: 9 },
      { language: "javascript", fileCount: 45 },
    ]);
  });
});

describe("JoernProgramAnalysisBackend buildModel", () => {
  it("uses joern-parse and stores raw CPG bytes in CAS", async () => {
    const artifacts = new MemoryArtifacts();
    const session = new FakeSandboxSession("joern-test", (command, currentSession) => {
      if (command[0] === "joern-parse") {
        currentSession.files.set(JOERN_MODEL_PATH, bytes("joern-cpg"));
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const backend = new JoernProgramAnalysisBackend({ session, artifacts });

    const model = await backend.buildModel({
      sourceDir: SOURCE_DIR,
      manifest: manifest(["src/app.ts"]),
    });

    expect(session.invocations[0]?.command).toEqual([
      "joern-parse",
      "--language",
      "javascript",
      "-o",
      JOERN_MODEL_PATH,
      SOURCE_DIR,
    ]);
    expect(session.invocations[0]?.timeoutMs).toBe(300_000);
    expect(model).toMatchObject({
      backend: "joern",
      backendVersion: "joern@4.0.565",
      language: "typescript",
      sourceDir: SOURCE_DIR,
      modelPath: JOERN_MODEL_PATH,
      artifact: { role: "program-analysis.raw", bytes: 9 },
    });
    await expect(artifacts.read(model.artifact.blobSha256)).resolves.toEqual(bytes("joern-cpg"));
  });

  it("maps Java and Go to Joern frontend names", async () => {
    const java = await buildModelFor(["src/main/java/App.java"]);
    const go = await buildModelFor(["cmd/server.go"]);

    expect(java.command).toContain("javasrc");
    expect(go.command).toContain("golang");
  });

  it("turns sandbox stream events into owner-facing progress without leaking raw output", async () => {
    const artifacts = new MemoryArtifacts();
    const events = new CollectingEvents();
    const session = new FakeSandboxSession("joern-test", (_command, currentSession, options) => {
      options.onEvent?.({ type: "started", pid: 42 });
      options.onEvent?.({ type: "stderr", data: "joern internal: parsing source files\n" });
      currentSession.files.set(JOERN_MODEL_PATH, bytes("joern-cpg"));
      options.onEvent?.({ type: "exited", exitCode: 0 });
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const backend = new JoernProgramAnalysisBackend({ session, artifacts, events });

    await backend.buildModel({
      sourceDir: SOURCE_DIR,
      manifest: manifest(["src/app.ts"]),
    });

    expect(events.events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "scan-progress",
          stageId: "deep.static.compose",
          message: "Building the code map",
          details: expect.objectContaining({
            publicLabel: "Building the code map",
            source: "sandbox",
            producer: "joern",
            area: "model",
          }),
        }),
        expect.objectContaining({
          type: "scan-progress",
          details: expect.objectContaining({
            stream: "stderr",
            bytes: "joern internal: parsing source files\n".length,
          }),
        }),
      ]),
    );
    expect(JSON.stringify(events.events)).not.toContain("joern internal");
  });
});

describe("JoernProgramAnalysisBackend extract", () => {
  it("runs the VibeShield Joern extractor, parses JSON, and stores raw slice artifacts", async () => {
    const artifacts = new MemoryArtifacts();
    const session = new FakeSandboxSession("joern-test", (command, currentSession) => {
      const slicePath = valueAfter(command, "-o");
      if (slicePath !== undefined) {
        currentSession.files.set(slicePath, jsonBytes([{ kind: valueAfter(command, "--kind") }]));
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const backend = new JoernProgramAnalysisBackend({ session, artifacts });
    const model = modelRef();

    const entities = await backend.extractEntities(model);
    const boundaries = await backend.extractBoundaries(model);
    const callEdges = await backend.extractCallEdges(model);
    const flows = await backend.extractFlows(model);
    const componentUsage = await backend.extractComponentUsage(model);

    expect(entities).toMatchObject({
      kind: "entities",
      slicePath: JOERN_ENTITIES_SLICE_PATH,
      sliceArtifact: { role: "program-analysis.slice" },
      parsed: [{ kind: "entities" }],
    });
    expect(callEdges.command).toEqual([
      "vibeshield-joern-extract",
      "--kind",
      "call_edges",
      "--cpg",
      JOERN_MODEL_PATH,
      "--source-root",
      SOURCE_DIR,
      "-o",
      JOERN_CALL_EDGES_SLICE_PATH,
    ]);
    expect(session.invocations.map((item) => valueAfter(item.command, "-o"))).toEqual([
      JOERN_ENTITIES_SLICE_PATH,
      JOERN_BOUNDARIES_SLICE_PATH,
      JOERN_CALL_EDGES_SLICE_PATH,
      JOERN_FLOWS_SLICE_PATH,
      JOERN_COMPONENT_USAGE_SLICE_PATH,
    ]);
    expect(boundaries.kind).toBe("boundaries");
    expect(flows.kind).toBe("flows");
    expect(componentUsage.kind).toBe("component_usage");
  });

  it("merges numbered Joern slice shards into one extraction artifact", async () => {
    const artifacts = new MemoryArtifacts();
    const session = new FakeSandboxSession("joern-test", (command, currentSession) => {
      const slicePath = valueAfter(command, "-o");
      const kind = valueAfter(command, "--kind");
      if (slicePath !== undefined) {
        currentSession.files.set(slicePath, jsonBytes([{ kind, id: "primary" }]));
        currentSession.files.set(
          slicePath.replace(/\.json$/, "_1.json"),
          jsonBytes([{ kind, id: "shard-1" }]),
        );
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const backend = new JoernProgramAnalysisBackend({ session, artifacts });

    const callEdges = await backend.extractCallEdges(modelRef());

    expect(callEdges.parsed).toEqual([
      { kind: "call_edges", id: "primary" },
      { kind: "call_edges", id: "shard-1" },
    ]);
    await expect(artifacts.read(callEdges.sliceArtifact.blobSha256)).resolves.toEqual(
      jsonBytes([
        { kind: "call_edges", id: "primary" },
        { kind: "call_edges", id: "shard-1" },
      ]),
    );
  });
});

describe("JoernProgramAnalysisBackend failure", () => {
  it("throws clear backend errors for non-zero exits, missing outputs, and invalid JSON", async () => {
    const nonZero = new JoernProgramAnalysisBackend({
      artifacts: new MemoryArtifacts(),
      session: new FakeSandboxSession("joern-test", () => ({
        exitCode: 127,
        stdout: "",
        stderr: "joern-parse: not found",
      })),
    });

    await expect(
      nonZero.buildModel({ sourceDir: SOURCE_DIR, manifest: manifest(["src/app.ts"]) }),
    ).rejects.toMatchObject({
      code: "joern_exit_nonzero",
      message: "Joern model command failed with exit code 127. stderr: joern-parse: not found",
    });

    const missing = new JoernProgramAnalysisBackend({
      artifacts: new MemoryArtifacts(),
      session: new FakeSandboxSession("joern-test", () => ({
        exitCode: 0,
        stdout: "",
        stderr: "",
      })),
    });

    await expect(
      missing.buildModel({ sourceDir: SOURCE_DIR, manifest: manifest(["src/app.ts"]) }),
    ).rejects.toMatchObject({
      code: "joern_output_missing",
    });

    const invalidJson = new JoernProgramAnalysisBackend({
      artifacts: new MemoryArtifacts(),
      session: new FakeSandboxSession("joern-test", (command, currentSession) => {
        const slicePath = valueAfter(command, "-o");
        if (slicePath !== undefined) {
          currentSession.files.set(slicePath, bytes("not-json"));
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      }),
    });

    await expect(invalidJson.extractFlows(modelRef())).rejects.toMatchObject({
      code: "joern_invalid_json",
    });
  });

  it("reports Joern command timeouts with the timed-out area", async () => {
    const session = new FakeSandboxSession("joern-test", () => ({
      exitCode: 124,
      stdout: "",
      stderr: "",
    }));
    const backend = new JoernProgramAnalysisBackend({
      artifacts: new MemoryArtifacts(),
      session,
      commandTimeoutMs: 1000,
      flowCommandTimeoutMs: 1000,
    });

    await expect(backend.extractFlows(modelRef())).rejects.toMatchObject({
      code: "joern_timeout",
      message: "Joern flows command timed out after 1s.",
      details: expect.objectContaining({
        area: "flows",
        timeoutMs: 1000,
      }),
    });
    expect(session.invocations[0]?.timeoutMs).toBe(1000);
  });
});

describe("JoernProgramAnalysisBackend coverage", () => {
  it("reports model coverage and backend failures without inventing facts", () => {
    const backend = new JoernProgramAnalysisBackend({
      artifacts: new MemoryArtifacts(),
      session: new FakeSandboxSession("joern-test", () => ({
        exitCode: 0,
        stdout: "",
        stderr: "",
      })),
    });

    const coverage = backend.reportCoverage({
      manifest: manifest(["src/app.ts", "src/legacy.rb"]),
      model: modelRef(),
      failures: [{ area: "flows", reason: "Joern data-flow extraction failed." }],
    });

    expect(coverage).toEqual([
      {
        area: "language_support",
        state: "partial",
        producer: "joern",
        producerVersion: "joern@4.0.565",
        coveredCount: 1,
        totalCount: 2,
        reason: "Some source languages are not supported by Deep Static v1: ruby=1.",
      },
      {
        area: "model",
        state: "checked",
        producer: "joern",
        producerVersion: "joern@4.0.565",
      },
      {
        area: "flows",
        state: "failed",
        producer: "joern",
        producerVersion: "joern@4.0.565",
        reason: "Joern data-flow extraction failed.",
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

class CollectingEvents implements EventSink {
  readonly events: ScanEvent[] = [];

  emit(event: ScanEvent): void {
    this.events.push(event);
  }
}

async function buildModelFor(paths: string[]): Promise<ProgramAnalysisModelRef> {
  const artifacts = new MemoryArtifacts();
  const session = new FakeSandboxSession("joern-test", (_command, currentSession) => {
    currentSession.files.set(JOERN_MODEL_PATH, bytes("joern-cpg"));
    return { exitCode: 0, stdout: "", stderr: "" };
  });
  return await new JoernProgramAnalysisBackend({ session, artifacts }).buildModel({
    sourceDir: SOURCE_DIR,
    manifest: manifest(paths),
  });
}

function modelRef(): ProgramAnalysisModelRef {
  return {
    backend: "joern",
    backendVersion: "joern@4.0.565",
    language: "typescript",
    sourceDir: SOURCE_DIR,
    modelPath: JOERN_MODEL_PATH,
    artifact: { blobSha256: "model-sha", role: "program-analysis.raw", bytes: 10 },
    command: ["joern-parse", "--language", "javascript", "-o", JOERN_MODEL_PATH, SOURCE_DIR],
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
