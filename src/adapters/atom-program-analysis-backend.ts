import type { ArtifactRef } from "../domain/run.js";
import type { ArtifactStore } from "../ports/artifact-store.js";
import {
  languageSupportFromManifest,
  type ProgramAnalysisBackend,
  ProgramAnalysisBackendError,
  type ProgramAnalysisBuildInput,
  type ProgramAnalysisCoverage,
  type ProgramAnalysisCoverageArea,
  type ProgramAnalysisCoverageInput,
  type ProgramAnalysisExtractionArtifact,
  type ProgramAnalysisExtractionKind,
  type ProgramAnalysisLanguage,
  type ProgramAnalysisModelRef,
} from "../ports/program-analysis-backend.js";
import type { SandboxSession } from "../ports/sandbox-runtime.js";
import {
  ATOM_BOUNDARIES_SLICE_PATH,
  ATOM_CALL_EDGES_SLICE_PATH,
  ATOM_COMPONENT_USAGE_SLICE_PATH,
  ATOM_ENTITIES_SLICE_PATH,
  ATOM_FLOWS_SLICE_PATH,
  ATOM_MODEL_PATH,
} from "../stages/paths.js";

const DEFAULT_ATOM_BIN = "atom";
const DEFAULT_ATOM_VERSION = "2.5.6";
const MAX_ERROR_OUTPUT = 4000;
const MAX_PUBLIC_ERROR_OUTPUT = 500;
const MAX_SLICE_SHARDS = 999;
const encoder = new TextEncoder();

export interface AtomProgramAnalysisBackendOptions {
  readonly session: SandboxSession;
  readonly artifacts: ArtifactStore;
  readonly atomBin?: string;
  readonly atomVersion?: string;
}

export class AtomProgramAnalysisBackend implements ProgramAnalysisBackend {
  private readonly session: SandboxSession;
  private readonly artifacts: ArtifactStore;
  private readonly atomBin: string;
  private readonly atomVersion: string;

  constructor(options: AtomProgramAnalysisBackendOptions) {
    this.session = options.session;
    this.artifacts = options.artifacts;
    this.atomBin = options.atomBin ?? DEFAULT_ATOM_BIN;
    this.atomVersion = options.atomVersion ?? DEFAULT_ATOM_VERSION;
  }

  async buildModel(input: ProgramAnalysisBuildInput): Promise<ProgramAnalysisModelRef> {
    const language = this.selectLanguage(input);
    const modelPath = input.outputPath ?? ATOM_MODEL_PATH;
    const command = [this.atomBin, "-o", modelPath, "-l", language, input.sourceDir];

    await this.execAtom(command, "model");
    const modelBytes = await this.readRequired(modelPath, "model");
    const stored = await this.artifacts.store(modelBytes);

    return {
      backend: "atom",
      backendVersion: this.versionLabel(),
      language,
      sourceDir: input.sourceDir,
      modelPath,
      artifact: artifactRef(stored.sha256, "program-analysis.raw", stored.bytes),
      command,
    };
  }

  async extractEntities(
    model: ProgramAnalysisModelRef,
  ): Promise<ProgramAnalysisExtractionArtifact> {
    return await this.extractSlice(model, "entities", "usages", ATOM_ENTITIES_SLICE_PATH);
  }

  async extractBoundaries(
    model: ProgramAnalysisModelRef,
  ): Promise<ProgramAnalysisExtractionArtifact> {
    return await this.extractSlice(model, "boundaries", "usages", ATOM_BOUNDARIES_SLICE_PATH);
  }

  async extractCallEdges(
    model: ProgramAnalysisModelRef,
  ): Promise<ProgramAnalysisExtractionArtifact> {
    return await this.extractSlice(model, "call_edges", "reachables", ATOM_CALL_EDGES_SLICE_PATH);
  }

  async extractFlows(model: ProgramAnalysisModelRef): Promise<ProgramAnalysisExtractionArtifact> {
    return await this.extractSlice(model, "flows", "data-flow", ATOM_FLOWS_SLICE_PATH);
  }

  async extractComponentUsage(
    model: ProgramAnalysisModelRef,
  ): Promise<ProgramAnalysisExtractionArtifact> {
    return await this.extractSlice(
      model,
      "component_usage",
      "reachables",
      ATOM_COMPONENT_USAGE_SLICE_PATH,
    );
  }

  reportCoverage(input: ProgramAnalysisCoverageInput): ReadonlyArray<ProgramAnalysisCoverage> {
    const languageSupport = languageSupportFromManifest(input.manifest);
    const languageCoverageOptions = {
      coveredCount: countCovered(languageSupport.supported),
      totalCount: languageSupport.totalSourceFiles,
      ...(languageSupport.reason === undefined ? {} : { reason: languageSupport.reason }),
    };
    const coverage: ProgramAnalysisCoverage[] = [
      coverageRecord(
        "language_support",
        languageSupport.coverageState,
        this.atomVersion,
        languageCoverageOptions,
      ),
    ];

    if (input.model !== undefined) {
      coverage.push(coverageRecord("model", "checked", this.atomVersion));
    } else if (languageSupport.selectedLanguage !== undefined) {
      coverage.push(
        coverageRecord("model", "skipped", this.atomVersion, {
          reason: "Atom model has not been built yet.",
        }),
      );
    }

    for (const failure of input.failures ?? []) {
      coverage.push(
        coverageRecord(failure.area, "failed", this.atomVersion, {
          reason: failure.reason,
        }),
      );
    }

    return coverage;
  }

  private selectLanguage(input: ProgramAnalysisBuildInput): ProgramAnalysisLanguage {
    if (input.language !== undefined) {
      return input.language;
    }
    const support = languageSupportFromManifest(input.manifest);
    if (support.selectedLanguage === undefined) {
      throw new ProgramAnalysisBackendError(
        "unsupported_language",
        support.reason ?? "No supported JS/TS/Python source files found for Atom analysis.",
        { sourceDir: input.sourceDir },
      );
    }
    return support.selectedLanguage;
  }

  private versionLabel(): string {
    return `atom@${this.atomVersion}`;
  }

  private async extractSlice(
    model: ProgramAnalysisModelRef,
    kind: ProgramAnalysisExtractionKind,
    subcommand: "usages" | "reachables" | "data-flow",
    slicePath: string,
  ): Promise<ProgramAnalysisExtractionArtifact> {
    const command = [
      this.atomBin,
      subcommand,
      "-o",
      model.modelPath,
      "-s",
      slicePath,
      "-l",
      model.language,
      model.sourceDir,
    ];

    await this.execAtom(command, kind);
    const sliceBytes = await this.readRequiredSlice(slicePath, kind);
    const parsed = parseSliceJson(sliceBytes, kind);
    const stored = await this.artifacts.store(sliceBytes);

    return {
      backend: "atom",
      backendVersion: this.versionLabel(),
      kind,
      language: model.language,
      modelArtifact: model.artifact,
      sliceArtifact: artifactRef(stored.sha256, "program-analysis.slice", stored.bytes),
      slicePath,
      command,
      parsed,
    };
  }

  private async execAtom(
    command: ReadonlyArray<string>,
    area: ProgramAnalysisCoverageArea,
  ): Promise<void> {
    try {
      const result = await this.session.exec([...command]);
      if (result.exitCode !== 0) {
        const output = publicOutputSummary(result);
        throw new ProgramAnalysisBackendError(
          "atom_exit_nonzero",
          `Atom ${area} command failed with exit code ${result.exitCode}.${output}`,
          {
            area,
            command,
            stdout: truncate(result.stdout),
            stderr: truncate(result.stderr),
          },
        );
      }
    } catch (error) {
      if (error instanceof ProgramAnalysisBackendError) {
        throw error;
      }
      const message = error instanceof Error ? error.message : String(error);
      throw new ProgramAnalysisBackendError(
        "atom_unavailable",
        `Atom ${area} command failed: ${message}`,
        {
          area,
          command,
        },
      );
    }
  }

  private async readRequired(path: string, area: ProgramAnalysisCoverageArea): Promise<Uint8Array> {
    const bytes = await this.readOptional(path);
    if (bytes.byteLength === 0) {
      throw new ProgramAnalysisBackendError(
        "atom_output_missing",
        `Atom ${area} output is missing: ${path}`,
        {
          area,
          path,
        },
      );
    }
    return bytes;
  }

  private async readRequiredSlice(
    path: string,
    kind: ProgramAnalysisExtractionKind,
  ): Promise<Uint8Array> {
    const chunks = await this.readSliceChunks(path);
    if (chunks.length === 0) {
      throw new ProgramAnalysisBackendError(
        "atom_output_missing",
        `Atom ${kind} output is missing: ${path}`,
        {
          kind,
          path,
        },
      );
    }
    const firstChunk = chunks[0];
    if (chunks.length === 1 && firstChunk !== undefined) {
      return firstChunk;
    }
    return mergeSliceChunks(chunks, kind);
  }

  private async readSliceChunks(path: string): Promise<Uint8Array[]> {
    const chunks: Uint8Array[] = [];
    const primary = await this.readOptional(path);
    if (primary.byteLength > 0) {
      chunks.push(primary);
    }
    for (let index = 1; index <= MAX_SLICE_SHARDS; index += 1) {
      const shard = await this.readOptional(sliceShardPath(path, index));
      if (shard.byteLength === 0) {
        break;
      }
      chunks.push(shard);
    }
    return chunks;
  }

  private async readOptional(path: string): Promise<Uint8Array> {
    try {
      return await this.session.read(path);
    } catch (error) {
      if (isMissingPathError(error)) {
        return new Uint8Array();
      }
      throw error;
    }
  }
}

function parseSliceJson(bytes: Uint8Array, kind: ProgramAnalysisExtractionKind): unknown {
  const text = new TextDecoder().decode(bytes);
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed === null || (typeof parsed !== "object" && !Array.isArray(parsed))) {
      throw new Error("root must be a JSON object or array");
    }
    return parsed;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new ProgramAnalysisBackendError(
      "atom_invalid_json",
      `Atom ${kind} slice JSON is invalid: ${message}`,
      {
        kind,
      },
    );
  }
}

function artifactRef(blobSha256: string, role: ArtifactRef["role"], bytes: number): ArtifactRef {
  return { blobSha256, role, bytes };
}

function coverageRecord(
  area: ProgramAnalysisCoverageArea,
  state: ProgramAnalysisCoverage["state"],
  atomVersion: string,
  options: {
    readonly coveredCount?: number;
    readonly totalCount?: number;
    readonly reason?: string;
  } = {},
): ProgramAnalysisCoverage {
  return {
    area,
    state,
    producer: "atom",
    producerVersion: `atom@${atomVersion}`,
    ...(options.coveredCount === undefined ? {} : { coveredCount: options.coveredCount }),
    ...(options.totalCount === undefined ? {} : { totalCount: options.totalCount }),
    ...(options.reason === undefined ? {} : { reason: options.reason }),
  };
}

function countCovered(counts: ReadonlyArray<{ readonly fileCount: number }>): number {
  return counts.reduce((total, item) => total + item.fileCount, 0);
}

function truncate(value: string): string {
  return value.length > MAX_ERROR_OUTPUT ? `${value.slice(0, MAX_ERROR_OUTPUT)}...` : value;
}

function publicOutputSummary(result: { readonly stdout: string; readonly stderr: string }): string {
  const stderr = compact(result.stderr);
  if (stderr.length > 0) {
    return ` stderr: ${truncatePublic(stderr)}`;
  }
  const stdout = compact(result.stdout);
  if (stdout.length > 0) {
    return ` stdout: ${truncatePublic(stdout)}`;
  }
  return "";
}

function compact(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function truncatePublic(value: string): string {
  return value.length > MAX_PUBLIC_ERROR_OUTPUT
    ? `${value.slice(0, MAX_PUBLIC_ERROR_OUTPUT)}...`
    : value;
}

function sliceShardPath(path: string, index: number): string {
  return path.endsWith(".json")
    ? `${path.slice(0, -".json".length)}_${index}.json`
    : `${path}_${index}`;
}

function mergeSliceChunks(
  chunks: ReadonlyArray<Uint8Array>,
  kind: ProgramAnalysisExtractionKind,
): Uint8Array {
  const parsed = chunks.map((chunk) => parseSliceJson(chunk, kind));
  if (parsed.every(Array.isArray)) {
    return encoder.encode(JSON.stringify(parsed.flat()));
  }
  if (parsed.every(hasObjectSlices)) {
    const objectChunks = parsed as Array<{ readonly objectSlices: unknown[] }>;
    const first = objectChunks[0];
    if (first === undefined) {
      return encoder.encode(JSON.stringify({ objectSlices: [] }));
    }
    const rest = objectChunks.slice(1);
    return encoder.encode(
      JSON.stringify({
        ...first,
        objectSlices: [...first.objectSlices, ...rest.flatMap((chunk) => chunk.objectSlices)],
      }),
    );
  }
  throw new ProgramAnalysisBackendError(
    "atom_invalid_json",
    `Atom ${kind} sharded slice JSON cannot be merged: expected arrays or objectSlices objects.`,
    {
      kind,
      chunks: chunks.length,
    },
  );
}

function hasObjectSlices(value: unknown): value is { readonly objectSlices: unknown[] } {
  return (
    typeof value === "object" &&
    value !== null &&
    Array.isArray((value as { readonly objectSlices?: unknown }).objectSlices)
  );
}

function isMissingPathError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /(?:enoent|not found|no such file)/iu.test(message);
}
