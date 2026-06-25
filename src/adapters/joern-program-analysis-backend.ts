import type { ArtifactRef } from "../domain/run.js";
import type { ArtifactStore } from "../ports/artifact-store.js";
import type { EventSink } from "../ports/event-sink.js";
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
import type { SandboxExecEvent, SandboxSession } from "../ports/sandbox-runtime.js";
import {
  JOERN_BOUNDARIES_SLICE_PATH,
  JOERN_CALL_EDGES_SLICE_PATH,
  JOERN_COMPONENT_USAGE_SLICE_PATH,
  JOERN_ENTITIES_SLICE_PATH,
  JOERN_FLOWS_SLICE_PATH,
  JOERN_MODEL_PATH,
} from "../stages/paths.js";

const DEFAULT_JOERN_PARSE_BIN = "joern-parse";
const DEFAULT_JOERN_EXTRACT_BIN = "vibeshield-joern-extract";
const DEFAULT_JOERN_VERSION = "4.0.565";
const DEFAULT_JOERN_COMMAND_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_JOERN_FLOW_COMMAND_TIMEOUT_MS = 60 * 1000;
const MAX_ERROR_OUTPUT = 4000;
const MAX_PUBLIC_ERROR_OUTPUT = 500;
const MAX_SLICE_SHARDS = 999;
const encoder = new TextEncoder();

export interface JoernProgramAnalysisBackendOptions {
  readonly session: SandboxSession;
  readonly artifacts: ArtifactStore;
  readonly events?: EventSink;
  readonly joernParseBin?: string;
  readonly joernExtractBin?: string;
  readonly joernVersion?: string;
  readonly commandTimeoutMs?: number;
  readonly flowCommandTimeoutMs?: number;
}

export class JoernProgramAnalysisBackend implements ProgramAnalysisBackend {
  private readonly session: SandboxSession;
  private readonly artifacts: ArtifactStore;
  private readonly events: EventSink | undefined;
  private readonly joernParseBin: string;
  private readonly joernExtractBin: string;
  private readonly joernVersion: string;
  private readonly commandTimeoutMs: number;
  private readonly flowCommandTimeoutMs: number;

  constructor(options: JoernProgramAnalysisBackendOptions) {
    this.session = options.session;
    this.artifacts = options.artifacts;
    this.events = options.events;
    this.joernParseBin = options.joernParseBin ?? DEFAULT_JOERN_PARSE_BIN;
    this.joernExtractBin = options.joernExtractBin ?? DEFAULT_JOERN_EXTRACT_BIN;
    this.joernVersion = options.joernVersion ?? DEFAULT_JOERN_VERSION;
    this.commandTimeoutMs = options.commandTimeoutMs ?? DEFAULT_JOERN_COMMAND_TIMEOUT_MS;
    this.flowCommandTimeoutMs =
      options.flowCommandTimeoutMs ?? DEFAULT_JOERN_FLOW_COMMAND_TIMEOUT_MS;
  }

  async buildModel(input: ProgramAnalysisBuildInput): Promise<ProgramAnalysisModelRef> {
    const language = this.selectLanguage(input);
    const modelPath = input.outputPath ?? JOERN_MODEL_PATH;
    const command = [
      this.joernParseBin,
      "--language",
      joernParseLanguage(language),
      "-o",
      modelPath,
      input.sourceDir,
    ];

    await this.execJoern(command, "model");
    const modelBytes = await this.readRequired(modelPath, "model");
    const stored = await this.artifacts.store(modelBytes);

    return {
      backend: "joern",
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
    return await this.extractSlice(model, "entities", JOERN_ENTITIES_SLICE_PATH);
  }

  async extractBoundaries(
    model: ProgramAnalysisModelRef,
  ): Promise<ProgramAnalysisExtractionArtifact> {
    return await this.extractSlice(model, "boundaries", JOERN_BOUNDARIES_SLICE_PATH);
  }

  async extractCallEdges(
    model: ProgramAnalysisModelRef,
  ): Promise<ProgramAnalysisExtractionArtifact> {
    return await this.extractSlice(model, "call_edges", JOERN_CALL_EDGES_SLICE_PATH);
  }

  async extractFlows(model: ProgramAnalysisModelRef): Promise<ProgramAnalysisExtractionArtifact> {
    return await this.extractSlice(model, "flows", JOERN_FLOWS_SLICE_PATH);
  }

  async extractComponentUsage(
    model: ProgramAnalysisModelRef,
  ): Promise<ProgramAnalysisExtractionArtifact> {
    return await this.extractSlice(model, "component_usage", JOERN_COMPONENT_USAGE_SLICE_PATH);
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
        this.joernVersion,
        languageCoverageOptions,
      ),
    ];

    if (input.model !== undefined) {
      coverage.push(coverageRecord("model", "checked", this.joernVersion));
    } else if (languageSupport.selectedLanguage !== undefined) {
      coverage.push(
        coverageRecord("model", "skipped", this.joernVersion, {
          reason: "Joern CPG has not been built yet.",
        }),
      );
    }

    for (const failure of input.failures ?? []) {
      coverage.push(
        coverageRecord(failure.area, "failed", this.joernVersion, {
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
        support.reason ??
          "No supported JS/TS/Java/Python/Go source files found for Joern analysis.",
        { sourceDir: input.sourceDir },
      );
    }
    return support.selectedLanguage;
  }

  private versionLabel(): string {
    return `joern@${this.joernVersion}`;
  }

  private async extractSlice(
    model: ProgramAnalysisModelRef,
    kind: ProgramAnalysisExtractionKind,
    slicePath: string,
  ): Promise<ProgramAnalysisExtractionArtifact> {
    const command = [
      this.joernExtractBin,
      "--kind",
      kind,
      "--cpg",
      model.modelPath,
      "--source-root",
      model.sourceDir,
      "-o",
      slicePath,
    ];

    await this.execJoern(command, kind);
    const sliceBytes = await this.readRequiredSlice(slicePath, kind);
    const parsed = parseSliceJson(sliceBytes, kind);
    const stored = await this.artifacts.store(sliceBytes);

    return {
      backend: "joern",
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

  private async execJoern(
    command: ReadonlyArray<string>,
    area: ProgramAnalysisCoverageArea,
  ): Promise<void> {
    this.emitProgress(area);
    const timeoutMs = area === "flows" ? this.flowCommandTimeoutMs : this.commandTimeoutMs;
    try {
      const result = await this.session.exec([...command], {
        timeoutMs,
        onEvent: (event) => {
          this.emitSandboxEvent(area, event);
        },
      });
      if (result.exitCode === 124 || result.exitCode === 137) {
        throw new ProgramAnalysisBackendError(
          "joern_timeout",
          `Joern ${area} command timed out after ${formatDuration(timeoutMs)}.`,
          {
            area,
            command,
            timeoutMs,
            stdout: truncate(result.stdout),
            stderr: truncate(result.stderr),
          },
        );
      }
      if (result.exitCode !== 0) {
        const output = publicOutputSummary(result);
        throw new ProgramAnalysisBackendError(
          "joern_exit_nonzero",
          `Joern ${area} command failed with exit code ${result.exitCode}.${output}`,
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
        "joern_unavailable",
        `Joern ${area} command failed: ${message}`,
        {
          area,
          command,
        },
      );
    }
  }

  private emitProgress(area: ProgramAnalysisCoverageArea): void {
    const label = joernProgressLabel(area);
    this.events?.emit({
      type: "scan-progress",
      stageId: "deep.static.compose",
      message: label,
      details: {
        publicLabel: label,
        source: "sandbox",
        producer: "joern",
        area,
      },
      timestamp: new Date().toISOString(),
    });
  }

  private emitSandboxEvent(area: ProgramAnalysisCoverageArea, event: SandboxExecEvent): void {
    const label = joernProgressLabel(area);
    this.events?.emit({
      type: "scan-progress",
      stageId: "deep.static.compose",
      message: label,
      details: {
        publicLabel: label,
        source: "sandbox",
        producer: "joern",
        area,
        event: event.type,
        ...(event.type === "stdout" || event.type === "stderr"
          ? { stream: event.type, bytes: event.data.length }
          : {}),
      },
      timestamp: new Date().toISOString(),
    });
  }

  private async readRequired(path: string, area: ProgramAnalysisCoverageArea): Promise<Uint8Array> {
    const bytes = await this.readOptional(path);
    if (bytes.byteLength === 0) {
      throw new ProgramAnalysisBackendError(
        "joern_output_missing",
        `Joern ${area} output is missing: ${path}`,
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
        "joern_output_missing",
        `Joern ${kind} output is missing: ${path}`,
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
      "joern_invalid_json",
      `Joern ${kind} slice JSON is invalid: ${message}`,
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
  joernVersion: string,
  options: {
    readonly coveredCount?: number;
    readonly totalCount?: number;
    readonly reason?: string;
  } = {},
): ProgramAnalysisCoverage {
  return {
    area,
    state,
    producer: "joern",
    producerVersion: `joern@${joernVersion}`,
    ...(options.coveredCount === undefined ? {} : { coveredCount: options.coveredCount }),
    ...(options.totalCount === undefined ? {} : { totalCount: options.totalCount }),
    ...(options.reason === undefined ? {} : { reason: options.reason }),
  };
}

function joernProgressLabel(area: ProgramAnalysisCoverageArea): string {
  switch (area) {
    case "model":
      return "Building the code map";
    case "entities":
      return "Reading project structure";
    case "boundaries":
      return "Finding entry points";
    case "call_edges":
      return "Tracing code paths";
    case "flows":
      return "Tracing data flow";
    case "component_usage":
      return "Checking dependency usage";
    case "ci_iac":
      return "Checking CI and IaC context";
    case "content_assets":
      return "Checking content and static assets";
    case "smart_contracts":
      return "Checking smart contracts";
    case "language_support":
      return "Checking language support";
  }
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

function formatDuration(ms: number): string {
  const seconds = Math.ceil(ms / 1000);
  return seconds % 60 === 0 ? `${seconds / 60}m` : `${seconds}s`;
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
    "joern_invalid_json",
    `Joern ${kind} sharded slice JSON cannot be merged: expected arrays or objectSlices objects.`,
    {
      kind,
      chunks: chunks.length,
    },
  );
}

function joernParseLanguage(language: ProgramAnalysisLanguage): string {
  switch (language) {
    case "typescript":
    case "javascript":
      return "javascript";
    case "java":
      return "javasrc";
    case "python":
      return "python";
    case "go":
      return "golang";
  }
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
