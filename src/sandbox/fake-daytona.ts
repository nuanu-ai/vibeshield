import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { copyFile, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import type {
  BaselineObservation,
  BaselineToolName,
  DataFlowsArtifact,
  EntryPointsArtifact,
  PiContextPackArtifact,
  PiSemanticEvaluationArtifact,
  ProjectUnderstandingArtifact,
  SensitiveSinksArtifact,
  ToolAvailabilityArtifact,
} from "../artifacts/contracts.js";
import { buildRepoInventory } from "../inventory/repo-inventory.js";
import { ScanStageError } from "../run/errors.js";
import { redactDeep } from "../run/redaction.js";
import type { SandboxCleanupState } from "../run/types.js";
import type {
  CloneRepositoryResult,
  GenerateInventoryInput,
  PrepareBaselineToolsInput,
  PrepareBaselineToolsResult,
  PullFileContext,
  RuntimeJobInput,
  RuntimeJobResult,
  SandboxArtifact,
  SandboxCommandLogEntry,
  SandboxCreateContext,
  SandboxProvider,
  SandboxSession,
} from "./types.js";

const execFileAsync = promisify(execFile);

export interface FakeDaytonaSandboxProviderOptions {
  failAt?: "baseline" | "clone" | "inventory" | "pi";
  fixtureRepos: Map<string, string>;
  piOutputs?: Partial<Record<string, FakePiOutput>>;
  projectUnderstandingOutput?: ProjectUnderstandingArtifact | ((input: RuntimeJobInput) => unknown);
  sandboxRoot: string;
  unavailableTools?: BaselineToolName[];
}

type FakePiOutput = unknown | ((input: RuntimeJobInput) => unknown);

export class FakeDaytonaSandboxProvider implements SandboxProvider {
  readonly createdSandboxIds: string[] = [];
  readonly liveSandboxIds: string[] = [];
  readonly sessions: FakeDaytonaSandboxSession[] = [];

  private sequence = 0;

  constructor(private readonly options: FakeDaytonaSandboxProviderOptions) {}

  async createSandbox(context: SandboxCreateContext): Promise<SandboxSession> {
    this.sequence += 1;
    const id = `fake-daytona-${this.sequence}-${randomUUID().slice(0, 8)}`;
    const sandboxDir = path.join(this.options.sandboxRoot, id);
    await mkdir(sandboxDir, { recursive: true });

    const sessionOptions: FakeDaytonaSandboxSessionOptions = {
      fixtureRepos: this.options.fixtureRepos,
      id,
      piOutputs: this.options.piOutputs ?? {},
      repoUrl: context.repo.url,
      sandboxDir,
      unavailableTools: this.options.unavailableTools ?? [],
      ...(this.options.projectUnderstandingOutput === undefined
        ? {}
        : { projectUnderstandingOutput: this.options.projectUnderstandingOutput }),
      removeLiveSandboxId: () => {
        const index = this.liveSandboxIds.indexOf(id);
        if (index >= 0) {
          this.liveSandboxIds.splice(index, 1);
        }
      },
    };
    if (this.options.failAt !== undefined) {
      sessionOptions.failAt = this.options.failAt;
    }

    const session = new FakeDaytonaSandboxSession(sessionOptions);

    this.createdSandboxIds.push(id);
    this.liveSandboxIds.push(id);
    this.sessions.push(session);

    return session;
  }
}

export class FakeDaytonaSandboxSession implements SandboxSession {
  readonly artifactsDir: string;
  readonly commands: SandboxCommandLogEntry[] = [];
  readonly providerName = "fake-daytona";
  readonly repoPath: string;

  constructor(private readonly options: FakeDaytonaSandboxSessionOptions) {
    this.artifactsDir = path.join(options.sandboxDir, "artifacts");
    this.repoPath = path.join(options.sandboxDir, "repo");
  }

  get id(): string {
    return this.options.id;
  }

  async cloneRepository(): Promise<CloneRepositoryResult> {
    this.commands.push({
      command: "git clone --no-local <fixture-repo> <sandbox-repo>",
      cwd: this.options.sandboxDir,
      repoDefinedCommand: false,
      stage: "clone",
    });

    if (this.options.failAt === "clone") {
      throw new ScanStageError({
        message: "Fake Daytona clone failure.",
        stage: "clone",
        userMessage: "VibeShield could not clone the repository inside the sandbox.",
      });
    }

    const fixtureRepo = this.options.fixtureRepos.get(this.options.repoUrl);
    if (fixtureRepo === undefined) {
      throw new ScanStageError({
        message: `No fake fixture repo is mapped for ${this.options.repoUrl}.`,
        stage: "clone",
        userMessage: "No fake fixture repository is configured for this GitHub URL.",
      });
    }

    await execFileAsync("git", ["clone", "--no-local", "--quiet", fixtureRepo, this.repoPath], {
      cwd: this.options.sandboxDir,
    });

    this.commands.push({
      command: "git -C <sandbox-repo> rev-parse HEAD",
      cwd: this.options.sandboxDir,
      repoDefinedCommand: false,
      stage: "commit",
    });
    const { stdout } = await execFileAsync("git", ["-C", this.repoPath, "rev-parse", "HEAD"], {
      cwd: this.options.sandboxDir,
    });

    return {
      commitSha: stdout.trim(),
      repoPath: this.repoPath,
    };
  }

  async generateInventory(input: GenerateInventoryInput): Promise<SandboxArtifact> {
    this.commands.push({
      command: "vibeshield-inventory --read-only <sandbox-repo>",
      cwd: this.options.sandboxDir,
      repoDefinedCommand: false,
      stage: "inventory",
    });

    if (this.options.failAt === "inventory") {
      throw new ScanStageError({
        message: "Fake Daytona inventory failure.",
        stage: "inventory",
        userMessage: "VibeShield could not complete the read-only inventory step.",
      });
    }

    await mkdir(this.artifactsDir, { recursive: true });
    const inventory = await buildRepoInventory({
      commitSha: input.commitSha,
      generatedAt: input.generatedAt,
      repoRoot: this.repoPath,
      sandboxId: this.id,
      source: input.repo,
    });
    const artifactPath = path.join(this.artifactsDir, "repo-inventory.json");
    await writeFile(artifactPath, `${JSON.stringify(inventory, null, 2)}\n`, "utf8");

    return {
      relativePath: "inventory.v1.json",
      sandboxPath: artifactPath,
    };
  }

  async runJob(input: RuntimeJobInput): Promise<RuntimeJobResult> {
    this.commands.push({
      command: `vibeshield-runtime-job ${input.kind} ${input.name}`,
      cwd: this.options.sandboxDir,
      repoDefinedCommand: false,
      stage: input.stage,
    });

    if (input.kind === "baseline-tool") {
      if (this.options.failAt === "baseline") {
        throw new ScanStageError({
          message: "Fake Daytona baseline failure.",
          stage: "deterministic-baseline",
          userMessage: "VibeShield could not complete the deterministic baseline step.",
        });
      }
      return this.runFakeBaselineTool(input);
    }

    if (this.options.failAt === "pi") {
      throw new ScanStageError({
        message: "Fake Daytona Pi failure.",
        stage: "pi",
        userMessage: "VibeShield could not complete the Pi project-understanding step.",
      });
    }
    return this.runFakePi(input);
  }

  async prepareBaselineTools(
    input: PrepareBaselineToolsInput,
  ): Promise<PrepareBaselineToolsResult> {
    const toolDir = path.join(this.artifactsDir, "baseline");
    await mkdir(toolDir, { recursive: true });
    const unavailable = new Set(this.options.unavailableTools ?? []);
    const availability: ToolAvailabilityArtifact = {
      artifact_version: 1,
      generated_at: input.generatedAt,
      kind: "tool-availability.v1",
      tool_bin_dir: path.join(this.options.sandboxDir, "tools", "bin"),
      tools: input.tools.map((tool) => {
        if (!tool.required) {
          return {
            attempts: [],
            diagnostics: [],
            required: false,
            ...(tool.skippedReason === undefined ? {} : { skipped_reason: tool.skippedReason }),
            status: "not_required",
            tool: tool.tool,
          };
        }

        if (unavailable.has(tool.tool)) {
          return {
            attempts: [
              {
                command: `provision ${tool.tool}`,
                exit_code: 127,
                stderr: `${tool.tool} is unavailable in fake runtime`,
              },
            ],
            diagnostics: [`Required baseline tool is unavailable: ${tool.tool}`],
            required: true,
            status: "failed",
            tool: tool.tool,
          };
        }

        return {
          attempts: [],
          diagnostics: [],
          path: path.join(this.options.sandboxDir, "tools", "bin", tool.tool),
          required: true,
          status: "available",
          tool: tool.tool,
          version: `fake-${tool.tool}-1.0.0`,
        };
      }),
    };
    const artifactPath = path.join(toolDir, "tool-availability.v1.json");
    await writeFile(artifactPath, `${JSON.stringify(availability, null, 2)}\n`, "utf8");

    return {
      artifact: {
        relativePath: "baseline/tool-availability.v1.json",
        sandboxPath: artifactPath,
      },
      availability,
    };
  }

  private async runFakeBaselineTool(input: RuntimeJobInput): Promise<RuntimeJobResult> {
    const baseline = input.baseline;
    if (baseline === undefined) {
      throw new Error("Missing baseline job input.");
    }

    const startedAt = new Date().toISOString();
    const tool = baseline.tool;
    const files = await listRepoFiles(this.repoPath);
    const toolDir = path.join(this.artifactsDir, "baseline", tool);
    await mkdir(toolDir, { recursive: true });

    const skippedReason = skippedReasonForTool(tool, baseline);
    const status = skippedReason === undefined ? "completed" : "skipped";
    const observations = status === "completed" ? fakeObservationsForTool(tool, files) : [];
    const normalized = {
      diagnostics: status === "skipped" ? [`Skipped ${tool}: ${skippedReason}`] : [],
      observations,
      status,
      tool,
      version: `fake-${tool}-1.0.0`,
    };

    const resultPath = path.join(toolDir, "result.redacted.json");
    await writeFile(resultPath, `${JSON.stringify(normalized, null, 2)}\n`, "utf8");
    const logPath = path.join(toolDir, "stderr.redacted.log");
    await writeFile(
      logPath,
      status === "skipped" ? `Skipped ${tool}: ${skippedReason}\n` : `${tool} completed\n`,
      "utf8",
    );

    const artifacts: SandboxArtifact[] = [
      {
        relativePath: `baseline/${tool}/result.redacted.json`,
        sandboxPath: resultPath,
      },
      {
        relativePath: `baseline/${tool}/stderr.redacted.log`,
        sandboxPath: logPath,
      },
    ];

    if (tool === "syft") {
      const sbomPath = path.join(this.artifactsDir, "baseline", "syft-sbom.json");
      await writeFile(
        sbomPath,
        `${JSON.stringify({ artifact_version: 1, files, generated_by: "fake-syft" }, null, 2)}\n`,
        "utf8",
      );
      artifacts.unshift({
        relativePath: "baseline/syft-sbom.json",
        sandboxPath: sbomPath,
      });
    }

    const diagnostics = status === "skipped" && skippedReason !== undefined ? [skippedReason] : [];
    return {
      artifacts,
      diagnostics,
      finishedAt: new Date().toISOString(),
      invocation: {
        args: fakeToolArgs(tool),
        command: tool,
        cwd: this.repoPath,
      },
      kind: "baseline-tool",
      observations,
      ...(skippedReason === undefined ? {} : { skippedReason }),
      startedAt,
      status,
      version: `fake-${tool}-1.0.0`,
    };
  }

  private async runFakePi(input: RuntimeJobInput): Promise<RuntimeJobResult> {
    if (input.pi === undefined) {
      throw new Error("Missing Pi job input.");
    }

    const startedAt = new Date().toISOString();
    const stepDir = path.join(this.artifactsDir, "pi", input.pi.artifactSubdir);
    await mkdir(stepDir, { recursive: true });

    await input.onProgress?.({
      job: input.name,
      message: `Running Pi ${input.pi.step}.`,
      type: "runner.started",
    });

    const selectedOutput = fakePiOutputForStep(input, this.options);
    const output = redactDeep(selectedOutput);

    const rawPath = path.join(stepDir, `${input.pi.outputBaseName}.raw.redacted.txt`);
    const stderrPath = path.join(stepDir, "stderr.redacted.log");
    const progressPath = path.join(stepDir, "progress.jsonl");
    const metadataPath = path.join(stepDir, "metadata.json");

    await writeFile(
      rawPath,
      isFakeRawPiOutput(output) ? `${output.rawText}\n` : `${JSON.stringify(output, null, 2)}\n`,
      "utf8",
    );
    await writeFile(stderrPath, "fake pi completed\n", "utf8");
    await writeFile(
      progressPath,
      `${JSON.stringify({
        message: `Fake Pi produced ${input.pi.step}.`,
        step: input.pi.step,
        timestamp: new Date().toISOString(),
        type: "pi.completed",
      })}\n`,
      "utf8",
    );
    await writeFile(
      metadataPath,
      `${JSON.stringify(
        {
          input_context_artifact: input.pi.inputContextArtifact,
          invocation: {
            args: ["-p", "--tools", input.pi.tools.join(",")],
            command: "pi",
            cwd: this.repoPath,
            metadata: { tools: input.pi.tools },
            provider: "openrouter",
          },
          model: input.pi.model,
          provider: input.pi.provider,
          stderr_bytes: "fake pi completed\n".length,
          stdout_bytes: isFakeRawPiOutput(output)
            ? output.rawText.length
            : JSON.stringify(output, null, 2).length + 1,
          step: input.pi.step,
          version: "fake-pi-0.0.0",
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    await input.onProgress?.({
      job: input.name,
      message: `Pi ${input.pi.step} completed.`,
      type: "pi.completed",
    });

    return {
      artifacts: [
        {
          relativePath: `pi/${input.pi.artifactSubdir}/${input.pi.outputBaseName}.raw.redacted.txt`,
          sandboxPath: rawPath,
        },
        {
          relativePath: `pi/${input.pi.artifactSubdir}/stderr.redacted.log`,
          sandboxPath: stderrPath,
        },
        {
          relativePath: `pi/${input.pi.artifactSubdir}/progress.jsonl`,
          sandboxPath: progressPath,
        },
        {
          relativePath: `pi/${input.pi.artifactSubdir}/metadata.json`,
          sandboxPath: metadataPath,
        },
      ],
      diagnostics: [],
      exitCode: 0,
      finishedAt: new Date().toISOString(),
      invocation: {
        args: ["-p", "--tools", input.pi.tools.join(",")],
        command: "pi",
        cwd: this.repoPath,
        metadata: { tools: input.pi.tools },
        provider: "openrouter",
      },
      kind: "pi-repository-mapping",
      metadata: {
        input_context_artifact: input.pi.inputContextArtifact,
        model: input.pi.model,
        provider: input.pi.provider,
        step: input.pi.step,
        version: "fake-pi-0.0.0",
      },
      observations: [],
      startedAt,
      status: "completed",
      version: "fake-pi-0.0.0",
    };
  }

  async pullFile(
    sandboxPath: string,
    localPath: string,
    _context?: PullFileContext,
  ): Promise<void> {
    const resolvedSandboxDir = path.resolve(this.options.sandboxDir);
    const resolvedSandboxPath = path.resolve(sandboxPath);
    if (
      resolvedSandboxPath !== resolvedSandboxDir &&
      !resolvedSandboxPath.startsWith(`${resolvedSandboxDir}${path.sep}`)
    ) {
      throw new ScanStageError({
        message: `Refusing to pull file outside sandbox: ${sandboxPath}`,
        stage: "inventory",
      });
    }

    await mkdir(path.dirname(localPath), { recursive: true });
    await copyFile(resolvedSandboxPath, localPath);
  }

  async delete(): Promise<SandboxCleanupState> {
    await rm(this.options.sandboxDir, { force: true, recursive: true });
    this.options.removeLiveSandboxId();
    return {
      attempted: true,
      deleted: true,
      success: true,
    };
  }
}

interface FakeDaytonaSandboxSessionOptions {
  failAt?: "baseline" | "clone" | "inventory" | "pi";
  fixtureRepos: Map<string, string>;
  id: string;
  piOutputs: Partial<Record<string, FakePiOutput>>;
  projectUnderstandingOutput?: ProjectUnderstandingArtifact | ((input: RuntimeJobInput) => unknown);
  removeLiveSandboxId: () => void;
  repoUrl: string;
  sandboxDir: string;
  unavailableTools: BaselineToolName[];
}

async function listRepoFiles(repoPath: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(relativeDirectory: string): Promise<void> {
    const absoluteDirectory = path.join(repoPath, relativeDirectory);
    const entries = await readdir(absoluteDirectory, { withFileTypes: true });

    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      const relativePath = toPosixPath(path.join(relativeDirectory, entry.name));
      if (relativePath === ".git" || relativePath.startsWith(".git/")) {
        continue;
      }
      if (entry.isDirectory()) {
        await walk(relativePath);
      } else if (entry.isFile()) {
        files.push(relativePath);
      }
    }
  }

  await walk("");
  return files;
}

function skippedReasonForTool(
  tool: BaselineToolName,
  baseline: NonNullable<RuntimeJobInput["baseline"]>,
): string | undefined {
  if ((tool === "actionlint" || tool === "zizmor") && !baseline.hasGithubActions) {
    return "No GitHub Actions workflows were detected in inventory.";
  }
  if (tool === "checkov" && !baseline.hasIacCandidates) {
    return "No IaC/config candidates were detected in inventory.";
  }
  return undefined;
}

function fakeToolArgs(tool: BaselineToolName): string[] {
  switch (tool) {
    case "syft":
      return ["dir:<repo>", "-o", "json"];
    case "gitleaks":
      return ["detect", "--source", "<repo>", "--redact"];
    case "trivy":
      return ["sbom", "--format", "json", "<syft-sbom>"];
    case "actionlint":
      return [".github/workflows"];
    case "zizmor":
      return ["--format", "json", ".github/workflows"];
    case "checkov":
      return ["-d", "<repo>", "-o", "json"];
  }
}

function fakeObservationsForTool(tool: BaselineToolName, files: string[]): BaselineObservation[] {
  const observations: BaselineObservation[] = [];
  const manifests = files.filter((file) =>
    ["package.json", "pnpm-lock.yaml", "package-lock.json", "requirements.txt"].includes(
      path.posix.basename(file),
    ),
  );

  if ((tool === "syft" || tool === "trivy") && manifests.length > 0) {
    observations.push({
      confidence: "medium",
      evidence: manifests.map((file) => `${file}:1`),
      kind: "dependency",
      message: `${tool} saw dependency manifests for follow-up vulnerability review.`,
      severity: "info",
    });
  }

  if (tool === "gitleaks" && files.some((file) => file.startsWith(".env"))) {
    observations.push({
      confidence: "medium",
      evidence: files.filter((file) => file.startsWith(".env")).map((file) => `${file}:1`),
      kind: "secret",
      message: "Environment files are present and should be reviewed for secret handling.",
      severity: "info",
    });
  }

  if ((tool === "actionlint" || tool === "zizmor") && files.some(isWorkflowPath)) {
    observations.push({
      confidence: "medium",
      evidence: files.filter(isWorkflowPath).map((file) => `${file}:1`),
      kind: "workflow",
      message: `${tool} inspected GitHub Actions workflow candidates.`,
      severity: "info",
    });
  }

  if (tool === "checkov" && files.some(isIacCandidatePath)) {
    observations.push({
      confidence: "medium",
      evidence: files.filter(isIacCandidatePath).map((file) => `${file}:1`),
      kind: "iac",
      message: "IaC/config candidates were routed through checkov.",
      severity: "info",
    });
  }

  return observations;
}

function fakePiOutputForStep(
  input: RuntimeJobInput,
  options: FakeDaytonaSandboxSessionOptions,
): unknown {
  if (input.pi === undefined) {
    throw new Error("Missing Pi job input.");
  }

  const configured = options.piOutputs[input.pi.step] ?? options.piOutputs[input.pi.outputBaseName];
  if (configured !== undefined) {
    return typeof configured === "function" ? configured(input) : configured;
  }

  if (
    input.pi.outputBaseName === "project-understanding" &&
    options.projectUnderstandingOutput !== undefined
  ) {
    return typeof options.projectUnderstandingOutput === "function"
      ? options.projectUnderstandingOutput(input)
      : options.projectUnderstandingOutput;
  }

  if (input.pi.outputBaseName.endsWith("-semantic-evaluation")) {
    return defaultFakeSemanticEvaluation(input);
  }

  switch (input.pi.outputBaseName) {
    case "entry-points":
      return defaultFakeEntryPoints(input);
    case "sensitive-sinks":
      return defaultFakeSensitiveSinks(input);
    case "data-flows":
      return defaultFakeDataFlows(input);
    case "project-understanding":
      return defaultFakeProjectUnderstanding(input);
    default:
      throw new Error(`No fake Pi output is configured for ${input.pi.outputBaseName}.`);
  }
}

function defaultFakeSemanticEvaluation(input: RuntimeJobInput): PiSemanticEvaluationArtifact {
  const context = input.pi?.contextPack as Partial<PiContextPackArtifact> | undefined;
  const stage = input.pi?.step.replace(/:semantic-evaluation$/, "") ?? "unknown";
  return {
    accepted: true,
    artifact_version: 1,
    attempt_count: 1,
    candidate_kind: stage as PiSemanticEvaluationArtifact["candidate_kind"],
    generated_at: new Date().toISOString(),
    generated_by: "pi",
    issues: [],
    kind: "pi-semantic-evaluation.v1",
    missing_coverage: [],
    overclaims: [],
    repo: {
      commit_sha: context?.repo?.commit_sha ?? null,
      url: context?.repo?.url ?? "https://github.com/vibeshield/fixture",
    },
    stage,
    summary: "Fake semantic evaluator accepted the candidate artifact.",
  };
}

function isFakeRawPiOutput(value: unknown): value is { rawText: string } {
  return (
    value !== null &&
    typeof value === "object" &&
    "rawText" in value &&
    typeof (value as { rawText?: unknown }).rawText === "string"
  );
}

function defaultFakeEntryPoints(input: RuntimeJobInput): EntryPointsArtifact {
  const now = new Date().toISOString();
  const context = input.pi?.contextPack as Partial<PiContextPackArtifact> | undefined;
  const inventory = context?.inventory;
  const manifestPath = inventory?.manifest_files?.[0] ?? "README.md";
  const entrypointPath = inventory?.candidate_entrypoints?.[0] ?? manifestPath;
  const repo = {
    commit_sha: context?.repo?.commit_sha ?? null,
    url: context?.repo?.url ?? "https://github.com/vibeshield/fixture",
  };

  return {
    artifact_version: 1,
    coverage: {
      not_covered: [
        { area: "Runtime-only entrypoints", reason: "Fake Pi does not execute the app." },
      ],
      reviewed: [{ area: "Candidate entrypoint files", evidence: [`${entrypointPath}:1`] }],
    },
    entry_points: [
      {
        confidence: "medium",
        evidence: [`${entrypointPath}:1`],
        id: "ep-1",
        kind: "http_route",
        location: entrypointPath,
        name: "Primary HTTP route candidate",
        route: "/api",
      },
    ],
    generated_at: now,
    generated_by: "pi",
    kind: "entry-points.v1",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo,
  };
}

function defaultFakeSensitiveSinks(input: RuntimeJobInput): SensitiveSinksArtifact {
  const now = new Date().toISOString();
  const context = input.pi?.contextPack as Partial<PiContextPackArtifact> | undefined;
  const inventory = context?.inventory;
  const manifestPath = inventory?.manifest_files?.[0] ?? "README.md";
  const sinkPath =
    inventory?.candidate_entrypoints?.[1] ?? inventory?.candidate_entrypoints?.[0] ?? manifestPath;
  const repo = {
    commit_sha: context?.repo?.commit_sha ?? null,
    url: context?.repo?.url ?? "https://github.com/vibeshield/fixture",
  };

  return {
    artifact_version: 1,
    coverage: {
      not_covered: [{ area: "Runtime-only sinks", reason: "Fake Pi does not execute the app." }],
      reviewed: [{ area: "Candidate operation files", evidence: [`${sinkPath}:1`] }],
    },
    generated_at: now,
    generated_by: "pi",
    kind: "sensitive-sinks.v1",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo,
    sinks: [
      {
        confidence: "medium",
        evidence: [`${sinkPath}:1`],
        id: "sink-1",
        kind: "filesystem_operation",
        location: sinkPath,
        operation: "Observable operation candidate",
      },
    ],
  };
}

function defaultFakeDataFlows(input: RuntimeJobInput): DataFlowsArtifact {
  const now = new Date().toISOString();
  const context = input.pi?.contextPack as Partial<PiContextPackArtifact> | undefined;
  const inventory = context?.inventory;
  const evidencePath =
    inventory?.candidate_entrypoints?.[0] ?? inventory?.manifest_files?.[0] ?? "README.md";
  const repo = {
    commit_sha: context?.repo?.commit_sha ?? null,
    url: context?.repo?.url ?? "https://github.com/vibeshield/fixture",
  };

  return {
    artifact_version: 1,
    coverage: {
      not_covered: [{ area: "Runtime execution", reason: "Fake Pi does not execute requests." }],
      reviewed: [{ area: "Entry-to-sink candidates", evidence: [`${evidencePath}:1`] }],
    },
    flows: [
      {
        id: "flow-1",
        intermediate_functions: [],
        sink: "sink-1",
        sink_evidence: [`${evidencePath}:1`],
        source_entrypoint: "ep-1",
        source_evidence: [`${evidencePath}:1`],
        trace_status: "direct observed",
      },
    ],
    generated_at: now,
    generated_by: "pi",
    inputs: {
      entry_points_artifact: "outputs/entry-points.v1.json",
      sensitive_sinks_artifact: "outputs/sensitive-sinks.v1.json",
    },
    kind: "data-flows.v1",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo,
  };
}

function defaultFakeProjectUnderstanding(input: RuntimeJobInput): ProjectUnderstandingArtifact {
  const now = new Date().toISOString();
  const context = input.pi?.contextPack as Partial<PiContextPackArtifact> | undefined;
  const inventory = context?.inventory;
  const manifestPath = inventory?.manifest_files?.[0] ?? "README.md";
  const entrypointPath = inventory?.candidate_entrypoints?.[0] ?? manifestPath;
  const repo = {
    commit_sha: context?.repo?.commit_sha ?? null,
    url: context?.repo?.url ?? "https://github.com/vibeshield/fixture",
  };

  return {
    artifact_version: 1,
    coverage: {
      not_covered: [{ area: "Runtime behavior", reason: "Phase 1 does not execute the app." }],
      reviewed: [{ area: "Previous Pi artifacts", evidence: [`${entrypointPath}:1`] }],
    },
    data_flow_groups: [
      {
        evidence: [`${entrypointPath}:1`],
        flow_ids: ["flow-1"],
        name: "Observed entry-to-operation traces",
        summary: "Data-flow synthesis is based on data-flows.v1.",
        trace_statuses: ["direct observed"],
      },
    ],
    entry_point_groups: [
      {
        entry_point_ids: ["ep-1"],
        evidence: [`${entrypointPath}:1`],
        name: "Primary entrypoint group",
        summary: "Entry point group summarized from entry-points.v1.",
      },
    ],
    generated_at: now,
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
          evidence: [`${entrypointPath}:1`],
          kind: "application",
          name: "Repository application surface",
          summary: "Component grouping synthesized from prior Pi artifacts.",
        },
      ],
      important_files: [
        {
          evidence: [`${manifestPath}:1`],
          path: manifestPath,
          reason: "Important project manifest or configuration file.",
        },
      ],
    },
    metadata: {
      pi: fakePiMetadata(input),
    },
    fact_gaps: [
      {
        area: "Runtime behavior",
        evidence: [`${entrypointPath}:1`],
        missing_fact: "Runtime behavior was not executed or observed in Phase 1.",
      },
    ],
    repo,
    sensitive_sink_groups: [
      {
        evidence: [`${entrypointPath}:1`],
        name: "Observable operation sinks",
        sensitive_sink_ids: ["sink-1"],
        summary: "Sink group summarized from sensitive-sinks.v1.",
      },
    ],
    stack: [{ evidence: [`${manifestPath}:1`], name: "Repository stack", role: "detected" }],
    summary: {
      confidence: "medium",
      evidence: [`${manifestPath}:1`],
      project_kind: "unknown",
      text: "Repository orientation generated from Phase 1 context pack.",
    },
  };
}

function fakePiMetadata(input: RuntimeJobInput): ProjectUnderstandingArtifact["metadata"]["pi"] {
  const tools = input.pi?.tools ?? ["read", "grep", "find", "ls"];
  return {
    input_context_artifact: input.pi?.inputContextArtifact ?? "outputs/pi-context-pack.v1.json",
    invocation: {
      args: ["-p", "--tools", tools.join(",")],
      command: "pi",
      cwd: "repo",
      metadata: { tools },
      provider: "openrouter",
    },
    model: input.pi?.model ?? "fake",
    provider: input.pi?.provider ?? "openrouter",
    step: input.pi?.step ?? "fake",
    version: "fake-pi-0.0.0",
  };
}

function isWorkflowPath(file: string): boolean {
  return file.startsWith(".github/workflows/");
}

function isIacCandidatePath(file: string): boolean {
  return (
    file.endsWith(".tf") ||
    file === "Dockerfile" ||
    file.endsWith("docker-compose.yml") ||
    file.endsWith("compose.yaml") ||
    file.endsWith("compose.yml") ||
    file.endsWith(".yaml") ||
    file.endsWith(".yml")
  );
}

function toPosixPath(filePath: string): string {
  return filePath.split(path.sep).join("/");
}
