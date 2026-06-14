import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  copyFile,
  lstat,
  mkdir,
  readdir,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import type {
  BaselineObservation,
  BaselineToolName,
  PiArtifactMetadata,
  PiContextPackArtifact,
  ToolAvailabilityArtifact,
} from "../artifacts/contracts.js";
import { buildRepoInventory } from "../inventory/repo-inventory.js";
import { ScanStageError } from "../run/errors.js";
import { type SourceReference, sourceArtifactReference } from "../run/github-url.js";
import { redactDeep } from "../run/redaction.js";
import type { SandboxCleanupState } from "../run/types.js";
import type {
  CollectDiagnosticsInput,
  CollectDiagnosticsResult,
  GenerateInventoryInput,
  MaterializeRepositoryOptions,
  MaterializeRepositoryResult,
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
  failAt?: "baseline" | "baseline-prepare" | "clone" | "inventory" | "pi";
  fixtureRepos: Map<string, string>;
  piOutputs?: Partial<Record<string, FakePiOutput>>;
  sandboxRoot: string;
  unavailableTools?: BaselineToolName[];
}

type FakePiOutput = unknown | ((input: RuntimeJobInput) => unknown);

type RepoMapStep =
  | "attack-hypotheses"
  | "auth-access"
  | "config-secrets"
  | "coverage-structure"
  | "crypto"
  | "data-flows"
  | "entrypoints"
  | "external-integrations-egress"
  | "infra-deploy"
  | "logging-observability"
  | "operation-sinks"
  | "repository-map"
  | "stack-build-deps"
  | "storage-data-model"
  | "trust-boundaries";

export class FakeDaytonaSandboxProvider implements SandboxProvider {
  readonly createdSandboxIds: string[] = [];
  readonly liveSandboxIds: string[] = [];
  readonly sessions: FakeDaytonaSandboxSession[] = [];
  readonly staleDeleteCalls: string[] = [];

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
      sandboxDir,
      source: context.repo,
      unavailableTools: this.options.unavailableTools ?? [],
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

  async deleteSandboxById(sandboxId: string): Promise<SandboxCleanupState> {
    this.staleDeleteCalls.push(sandboxId);
    const index = this.liveSandboxIds.indexOf(sandboxId);
    if (index >= 0) {
      this.liveSandboxIds.splice(index, 1);
    }

    return {
      attempted: true,
      deleted: index >= 0,
      success: true,
    };
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

  async collectDiagnostics(input: CollectDiagnosticsInput): Promise<CollectDiagnosticsResult> {
    const diagnosticsDir = path.join(this.artifactsDir, "diagnostics", "sandbox-failure");
    await mkdir(diagnosticsDir, { recursive: true });
    const manifestPath = path.join(diagnosticsDir, "manifest.json");
    const archivePath = path.join(diagnosticsDir, "sandbox-failure.tar.gz");
    await writeFile(
      manifestPath,
      `${JSON.stringify(
        {
          generated_at: new Date().toISOString(),
          included: [
            {
              label: "fake_artifacts",
              path: this.artifactsDir,
            },
          ],
          reason: input.reason,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    await writeFile(archivePath, "fake diagnostics archive\n", "utf8");
    return {
      artifacts: [
        {
          relativePath: "diagnostics/sandbox-failure/manifest.json",
          sandboxPath: manifestPath,
        },
        {
          relativePath: "diagnostics/sandbox-failure/sandbox-failure.tar.gz",
          sandboxPath: archivePath,
        },
      ],
      diagnostics: [],
    };
  }

  async materializeRepository(
    _repo?: SourceReference,
    options: MaterializeRepositoryOptions = {},
  ): Promise<MaterializeRepositoryResult> {
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

    if (this.options.source.type === "local") {
      this.commands[this.commands.length - 1] = {
        command: "vibeshield-local-snapshot <git-filtered-files> <sandbox-repo>",
        cwd: this.options.sandboxDir,
        repoDefinedCommand: false,
        stage: "clone",
      };
      await copyLocalSnapshotToSandbox(this.options.source, this.repoPath);
      return {
        commitSha: null,
        repoPath: this.repoPath,
      };
    }

    const fixtureRepo = this.options.fixtureRepos.get(this.options.source.url);
    if (fixtureRepo === undefined) {
      throw new ScanStageError({
        message: `No fake fixture repo is mapped for ${this.options.source.url}.`,
        stage: "clone",
        userMessage: "No fake fixture repository is configured for this GitHub URL.",
      });
    }

    await execFileAsync("git", ["clone", "--no-local", "--quiet", fixtureRepo, this.repoPath], {
      cwd: this.options.sandboxDir,
    });

    if (options.commitSha !== undefined) {
      this.commands.push({
        command: "git -C <sandbox-repo> checkout --detach <commit>",
        cwd: this.options.sandboxDir,
        repoDefinedCommand: false,
        stage: "clone",
      });
      await execFileAsync("git", ["-C", this.repoPath, "checkout", "--detach", options.commitSha], {
        cwd: this.options.sandboxDir,
      });
    }

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
      source: sourceArtifactReference(input.repo),
    });
    const artifactPath = path.join(this.artifactsDir, "inventory.json");
    await writeFile(artifactPath, `${JSON.stringify(inventory, null, 2)}\n`, "utf8");

    return {
      relativePath: "inventory.json",
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
        userMessage: "VibeShield could not complete the Pi repository-map step.",
      });
    }
    return this.runFakePi(input);
  }

  async prepareBaselineTools(
    input: PrepareBaselineToolsInput,
  ): Promise<PrepareBaselineToolsResult> {
    if (this.options.failAt === "baseline-prepare") {
      throw new ScanStageError({
        message: "Fake Daytona baseline tool preparation failure: read ECONNRESET.",
        stage: "deterministic-baseline",
        userMessage: "VibeShield could not prepare baseline checks.",
      });
    }

    const toolDir = path.join(this.artifactsDir, "baseline");
    await mkdir(toolDir, { recursive: true });
    const unavailable = new Set(this.options.unavailableTools ?? []);
    const availability: ToolAvailabilityArtifact = {
      generated_at: input.generatedAt,
      kind: "tool-availability",
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
            diagnostics: ["Required baseline check is unavailable."],
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
    const artifactPath = path.join(toolDir, "tool-availability.json");
    await writeFile(artifactPath, `${JSON.stringify(availability, null, 2)}\n`, "utf8");

    return {
      artifact: {
        relativePath: "baseline/tool-availability.json",
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
        `${JSON.stringify({ files, generated_by: "fake-syft" }, null, 2)}\n`,
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
      message: piStepStartMessage(input.pi.step),
      details: { step: input.pi.step },
      type: "runner.started",
    });

    const selectedOutput = fakePiOutputForStep(input, this.options);
    const output = redactDeep(selectedOutput);

    const rawPath = path.join(stepDir, `${input.pi.outputBaseName}.raw.redacted.txt`);
    const stderrPath = path.join(stepDir, "stderr.redacted.log");
    const progressPath = path.join(stepDir, "progress.jsonl");
    const metadataPath = path.join(stepDir, "metadata.json");
    const piToolArgs = input.pi.tools.length > 0 ? ["--tools", input.pi.tools.join(",")] : [];

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
            args: ["-p", ...piToolArgs],
            command: "pi",
            cwd: this.repoPath,
            metadata: { delivery: "final-response", tools: input.pi.tools },
            provider: "openrouter",
          },
          model: input.pi.model,
          final_response_bytes: isFakeRawPiOutput(output)
            ? output.rawText.length
            : JSON.stringify(output, null, 2).length + 1,
          provider: input.pi.provider,
          stderr_bytes: "fake pi completed\n".length,
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
      message: piStepDoneMessage(input.pi.step),
      details: { step: input.pi.step },
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
        args: ["-p", ...piToolArgs],
        command: "pi",
        cwd: this.repoPath,
        metadata: { delivery: "final-response", tools: input.pi.tools },
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
  failAt?: "baseline" | "baseline-prepare" | "clone" | "inventory" | "pi";
  fixtureRepos: Map<string, string>;
  id: string;
  piOutputs: Partial<Record<string, FakePiOutput>>;
  removeLiveSandboxId: () => void;
  sandboxDir: string;
  source: SourceReference;
  unavailableTools: BaselineToolName[];
}

async function copyLocalSnapshotToSandbox(
  source: Extract<SourceReference, { type: "local" }>,
  repoPath: string,
): Promise<void> {
  await rm(repoPath, { force: true, recursive: true });
  await mkdir(repoPath, { recursive: true });

  for (const file of source.snapshot.files) {
    const from = path.join(source.path, ...file.path.split("/"));
    const to = path.join(repoPath, ...file.path.split("/"));
    const stats = await lstat(from).catch(() => undefined);
    if (stats === undefined || stats.isDirectory()) {
      continue;
    }

    await mkdir(path.dirname(to), { recursive: true });
    if (stats.isSymbolicLink()) {
      const target = await readlink(from);
      await symlink(target, to);
      continue;
    }

    if (stats.isFile()) {
      await copyFile(from, to);
    }
  }
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
      return ["dir:<repo>", "-o", "cyclonedx-json"];
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

  if (tool === "trivy" && manifests.length > 0) {
    observations.push({
      confidence: "high",
      evidence: [`${manifests[0]}:1`],
      kind: "dependency",
      message: "CVE-FAKE-0001 in fixture-dependency@1.0.0 fixed in 1.0.1",
      severity: "medium",
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
    const candidate = files.find(isIacCandidatePath);
    observations.push({
      confidence: "high",
      evidence: candidate === undefined ? [] : [`${candidate}:1`],
      kind: "iac",
      message: "CKV_FAKE_1: Fixture IaC check failed",
      severity: "medium",
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

  const configured = configuredFakePiOutput(input, options);
  if (configured !== undefined) {
    return typeof configured === "function" ? configured(input) : configured;
  }

  const repoMapStep = repoMapStepFromInput(input);
  switch (repoMapStep) {
    case "attack-hypotheses":
      return defaultFakeAttackHypotheses(input);
    case "coverage-structure":
      return defaultFakeRepoMapCoverageStructure(input);
    case "stack-build-deps":
      return defaultFakeRepoMapStackBuildDeps(input);
    case "entrypoints":
      return defaultFakeRepoMapEntrypoints(input);
    case "auth-access":
      return defaultFakeRepoMapAuthAccess(input);
    case "config-secrets":
      return defaultFakeRepoMapConfigSecrets(input);
    case "storage-data-model":
      return defaultFakeRepoMapStorageDataModel(input);
    case "external-integrations-egress":
      return defaultFakeRepoMapExternalIntegrationsEgress(input);
    case "infra-deploy":
      return defaultFakeRepoMapInfraDeploy(input);
    case "operation-sinks":
      return defaultFakeRepoMapOperationSinks(input);
    case "crypto":
      return defaultFakeRepoMapCrypto(input);
    case "logging-observability":
      return defaultFakeRepoMapLoggingObservability(input);
    case "data-flows":
      return defaultFakeRepoMapDataFlows(input);
    case "trust-boundaries":
      return defaultFakeRepoMapTrustBoundaries(input);
    case "repository-map":
      return defaultFakeRepositoryMap(input);
    case undefined:
      break;
  }

  throw new Error(`No fake Pi output is configured for ${input.pi.outputBaseName}.`);
}

function configuredFakePiOutput(
  input: RuntimeJobInput,
  options: FakeDaytonaSandboxSessionOptions,
): FakePiOutput | undefined {
  const pi = input.pi;
  if (pi === undefined) {
    return undefined;
  }

  const keys = new Set([pi.step, pi.outputBaseName, pi.artifactSubdir]);
  const repoMapStep = repoMapStepFromInput(input);
  if (repoMapStep !== undefined) {
    keys.add(repoMapStep);
    keys.add(`repo-map/${repoMapStep}`);
    keys.add(`repo-map-${repoMapStep}`);
  }

  for (const key of keys) {
    const output = options.piOutputs[key];
    if (output !== undefined) {
      return output;
    }
  }

  return undefined;
}

function repoMapStepFromInput(input: RuntimeJobInput): RepoMapStep | undefined {
  if (input.pi === undefined) {
    return undefined;
  }

  return (
    normalizeRepoMapStep(input.pi.step) ??
    normalizeRepoMapStep(input.pi.outputBaseName) ??
    normalizeRepoMapStep(input.pi.artifactSubdir)
  );
}

function normalizeRepoMapStep(value: string): RepoMapStep | undefined {
  const normalized = value
    .replace(/^outputs\//, "")
    .replace(/^repo-map\//, "")
    .replace(/^pi-repo-map-/, "")
    .replace(/^repo-map-/, "")
    .replace(/\.json$/, "");

  switch (normalized) {
    case "coverage":
    case "coverage-structure":
      return "coverage-structure";
    case "attack-hypotheses":
    case "hypotheses":
      return "attack-hypotheses";
    case "stack":
    case "stack-build-deps":
      return "stack-build-deps";
    case "entrypoints":
      return "entrypoints";
    case "auth":
    case "auth-access":
      return "auth-access";
    case "config":
    case "config-secrets":
      return "config-secrets";
    case "storage":
    case "storage-data-model":
      return "storage-data-model";
    case "external-integrations-egress":
    case "integrations":
      return "external-integrations-egress";
    case "infra":
    case "infra-deploy":
      return "infra-deploy";
    case "operation-sinks":
      return "operation-sinks";
    case "crypto":
      return "crypto";
    case "logging":
    case "logging-observability":
      return "logging-observability";
    case "data-flows":
      return "data-flows";
    case "trust-boundaries":
      return "trust-boundaries";
    case "repository-map":
      return "repository-map";
    default:
      return undefined;
  }
}

function isFakeRawPiOutput(value: unknown): value is { rawText: string } {
  return (
    value !== null &&
    typeof value === "object" &&
    "rawText" in value &&
    typeof (value as { rawText?: unknown }).rawText === "string"
  );
}

function defaultFakeRepoMapCoverageStructure(input: RuntimeJobInput) {
  const now = new Date().toISOString();
  const repo = fakeRepoFromInput(input);
  const manifestPath = fakeManifestPath(input);

  return {
    coverage: fakeRepoMapCoverage("Repository structure", [`${manifestPath}:1`]),
    coverage_targets: [
      {
        area: "Application source",
        evidence: ["src/server.ts:1"],
        reason: "Primary source directory reviewed for repository map facts.",
      },
    ],
    fact_gaps: [],
    generated_at: now,
    generated_by: "pi",
    important_files: [
      {
        evidence: [`${manifestPath}:1`],
        path: manifestPath,
        reason: "Defines dependencies and scripts.",
      },
      {
        evidence: ["Dockerfile:1"],
        path: "Dockerfile",
        reason: "Defines runtime image.",
      },
    ],
    kind: "coverage-structure",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo,
    repository_structure: [
      { evidence: ["src/server.ts:1"], kind: "source", path: "src", role: "application source" },
      { evidence: ["infra/main.tf:1"], kind: "infra", path: "infra", role: "infrastructure" },
      { evidence: [`${manifestPath}:1`], kind: "dependency", path: manifestPath, role: "manifest" },
    ],
  };
}

function defaultFakeRepoMapStackBuildDeps(input: RuntimeJobInput) {
  const now = new Date().toISOString();
  const repo = fakeRepoFromInput(input);
  const manifestPath = fakeManifestPath(input);

  return {
    build: {
      commands: [
        {
          command: "node scripts/should-not-run.js",
          evidence: [`${manifestPath}:6`],
          id: "build-package-script",
          name: "package build script",
          source: "package.json scripts.build",
        },
      ],
      lockfiles: [],
      manifests: [{ evidence: [`${manifestPath}:1`], path: manifestPath }],
    },
    coverage: fakeRepoMapCoverage("Stack, build, dependencies, and CI", [
      `${manifestPath}:1`,
      ".github/workflows/ci.yml:1",
    ]),
    dependencies: [
      {
        confidence: "high",
        evidence: [`${manifestPath}:4`],
        id: "dep-express",
        kind: "dependency",
        name: "express",
        role: "^5.0.0 runtime dependency",
      },
    ],
    fact_gaps: [],
    generated_at: now,
    generated_by: "pi",
    kind: "stack-build-deps",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo,
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

function defaultFakeRepoMapEntrypoints(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    coverage: fakeRepoMapCoverage("External entrypoints", [
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
    fact_gaps: [],
    generated_at: now,
    generated_by: "pi",
    kind: "entrypoints",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
  };
}

function defaultFakeRepoMapAuthAccess(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    auth: [
      {
        confidence: "high",
        evidence: ["src/auth.ts:2"],
        id: "auth-session-middleware",
        kind: "middleware",
        location: "src/auth.ts",
        name: "requireSession middleware",
        notes: "Used by entry-http-spam route.",
      },
    ],
    coverage: fakeRepoMapCoverage("Auth and access control", ["src/auth.ts:2"]),
    entrypoint_access: [
      {
        entrypoint_id: "entry-http-spam",
        evidence: ["src/server.ts:6", "src/auth.ts:2"],
        mechanism: "session",
        status: "protected",
      },
    ],
    fact_gaps: [],
    generated_at: now,
    generated_by: "pi",
    kind: "auth-access",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
  };
}

function defaultFakeRepoMapConfigSecrets(input: RuntimeJobInput) {
  const now = new Date().toISOString();

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
    coverage: fakeRepoMapCoverage("Configuration and secret references", [
      "src/config.ts:1",
      ".env.example:1",
    ]),
    fact_gaps: [],
    generated_at: now,
    generated_by: "pi",
    kind: "config-secrets",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
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

function defaultFakeRepoMapStorageDataModel(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    coverage: fakeRepoMapCoverage("Storage and data model", ["src/db.ts:2", "src/schema.sql:1"]),
    fact_gaps: [],
    generated_at: now,
    generated_by: "pi",
    kind: "storage-data-model",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
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

function defaultFakeRepoMapExternalIntegrationsEgress(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    coverage: fakeRepoMapCoverage("External integrations and egress", ["src/http.ts:3"]),
    fact_gaps: [],
    generated_at: now,
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
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
  };
}

function defaultFakeRepoMapInfraDeploy(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    coverage: fakeRepoMapCoverage("Infrastructure and deployment", [
      "Dockerfile:1",
      "infra/main.tf:1",
      ".github/workflows/ci.yml:1",
    ]),
    fact_gaps: [],
    generated_at: now,
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
    kind: "infra-deploy",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
  };
}

function defaultFakeRepoMapOperationSinks(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    coverage: fakeRepoMapCoverage("Operation sinks", [
      "src/db.ts:2",
      "src/files.ts:4",
      "src/http.ts:3",
    ]),
    fact_gaps: [],
    generated_at: now,
    generated_by: "pi",
    kind: "operation-sinks",
    metadata: {
      pi: fakePiMetadata(input),
    },
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
    repo: fakeRepoFromInput(input),
  };
}

function defaultFakeRepoMapCrypto(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    coverage: fakeRepoMapCoverage("Crypto and randomness", ["src/crypto.ts:2", "src/crypto.ts:3"]),
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
    fact_gaps: [],
    generated_at: now,
    generated_by: "pi",
    kind: "crypto",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
  };
}

function defaultFakeRepoMapLoggingObservability(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    coverage: fakeRepoMapCoverage("Logging and observability", ["src/logger.ts:2"]),
    fact_gaps: [],
    generated_at: now,
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
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
  };
}

function defaultFakeRepoMapDataFlows(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    coverage: fakeRepoMapCoverage("Bounded external-input data flows", [
      "src/server.ts:5",
      "src/db.ts:2",
    ]),
    fact_gaps: [],
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
    generated_at: now,
    generated_by: "pi",
    inputs: {
      entrypoints_artifact: "outputs/repo-map/entrypoints.json",
      operation_sinks_artifact: "outputs/repo-map/operation-sinks.json",
    },
    kind: "data-flows",
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
  };
}

function defaultFakeRepoMapTrustBoundaries(input: RuntimeJobInput) {
  const now = new Date().toISOString();

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
        summary: "External HTTP request data crosses into the application and database layer.",
      },
    ],
    coverage: fakeRepoMapCoverage("Trust-boundary inferences", [
      "src/server.ts:5",
      "src/auth.ts:2",
      "src/db.ts:2",
    ]),
    fact_gaps: [],
    generated_at: now,
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
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
  };
}

function defaultFakeRepositoryMap(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    coverage: fakeRepoMapCoverage("Repository map synthesis", ["src/server.ts:5"]),
    fact_gaps: [],
    generated_at: now,
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
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
    sections: [
      fakeRepoMapSection("coverage-structure", "outputs/repo-map/coverage-structure.json", 3),
      fakeRepoMapSection("stack-build-deps", "outputs/repo-map/stack-build-deps.json", 4),
      fakeRepoMapSection("entrypoints", "outputs/repo-map/entrypoints.json", 4),
      fakeRepoMapSection("auth-access", "outputs/repo-map/auth-access.json", 4),
      fakeRepoMapSection("config-secrets", "outputs/repo-map/config-secrets.json", 7),
      fakeRepoMapSection("storage-data-model", "outputs/repo-map/storage-data-model.json", 2),
      fakeRepoMapSection(
        "external-integrations-egress",
        "outputs/repo-map/external-integrations-egress.json",
        1,
      ),
      fakeRepoMapSection("infra-deploy", "outputs/repo-map/infra-deploy.json", 3),
      fakeRepoMapSection("operation-sinks", "outputs/repo-map/operation-sinks.json", 6),
      fakeRepoMapSection("crypto", "outputs/repo-map/crypto.json", 2),
      fakeRepoMapSection("logging-observability", "outputs/repo-map/logging-observability.json", 1),
      fakeRepoMapSection("data-flows", "outputs/repo-map/data-flows.json", 1),
      fakeRepoMapSection("trust-boundaries", "outputs/repo-map/trust-boundaries.json", 1),
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

function defaultFakeAttackHypotheses(input: RuntimeJobInput) {
  const now = new Date().toISOString();

  return {
    blocking_fact_gaps: [],
    coverage: fakeRepoMapCoverage("Attack hypothesis generation", [
      "entry-http-spam",
      "flow-http-spam-db",
      "sink-db-insert",
    ]),
    cross_cutting_chains: [],
    deprioritized_areas: [],
    executive_summary: {
      hypothesis_counts: { P2: 1 },
      limitations: ["Fake fixture hypotheses are generated from static map facts only."],
      strong_hypothesis_count: 1,
      text: "One medium-priority hypothesis links external HTTP input to a database write.",
      top_risk_areas: ["HTTP input to database write"],
    },
    fact_gaps: [],
    generated_at: now,
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
    metadata: {
      pi: fakePiMetadata(input),
    },
    repo: fakeRepoFromInput(input),
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

function fakeRepoMapSection(artifact: RepoMapStep, artifactPath: string, itemCount: number) {
  return {
    artifact,
    evidence: ["src/server.ts:5"],
    item_count: itemCount,
    path: artifactPath,
    summary: `${artifact} facts are available.`,
  };
}

function fakeRepoMapCoverage(area: string, evidence: string[]) {
  return {
    not_covered: [
      {
        area: "Runtime-only behavior",
        reason: "Fake Pi does not execute the application.",
      },
    ],
    reviewed: [{ area, evidence }],
  };
}

function piStepStartMessage(step: string): string {
  switch (step) {
    case "attack-hypotheses":
      return "Generating attack hypotheses from the repository map.";
    case "coverage-structure":
      return "Mapping repository coverage and structure.";
    case "stack-build-deps":
      return "Collecting stack, build, and dependency facts.";
    case "entrypoints":
      return "Collecting externally reachable entrypoints.";
    case "auth-access":
      return "Mapping auth and access-control facts.";
    case "config-secrets":
      return "Mapping configuration and secret-reference facts.";
    case "storage-data-model":
      return "Collecting storage and data-model facts.";
    case "external-integrations-egress":
      return "Collecting external integration and egress facts.";
    case "infra-deploy":
      return "Collecting infrastructure and deployment facts.";
    case "operation-sinks":
      return "Collecting observable operation sinks.";
    case "crypto":
      return "Collecting crypto and randomness facts.";
    case "logging-observability":
      return "Collecting logging and observability facts.";
    case "data-flows":
      return "Tracing bounded entrypoint-to-sink flows.";
    case "trust-boundaries":
      return "Synthesizing trust boundaries from accepted map facts.";
    case "repository-map":
      return "Assembling the final repository map.";
    default:
      return "Running repository-map collection.";
  }
}

function piStepDoneMessage(step: string): string {
  switch (step) {
    case "attack-hypotheses":
      return "Attack hypothesis generation completed.";
    case "coverage-structure":
      return "Coverage and structure map completed.";
    case "stack-build-deps":
      return "Stack, build, and dependency facts completed.";
    case "entrypoints":
      return "Entrypoint collection completed.";
    case "auth-access":
      return "Auth and access-control map completed.";
    case "config-secrets":
      return "Configuration and secret-reference map completed.";
    case "storage-data-model":
      return "Storage and data-model facts completed.";
    case "external-integrations-egress":
      return "External integration and egress facts completed.";
    case "infra-deploy":
      return "Infrastructure and deployment facts completed.";
    case "operation-sinks":
      return "Operation sink inventory completed.";
    case "crypto":
      return "Crypto and randomness facts completed.";
    case "logging-observability":
      return "Logging and observability facts completed.";
    case "data-flows":
      return "Bounded data-flow tracing completed.";
    case "trust-boundaries":
      return "Trust-boundary synthesis completed.";
    case "repository-map":
      return "Final repository map assembled.";
    default:
      return "Repository-map collection completed.";
  }
}

function fakeRepoFromInput(input: RuntimeJobInput): { commit_sha: string | null; url: string } {
  const context = input.pi?.contextPack as Partial<PiContextPackArtifact> | undefined;
  return {
    commit_sha: context?.repo?.commit_sha ?? null,
    url: context?.repo?.url ?? "https://github.com/vibeshield/fixture",
  };
}

function fakeManifestPath(input: RuntimeJobInput): string {
  const context = input.pi?.contextPack as Partial<PiContextPackArtifact> | undefined;
  return context?.inventory?.manifest_files?.[0] ?? "package.json";
}

function fakePiMetadata(input: RuntimeJobInput): PiArtifactMetadata["pi"] {
  const tools = input.pi?.tools ?? ["read", "grep", "find", "ls"];
  const toolArgs = tools.length > 0 ? ["--tools", tools.join(",")] : [];
  return {
    input_context_artifact: input.pi?.inputContextArtifact ?? "outputs/pi-context-pack.json",
    invocation: {
      args: ["-p", ...toolArgs],
      command: "pi",
      cwd: "repo",
      metadata: { delivery: "final-response", tools },
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
