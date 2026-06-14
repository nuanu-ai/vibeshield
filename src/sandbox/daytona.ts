import { randomUUID } from "node:crypto";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import type { CreateSandboxFromSnapshotParams, DaytonaConfig } from "@daytona/sdk";
import { CodeLanguage, Daytona } from "@daytona/sdk";
import type { BaselineToolName } from "../artifacts/contracts.js";
import { errorMessage, ScanStageError } from "../run/errors.js";
import type { SandboxCleanupState } from "../run/types.js";
import { buildDaytonaInventoryScript } from "./daytona-inventory-script.js";
import type {
  CloneRepositoryOptions,
  CloneRepositoryResult,
  GenerateInventoryInput,
  PrepareBaselineToolsInput,
  PrepareBaselineToolsResult,
  PullFileContext,
  RuntimeJobInput,
  RuntimeJobProgressEvent,
  RuntimeJobResult,
  SandboxArtifact,
  SandboxCreateContext,
  SandboxProvider,
  SandboxSession,
} from "./types.js";

export interface DaytonaExecuteResponse {
  artifacts?: {
    stdout?: string;
  };
  exitCode: number;
  result?: string;
}

export interface DaytonaSandboxLike {
  readonly fs: {
    downloadFile(remotePath: string, localPath: string, timeout?: number): Promise<void>;
  };
  readonly git: {
    clone(
      url: string,
      path: string,
      branch?: string,
      commitId?: string,
      username?: string,
      password?: string,
      insecureSkipTls?: boolean,
    ): Promise<void>;
  };
  readonly id: string;
  readonly process: {
    codeRun(
      code: string,
      params?: { argv?: string[]; env?: Record<string, string> },
      timeout?: number,
    ): Promise<DaytonaExecuteResponse>;
    createSession?(sessionId: string): Promise<void>;
    deleteSession?(sessionId: string): Promise<void>;
    executeCommand(
      command: string,
      cwd?: string,
      env?: Record<string, string>,
      timeout?: number,
    ): Promise<DaytonaExecuteResponse>;
    executeSessionCommand?(
      sessionId: string,
      command: {
        command: string;
        runAsync?: boolean;
        suppressInputEcho?: boolean;
      },
      timeout?: number,
    ): Promise<{ cmdId?: string }>;
    getSessionCommand?(sessionId: string, commandId: string): Promise<unknown>;
    getSessionCommandLogs?(
      sessionId: string,
      commandId: string,
    ): Promise<{ output?: string; stderr?: string; stdout?: string }>;
    getSessionCommandLogs?(
      sessionId: string,
      commandId: string,
      onStdout: (chunk: string) => void,
      onStderr: (chunk: string) => void,
    ): Promise<void>;
  };
  delete(timeout?: number): Promise<void>;
}

export interface DaytonaClientLike {
  create(
    params?: CreateSandboxFromSnapshotParams,
    options?: { timeout?: number },
  ): Promise<DaytonaSandboxLike>;
  get?(sandboxId: string): Promise<DaytonaSandboxLike>;
}

interface DaytonaSessionProcessApi {
  createSession(sessionId: string): Promise<void>;
  deleteSession(sessionId: string): Promise<void>;
  executeSessionCommand(
    sessionId: string,
    command: {
      command: string;
      runAsync?: boolean;
      suppressInputEcho?: boolean;
    },
    timeout?: number,
  ): Promise<{ cmdId?: string }>;
  getSessionCommand(sessionId: string, commandId: string): Promise<unknown>;
  getSessionCommandLogs(
    sessionId: string,
    commandId: string,
  ): Promise<{ output?: string; stderr?: string; stdout?: string }>;
  getSessionCommandLogs(
    sessionId: string,
    commandId: string,
    onStdout: (chunk: string) => void,
    onStderr: (chunk: string) => void,
  ): Promise<void>;
}

export interface DaytonaSandboxProviderOptions {
  client?: DaytonaClientLike;
  clientFactory?: () => DaytonaClientLike;
  commandTimeoutSeconds?: number;
  createTimeoutSeconds?: number;
  deleteTimeoutSeconds?: number;
  downloadTimeoutSeconds?: number;
  repoPath?: string;
}

const defaultRepoPath = "repo";
const defaultArtifactDir = "vibeshield/artifacts";
const defaultArtifactPath = "vibeshield/artifacts/inventory.json";

export class DaytonaSandboxProvider implements SandboxProvider {
  private client?: DaytonaClientLike;

  constructor(private readonly options: DaytonaSandboxProviderOptions = {}) {}

  async createSandbox(context: SandboxCreateContext): Promise<SandboxSession> {
    const client = this.getClient();
    const sandbox = await client
      .create(
        {
          autoStopInterval: 15,
          ephemeral: true,
          labels: {
            app: "vibeshield",
            run_id: context.runId,
            source: "github",
            source_owner: context.repo.owner,
            source_repo: context.repo.repo,
            workflow: "repository-map",
          },
          language: CodeLanguage.TYPESCRIPT,
          public: false,
        },
        { timeout: this.options.createTimeoutSeconds ?? 120 },
      )
      .catch((error: unknown) => {
        throw new ScanStageError({
          cause: error,
          message: errorMessage(error),
          stage: "create_sandbox",
          userMessage: `Could not create Daytona sandbox: ${errorMessage(error)}`,
        });
      });

    return new DaytonaSandboxSession(sandbox, {
      commandTimeoutSeconds: this.options.commandTimeoutSeconds ?? 120,
      deleteTimeoutSeconds: this.options.deleteTimeoutSeconds ?? 120,
      downloadTimeoutSeconds: this.options.downloadTimeoutSeconds ?? 120,
      repoPath: this.options.repoPath ?? defaultRepoPath,
      sandboxArtifactDir: defaultArtifactDir,
      sandboxArtifactPath: defaultArtifactPath,
    });
  }

  async deleteSandboxById(sandboxId: string): Promise<SandboxCleanupState> {
    const client = this.getClient();
    if (client.get === undefined) {
      return {
        attempted: true,
        deleted: false,
        error: "Daytona client does not support get(sandboxId).",
        success: false,
      };
    }

    try {
      const sandbox = await client.get(sandboxId);
      await sandbox.delete(this.options.deleteTimeoutSeconds ?? 120);
      return {
        attempted: true,
        deleted: true,
        success: true,
      };
    } catch (error) {
      return {
        attempted: true,
        deleted: false,
        error: errorMessage(error),
        success: false,
      };
    }
  }

  private getClient(): DaytonaClientLike {
    if (this.client !== undefined) {
      return this.client;
    }

    if (this.options.client !== undefined) {
      this.client = this.options.client;
      return this.client;
    }

    if (this.options.clientFactory !== undefined) {
      this.client = this.options.clientFactory();
      return this.client;
    }

    try {
      const missingEnvVars = missingDaytonaEnvVars();
      if (missingEnvVars.length > 0) {
        throw new Error(`Missing ${missingEnvVars.join(", ")}`);
      }
      this.client = new Daytona(readDaytonaConfigFromEnv());
      return this.client;
    } catch (error) {
      throw new ScanStageError({
        cause: error,
        message: errorMessage(error),
        stage: "create_sandbox",
        userMessage:
          `Could not initialize Daytona SDK: ${errorMessage(error)}. ` +
          "Set DAYTONA_API_KEY for live scans. DAYTONA_API_URL and DAYTONA_TARGET are optional overrides.",
      });
    }
  }
}

export class DaytonaSandboxSession implements SandboxSession {
  readonly providerName = "daytona";

  constructor(
    private readonly sandbox: DaytonaSandboxLike,
    private readonly options: {
      commandTimeoutSeconds: number;
      deleteTimeoutSeconds: number;
      downloadTimeoutSeconds: number;
      repoPath: string;
      sandboxArtifactDir: string;
      sandboxArtifactPath: string;
    },
  ) {}

  get id(): string {
    return this.sandbox.id;
  }

  async cloneRepository(
    repo: { url: string },
    options: CloneRepositoryOptions = {},
  ): Promise<CloneRepositoryResult> {
    await this.sandbox.git.clone(repo.url, this.options.repoPath).catch((error: unknown) => {
      throw new ScanStageError({
        cause: error,
        message: errorMessage(error),
        stage: "clone",
        userMessage: `Could not clone repository inside Daytona sandbox: ${errorMessage(error)}`,
      });
    });

    if (options.commitSha !== undefined) {
      const checkoutResponse = await this.sandbox.process
        .executeCommand(
          `git checkout --detach ${options.commitSha}`,
          this.options.repoPath,
          {},
          this.options.commandTimeoutSeconds,
        )
        .catch((error: unknown) => {
          throw new ScanStageError({
            cause: error,
            message: errorMessage(error),
            stage: "clone",
            userMessage: `Could not checkout commit inside Daytona sandbox: ${errorMessage(error)}`,
          });
        });

      assertSandboxCommandSucceeded(checkoutResponse, "clone", "checkout commit");
    }

    const commitResponse = await this.sandbox.process
      .executeCommand(
        "git rev-parse HEAD",
        this.options.repoPath,
        {},
        this.options.commandTimeoutSeconds,
      )
      .catch((error: unknown) => {
        throw new ScanStageError({
          cause: error,
          message: errorMessage(error),
          stage: "clone",
          userMessage: `Could not read commit SHA inside Daytona sandbox: ${errorMessage(error)}`,
        });
      });

    assertSandboxCommandSucceeded(commitResponse, "clone", "read commit SHA");

    return {
      commitSha: readCommandStdout(commitResponse).trim() || null,
      repoPath: this.options.repoPath,
    };
  }

  async generateInventory(input: GenerateInventoryInput): Promise<SandboxArtifact> {
    const script = buildDaytonaInventoryScript({
      artifactPath: this.options.sandboxArtifactPath,
      commitSha: input.commitSha,
      generatedAt: input.generatedAt,
      repoRoot: this.options.repoPath,
      sandboxId: this.id,
      source: input.repo,
    });

    const response = await this.sandbox.process
      .codeRun(script, undefined, this.options.commandTimeoutSeconds)
      .catch((error: unknown) => {
        throw new ScanStageError({
          cause: error,
          message: errorMessage(error),
          stage: "inventory",
          userMessage: `Could not run read-only inventory inside Daytona sandbox: ${errorMessage(error)}`,
        });
      });

    assertSandboxCommandSucceeded(response, "inventory", "run read-only inventory");

    return {
      relativePath: "inventory.json",
      sandboxPath: this.options.sandboxArtifactPath,
    };
  }

  async runJob(input: RuntimeJobInput): Promise<RuntimeJobResult> {
    if (input.kind === "baseline-tool") {
      return this.runBaselineTool(input);
    }
    return this.runPiRepositoryMap(input);
  }

  async prepareBaselineTools(
    input: PrepareBaselineToolsInput,
  ): Promise<PrepareBaselineToolsResult> {
    const response = await this.sandbox.process
      .codeRun(
        buildToolAvailabilityScript({
          artifactDir: this.options.sandboxArtifactDir,
          generatedAt: input.generatedAt,
          toolBinDir: "/tmp/vibeshield-tools/bin",
          tools: input.tools,
        }),
        undefined,
        900,
      )
      .catch((error: unknown) => {
        throw new ScanStageError({
          cause: error,
          message: errorMessage(error),
          stage: "deterministic-baseline",
          userMessage: `Could not prepare deterministic baseline tools inside Daytona sandbox: ${errorMessage(
            error,
          )}`,
        });
      });

    assertSandboxCommandSucceeded(response, "deterministic-baseline", "prepare baseline tools");

    try {
      return parseJsonObjectFromText(readCommandStdout(response)) as PrepareBaselineToolsResult;
    } catch (error) {
      throw new ScanStageError({
        cause: error,
        message: `Could not parse tool availability artifact metadata: ${errorMessage(error)}`,
        stage: "deterministic-baseline",
        userMessage: "VibeShield could not read baseline tool availability metadata.",
      });
    }
  }

  private async runBaselineTool(input: RuntimeJobInput): Promise<RuntimeJobResult> {
    if (input.baseline === undefined) {
      throw new ScanStageError({
        message: "Missing baseline tool runtime input.",
        stage: "deterministic-baseline",
      });
    }

    const script = buildBaselineToolScript({
      artifactDir: this.options.sandboxArtifactDir,
      generatedAt: input.generatedAt,
      hasGithubActions: input.baseline.hasGithubActions,
      hasIacCandidates: input.baseline.hasIacCandidates,
      repoPath: this.options.repoPath,
      ...(input.baseline.sbomSandboxPath === undefined
        ? {}
        : { sbomSandboxPath: input.baseline.sbomSandboxPath }),
      toolBinDir: "/tmp/vibeshield-tools/bin",
      tool: input.baseline.tool,
    });

    const response = await this.sandbox.process
      .codeRun(script, undefined, 900)
      .catch((error: unknown) => {
        throw new ScanStageError({
          cause: error,
          message: errorMessage(error),
          stage: "deterministic-baseline",
          userMessage: `Could not run ${input.baseline?.tool ?? input.name} inside Daytona sandbox: ${errorMessage(
            error,
          )}`,
        });
      });

    assertSandboxCommandSucceeded(response, "deterministic-baseline", `run ${input.name}`);

    try {
      return parseJsonObjectFromText(readCommandStdout(response)) as RuntimeJobResult;
    } catch (error) {
      throw new ScanStageError({
        cause: error,
        message: `Could not parse runtime result for ${input.name}: ${errorMessage(error)}`,
        stage: "deterministic-baseline",
        userMessage: `VibeShield could not read ${input.name} baseline metadata from the sandbox.`,
      });
    }
  }

  private async runPiRepositoryMap(input: RuntimeJobInput): Promise<RuntimeJobResult> {
    if (input.pi === undefined) {
      throw new ScanStageError({
        message: "Missing Pi runtime input.",
        stage: "pi",
      });
    }

    const apiKey = readNonEmptyEnv("OPENROUTER_API_KEY");
    if (apiKey === undefined) {
      throw new ScanStageError({
        message: "Missing OPENROUTER_API_KEY.",
        stage: "pi",
        userMessage:
          "Pi repository mapping requires OPENROUTER_API_KEY. Set it in .env or the shell.",
      });
    }

    const authResponse = await this.sandbox.process
      .executeCommand(buildPiAuthCommand(), undefined, { OPENROUTER_API_KEY: apiKey }, 60)
      .catch((error: unknown) => {
        throw new ScanStageError({
          cause: error,
          message: errorMessage(error),
          stage: "pi",
          userMessage: `Could not prepare Pi auth inside Daytona sandbox: ${errorMessage(error)}`,
        });
      });

    assertSandboxCommandSucceeded(authResponse, "pi", "prepare Pi auth");

    const startedAt = new Date().toISOString();
    const command = buildPiRunnerCommand({
      artifactSubdir: input.pi.artifactSubdir,
      artifactDir: this.options.sandboxArtifactDir,
      ...(input.pi.attempt === undefined ? {} : { attempt: input.pi.attempt }),
      contextPack: input.pi.contextPack,
      inputContextArtifact: input.pi.inputContextArtifact,
      jobName: input.name,
      model: input.pi.model,
      outputFile: input.pi.outputFile,
      outputBaseName: input.pi.outputBaseName,
      prompt: input.pi.prompt,
      provider: input.pi.provider,
      repoPath: this.options.repoPath,
      step: input.pi.step,
      tools: input.pi.tools,
    });
    const exitCode = await this.runLongRunningPiCommand(command, apiKey, input.onProgress);
    const artifacts = piRuntimeArtifacts({
      artifactDir: this.options.sandboxArtifactDir,
      artifactSubdir: input.pi.artifactSubdir,
      outputBaseName: input.pi.outputBaseName,
    });
    const piToolArgs = input.pi.tools.length > 0 ? ["--tools", input.pi.tools.join(",")] : [];

    return {
      artifacts,
      diagnostics: exitCode === 0 ? [] : [`Pi exited with code ${exitCode}.`],
      exitCode,
      finishedAt: new Date().toISOString(),
      invocation: {
        args: [
          "-p",
          "--no-session",
          "--no-context-files",
          "--no-extensions",
          "--no-skills",
          "--no-prompt-templates",
          "--no-themes",
          ...piToolArgs,
          "--provider",
          input.pi.provider,
          "--model",
          input.pi.model,
          "--thinking",
          "low",
          "--mode",
          "json",
          "<prompt>",
        ],
        command: "pi",
        cwd: this.options.repoPath,
        metadata: {
          output_file: input.pi.outputFile,
          package: "@earendil-works/pi-coding-agent",
          tools: input.pi.tools,
          verified_help_version: "0.79.1",
        },
        provider: input.pi.provider,
      },
      kind: "pi-repository-mapping",
      metadata: {
        input_context_artifact: input.pi.inputContextArtifact,
        model: input.pi.model,
        provider: input.pi.provider,
        step: input.pi.step,
      },
      observations: [],
      startedAt,
      status: exitCode === 0 ? "completed" : "failed",
    };
  }

  private async runLongRunningPiCommand(
    command: string,
    apiKey: string,
    onProgress?: (event: RuntimeJobProgressEvent) => unknown | Promise<unknown>,
  ): Promise<number> {
    const processApi = this.sandbox.process;
    const sessionApi = readSessionProcessApi(processApi);
    if (sessionApi !== null) {
      return this.runPiCommandInSession(command, sessionApi, onProgress);
    }

    const response = await processApi
      .executeCommand(command, undefined, { OPENROUTER_API_KEY: apiKey }, 900)
      .catch((error: unknown) => {
        throw new ScanStageError({
          cause: error,
          message: errorMessage(error),
          stage: "pi",
          userMessage: `Could not run Pi inside Daytona sandbox: ${errorMessage(error)}`,
        });
      });

    return response.exitCode;
  }

  private async runPiCommandInSession(
    command: string,
    processApi: DaytonaSessionProcessApi,
    onProgress?: (event: RuntimeJobProgressEvent) => unknown | Promise<unknown>,
  ): Promise<number> {
    const sessionId = `vibeshield-pi-${randomUUID()}`;
    await processApi.createSession(sessionId);

    try {
      const started = await processApi.executeSessionCommand(
        sessionId,
        {
          command,
          runAsync: true,
          suppressInputEcho: true,
        },
        30,
      );

      if (started.cmdId === undefined || started.cmdId === "") {
        throw new ScanStageError({
          message: "Daytona did not return a command id for the Pi session command.",
          stage: "pi",
        });
      }
      const commandId = started.cmdId;

      let logsSettled = false;
      let progressQueue: Promise<unknown> = Promise.resolve();
      const progressParser = createPiProgressParser((event) => {
        if (onProgress === undefined) {
          return;
        }
        progressQueue = progressQueue.then(() =>
          Promise.resolve(onProgress(event)).catch(() => undefined),
        );
      });
      let consumedStdout = "";
      const consumeStdout = (chunk: string) => {
        if (chunk === "") {
          return;
        }
        if (chunk.startsWith(consumedStdout)) {
          const delta = chunk.slice(consumedStdout.length);
          consumedStdout = chunk;
          progressParser.consume(delta);
          return;
        }
        consumedStdout += chunk;
        progressParser.consume(chunk);
      };
      const logsPromise = processApi
        .getSessionCommandLogs(
          sessionId,
          commandId,
          (chunk) => consumeStdout(chunk),
          () => {},
        )
        .catch(() => undefined)
        .finally(() => {
          progressParser.flush();
          logsSettled = true;
        });

      const exitCode = await waitForSessionCommandExit({
        commandId,
        getCommand: (commandId) => processApi.getSessionCommand(sessionId, commandId),
        logsSettled: () => logsSettled,
        pollLogs: async () => {
          const logs = await processApi.getSessionCommandLogs(sessionId, commandId);
          consumeStdout(logs.stdout ?? logs.output ?? "");
        },
        timeoutMs: 900_000,
      });

      await Promise.race([logsPromise, sleep(5_000)]);
      await progressQueue;
      return exitCode;
    } finally {
      await processApi.deleteSession(sessionId).catch(() => undefined);
    }
  }

  async pullFile(
    sandboxPath: string,
    localPath: string,
    context: PullFileContext = { stage: "inventory" },
  ): Promise<void> {
    await mkdir(path.dirname(localPath), { recursive: true });
    await this.sandbox.fs
      .downloadFile(sandboxPath, localPath, this.options.downloadTimeoutSeconds)
      .catch((error: unknown) => {
        const artifactLabel = context.artifact ?? context.job ?? context.stage;
        throw new ScanStageError({
          cause: error,
          message: errorMessage(error),
          stage: context.stage,
          userMessage: `Could not pull ${artifactLabel} artifact from Daytona sandbox: ${errorMessage(
            error,
          )}`,
        });
      });
  }

  async delete(): Promise<SandboxCleanupState> {
    await this.sandbox.delete(this.options.deleteTimeoutSeconds);
    return {
      attempted: true,
      deleted: true,
      success: true,
    };
  }
}

function assertSandboxCommandSucceeded(
  response: DaytonaExecuteResponse,
  stage: "clone" | "deterministic-baseline" | "inventory" | "pi",
  action: string,
): void {
  if (response.exitCode === 0) {
    return;
  }

  throw new ScanStageError({
    message: readCommandStdout(response),
    stage,
    userMessage: `Daytona sandbox command failed while trying to ${action}.`,
  });
}

function readCommandStdout(response: DaytonaExecuteResponse): string {
  return response.artifacts?.stdout ?? response.result ?? "";
}

function parseJsonObjectFromText(text: string): unknown {
  const trimmed = text.trim();
  for (const candidate of jsonObjectCandidates(trimmed)) {
    try {
      return JSON.parse(candidate);
    } catch {
      // Try the next extraction strategy.
    }
  }
  throw new Error("No valid JSON object found in Daytona command output.");
}

function jsonObjectCandidates(trimmed: string): string[] {
  const candidates = [trimmed];
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start >= 0 && end > start) {
    candidates.push(trimmed.slice(start, end + 1));
  }
  return candidates;
}

function buildToolAvailabilityScript(input: {
  artifactDir: string;
  generatedAt: string;
  toolBinDir: string;
  tools: Array<{
    required: boolean;
    skippedReason?: string;
    tool: BaselineToolName;
  }>;
}): string {
  const config = JSON.stringify(input);

  return `
const fs = require("node:fs");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const config = ${config};
fs.mkdirSync(config.toolBinDir, { recursive: true });
fs.mkdirSync(path.join(config.artifactDir, "baseline"), { recursive: true });

const redact = (value) => String(value ?? "")
  .replace(/\\bsk-[A-Za-z0-9_-]{16,}\\b/g, "[REDACTED]")
  .replace(/\\bgh[pousr]_[A-Za-z0-9_]{16,}\\b/g, "[REDACTED]")
  .replace(/\\bAKIA[0-9A-Z]{16}\\b/g, "[REDACTED]")
  .replace(/((?:api[_-]?key|secret|token|password|passwd|pwd)\\s*[:=]\\s*)(["']?)[^"'\\s,}]{6,}\\2/gi, "$1[REDACTED]");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env: options.env === undefined ? process.env : { ...process.env, ...options.env },
    maxBuffer: 20 * 1024 * 1024,
    timeout: options.timeout ?? 600000,
  });
  return {
    command: [command, ...args].join(" "),
    exit_code: result.status ?? (result.error ? 127 : 0),
    stderr: redact(result.stderr || (result.error ? result.error.message : "")),
    stdout: redact(result.stdout || ""),
  };
}

function commandPath(tool) {
  return path.join(config.toolBinDir, tool);
}

function executableExists(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function commandExists(tool) {
  if (executableExists(commandPath(tool))) {
    return commandPath(tool);
  }
  const result = spawnSync("sh", ["-lc", "command -v " + shellQuote(tool)], {
    encoding: "utf8",
    timeout: 30000,
  });
  if (result.status === 0 && result.stdout.trim()) {
    return result.stdout.trim().split(/\\r?\\n/)[0];
  }
  return null;
}

function versionFor(tool, executable) {
  const result = spawnSync(executable, ["--version"], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: 30000,
  });
  if (result.error !== undefined) return undefined;
  return redact((result.stdout || result.stderr || "").split(/\\r?\\n/)[0] || "").slice(0, 200);
}

function readinessCheck(tool, executable) {
  return { attempts: [], diagnostics: [] };
}

function shellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\\\''") + "'";
}

function installWithShellScript(tool, url) {
  return run("sh", ["-lc", "curl -fsSL " + shellQuote(url) + " | sh -s -- -b " + shellQuote(config.toolBinDir)], {
    timeout: 600000,
  });
}

function installGitleaks() {
  const script = String.raw\`
set -eu
tmp="$(mktemp -d)"
json="$tmp/release.json"
curl -fsSL -H 'User-Agent: vibeshield' https://api.github.com/repos/gitleaks/gitleaks/releases/latest -o "$json"
asset_url="$(node - "$json" <<'NODE'
const fs = require('node:fs');
const release = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
const asset = release.assets.find((candidate) => candidate.name.includes('linux_' + arch) && candidate.name.endsWith('.tar.gz'));
if (!asset) process.exit(2);
console.log(asset.browser_download_url);
NODE
)"
curl -fsSL "$asset_url" -o "$tmp/gitleaks.tar.gz"
tar -xzf "$tmp/gitleaks.tar.gz" -C "$tmp"
install -m 0755 "$tmp/gitleaks" "\${config.toolBinDir}/gitleaks"
\`;
  return run("sh", ["-lc", script], { timeout: 600000 });
}

function installActionlint() {
  const script = String.raw\`
set -eu
tmp="$(mktemp -d)"
json="$tmp/release.json"
curl -fsSL -H 'User-Agent: vibeshield' https://api.github.com/repos/rhysd/actionlint/releases/latest -o "$json"
asset_url="$(node - "$json" <<'NODE'
const fs = require('node:fs');
const release = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const arch = process.arch === 'arm64' ? 'arm64' : 'amd64';
const asset = release.assets.find((candidate) => candidate.name.includes('linux_' + arch) && candidate.name.endsWith('.tar.gz'));
if (!asset) process.exit(2);
console.log(asset.browser_download_url);
NODE
)"
curl -fsSL "$asset_url" -o "$tmp/actionlint.tar.gz"
tar -xzf "$tmp/actionlint.tar.gz" -C "$tmp"
binary="$(find "$tmp" -type f -name actionlint -perm -111 | head -n 1)"
test -n "$binary"
install -m 0755 "$binary" "\${config.toolBinDir}/actionlint"
\`;
  return run("sh", ["-lc", script], { timeout: 600000 });
}

function installZizmor() {
  const script = String.raw\`
set -eu
tmp="$(mktemp -d)"
json="$tmp/release.json"
curl -fsSL -H 'User-Agent: vibeshield' https://api.github.com/repos/zizmorcore/zizmor/releases/latest -o "$json"
asset_url="$(node - "$json" <<'NODE'
const fs = require('node:fs');
const release = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const arch = process.arch === 'arm64' ? 'aarch64' : 'x86_64';
const asset = release.assets.find((candidate) => candidate.name === 'zizmor-' + arch + '-unknown-linux-gnu.tar.gz');
if (!asset) process.exit(2);
console.log(asset.browser_download_url);
NODE
)"
curl -fsSL "$asset_url" -o "$tmp/zizmor.tar.gz"
tar -xzf "$tmp/zizmor.tar.gz" -C "$tmp"
binary="$(find "$tmp" -type f -name zizmor -perm -111 | head -n 1)"
test -n "$binary"
install -m 0755 "$binary" "\${config.toolBinDir}/zizmor"
\`;
  return run("sh", ["-lc", script], { timeout: 600000 });
}

function installTrivy() {
  const script = String.raw\`
set -eu
tmp="$(mktemp -d)"
json="$tmp/release.json"
curl -fsSL --retry 3 --retry-delay 2 -H 'User-Agent: vibeshield' https://api.github.com/repos/aquasecurity/trivy/releases/latest -o "$json"
asset_url="$(node - "$json" <<'NODE'
const fs = require('node:fs');
const release = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const arch = process.arch === 'arm64' ? 'ARM64' : '64bit';
const asset = release.assets.find((candidate) => candidate.name.includes('Linux-' + arch) && candidate.name.endsWith('.tar.gz'));
if (!asset) process.exit(2);
console.log(asset.browser_download_url);
NODE
)"
curl -fsSL --retry 3 --retry-delay 2 "$asset_url" -o "$tmp/trivy.tar.gz"
tar -xzf "$tmp/trivy.tar.gz" -C "$tmp"
install -m 0755 "$tmp/trivy" "\${config.toolBinDir}/trivy"
\`;
  return run("sh", ["-lc", script], { timeout: 600000 });
}

function installCheckov() {
  const script = String.raw\`
set -eu
venv="/tmp/vibeshield-tools/checkov-venv"
python3 -m venv "$venv"
"$venv/bin/python" -m pip install --upgrade pip setuptools
"$venv/bin/python" -m pip install checkov
ln -sf "$venv/bin/checkov" "\${config.toolBinDir}/checkov"
\`;
  return run("sh", ["-lc", script], { timeout: 900000 });
}

function provision(tool) {
  switch (tool) {
    case "syft":
      return installWithShellScript(tool, "https://raw.githubusercontent.com/anchore/syft/main/install.sh");
    case "trivy":
      return installTrivy();
    case "gitleaks":
      return installGitleaks();
    case "actionlint":
      return installActionlint();
    case "zizmor":
      return installZizmor();
    case "checkov":
      return installCheckov();
    default:
      return {
        command: "provision " + tool,
        exit_code: 127,
        stderr: "No controlled provisioner is configured for " + tool,
        stdout: "",
      };
  }
}

const availability = {
  generated_at: config.generatedAt,
  kind: "tool-availability",
  tool_bin_dir: config.toolBinDir,
  tools: [],
};

for (const requested of config.tools) {
  if (!requested.required) {
    availability.tools.push({
      attempts: [],
      diagnostics: [],
      required: false,
      ...(requested.skippedReason ? { skipped_reason: requested.skippedReason } : {}),
      status: "not_required",
      tool: requested.tool,
    });
    continue;
  }

  const attempts = [];
  let executable = commandExists(requested.tool);
  if (!executable) {
    const provisionResult = provision(requested.tool);
    attempts.push(...(Array.isArray(provisionResult) ? provisionResult : [provisionResult]));
    executable = commandExists(requested.tool);
  }

  const readiness = executable ? readinessCheck(requested.tool, executable) : { attempts: [], diagnostics: [] };
  attempts.push(...readiness.attempts);

  if (executable && readiness.diagnostics.length === 0) {
    availability.tools.push({
      attempts,
      diagnostics: [],
      path: executable,
      required: true,
      status: "available",
      tool: requested.tool,
      version: versionFor(requested.tool, executable),
    });
  } else {
    availability.tools.push({
      attempts,
      diagnostics:
        readiness.diagnostics.length > 0
          ? readiness.diagnostics
          : ["Required baseline tool could not be provisioned: " + requested.tool],
      required: true,
      status: "failed",
      tool: requested.tool,
    });
  }
}

const artifactPath = path.join(config.artifactDir, "baseline", "tool-availability.json");
fs.writeFileSync(artifactPath, JSON.stringify(availability, null, 2) + "\\n");
process.stdout.write(JSON.stringify({
  artifact: {
    relativePath: "baseline/tool-availability.json",
    sandboxPath: artifactPath,
  },
  availability,
}));
`;
}

function buildBaselineToolScript(input: {
  artifactDir: string;
  generatedAt: string;
  hasGithubActions: boolean;
  hasIacCandidates: boolean;
  repoPath: string;
  sbomSandboxPath?: string;
  toolBinDir: string;
  tool: BaselineToolName;
}): string {
  const config = JSON.stringify(input);

  return `
const fs = require("node:fs");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const config = ${config};
const startedAt = new Date().toISOString();
const toolDir = path.join(config.artifactDir, "baseline", config.tool);
fs.mkdirSync(toolDir, { recursive: true });

const redact = (value) => String(value ?? "")
  .replace(/\\bsk-[A-Za-z0-9_-]{16,}\\b/g, "[REDACTED]")
  .replace(/\\bgh[pousr]_[A-Za-z0-9_]{16,}\\b/g, "[REDACTED]")
  .replace(/\\bAKIA[0-9A-Z]{16}\\b/g, "[REDACTED]")
  .replace(/((?:api[_-]?key|secret|token|password|passwd|pwd)\\s*[:=]\\s*)(["']?)[^"'\\s,}]{6,}\\2/gi, "$1[REDACTED]");

function conditionalSkipReason() {
  if ((config.tool === "actionlint" || config.tool === "zizmor") && !config.hasGithubActions) {
    return "No GitHub Actions workflows were detected in inventory.";
  }
  if (config.tool === "checkov" && !config.hasIacCandidates) {
    return "No IaC/config candidates were detected in inventory.";
  }
  return null;
}

function workflowFileArgs() {
  const workflowDir = path.join(config.repoPath, ".github", "workflows");
  try {
    return fs.readdirSync(workflowDir)
      .filter((entry) => /\\.ya?ml$/i.test(entry))
      .map((entry) => path.join(workflowDir, entry))
      .filter((entryPath) => fs.statSync(entryPath).isFile());
  } catch {
    return [];
  }
}

function toolArgs() {
  switch (config.tool) {
    case "syft":
      return ["dir:" + config.repoPath, "-o", "cyclonedx-json"];
    case "trivy":
      return config.sbomSandboxPath
        ? ["sbom", "--format", "json", config.sbomSandboxPath]
        : ["fs", "--format", "json", config.repoPath];
    case "gitleaks":
      return [
        "detect",
        "--source",
        config.repoPath,
        "--no-git",
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        path.join(toolDir, "gitleaks-report.redacted.json"),
      ];
    case "actionlint":
      return workflowFileArgs();
    case "zizmor":
      return ["--format", "json", path.join(config.repoPath, ".github", "workflows")];
    case "checkov":
      return ["-d", config.repoPath, "-o", "json"];
    default:
      return ["--version"];
  }
}

function commandExists(command) {
  return resolvedCommand(command) !== null;
}

function resolvedCommand(command) {
  const candidate = path.join(config.toolBinDir, command);
  try {
    fs.accessSync(candidate, fs.constants.X_OK);
    return candidate;
  } catch {}

  const result = spawnSync("sh", ["-lc", "PATH=" + shellQuote(config.toolBinDir) + ":$PATH command -v " + shellQuote(command)], {
    encoding: "utf8",
    timeout: 30000,
  });
  if (result.status === 0 && result.stdout.trim()) {
    return result.stdout.trim().split(/\\r?\\n/)[0];
  }
  return null;
}

function shellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\\\''") + "'";
}

function toolVersion(command) {
  const result = spawnSync(command, ["--version"], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: 30000,
  });
  if (result.error !== undefined) return undefined;
  return redact((result.stdout || result.stderr || "").split(/\\r?\\n/)[0] || "").slice(0, 200);
}

function toolEnvironment() {
  const env = {
    ...process.env,
    PATH: config.toolBinDir + ":" + (process.env.PATH || ""),
  };
  return env;
}

function findingExitCode(tool, exitCode) {
  return (
    exitCode === 0 ||
    ((tool === "gitleaks" ||
      tool === "checkov") &&
      exitCode === 1) ||
    (tool === "actionlint" && exitCode === 1) ||
    (tool === "zizmor" && exitCode >= 11 && exitCode <= 14)
  );
}

function observationKind(tool) {
  if (tool === "gitleaks") return "secret";
  if (tool === "actionlint" || tool === "zizmor") return "workflow";
  if (tool === "checkov") return "iac";
  return "dependency";
}

const command = config.tool === "trivy" ? "trivy" : config.tool;
const args = toolArgs();
const executable = resolvedCommand(command);
let status = "completed";
let skippedReason = conditionalSkipReason();
let diagnostics = [];
let exitCode = undefined;
let version = undefined;
let stdout = "";
let stderr = "";

if (skippedReason !== null) {
  status = "skipped";
  diagnostics.push(skippedReason);
} else if (!executable) {
  status = "failed";
  diagnostics.push("Required baseline tool is unavailable after provisioning: " + config.tool);
} else {
  version = toolVersion(executable);
  const result = spawnSync(executable, args, {
    cwd: ".",
    encoding: "utf8",
    env: toolEnvironment(),
    maxBuffer: 20 * 1024 * 1024,
    timeout: 600000,
  });
  exitCode = result.status ?? (result.error ? 127 : 0);
  stdout = redact(result.stdout || "");
  stderr = redact(result.stderr || "");
  if (config.tool === "gitleaks") {
    const reportPath = path.join(toolDir, "gitleaks-report.redacted.json");
    if (fs.existsSync(reportPath)) {
      stdout = redact(fs.readFileSync(reportPath, "utf8"));
    }
  }
  if (!findingExitCode(config.tool, exitCode)) {
    status = "failed";
    diagnostics.push("Tool execution failed with exit code " + exitCode + ".");
    const diagnosticText = (stderr || stdout).trim().split(/\\r?\\n/).slice(0, 8).join("\\n");
    if (diagnosticText) diagnostics.push(diagnosticText);
    if (result.error) diagnostics.push(redact(result.error.message));
  }
}

const stdoutPath = path.join(toolDir, "stdout.redacted.txt");
const stderrPath = path.join(toolDir, "stderr.redacted.log");
const resultPath = path.join(toolDir, "result.redacted.json");
fs.writeFileSync(stdoutPath, stdout);
fs.writeFileSync(stderrPath, stderr || diagnostics.join("\\n"));

const observations = [];

const artifacts = [
  {
    relativePath: "baseline/" + config.tool + "/stdout.redacted.txt",
    sandboxPath: stdoutPath,
  },
  {
    relativePath: "baseline/" + config.tool + "/stderr.redacted.log",
    sandboxPath: stderrPath,
  },
  {
    relativePath: "baseline/" + config.tool + "/result.redacted.json",
    sandboxPath: resultPath,
  },
];

if (config.tool === "syft") {
  if (status === "completed" && stdout.trim() !== "") {
    const sbomPath = path.join(config.artifactDir, "baseline", "syft-sbom.json");
    fs.mkdirSync(path.dirname(sbomPath), { recursive: true });
    fs.writeFileSync(sbomPath, stdout);
    artifacts.unshift({
      relativePath: "baseline/syft-sbom.json",
      sandboxPath: sbomPath,
    });
  }
}

const result = {
  artifacts,
  diagnostics,
  ...(exitCode === undefined ? {} : { exitCode }),
  finishedAt: new Date().toISOString(),
  invocation: {
    args,
    command: executable || command,
    cwd: config.repoPath,
  },
  kind: "baseline-tool",
  observations,
  ...(skippedReason === null ? {} : { skippedReason }),
  startedAt,
  status,
  ...(version === undefined ? {} : { version }),
};

fs.writeFileSync(resultPath, JSON.stringify(result, null, 2) + "\\n");
process.stdout.write(JSON.stringify(result));
`;
}

function buildPiAuthCommand(): string {
  const source = String.raw`
const fs = require("node:fs");
const path = require("node:path");
const apiKey = process.env.OPENROUTER_API_KEY;
if (!apiKey) {
  throw new Error("OPENROUTER_API_KEY was not provided to auth writer.");
}
const dir = "/tmp/vibeshield-pi-agent";
fs.mkdirSync(dir, { mode: 0o700, recursive: true });
fs.writeFileSync(
  path.join(dir, "auth.json"),
  JSON.stringify({ openrouter: { key: apiKey, type: "api_key" } }, null, 2) + "\n",
  { mode: 0o600 },
);
`;

  return `node <<'NODE'\n${source}\nNODE`;
}

function buildPiRunnerCommand(input: {
  artifactSubdir: string;
  artifactDir: string;
  attempt?: number;
  contextPack: unknown;
  inputContextArtifact: string;
  jobName: string;
  model: string;
  outputFile: string;
  outputBaseName: string;
  prompt: string;
  provider: "openrouter";
  repoPath: string;
  step: string;
  tools: string[];
}): string {
  const runnerSource = String.raw`
const fs = require("node:fs");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const config = __VIBESHIELD_PI_CONFIG__;
const startedAt = new Date().toISOString();
const piDir = path.join(config.artifactDir, "pi", config.artifactSubdir);
fs.mkdirSync(piDir, { recursive: true });

const secret = process.env.OPENROUTER_API_KEY || "";
const redact = (value) => {
  let output = String(value || "");
  if (secret) output = output.split(secret).join("[REDACTED]");
  return output
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, "[REDACTED]")
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{16,}\b/g, "[REDACTED]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED]")
    .replace(/((?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*)(["']?)[^"'\s,}]{6,}\2/gi, "$1[REDACTED]");
};

const rawPath = path.join(piDir, config.outputBaseName + ".raw.redacted.txt");
const stderrPath = path.join(piDir, "stderr.redacted.log");
const progressPath = path.join(piDir, "progress.jsonl");
const metadataPath = path.join(piDir, "metadata.json");
const agentOutputPath = path.resolve(config.repoPath, config.outputFile);
fs.mkdirSync(path.dirname(agentOutputPath), { recursive: true });

const progressEvents = [];
const progressPrefix = "__VIBESHIELD_PROGRESS__";
const emitProgress = (type, message, details = undefined) => {
  const event = { details, job: config.jobName, message, timestamp: new Date().toISOString(), type };
  progressEvents.push(event);
  process.stdout.write(progressPrefix + JSON.stringify(event) + "\n");
};

function commandExists(command) {
  const result = spawnSync(command, ["--version"], { encoding: "utf8", timeout: 30000 });
  return result.error === undefined && result.status === 0;
}

function textFromAssistantMessage(message) {
  if (!message || message.role !== "assistant" || !Array.isArray(message.content)) {
    return "";
  }
  return message.content
    .filter((part) => part && part.type === "text" && typeof part.text === "string")
    .map((part) => part.text)
    .join("");
}

function actorLabel() {
  const stage = String(config.step || "pi");
  const role = "collector";
  const attempt = typeof config.attempt === "number" ? " attempt " + config.attempt : "";
  return stage + " " + role + attempt;
}

function piStepStartMessage(step) {
  switch (step) {
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

function piStepDoneMessage(step) {
  switch (step) {
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

function piStepFailedMessage(step) {
  switch (step) {
    case "coverage-structure":
      return "Coverage and structure mapping failed.";
    case "stack-build-deps":
      return "Stack, build, and dependency collection failed.";
    case "entrypoints":
      return "Entrypoint collection failed.";
    case "auth-access":
      return "Auth and access-control mapping failed.";
    case "config-secrets":
      return "Configuration and secret-reference mapping failed.";
    case "storage-data-model":
      return "Storage and data-model collection failed.";
    case "external-integrations-egress":
      return "External integration and egress collection failed.";
    case "infra-deploy":
      return "Infrastructure and deployment collection failed.";
    case "operation-sinks":
      return "Operation sink collection failed.";
    case "crypto":
      return "Crypto and randomness collection failed.";
    case "logging-observability":
      return "Logging and observability collection failed.";
    case "data-flows":
      return "Bounded data-flow tracing failed.";
    case "trust-boundaries":
      return "Trust-boundary synthesis failed.";
    case "repository-map":
      return "Final repository map assembly failed.";
    default:
      return "Repository-map collection failed.";
  }
}

function compactValue(value, maxLength = 96) {
  if (value === undefined || value === null) {
    return "";
  }
  const text = redact(String(value)).replace(/\s+/g, " ").trim();
  if (text.length <= maxLength) {
    return text;
  }
  return text.slice(0, maxLength - 3) + "...";
}

function readToolArguments(toolCall) {
  if (!toolCall || typeof toolCall !== "object") {
    return {};
  }
  const rawArgs = toolCall.arguments ?? toolCall.partialArgs;
  if (rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs)) {
    return rawArgs;
  }
  if (typeof rawArgs === "string" && rawArgs.trim()) {
    try {
      const parsed = JSON.parse(rawArgs);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      return {};
    }
  }
  return {};
}

function toolCallFromAssistantEvent(assistantEvent) {
  if (!assistantEvent || typeof assistantEvent !== "object") {
    return undefined;
  }
  if (assistantEvent.toolCall) {
    return assistantEvent.toolCall;
  }
  return assistantEvent.partial?.content?.[assistantEvent.contentIndex];
}

function summarizeToolCall(toolCall) {
  const tool = compactValue(toolCall?.name || "tool", 40) || "tool";
  const args = readToolArguments(toolCall);
  const pathValue = compactValue(
    args.path ?? args.file ?? args.cwd ?? args.directory ?? args.paths ?? args.files,
    96,
  );
  const patternValue = compactValue(
    args.pattern ?? args.query ?? args.regex ?? args.glob ?? args.include,
    96,
  );

  if (tool === "read" && pathValue) {
    return { target: pathValue, text: "read " + pathValue, tool };
  }
  if (tool === "grep") {
    const pattern = patternValue ? '"' + patternValue.replace(/"/g, '\\"') + '"' : "pattern";
    const target = pathValue ? " in " + pathValue : "";
    return { target: (patternValue + " " + pathValue).trim(), text: "grep " + pattern + target, tool };
  }
  if (tool === "find") {
    const target = patternValue || pathValue;
    return { target, text: target ? "find " + target : "find", tool };
  }
  if (tool === "ls") {
    return { target: pathValue, text: pathValue ? "ls " + pathValue : "ls", tool };
  }

  return { target: pathValue || patternValue, text: "called " + tool, tool };
}

function eventMessageForPiEvent(event) {
  if (!event || typeof event !== "object") {
    return undefined;
  }

  if (event.type === "turn_start") {
    return { message: actorLabel() + ": thinking...", type: "pi.thinking" };
  }

  const assistantEvent = event.assistantMessageEvent;
  if (!assistantEvent || typeof assistantEvent !== "object") {
    return undefined;
  }

  if (assistantEvent.type === "toolcall_end") {
    const summary = summarizeToolCall(toolCallFromAssistantEvent(assistantEvent));
    return {
      details: { target: summary.target, tool: summary.tool },
      message: actorLabel() + ": " + summary.text + ".",
      type: "pi.tool.called",
    };
  }
  if (assistantEvent.type === "text_start") {
    return { message: actorLabel() + ": writing structured output.", type: "pi.output.started" };
  }

  return undefined;
}

function runPiJsonStream(command, args) {
  return new Promise((resolve) => {
    let stdoutBuffer = "";
    let stderr = "";
    let finalText = "";
    let emittedOutputStarted = false;
    let toolCallCount = 0;
    let childError;
    let timedOut = false;

    const child = spawn(command, args, {
      cwd: config.repoPath,
      env: {
        ...process.env,
        PI_CODING_AGENT_DIR: "/tmp/vibeshield-pi-agent",
        PI_CODING_AGENT_SESSION_DIR: "/tmp/vibeshield-pi-sessions",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    const timeout = setTimeout(() => {
      timedOut = true;
      emitProgress("pi.timeout", "Pi " + config.step + " exceeded runtime timeout.", { step: config.step });
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 5000).unref();
    }, 900000);
    timeout.unref();

    const heartbeat = setInterval(() => {
      emitProgress("pi.heartbeat", actorLabel() + ": agent still running.", {
        step: config.step,
        tool_calls: toolCallCount,
      });
    }, 30000);
    heartbeat.unref();

    const processLine = (line) => {
      if (!line.trim()) {
        return;
      }
      let event;
      try {
        event = JSON.parse(line);
      } catch {
        return;
      }

      const text = textFromAssistantMessage(event.message);
      if (text) {
        finalText = text;
      }
      if (event.type === "agent_end" && Array.isArray(event.messages)) {
        const assistantMessages = event.messages.filter((message) => message && message.role === "assistant");
        const lastText = textFromAssistantMessage(assistantMessages[assistantMessages.length - 1]);
        if (lastText) {
          finalText = lastText;
        }
      }

      const progress = eventMessageForPiEvent(event);
      if (progress === undefined) {
        return;
      }

      if (progress.type === "pi.output.started") {
        if (emittedOutputStarted) {
          return;
        }
        emittedOutputStarted = true;
      }
      if (progress.type === "pi.tool.called") {
        toolCallCount += 1;
      }

      emitProgress(progress.type, progress.message, {
        ...(progress.details || {}),
        step: config.step,
      });
    };

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdoutBuffer += chunk;
      const lines = stdoutBuffer.split(/\r?\n/);
      stdoutBuffer = lines.pop() || "";
      for (const line of lines) {
        processLine(line);
      }
    });

    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr += redact(chunk);
    });

    child.on("error", (error) => {
      childError = error;
    });

    child.on("close", (code, signal) => {
      clearTimeout(timeout);
      clearInterval(heartbeat);
      if (stdoutBuffer.trim()) {
        processLine(stdoutBuffer);
      }
      resolve({
        error: childError,
        finalText,
        signal,
        status: timedOut ? 124 : code,
        stderr,
      });
    });
  });
}

const toolArgs = Array.isArray(config.tools) && config.tools.length > 0
  ? ["--tools", config.tools.join(",")]
  : [];

const piArgs = [
  "-p",
  "--no-session",
  "--no-context-files",
  "--no-extensions",
  "--no-skills",
  "--no-prompt-templates",
  "--no-themes",
  ...toolArgs,
  "--provider",
  config.provider,
  "--model",
  config.model,
  "--thinking",
  "low",
  "--mode",
  "json",
  config.prompt,
];

emitProgress("runner.started", piStepStartMessage(config.step), { step: config.step });
const usePnpm = commandExists("pnpm");
const command = usePnpm ? "pnpm" : "npm";
const args = usePnpm
  ? ["--config.ignore-scripts=true", "dlx", "@earendil-works/pi-coding-agent", ...piArgs]
  : [
      "exec",
      "--ignore-scripts",
      "--yes",
      "--package",
      "@earendil-works/pi-coding-agent",
      "--",
      "pi",
      ...piArgs,
    ];

const versionArgs = usePnpm
  ? ["--config.ignore-scripts=true", "dlx", "@earendil-works/pi-coding-agent", "--version"]
  : ["exec", "--ignore-scripts", "--yes", "--package", "@earendil-works/pi-coding-agent", "--", "pi", "--version"];

const versionResult = spawnSync(command, versionArgs, {
  cwd: config.repoPath,
  encoding: "utf8",
  maxBuffer: 1024 * 1024,
  timeout: 120000,
});
const version = redact((versionResult.stdout || versionResult.stderr || "").trim().split(/\r?\n/)[0] || "");

runPiJsonStream(command, args)
  .then((result) => {
    let outputText = "";
    let outputReadError = "";
    try {
      outputText = fs.readFileSync(agentOutputPath, "utf8");
    } catch (error) {
      outputReadError = error && error.message ? error.message : String(error);
    }
    const output = redact(outputText);
    const stderr = redact(result.stderr || (result.error ? result.error.message : ""));
    fs.writeFileSync(rawPath, output);
    fs.writeFileSync(stderrPath, stderr);
    const completed = result.status === 0 && outputReadError === "";
    emitProgress(completed ? "pi.completed" : "pi.failed", completed ? piStepDoneMessage(config.step) : piStepFailedMessage(config.step), { signal: result.signal, step: config.step });
    fs.writeFileSync(progressPath, progressEvents.map((event) => JSON.stringify(event)).join("\n") + "\n");

    const metadata = {
      input_context_artifact: config.inputContextArtifact,
      invocation: {
        args: ["-p", "--no-session", "--no-context-files", "--no-extensions", "--no-skills", "--no-prompt-templates", "--no-themes", ...toolArgs, "--provider", config.provider, "--model", config.model, "--thinking", "low", "--mode", "json", "<prompt>"],
        command,
        cwd: config.repoPath,
        metadata: { output_file: config.outputFile, tools: config.tools },
        provider: config.provider,
      },
      model: config.model,
      output_bytes: Buffer.byteLength(output, "utf8"),
      output_file: config.outputFile,
      output_read_error: outputReadError,
      pi_exit_code: result.status,
      prompt_bytes: Buffer.byteLength(config.prompt, "utf8"),
      provider: config.provider,
      runner_package: "@earendil-works/pi-coding-agent",
      stderr_bytes: Buffer.byteLength(stderr, "utf8"),
      step: config.step,
      version,
    };
    fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2) + "\n");

    const runtimeResult = {
      artifacts: [
        { relativePath: "pi/" + config.artifactSubdir + "/" + config.outputBaseName + ".raw.redacted.txt", sandboxPath: rawPath },
        { relativePath: "pi/" + config.artifactSubdir + "/stderr.redacted.log", sandboxPath: stderrPath },
        { relativePath: "pi/" + config.artifactSubdir + "/progress.jsonl", sandboxPath: progressPath },
        { relativePath: "pi/" + config.artifactSubdir + "/metadata.json", sandboxPath: metadataPath },
      ],
      diagnostics: completed
        ? []
        : [
            ...(result.status === 0 ? [] : ["Pi exited with code " + result.status + "."]),
            ...(outputReadError === "" ? [] : ["Pi did not write output file " + config.outputFile + ": " + redact(outputReadError)]),
          ],
      exitCode: completed ? result.status : result.status === 0 ? 1 : result.status,
      finishedAt: new Date().toISOString(),
      invocation: metadata.invocation,
      kind: "pi-repository-mapping",
      metadata,
      observations: [],
      startedAt,
      status: completed ? "completed" : "failed",
      ...(version ? { version } : {}),
    };

    if (!completed) {
      process.exitCode = result.status === 0 ? 1 : result.status ?? 1;
    }

    process.stdout.write(JSON.stringify(runtimeResult));
  })
  .catch((error) => {
    const stderr = redact(error && error.message ? error.message : String(error));
    fs.writeFileSync(rawPath, "");
    fs.writeFileSync(stderrPath, stderr);
    emitProgress("pi.failed", "Pi " + config.step + " runner failed.", { step: config.step });
    fs.writeFileSync(progressPath, progressEvents.map((event) => JSON.stringify(event)).join("\n") + "\n");
    process.exitCode = 1;
  });
`;

  const rendered = runnerSource.replace(
    "__VIBESHIELD_PI_CONFIG__",
    JSON.stringify({
      artifactSubdir: input.artifactSubdir,
      artifactDir: input.artifactDir,
      attempt: input.attempt,
      contextPack: input.contextPack,
      inputContextArtifact: input.inputContextArtifact,
      jobName: input.jobName,
      model: input.model,
      outputFile: input.outputFile,
      outputBaseName: input.outputBaseName,
      prompt: input.prompt,
      provider: input.provider,
      repoPath: input.repoPath,
      step: input.step,
      tools: input.tools,
    }),
  );

  return `node <<'NODE'\n${rendered}\nNODE`;
}

function piRuntimeArtifacts(input: {
  artifactDir: string;
  artifactSubdir: string;
  outputBaseName: string;
}): SandboxArtifact[] {
  return [
    {
      relativePath: `pi/${input.artifactSubdir}/${input.outputBaseName}.raw.redacted.txt`,
      sandboxPath: `${input.artifactDir}/pi/${input.artifactSubdir}/${input.outputBaseName}.raw.redacted.txt`,
    },
    {
      relativePath: `pi/${input.artifactSubdir}/stderr.redacted.log`,
      sandboxPath: `${input.artifactDir}/pi/${input.artifactSubdir}/stderr.redacted.log`,
    },
    {
      relativePath: `pi/${input.artifactSubdir}/progress.jsonl`,
      sandboxPath: `${input.artifactDir}/pi/${input.artifactSubdir}/progress.jsonl`,
    },
    {
      relativePath: `pi/${input.artifactSubdir}/metadata.json`,
      sandboxPath: `${input.artifactDir}/pi/${input.artifactSubdir}/metadata.json`,
    },
  ];
}

function readSessionProcessApi(
  processApi: DaytonaSandboxLike["process"],
): DaytonaSessionProcessApi | null {
  if (
    processApi.createSession === undefined ||
    processApi.executeSessionCommand === undefined ||
    processApi.getSessionCommand === undefined ||
    processApi.getSessionCommandLogs === undefined ||
    processApi.deleteSession === undefined
  ) {
    return null;
  }

  return {
    createSession: processApi.createSession.bind(processApi),
    deleteSession: processApi.deleteSession.bind(processApi),
    executeSessionCommand: processApi.executeSessionCommand.bind(processApi),
    getSessionCommand: processApi.getSessionCommand.bind(processApi),
    getSessionCommandLogs: processApi.getSessionCommandLogs.bind(processApi),
  };
}

const piProgressPrefix = "__VIBESHIELD_PROGRESS__";

function createPiProgressParser(onProgress: (event: RuntimeJobProgressEvent) => void): {
  consume(chunk: string): void;
  flush(): void;
} {
  let buffer = "";
  const seen = new Set<string>();

  const processLine = (line: string) => {
    const markerIndex = line.indexOf(piProgressPrefix);
    if (markerIndex < 0) {
      return;
    }

    const payload = line.slice(markerIndex + piProgressPrefix.length).trim();
    if (payload === "" || seen.has(payload)) {
      return;
    }
    seen.add(payload);

    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch {
      return;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return;
    }

    const event = parsed as Record<string, unknown>;
    if (typeof event.message !== "string" || typeof event.type !== "string") {
      return;
    }
    const details =
      event.details !== null && typeof event.details === "object" && !Array.isArray(event.details)
        ? (event.details as Record<string, unknown>)
        : undefined;

    onProgress({
      ...(details === undefined ? {} : { details }),
      job: typeof event.job === "string" && event.job.trim() !== "" ? event.job : "pi",
      message: event.message,
      type: event.type,
    });
  };

  return {
    consume(chunk: string) {
      buffer += chunk;
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        processLine(line);
      }
    },
    flush() {
      if (buffer !== "") {
        processLine(buffer);
        buffer = "";
      }
    },
  };
}

async function waitForSessionCommandExit(input: {
  commandId: string;
  getCommand: (commandId: string) => Promise<unknown>;
  logsSettled: () => boolean;
  pollLogs?: () => Promise<void>;
  timeoutMs: number;
}): Promise<number> {
  const startedAt = Date.now();
  let lastHeartbeatAt = Date.now();
  let lastPollError: unknown;

  while (Date.now() - startedAt < input.timeoutMs) {
    let command: unknown;
    try {
      command = await input.getCommand(input.commandId);
      lastPollError = undefined;
    } catch (error) {
      lastPollError = error;
      await sleep(5_000);
      continue;
    }

    await input.pollLogs?.().catch(() => undefined);

    const exitCode = readOptionalSessionExitCode(command);
    if (exitCode !== undefined) {
      await input.pollLogs?.().catch(() => undefined);
      return exitCode;
    }

    const now = Date.now();
    if (now - lastHeartbeatAt > 30_000) {
      lastHeartbeatAt = now;
      if (input.logsSettled()) {
        await sleep(1);
      }
    }

    await sleep(5_000);
  }

  throw new ScanStageError({
    message:
      lastPollError === undefined
        ? "Timed out waiting for Pi session command to finish."
        : `Timed out waiting for Pi session command to finish after polling error: ${errorMessage(
            lastPollError,
          )}`,
    stage: "pi",
    userMessage: "Timed out while waiting for Pi repository mapping inside Daytona.",
  });
}

function readOptionalSessionExitCode(command: unknown): number | undefined {
  if (command === null || typeof command !== "object") {
    return undefined;
  }

  const candidates = command as {
    code?: unknown;
    exit_code?: unknown;
    exitCode?: unknown;
  };

  for (const value of [candidates.exitCode, candidates.exit_code, candidates.code]) {
    if (typeof value === "number") {
      return value;
    }
  }

  return undefined;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export function readDaytonaConfigFromEnv(): DaytonaConfig {
  const config: DaytonaConfig = {};
  const apiKey = readNonEmptyEnv("DAYTONA_API_KEY");
  const apiUrl = readNonEmptyEnv("DAYTONA_API_URL");
  const target = readNonEmptyEnv("DAYTONA_TARGET");

  if (apiKey !== undefined) {
    config.apiKey = apiKey;
  }
  if (apiUrl !== undefined) {
    config.apiUrl = apiUrl;
  }
  if (target !== undefined) {
    config.target = target;
  }
  return config;
}

export function missingDaytonaEnvVars(): string[] {
  return ["DAYTONA_API_KEY"].filter((name) => readNonEmptyEnv(name) === undefined);
}

function readNonEmptyEnv(name: string): string | undefined {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") {
    return undefined;
  }
  return value;
}
