import { mkdir } from "node:fs/promises";
import path from "node:path";
import type { CreateSandboxFromSnapshotParams, DaytonaConfig } from "@daytona/sdk";
import { CodeLanguage, Daytona } from "@daytona/sdk";
import { errorMessage, ScanStageError } from "../run/errors.js";
import type { SandboxCleanupState } from "../run/types.js";
import { buildDaytonaInventoryScript } from "./daytona-inventory-script.js";
import type {
  CloneRepositoryResult,
  GenerateInventoryInput,
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
    executeCommand(
      command: string,
      cwd?: string,
      env?: Record<string, string>,
      timeout?: number,
    ): Promise<DaytonaExecuteResponse>;
  };
  delete(timeout?: number): Promise<void>;
}

export interface DaytonaClientLike {
  create(
    params?: CreateSandboxFromSnapshotParams,
    options?: { timeout?: number },
  ): Promise<DaytonaSandboxLike>;
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
const defaultArtifactPath = "vibeshield/artifacts/repo-inventory.json";

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
            phase: "0",
            run_id: context.runId,
            source: "github",
            source_owner: context.repo.owner,
            source_repo: context.repo.repo,
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
      sandboxArtifactPath: defaultArtifactPath,
    });
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
          "Set DAYTONA_API_KEY, DAYTONA_API_URL, and DAYTONA_TARGET for live scans.",
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
      sandboxArtifactPath: string;
    },
  ) {}

  get id(): string {
    return this.sandbox.id;
  }

  async cloneRepository(repo: { url: string }): Promise<CloneRepositoryResult> {
    await this.sandbox.git.clone(repo.url, this.options.repoPath).catch((error: unknown) => {
      throw new ScanStageError({
        cause: error,
        message: errorMessage(error),
        stage: "clone",
        userMessage: `Could not clone repository inside Daytona sandbox: ${errorMessage(error)}`,
      });
    });

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
      relativePath: "repo-inventory.json",
      sandboxPath: this.options.sandboxArtifactPath,
    };
  }

  async pullFile(sandboxPath: string, localPath: string): Promise<void> {
    await mkdir(path.dirname(localPath), { recursive: true });
    await this.sandbox.fs
      .downloadFile(sandboxPath, localPath, this.options.downloadTimeoutSeconds)
      .catch((error: unknown) => {
        throw new ScanStageError({
          cause: error,
          message: errorMessage(error),
          stage: "inventory",
          userMessage: `Could not pull inventory artifact from Daytona sandbox: ${errorMessage(error)}`,
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
  stage: "clone" | "inventory",
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

function readDaytonaConfigFromEnv(): DaytonaConfig {
  const config: DaytonaConfig = {};
  if (process.env.DAYTONA_API_KEY !== undefined) {
    config.apiKey = process.env.DAYTONA_API_KEY;
  }
  if (process.env.DAYTONA_API_URL !== undefined) {
    config.apiUrl = process.env.DAYTONA_API_URL;
  }
  if (process.env.DAYTONA_TARGET !== undefined) {
    config.target = process.env.DAYTONA_TARGET;
  }
  return config;
}

function missingDaytonaEnvVars(): string[] {
  return ["DAYTONA_API_KEY", "DAYTONA_API_URL", "DAYTONA_TARGET"].filter(
    (name) => process.env[name] === undefined || process.env[name] === "",
  );
}
