import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { copyFile, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { buildRepoInventory } from "../inventory/repo-inventory.js";
import { ScanStageError } from "../run/errors.js";
import type { SandboxCleanupState } from "../run/types.js";
import type {
  CloneRepositoryResult,
  GenerateInventoryInput,
  SandboxArtifact,
  SandboxCommandLogEntry,
  SandboxCreateContext,
  SandboxProvider,
  SandboxSession,
} from "./types.js";

const execFileAsync = promisify(execFile);

export interface FakeDaytonaSandboxProviderOptions {
  failAt?: "clone" | "inventory";
  fixtureRepos: Map<string, string>;
  sandboxRoot: string;
}

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
      repoUrl: context.repo.url,
      sandboxDir,
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
      relativePath: "repo-inventory.json",
      sandboxPath: artifactPath,
    };
  }

  async pullFile(sandboxPath: string, localPath: string): Promise<void> {
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
  failAt?: "clone" | "inventory";
  fixtureRepos: Map<string, string>;
  id: string;
  removeLiveSandboxId: () => void;
  repoUrl: string;
  sandboxDir: string;
}
