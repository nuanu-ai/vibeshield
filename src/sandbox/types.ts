import type { GitHubRepoReference } from "../run/github-url.js";
import type { RunStage, SandboxCleanupState } from "../run/types.js";

export interface SandboxCreateContext {
  repo: GitHubRepoReference;
  runId: string;
}

export interface CloneRepositoryResult {
  commitSha: string | null;
  repoPath: string;
}

export interface GenerateInventoryInput {
  commitSha: string | null;
  generatedAt: string;
  repo: GitHubRepoReference;
}

export interface SandboxArtifact {
  relativePath: string;
  sandboxPath: string;
}

export interface SandboxCommandLogEntry {
  command: string;
  cwd: string;
  repoDefinedCommand: boolean;
  stage: RunStage | "commit";
}

export interface SandboxSession {
  readonly id: string;
  readonly providerName: string;
  cloneRepository(repo: GitHubRepoReference): Promise<CloneRepositoryResult>;
  delete(): Promise<SandboxCleanupState>;
  generateInventory(input: GenerateInventoryInput): Promise<SandboxArtifact>;
  pullFile(sandboxPath: string, localPath: string): Promise<void>;
}

export interface SandboxProvider {
  createSandbox(context: SandboxCreateContext): Promise<SandboxSession>;
}
