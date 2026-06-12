import type {
  BaselineObservation,
  BaselineToolName,
  ToolAvailabilityArtifact,
} from "../artifacts/contracts.js";
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

export interface PullFileContext {
  artifact?: string;
  job?: string;
  stage: RunStage;
}

export interface PrepareBaselineToolsInput {
  generatedAt: string;
  tools: Array<{
    required: boolean;
    skippedReason?: string;
    tool: BaselineToolName;
  }>;
}

export interface PrepareBaselineToolsResult {
  artifact: SandboxArtifact;
  availability: ToolAvailabilityArtifact;
}

export type RuntimeJobKind = "baseline-tool" | "pi-project-understanding";

export type RuntimeJobStatus = "completed" | "failed" | "skipped";

export interface RuntimeInvocation {
  args?: string[];
  command: string;
  cwd?: string;
  metadata?: Record<string, unknown>;
  provider?: string;
}

export interface RuntimeJobInput {
  baseline?: {
    hasGithubActions: boolean;
    hasIacCandidates: boolean;
    sbomSandboxPath?: string;
    tool: BaselineToolName;
  };
  generatedAt: string;
  kind: RuntimeJobKind;
  name: string;
  pi?: {
    contextPack: unknown;
    inputContextArtifact: string;
    model: string;
    prompt: string;
    provider: "openrouter";
  };
  stage: RunStage;
}

export interface RuntimeJobResult {
  artifacts: SandboxArtifact[];
  diagnostics: string[];
  exitCode?: number;
  finishedAt: string;
  invocation: RuntimeInvocation;
  kind: RuntimeJobKind;
  metadata?: Record<string, unknown>;
  observations: BaselineObservation[];
  skippedReason?: string;
  startedAt: string;
  status: RuntimeJobStatus;
  version?: string;
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
  prepareBaselineTools(input: PrepareBaselineToolsInput): Promise<PrepareBaselineToolsResult>;
  pullFile(sandboxPath: string, localPath: string, context?: PullFileContext): Promise<void>;
  runJob(input: RuntimeJobInput): Promise<RuntimeJobResult>;
}

export interface SandboxProvider {
  createSandbox(context: SandboxCreateContext): Promise<SandboxSession>;
}
