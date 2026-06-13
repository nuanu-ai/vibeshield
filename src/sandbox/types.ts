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

export interface CloneRepositoryOptions {
  commitSha?: string;
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

export type RuntimeJobKind = "baseline-tool" | "pi-repository-mapping";

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
    artifactSubdir: string;
    attempt?: number;
    contextPack: unknown;
    inputContextArtifact: string;
    model: string;
    outputBaseName: string;
    prompt: string;
    provider: "openrouter";
    step: string;
    tools: string[];
  };
  onProgress?: (event: RuntimeJobProgressEvent) => unknown | Promise<unknown>;
  stage: RunStage;
}

export interface RuntimeJobProgressEvent {
  details?: Record<string, unknown>;
  job: string;
  message: string;
  type: string;
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
  cloneRepository(
    repo: GitHubRepoReference,
    options?: CloneRepositoryOptions,
  ): Promise<CloneRepositoryResult>;
  delete(): Promise<SandboxCleanupState>;
  generateInventory(input: GenerateInventoryInput): Promise<SandboxArtifact>;
  prepareBaselineTools(input: PrepareBaselineToolsInput): Promise<PrepareBaselineToolsResult>;
  pullFile(sandboxPath: string, localPath: string, context?: PullFileContext): Promise<void>;
  runJob(input: RuntimeJobInput): Promise<RuntimeJobResult>;
}

export interface SandboxProvider {
  createSandbox(context: SandboxCreateContext): Promise<SandboxSession>;
  deleteSandboxById?(sandboxId: string): Promise<SandboxCleanupState>;
}
