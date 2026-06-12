import type { GitHubRepoReference } from "./github-url.js";

export type RunStatus = "failed" | "running" | "success";

export type RunStage =
  | "cleanup"
  | "clone"
  | "completed"
  | "context"
  | "create_run"
  | "create_sandbox"
  | "deterministic-baseline"
  | "inventory"
  | "pi"
  | "project-understanding-validation"
  | "report";

export interface RunError {
  diagnostics?: string[];
  message: string;
  stage: RunStage;
  user_message: string;
}

export interface SandboxCleanupState {
  attempted: boolean;
  deleted: boolean;
  error?: string;
  success: boolean;
}

export interface ScanRunState {
  artifacts: {
    baseline_summary?: string;
    baseline_tool_availability?: string;
    events: string;
    inventory?: string;
    inventory_legacy?: string;
    outputs_dir: string;
    pi_context_pack?: string;
    pi_progress?: string;
    pi_raw_output?: string;
    pi_stderr?: string;
    project_understanding?: string;
    report?: string;
  };
  commit_sha?: string;
  created_at: string;
  current_stage: RunStage;
  error?: RunError;
  finished_at?: string;
  run_id: string;
  sandbox?: {
    cleanup: SandboxCleanupState;
    id: string;
    provider: string;
  };
  source: GitHubRepoReference;
  status: RunStatus;
  steps?: RunStepState[];
}

export interface RunEvent {
  artifact?: string;
  diagnostics?: string[];
  job?: string;
  message: string;
  sandbox_id?: string;
  stage: RunStage;
  timestamp: string;
  type: string;
}

export type RunStepStatus = "failed" | "running" | "skipped" | "success";

export interface RunJobState {
  artifacts: string[];
  diagnostics: string[];
  finished_at?: string;
  invocation?: {
    args?: string[];
    command: string;
    cwd?: string;
    metadata?: Record<string, unknown>;
    provider?: string;
  };
  name: string;
  observations: number;
  skipped_reason?: string;
  started_at: string;
  status: RunStepStatus;
  version?: string;
}

export interface RunStepState {
  diagnostics: string[];
  finished_at?: string;
  jobs: RunJobState[];
  name: string;
  stage: RunStage;
  started_at: string;
  status: RunStepStatus;
}
