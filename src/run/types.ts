import type { GitHubRepoReference } from "./github-url.js";

export type RunStatus = "failed" | "running" | "success";

export type RunStage =
  | "cleanup"
  | "clone"
  | "completed"
  | "create_run"
  | "create_sandbox"
  | "inventory";

export interface RunError {
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
    events: string;
    inventory?: string;
    outputs_dir: string;
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
}

export interface RunEvent {
  artifact?: string;
  message: string;
  sandbox_id?: string;
  stage: RunStage;
  timestamp: string;
  type: string;
}
