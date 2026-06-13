import type { GitHubRepoReference } from "./github-url.js";

export type RunStatus = "failed" | "running" | "success";

export type RunStage =
  | "auth-config-secrets-validation"
  | "cleanup"
  | "clone"
  | "completed"
  | "context"
  | "coverage-structure-validation"
  | "create_run"
  | "create_sandbox"
  | "data-flows-validation"
  | "deterministic-baseline"
  | "entrypoints-validation"
  | "inventory"
  | "operation-sinks-validation"
  | "pi"
  | "report"
  | "repository-map-validation"
  | "resume"
  | "stack-build-deps-validation"
  | "storage-integrations-infra-validation"
  | "trust-boundaries-validation";

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
    repo_map?: {
      auth_config_secrets?: string;
      coverage_structure?: string;
      data_flows?: string;
      entrypoints?: string;
      operation_sinks?: string;
      stack_build_deps?: string;
      storage_integrations_infra?: string;
      trust_boundaries?: string;
    };
    events: string;
    inventory?: string;
    inventory_legacy?: string;
    outputs_dir: string;
    pi_context_pack?: string;
    report?: string;
    repository_map?: string;
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
  details?: Record<string, unknown>;
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
