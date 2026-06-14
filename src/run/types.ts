import type { GitHubRepoReference } from "./github-url.js";

export type RunStatus = "failed" | "running" | "success";

export type RunStage =
  | "attack-hypotheses-validation"
  | "auth-access-validation"
  | "config-secrets-validation"
  | "cleanup"
  | "clone"
  | "completed"
  | "context"
  | "coverage-structure-validation"
  | "create_run"
  | "create_sandbox"
  | "crypto-validation"
  | "data-flows-validation"
  | "deterministic-baseline"
  | "entrypoints-validation"
  | "external-integrations-egress-validation"
  | "final-report"
  | "infra-deploy-validation"
  | "inventory"
  | "logging-observability-validation"
  | "operation-sinks-validation"
  | "pi"
  | "repository-map-validation"
  | "resume"
  | "stack-build-deps-validation"
  | "storage-data-model-validation"
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
    attack_hypotheses?: string;
    repo_map?: {
      auth_access?: string;
      config_secrets?: string;
      coverage_structure?: string;
      crypto?: string;
      data_flows?: string;
      entrypoints?: string;
      external_integrations_egress?: string;
      infra_deploy?: string;
      logging_observability?: string;
      operation_sinks?: string;
      stack_build_deps?: string;
      storage_data_model?: string;
      trust_boundaries?: string;
    };
    events: string;
    diagnostics?: string[];
    final_report_markdown?: string;
    final_report_pdf?: string;
    inventory?: string;
    outputs_dir: string;
    pi_context_pack?: string;
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
