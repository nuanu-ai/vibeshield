import type { GitHubRepoReference } from "../run/github-url.js";

export type ArtifactKind =
  | "auth-access"
  | "baseline-summary"
  | "config-secrets"
  | "coverage-structure"
  | "crypto"
  | "data-flows"
  | "entrypoints"
  | "external-integrations-egress"
  | "infra-deploy"
  | "inventory"
  | "logging-observability"
  | "operation-sinks"
  | "pi-context-pack"
  | "repository-map"
  | "stack-build-deps"
  | "storage-data-model"
  | "tool-availability"
  | "trust-boundaries";

export interface EvidenceRef {
  path: string;
  start_line?: number;
  end_line?: number;
}

export interface InventoryFileContract {
  line_count?: number;
  path: string;
  sha256?: string;
  size_bytes: number;
  type: "file" | "other" | "symlink";
}

export interface InventoryArtifact {
  directories: Array<{ path: string }>;
  files: InventoryFileContract[];
  generated_at: string;
  generated_by: string;
  kind: "inventory";
  sandbox: {
    id: string;
    inventory_location: "inside_sandbox";
  };
  source: GitHubRepoReference & {
    commit_sha: string | null;
  };
  summary: {
    directory_count: number;
    file_count: number;
    manifest_files: string[];
    total_file_bytes: number;
  };
}

export type BaselineToolName = "actionlint" | "checkov" | "gitleaks" | "syft" | "trivy" | "zizmor";

export type BaselineToolStatus = "completed" | "failed" | "skipped";

export interface BaselineObservation {
  confidence: "high" | "low" | "medium";
  evidence: string[];
  kind: "dependency" | "iac" | "secret" | "supply-chain" | "workflow";
  message: string;
  severity: "critical" | "high" | "info" | "low" | "medium" | "unknown";
}

export interface BaselineToolSummary {
  artifacts: string[];
  diagnostics: string[];
  exit_code?: number;
  invocation: {
    args?: string[];
    command: string;
    cwd?: string;
    metadata?: Record<string, unknown>;
    provider?: string;
  };
  observations: BaselineObservation[];
  skipped_reason?: string;
  status: BaselineToolStatus;
  tool: BaselineToolName;
  version?: string;
}

export interface BaselineSummaryArtifact {
  generated_at: string;
  kind: "baseline-summary";
  source: {
    commit_sha: string | null;
    url: string;
  };
  summary: {
    github_actions_workflows: string[];
    iac_candidates: string[];
    important_paths: string[];
    observation_counts: Record<string, number>;
    sbom_artifact?: string;
    tool_availability_artifact?: string;
    tool_order: BaselineToolName[];
  };
  tools: BaselineToolSummary[];
}

export type ToolAvailabilityStatus = "available" | "failed" | "not_required";

export interface ToolAvailabilityRecord {
  attempts: Array<{
    command: string;
    exit_code?: number;
    stderr?: string;
    stdout?: string;
  }>;
  diagnostics: string[];
  path?: string;
  required: boolean;
  skipped_reason?: string;
  status: ToolAvailabilityStatus;
  tool: BaselineToolName;
  version?: string;
}

export interface ToolAvailabilityArtifact {
  generated_at: string;
  kind: "tool-availability";
  tool_bin_dir: string;
  tools: ToolAvailabilityRecord[];
}

export interface PiContextPackArtifact {
  inventory: {
    config_files: string[];
    github_actions_workflows: string[];
    iac_candidates: string[];
    infra_files: string[];
    language_summary?: Array<{
      file_count: number;
      language: string;
      loc: number;
      source: "inventory";
    }>;
    manifest_files: string[];
    package_and_lock_files: string[];
    source_index: Array<{
      directory: string;
      file_count: number;
      languages: string[];
      sample_files: string[];
      total_loc?: number;
    }>;
    summary: InventoryArtifact["summary"];
    top_level_directories: string[];
  };
  repo: {
    commit_sha: string | null;
    url: string;
  };
}

export type PiConfidence = "high" | "low" | "medium";

export interface PiArtifactMetadata {
  pi: {
    input_context_artifact: string;
    invocation: {
      args?: string[];
      command: string;
      cwd?: string;
      metadata?: Record<string, unknown>;
      provider?: string;
    };
    final_response_bytes?: number;
    json_delivery?: "fenced" | "repaired" | "strict";
    model: string;
    provider: string;
    repair_applied?: boolean;
    stderr_bytes?: number;
    step: string;
    version?: string;
  };
  degraded?: {
    diagnostics: string[];
    raw_artifact?: string;
    reason: string;
  };
}

export interface PiCoverage {
  not_covered: Array<{
    area: string;
    reason: string;
  }>;
  reviewed: Array<{
    area: string;
    evidence: string[];
  }>;
}

export interface FactGap {
  area: string;
  evidence?: string[];
  inference?: boolean;
  missing_fact: string;
}

export type PiRepositoryMapArtifactKind =
  | "auth-access"
  | "config-secrets"
  | "coverage-structure"
  | "crypto"
  | "data-flows"
  | "entrypoints"
  | "external-integrations-egress"
  | "infra-deploy"
  | "logging-observability"
  | "operation-sinks"
  | "repository-map"
  | "stack-build-deps"
  | "storage-data-model"
  | "trust-boundaries";

export interface PiRepositoryMapBaseArtifact<TKind extends PiRepositoryMapArtifactKind> {
  coverage?: PiCoverage;
  fact_gaps?: FactGap[];
  generated_at: string;
  generated_by: "pi" | "vibeshield";
  kind: TKind;
  metadata: PiArtifactMetadata | Record<string, unknown>;
  repo: {
    commit_sha: string | null;
    url: string;
  };
}

export interface CoverageStructureArtifact
  extends PiRepositoryMapBaseArtifact<"coverage-structure"> {
  access_gaps?: Array<{
    area: string;
    evidence?: string[];
    reason: string;
  }>;
  coverage_targets?: Array<{
    area: string;
    evidence: string[];
    reason: string;
  }>;
  excluded_directories?: Array<{
    evidence?: string[];
    path: string;
    reason: string;
  }>;
  important_files?: Array<{
    evidence: string[];
    path: string;
    reason: string;
  }>;
  language_summary?: Array<{
    file_count: number;
    language: string;
    loc: number;
    source: "inventory";
  }>;
  repo_size?: {
    file_count: number;
    source: "inventory";
    total_loc?: number;
  };
  repository_structure: Array<{
    evidence: string[];
    kind: "config" | "dependency" | "docs" | "generated" | "infra" | "other" | "source" | "test";
    path: string;
    role: string;
  }>;
  reviewed_directories?: Array<{
    evidence: string[];
    path: string;
    reason?: string;
  }>;
  top_level_tree?: Array<{
    depth?: number;
    evidence: string[];
    kind: "config" | "dependency" | "docs" | "generated" | "infra" | "other" | "source" | "test";
    path: string;
    role: string;
  }>;
}

export interface StackBuildDependencyRecord {
  confidence: PiConfidence;
  direct?: boolean;
  evidence: string[];
  id: string;
  kind:
    | "build-tool"
    | "dependency"
    | "framework"
    | "language"
    | "package-manager"
    | "runtime"
    | "service"
    | "test-tool"
    | "other";
  name: string;
  role: string;
  share?: string;
  source?: string;
  version?: string;
  required_version?: string;
}

export interface StackBuildDepsArtifact extends PiRepositoryMapBaseArtifact<"stack-build-deps"> {
  build: {
    commands: Array<{
      command: string;
      evidence: string[];
      id: string;
      name: string;
      source: string;
    }>;
    lockfiles: Array<{ evidence: string[]; path: string }>;
    manifests: Array<{ evidence: string[]; path: string }>;
  };
  ci?: Array<{
    command?: string;
    evidence: string[];
    file: string;
    id: string;
    name?: string;
    step?: string;
  }>;
  dependencies: StackBuildDependencyRecord[];
  dependency_notes?: Array<{
    evidence?: string[];
    kind:
      | "dependency_count"
      | "lockfile_absent"
      | "lockfile_present"
      | "transitive_available"
      | "vendored_dependencies";
    path?: string;
    summary: string;
  }>;
  stack: StackBuildDependencyRecord[];
}

export interface EntryPointRecord {
  command?: string;
  confidence?: PiConfidence;
  // When this record represents a collapsed family of uniform boundaries, the
  // number of boundaries it stands for.
  count?: number;
  evidence: string[];
  handler?: string;
  id: string;
  kind:
    | "cli_command"
    | "cron_job"
    | "external_format_parser"
    | "file_upload_handler"
    | "graphql_resolver"
    | "grpc_method"
    | "http_route"
    | "other"
    | "queue_event_handler"
    | "webhook";
  location?: string;
  method?: string;
  name?: string;
  notes?: string;
  path?: string;
  route?: string;
  schedule?: string;
}

export interface EntrypointsArtifact extends PiRepositoryMapBaseArtifact<"entrypoints"> {
  entrypoints: EntryPointRecord[];
}

export interface AuthConfigRecord {
  confidence?: PiConfidence;
  evidence: string[];
  id: string;
  kind?:
    | "auth_config"
    | "authorization_rule"
    | "config_source"
    | "credential_reference"
    | "identity_provider"
    | "middleware"
    | "other"
    | "secret_reference";
  location?: string;
  mechanism?: string;
  name?: string;
  notes?: string;
  protects_entrypoint_ids?: string[];
  source?: string;
  value_status?: string;
  variables?: string[];
}

export interface AuthAccessArtifact extends PiRepositoryMapBaseArtifact<"auth-access"> {
  auth: AuthConfigRecord[];
  entrypoint_access?: Array<{
    entrypoint_id: string;
    evidence: string[];
    mechanism?: string;
    roles_scopes?: string[];
    session_storage?: string;
    status: "protected" | "public" | "unknown";
  }>;
}

export interface ConfigSecretsArtifact extends PiRepositoryMapBaseArtifact<"config-secrets"> {
  config: AuthConfigRecord[];
  secret_locations?: AuthConfigRecord[];
  secret_references?: Array<
    AuthConfigRecord & {
      value_redacted: true;
    }
  >;
}

export interface StorageDataModelRecord {
  confidence?: PiConfidence;
  data_categories?: string[];
  evidence: string[];
  fields?: string[];
  id: string;
  kind?: string;
  location?: string;
  name?: string;
  role?: string;
  schema_evidence?: string[];
  type?: string;
}

export interface StorageDataModelArtifact
  extends PiRepositoryMapBaseArtifact<"storage-data-model"> {
  storage: StorageDataModelRecord[];
}

export interface ExternalIntegrationEgressRecord {
  confidence?: PiConfidence;
  evidence: string[];
  from?: string;
  id: string;
  kind?: string;
  location?: string;
  name?: string;
  provider?: string;
  role?: string;
  target?: string;
  type?: string;
}

export interface ExternalIntegrationsEgressArtifact
  extends PiRepositoryMapBaseArtifact<"external-integrations-egress"> {
  integrations: ExternalIntegrationEgressRecord[];
}

export interface InfraDeployRecord {
  base_image?: string;
  confidence?: PiConfidence;
  entrypoint?: string;
  evidence: string[];
  id: string;
  kind?: string;
  location?: string;
  mounts?: string[];
  name?: string;
  ports?: string[];
  role?: string;
  secrets?: string[];
  type?: string;
  user?: string;
}

export interface InfraDeployArtifact extends PiRepositoryMapBaseArtifact<"infra-deploy"> {
  ci?: InfraDeployRecord[];
  infra: InfraDeployRecord[];
}

export interface OperationSinkRecord {
  confidence: PiConfidence;
  destination?: string;
  evidence: string[];
  id: string;
  input_variables?: string[];
  kind:
    | "deserialization_or_parsing"
    | "filesystem_operation"
    | "nosql_query"
    | "other"
    | "outbound_http_or_sdk_url"
    | "path_construction"
    | "process_execution"
    | "redirect"
    | "sql_or_orm_query"
    | "template_rendering";
  location: string;
  notes?: string;
  operation: string;
  parameters?: string[];
  query_construction?: "concatenated" | "literal" | "parameterized" | "unknown";
}

export interface OperationSinksArtifact extends PiRepositoryMapBaseArtifact<"operation-sinks"> {
  operation_sinks: OperationSinkRecord[];
}

export interface CryptoRecord {
  algorithm?: string;
  confidence?: PiConfidence;
  evidence: string[];
  id: string;
  kind?: "crypto_operation" | "password_hashing" | "randomness" | "tls_configuration" | "other";
  location?: string;
  mode?: string;
  name?: string;
  operation?: string;
  parameters?: string[];
}

export interface CryptoArtifact extends PiRepositoryMapBaseArtifact<"crypto"> {
  crypto: CryptoRecord[];
}

export interface LoggingObservabilityRecord {
  confidence?: PiConfidence;
  destination?: string;
  evidence: string[];
  id: string;
  kind?: "logging" | "metrics" | "tracing" | "telemetry" | "other";
  location?: string;
  logged_fields?: string[];
  name?: string;
  operation?: string;
}

export interface LoggingObservabilityArtifact
  extends PiRepositoryMapBaseArtifact<"logging-observability"> {
  logging: LoggingObservabilityRecord[];
}

export type DataFlowTraceStatus =
  | "direct observed"
  | "multi-step inferred"
  | "not established"
  | "not traced further";

export interface DataFlowTrace {
  breakpoint?: {
    evidence?: string[];
    reason: string;
  } | null;
  evidence?: string[];
  id: string;
  inference?: boolean;
  intermediate_functions?: Array<{
    evidence: string[];
    name: string;
  }>;
  operation_sink?: string;
  operation_sink_evidence?: string[];
  sink_evidence?: string[];
  sink_id?: string;
  source_entrypoint?: string;
  source_entrypoint_id?: string;
  source_evidence: string[];
  steps?: Array<{
    evidence: string[];
    name: string;
  }>;
  trace_status: DataFlowTraceStatus;
}

export interface DataFlowsArtifact extends PiRepositoryMapBaseArtifact<"data-flows"> {
  flows: DataFlowTrace[];
  inputs: {
    entrypoints_artifact: string;
    operation_sinks_artifact: string;
  };
}

export interface PriorMapArtifactInputs {
  auth_access_artifact?: string;
  config_secrets_artifact?: string;
  coverage_structure_artifact?: string;
  crypto_artifact?: string;
  data_flows_artifact?: string;
  entrypoints_artifact?: string;
  external_integrations_egress_artifact?: string;
  infra_deploy_artifact?: string;
  logging_observability_artifact?: string;
  operation_sinks_artifact?: string;
  stack_build_deps_artifact?: string;
  storage_data_model_artifact?: string;
  trust_boundaries_artifact?: string;
}

export interface TrustBoundaryRecord {
  confidence?: PiConfidence;
  description?: string;
  evidence: string[];
  flow_ids?: string[];
  id: string;
  inference: true;
  kind?:
    | "external_user_to_app"
    | "network"
    | "other"
    | "process"
    | "repository_to_ci"
    | "runtime_to_external_service"
    | "storage"
    | "trust_zone";
  name?: string;
  sink_ids?: string[];
  source_artifact_ids?: PiRepositoryMapArtifactKind[];
  source_entrypoint_ids?: string[];
  summary?: string;
}

export interface TrustBoundariesArtifact extends PiRepositoryMapBaseArtifact<"trust-boundaries"> {
  boundaries: TrustBoundaryRecord[];
  inputs?: Omit<PriorMapArtifactInputs, "trust_boundaries_artifact">;
}

export interface RepositoryMapArtifact extends PiRepositoryMapBaseArtifact<"repository-map"> {
  inputs?: PriorMapArtifactInputs;
  sections: Array<{
    artifact?: PiRepositoryMapArtifactKind | undefined;
    evidence: string[];
    id?: number;
    item_count?: number;
    path?: string;
    summary?: string;
    title?: string;
  }>;
  summary: {
    confidence?: PiConfidence;
    evidence: string[];
    inference?: true;
    project_kind?: string;
    text: string;
  };
}

export type PiStructuredArtifactKind = PiRepositoryMapArtifactKind;

export function parseEvidenceRef(value: string): EvidenceRef | null {
  const match = value.match(/^(?<path>.+?):(?<start>\d+)(?:-(?<end>\d+))?$/);
  if (match?.groups === undefined) {
    return null;
  }

  const startLine = Number(match.groups.start);
  const endLine = match.groups.end === undefined ? startLine : Number(match.groups.end);
  if (
    match.groups.path === undefined ||
    !Number.isInteger(startLine) ||
    !Number.isInteger(endLine) ||
    startLine < 1 ||
    endLine < startLine
  ) {
    return null;
  }

  return {
    end_line: endLine,
    path: match.groups.path,
    start_line: startLine,
  };
}
