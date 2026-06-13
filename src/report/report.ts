import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { BaselineSummaryArtifact } from "../artifacts/contracts.js";
import type { ScanRunState } from "../run/types.js";

type JsonObject = Record<string, unknown>;

type RepoMapArtifactKey = keyof NonNullable<ScanRunState["artifacts"]["repo_map"]>;

interface RepositoryMapReportSection {
  artifactKey?: RepoMapArtifactKey;
  index: number;
  keys: string[];
  title: string;
}

const repositoryMapReportSections: RepositoryMapReportSection[] = [
  {
    artifactKey: "coverage_structure",
    index: 0,
    keys: ["coverage", "coverage_structure", "coverage-structure"],
    title: "Coverage",
  },
  {
    artifactKey: "stack_build_deps",
    index: 1,
    keys: ["stack_build_deps", "stack-build-deps", "stack_and_build", "stack"],
    title: "Stack And Build",
  },
  {
    artifactKey: "coverage_structure",
    index: 2,
    keys: ["repository_structure", "repo_structure", "structure"],
    title: "Repository Structure",
  },
  {
    artifactKey: "entrypoints",
    index: 3,
    keys: ["entrypoints", "entry_points", "attack_surface"],
    title: "Attack Surface And Entry Points",
  },
  {
    artifactKey: "auth_config_secrets",
    index: 4,
    keys: ["auth", "authentication_authorization", "authentication_and_authorization"],
    title: "Authentication And Authorization",
  },
  {
    artifactKey: "data_flows",
    index: 5,
    keys: ["data_flows", "data-flows", "flows_to_sinks"],
    title: "Data Flows To Operation Sinks",
  },
  {
    artifactKey: "operation_sinks",
    index: 6,
    keys: ["operation_sinks", "operation-sinks"],
    title: "Operation Sink Inventory",
  },
  {
    artifactKey: "auth_config_secrets",
    index: 7,
    keys: ["secrets_config", "secrets_and_configuration", "configuration_secrets"],
    title: "Secrets And Configuration",
  },
  {
    artifactKey: "operation_sinks",
    index: 8,
    keys: ["crypto", "cryptography"],
    title: "Cryptography",
  },
  {
    artifactKey: "storage_integrations_infra",
    index: 9,
    keys: ["storage", "data_model", "storage_and_data_model"],
    title: "Storage And Data Model",
  },
  {
    artifactKey: "storage_integrations_infra",
    index: 10,
    keys: ["external_integrations", "network_egress", "integrations_egress"],
    title: "External Integrations And Network Egress",
  },
  {
    artifactKey: "stack_build_deps",
    index: 11,
    keys: ["dependencies", "dependency_inventory"],
    title: "Dependencies",
  },
  {
    artifactKey: "storage_integrations_infra",
    index: 12,
    keys: ["infra_deploy", "infrastructure_deployment", "infrastructure_and_deployment"],
    title: "Infrastructure And Deployment",
  },
  {
    artifactKey: "operation_sinks",
    index: 13,
    keys: ["logging_observability", "logging_and_observability", "observability"],
    title: "Logging And Observability",
  },
  {
    artifactKey: "trust_boundaries",
    index: 14,
    keys: ["trust_boundaries", "trust-boundaries"],
    title: "Trust Boundaries",
  },
];

export async function writeSuccessReport(input: {
  reportPath: string;
  run: ScanRunState;
}): Promise<void> {
  const runDir = path.dirname(input.reportPath);
  const baseline = await readArtifact<BaselineSummaryArtifact>(
    runDir,
    input.run.artifacts.baseline_summary,
  );
  const repositoryMap = await readArtifact<JsonObject>(runDir, input.run.artifacts.repository_map);
  const repoMapSections = await readRepoMapSectionArtifacts(runDir, input.run);
  const sandboxCleanup = input.run.sandbox?.cleanup;
  const lines = [
    "# VibeShield facts-only repository map",
    "",
    "Status: success",
    `Run ID: ${input.run.run_id}`,
    `Source: ${input.run.source.url}`,
    `Commit: ${input.run.commit_sha ?? "unknown"}`,
    `Sandbox: ${input.run.sandbox?.id ?? "unknown"}`,
    `Sandbox deleted: ${sandboxCleanup?.deleted === true ? "yes" : "unknown"}`,
    "",
    "Intake, inventory, deterministic baseline, and repository mapping are included in this run.",
    "This repository-mapping report is not a security audit.",
    "No security findings or verdict are produced.",
    "",
    "## Deterministic baseline overview",
    ...(baseline?.tools.map(
      (tool) =>
        `- ${tool.tool}: ${tool.status}${tool.skipped_reason ? ` (${tool.skipped_reason})` : ""}; observations: ${tool.observations.length}`,
    ) ?? ["- Baseline summary artifact was not available."]),
    "",
    "## Deterministic scanner findings",
    ...formatBaselineFindings(baseline),
    "",
    "## Repository map",
    ...formatRepositoryMap(repositoryMap, repoMapSections),
    "",
    "## Inspectable artifacts",
    ...formatArtifactLinks(input.run),
    "",
  ];

  await writeFile(input.reportPath, `${lines.join("\n")}\n`, "utf8");
}

export async function writeFailureReport(input: {
  reportPath: string;
  run: ScanRunState;
}): Promise<void> {
  const cleanup = input.run.sandbox?.cleanup;
  const lines = [
    "# VibeShield failure report",
    "",
    "Scan did not complete.",
    "Completed artifacts remain inspectable below.",
    `Run ID: ${input.run.run_id}`,
    `Source: ${input.run.source.url}`,
    `Failed stage: ${input.run.error?.stage ?? input.run.current_stage}`,
    `Error: ${input.run.error?.user_message ?? "Unknown error"}`,
    "",
    "Diagnostics:",
    ...(input.run.error?.diagnostics?.length
      ? input.run.error.diagnostics.map((diagnostic) => `- ${diagnostic}`)
      : ["- No additional diagnostics were recorded."]),
    "",
    "Partial artifacts:",
    ...formatArtifactLinks(input.run),
    "",
    "Cleanup:",
    `- sandbox cleanup attempted: ${cleanup?.attempted === true ? "yes" : "no"}.`,
    `- sandbox deleted: ${cleanup?.deleted === true ? "yes" : "no"}.`,
    "",
    "Open run.json and events.jsonl in this run directory for diagnostics.",
    "",
  ];

  await writeFile(input.reportPath, `${lines.join("\n")}\n`, "utf8");
}

async function readRepoMapSectionArtifacts(
  runDir: string,
  run: ScanRunState,
): Promise<Partial<Record<RepoMapArtifactKey, JsonObject>>> {
  const sections: Partial<Record<RepoMapArtifactKey, JsonObject>> = {};
  for (const key of repositoryMapArtifactKeys(run)) {
    const section = await readArtifact<JsonObject>(runDir, run.artifacts.repo_map?.[key]);
    if (section !== null) {
      sections[key] = section;
    }
  }
  return sections;
}

async function readArtifact<T>(
  runDir: string,
  relativePath: string | undefined,
): Promise<T | null> {
  if (relativePath === undefined) {
    return null;
  }

  try {
    return JSON.parse(await readFile(path.join(runDir, relativePath), "utf8")) as T;
  } catch {
    return null;
  }
}

function repositoryMapArtifactKeys(run: ScanRunState): RepoMapArtifactKey[] {
  return Object.keys(run.artifacts.repo_map ?? {}) as RepoMapArtifactKey[];
}

function formatBaselineFindings(baseline: BaselineSummaryArtifact | null): string[] {
  const findings =
    baseline?.tools.flatMap((tool) =>
      tool.observations.map((observation) => {
        const evidence =
          observation.evidence.length > 0 ? ` (${observation.evidence.join(", ")})` : "";
        return `${tool.tool} ${observation.severity} ${observation.kind}: ${observation.message}${evidence}`;
      }),
    ) ?? [];

  return formatEntries(
    findings.length > 0 ? findings : ["No deterministic scanner findings were normalized."],
  );
}

function formatRepositoryMap(
  repositoryMap: JsonObject | null,
  sectionArtifacts: Partial<Record<RepoMapArtifactKey, JsonObject>>,
): string[] {
  return repositoryMapReportSections.flatMap((section) => [
    `### ${section.index}. ${section.title}`,
    ...formatRepositoryMapSection(repositoryMap, sectionArtifacts, section),
    "",
  ]);
}

function formatRepositoryMapSection(
  repositoryMap: JsonObject | null,
  sectionArtifacts: Partial<Record<RepoMapArtifactKey, JsonObject>>,
  section: RepositoryMapReportSection,
): string[] {
  const sectionValue =
    findSectionValue(repositoryMap, section) ??
    (section.artifactKey === undefined ? undefined : sectionArtifacts[section.artifactKey]);

  return formatMapValue(sectionValue);
}

function findSectionValue(
  repositoryMap: JsonObject | null,
  section: RepositoryMapReportSection,
): unknown {
  if (repositoryMap === null) {
    return undefined;
  }

  const fromArray = findSectionInArrays(repositoryMap, section);
  if (fromArray !== undefined) {
    return fromArray;
  }

  const containers = [
    repositoryMap,
    objectField(repositoryMap, "map"),
    objectField(repositoryMap, "repository_map"),
  ].filter((value): value is JsonObject => value !== undefined);

  for (const container of containers) {
    for (const key of [`section_${section.index}`, String(section.index), ...section.keys]) {
      if (container[key] !== undefined) {
        return container[key];
      }
    }
  }

  return undefined;
}

function findSectionInArrays(
  repositoryMap: JsonObject,
  section: RepositoryMapReportSection,
): unknown {
  const candidateArrays = [
    arrayField(repositoryMap, "sections"),
    arrayField(repositoryMap, "map_sections"),
    arrayField(objectField(repositoryMap, "map"), "sections"),
    arrayField(objectField(repositoryMap, "repository_map"), "sections"),
  ].filter((value): value is unknown[] => value !== undefined);

  for (const candidates of candidateArrays) {
    const match = candidates.find((candidate) => isMatchingSection(candidate, section));
    if (match !== undefined) {
      return match;
    }
  }

  return undefined;
}

function isMatchingSection(candidate: unknown, section: RepositoryMapReportSection): boolean {
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    return false;
  }

  const record = candidate as Record<string, unknown>;
  const numericFields = [record.index, record.number, record.section, record.section_index];
  if (numericFields.some((value) => Number(value) === section.index)) {
    return true;
  }

  const text = [record.id, record.key, record.slug, record.title, record.name]
    .filter((value): value is string => typeof value === "string")
    .join(" ")
    .toLowerCase();
  const normalizedText = text.replaceAll("_", "-");

  if (
    section.keys.some((key) => normalizedText.includes(key.replaceAll("_", "-"))) ||
    text.includes(`${section.index}.`) ||
    text.includes(`${section.index}:`)
  ) {
    return true;
  }

  return text.startsWith(String(section.index));
}

function formatMapValue(value: unknown): string[] {
  if (value === undefined || value === null) {
    return ["- Not available."];
  }

  if (typeof value === "string") {
    const lines = value
      .split("\n")
      .map((line) => line.trimEnd())
      .filter((line) => line.trim() !== "");
    return lines.length > 0 ? lines : ["- Not available."];
  }

  return ["```json", JSON.stringify(stripSectionWrapper(value), null, 2), "```"];
}

function stripSectionWrapper(value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return value;
  }

  const record = value as Record<string, unknown>;
  const wrapperKeys = new Set(["id", "index", "key", "name", "number", "section", "title"]);
  const stripped = Object.fromEntries(
    Object.entries(record).filter(([key]) => !wrapperKeys.has(key)),
  );

  return Object.keys(stripped).length > 0 ? stripped : value;
}

function objectField(value: unknown, field: string): JsonObject | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const candidate = (value as Record<string, unknown>)[field];
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    return undefined;
  }
  return candidate as JsonObject;
}

function arrayField(value: unknown, field: string): unknown[] | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const candidate = (value as Record<string, unknown>)[field];
  return Array.isArray(candidate) ? candidate : undefined;
}

function formatEntries(values: string[] | undefined): string[] {
  if (values === undefined || values.length === 0) {
    return ["- Not available."];
  }
  return values.map((value) => `- ${value}`);
}

function formatArtifactLinks(run: ScanRunState): string[] {
  const artifacts = [
    run.artifacts.inventory_legacy,
    run.artifacts.inventory,
    run.artifacts.baseline_tool_availability,
    run.artifacts.baseline_summary,
    run.artifacts.pi_context_pack,
    run.artifacts.repo_map?.coverage_structure,
    run.artifacts.repo_map?.stack_build_deps,
    run.artifacts.repo_map?.entrypoints,
    run.artifacts.repo_map?.auth_config_secrets,
    run.artifacts.repo_map?.storage_integrations_infra,
    run.artifacts.repo_map?.operation_sinks,
    run.artifacts.repo_map?.data_flows,
    run.artifacts.repo_map?.trust_boundaries,
    run.artifacts.repository_map,
    run.artifacts.events,
    ...(run.steps?.flatMap((step) => step.jobs.flatMap((job) => job.artifacts)) ?? []),
  ].filter((artifact): artifact is string => artifact !== undefined);

  if (artifacts.length === 0) {
    return ["- No artifacts were recorded."];
  }

  return [...new Set(artifacts)].map((artifact) => `- ${artifact}`);
}
