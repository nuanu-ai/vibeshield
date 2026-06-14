import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { BaselineSummaryArtifact } from "../artifacts/contracts.js";
import type { ScanRunState } from "../run/types.js";

type JsonObject = Record<string, unknown>;

type RepoMapArtifactKey = keyof NonNullable<ScanRunState["artifacts"]["repo_map"]>;

interface RepositoryMapReportSection {
  artifactKey?: RepoMapArtifactKey;
  index: number;
  title: string;
}

const repositoryMapReportSections: RepositoryMapReportSection[] = [
  { artifactKey: "coverage_structure", index: 0, title: "Coverage" },
  { artifactKey: "stack_build_deps", index: 1, title: "Stack And Build" },
  { artifactKey: "coverage_structure", index: 2, title: "Repository Structure" },
  { artifactKey: "entrypoints", index: 3, title: "Attack Surface And Entry Points" },
  { artifactKey: "auth_access", index: 4, title: "Authentication And Authorization" },
  { artifactKey: "data_flows", index: 5, title: "Data Flows To Operation Sinks" },
  { artifactKey: "operation_sinks", index: 6, title: "Operation Sink Inventory" },
  { artifactKey: "config_secrets", index: 7, title: "Secrets And Configuration" },
  { artifactKey: "crypto", index: 8, title: "Cryptography" },
  { artifactKey: "storage_data_model", index: 9, title: "Storage And Data Model" },
  {
    artifactKey: "external_integrations_egress",
    index: 10,
    title: "External Integrations And Network Egress",
  },
  { artifactKey: "stack_build_deps", index: 11, title: "Dependencies" },
  {
    artifactKey: "infra_deploy",
    index: 12,
    title: "Infrastructure And Deployment",
  },
  { artifactKey: "logging_observability", index: 13, title: "Logging And Observability" },
  { artifactKey: "trust_boundaries", index: 14, title: "Trust Boundaries" },
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
  const repoMapSections = await readRepoMapSectionArtifacts(runDir, input.run);
  const baselineObservations = formatBaselineObservations(baseline);
  const lines = [
    "# VibeShield Repository Map",
    "",
    `Source: ${input.run.source.url}`,
    `Commit: ${input.run.commit_sha ?? "unknown"}`,
    `Run ID: ${input.run.run_id}`,
    "",
    ...(baselineObservations.length > 0
      ? ["## Deterministic Scanner Observations", ...baselineObservations, ""]
      : []),
    ...formatRepositoryMap(repoMapSections),
  ];

  await writeFile(input.reportPath, `${normalizeMarkdownSpacing(lines).join("\n")}\n`, "utf8");
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

function formatBaselineObservations(baseline: BaselineSummaryArtifact | null): string[] {
  const rows =
    baseline?.tools.flatMap((tool) =>
      tool.observations.map((observation) => [
        tool.tool,
        observation.severity,
        observation.kind,
        observation.message,
        formatEvidence(observation.evidence),
      ]),
    ) ?? [];

  return rows.length > 0
    ? markdownTable(["Tool", "Severity", "Kind", "Observation", "Evidence"], rows)
    : [];
}

function formatRepositoryMap(
  sectionArtifacts: Partial<Record<RepoMapArtifactKey, JsonObject>>,
): string[] {
  return repositoryMapReportSections.flatMap((section) => [
    `## ${section.index}. ${section.title}`,
    ...formatRepositoryMapSection(sectionArtifacts, section),
    "",
  ]);
}

function formatRepositoryMapSection(
  sectionArtifacts: Partial<Record<RepoMapArtifactKey, JsonObject>>,
  section: RepositoryMapReportSection,
): string[] {
  const artifact =
    section.artifactKey === undefined ? undefined : sectionArtifacts[section.artifactKey];

  switch (section.index) {
    case 0:
      return formatCoverageSection(artifact);
    case 1:
      return formatStackAndBuildSection(artifact);
    case 2:
      return formatRepositoryStructureSection(artifact);
    case 3:
      return formatEntrypointsSection(artifact);
    case 4:
      return formatAuthSection(artifact);
    case 5:
      return formatDataFlowsSection(artifact);
    case 6:
      return formatOperationSinksSection(artifact);
    case 7:
      return formatSecretsConfigSection(artifact);
    case 8:
      return formatCryptographySection(artifact);
    case 9:
      return formatStorageSection(artifact);
    case 10:
      return formatIntegrationsSection(artifact);
    case 11:
      return formatDependenciesSection(artifact);
    case 12:
      return formatInfrastructureSection(artifact);
    case 13:
      return formatLoggingSection(artifact);
    case 14:
      return formatTrustBoundariesSection(artifact);
    default:
      return ["- Not available."];
  }
}

function formatCoverageSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  const repoSize = objectField(artifact, "repo_size");
  const sizeLine =
    repoSize === undefined
      ? undefined
      : `- Repo size: ${cell(repoSize.file_count)} files${
          repoSize.total_loc === undefined ? "" : `, ${cell(repoSize.total_loc)} LOC`
        } (${cell(repoSize.source)}).`;

  return compactLines([
    sizeLine,
    ...optionalTable(
      "Languages",
      ["Language", "Files", "LOC", "Source"],
      recordArray(artifact, "language_summary").map((item) => [
        field(item, "language"),
        field(item, "file_count"),
        field(item, "loc"),
        field(item, "source"),
      ]),
    ),
    ...optionalTable(
      "Reviewed Areas",
      ["Area", "Reason", "Evidence"],
      [
        ...recordArray(objectField(artifact, "coverage"), "reviewed").map((item) => [
          field(item, "area"),
          "",
          recordEvidence(item),
        ]),
        ...recordArray(artifact, "reviewed_directories").map((item) => [
          field(item, "path"),
          field(item, "reason"),
          recordEvidence(item),
        ]),
      ],
    ),
    ...optionalTable(
      "Not Covered Or Excluded",
      ["Area", "Reason", "Evidence"],
      [
        ...recordArray(objectField(artifact, "coverage"), "not_covered").map((item) => [
          field(item, "area"),
          field(item, "reason"),
          recordEvidence(item),
        ]),
        ...recordArray(artifact, "excluded_directories").map((item) => [
          field(item, "path"),
          field(item, "reason"),
          recordEvidence(item),
        ]),
        ...recordArray(artifact, "access_gaps").map((item) => [
          field(item, "area"),
          field(item, "reason"),
          recordEvidence(item),
        ]),
      ],
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatStackAndBuildSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...optionalTable(
      "Stack",
      ["Kind", "Name", "Version", "Role", "Evidence"],
      recordArray(artifact, "stack").map((item) => [
        field(item, "kind"),
        field(item, "name"),
        firstField(item, ["version", "required_version", "share"]),
        field(item, "role"),
        recordEvidence(item),
      ]),
    ),
    ...optionalTable(
      "Build Commands",
      ["Name", "Command", "Source", "Evidence"],
      recordArray(objectField(artifact, "build"), "commands").map((item) => [
        field(item, "name"),
        field(item, "command"),
        field(item, "source"),
        recordEvidence(item),
      ]),
    ),
    ...optionalTable(
      "CI/CD",
      ["File", "Step", "Command", "Evidence"],
      recordArray(artifact, "ci").map((item) => [
        field(item, "file"),
        firstField(item, ["step", "name"]),
        field(item, "command"),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatRepositoryStructureSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  const rows = uniqueRows(
    [
      ...recordArray(artifact, "top_level_tree"),
      ...recordArray(artifact, "repository_structure"),
      ...recordArray(artifact, "important_files"),
    ].map((item) => [
      field(item, "path"),
      field(item, "kind"),
      firstField(item, ["role", "reason"]),
      recordEvidence(item),
    ]),
  );

  return compactLines([
    ...tableOrNotObserved(["Path", "Kind", "Purpose", "Evidence"], rows),
    ...formatFactGaps(artifact),
  ]);
}

function formatEntrypointsSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...tableOrNotObserved(
      ["Type", "Name", "Handler", "External Input", "Evidence"],
      recordArray(artifact, "entrypoints").map((item) => {
        const name = firstField(item, ["name", "route", "path", "command"]);
        const count = typeof item.count === "number" && item.count > 1 ? ` ×${item.count}` : "";
        return [
          field(item, "kind"),
          `${name}${count}`,
          firstField(item, ["handler", "location"]),
          entrypointExternalInput(item),
          recordEvidence(item),
        ];
      }),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatAuthSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...optionalTable(
      "Mechanisms",
      ["Mechanism", "Name", "Location", "Protects", "Evidence"],
      recordArray(artifact, "auth").map((item) => [
        firstField(item, ["mechanism", "kind"]),
        field(item, "name"),
        field(item, "location"),
        listField(item, "protects_entrypoint_ids"),
        recordEvidence(item),
      ]),
    ),
    ...optionalTable(
      "Entrypoint Access",
      ["Entrypoint", "Status", "Mechanism", "Roles/Scopes", "Evidence"],
      recordArray(artifact, "entrypoint_access").map((item) => [
        field(item, "entrypoint_id"),
        field(item, "status"),
        firstField(item, ["mechanism", "session_storage"]),
        listField(item, "roles_scopes"),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatDataFlowsSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...tableOrNotObserved(
      ["Source", "Intermediates", "Sink", "Trace Status", "Evidence"],
      recordArray(artifact, "flows").map((item) => [
        firstField(item, ["source_entrypoint", "source_entrypoint_id"]),
        intermediateFunctions(item),
        firstField(item, ["operation_sink", "sink_id"]),
        field(item, "trace_status"),
        formatEvidence(recordEvidenceRefs(item)),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatOperationSinksSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...tableOrNotObserved(
      ["Category", "Operation", "Input Variables", "Destination", "Evidence"],
      operationSinkRecords(artifact).map((item) => [
        field(item, "kind"),
        field(item, "operation"),
        listField(item, "input_variables"),
        firstField(item, ["destination", "location", "query_construction"]),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatSecretsConfigSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  const secretReferences = [
    ...recordArray(artifact, "secret_references"),
    ...recordArray(artifact, "secret_locations"),
  ];

  return compactLines([
    ...optionalTable(
      "Configuration",
      ["Name", "Kind", "Location", "Status", "Evidence"],
      recordArray(artifact, "config").map((item) => [
        field(item, "name"),
        field(item, "kind"),
        firstField(item, ["location", "source"]),
        field(item, "value_status"),
        recordEvidence(item),
      ]),
    ),
    ...optionalTable(
      "Secret References",
      ["Name", "Kind", "Location", "Status", "Evidence"],
      secretReferences.map((item) => [
        field(item, "name"),
        field(item, "kind"),
        firstField(item, ["location", "source"]),
        item.value_redacted === true ? "redacted" : field(item, "value_status"),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatCryptographySection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...tableOrNotObserved(
      ["Operation", "Algorithm/Mode", "Inputs", "Evidence"],
      recordArray(artifact, "crypto").map((item) => [
        firstField(item, ["operation", "name", "kind"]),
        compactJoin([field(item, "algorithm"), field(item, "mode")]),
        listField(item, "parameters"),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatStorageSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...tableOrNotObserved(
      ["Kind", "Name", "Location", "Fields/Data", "Evidence"],
      recordArray(artifact, "storage").map((item) => [
        firstField(item, ["kind", "type"]),
        field(item, "name"),
        field(item, "location"),
        compactJoin([listField(item, "fields"), listField(item, "data_categories")]),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatIntegrationsSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...tableOrNotObserved(
      ["Target", "From", "Purpose", "Evidence"],
      recordArray(artifact, "integrations").map((item) => [
        firstField(item, ["target", "name", "kind"]),
        firstField(item, ["from", "location"]),
        field(item, "role"),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatDependenciesSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  const build = objectField(artifact, "build");
  return compactLines([
    ...optionalTable(
      "Manifest And Lock Files",
      ["Type", "Path", "Evidence"],
      [
        ...recordArray(build, "manifests").map((item) => [
          "manifest",
          field(item, "path"),
          recordEvidence(item),
        ]),
        ...recordArray(build, "lockfiles").map((item) => [
          "lockfile",
          field(item, "path"),
          recordEvidence(item),
        ]),
      ],
    ),
    ...optionalTable(
      "Direct Dependencies",
      ["Name", "Version", "Role", "Evidence"],
      recordArray(artifact, "dependencies").map((item) => [
        field(item, "name"),
        field(item, "version"),
        field(item, "role"),
        recordEvidence(item),
      ]),
    ),
    ...optionalTable(
      "Dependency Notes",
      ["Kind", "Path", "Summary", "Evidence"],
      recordArray(artifact, "dependency_notes").map((item) => [
        field(item, "kind"),
        field(item, "path"),
        field(item, "summary"),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatInfrastructureSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...optionalTable(
      "Runtime And Deployment",
      ["Kind", "Name", "Runtime Details", "Role", "Evidence"],
      recordArray(artifact, "infra").map((item) => [
        field(item, "kind"),
        field(item, "name"),
        compactJoin([
          field(item, "base_image"),
          field(item, "user"),
          listField(item, "ports"),
          listField(item, "mounts"),
          field(item, "entrypoint"),
        ]),
        field(item, "role"),
        recordEvidence(item),
      ]),
    ),
    ...optionalTable(
      "CI/CD",
      ["Name", "Location", "Role", "Evidence"],
      recordArray(artifact, "ci").map((item) => [
        firstField(item, ["name", "kind"]),
        field(item, "location"),
        field(item, "role"),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatLoggingSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...tableOrNotObserved(
      ["Operation", "Fields/Inputs", "Destination", "Evidence"],
      recordArray(artifact, "logging").map((item) => [
        firstField(item, ["operation", "name", "kind"]),
        listField(item, "logged_fields"),
        firstField(item, ["destination", "location"]),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function formatTrustBoundariesSection(artifact: JsonObject | undefined): string[] {
  if (artifact === undefined) {
    return ["- Not available."];
  }

  return compactLines([
    ...tableOrNotObserved(
      ["Boundary", "Type", "Description", "Linked Facts", "Evidence"],
      recordArray(artifact, "boundaries").map((item) => [
        firstField(item, ["name", "id"]),
        field(item, "kind"),
        firstField(item, ["description", "summary"]),
        compactJoin([
          listField(item, "source_entrypoint_ids"),
          listField(item, "flow_ids"),
          listField(item, "sink_ids"),
        ]),
        recordEvidence(item),
      ]),
    ),
    ...formatFactGaps(artifact),
  ]);
}

function optionalTable(title: string, headers: string[], rows: string[][]): string[] {
  const normalizedRows = rows.filter((row) => row.some((cellValue) => cellValue.trim() !== ""));
  if (normalizedRows.length === 0) {
    return [];
  }
  return [`**${title}**`, ...markdownTable(headers, normalizedRows), ""];
}

function tableOrNotObserved(headers: string[], rows: string[][]): string[] {
  const normalizedRows = rows.filter((row) => row.some((cellValue) => cellValue.trim() !== ""));
  return normalizedRows.length > 0
    ? [...markdownTable(headers, normalizedRows), ""]
    : ["- Not observed in accepted artifacts.", ""];
}

function markdownTable(headers: string[], rows: string[][]): string[] {
  return [
    `| ${headers.map(markdownCell).join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(markdownCell).join(" | ")} |`),
  ];
}

function markdownCell(value: string): string {
  const trimmed = value.trim();
  return trimmed === ""
    ? "n/a"
    : trimmed.replaceAll("|", "\\|").replaceAll("\n", "<br>").replace(/\s+/g, " ");
}

function formatFactGaps(artifact: JsonObject): string[] {
  return optionalTable(
    "Fact Gaps",
    ["Area", "Missing Fact", "Evidence"],
    recordArray(artifact, "fact_gaps").map((item) => [
      field(item, "area"),
      field(item, "missing_fact"),
      recordEvidence(item),
    ]),
  );
}

function operationSinkRecords(artifact: JsonObject): JsonObject[] {
  return recordArray(artifact, "operation_sinks");
}

function entrypointExternalInput(item: JsonObject): string {
  return compactJoin([
    compactJoin([field(item, "method"), firstField(item, ["route", "path"])]),
    field(item, "command"),
    field(item, "schedule"),
  ]);
}

function intermediateFunctions(flow: JsonObject): string {
  const intermediates = [
    ...recordArray(flow, "intermediate_functions"),
    ...recordArray(flow, "steps"),
  ].map((item) => {
    const evidence = recordEvidence(item);
    return evidence === "" ? field(item, "name") : `${field(item, "name")} (${evidence})`;
  });
  return intermediates.join(", ");
}

function recordEvidence(record: JsonObject): string {
  return formatEvidence(evidenceArray(record.evidence));
}

function recordEvidenceRefs(record: JsonObject): string[] {
  return [
    ...evidenceArray(record.evidence),
    ...evidenceArray(record.source_evidence),
    ...evidenceArray(record.operation_sink_evidence),
    ...evidenceArray(record.sink_evidence),
    ...recordArray(record, "intermediate_functions").flatMap((item) =>
      evidenceArray(item.evidence),
    ),
    ...recordArray(record, "steps").flatMap((item) => evidenceArray(item.evidence)),
    ...evidenceArray(objectField(record, "breakpoint")?.evidence),
  ];
}

function formatEvidence(value: string[]): string {
  return [...new Set(value)].join(", ");
}

function evidenceArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
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

function recordArray(value: unknown, field: string): JsonObject[] {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return [];
  }
  const candidate = (value as Record<string, unknown>)[field];
  if (!Array.isArray(candidate)) {
    return [];
  }
  return candidate.filter(
    (item): item is JsonObject => item !== null && typeof item === "object" && !Array.isArray(item),
  );
}

function field(record: JsonObject, key: string): string {
  return cell(record[key]);
}

function firstField(record: JsonObject, keys: string[]): string {
  for (const key of keys) {
    const value = field(record, key);
    if (value !== "") {
      return value;
    }
  }
  return "";
}

function listField(record: JsonObject, key: string): string {
  const value = record[key];
  if (Array.isArray(value)) {
    return value
      .map(cell)
      .filter((item) => item !== "")
      .join(", ");
  }
  return cell(value);
}

function cell(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return "";
}

function compactJoin(values: string[]): string {
  return values.filter((value) => value.trim() !== "").join(", ");
}

function uniqueRows(rows: string[][]): string[][] {
  const seen = new Set<string>();
  return rows.filter((row) => {
    const key = row.join("\u0000");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function compactLines(lines: Array<string | undefined>): string[] {
  const compacted = lines.filter((line): line is string => line !== undefined);
  return compacted.length > 0 ? trimTrailingEmptyLines(compacted) : ["- Not available."];
}

function trimTrailingEmptyLines(lines: string[]): string[] {
  const result = [...lines];
  while (result[result.length - 1] === "") {
    result.pop();
  }
  return result;
}

function normalizeMarkdownSpacing(lines: string[]): string[] {
  const output: string[] = [];
  for (const line of lines) {
    if (needsBlankLineBefore(line) && output.length > 0 && output[output.length - 1] !== "") {
      output.push("");
    }
    output.push(line);
  }
  return trimTrailingEmptyLines(output);
}

function needsBlankLineBefore(line: string): boolean {
  return line.startsWith("## ") || /^\*\*[^*].*\*\*$/.test(line);
}

function formatArtifactLinks(run: ScanRunState): string[] {
  const artifacts = [
    run.artifacts.inventory,
    run.artifacts.baseline_tool_availability,
    run.artifacts.baseline_summary,
    run.artifacts.pi_context_pack,
    run.artifacts.repo_map?.coverage_structure,
    run.artifacts.repo_map?.stack_build_deps,
    run.artifacts.repo_map?.entrypoints,
    run.artifacts.repo_map?.auth_access,
    run.artifacts.repo_map?.config_secrets,
    run.artifacts.repo_map?.storage_data_model,
    run.artifacts.repo_map?.external_integrations_egress,
    run.artifacts.repo_map?.infra_deploy,
    run.artifacts.repo_map?.operation_sinks,
    run.artifacts.repo_map?.crypto,
    run.artifacts.repo_map?.logging_observability,
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
