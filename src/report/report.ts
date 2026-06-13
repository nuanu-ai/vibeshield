import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type {
  BaselineSummaryArtifact,
  DataFlowsArtifact,
  EntryPointsArtifact,
  ProjectUnderstandingArtifact,
  SensitiveSinksArtifact,
} from "../artifacts/contracts.js";
import type { ScanRunState } from "../run/types.js";

export async function writeSuccessReport(input: {
  reportPath: string;
  run: ScanRunState;
}): Promise<void> {
  const runDir = path.dirname(input.reportPath);
  const baseline = await readArtifact<BaselineSummaryArtifact>(
    runDir,
    input.run.artifacts.baseline_summary,
  );
  const projectUnderstanding = await readArtifact<ProjectUnderstandingArtifact>(
    runDir,
    input.run.artifacts.project_understanding,
  );
  const entryPoints = await readArtifact<EntryPointsArtifact>(
    runDir,
    input.run.artifacts.entry_points,
  );
  const sensitiveSinks = await readArtifact<SensitiveSinksArtifact>(
    runDir,
    input.run.artifacts.sensitive_sinks,
  );
  const dataFlows = await readArtifact<DataFlowsArtifact>(runDir, input.run.artifacts.data_flows);
  const sandboxCleanup = input.run.sandbox?.cleanup;
  const lines = [
    "# VibeShield Phase 1 repository mapping",
    "",
    "Status: success",
    `Run ID: ${input.run.run_id}`,
    `Source: ${input.run.source.url}`,
    `Commit: ${input.run.commit_sha ?? "unknown"}`,
    `Sandbox: ${input.run.sandbox?.id ?? "unknown"}`,
    `Sandbox deleted: ${sandboxCleanup?.deleted === true ? "yes" : "unknown"}`,
    "",
    "Phase 0 intake and inventory is included in this run.",
    "This is a Phase 1 repository-mapping report, not a security audit.",
    "No security findings or verdict are produced in Phase 1.",
    "",
    "## Project summary",
    projectUnderstanding?.summary.text ?? "Project summary was not available.",
    "",
    `Kind: ${projectUnderstanding?.summary.project_kind ?? "unknown"}`,
    `Confidence: ${projectUnderstanding?.summary.confidence ?? "unknown"}`,
    "",
    "## Deterministic baseline overview",
    ...(baseline?.tools.map(
      (tool) =>
        `- ${tool.tool}: ${tool.status}${tool.skipped_reason ? ` (${tool.skipped_reason})` : ""}; observations: ${tool.observations.length}`,
    ) ?? ["- Baseline summary artifact was not available."]),
    "",
    "## Entrypoints",
    ...formatEntries(
      entryPoints?.entry_points.map(
        (entry) =>
          `${entry.kind} ${entry.name} at ${entry.location}${entry.route ? ` ${entry.route}` : ""} (${entry.evidence.join(", ")})`,
      ),
    ),
    "",
    "## Sensitive sinks",
    ...formatEntries(
      sensitiveSinks?.sinks.map(
        (sink) =>
          `${sink.kind} ${sink.operation} at ${sink.location} (${sink.evidence.join(", ")})`,
      ),
    ),
    "",
    "## Data flows",
    ...formatEntries(
      dataFlows?.flows.map(
        (flow) =>
          `${flow.source_entrypoint} -> ${flow.sink}: ${flow.trace_status} (${[
            ...flow.source_evidence,
            ...flow.sink_evidence,
          ].join(", ")})`,
      ),
    ),
    "",
    "## Important files",
    ...formatEntries(
      projectUnderstanding?.map.important_files.map(
        (entry) => `${entry.path} - ${entry.reason} (${entry.evidence.join(", ")})`,
      ),
    ),
    "",
    "## Coverage gaps",
    ...formatEntries(
      projectUnderstanding?.coverage.not_covered.map((gap) => `${gap.area} - ${gap.reason}`),
    ),
    "",
    "## Fact gaps",
    ...formatEntries(
      projectUnderstanding?.fact_gaps.map(
        (gap) => `${gap.area} - ${gap.missing_fact} (${gap.evidence.join(", ")})`,
      ),
    ),
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
    "# VibeShield Phase 1 failure report",
    "",
    "Phase 0 scan did not complete.",
    "Phase 1 scan did not complete.",
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
    run.artifacts.entry_points,
    run.artifacts.sensitive_sinks,
    run.artifacts.data_flows,
    run.artifacts.project_understanding,
    run.artifacts.events,
    ...(run.steps?.flatMap((step) => step.jobs.flatMap((job) => job.artifacts)) ?? []),
  ].filter((artifact): artifact is string => artifact !== undefined);

  if (artifacts.length === 0) {
    return ["- No artifacts were recorded."];
  }

  return [...new Set(artifacts)].map((artifact) => `- ${artifact}`);
}
