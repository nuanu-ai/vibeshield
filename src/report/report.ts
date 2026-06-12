import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type {
  BaselineSummaryArtifact,
  ProjectUnderstandingArtifact,
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
  const sandboxCleanup = input.run.sandbox?.cleanup;
  const lines = [
    "# VibeShield Phase 1 project understanding",
    "",
    "Status: success",
    `Run ID: ${input.run.run_id}`,
    `Source: ${input.run.source.url}`,
    `Commit: ${input.run.commit_sha ?? "unknown"}`,
    `Sandbox: ${input.run.sandbox?.id ?? "unknown"}`,
    `Sandbox deleted: ${sandboxCleanup?.deleted === true ? "yes" : "unknown"}`,
    "",
    "Phase 0 intake and inventory is included in this run.",
    "This is a Phase 1 project-understanding report, not a security audit.",
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
      projectUnderstanding?.map.entrypoints.map(
        (entry) => `${entry.path} - ${entry.summary} (${entry.evidence.join(", ")})`,
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
    "## Observed surfaces",
    ...formatEntries(
      projectUnderstanding?.map.observed_surfaces.map(
        (surface) =>
          `${surface.kind}${surface.path ? ` ${surface.path}` : ""} - ${surface.summary} (${surface.evidence.join(", ")})`,
      ),
    ),
    "",
    "## Env and config facts",
    ...formatEntries(
      projectUnderstanding?.env_and_config_surface.map(
        (entry) => `${entry.name} - ${entry.observed_use} (${entry.evidence.join(", ")})`,
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
    run.artifacts.project_understanding,
    run.artifacts.pi_progress,
    run.artifacts.pi_raw_output,
    run.artifacts.pi_stderr,
    run.artifacts.events,
  ].filter((artifact): artifact is string => artifact !== undefined);

  if (artifacts.length === 0) {
    return ["- No artifacts were recorded."];
  }

  return artifacts.map((artifact) => `- ${artifact}`);
}
