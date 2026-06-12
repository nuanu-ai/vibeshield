import { writeFile } from "node:fs/promises";
import type { ScanRunState } from "../run/types.js";

export async function writeSuccessReport(input: {
  inventoryPath: string;
  reportPath: string;
  run: ScanRunState;
}): Promise<void> {
  const sandboxCleanup = input.run.sandbox?.cleanup;
  const lines = [
    "# VibeShield Phase 0 intake and inventory",
    "",
    "Status: success",
    `Run ID: ${input.run.run_id}`,
    `Source: ${input.run.source.url}`,
    `Commit: ${input.run.commit_sha ?? "unknown"}`,
    `Sandbox: ${input.run.sandbox?.id ?? "unknown"}`,
    `Sandbox deleted: ${sandboxCleanup?.deleted === true ? "yes" : "unknown"}`,
    "",
    "This is a Phase 0 intake and inventory report, not a security audit.",
    "No security findings or verdict are produced in Phase 0.",
    "",
    "What happened:",
    "- the GitHub repository URL was accepted;",
    "- a fresh sandbox was requested for this scan run;",
    "- the repository was cloned inside the sandbox;",
    "- VibeShield ran a controlled read-only inventory step;",
    "- the inventory artifact was copied into the local run directory;",
    "- sandbox cleanup was attempted before this report was written.",
    "",
    "Inspectable artifacts:",
    `- ${input.inventoryPath}: generated repo inventory from the cloned repository.`,
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
    "# VibeShield Phase 0 failure report",
    "",
    "Phase 0 scan did not complete.",
    `Run ID: ${input.run.run_id}`,
    `Source: ${input.run.source.url}`,
    `Failed stage: ${input.run.error?.stage ?? input.run.current_stage}`,
    `Error: ${input.run.error?.user_message ?? "Unknown error"}`,
    "",
    "What happened:",
    "- the run stopped before a completed Phase 0 intake report could be produced;",
    "- no findings were produced;",
    `- sandbox cleanup attempted: ${cleanup?.attempted === true ? "yes" : "no"}.`,
    `- sandbox deleted: ${cleanup?.deleted === true ? "yes" : "no"}.`,
    "",
    "Open run.json and events.jsonl in this run directory for diagnostics.",
    "",
  ];

  await writeFile(input.reportPath, `${lines.join("\n")}\n`, "utf8");
}
