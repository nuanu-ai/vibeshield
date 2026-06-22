#!/usr/bin/env node
import "dotenv/config";
import { stat } from "node:fs/promises";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { FilesystemBlobs } from "./adapters/filesystem-blobs.js";
import { MicrosandboxRuntime } from "./adapters/microsandbox/runtime.js";
import { NullModelProvider } from "./adapters/null-model-provider.js";
import { SqliteStateStore } from "./adapters/sqlite-state-store.js";
import { ensureStateRoot, resolveStateRoot, stateDbPath } from "./adapters/state-root.js";
import { runScan } from "./application/scan-service.js";
import { verdictLabel } from "./domain/assessment.js";
import type { SourceInput } from "./domain/run.js";
import type { ScanEvent } from "./ports/event-sink.js";
import { DEFAULT_TOOLCHAIN_IMAGE } from "./stages/paths.js";

class TerminalEventSink {
  emit(event: ScanEvent): void {
    if (event.type === "stage-started") {
      process.stderr.write(`-> ${event.stageId}\n`);
      return;
    }
    if (event.type === "stage-failed" || event.type === "error") {
      process.stderr.write(`! ${event.message}\n`);
    }
  }
}

const args = process.argv.slice(2);
const command = args[0];

try {
  if (command === "scan") {
    await scan(args.slice(1));
  } else if (command === "resume") {
    throw new Error("resume is not implemented yet; run a fresh scan for now.");
  } else {
    printHelp();
    process.exitCode = command === undefined || command === "--help" || command === "-h" ? 0 : 1;
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`vibeshield: ${message}\n`);
  process.exitCode = 1;
}

async function scan(args: string[]): Promise<void> {
  const sourceArg = args[0];
  if (sourceArg === undefined) {
    throw new Error("usage: vibeshield scan <github-url-or-local-folder>");
  }

  const source = await parseSource(sourceArg);
  const stateRoot = resolveStateRoot();
  await ensureStateRoot(stateRoot);

  const db = new DatabaseSync(stateDbPath(stateRoot));
  try {
    const outcome = await runScan(
      {
        sandbox: new MicrosandboxRuntime({ imageTag: DEFAULT_TOOLCHAIN_IMAGE }),
        state: new SqliteStateStore(db),
        artifacts: new FilesystemBlobs(stateRoot),
        events: new TerminalEventSink(),
        model: new NullModelProvider(),
      },
      {
        source,
        runRoot: path.join(stateRoot, "runs"),
        toolchainImage: process.env.VIBESHIELD_TOOLCHAIN_TAG ?? DEFAULT_TOOLCHAIN_IMAGE,
      },
    );
    renderTerminalOutcome(outcome);
  } finally {
    db.close();
  }
}

async function parseSource(raw: string): Promise<SourceInput> {
  const maybeUrl = parseGithubUrl(raw);
  if (maybeUrl !== null) {
    return { kind: "github", url: maybeUrl };
  }

  const localPath = path.resolve(raw);
  const st = await stat(localPath).catch(() => null);
  if (st === null || !st.isDirectory()) {
    throw new Error(`source is neither a public GitHub URL nor a local folder: ${raw}`);
  }
  return { kind: "local", path: localPath };
}

function parseGithubUrl(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.hostname !== "github.com") {
    return null;
  }
  const parts = url.pathname.replace(/\/$/, "").split("/").filter(Boolean);
  if (parts.length < 2) {
    return null;
  }
  const owner = parts[0];
  const repo = parts[1];
  if (owner === undefined || repo === undefined) {
    return null;
  }
  return `https://github.com/${owner}/${repo.replace(/\.git$/, "")}.git`;
}

function renderTerminalOutcome(outcome: Awaited<ReturnType<typeof runScan>>): void {
  const { assessment } = outcome;
  process.stdout.write("\nVibeShield Quick Scan\n");
  process.stdout.write(`Run: ${outcome.runId}\n`);
  process.stdout.write(`Verdict: ${verdictLabel(assessment.verdict)}\n`);
  process.stdout.write(`Files scanned: ${assessment.manifest.fileCount}\n`);
  process.stdout.write(`Findings: ${assessment.findingSummary.total}\n`);
  process.stdout.write(`Reports: ${outcome.reportPaths.json}\n`);
  process.stdout.write(`${assessment.limitation}\n`);

  for (const ranked of assessment.rankedActions) {
    process.stdout.write("\n");
    process.stdout.write(`${ranked.remediation.title}\n`);
    process.stdout.write(`${ranked.remediation.risk}\n`);
    process.stdout.write("\nAgent prompt:\n");
    process.stdout.write(`${ranked.remediation.agentPrompt}\n`);
  }
}

function printHelp(): void {
  process.stdout.write(
    [
      "VibeShield",
      "",
      "Usage:",
      "  vibeshield scan <github-url-or-local-folder>",
      "",
      "Environment:",
      "  VIBESHIELD_STATE_ROOT     override ~/.vibeshield",
      "  VIBESHIELD_TOOLCHAIN_TAG  override vibeshield-toolchain:latest",
      "",
    ].join("\n"),
  );
}
