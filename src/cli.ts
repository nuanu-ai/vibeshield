#!/usr/bin/env node
import "dotenv/config";
import { stat } from "node:fs/promises";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { FilesystemBlobs } from "./adapters/filesystem-blobs.js";
import { MicrosandboxRuntime } from "./adapters/microsandbox/runtime.js";
import { NullModelProvider } from "./adapters/null-model-provider.js";
import {
  DEFAULT_REMEDIATION_MODEL,
  OpenRouterModelProvider,
} from "./adapters/openrouter-model-provider.js";
import { SqliteStateStore } from "./adapters/sqlite-state-store.js";
import { ensureStateRoot, resolveStateRoot, stateDbPath } from "./adapters/state-root.js";
import { parseScanArgs } from "./application/scan-args.js";
import { runScan } from "./application/scan-service.js";
import type { SourceInput } from "./domain/run.js";
import type { ModelProvider } from "./ports/model-provider.js";
import {
  renderError,
  renderHelp,
  renderScanOutcome,
  supportsAnsiColor,
  TerminalEventSink,
} from "./reporting/terminal.js";
import { assertLocalGitWorktreeRoot } from "./stages/local-source-package.js";
import { DEFAULT_TOOLCHAIN_IMAGE } from "./stages/paths.js";

const args = process.argv.slice(2);
const command = args[0];

try {
  if (command === "scan") {
    await scan(args.slice(1));
  } else if (command === "resume") {
    throw new Error("Resume isn't available yet. Run a fresh scan for now.");
  } else {
    const wantsHelp = command === undefined || command === "--help" || command === "-h";
    if (!wantsHelp) {
      process.stderr.write(
        renderError(`Unknown command: ${command}`, { color: supportsAnsiColor(process.stderr) }),
      );
    }
    process.stdout.write(renderHelp({ color: supportsAnsiColor(process.stdout) }));
    process.exitCode = wantsHelp ? 0 : 1;
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(renderError(message, { color: supportsAnsiColor(process.stderr) }));
  process.exitCode = 1;
}

async function scan(args: string[]): Promise<void> {
  const parsed = parseScanArgs(args);
  const sourceArg = parsed.sourceArg;
  if (sourceArg === undefined) {
    throw new Error(
      "Tell me what to scan. For example: vibeshield scan https://github.com/owner/repo",
    );
  }

  const source = await parseSource(sourceArg);
  const stateRoot = resolveStateRoot();
  await ensureStateRoot(stateRoot);
  const toolchainImage = process.env.VIBESHIELD_TOOLCHAIN_TAG ?? DEFAULT_TOOLCHAIN_IMAGE;
  const remediationModel = process.env.VIBESHIELD_REMEDIATION_MODEL ?? DEFAULT_REMEDIATION_MODEL;
  const model = modelProviderFor({
    noModel: parsed.modelMode === "off" || envFlag(process.env.VIBESHIELD_NO_MODEL),
    remediationModel,
  });

  const db = new DatabaseSync(stateDbPath(stateRoot));
  try {
    const outcome = await runScan(
      {
        sandbox: new MicrosandboxRuntime({ imageTag: toolchainImage }),
        state: new SqliteStateStore(db),
        artifacts: new FilesystemBlobs(stateRoot),
        events: new TerminalEventSink(process.stderr, { color: supportsAnsiColor(process.stderr) }),
        model,
      },
      {
        source,
        runRoot: path.join(stateRoot, "runs"),
        toolchainImage,
        deep: parsed.deep,
      },
    );
    process.stdout.write(renderScanOutcome(outcome, { color: supportsAnsiColor(process.stdout) }));
  } finally {
    db.close();
  }
}

function modelProviderFor(input: {
  readonly noModel: boolean;
  readonly remediationModel: string;
}): ModelProvider {
  if (input.noModel) {
    return new NullModelProvider();
  }
  return new OpenRouterModelProvider({
    model: input.remediationModel,
    ...(process.env.OPENROUTER_API_KEY !== undefined
      ? { apiKey: process.env.OPENROUTER_API_KEY }
      : {}),
  });
}

function envFlag(value: string | undefined): boolean {
  return value !== undefined && /^(?:1|true|yes|on)$/i.test(value.trim());
}

async function parseSource(raw: string): Promise<SourceInput> {
  const maybeUrl = parseGithubUrl(raw);
  if (maybeUrl !== null) {
    return { kind: "github", url: maybeUrl };
  }

  const localPath = path.resolve(raw);
  const st = await stat(localPath).catch(() => null);
  if (st === null || !st.isDirectory()) {
    throw new Error(
      `I can scan a public GitHub URL or a local Git project folder. I couldn't use: ${raw}`,
    );
  }
  await assertLocalGitWorktreeRoot(localPath);
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
