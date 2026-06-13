import { type RunScanOptions, runResume, runScan } from "../run/run-scan.js";
import type { RunEvent } from "../run/types.js";

export interface CliWritable {
  write(chunk: string): unknown;
}

export interface CliIo {
  stderr: CliWritable;
  stdout: CliWritable;
}

export type CliDependencies = Pick<RunScanOptions, "runsRoot" | "sandboxProvider">;

const usage = `Usage:
  vibeshield scan https://github.com/owner/repo
  vibeshield resume /path/to/run-directory
`;

export async function runCli(
  argv: string[],
  io: CliIo,
  dependencies: CliDependencies = {},
): Promise<number> {
  const [command, target, ...rest] = argv;

  if ((command !== "scan" && command !== "resume") || target === undefined || rest.length > 0) {
    io.stderr.write(usage);
    return 1;
  }

  const formatProgress = createProgressFormatter();
  const onProgress = (event: RunEvent) => {
    const line = formatProgress(event);
    if (line !== undefined) {
      io.stdout.write(line);
    }
  };

  const scanOptions: RunScanOptions = { repoUrlInput: target };
  scanOptions.onProgress = onProgress;
  if (dependencies.runsRoot !== undefined) {
    scanOptions.runsRoot = dependencies.runsRoot;
  }
  if (dependencies.sandboxProvider !== undefined) {
    scanOptions.sandboxProvider = dependencies.sandboxProvider;
  }

  const result =
    command === "scan"
      ? await runScan(scanOptions)
      : await runResume({
          onProgress,
          runDir: target,
          ...(dependencies.sandboxProvider === undefined
            ? {}
            : { sandboxProvider: dependencies.sandboxProvider }),
        });

  if (result.exitCode === 0) {
    io.stdout.write(`Run directory: ${result.runDir}\n`);
    return 0;
  }

  io.stderr.write(`Error: ${result.userMessage}\n`);
  if (result.runDir !== undefined) {
    io.stderr.write(`Run directory: ${result.runDir}\n`);
  }
  return 1;
}

interface PiProgressState {
  lastPrintedAtByJob: Map<string, number>;
  lastPrintedMessageByJob: Map<string, string>;
}

const quietPiProgressIntervalMs = 60_000;

function createProgressFormatter(): (event: RunEvent) => string | undefined {
  const piState: PiProgressState = {
    lastPrintedAtByJob: new Map(),
    lastPrintedMessageByJob: new Map(),
  };

  return (event) => formatProgressLine(event, piState);
}

function formatProgressLine(event: RunEvent, piState: PiProgressState): string | undefined {
  if (event.stage !== "pi") {
    return `[${formatTimestamp(event.timestamp)}] [${progressLabel(event)}] ${event.message}\n`;
  }

  return formatPiProgressLine(event, piState);
}

function formatPiProgressLine(event: RunEvent, state: PiProgressState): string | undefined {
  const actor = piActorFromEvent(event);
  const jobKey = actor.step ?? stringValue(event.details?.step) ?? event.job ?? "pi";
  const timestampMs = timestampToMs(event.timestamp);
  const message = normalizePiMessage(event.message);
  const lastPrintedAt = state.lastPrintedAtByJob.get(jobKey);

  if (
    (event.type === "pi.thinking" || message === "thinking...") &&
    lastPrintedAt !== undefined &&
    timestampMs - lastPrintedAt < quietPiProgressIntervalMs
  ) {
    return undefined;
  }

  if (
    (event.type === "pi.heartbeat" || message === "still running.") &&
    lastPrintedAt !== undefined &&
    timestampMs - lastPrintedAt < quietPiProgressIntervalMs
  ) {
    return undefined;
  }

  const displayMessage = actor.step === undefined ? message : `${actor.step}: ${message}`;
  const printedMessageKey = `${progressLabel(event)} ${displayMessage}`;
  if (state.lastPrintedMessageByJob.get(jobKey) === printedMessageKey) {
    return undefined;
  }

  state.lastPrintedAtByJob.set(jobKey, timestampMs);
  state.lastPrintedMessageByJob.set(jobKey, printedMessageKey);

  return `[${formatTimestamp(event.timestamp)}] [${progressLabel(event)}] ${displayMessage}\n`;
}

function progressLabel(event: RunEvent): string {
  if (event.stage !== "pi") {
    return event.stage;
  }

  return isEvaluatorEvent(event) ? "evaluator-agent" : "collector-agent";
}

function isEvaluatorEvent(event: RunEvent): boolean {
  const values = [event.job, event.message, event.type, event.details?.step, event.details?.role];
  return values.some((value) => typeof value === "string" && value.includes("evaluator"));
}

function normalizePiMessage(message: string): string {
  return message
    .replace(/^[^:]+? (?:collector|evaluator)(?: attempt \d+)?:\s*/, "")
    .replaceAll("/home/daytona/repo/", "")
    .trim();
}

function piActorFromEvent(event: RunEvent): { step?: string } {
  const step = stringValue(event.details?.step) ?? stepFromPiActorMessage(event.message);
  return step === undefined ? {} : { step };
}

function stepFromPiActorMessage(message: string): string | undefined {
  const match = /^(?<step>[^:]+?) (?:collector|evaluator)(?: attempt \d+)?:/.exec(message);
  return match?.groups?.step;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function formatTimestamp(timestamp: string): string {
  return timestamp.replace("T", " ").replace(/\.\d{3}Z$/, "");
}

function timestampToMs(timestamp: string): number {
  const parsed = Date.parse(timestamp);
  return Number.isNaN(parsed) ? Date.now() : parsed;
}
