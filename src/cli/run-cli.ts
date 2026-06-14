import { type RunScanOptions, type RunScanResult, runResume, runScan } from "../run/run-scan.js";
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

  const live = createLiveStatus(io, isInteractive(io.stdout));
  const formatProgress = createProgressFormatter();
  const onProgress = (event: RunEvent) => {
    live.update(event);
    const line = formatProgress(event);
    if (line !== undefined) {
      live.print(line);
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

  live.start();
  let result: RunScanResult;
  try {
    result =
      command === "scan"
        ? await runScan(scanOptions)
        : await runResume({
            onProgress,
            runDir: target,
            ...(dependencies.sandboxProvider === undefined
              ? {}
              : { sandboxProvider: dependencies.sandboxProvider }),
          });
  } finally {
    live.stop();
  }

  if (result.exitCode === 0) {
    io.stdout.write(`Run directory: ${result.runDir}\n`);
    return 0;
  }

  io.stderr.write(`Error: ${result.userMessage}\n`);
  const runError = result.run?.error;
  if (runError !== undefined) {
    const reasons = (
      runError.diagnostics !== undefined && runError.diagnostics.length > 0
        ? runError.diagnostics
        : [runError.message]
    ).filter((reason) => reason.trim() !== "" && reason !== result.userMessage);
    for (const reason of reasons) {
      io.stderr.write(`  - ${reason}\n`);
    }
  }
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

  if (isRepositoryMapCoordinatorEvent(event) || isDeterministicRepositoryMapEvent(event)) {
    return `[${formatTimestamp(event.timestamp)}] [${progressLabel(event)}] ${event.message}\n`;
  }

  return formatPiProgressLine(event, piState);
}

function formatPiProgressLine(event: RunEvent, state: PiProgressState): string | undefined {
  const actor = piActorFromEvent(event);
  const jobKey = actor.step ?? stringValue(event.details?.step) ?? event.job ?? "pi";
  const timestampMs = timestampToMs(event.timestamp);
  const message = normalizePiMessage(event.message);
  const periodicProgress = isPeriodicPiProgress(event, message);
  const lastPrintedAt = state.lastPrintedAtByJob.get(jobKey);

  if (
    (event.type === "pi.thinking" || message === "thinking...") &&
    lastPrintedAt !== undefined &&
    timestampMs - lastPrintedAt < quietPiProgressIntervalMs
  ) {
    return undefined;
  }

  if (
    periodicProgress &&
    lastPrintedAt !== undefined &&
    timestampMs - lastPrintedAt < quietPiProgressIntervalMs
  ) {
    return undefined;
  }

  const displayMessage = actor.step === undefined ? message : `${actor.step}: ${message}`;
  const printedMessageKey = `${progressLabel(event)} ${displayMessage}`;
  if (!periodicProgress && state.lastPrintedMessageByJob.get(jobKey) === printedMessageKey) {
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

  if (isRepositoryMapCoordinatorEvent(event)) {
    return "repository-map";
  }

  if (isDeterministicRepositoryMapEvent(event)) {
    return event.job ?? "deterministic-map";
  }

  return isEvaluatorEvent(event) ? "evaluator-agent" : "collector-agent";
}

function isRepositoryMapCoordinatorEvent(event: RunEvent): boolean {
  return event.type.startsWith("repository-map.") || event.type === "resume.artifact_reused";
}

function isDeterministicRepositoryMapEvent(event: RunEvent): boolean {
  return event.type.startsWith("coverage-structure.");
}

function isEvaluatorEvent(event: RunEvent): boolean {
  const values = [event.job, event.message, event.type, event.details?.step, event.details?.role];
  return values.some((value) => typeof value === "string" && value.includes("evaluator"));
}

function isPeriodicPiProgress(event: RunEvent, normalizedMessage: string): boolean {
  return (
    event.type.endsWith(".heartbeat") ||
    event.type === "pi.thinking" ||
    normalizedMessage === "agent still running." ||
    normalizedMessage === "thinking..."
  );
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

interface LiveStatus {
  print(line: string): void;
  start(): void;
  stop(): void;
  update(event: RunEvent): void;
}

const spinnerFrames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const spinnerIntervalMs = 120;
const ansi = {
  cyan: "\x1b[36m",
  dim: "\x1b[2m",
  gray: "\x1b[90m",
  hideCursor: "\x1b[?25l",
  reset: "\x1b[0m",
  showCursor: "\x1b[?25h",
  yellow: "\x1b[33m",
} as const;

function isInteractive(stdout: CliWritable): boolean {
  return (stdout as { isTTY?: boolean }).isTTY === true && process.env.NO_COLOR === undefined;
}

function createLiveStatus(io: CliIo, interactive: boolean): LiveStatus {
  if (!interactive) {
    return {
      print: (line) => {
        io.stdout.write(line);
      },
      start: () => {},
      stop: () => {},
      update: () => {},
    };
  }

  let frame = 0;
  let timer: ReturnType<typeof setInterval> | undefined;
  let onScreen = false;
  let phaseKey = "";
  let phaseLabel = "starting";
  let phaseStartedAt = Date.now();
  let activity = "warming up";
  let activityKind: "idle" | "info" | "think" | "tool" = "info";
  let toolCount = 0;

  const columns = (): number => (io.stdout as { columns?: number }).columns ?? 80;

  const render = (): void => {
    const spinner = spinnerFrames[frame % spinnerFrames.length];
    const color =
      activityKind === "think" ? ansi.yellow : activityKind === "tool" ? ansi.cyan : ansi.gray;
    const segments = [phaseLabel];
    if (toolCount > 0) {
      segments.push(`${toolCount} tool${toolCount === 1 ? "" : "s"}`);
    }
    if (activity !== "") {
      segments.push(activity);
    }
    segments.push(formatElapsed(Date.now() - phaseStartedAt));

    let body = segments.join(" · ");
    const max = Math.max(12, columns() - 3);
    if (body.length > max) {
      body = `${body.slice(0, max - 1)}…`;
    }
    io.stdout.write(`\r\x1b[2K${color}${spinner}${ansi.reset} ${ansi.dim}${body}${ansi.reset}`);
    onScreen = true;
  };

  const clear = (): void => {
    if (onScreen) {
      io.stdout.write("\r\x1b[2K");
      onScreen = false;
    }
  };

  return {
    print(line) {
      clear();
      io.stdout.write(line);
      if (timer !== undefined) {
        render();
      }
    },
    start() {
      io.stdout.write(ansi.hideCursor);
      timer = setInterval(() => {
        frame += 1;
        render();
      }, spinnerIntervalMs);
      (timer as { unref?: () => void }).unref?.();
    },
    stop() {
      if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
      clear();
      io.stdout.write(ansi.showCursor);
    },
    update(event) {
      const step = stringValue(event.details?.step);
      const key = step ?? progressLabel(event);
      if (key !== phaseKey) {
        phaseKey = key;
        phaseStartedAt = Date.now();
        toolCount = 0;
      }
      phaseLabel = key;

      if (event.type === "pi.tool.called") {
        toolCount += 1;
        const tool = stringValue(event.details?.tool) ?? "tool";
        const target = stringValue(event.details?.target);
        activity = target === undefined ? tool : `${tool} ${shortenTail(target, 44)}`;
        activityKind = "tool";
      } else if (
        event.type === "pi.thinking" ||
        normalizePiMessage(event.message) === "thinking..."
      ) {
        activity = "thinking";
        activityKind = "think";
      } else if (event.type.endsWith(".heartbeat")) {
        activity = "working";
        activityKind = "idle";
      } else {
        activity = shortenTail(normalizePiMessage(event.message), 60);
        activityKind = "info";
      }
    },
  };
}

function formatElapsed(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m${String(seconds % 60).padStart(2, "0")}s`;
}

function shortenTail(value: string, max: number): string {
  return value.length <= max ? value : `…${value.slice(value.length - (max - 1))}`;
}
