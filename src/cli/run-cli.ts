import {
  parseRunResumeFromStep,
  type RunResumeFromStep,
  resumeStepDefinitions,
} from "../run/resume-steps.js";
import {
  type RunScanFailure,
  type RunScanOptions,
  type RunScanResult,
  type RunScanSuccess,
  runResume,
  runScan,
} from "../run/run-scan.js";
import type { RunEvent } from "../run/types.js";

export interface CliWritable {
  write(chunk: string): unknown;
}

export interface CliIo {
  stderr: CliWritable;
  stdout: CliWritable;
}

export type CliDependencies = Pick<RunScanOptions, "runsRoot" | "sandboxProvider">;

interface ParsedCliArgs {
  command: "resume" | "scan";
  fromStep?: RunResumeFromStep;
  onlyStep?: RunResumeFromStep;
  target: string;
}

export async function runCli(
  argv: string[],
  io: CliIo,
  dependencies: CliDependencies = {},
): Promise<number> {
  const parsed = parseCliArgs(argv);
  if (parsed === "help") {
    io.stdout.write(renderHelp(isInteractive(io.stdout)));
    return 0;
  }
  if (typeof parsed === "string") {
    io.stderr.write(renderCliError(parsed, isInteractive(io.stderr)));
    return 1;
  }

  const { command, fromStep, onlyStep, target } = parsed;
  if ((fromStep !== undefined || onlyStep !== undefined) && command !== "resume") {
    io.stderr.write(renderHelp(isInteractive(io.stderr)));
    return 1;
  }

  const renderer = createRenderer(io, isInteractive(io.stdout));
  renderer.header(command, target);

  const onProgress = (event: RunEvent) => {
    renderer.event(event);
  };

  const scanOptions: RunScanOptions = { sourceInput: target };
  scanOptions.onProgress = onProgress;
  if (dependencies.runsRoot !== undefined) {
    scanOptions.runsRoot = dependencies.runsRoot;
  }
  if (dependencies.sandboxProvider !== undefined) {
    scanOptions.sandboxProvider = dependencies.sandboxProvider;
  }

  renderer.startSpinner();
  let result: RunScanResult;
  try {
    result =
      command === "scan"
        ? await runScan(scanOptions)
        : await runResume({
            ...(fromStep === undefined ? {} : { fromStep }),
            ...(onlyStep === undefined ? {} : { onlyStep }),
            onProgress,
            runDir: target,
            ...(dependencies.sandboxProvider === undefined
              ? {}
              : { sandboxProvider: dependencies.sandboxProvider }),
          });
  } finally {
    renderer.stopSpinner();
  }

  if (result.exitCode === 0) {
    renderer.success(result, onlyStep === undefined ? {} : { onlyStep });
    return 0;
  }

  renderer.failure(result);
  return 1;
}

function parseCliArgs(argv: string[]): ParsedCliArgs | "help" | string {
  if (argv[0] === "--") {
    return parseCliArgs(argv.slice(1));
  }

  const [command, target, ...rest] = argv;
  if (command === "help" || command === "--help" || command === "-h") {
    return "help";
  }
  if (command !== "scan" && command !== "resume") {
    return "Unknown command.";
  }
  if (target === undefined || target === "--help" || target === "-h") {
    return target === "--help" || target === "-h" ? "help" : `Missing target for ${command}.`;
  }

  let fromStep: RunResumeFromStep | undefined;
  let onlyStep: RunResumeFromStep | undefined;
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === undefined) {
      continue;
    }
    const inlineFrom = arg.match(/^--from(?:-step)?=(?<step>.+)$/)?.groups?.step;
    if (inlineFrom !== undefined) {
      if (fromStep !== undefined) {
        return "--from can only be provided once.";
      }
      const parsed = parseRunResumeFromStep(inlineFrom);
      if (parsed === undefined) {
        return `Unknown resume step: ${inlineFrom}`;
      }
      fromStep = parsed;
      continue;
    }

    if (arg === "--from" || arg === "--from-step") {
      if (fromStep !== undefined) {
        return "--from can only be provided once.";
      }
      const value = rest[index + 1];
      if (value === undefined || value.startsWith("-")) {
        return `${arg} requires a step name.`;
      }
      const parsed = parseRunResumeFromStep(value);
      if (parsed === undefined) {
        return `Unknown resume step: ${value}`;
      }
      fromStep = parsed;
      index += 1;
      continue;
    }

    const inlineOnly = arg.match(/^--only=(?<step>.+)$/)?.groups?.step;
    if (inlineOnly !== undefined) {
      if (onlyStep !== undefined) {
        return "--only can only be provided once.";
      }
      const parsed = parseRunResumeFromStep(inlineOnly);
      if (parsed === undefined) {
        return `Unknown resume step: ${inlineOnly}`;
      }
      onlyStep = parsed;
      continue;
    }

    if (arg === "--only") {
      if (onlyStep !== undefined) {
        return "--only can only be provided once.";
      }
      const value = rest[index + 1];
      if (value === undefined || value.startsWith("-")) {
        return "--only requires a step name.";
      }
      const parsed = parseRunResumeFromStep(value);
      if (parsed === undefined) {
        return `Unknown resume step: ${value}`;
      }
      onlyStep = parsed;
      index += 1;
      continue;
    }

    if (arg === "--help" || arg === "-h") {
      return "help";
    }

    return `Unknown argument: ${arg}`;
  }

  if (command === "scan" && fromStep !== undefined) {
    return "--from is only supported for resume.";
  }
  if (command === "scan" && onlyStep !== undefined) {
    return "--only is only supported for resume.";
  }
  if (fromStep !== undefined && onlyStep !== undefined) {
    return "--from and --only cannot be used together.";
  }

  return {
    command,
    ...(fromStep === undefined ? {} : { fromStep }),
    ...(onlyStep === undefined ? {} : { onlyStep }),
    target,
  };
}

interface Renderer {
  event(event: RunEvent): void;
  failure(result: RunScanFailure): void;
  header(command: string, target: string): void;
  startSpinner(): void;
  stopSpinner(): void;
  success(result: RunScanSuccess, options?: { onlyStep?: RunResumeFromStep }): void;
}

const spinnerFrames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const spinnerIntervalMs = 120;

const glyph = {
  active: "◆",
  done: "✓",
  fail: "✗",
  reuse: "↺",
  skip: "⚠",
  step: "›",
} as const;

const code = {
  bold: "\x1b[1m",
  cyan: "\x1b[36m",
  dim: "\x1b[2m",
  gray: "\x1b[90m",
  green: "\x1b[32m",
  hideCursor: "\x1b[?25l",
  magenta: "\x1b[35m",
  red: "\x1b[31m",
  reset: "\x1b[0m",
  showCursor: "\x1b[?25h",
  yellow: "\x1b[33m",
} as const;

function makePaint(interactive: boolean): (codes: string, text: string) => string {
  return (codes, text) => (interactive ? `${codes}${text}${code.reset}` : text);
}

function isInteractive(stdout: CliWritable): boolean {
  return (stdout as { isTTY?: boolean }).isTTY === true && process.env.NO_COLOR === undefined;
}

// Owner-facing help in the same visual language as the live run output: a brand
// line, sectioned blocks, cyan command/step names, and dim descriptions. Colors
// only render on an interactive TTY; piped/non-TTY output stays plain text.
function renderHelp(interactive: boolean): string {
  const paint = makePaint(interactive);
  const heading = (text: string): string => `  ${paint(code.bold, text)}`;
  const stepWidth = Math.max(...resumeStepDefinitions.map((definition) => definition.step.length));

  const lines = [
    "",
    `  ${paint(code.magenta, glyph.active)} ${paint(code.bold, "vibeshield")}   ${paint(code.dim, "security autopilot for AI-generated code")}`,
    "",
    `  ${paint(code.dim, "Scan a GitHub repo or local Git worktree in an isolated sandbox, then get")}`,
    `  ${paint(code.dim, "an owner-facing report: what to fix now and what to check next.")}`,
    "",
    heading("Usage"),
    `    ${paint(code.cyan, "vibeshield scan")} <github-url-or-local-path>`,
    `    ${paint(code.cyan, "vibeshield resume")} /path/to/run-directory [--from <step>]`,
    `    ${paint(code.cyan, "vibeshield resume")} /path/to/run-directory --only <step>`,
    "",
    heading("Commands"),
    `    ${paint(code.cyan, "scan".padEnd(9))}${paint(code.dim, "Run a full security scan; write the report and artifacts")}`,
    `    ${paint(code.cyan, "resume".padEnd(9))}${paint(code.dim, "Continue or rerun a previous run from saved artifacts")}`,
    "",
    heading("Options"),
    `    ${paint(code.cyan, "-h, --help".padEnd(16))}${paint(code.dim, "Show this help")}`,
    `    ${paint(code.cyan, "--from <step>".padEnd(16))}${paint(code.dim, "Rerun from <step> and everything after it  (resume)")}`,
    `    ${paint(code.cyan, "--only <step>".padEnd(16))}${paint(code.dim, "Rerun just <step>, keep later artifacts    (resume)")}`,
    "",
    heading("Examples"),
    `    ${paint(code.dim, "vibeshield scan https://github.com/owner/repo")}`,
    `    ${paint(code.dim, "vibeshield scan ./my-app")}`,
    `    ${paint(code.dim, "vibeshield resume ./runs/<run-id> --from attack-hypotheses")}`,
    `    ${paint(code.dim, "vibeshield resume ./runs/<run-id> --only final-report")}`,
    "",
    `${heading("Resume steps")}  ${paint(code.dim, "· pipeline order; pass a name or alias to --from / --only")}`,
    ...resumeStepDefinitions.map((definition) => {
      const alias = "aliases" in definition ? paint(code.dim, `  (${definition.aliases[0]})`) : "";
      return `    ${paint(code.cyan, definition.step.padEnd(stepWidth))}  ${paint(code.dim, definition.description)}${alias}`;
    }),
    "",
    heading("Output"),
    `    ${paint(code.dim, "runs/<run-id>/ — final-report.md, final-report.pdf, and JSON artifacts")}`,
    "",
  ];

  return `${lines.join("\n")}\n`;
}

function renderCliError(message: string, interactive: boolean): string {
  const paint = makePaint(interactive);
  return `\n  ${paint(code.red, glyph.fail)} ${paint(code.bold, message)}\n${renderHelp(interactive)}`;
}

function createRenderer(io: CliIo, interactive: boolean): Renderer {
  const paint = makePaint(interactive);

  let frame = 0;
  let timer: ReturnType<typeof setInterval> | undefined;
  let onScreen = false;
  let activeLabel = "starting";
  let activeDetail = "";
  let activeKind: "idle" | "think" | "tool" = "idle";
  let activeToolStep: string | undefined;
  let activeStartedWall = Date.now();
  let runStartedWall = Date.now();
  let lastActionLine = "";

  const startedAtMs = new Map<string, number>();
  const toolCountByStep = new Map<string, number>();
  const labelByKey = new Map<string, string>();

  const columns = (): number => (io.stdout as { columns?: number }).columns ?? 80;

  const renderSpinner = (): void => {
    if (!interactive || timer === undefined) {
      return;
    }
    const spinner = spinnerFrames[frame % spinnerFrames.length];
    const color =
      activeKind === "think" ? code.yellow : activeKind === "tool" ? code.cyan : code.gray;
    const segments = [activeLabel];
    if (activeDetail !== "") {
      segments.push(activeDetail);
    }
    const count = activeToolStep === undefined ? 0 : (toolCountByStep.get(activeToolStep) ?? 0);
    if (count > 0) {
      segments.push(`${count} step${count === 1 ? "" : "s"}`);
    }
    segments.push(formatElapsed(Date.now() - activeStartedWall));
    let body = segments.join(" · ");
    const max = Math.max(12, columns() - 3);
    if (body.length > max) {
      body = `${body.slice(0, max - 1)}…`;
    }
    io.stdout.write(`\r\x1b[2K${color}${spinner}${code.reset} ${code.dim}${body}${code.reset}`);
    onScreen = true;
  };

  const clearSpinner = (): void => {
    if (interactive && onScreen) {
      io.stdout.write("\r\x1b[2K");
      onScreen = false;
    }
  };

  const out = (text: string): void => {
    clearSpinner();
    io.stdout.write(text);
    renderSpinner();
  };

  const milestoneLine = (params: {
    glyph: string;
    glyphCode: string;
    label: string;
    meta?: string | undefined;
    sub?: boolean;
  }): void => {
    const indent = params.sub === true ? "    " : "  ";
    const width = params.sub === true ? 22 : 24;
    const label = params.label.length > width ? params.label : params.label.padEnd(width);
    const meta = params.meta === undefined ? "" : ` ${paint(code.dim, params.meta)}`;
    out(`${indent}${paint(params.glyphCode, params.glyph)} ${label}${meta}\n`);
  };

  const setActive = (
    label: string,
    key: string,
    kind: typeof activeKind,
    eventMs: number,
    toolStep?: string,
  ): void => {
    activeLabel = label;
    activeDetail = "";
    activeKind = kind;
    activeToolStep = toolStep;
    activeStartedWall = Date.now();
    lastActionLine = "";
    startedAtMs.set(key, eventMs);
  };

  // Live trail of what the agent is doing inside a step (read/grep/find/ls),
  // printed as dim nested lines under the active section. Consecutive identical
  // actions collapse so the trail stays readable.
  const printAction = (event: RunEvent): void => {
    const action = humanLabel(event.message);
    if (action === "" || action === lastActionLine) {
      return;
    }
    lastActionLine = action;
    out(`    ${paint(code.gray, glyph.step)} ${paint(code.dim, action)}\n`);
  };

  const duration = (key: string, eventMs: number): string | undefined => {
    const started = startedAtMs.get(key);
    return started === undefined ? undefined : formatElapsed(eventMs - started);
  };

  // Baseline scanners run sequentially and only emit a start signal on success,
  // so the next start (or the summary write) finalizes the previous tool as done.
  let pendingBaseline: { key: string; label: string } | undefined;
  const finalizeBaseline = (eventMs: number): void => {
    if (pendingBaseline !== undefined) {
      milestoneLine({
        glyph: glyph.done,
        glyphCode: code.green,
        label: pendingBaseline.label,
        meta: duration(pendingBaseline.key, eventMs),
        sub: true,
      });
      pendingBaseline = undefined;
    }
  };

  const updateSpinnerActivity = (event: RunEvent): void => {
    if (event.type === "pi.tool.called") {
      const step = stringValue(event.details?.step);
      if (step !== undefined) {
        toolCountByStep.set(step, (toolCountByStep.get(step) ?? 0) + 1);
        activeToolStep = step;
      }
      const tool = stringValue(event.details?.tool) ?? "tool";
      const targetValue = stringValue(event.details?.target);
      activeDetail = targetValue === undefined ? tool : `${tool} ${shortenTail(targetValue, 40)}`;
      activeKind = "tool";
    } else if (
      event.type === "pi.thinking" ||
      normalizePiMessage(event.message) === "thinking..."
    ) {
      activeDetail = "thinking";
      activeKind = "think";
    } else if (event.type.endsWith(".heartbeat")) {
      activeKind = "idle";
    }
  };

  const handleMilestone = (event: RunEvent): boolean => {
    const eventMs = timestampToMs(event.timestamp);
    switch (event.type) {
      case "run.created":
        return true;
      case "sandbox.create.started":
        setActive("Creating sandbox", "sandbox", "idle", eventMs);
        return true;
      case "sandbox.created":
        milestoneLine({
          glyph: glyph.done,
          glyphCode: code.green,
          label: "Sandbox ready",
          meta: duration("sandbox", eventMs),
        });
        return true;
      case "clone.started":
        setActive("Cloning repository", "clone", "idle", eventMs);
        return true;
      case "clone.completed":
        milestoneLine({
          glyph: glyph.done,
          glyphCode: code.green,
          label: "Repository cloned",
          meta: duration("clone", eventMs),
        });
        return true;
      case "inventory.started":
        setActive("Taking inventory", "inventory", "idle", eventMs);
        return true;
      case "context.started":
        setActive("Preparing analysis context", "context", "idle", eventMs);
        return true;
      case "artifact.written":
        if (event.stage === "inventory") {
          milestoneLine({
            glyph: glyph.done,
            glyphCode: code.green,
            label: "Inventory",
            meta: duration("inventory", eventMs),
          });
          return true;
        }
        if (event.stage === "context") {
          milestoneLine({
            glyph: glyph.done,
            glyphCode: code.green,
            label: "Analysis context ready",
            meta: duration("context", eventMs),
          });
          return true;
        }
        if (event.stage === "deterministic-baseline") {
          finalizeBaseline(eventMs);
          return true;
        }
        if (event.stage === "final-report") {
          milestoneLine({
            glyph: glyph.done,
            glyphCode: code.green,
            label: "Final report",
            meta: duration("final-report", eventMs),
          });
          return true;
        }
        return false;
      case "step.started":
        if (event.stage === "deterministic-baseline") {
          out(`\n  ${paint(code.bold, "Quick security checks")}\n`);
          return true;
        }
        return false;
      case "baseline.job.started": {
        finalizeBaseline(eventMs);
        const label = humanLabel(event.message);
        const key = `bl:${event.job ?? label}`;
        setActive(label, key, "idle", eventMs);
        pendingBaseline = { key, label };
        return true;
      }
      case "baseline.job.failed": {
        const label = pendingBaseline?.label ?? humanLabel(event.message);
        const meta =
          pendingBaseline === undefined ? undefined : duration(pendingBaseline.key, eventMs);
        pendingBaseline = undefined;
        milestoneLine({ glyph: glyph.fail, glyphCode: code.red, label, meta, sub: true });
        return true;
      }
      case "baseline.job.skipped":
        finalizeBaseline(eventMs);
        milestoneLine({
          glyph: glyph.skip,
          glyphCode: code.yellow,
          label: humanLabel(event.message),
          sub: true,
        });
        return true;
      case "repository-map.started":
        out(`\n  ${paint(code.bold, "Understanding your project")}\n`);
        return true;
      case "coverage-structure.started": {
        const label = humanLabel(event.message);
        labelByKey.set("pi:coverage-structure", label);
        setActive(label, "pi:coverage-structure", "idle", eventMs);
        return true;
      }
      case "coverage-structure.completed":
        milestoneLine({
          glyph: glyph.done,
          glyphCode: code.green,
          label: labelByKey.get("pi:coverage-structure") ?? humanLabel(event.message),
          meta: duration("pi:coverage-structure", eventMs),
          sub: true,
        });
        return true;
      case "runner.started": {
        const step = stringValue(event.details?.step) ?? "section";
        const label = humanLabel(event.message);
        labelByKey.set(`pi:${step}`, label);
        setActive(label, `pi:${step}`, "think", eventMs, step);
        return true;
      }
      case "pi.completed": {
        const step = stringValue(event.details?.step) ?? "section";
        milestoneLine({
          glyph: glyph.done,
          glyphCode: code.green,
          label: labelByKey.get(`pi:${step}`) ?? humanLabel(event.message),
          meta: duration(`pi:${step}`, eventMs),
          sub: true,
        });
        return true;
      }
      case "pi.failed": {
        const step = stringValue(event.details?.step) ?? "section";
        milestoneLine({
          glyph: glyph.fail,
          glyphCode: code.red,
          label: labelByKey.get(`pi:${step}`) ?? humanLabel(event.message),
          meta: duration(`pi:${step}`, eventMs),
          sub: true,
        });
        return true;
      }
      case "pi.output.recovered": {
        const step = stringValue(event.details?.step) ?? "section";
        milestoneLine({
          glyph: glyph.reuse,
          glyphCode: code.yellow,
          label: `${labelByKey.get(`pi:${step}`) ?? "Section"} · recovered`,
          sub: true,
        });
        return true;
      }
      case "resume.started":
        out(
          `  ${paint(code.gray, glyph.reuse)} ${paint(code.dim, "Resuming from durable artifacts")}\n`,
        );
        return true;
      case "resume.artifact_reused":
        milestoneLine({
          glyph: glyph.reuse,
          glyphCode: code.gray,
          label: normalizePiMessage(event.message),
          sub: true,
        });
        return true;
      case "final-report.started":
        setActive("Rendering final report", "final-report", "idle", eventMs);
        return true;
      default:
        return false;
    }
  };

  const isSpinnerOnly = (event: RunEvent): boolean =>
    event.type === "pi.thinking" ||
    event.type === "pi.output.started" ||
    event.type.endsWith(".heartbeat");

  return {
    event(event) {
      updateSpinnerActivity(event);
      if (event.type === "pi.tool.called") {
        printAction(event);
        return;
      }
      if (isSpinnerOnly(event)) {
        return;
      }
      const handled = handleMilestone(event);
      if (!handled && event.stage !== "pi") {
        out(
          `  ${paint(code.gray, glyph.step)} ${paint(code.dim, normalizePiMessage(event.message))}\n`,
        );
      }
    },
    failure(result) {
      const elapsed = formatElapsed(Date.now() - runStartedWall);
      io.stderr.write(
        `\n  ${paint(code.red, glyph.fail)} ${paint(code.bold, "Scan failed")} ${paint(code.dim, `· ${elapsed}`)}\n`,
      );
      io.stderr.write(`    ${result.userMessage}\n`);
      const runError = result.run?.error;
      if (runError !== undefined) {
        const reasons = (
          runError.diagnostics !== undefined && runError.diagnostics.length > 0
            ? runError.diagnostics
            : [runError.message]
        ).filter((reason) => reason.trim() !== "" && reason !== result.userMessage);
        for (const reason of reasons) {
          io.stderr.write(`    ${paint(code.dim, `- ${reason}`)}\n`);
        }
      }
      if (result.runDir !== undefined) {
        io.stderr.write(`    Run directory: ${result.runDir}\n`);
      }
    },
    header(command, target) {
      runStartedWall = Date.now();
      const repo = prettifyTarget(command, target);
      io.stdout.write(
        `\n  ${paint(code.magenta, glyph.active)} ${paint(code.bold, "vibeshield")} ${paint(code.dim, `· ${command} ·`)} ${paint(code.cyan, repo)}\n\n`,
      );
    },
    startSpinner() {
      if (!interactive) {
        return;
      }
      io.stdout.write(code.hideCursor);
      timer = setInterval(() => {
        frame += 1;
        renderSpinner();
      }, spinnerIntervalMs);
      (timer as { unref?: () => void }).unref?.();
    },
    stopSpinner() {
      if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
      clearSpinner();
      if (interactive) {
        io.stdout.write(code.showCursor);
      }
    },
    success(result, options = {}) {
      const elapsed = formatElapsed(Date.now() - runStartedWall);
      const isOnlyStep = options.onlyStep !== undefined;
      io.stdout.write(
        `\n  ${paint(code.green, glyph.done)} ${paint(code.bold, isOnlyStep ? "Step complete" : "Scan complete")} ${paint(code.dim, `· ${elapsed}`)}\n`,
      );
      io.stdout.write(`    Run directory: ${result.runDir}\n`);
      if (!isOnlyStep && result.runDir !== undefined) {
        io.stdout.write(
          `    ${paint(code.dim, `Final report PDF: ${result.runDir}/final-report.pdf`)}\n`,
        );
        io.stdout.write(
          `    ${paint(code.dim, `Final report MD:  ${result.runDir}/final-report.md`)}\n`,
        );
      }
    },
  };
}

function prettifyTarget(command: string, target: string): string {
  if (command === "resume") {
    return (
      target
        .split("/")
        .filter((segment) => segment !== "")
        .pop() ?? target
    );
  }
  const match = target.match(/github\.com[/:](?<slug>[^/]+\/[^/]+?)(?:\.git)?\/?$/i);
  return match?.groups?.slug ?? target;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function normalizePiMessage(message: string): string {
  return message
    .replace(/^[^:]+? (?:collector|evaluator)(?: attempt \d+)?:\s*/, "")
    .replaceAll("/home/daytona/repo/", "")
    .trim();
}

// Human-facing label from a progress message: strip the agent prefix and the
// trailing period so it reads as a clean checklist item for non-technical users.
function humanLabel(message: string): string {
  const text = normalizePiMessage(message);
  return text.endsWith(".") ? text.slice(0, -1) : text;
}

function timestampToMs(timestamp: string): number {
  const parsed = Date.parse(timestamp);
  return Number.isNaN(parsed) ? Date.now() : parsed;
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
