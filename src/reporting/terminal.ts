import type { Writable } from "node:stream";
import type { ScanOutcome } from "../application/scan-service.js";
import type { Verdict } from "../domain/assessment.js";
import { verdictLabel } from "../domain/assessment.js";
import type { SecurityAssessment } from "../domain/security-assessment.js";
import type { EventSink, ScanEvent } from "../ports/event-sink.js";

interface RenderOptions {
  readonly color?: boolean;
}

interface TerminalStream extends Pick<Writable, "write"> {
  readonly isTTY?: boolean;
}

type Paint = (text: string) => string;

interface Palette {
  readonly bold: Paint;
  readonly dim: Paint;
  readonly green: Paint;
  readonly red: Paint;
  readonly yellow: Paint;
  readonly cyan: Paint;
  readonly magenta: Paint;
}

const glyph = {
  brand: "◆",
  ok: "✓",
  fail: "✗",
  warn: "⚠",
  step: "›",
} as const;

// Friendly, deduplicated progress labels. Internal stage ids never reach the
// user; several scanner stages collapse into one "Running security checks" line.
const STAGE_PROGRESS_LABELS: Readonly<Record<string, string>> = {
  "source.resolve": "Preparing the repository",
  "toolchain.refresh": "Updating scanner data",
  "snapshot.manifest": "Understanding the project",
  "inventory.detect": "Understanding the project",
  "scan.secrets.gitleaks": "Running security checks",
  "scan.code.opengrep": "Running security checks",
  "scan.sbom.syft": "Running security checks",
  "scan.dependencies.trivy": "Running security checks",
  "scan.github-actions.actionlint": "Running security checks",
  "scan.github-actions.zizmor": "Running security checks",
  "scan.iac.trivy-config": "Running security checks",
  "findings.normalize": "Prioritizing what matters",
  "findings.correlate": "Prioritizing what matters",
  "actions.rank": "Prioritizing what matters",
  "remediation.generate": "Writing your fixes",
  "deep.static.compose": "Running Deep Static analysis",
  "report.compose": "Writing the report",
};

export class TerminalEventSink implements EventSink {
  private readonly palette: Palette;
  private readonly printedProgressLabels = new Set<string>();

  constructor(
    private readonly stream: TerminalStream = process.stderr,
    opts: RenderOptions = {},
  ) {
    this.palette = makePalette(opts.color ?? supportsAnsiColor(stream));
  }

  emit(event: ScanEvent): void {
    const p = this.palette;
    if (event.type === "run-started") {
      this.write(`${p.magenta(glyph.brand)} ${p.bold("VibeShield")} ${p.dim("quick scan")}`);
      return;
    }
    if (event.type === "stage-started") {
      const label = progressLabel(event);
      if (!this.printedProgressLabels.has(label)) {
        this.printedProgressLabels.add(label);
        this.write(`  ${p.cyan(glyph.step)} ${p.dim(label)}`);
      }
      return;
    }
    if (event.type === "stage-failed" || event.type === "error") {
      this.write(`  ${p.red(glyph.fail)} ${event.message}`);
      return;
    }
    if (event.type === "run-finished") {
      if (event.details?.status === "failed") {
        return;
      }
      this.write(`  ${p.green(glyph.ok)} ${p.dim("Scan complete")}`);
    }
  }

  private write(line: string): void {
    this.stream.write(`${line}\n`);
  }
}

function progressLabel(event: ScanEvent): string {
  if (event.stageId !== undefined) {
    return STAGE_PROGRESS_LABELS[event.stageId] ?? humanizeStageId(event.stageId);
  }
  return event.message;
}

function humanizeStageId(stageId: string): string {
  return stageId
    .split(".")
    .filter((part) => part.length > 0)
    .map((part) => part.replaceAll("-", " "))
    .join(" ");
}

// Short owner-facing receipt. The full Fix Pack lives in the reports; the
// terminal only answers "what's the verdict and where is the report". Scanner
// counts, toolchain tags, source hashes, and fix details stay in reports.
export function renderScanOutcome(outcome: ScanOutcome, opts: RenderOptions = {}): string {
  const p = makePalette(opts.color ?? false);
  const { assessment } = outcome;
  const lines: string[] = [];

  lines.push("");
  lines.push(
    `  ${p.magenta(glyph.brand)} ${p.bold("VibeShield")}  ${p.dim(repositoryLine(assessment))}`,
  );
  lines.push("");

  const verdict = verdictStyle(assessment.verdict, p);
  lines.push(
    `  ${verdict.paint(verdict.glyph)} ${p.bold(verdict.paint(verdictLabel(assessment.verdict)))}`,
  );
  lines.push(`    ${p.dim(verdictSubline(assessment))}`);
  lines.push("");

  const htmlPath = outcome.reportPaths.html;
  const markdownPath = outcome.reportPaths.markdown ?? outcome.reportPaths.md;
  lines.push(`  ${p.bold("Full report")}`);
  if (htmlPath !== undefined) {
    lines.push(`    ${htmlPath} ${p.dim("← open in a browser")}`);
  }
  const alongside = [markdownPath, outcome.reportPaths.json].filter(
    (value): value is string => value !== undefined,
  );
  if (alongside.length > 0) {
    lines.push(`    ${p.dim(`Markdown and JSON are in the same folder.`)}`);
  }
  lines.push("");
  lines.push(`  ${p.dim(assessment.limitation)}`);
  lines.push("");

  return `${lines.join("\n")}\n`;
}

// Styled, owner-facing help for `vibeshield` and `vibeshield --help`.
export function renderHelp(opts: RenderOptions = {}): string {
  const p = makePalette(opts.color ?? false);
  const heading = (text: string): string => `  ${p.bold(text)}`;
  const lines = [
    "",
    `  ${p.magenta(glyph.brand)} ${p.bold("VibeShield")}   ${p.dim("security autopilot for AI-generated code")}`,
    "",
    `  ${p.dim("Scan a repo and get back a short, prioritized Fix Pack: what to change,")}`,
    `  ${p.dim("why it matters, and a ready-to-paste prompt for your coding agent.")}`,
    "",
    heading("Usage"),
    `    ${p.cyan("vibeshield scan")} <github-url-or-local-git-root> ${p.dim("[--deep]")}`,
    "",
    heading("Examples"),
    `    ${p.dim("vibeshield scan https://github.com/owner/repo")}`,
    `    ${p.dim("vibeshield scan ./my-app")}`,
    `    ${p.dim("vibeshield scan ./my-app --deep")}`,
    "",
    heading("Output"),
    `    ${p.dim("A short summary here, plus a full report you can open:")}`,
    `    ${p.dim("report.html · report.md · report.json")}`,
    "",
    heading("Setup"),
    `    ${p.dim("Needs Docker or Podman + Microsandbox. First run:")} ${p.cyan("pnpm toolchain:prepare")}`,
    `    ${p.dim("Set OPENROUTER_API_KEY (optional) to improve how each fix is explained.")}`,
    "",
  ];
  return `${lines.join("\n")}\n`;
}

// Single, friendly error line for the CLI's top-level failure path.
export function renderError(message: string, opts: RenderOptions = {}): string {
  const p = makePalette(opts.color ?? false);
  return `\n  ${p.red(glyph.fail)} ${message}\n\n`;
}

export function supportsAnsiColor(stream: TerminalStream): boolean {
  return Boolean(stream.isTTY) && process.env.NO_COLOR === undefined;
}

function verdictStyle(verdict: Verdict, palette: Palette): { glyph: string; paint: Paint } {
  if (verdict === "critical-fix-needed" || verdict === "not-ready-to-deploy") {
    return { glyph: glyph.fail, paint: palette.red };
  }
  if (verdict === "scan-incomplete") {
    return { glyph: glyph.warn, paint: palette.yellow };
  }
  return { glyph: glyph.ok, paint: palette.green };
}

function verdictSubline(assessment: SecurityAssessment): string {
  const count = assessment.rankedActions.length;
  switch (assessment.verdict) {
    case "critical-fix-needed":
    case "not-ready-to-deploy":
      return count === 0
        ? "There are problems to fix before you rely on this code — see the report."
        : `${count} ${count === 1 ? "fix" : "fixes"} to make before you ship — see the report.`;
    case "scan-incomplete":
      return "Some checks didn't finish, so this isn't the full picture — see the report.";
    case "looks-ok-for-now":
      return "No blocking issues from the checks that ran. Not a guarantee — keep reviewing.";
  }
}

function repositoryLine(assessment: SecurityAssessment): string {
  const commit = assessment.repository.commitSha ?? assessment.manifest.commitSha;
  const source =
    assessment.repository.originUrl ??
    assessment.repository.localPath ??
    assessment.repository.name;
  const cleaned = source.replace(/^https?:\/\//, "").replace(/\.git$/, "");
  if (commit === undefined || commit === null) {
    return cleaned;
  }
  return `${cleaned} @ ${shortHash(commit)}`;
}

function shortHash(value: string): string {
  return value.length <= 12 ? value : value.slice(0, 12);
}

function makePalette(color: boolean): Palette {
  const paint = (open: string, close: string): Paint =>
    color ? (text) => `${open}${text}${close}` : (text) => text;
  return {
    bold: paint("[1m", "[22m"),
    dim: paint("[2m", "[22m"),
    green: paint("[32m", "[39m"),
    red: paint("[31m", "[39m"),
    yellow: paint("[33m", "[39m"),
    cyan: paint("[36m", "[39m"),
    magenta: paint("[35m", "[39m"),
  };
}
