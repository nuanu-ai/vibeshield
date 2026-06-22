import type { Writable } from "node:stream";
import type { ScanOutcome } from "../application/scan-service.js";
import { verdictLabel } from "../domain/assessment.js";
import type { CoverageEntry, CoverageStatus } from "../domain/coverage-summary.js";
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
}

const STATUS_ORDER: ReadonlyArray<CoverageStatus> = ["checked", "degraded", "failed", "skipped"];

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
  "findings.normalize": "Prioritizing findings",
  "findings.correlate": "Prioritizing findings",
  "actions.rank": "Prioritizing findings",
  "remediation.generate": "Writing the Agent Fix Pack",
  "report.compose": "Rendering reports",
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
    if (event.type === "run-started") {
      this.write(`${this.palette.bold("VibeShield")} ${this.palette.dim("quick scan started")}`);
      return;
    }
    if (event.type === "stage-started") {
      const label = progressLabel(event);
      if (!this.printedProgressLabels.has(label)) {
        this.printedProgressLabels.add(label);
        this.write(`${this.palette.cyan("[scan]")} ${label}`);
      }
      return;
    }
    if (event.type === "stage-failed" || event.type === "error") {
      this.write(`${this.palette.red("[fail]")} ${event.message}`);
      return;
    }
    if (event.type === "run-finished") {
      if (event.details?.status === "failed") {
        return;
      }
      this.write(`${this.palette.green("[done]")} Quick scan finished`);
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

export function renderScanOutcome(outcome: ScanOutcome, opts: RenderOptions = {}): string {
  const palette = makePalette(opts.color ?? false);
  const { assessment } = outcome;
  const lines: string[] = [];

  lines.push("", palette.bold("VibeShield Quick Scan"));
  lines.push(`Run: ${outcome.runId}`);
  lines.push(`Repository: ${repositoryLine(assessment)}`);
  lines.push(`Verdict: ${verdictText(assessment.verdict, palette)}`);
  lines.push(`Fix Pack: ${fixPackSummary(assessment)}`);
  lines.push(`Checks: ${coverageSummary(assessment.coverage)}`);
  lines.push(`Snapshot: ${assessment.manifest.fileCount} files scanned`);
  lines.push("");
  lines.push(palette.bold("What to do next"));
  if (assessment.rankedActions.length === 0) {
    lines.push("  No blocking fixes from the checks that completed.");
  } else {
    lines.push(`  Open the HTML report and fix the ${topActionNoun(assessment)} in order.`);
    lines.push("  Each fix has a clearly labeled prompt to paste into your coding agent.");
  }
  lines.push("");
  lines.push(palette.bold("Reports"));
  lines.push(`  Human report: ${reportPath(outcome.reportPaths, "html") ?? "not written"}`);
  lines.push(`  Markdown: ${reportPath(outcome.reportPaths, "markdown") ?? "not written"}`);
  lines.push(`  JSON: ${reportPath(outcome.reportPaths, "json") ?? "not written"}`);
  lines.push("");
  lines.push(palette.bold("Top fixes"));
  if (assessment.rankedActions.length === 0) {
    lines.push("  None.");
  } else {
    for (const line of topActionLines(assessment, palette)) {
      lines.push(`  ${line}`);
    }
  }
  lines.push("");
  lines.push(palette.dim(`Toolchain: ${assessment.toolchain.imageTag}`));
  lines.push(
    palette.dim(
      `Source snapshot: ${shortHash(assessment.manifest.sourceHash)}; ${assessment.manifest.exclusionCount} exclusions`,
    ),
  );
  lines.push(palette.dim(assessment.limitation));

  return `${lines.join("\n")}\n`;
}

export function supportsAnsiColor(stream: TerminalStream): boolean {
  return Boolean(stream.isTTY) && process.env.NO_COLOR === undefined;
}

function topActionLines(assessment: SecurityAssessment, palette: Palette): string[] {
  return assessment.rankedActions.slice(0, 3).map((ranked, index) => {
    const locations = actionLocations(ranked.candidate.findingIds, assessment);
    const where = locations.length > 0 ? ` at ${locations.slice(0, 2).join(", ")}` : "";
    return `${index + 1}. ${palette.bold(ranked.remediation.title)}${where}`;
  });
}

function topActionNoun(assessment: SecurityAssessment): string {
  const count = assessment.rankedActions.length;
  return count === 1 ? "top fix" : `${count} fixes`;
}

function actionLocations(
  findingIds: ReadonlyArray<string>,
  assessment: SecurityAssessment,
): string[] {
  const findingsById = new Map(assessment.findings.map((finding) => [finding.id, finding]));
  const seen = new Set<string>();
  const out: string[] = [];
  for (const findingId of findingIds) {
    const finding = findingsById.get(findingId);
    if (finding === undefined) {
      continue;
    }
    for (const location of finding.locations) {
      const value = `${location.filePath}:${location.startLine}`;
      if (!seen.has(value)) {
        seen.add(value);
        out.push(value);
      }
    }
  }
  return out;
}

function repositoryLine(assessment: SecurityAssessment): string {
  const commit = assessment.repository.commitSha ?? assessment.manifest.commitSha;
  const source =
    assessment.repository.originUrl ??
    assessment.repository.localPath ??
    assessment.repository.name;
  if (commit === undefined || commit === null) {
    return source;
  }
  return `${source} @ ${shortHash(commit)}`;
}

function verdictText(verdict: SecurityAssessment["verdict"], palette: Palette): string {
  const label = verdictLabel(verdict);
  if (verdict === "critical-fix-needed" || verdict === "not-ready-to-deploy") {
    return palette.red(label);
  }
  if (verdict === "scan-incomplete") {
    return palette.yellow(label);
  }
  return palette.green(label);
}

function fixPackSummary(assessment: SecurityAssessment): string {
  const count = assessment.rankedActions.length;
  const noun = count === 1 ? "action" : "actions";
  const source = remediationSource(assessment);
  const findings = severitySummary(assessment);
  return `${count} ${noun} (${source}; deterministic verdict/actions; ${findings})`;
}

function remediationSource(assessment: SecurityAssessment): string {
  if (assessment.rankedActions.length === 0) {
    return "no remediation needed";
  }
  const catalogCount = assessment.rankedActions.filter(
    (action) => action.remediation.fromCatalog,
  ).length;
  if (catalogCount === assessment.rankedActions.length) {
    return "catalog fallback";
  }
  if (catalogCount === 0) {
    return "OpenRouter enhanced";
  }
  return "OpenRouter enhanced + catalog fallback";
}

function severitySummary(assessment: SecurityAssessment): string {
  const parts = ["critical", "high", "medium", "low", "unknown"]
    .map((severity) => {
      const count = assessment.findingSummary.bySeverity[severity] ?? 0;
      return count > 0 ? `${count} ${severity}` : "";
    })
    .filter((part) => part.length > 0);
  if (parts.length === 0) {
    return "0 findings";
  }
  return parts.join(", ");
}

function coverageSummary(coverage: ReadonlyArray<CoverageEntry>): string {
  const counts = new Map<CoverageStatus, number>();
  for (const entry of coverage) {
    counts.set(entry.status, (counts.get(entry.status) ?? 0) + 1);
  }
  return STATUS_ORDER.map((status) => `${status} ${counts.get(status) ?? 0}`).join(", ");
}

function reportPath(
  reportPaths: ScanOutcome["reportPaths"],
  key: "html" | "json" | "markdown",
): string | undefined {
  return reportPaths[key] ?? (key === "markdown" ? reportPaths.md : undefined);
}

function shortHash(value: string): string {
  return value.length <= 12 ? value : value.slice(0, 12);
}

function makePalette(color: boolean): Palette {
  const paint = (open: string, close: string): Paint =>
    color ? (text) => `${open}${text}${close}` : (text) => text;
  return {
    bold: paint("\u001b[1m", "\u001b[22m"),
    dim: paint("\u001b[2m", "\u001b[22m"),
    green: paint("\u001b[32m", "\u001b[39m"),
    red: paint("\u001b[31m", "\u001b[39m"),
    yellow: paint("\u001b[33m", "\u001b[39m"),
    cyan: paint("\u001b[36m", "\u001b[39m"),
  };
}
