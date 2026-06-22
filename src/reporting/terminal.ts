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

const REPORT_ORDER = ["json", "markdown", "md", "html"] as const;

export class TerminalEventSink implements EventSink {
  private readonly palette: Palette;

  constructor(
    private readonly stream: TerminalStream = process.stderr,
    opts: RenderOptions = {},
  ) {
    this.palette = makePalette(opts.color ?? supportsAnsiColor(stream));
  }

  emit(event: ScanEvent): void {
    if (event.type === "run-started") {
      this.write(`${this.palette.bold("VibeShield")} ${this.palette.dim("starting quick scan")}`);
      return;
    }
    if (event.type === "stage-started") {
      this.write(`${this.palette.cyan("[scan]")} ${event.stageId ?? event.message}`);
      return;
    }
    if (event.type === "stage-failed" || event.type === "error") {
      this.write(`${this.palette.red("[fail]")} ${event.message}`);
      return;
    }
    if (event.type === "run-finished") {
      this.write(`${this.palette.green("[done]")} ${event.message}`);
    }
  }

  private write(line: string): void {
    this.stream.write(`${line}\n`);
  }
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
  lines.push(
    `Snapshot: ${assessment.manifest.fileCount} files, ${formatBytes(
      assessment.manifest.totalBytes,
    )}, ${assessment.manifest.exclusionCount} exclusions, source ${shortHash(
      assessment.manifest.sourceHash,
    )}`,
  );
  lines.push(`Toolchain: ${assessment.toolchain.imageTag}`);
  lines.push("");
  lines.push(palette.bold("Coverage"));
  lines.push(`Summary: ${coverageSummary(assessment.coverage)}`);
  for (const entry of assessment.coverage) {
    lines.push(`  ${coverageStatusLabel(entry.status, palette)} ${entry.check}${reason(entry)}`);
  }
  lines.push("");
  lines.push(palette.bold("Reports"));
  for (const line of reportPathLines(outcome.reportPaths)) {
    lines.push(`  ${line}`);
  }
  lines.push("");
  lines.push(palette.bold("Agent Fix Pack"));
  if (assessment.rankedActions.length === 0) {
    lines.push("  No blocking actions from the checks that completed.");
  } else {
    assessment.rankedActions.forEach((ranked, index) => {
      if (index > 0) {
        lines.push("");
      }
      lines.push(...renderAction(index + 1, ranked, assessment, palette));
    });
  }
  lines.push("");
  lines.push(palette.dim(assessment.limitation));

  return `${lines.join("\n")}\n`;
}

export function supportsAnsiColor(stream: TerminalStream): boolean {
  return Boolean(stream.isTTY) && process.env.NO_COLOR === undefined;
}

function renderAction(
  rank: number,
  ranked: SecurityAssessment["rankedActions"][number],
  assessment: SecurityAssessment,
  palette: Palette,
): string[] {
  const { candidate, remediation } = ranked;
  const lines = [
    `${rank}. ${palette.bold(remediation.title)}`,
    `   Source: ${remediation.fromCatalog ? "catalog fallback" : "OpenRouter enhanced"}; impact: ${
      candidate.verdictImpact
    }; priority: ${candidate.priorityScore}`,
  ];
  const locations = actionLocations(candidate.findingIds, assessment);
  if (locations.length > 0) {
    lines.push(`   Evidence: ${locations.slice(0, 5).join(", ")}`);
  } else if (candidate.affectedFiles.length > 0) {
    lines.push(`   Files: ${candidate.affectedFiles.join(", ")}`);
  }
  lines.push(`   Risk: ${remediation.risk}`);
  lines.push(`   Why now: ${remediation.whyFixNow}`);
  appendList(lines, "Fix", remediation.fixSteps);
  appendList(lines, "Operations", remediation.operationalSteps);
  lines.push("   Agent prompt:");
  lines.push(...indentBlock(remediation.agentPrompt, "     "));
  appendList(lines, "Verify", remediation.verifySteps);
  return lines;
}

function appendList(lines: string[], label: string, values: ReadonlyArray<string>): void {
  if (values.length === 0) {
    return;
  }
  lines.push(`   ${label}:`);
  for (const value of values) {
    lines.push(`     - ${value}`);
  }
}

function indentBlock(text: string, prefix: string): string[] {
  return text.split(/\r?\n/).map((line) => `${prefix}${line}`);
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

function coverageStatusLabel(status: CoverageStatus, palette: Palette): string {
  switch (status) {
    case "checked":
      return palette.green("[ok]");
    case "degraded":
      return palette.yellow("[degraded]");
    case "failed":
      return palette.red("[failed]");
    case "skipped":
      return palette.dim("[skipped]");
  }
}

function reason(entry: CoverageEntry): string {
  return entry.reason === undefined ? "" : ` - ${entry.reason}`;
}

function reportPathLines(reportPaths: ScanOutcome["reportPaths"]): string[] {
  const lines: string[] = [];
  for (const key of REPORT_ORDER) {
    const value = reportPaths[key];
    if (value !== undefined) {
      lines.push(`${reportLabel(key)}: ${value}`);
    }
  }
  for (const [key, value] of Object.entries(reportPaths)) {
    if (!REPORT_ORDER.includes(key as (typeof REPORT_ORDER)[number])) {
      lines.push(`${reportLabel(key)}: ${value}`);
    }
  }
  return lines;
}

function reportLabel(key: string): string {
  return key === "markdown" ? "md" : key;
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KiB`;
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
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
