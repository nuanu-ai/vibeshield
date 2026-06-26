import type { Writable } from "node:stream";
import type { ScanOutcome } from "../application/scan-service.js";
import type { Verdict } from "../domain/assessment.js";
import { verdictLabel } from "../domain/assessment.js";
import type { SecurityAssessment } from "../domain/security-assessment.js";
import type { StaticHypothesis } from "../domain/static-hypothesis.js";
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

interface TerminalAttackPath {
  readonly hypothesis: StaticHypothesis;
  readonly family: string;
  readonly reason: string;
}

const glyph = {
  brand: "◆",
  ok: "✓",
  fail: "✗",
  warn: "⚠",
  step: "›",
} as const;

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"] as const;
const TERMINAL_COVERAGE_AREAS = [
  "language_support",
  "data_flow",
  "dependency_usage",
  "ci_iac",
  "content_assets",
  "smart_contracts",
] as const;

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
  "hypotheses.enrich": "Explaining likely attack paths",
  "report.compose": "Writing the report",
};

export class TerminalEventSink implements EventSink {
  private readonly palette: Palette;
  private readonly tty: boolean;
  private readonly printedProgressLabels = new Set<string>();
  private spinnerTimer: ReturnType<typeof setInterval> | undefined;
  private spinnerFrame = 0;
  private spinnerLabel: string | undefined;

  constructor(
    private readonly stream: TerminalStream = process.stderr,
    opts: RenderOptions = {},
  ) {
    this.palette = makePalette(opts.color ?? supportsAnsiColor(stream));
    this.tty = Boolean(stream.isTTY);
  }

  emit(event: ScanEvent): void {
    const p = this.palette;
    if (event.type === "run-started") {
      this.write(`${p.magenta(glyph.brand)} ${p.bold("VibeShield")} ${p.dim("quick scan")}`);
      return;
    }
    if (event.type === "stage-started" || event.type === "scan-progress") {
      this.showProgress(progressLabel(event));
      return;
    }
    if (event.type === "stage-failed" || event.type === "error") {
      this.finishSpinnerLine();
      this.write(`  ${p.red(glyph.fail)} ${event.message}`);
      return;
    }
    if (event.type === "run-finished") {
      if (event.details?.status === "failed") {
        this.clearSpinnerLine();
        return;
      }
      this.finishSpinnerLine();
      this.write(`  ${p.green(glyph.ok)} ${p.dim("Scan complete")}`);
    }
  }

  private showProgress(label: string): void {
    const trimmed = label.trim();
    if (trimmed.length === 0) {
      return;
    }
    if (!this.tty) {
      if (!this.printedProgressLabels.has(trimmed)) {
        this.printedProgressLabels.add(trimmed);
        this.write(`  ${this.palette.cyan(glyph.step)} ${this.palette.dim(trimmed)}`);
      }
      return;
    }
    if (this.spinnerLabel === trimmed) {
      return;
    }
    this.finishSpinnerLine();
    this.spinnerLabel = trimmed;
    this.spinnerFrame = 0;
    this.startSpinner();
    this.renderSpinner();
  }

  private startSpinner(): void {
    if (this.spinnerTimer !== undefined) {
      return;
    }
    this.spinnerTimer = setInterval(() => {
      this.renderSpinner();
    }, 120);
    this.spinnerTimer.unref();
  }

  private finishSpinnerLine(): void {
    if (!this.tty || this.spinnerLabel === undefined) {
      return;
    }
    const label = this.spinnerLabel;
    this.clearSpinnerLine();
    if (!this.printedProgressLabels.has(label)) {
      this.printedProgressLabels.add(label);
      this.write(`  ${this.palette.cyan(glyph.step)} ${this.palette.dim(label)}`);
    }
  }

  private clearSpinnerLine(): void {
    if (!this.tty) {
      return;
    }
    this.stopSpinner();
    if (this.spinnerLabel !== undefined) {
      this.stream.write("\r\x1b[2K");
      this.spinnerLabel = undefined;
    }
  }

  private stopSpinner(): void {
    if (this.spinnerTimer !== undefined) {
      clearInterval(this.spinnerTimer);
      this.spinnerTimer = undefined;
    }
  }

  private renderSpinner(): void {
    if (!this.tty || this.spinnerLabel === undefined) {
      return;
    }
    const frame = SPINNER_FRAMES[this.spinnerFrame % SPINNER_FRAMES.length] ?? SPINNER_FRAMES[0];
    this.spinnerFrame += 1;
    this.stream.write(
      `\r\x1b[2K  ${this.palette.cyan(frame)} ${this.palette.dim(this.spinnerLabel)}`,
    );
  }

  private write(line: string): void {
    this.stream.write(`${line}\n`);
  }
}

function progressLabel(event: ScanEvent): string {
  const publicLabel = event.details?.publicLabel;
  if (typeof publicLabel === "string" && publicLabel.trim().length > 0) {
    return publicLabel;
  }
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

  appendDeepStaticSummary(lines, assessment, p);

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
    `    ${p.cyan("vibeshield scan")} <github-url-or-local-git-root> ${p.dim("[--deep] [--no-model]")}`,
    "",
    heading("Examples"),
    `    ${p.dim("vibeshield scan https://github.com/owner/repo")}`,
    `    ${p.dim("vibeshield scan ./my-app")}`,
    `    ${p.dim("vibeshield scan ./my-app --deep")}`,
    `    ${p.dim("vibeshield scan ./my-app --deep --no-model")}`,
    "",
    heading("Output"),
    `    ${p.dim("A short summary here, plus a full report you can open:")}`,
    `    ${p.dim("report.html · report.md · report.json")}`,
    "",
    heading("Setup"),
    `    ${p.dim("Needs Docker or Podman + Microsandbox. First run:")} ${p.cyan("pnpm toolchain:prepare")}`,
    `    ${p.dim("Set OPENROUTER_API_KEY (optional) to improve how fixes are explained.")}`,
    `    ${p.dim("Use VIBESHIELD_REMEDIATION_MODEL to try another OpenRouter model.")}`,
    `    ${p.dim("Use --no-model or VIBESHIELD_NO_MODEL=1 for catalog-only wording.")}`,
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

function appendDeepStaticSummary(
  lines: string[],
  assessment: SecurityAssessment,
  palette: Palette,
): void {
  if (assessment.deepCoverage === undefined && assessment.staticHypotheses === undefined) {
    return;
  }

  const rawAttackPathCount = (assessment.staticHypotheses ?? []).filter(
    (hypothesis) => hypothesis.status !== "statically_contradicted",
  ).length;
  const attackPaths = terminalAttackPaths(assessment);
  const supported = (assessment.staticHypotheses ?? []).filter(
    (hypothesis) => hypothesis.status === "statically_supported",
  ).length;
  lines.push(`  ${palette.bold("Deep Static")}`);
  lines.push(
    `    ${attackPathCountLabel(attackPaths.length, rawAttackPathCount)}${
      supported > 0 ? ` · ${supported} with static support` : ""
    }`,
  );

  const families = familyCounts(attackPaths);
  if (families.length > 0) {
    lines.push(`    ${families.map(({ label, count }) => `${label} ${count}`).join(" · ")}`);
  }

  const examples = representativeAttackPaths(attackPaths, 3);
  for (const path of examples) {
    lines.push(`    ${glyph.step} ${trimForTerminal(path.reason, 100)}`);
  }

  const coverage = deepCoverageLine(assessment);
  if (coverage !== undefined) {
    lines.push(`    ${palette.dim(coverage)}`);
  }

  const limitations = assessment.limitations ?? [];
  if (limitations.length > 0) {
    lines.push(`    ${palette.yellow(glyph.warn)} ${trimForTerminal(limitations[0] ?? "", 110)}`);
  } else if (attackPaths.length > 0) {
    lines.push(
      `    ${palette.dim("Static paths still need runtime validation before you treat them as confirmed exploits.")}`,
    );
  }
  lines.push("");
}

function terminalAttackPaths(assessment: SecurityAssessment): TerminalAttackPath[] {
  const candidates = new Map(
    (assessment.hypothesisCandidates ?? []).map((candidate) => [candidate.id, candidate]),
  );
  const seen = new Set<string>();
  const out: TerminalAttackPath[] = [];

  for (const hypothesis of [...(assessment.staticHypotheses ?? [])].sort(
    (a, b) =>
      b.staticConfidence - a.staticConfidence ||
      a.title.localeCompare(b.title) ||
      a.id.localeCompare(b.id),
  )) {
    if (hypothesis.status === "statically_contradicted") {
      continue;
    }
    const candidate = candidates.get(hypothesis.candidateId);
    const family = candidate?.family ?? "static_analysis";
    const reason = candidate?.candidateReason ?? hypothesis.pathSummary;
    const key = `${family}\0${terminalAttackPathDedupReason(reason)}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push({ hypothesis, family, reason });
  }

  return out;
}

function terminalAttackPathDedupReason(reason: string): string {
  return reason.replace(/\s\([^()\n]+:\d+\)/g, "");
}

function attackPathCountLabel(uniqueCount: number, rawCount: number): string {
  const noun = uniqueCount === 1 ? "attack path" : "attack paths";
  if (rawCount > uniqueCount) {
    return `${uniqueCount} unique likely ${noun} traced from ${rawCount} static traces`;
  }
  return `${uniqueCount} likely ${noun} traced`;
}

function familyCounts(
  paths: ReadonlyArray<TerminalAttackPath>,
): ReadonlyArray<{ readonly label: string; readonly count: number }> {
  const counts = new Map<string, number>();
  for (const path of paths) {
    counts.set(path.family, (counts.get(path.family) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([family, count]) => ({ label: familyLabel(family), count }));
}

function representativeAttackPaths(
  paths: ReadonlyArray<TerminalAttackPath>,
  limit: number,
): TerminalAttackPath[] {
  const seenFamilies = new Set<string>();
  const out: TerminalAttackPath[] = [];
  for (const path of paths) {
    if (seenFamilies.has(path.family)) {
      continue;
    }
    seenFamilies.add(path.family);
    out.push(path);
    if (out.length >= limit) {
      break;
    }
  }
  if (out.length >= limit) {
    return out;
  }
  for (const path of paths) {
    if (out.includes(path)) {
      continue;
    }
    out.push(path);
    if (out.length >= limit) {
      break;
    }
  }
  return out;
}

function deepCoverageLine(assessment: SecurityAssessment): string | undefined {
  const entries = assessment.deepCoverage ?? [];
  if (entries.length === 0) {
    return undefined;
  }
  const byArea = new Map(entries.map((entry) => [entry.area, entry]));
  const parts = TERMINAL_COVERAGE_AREAS.flatMap((area) => {
    const entry = byArea.get(area);
    if (entry === undefined) {
      return [];
    }
    const counts =
      entry.coveredCount === undefined || entry.totalCount === undefined
        ? ""
        : ` ${entry.coveredCount}/${entry.totalCount}`;
    return [`${coverageLabel(area)} ${entry.state}${counts}`];
  });
  return parts.length === 0 ? undefined : `Coverage: ${parts.join(" · ")}`;
}

function familyLabel(family: string): string {
  switch (family) {
    case "external_input_to_dangerous_operation":
      return "input-to-danger";
    case "sast_reachable_path":
      return "reachable SAST";
    case "dependency_usage_path":
      return "dependency usage";
    case "ci_supply_chain_path":
      return "CI supply chain";
    case "secret_impact_chain":
      return "secret impact";
    case "content_resource_exposure_path":
      return "hidden content";
    case "smart_contract_risk_path":
      return "smart contract";
    default:
      return family.replaceAll("_", " ");
  }
}

function coverageLabel(area: string): string {
  switch (area) {
    case "language_support":
      return "languages";
    case "data_flow":
      return "data flow";
    case "dependency_usage":
      return "dependency usage";
    case "ci_iac":
      return "CI/IaC";
    case "content_assets":
      return "content assets";
    case "smart_contracts":
      return "smart contracts";
    default:
      return area.replaceAll("_", " ");
  }
}

function trimForTerminal(value: string, maxLength: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxLength) {
    return compact;
  }
  return `${compact.slice(0, Math.max(0, maxLength - 1)).trimEnd()}…`;
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
