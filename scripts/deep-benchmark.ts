#!/usr/bin/env tsx
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import type { DeepCoverageEntry } from "../src/domain/deep-coverage.js";
import type { Finding } from "../src/domain/finding.js";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
import type { SecurityAssessment } from "../src/domain/security-assessment.js";
import type { StaticHypothesis } from "../src/domain/static-hypothesis.js";

interface DeepReportJson {
  readonly runId: string;
  readonly assessment: SecurityAssessment;
}

interface BenchmarkSummary {
  readonly runId: string;
  readonly reportPath: string;
  readonly repository: string;
  readonly expectedName?: string;
  readonly verdict: string;
  readonly findings: number;
  readonly hypothesisCandidates: number;
  readonly staticHypotheses: number;
  readonly supportedHypotheses: number;
  readonly families: Readonly<Record<string, number>>;
  readonly coverage: Readonly<Record<string, CoverageSummary>>;
  readonly limitations: ReadonlyArray<string>;
  readonly groundTruth: GroundTruthSummary;
  readonly groundTruthGaps: ReadonlyArray<string>;
  readonly resolvedKnownGaps: ReadonlyArray<string>;
  readonly errors: ReadonlyArray<string>;
}

interface BenchmarkRun {
  readonly report: DeepReportJson;
  readonly summary: BenchmarkSummary;
}

interface GroundTruthSummary {
  readonly total: number;
  readonly passed: number;
  readonly knownGaps: number;
  readonly failed: number;
  readonly resolvedKnownGaps: number;
}

interface CoverageSummary {
  readonly state: string;
  readonly coveredCount?: number;
  readonly totalCount?: number;
  readonly reason?: string;
}

interface BenchmarkExpectationFile {
  readonly version: 1;
  readonly repositories: ReadonlyArray<BenchmarkExpectation>;
}

interface BenchmarkExpectation {
  readonly name: string;
  readonly match: {
    readonly originUrl?: string;
    readonly localPathSuffix?: string;
  };
  readonly minFindings?: number;
  readonly minHypothesisCandidates?: number;
  readonly minSupportedHypotheses?: number;
  readonly requiredFamilies?: Readonly<Record<string, number>>;
  readonly coverage?: Readonly<Record<string, CoverageExpectation>>;
  readonly groundTruth?: ReadonlyArray<GroundTruthItem>;
}

interface CoverageExpectation {
  readonly stateIn?: ReadonlyArray<string>;
  readonly minCoveredCount?: number;
  readonly minTotalCount?: number;
  readonly complete?: boolean;
  readonly reasonIncludes?: string;
}

type GroundTruthItem =
  | FamilyGroundTruthItem
  | FindingGroundTruthItem
  | HypothesisGroundTruthItem
  | CoverageGroundTruthItem
  | LimitationGroundTruthItem;

interface GroundTruthBase {
  readonly id: string;
  readonly title: string;
  readonly expected?: GroundTruthExpectation;
}

type GroundTruthExpectation = "covered" | "known_gap";

interface FamilyGroundTruthItem extends GroundTruthBase {
  readonly kind: "family";
  readonly family: string;
  readonly minCount?: number;
}

interface FindingGroundTruthItem extends GroundTruthBase {
  readonly kind: "finding";
  readonly ruleId?: string;
  readonly category?: string;
  readonly remediationKey?: string;
  readonly severityIn?: ReadonlyArray<string>;
  readonly filePathIncludes?: string;
  readonly minCount?: number;
}

interface HypothesisGroundTruthItem extends GroundTruthBase {
  readonly kind: "hypothesis";
  readonly family?: string;
  readonly ruleId?: string;
  readonly titleIncludes?: string;
  readonly candidateReasonIncludes?: string;
  readonly statusIn?: ReadonlyArray<string>;
  readonly minCount?: number;
}

interface CoverageGroundTruthItem extends GroundTruthBase {
  readonly kind: "coverage";
  readonly area: string;
  readonly stateIn?: ReadonlyArray<string>;
  readonly minCoveredCount?: number;
  readonly complete?: boolean;
  readonly reasonIncludes?: string;
}

interface LimitationGroundTruthItem extends GroundTruthBase {
  readonly kind: "limitation";
  readonly textIncludes: string;
}

interface CliOptions {
  readonly jsonOutput: boolean;
  readonly strictGroundTruth: boolean;
  readonly expectPath?: string;
  readonly inputs: ReadonlyArray<string>;
}

const options = parseArgs(process.argv.slice(2));

if (options.inputs.length === 0) {
  process.stderr.write(
    "Usage: pnpm exec tsx scripts/deep-benchmark.ts [--json] [--strict-ground-truth] [--expect benchmarks/deep-static-training-baseline.json] <run-dir-or-report.json>...\n",
  );
  process.exit(2);
}

const baseRuns = await Promise.all(
  options.inputs.map(async (input) => summarizeReport(await reportPath(input))),
);
const expectationFile =
  options.expectPath === undefined ? undefined : await loadExpectations(options.expectPath);
const { runs, globalErrors } =
  expectationFile === undefined
    ? { runs: baseRuns, globalErrors: [] }
    : applyExpectations(baseRuns, expectationFile, {
        strictGroundTruth: options.strictGroundTruth,
      });
const summaries = runs.map((run) => run.summary);
const failed = summaries.some((summary) => summary.errors.length > 0);

if (options.jsonOutput) {
  process.stdout.write(`${JSON.stringify(summaries, null, 2)}\n`);
} else {
  for (const summary of summaries) {
    const status = summary.errors.length === 0 ? "PASS" : "FAIL";
    const families = Object.entries(summary.families)
      .map(([family, count]) => `${family}=${count}`)
      .join(", ");
    const coverage = Object.entries(summary.coverage)
      .map(([area, entry]) => {
        const counts =
          entry.coveredCount === undefined || entry.totalCount === undefined
            ? ""
            : ` ${entry.coveredCount}/${entry.totalCount}`;
        return `${area}:${entry.state}${counts}`;
      })
      .join(", ");
    process.stdout.write(
      `${status} ${summary.repository} ${summary.runId} findings=${summary.findings} candidates=${summary.hypothesisCandidates} supported=${summary.supportedHypotheses}${
        summary.expectedName === undefined ? "" : ` expected=${summary.expectedName}`
      }\n`,
    );
    if (summary.groundTruth.total > 0) {
      process.stdout.write(
        `  ground truth: ${summary.groundTruth.passed}/${summary.groundTruth.total} covered${
          summary.groundTruth.knownGaps > 0 ? `, ${summary.groundTruth.knownGaps} known gaps` : ""
        }${summary.groundTruth.failed > 0 ? `, ${summary.groundTruth.failed} failed` : ""}${
          summary.groundTruth.resolvedKnownGaps > 0
            ? `, ${summary.groundTruth.resolvedKnownGaps} known gaps resolved`
            : ""
        }\n`,
      );
    }
    process.stdout.write(`  families: ${families || "none"}\n`);
    process.stdout.write(`  coverage: ${coverage || "none"}\n`);
    for (const error of summary.errors) {
      process.stdout.write(`  error: ${error}\n`);
    }
    for (const gap of summary.groundTruthGaps) {
      process.stdout.write(`  known gap: ${gap}\n`);
    }
    for (const resolved of summary.resolvedKnownGaps) {
      process.stdout.write(`  resolved known gap: ${resolved}\n`);
    }
  }
  for (const error of globalErrors) {
    process.stdout.write(`FAIL benchmark ${error}\n`);
  }
}

process.exit(failed || globalErrors.length > 0 ? 1 : 0);

function parseArgs(args: ReadonlyArray<string>): CliOptions {
  const inputs: string[] = [];
  let jsonOutput = false;
  let strictGroundTruth = false;
  let expectPath: string | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      jsonOutput = true;
      continue;
    }
    if (arg === "--strict-ground-truth") {
      strictGroundTruth = true;
      continue;
    }
    if (arg === "--expect") {
      const value = args[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new Error("--expect requires a file path");
      }
      expectPath = value;
      index += 1;
      continue;
    }
    if (arg?.startsWith("--expect=") === true) {
      expectPath = arg.slice("--expect=".length);
      continue;
    }
    if (arg?.startsWith("--") === true) {
      throw new Error(`Unknown option: ${arg}`);
    }
    if (arg !== undefined) {
      inputs.push(arg);
    }
  }
  return {
    jsonOutput,
    strictGroundTruth,
    ...(expectPath === undefined ? {} : { expectPath }),
    inputs,
  };
}

async function reportPath(input: string): Promise<string> {
  const resolved = path.resolve(input);
  const info = await stat(resolved);
  return info.isDirectory() ? path.join(resolved, "report.json") : resolved;
}

async function summarizeReport(reportPathValue: string): Promise<BenchmarkRun> {
  const parsed = JSON.parse(await readFile(reportPathValue, "utf8")) as DeepReportJson;
  const assessment = parsed.assessment;
  const candidates = assessment.hypothesisCandidates ?? [];
  const hypotheses = assessment.staticHypotheses ?? [];
  const coverage = coverageSummary(assessment.deepCoverage ?? []);
  const errors = benchmarkErrors({ assessment, candidates, hypotheses, coverage });

  return {
    report: parsed,
    summary: {
      runId: parsed.runId,
      reportPath: reportPathValue,
      repository: repositoryName(assessment),
      verdict: assessment.verdict,
      findings: assessment.findings.length,
      hypothesisCandidates: candidates.length,
      staticHypotheses: hypotheses.length,
      supportedHypotheses: hypotheses.filter(
        (hypothesis) => hypothesis.status === "statically_supported",
      ).length,
      families: familyCounts(candidates),
      coverage,
      limitations: assessment.limitations ?? [],
      groundTruth: { total: 0, passed: 0, knownGaps: 0, failed: 0, resolvedKnownGaps: 0 },
      groundTruthGaps: [],
      resolvedKnownGaps: [],
      errors,
    },
  };
}

async function loadExpectations(expectPath: string): Promise<BenchmarkExpectationFile> {
  const parsed = JSON.parse(
    await readFile(path.resolve(expectPath), "utf8"),
  ) as BenchmarkExpectationFile;
  if (parsed.version !== 1 || !Array.isArray(parsed.repositories)) {
    throw new Error(`Invalid benchmark expectation file: ${expectPath}`);
  }
  return parsed;
}

function applyExpectations(
  runs: ReadonlyArray<BenchmarkRun>,
  expectationFile: BenchmarkExpectationFile,
  options: { readonly strictGroundTruth: boolean },
): {
  readonly runs: ReadonlyArray<BenchmarkRun>;
  readonly globalErrors: ReadonlyArray<string>;
} {
  const used = new Set<number>();
  const checked = runs.map((run) => {
    const matches = expectationFile.repositories
      .map((expectation, index) => ({ expectation, index }))
      .filter(({ expectation }) => matchesExpectation(run.summary, expectation));
    if (matches.length === 0) {
      return {
        ...run,
        summary: {
          ...run.summary,
          errors: [
            ...run.summary.errors,
            "no matching benchmark expectation found for this repository",
          ],
        },
      };
    }
    if (matches.length > 1) {
      return {
        ...run,
        summary: {
          ...run.summary,
          errors: [
            ...run.summary.errors,
            `multiple benchmark expectations matched this repository: ${matches
              .map(({ expectation }) => expectation.name)
              .join(", ")}`,
          ],
        },
      };
    }
    const match = matches[0];
    if (match === undefined) {
      return run;
    }
    used.add(match.index);
    const groundTruth = evaluateGroundTruth(
      run,
      match.expectation.groundTruth ?? [],
      options.strictGroundTruth,
    );
    return {
      ...run,
      summary: {
        ...run.summary,
        expectedName: match.expectation.name,
        groundTruth: groundTruth.summary,
        groundTruthGaps: groundTruth.gaps,
        resolvedKnownGaps: groundTruth.resolvedKnownGaps,
        errors: [
          ...run.summary.errors,
          ...expectationErrors(run, match.expectation),
          ...groundTruth.errors,
        ],
      },
    };
  });
  const globalErrors = expectationFile.repositories.flatMap((expectation, index) =>
    used.has(index) ? [] : [`missing expected repository: ${expectation.name}`],
  );
  return { runs: checked, globalErrors };
}

function matchesExpectation(summary: BenchmarkSummary, expectation: BenchmarkExpectation): boolean {
  const originUrl = expectation.match.originUrl;
  if (
    originUrl !== undefined &&
    normalizeSource(summary.repository) === normalizeSource(originUrl)
  ) {
    return true;
  }
  const suffix = expectation.match.localPathSuffix;
  return suffix !== undefined && summary.repository.endsWith(suffix);
}

function expectationErrors(run: BenchmarkRun, expectation: BenchmarkExpectation): string[] {
  const summary = run.summary;
  const errors: string[] = [];
  if (expectation.minFindings !== undefined && summary.findings < expectation.minFindings) {
    errors.push(`findings below expectation: ${summary.findings}/${expectation.minFindings}`);
  }
  if (
    expectation.minHypothesisCandidates !== undefined &&
    summary.hypothesisCandidates < expectation.minHypothesisCandidates
  ) {
    errors.push(
      `hypothesisCandidates below expectation: ${summary.hypothesisCandidates}/${expectation.minHypothesisCandidates}`,
    );
  }
  if (
    expectation.minSupportedHypotheses !== undefined &&
    summary.supportedHypotheses < expectation.minSupportedHypotheses
  ) {
    errors.push(
      `supported hypotheses below expectation: ${summary.supportedHypotheses}/${expectation.minSupportedHypotheses}`,
    );
  }
  for (const [family, expectedCount] of Object.entries(expectation.requiredFamilies ?? {})) {
    const actual = summary.families[family] ?? 0;
    if (actual < expectedCount) {
      errors.push(`family ${family} below expectation: ${actual}/${expectedCount}`);
    }
  }
  for (const [area, expected] of Object.entries(expectation.coverage ?? {})) {
    const actual = summary.coverage[area];
    if (actual === undefined) {
      errors.push(`missing coverage area: ${area}`);
      continue;
    }
    if (expected.stateIn !== undefined && !expected.stateIn.includes(actual.state)) {
      errors.push(`coverage ${area} state ${actual.state} not in ${expected.stateIn.join(", ")}`);
    }
    if (
      expected.minCoveredCount !== undefined &&
      (actual.coveredCount ?? 0) < expected.minCoveredCount
    ) {
      errors.push(
        `coverage ${area} coveredCount below expectation: ${actual.coveredCount ?? 0}/${expected.minCoveredCount}`,
      );
    }
    if (expected.minTotalCount !== undefined && (actual.totalCount ?? 0) < expected.minTotalCount) {
      errors.push(
        `coverage ${area} totalCount below expectation: ${actual.totalCount ?? 0}/${expected.minTotalCount}`,
      );
    }
    if (
      expected.complete === true &&
      actual.totalCount !== undefined &&
      actual.coveredCount !== actual.totalCount
    ) {
      errors.push(
        `coverage ${area} is incomplete: ${actual.coveredCount ?? 0}/${actual.totalCount}`,
      );
    }
    if (
      expected.reasonIncludes !== undefined &&
      actual.reason?.includes(expected.reasonIncludes) !== true
    ) {
      errors.push(`coverage ${area} reason does not include ${expected.reasonIncludes}`);
    }
  }
  return errors;
}

function evaluateGroundTruth(
  run: BenchmarkRun,
  items: ReadonlyArray<GroundTruthItem>,
  strictGroundTruth: boolean,
): {
  readonly summary: GroundTruthSummary;
  readonly errors: ReadonlyArray<string>;
  readonly gaps: ReadonlyArray<string>;
  readonly resolvedKnownGaps: ReadonlyArray<string>;
} {
  let passed = 0;
  let knownGaps = 0;
  let failed = 0;
  let resolvedKnownGaps = 0;
  const errors: string[] = [];
  const gaps: string[] = [];
  const resolved: string[] = [];

  for (const item of items) {
    const itemErrors = groundTruthItemErrors(run, item);
    const expected = item.expected ?? "covered";
    if (expected === "covered") {
      if (itemErrors.length === 0) {
        passed += 1;
      } else {
        failed += 1;
        errors.push(...itemErrors.map((error) => `groundTruth ${item.id}: ${error}`));
      }
      continue;
    }

    if (itemErrors.length === 0) {
      resolvedKnownGaps += 1;
      resolved.push(`${item.id}: ${item.title}`);
      continue;
    }

    knownGaps += 1;
    gaps.push(`${item.id}: ${item.title} (${itemErrors.join("; ")})`);
    if (strictGroundTruth) {
      errors.push(`groundTruth ${item.id}: known gap still unresolved: ${itemErrors.join("; ")}`);
    }
  }

  return {
    summary: {
      total: items.length,
      passed,
      knownGaps,
      failed,
      resolvedKnownGaps,
    },
    errors,
    gaps,
    resolvedKnownGaps: resolved,
  };
}

function groundTruthItemErrors(run: BenchmarkRun, item: GroundTruthItem): string[] {
  const summary = run.summary;
  switch (item.kind) {
    case "family": {
      const expected = item.minCount ?? 1;
      const actual = summary.families[item.family] ?? 0;
      return actual >= expected
        ? []
        : [`${item.title} family ${item.family} below expectation: ${actual}/${expected}`];
    }
    case "finding":
      return countExpectationErrors(
        item.title,
        run.report.assessment.findings.filter((finding) => matchesFinding(finding, item)).length,
        item.minCount ?? 1,
      );
    case "hypothesis":
      return countExpectationErrors(
        item.title,
        matchingHypotheses(run, item).length,
        item.minCount ?? 1,
      );
    case "coverage": {
      const actual = summary.coverage[item.area];
      if (actual === undefined) {
        return [`${item.title} missing coverage area: ${item.area}`];
      }
      const errors: string[] = [];
      if (item.stateIn !== undefined && !item.stateIn.includes(actual.state)) {
        errors.push(`${item.title} coverage ${item.area} state ${actual.state}`);
      }
      if (item.minCoveredCount !== undefined && (actual.coveredCount ?? 0) < item.minCoveredCount) {
        errors.push(
          `${item.title} coverage ${item.area} coveredCount ${(actual.coveredCount ?? 0).toString()}/${item.minCoveredCount}`,
        );
      }
      if (
        item.complete === true &&
        actual.totalCount !== undefined &&
        actual.coveredCount !== actual.totalCount
      ) {
        errors.push(
          `${item.title} coverage ${item.area} incomplete ${(actual.coveredCount ?? 0).toString()}/${actual.totalCount}`,
        );
      }
      if (
        item.reasonIncludes !== undefined &&
        actual.reason?.includes(item.reasonIncludes) !== true
      ) {
        errors.push(
          `${item.title} coverage ${item.area} reason does not include ${item.reasonIncludes}`,
        );
      }
      return errors;
    }
    case "limitation":
      return summaryHasLimitation(summary, item.textIncludes)
        ? []
        : [`${item.title} limitation not found: ${item.textIncludes}`];
  }
}

function matchesFinding(finding: Finding, item: FindingGroundTruthItem): boolean {
  if (item.ruleId !== undefined && finding.ruleId !== item.ruleId) {
    return false;
  }
  if (item.category !== undefined && finding.category !== item.category) {
    return false;
  }
  if (item.remediationKey !== undefined && finding.remediationKey !== item.remediationKey) {
    return false;
  }
  if (item.severityIn !== undefined && !item.severityIn.includes(finding.severity)) {
    return false;
  }
  if (
    item.filePathIncludes !== undefined &&
    !finding.locations.some((location) => location.filePath.includes(item.filePathIncludes ?? ""))
  ) {
    return false;
  }
  return true;
}

function matchingHypotheses(
  run: BenchmarkRun,
  item: HypothesisGroundTruthItem,
): StaticHypothesis[] {
  const candidates = new Map(
    (run.report.assessment.hypothesisCandidates ?? []).map((candidate) => [
      candidate.id,
      candidate,
    ]),
  );
  return (run.report.assessment.staticHypotheses ?? []).filter((hypothesis) => {
    const candidate = candidates.get(hypothesis.candidateId);
    if (candidate === undefined) {
      return false;
    }
    if (item.family !== undefined && candidate.family !== item.family) {
      return false;
    }
    if (item.ruleId !== undefined && candidate.ruleId !== item.ruleId) {
      return false;
    }
    if (item.titleIncludes !== undefined && !hypothesis.title.includes(item.titleIncludes)) {
      return false;
    }
    if (
      item.candidateReasonIncludes !== undefined &&
      !candidate.candidateReason.includes(item.candidateReasonIncludes)
    ) {
      return false;
    }
    if (item.statusIn !== undefined && !item.statusIn.includes(hypothesis.status)) {
      return false;
    }
    return true;
  });
}

function countExpectationErrors(title: string, actual: number, expected: number): string[] {
  return actual >= expected ? [] : [`${title} matches below expectation: ${actual}/${expected}`];
}

function benchmarkErrors(input: {
  readonly assessment: SecurityAssessment;
  readonly candidates: ReadonlyArray<HypothesisCandidate>;
  readonly hypotheses: ReadonlyArray<StaticHypothesis>;
  readonly coverage: Readonly<Record<string, CoverageSummary>>;
}): string[] {
  const errors: string[] = [];
  const supported = input.hypotheses.filter(
    (hypothesis) => hypothesis.status === "statically_supported",
  );
  if (input.assessment.deepCoverage !== undefined && input.candidates.length === 0) {
    errors.push("deep report does not expose hypothesisCandidates for benchmark auditing");
  }
  if (input.assessment.deepCoverage !== undefined && supported.length === 0) {
    errors.push("deep report has no statically_supported hypotheses");
  }
  for (const [area, entry] of Object.entries(input.coverage)) {
    if (entry.state === "failed") {
      errors.push(
        `deep coverage failed for ${area}${entry.reason === undefined ? "" : `: ${entry.reason}`}`,
      );
    }
  }
  const dependencyUsage = input.coverage.dependency_usage;
  if (
    dependencyUsage?.totalCount !== undefined &&
    dependencyUsage.totalCount > 0 &&
    dependencyUsage.coveredCount !== dependencyUsage.totalCount
  ) {
    errors.push(
      `dependency_usage is incomplete: ${dependencyUsage.coveredCount ?? 0}/${dependencyUsage.totalCount}`,
    );
  }
  return errors;
}

function coverageSummary(
  entries: ReadonlyArray<DeepCoverageEntry>,
): Record<string, CoverageSummary> {
  const out: Record<string, CoverageSummary> = {};
  for (const entry of entries) {
    out[entry.area] = {
      state: entry.state,
      ...(entry.coveredCount === undefined ? {} : { coveredCount: entry.coveredCount }),
      ...(entry.totalCount === undefined ? {} : { totalCount: entry.totalCount }),
      ...(entry.reason === undefined ? {} : { reason: entry.reason }),
    };
  }
  return out;
}

function familyCounts(candidates: ReadonlyArray<HypothesisCandidate>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const candidate of candidates) {
    out[candidate.family] = (out[candidate.family] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(out).sort((a, b) => a[0].localeCompare(b[0])));
}

function repositoryName(assessment: SecurityAssessment): string {
  return (
    assessment.repository.originUrl ??
    assessment.repository.localPath ??
    assessment.repository.name ??
    "repository"
  );
}

function summaryHasLimitation(summary: BenchmarkSummary, text: string): boolean {
  return summary.limitations.some((limitation) => limitation.includes(text));
}

function normalizeSource(value: string): string {
  return value.replace(/\/$/, "").replace(/\.git$/, "");
}
