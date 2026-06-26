#!/usr/bin/env tsx
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Verdict } from "../src/domain/assessment.js";
import type { DeepCoverageEntry } from "../src/domain/deep-coverage.js";
import type { Finding } from "../src/domain/finding.js";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
import type { SecurityAssessment } from "../src/domain/security-assessment.js";
import type { StaticHypothesis } from "../src/domain/static-hypothesis.js";

export interface DeepReportJson {
  readonly runId: string;
  readonly assessment: SecurityAssessment;
}

export interface DeepScoreExpectationFile {
  readonly version: 1;
  readonly targets?: Partial<ScoreTargets>;
  readonly repositories: ReadonlyArray<ScoredRepositoryExpectation>;
}

export interface ScoreTargets {
  readonly directPrecision: number;
  readonly directRecall: number;
  readonly directF05: number;
  readonly staticSupportPrecision: number;
  readonly staticCandidateRecall: number;
  readonly maxTuningHeldOutGap: number;
}

export interface ScoredRepositoryExpectation {
  readonly name: string;
  readonly language: string;
  readonly split: "canary" | "held-out" | "tuning";
  readonly match: {
    readonly originUrl?: string;
    readonly localPathSuffix?: string;
  };
  readonly expectedVerdict?: Verdict;
  readonly directTruth: Completeness;
  readonly directFpReview: Completeness;
  readonly staticTruth: Completeness;
  readonly staticSupportReview: Completeness;
  readonly directFindings?: ReadonlyArray<DirectTruthItem>;
  readonly staticHypotheses?: ReadonlyArray<StaticTruthItem>;
  readonly trueButUncuratedDirect?: ReadonlyArray<DirectMatcherItem>;
  readonly trueButUncuratedStatic?: ReadonlyArray<StaticMatcherItem>;
  readonly coverage?: Readonly<Record<string, CoverageExpectation>>;
  readonly notes?: ReadonlyArray<string>;
}

type Completeness = "complete" | "incomplete";

export interface DirectTruthItem {
  readonly id: string;
  readonly title: string;
  readonly class?: string;
  readonly cwe?: string;
  readonly coverageArea: string;
  readonly inStaticScope?: boolean;
  readonly matcher: DirectFindingMatcher;
}

export interface StaticTruthItem {
  readonly id: string;
  readonly title: string;
  readonly class?: string;
  readonly cwe?: string;
  readonly coverageArea: string;
  readonly candidateFamily: string;
  readonly inGraphScope?: boolean;
  readonly matcher: StaticHypothesisMatcher;
}

export interface DirectMatcherItem {
  readonly id: string;
  readonly reason: string;
  readonly matcher: DirectFindingMatcher;
}

export interface StaticMatcherItem {
  readonly id: string;
  readonly reason: string;
  readonly matcher: StaticHypothesisMatcher;
}

export interface DirectFindingMatcher {
  readonly sourceTool?: string;
  readonly ruleId?: string;
  readonly category?: string;
  readonly remediationKey?: string;
  readonly severityIn?: ReadonlyArray<string>;
  readonly filePathIncludes?: string;
  readonly metadata?: Readonly<Record<string, string>>;
}

export interface StaticHypothesisMatcher {
  readonly family?: string;
  readonly ruleId?: string;
  readonly titleIncludes?: string;
  readonly titleIncludesAll?: ReadonlyArray<string>;
  readonly candidateReasonIncludes?: string;
  readonly candidateReasonIncludesAll?: ReadonlyArray<string>;
  readonly pathSummaryIncludes?: string;
  readonly pathSummaryIncludesAll?: ReadonlyArray<string>;
  readonly statusIn?: ReadonlyArray<string>;
}

export interface CoverageExpectation {
  readonly stateIn?: ReadonlyArray<string>;
  readonly complete?: boolean;
  readonly minCoveredCount?: number;
  readonly minTotalCount?: number;
  readonly reasonIncludes?: string;
}

export interface BenchmarkScoreSummary {
  readonly repositories: ReadonlyArray<RepositoryScore>;
  readonly missingRepositories: ReadonlyArray<string>;
  readonly aggregates: ReadonlyArray<AggregateScore>;
  readonly targetErrors: ReadonlyArray<string>;
}

export interface RepositoryScore {
  readonly name: string;
  readonly runId: string;
  readonly repository: string;
  readonly language: string;
  readonly split: "canary" | "held-out" | "tuning";
  readonly verdict: VerdictScore;
  readonly direct: DirectScore;
  readonly staticHypotheses: StaticScore;
  readonly coverageErrors: ReadonlyArray<string>;
  readonly scoreabilityErrors: ReadonlyArray<string>;
  readonly notes: ReadonlyArray<string>;
}

export interface VerdictScore {
  readonly actual: Verdict;
  readonly expected?: Verdict;
  readonly passed?: boolean;
}

export interface DirectScore {
  readonly tp: number;
  readonly fp: number;
  readonly fn: number;
  readonly fnIds: ReadonlyArray<string>;
  readonly trueButUncurated: number;
  readonly coverageLoss: number;
  readonly coverageLossIds: ReadonlyArray<string>;
  readonly outOfStaticScope: number;
  readonly outOfStaticScopeIds: ReadonlyArray<string>;
  readonly unreviewedFindings: number;
  readonly unreviewedFindingIds: ReadonlyArray<string>;
  readonly precision: RatioMetric;
  readonly recall: RatioMetric;
  readonly f05: RatioMetric;
}

export interface StaticScore {
  readonly candidateTp: number;
  readonly candidateFn: number;
  readonly candidateFnIds: ReadonlyArray<string>;
  readonly supportedTp: number;
  readonly falseSupport: number;
  readonly trueButUncuratedSupport: number;
  readonly falseContradiction: number;
  readonly falseContradictionIds: ReadonlyArray<string>;
  readonly coverageLoss: number;
  readonly coverageLossIds: ReadonlyArray<string>;
  readonly outOfGraphScope: number;
  readonly outOfGraphScopeIds: ReadonlyArray<string>;
  readonly unreviewedSupported: number;
  readonly unreviewedSupportedIds: ReadonlyArray<string>;
  readonly candidateRecall: RatioMetric;
  readonly supportPrecision: RatioMetric;
}

export interface StaticSupportReviewSummary {
  readonly name: string;
  readonly runId: string;
  readonly repository: string;
  readonly language: string;
  readonly split: "canary" | "held-out" | "tuning";
  readonly supported: number;
  readonly expectedTruth: number;
  readonly trueButUncurated: number;
  readonly unreviewed: number;
  readonly unreviewedGroups: ReadonlyArray<StaticSupportReviewGroup>;
}

export interface StaticSupportReviewGroup {
  readonly family: string;
  readonly title: string;
  readonly count: number;
  readonly sampleHypothesisIds: ReadonlyArray<string>;
  readonly sampleCandidateReasons: ReadonlyArray<string>;
}

export interface RatioMetric {
  readonly numerator: number;
  readonly denominator: number;
  readonly value: number | null;
  readonly scoreable: boolean;
  readonly blockedBy: ReadonlyArray<string>;
}

export interface AggregateScore {
  readonly key: string;
  readonly directPrecision: RatioMetric;
  readonly directRecall: RatioMetric;
  readonly directF05: RatioMetric;
  readonly staticSupportPrecision: RatioMetric;
  readonly staticCandidateRecall: RatioMetric;
}

interface CliOptions {
  readonly expectPath: string;
  readonly jsonOutput: boolean;
  readonly reviewStaticSupport: boolean;
  readonly inputs: ReadonlyArray<string>;
}

const DEFAULT_TARGETS: ScoreTargets = {
  directPrecision: 0.9,
  directRecall: 0.85,
  directF05: 0.88,
  staticSupportPrecision: 0.8,
  staticCandidateRecall: 0.8,
  maxTuningHeldOutGap: 0.1,
};
const ZERO_DENOMINATOR_REASON = "metric denominator is zero";

const mainModulePath = process.argv[1] === undefined ? undefined : path.resolve(process.argv[1]);
if (mainModulePath !== undefined && fileURLToPath(import.meta.url) === mainModulePath) {
  const options = parseArgs(process.argv.slice(2));
  if (options.inputs.length === 0) {
    process.stderr.write(
      "Usage: pnpm benchmark:score [--json] [--review-static-support] [--expect benchmarks/deep-static-scored-ground-truth.json] <run-dir-or-report.json>...\n",
    );
    process.exit(2);
  }

  const expectationFile = await loadScoreExpectations(options.expectPath);
  const reports = await Promise.all(
    options.inputs.map(async (input) => loadReport(await reportPath(input))),
  );
  if (options.reviewStaticSupport) {
    const summaries = staticSupportReviewSummaries(expectationFile, reports);
    if (options.jsonOutput) {
      process.stdout.write(`${JSON.stringify(summaries, null, 2)}\n`);
    } else {
      printStaticSupportReviewSummaries(summaries);
    }
    process.exit(0);
  }

  const summary = scoreBenchmarkReports(expectationFile, reports);
  const failed =
    summary.missingRepositories.length > 0 ||
    summary.targetErrors.length > 0 ||
    summary.repositories.some(
      (repository) =>
        repository.coverageErrors.length > 0 ||
        repository.scoreabilityErrors.length > 0 ||
        repository.verdict.passed === false,
    );

  if (options.jsonOutput) {
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  } else {
    printSummary(summary);
  }
  process.exit(failed ? 1 : 0);
}

export async function loadScoreExpectations(expectPath: string): Promise<DeepScoreExpectationFile> {
  const parsed = JSON.parse(await readFile(path.resolve(expectPath), "utf8")) as unknown;
  if (!isScoreExpectationFile(parsed)) {
    throw new Error(`Invalid scored benchmark expectation file: ${expectPath}`);
  }
  return parsed;
}

export function scoreBenchmarkReports(
  expectationFile: DeepScoreExpectationFile,
  reports: ReadonlyArray<DeepReportJson>,
): BenchmarkScoreSummary {
  const usedReportIndexes = new Set<number>();
  const repositories: RepositoryScore[] = [];
  const missingRepositories: string[] = [];

  for (const expectation of expectationFile.repositories) {
    const matches = reports
      .map((report, index) => ({ report, index }))
      .filter(({ report }) => matchesRepository(report.assessment, expectation));
    if (matches.length === 0) {
      missingRepositories.push(expectation.name);
      continue;
    }
    if (matches.length > 1) {
      throw new Error(
        `Multiple reports matched scored expectation ${expectation.name}: ${matches
          .map(({ report }) => report.runId)
          .join(", ")}`,
      );
    }
    const match = matches[0];
    if (match === undefined) {
      continue;
    }
    usedReportIndexes.add(match.index);
    repositories.push(scoreRepository(match.report, expectation));
  }

  const aggregates = aggregateScores(repositories);
  const targetErrors = targetGateErrors(
    aggregates,
    repositories,
    expectationFile.targets === undefined
      ? DEFAULT_TARGETS
      : { ...DEFAULT_TARGETS, ...expectationFile.targets },
  );

  for (const [index, report] of reports.entries()) {
    if (!usedReportIndexes.has(index)) {
      missingRepositories.push(`unmatched report: ${repositoryName(report.assessment)}`);
    }
  }

  return { repositories, missingRepositories, aggregates, targetErrors };
}

export function staticSupportReviewSummaries(
  expectationFile: DeepScoreExpectationFile,
  reports: ReadonlyArray<DeepReportJson>,
): StaticSupportReviewSummary[] {
  const summaries: StaticSupportReviewSummary[] = [];
  for (const expectation of expectationFile.repositories) {
    const report = reports.find((candidate) =>
      matchesRepository(candidate.assessment, expectation),
    );
    if (report === undefined) {
      continue;
    }
    summaries.push(staticSupportReviewSummary(report, expectation));
  }
  return summaries;
}

function staticSupportReviewSummary(
  report: DeepReportJson,
  expectation: ScoredRepositoryExpectation,
): StaticSupportReviewSummary {
  const candidates = report.assessment.hypothesisCandidates ?? [];
  const hypotheses = report.assessment.staticHypotheses ?? [];
  const candidatesById = new Map(candidates.map((candidate) => [candidate.id, candidate]));
  const supportedHypotheses = hypotheses.filter(
    (hypothesis) => hypothesis.status === "statically_supported",
  );
  const expectedTruthIds = new Set<string>();

  for (const item of expectation.staticHypotheses ?? []) {
    if (item.inGraphScope === false) {
      continue;
    }
    const hypothesis = supportedHypotheses.find(
      (supported) =>
        !expectedTruthIds.has(supported.id) &&
        matchesStaticHypothesis(supported, candidatesById, item.matcher, item.candidateFamily),
    );
    if (hypothesis !== undefined) {
      expectedTruthIds.add(hypothesis.id);
    }
  }

  const trueButUncuratedIds = new Set<string>();
  for (const hypothesis of supportedHypotheses) {
    if (expectedTruthIds.has(hypothesis.id)) {
      continue;
    }
    if (
      (expectation.trueButUncuratedStatic ?? []).some((item) =>
        matchesStaticHypothesis(hypothesis, candidatesById, item.matcher),
      )
    ) {
      trueButUncuratedIds.add(hypothesis.id);
    }
  }

  const groups = new Map<string, MutableStaticSupportReviewGroup>();
  for (const hypothesis of supportedHypotheses) {
    if (expectedTruthIds.has(hypothesis.id) || trueButUncuratedIds.has(hypothesis.id)) {
      continue;
    }
    const candidate = candidatesById.get(hypothesis.candidateId);
    const family = candidate?.family ?? "unknown";
    const key = `${family}\0${hypothesis.title}`;
    const existing = groups.get(key) ?? {
      family,
      title: hypothesis.title,
      count: 0,
      sampleHypothesisIds: [],
      sampleCandidateReasons: [],
    };
    existing.count += 1;
    if (existing.sampleHypothesisIds.length < 5) {
      existing.sampleHypothesisIds.push(hypothesis.id);
    }
    if (candidate !== undefined && existing.sampleCandidateReasons.length < 3) {
      existing.sampleCandidateReasons.push(candidate.candidateReason);
    }
    groups.set(key, existing);
  }

  const unreviewedGroups = [...groups.values()]
    .map((group) => ({
      family: group.family,
      title: group.title,
      count: group.count,
      sampleHypothesisIds: group.sampleHypothesisIds,
      sampleCandidateReasons: group.sampleCandidateReasons,
    }))
    .sort(
      (a, b) =>
        b.count - a.count || a.family.localeCompare(b.family) || a.title.localeCompare(b.title),
    );

  return {
    name: expectation.name,
    runId: report.runId,
    repository: repositoryName(report.assessment),
    language: expectation.language,
    split: expectation.split,
    supported: supportedHypotheses.length,
    expectedTruth: expectedTruthIds.size,
    trueButUncurated: trueButUncuratedIds.size,
    unreviewed: supportedHypotheses.length - expectedTruthIds.size - trueButUncuratedIds.size,
    unreviewedGroups,
  };
}

interface MutableStaticSupportReviewGroup {
  readonly family: string;
  readonly title: string;
  count: number;
  readonly sampleHypothesisIds: string[];
  readonly sampleCandidateReasons: string[];
}

export function scoreRepository(
  report: DeepReportJson,
  expectation: ScoredRepositoryExpectation,
): RepositoryScore {
  const coverage = coverageSummary(report.assessment.deepCoverage ?? []);
  const direct = scoreDirectFindings(report.assessment, expectation, coverage);
  const staticHypotheses = scoreStaticHypotheses(report.assessment, expectation, coverage);
  const coverageErrors = coverageGateErrors(coverage, expectation);
  const scoreabilityErrors = [
    ...direct.precision.blockedBy
      .filter((reason) => !isZeroDenominatorReason(reason))
      .map((reason) => `direct precision not scoreable: ${reason}`),
    ...direct.recall.blockedBy
      .filter((reason) => !isZeroDenominatorReason(reason))
      .map((reason) => `direct recall not scoreable: ${reason}`),
    ...staticHypotheses.supportPrecision.blockedBy.map(
      (reason) => `static support precision not scoreable: ${reason}`,
    ),
    ...staticHypotheses.candidateRecall.blockedBy.map(
      (reason) => `static candidate recall not scoreable: ${reason}`,
    ),
  ];

  return {
    name: expectation.name,
    runId: report.runId,
    repository: repositoryName(report.assessment),
    language: expectation.language,
    split: expectation.split,
    verdict: {
      actual: report.assessment.verdict,
      ...(expectation.expectedVerdict === undefined
        ? {}
        : {
            expected: expectation.expectedVerdict,
            passed: report.assessment.verdict === expectation.expectedVerdict,
          }),
    },
    direct,
    staticHypotheses,
    coverageErrors,
    scoreabilityErrors,
    notes: expectation.notes ?? [],
  };
}

function scoreDirectFindings(
  assessment: SecurityAssessment,
  expectation: ScoredRepositoryExpectation,
  coverage: Readonly<Record<string, CoverageSummary>>,
): DirectScore {
  const findings = assessment.findings;
  const unusedFindingIndexes = new Set(findings.map((_, index) => index));
  let tp = 0;
  let fn = 0;
  let coverageLoss = 0;
  let outOfStaticScope = 0;
  const fnIds: string[] = [];
  const coverageLossIds: string[] = [];
  const outOfStaticScopeIds: string[] = [];

  for (const item of expectation.directFindings ?? []) {
    if (item.inStaticScope === false) {
      outOfStaticScope += 1;
      outOfStaticScopeIds.push(item.id);
      continue;
    }
    if (!coverageAllowsDirectRecall(coverage[item.coverageArea])) {
      coverageLoss += 1;
      coverageLossIds.push(item.id);
      continue;
    }
    const matchIndex = [...unusedFindingIndexes].find((index) =>
      matchesFinding(findings[index], item.matcher),
    );
    if (matchIndex === undefined) {
      fn += 1;
      fnIds.push(item.id);
      continue;
    }
    tp += 1;
    unusedFindingIndexes.delete(matchIndex);
  }

  let fp = 0;
  let trueButUncurated = 0;
  let unreviewedFindings = 0;
  const unreviewedFindingIds: string[] = [];
  const directPrecisionBlockedBy = completenessBlockers(
    expectation.directTruth,
    expectation.directFpReview,
    "direct ground truth is incomplete",
    "direct false-positive review is incomplete",
  );

  for (const index of unusedFindingIndexes) {
    const finding = findings[index];
    if (finding === undefined) {
      continue;
    }
    if (
      (expectation.trueButUncuratedDirect ?? []).some((item) =>
        matchesFinding(finding, item.matcher),
      )
    ) {
      trueButUncurated += 1;
      continue;
    }
    if (directPrecisionBlockedBy.length === 0) {
      fp += 1;
    } else {
      unreviewedFindings += 1;
      unreviewedFindingIds.push(finding.id);
    }
  }

  const precision = ratio(tp, tp + fp, directPrecisionBlockedBy);
  const recall = ratio(
    tp,
    tp + fn,
    expectation.directTruth === "complete" ? [] : ["direct ground truth is incomplete"],
  );
  const f05 = fScore(precision, recall, 0.5);

  return {
    tp,
    fp,
    fn,
    fnIds,
    trueButUncurated,
    coverageLoss,
    coverageLossIds,
    outOfStaticScope,
    outOfStaticScopeIds,
    unreviewedFindings,
    unreviewedFindingIds,
    precision,
    recall,
    f05,
  };
}

function scoreStaticHypotheses(
  assessment: SecurityAssessment,
  expectation: ScoredRepositoryExpectation,
  coverage: Readonly<Record<string, CoverageSummary>>,
): StaticScore {
  const candidates = assessment.hypothesisCandidates ?? [];
  const hypotheses = assessment.staticHypotheses ?? [];
  const candidatesById = new Map(candidates.map((candidate) => [candidate.id, candidate]));
  const supportedHypotheses = hypotheses.filter(
    (hypothesis) => hypothesis.status === "statically_supported",
  );
  let candidateTp = 0;
  let candidateFn = 0;
  let coverageLoss = 0;
  let outOfGraphScope = 0;
  let falseContradiction = 0;
  const candidateFnIds: string[] = [];
  const coverageLossIds: string[] = [];
  const outOfGraphScopeIds: string[] = [];
  const falseContradictionIds: string[] = [];

  for (const item of expectation.staticHypotheses ?? []) {
    if (item.inGraphScope === false) {
      outOfGraphScope += 1;
      outOfGraphScopeIds.push(item.id);
      continue;
    }
    if (!coverageAllowsStaticRecall(coverage[item.coverageArea])) {
      coverageLoss += 1;
      coverageLossIds.push(item.id);
      continue;
    }
    if (candidates.some((candidate) => matchesCandidate(candidate, item))) {
      candidateTp += 1;
    } else {
      candidateFn += 1;
      candidateFnIds.push(item.id);
    }
    const contradiction = hypotheses.find(
      (hypothesis) =>
        hypothesis.status === "statically_contradicted" &&
        matchesStaticHypothesis(hypothesis, candidatesById, item.matcher, item.candidateFamily),
    );
    if (contradiction !== undefined) {
      falseContradiction += 1;
      falseContradictionIds.push(item.id);
    }
  }

  let supportedTp = 0;
  let falseSupport = 0;
  let trueButUncuratedSupport = 0;
  let unreviewedSupported = 0;
  const unreviewedSupportedIds: string[] = [];
  const usedSupportedIds = new Set<string>();
  const supportPrecisionBlockedBy = completenessBlockers(
    expectation.staticTruth,
    expectation.staticSupportReview,
    "static ground truth is incomplete",
    "static support review is incomplete",
  );

  for (const item of expectation.staticHypotheses ?? []) {
    const hypothesis = supportedHypotheses.find(
      (supported) =>
        !usedSupportedIds.has(supported.id) &&
        matchesStaticHypothesis(supported, candidatesById, item.matcher, item.candidateFamily),
    );
    if (hypothesis !== undefined) {
      supportedTp += 1;
      usedSupportedIds.add(hypothesis.id);
    }
  }

  for (const hypothesis of supportedHypotheses) {
    if (usedSupportedIds.has(hypothesis.id)) {
      continue;
    }
    if (
      (expectation.trueButUncuratedStatic ?? []).some((item) =>
        matchesStaticHypothesis(hypothesis, candidatesById, item.matcher),
      )
    ) {
      trueButUncuratedSupport += 1;
      continue;
    }
    if (supportPrecisionBlockedBy.length === 0) {
      falseSupport += 1;
    } else {
      unreviewedSupported += 1;
      unreviewedSupportedIds.push(hypothesis.id);
    }
  }

  const candidateRecall = ratio(
    candidateTp,
    candidateTp + candidateFn,
    expectation.staticTruth === "complete" ? [] : ["static ground truth is incomplete"],
  );
  const supportPrecision = ratio(
    supportedTp,
    supportedTp + falseSupport,
    supportPrecisionBlockedBy,
  );

  return {
    candidateTp,
    candidateFn,
    candidateFnIds,
    supportedTp,
    falseSupport,
    trueButUncuratedSupport,
    falseContradiction,
    falseContradictionIds,
    coverageLoss,
    coverageLossIds,
    outOfGraphScope,
    outOfGraphScopeIds,
    unreviewedSupported,
    unreviewedSupportedIds,
    candidateRecall,
    supportPrecision,
  };
}

function aggregateScores(repositories: ReadonlyArray<RepositoryScore>): AggregateScore[] {
  const scored = repositories.filter((repository) => repository.split !== "canary");
  const groups = new Map<string, RepositoryScore[]>();
  groups.set("all", scored);
  for (const repository of scored) {
    const key = `language:${repository.language}`;
    groups.set(key, [...(groups.get(key) ?? []), repository]);
  }

  return [...groups.entries()]
    .filter(([, entries]) => entries.length > 0)
    .map(([key, entries]) => aggregateGroup(key, entries));
}

function aggregateGroup(key: string, repositories: ReadonlyArray<RepositoryScore>): AggregateScore {
  const directPrecisionBlockers = aggregateBlockers(
    repositories,
    (repository) => repository.direct.precision,
  );
  const directRecallBlockers = aggregateBlockers(
    repositories,
    (repository) => repository.direct.recall,
  );
  const supportPrecisionBlockers = aggregateBlockers(
    repositories,
    (repository) => repository.staticHypotheses.supportPrecision,
  );
  const candidateRecallBlockers = aggregateBlockers(
    repositories,
    (repository) => repository.staticHypotheses.candidateRecall,
  );
  const directTp = sum(repositories.map((repository) => repository.direct.tp));
  const directFp = sum(repositories.map((repository) => repository.direct.fp));
  const directFn = sum(repositories.map((repository) => repository.direct.fn));
  const candidateTp = sum(
    repositories.map((repository) => repository.staticHypotheses.candidateTp),
  );
  const candidateFn = sum(
    repositories.map((repository) => repository.staticHypotheses.candidateFn),
  );
  const supportedTp = sum(
    repositories.map((repository) => repository.staticHypotheses.supportedTp),
  );
  const falseSupport = sum(
    repositories.map((repository) => repository.staticHypotheses.falseSupport),
  );
  const directPrecision = ratio(directTp, directTp + directFp, directPrecisionBlockers);
  const directRecall = ratio(directTp, directTp + directFn, directRecallBlockers);
  return {
    key,
    directPrecision,
    directRecall,
    directF05: fScore(directPrecision, directRecall, 0.5),
    staticSupportPrecision: ratio(
      supportedTp,
      supportedTp + falseSupport,
      supportPrecisionBlockers,
    ),
    staticCandidateRecall: ratio(candidateTp, candidateTp + candidateFn, candidateRecallBlockers),
  };
}

function aggregateBlockers(
  repositories: ReadonlyArray<RepositoryScore>,
  metricFor: (repository: RepositoryScore) => RatioMetric,
): string[] {
  return uniqueStrings(
    repositories.flatMap((repository) =>
      metricFor(repository).blockedBy.map((reason) => `${repository.name}: ${reason}`),
    ),
  ).filter((reason) => !isZeroDenominatorReason(reason));
}

function targetGateErrors(
  aggregates: ReadonlyArray<AggregateScore>,
  repositories: ReadonlyArray<RepositoryScore>,
  targets: ScoreTargets,
): string[] {
  const errors: string[] = [];
  for (const aggregate of aggregates) {
    pushMetricTargetError(errors, aggregate.key, "direct precision", aggregate.directPrecision, [
      targets.directPrecision,
    ]);
    pushMetricTargetError(errors, aggregate.key, "direct recall", aggregate.directRecall, [
      targets.directRecall,
    ]);
    pushMetricTargetError(errors, aggregate.key, "direct F0.5", aggregate.directF05, [
      targets.directF05,
    ]);
    pushMetricTargetError(
      errors,
      aggregate.key,
      "static support precision",
      aggregate.staticSupportPrecision,
      [targets.staticSupportPrecision],
    );
    pushMetricTargetError(
      errors,
      aggregate.key,
      "static candidate recall",
      aggregate.staticCandidateRecall,
      [targets.staticCandidateRecall],
    );
  }

  const tuning = aggregateBySplit(repositories, "tuning");
  const heldOut = aggregateBySplit(repositories, "held-out");
  const tuningHeldOutGap = maxMetricGap(tuning, heldOut);
  if (tuningHeldOutGap === null) {
    errors.push("tuning vs held-out gap is not scoreable");
  } else if (tuningHeldOutGap > targets.maxTuningHeldOutGap) {
    errors.push(
      `tuning vs held-out gap exceeds target: ${formatMetric(tuningHeldOutGap)} > ${formatMetric(
        targets.maxTuningHeldOutGap,
      )}`,
    );
  }

  for (const repository of repositories) {
    if (repository.verdict.passed === false) {
      errors.push(
        `${repository.name} verdict ${repository.verdict.actual} did not match expected ${repository.verdict.expected}`,
      );
    }
    for (const error of repository.coverageErrors) {
      errors.push(`${repository.name} coverage: ${error}`);
    }
  }
  return errors;
}

function pushMetricTargetError(
  errors: string[],
  key: string,
  label: string,
  metric: RatioMetric,
  [target]: readonly [number],
): void {
  if (!metric.scoreable) {
    if (key.startsWith("language:") && isZeroDenominatorMetric(metric)) {
      return;
    }
    errors.push(`${key} ${label} is not scoreable: ${metric.blockedBy.join("; ")}`);
    return;
  }
  if (metric.value === null || metric.value < target) {
    errors.push(`${key} ${label} below target: ${formatRatio(metric)} < ${formatMetric(target)}`);
  }
}

function isZeroDenominatorMetric(metric: RatioMetric): boolean {
  return metric.blockedBy.length > 0 && metric.blockedBy.every(isZeroDenominatorReason);
}

function isZeroDenominatorReason(reason: string): boolean {
  return reason === ZERO_DENOMINATOR_REASON || reason.endsWith(`: ${ZERO_DENOMINATOR_REASON}`);
}

function aggregateBySplit(
  repositories: ReadonlyArray<RepositoryScore>,
  split: "held-out" | "tuning",
): AggregateScore | undefined {
  const entries = repositories.filter((repository) => repository.split === split);
  return entries.length === 0 ? undefined : aggregateGroup(split, entries);
}

function maxMetricGap(
  left: AggregateScore | undefined,
  right: AggregateScore | undefined,
): number | null {
  if (left === undefined || right === undefined) {
    return null;
  }
  const pairs = [
    [left.directPrecision, right.directPrecision],
    [left.directRecall, right.directRecall],
    [left.staticSupportPrecision, right.staticSupportPrecision],
    [left.staticCandidateRecall, right.staticCandidateRecall],
  ] as const;
  let max = 0;
  for (const [a, b] of pairs) {
    if (!a.scoreable || !b.scoreable || a.value === null || b.value === null) {
      return null;
    }
    max = Math.max(max, Math.abs(a.value - b.value));
  }
  return max;
}

function coverageGateErrors(
  coverage: Readonly<Record<string, CoverageSummary>>,
  expectation: ScoredRepositoryExpectation,
): string[] {
  const errors: string[] = [];
  for (const [area, entry] of Object.entries(coverage)) {
    if (entry.state === "failed") {
      errors.push(`deep coverage failed for ${area}${reasonSuffix(entry.reason)}`);
    }
  }
  const dependencyUsage = coverage.dependency_usage;
  if (
    dependencyUsage?.totalCount !== undefined &&
    dependencyUsage.totalCount > 0 &&
    dependencyUsage.coveredCount !== dependencyUsage.totalCount
  ) {
    errors.push(
      `dependency_usage is incomplete: ${dependencyUsage.coveredCount ?? 0}/${dependencyUsage.totalCount}`,
    );
  }
  for (const [area, expected] of Object.entries(expectation.coverage ?? {})) {
    const actual = coverage[area];
    if (actual === undefined) {
      errors.push(`missing expected coverage area: ${area}`);
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

function matchesRepository(
  assessment: SecurityAssessment,
  expectation: ScoredRepositoryExpectation,
): boolean {
  const originUrl = expectation.match.originUrl;
  if (
    originUrl !== undefined &&
    assessment.repository.originUrl !== undefined &&
    normalizeSource(assessment.repository.originUrl) === normalizeSource(originUrl)
  ) {
    return true;
  }
  const suffix = expectation.match.localPathSuffix;
  return suffix !== undefined && (assessment.repository.localPath?.endsWith(suffix) ?? false);
}

function matchesFinding(finding: Finding | undefined, matcher: DirectFindingMatcher): boolean {
  if (finding === undefined) {
    return false;
  }
  if (matcher.sourceTool !== undefined && finding.sourceTool !== matcher.sourceTool) {
    return false;
  }
  if (matcher.ruleId !== undefined && finding.ruleId !== matcher.ruleId) {
    return false;
  }
  if (matcher.category !== undefined && finding.category !== matcher.category) {
    return false;
  }
  if (matcher.remediationKey !== undefined && finding.remediationKey !== matcher.remediationKey) {
    return false;
  }
  if (matcher.severityIn !== undefined && !matcher.severityIn.includes(finding.severity)) {
    return false;
  }
  if (
    matcher.filePathIncludes !== undefined &&
    !finding.locations.some((location) =>
      location.filePath.includes(matcher.filePathIncludes ?? ""),
    )
  ) {
    return false;
  }
  for (const [key, value] of Object.entries(matcher.metadata ?? {})) {
    if (finding.metadata?.[key] !== value) {
      return false;
    }
  }
  return true;
}

function matchesCandidate(candidate: HypothesisCandidate, item: StaticTruthItem): boolean {
  const family = item.matcher.family ?? item.candidateFamily;
  if (candidate.family !== family) {
    return false;
  }
  if (item.matcher.ruleId !== undefined && candidate.ruleId !== item.matcher.ruleId) {
    return false;
  }
  if (
    item.matcher.candidateReasonIncludes !== undefined &&
    !candidate.candidateReason.includes(item.matcher.candidateReasonIncludes)
  ) {
    return false;
  }
  if (!includesAll(candidate.candidateReason, item.matcher.candidateReasonIncludesAll)) {
    return false;
  }
  return true;
}

function matchesStaticHypothesis(
  hypothesis: StaticHypothesis,
  candidatesById: ReadonlyMap<string, HypothesisCandidate>,
  matcher: StaticHypothesisMatcher,
  fallbackFamily?: string,
): boolean {
  const candidate = candidatesById.get(hypothesis.candidateId);
  if (candidate === undefined) {
    return false;
  }
  if (matcher.family !== undefined || fallbackFamily !== undefined) {
    const family = matcher.family ?? fallbackFamily;
    if (candidate.family !== family) {
      return false;
    }
  }
  if (matcher.ruleId !== undefined && candidate.ruleId !== matcher.ruleId) {
    return false;
  }
  if (matcher.titleIncludes !== undefined && !hypothesis.title.includes(matcher.titleIncludes)) {
    return false;
  }
  if (!includesAll(hypothesis.title, matcher.titleIncludesAll)) {
    return false;
  }
  if (
    matcher.candidateReasonIncludes !== undefined &&
    !candidate.candidateReason.includes(matcher.candidateReasonIncludes)
  ) {
    return false;
  }
  if (!includesAll(candidate.candidateReason, matcher.candidateReasonIncludesAll)) {
    return false;
  }
  if (
    matcher.pathSummaryIncludes !== undefined &&
    !hypothesis.pathSummary.includes(matcher.pathSummaryIncludes)
  ) {
    return false;
  }
  if (!includesAll(hypothesis.pathSummary, matcher.pathSummaryIncludesAll)) {
    return false;
  }
  if (matcher.statusIn !== undefined && !matcher.statusIn.includes(hypothesis.status)) {
    return false;
  }
  return true;
}

function includesAll(value: string, expected: ReadonlyArray<string> | undefined): boolean {
  return expected === undefined || expected.every((part) => value.includes(part));
}

function coverageAllowsDirectRecall(entry: CoverageSummary | undefined): boolean {
  return entry?.state === "checked";
}

function coverageAllowsStaticRecall(entry: CoverageSummary | undefined): boolean {
  return entry !== undefined && entry.state !== "failed" && entry.state !== "partial";
}

function completenessBlockers(
  truth: Completeness,
  review: Completeness,
  truthMessage: string,
  reviewMessage: string,
): string[] {
  return [
    ...(truth === "complete" ? [] : [truthMessage]),
    ...(review === "complete" ? [] : [reviewMessage]),
  ];
}

function ratio(
  numerator: number,
  denominator: number,
  blockedBy: ReadonlyArray<string>,
): RatioMetric {
  if (blockedBy.length > 0) {
    return { numerator, denominator, value: null, scoreable: false, blockedBy };
  }
  if (denominator === 0) {
    return {
      numerator,
      denominator,
      value: null,
      scoreable: false,
      blockedBy: [ZERO_DENOMINATOR_REASON],
    };
  }
  return { numerator, denominator, value: numerator / denominator, scoreable: true, blockedBy: [] };
}

function fScore(precision: RatioMetric, recall: RatioMetric, beta: number): RatioMetric {
  const blockedBy = uniqueStrings([...precision.blockedBy, ...recall.blockedBy]);
  if (blockedBy.length > 0 || precision.value === null || recall.value === null) {
    return {
      numerator: precision.numerator,
      denominator: precision.denominator,
      value: null,
      scoreable: false,
      blockedBy,
    };
  }
  const betaSquared = beta * beta;
  const denominator = betaSquared * precision.value + recall.value;
  return {
    numerator: precision.numerator,
    denominator: precision.denominator,
    value:
      denominator === 0 ? 0 : ((1 + betaSquared) * precision.value * recall.value) / denominator,
    scoreable: true,
    blockedBy: [],
  };
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

interface CoverageSummary {
  readonly state: string;
  readonly coveredCount?: number;
  readonly totalCount?: number;
  readonly reason?: string;
}

async function loadReport(reportPathValue: string): Promise<DeepReportJson> {
  return JSON.parse(await readFile(reportPathValue, "utf8")) as DeepReportJson;
}

async function reportPath(input: string): Promise<string> {
  const resolved = path.resolve(input);
  const info = await stat(resolved);
  return info.isDirectory() ? path.join(resolved, "report.json") : resolved;
}

function parseArgs(args: ReadonlyArray<string>): CliOptions {
  const inputs: string[] = [];
  let jsonOutput = false;
  let reviewStaticSupport = false;
  let expectPath = "benchmarks/deep-static-scored-ground-truth.json";
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      jsonOutput = true;
      continue;
    }
    if (arg === "--review-static-support") {
      reviewStaticSupport = true;
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
  return { expectPath, jsonOutput, reviewStaticSupport, inputs };
}

function printStaticSupportReviewSummaries(
  summaries: ReadonlyArray<StaticSupportReviewSummary>,
): void {
  for (const summary of summaries) {
    process.stdout.write(
      `REVIEW ${summary.name} ${summary.runId} supported=${summary.supported} expectedTruth=${summary.expectedTruth} trueButUncurated=${summary.trueButUncurated} unreviewed=${summary.unreviewed}\n`,
    );
    for (const group of summary.unreviewedGroups) {
      process.stdout.write(`  ${group.count} ${group.family} | ${group.title}\n`);
      for (const reason of group.sampleCandidateReasons) {
        process.stdout.write(`    e.g. ${reason}\n`);
      }
    }
  }
}

function printSummary(summary: BenchmarkScoreSummary): void {
  for (const repository of summary.repositories) {
    const status =
      repository.coverageErrors.length === 0 &&
      repository.scoreabilityErrors.length === 0 &&
      repository.verdict.passed !== false
        ? "PASS"
        : "FAIL";
    process.stdout.write(
      `${status} ${repository.name} ${repository.runId} language=${repository.language} split=${repository.split} verdict=${repository.verdict.actual}\n`,
    );
    if (repository.verdict.expected !== undefined) {
      process.stdout.write(
        `  verdict target: ${repository.verdict.actual}/${repository.verdict.expected}\n`,
      );
    }
    process.stdout.write(
      `  direct: precision=${formatRatio(repository.direct.precision)} recall=${formatRatio(
        repository.direct.recall,
      )} f0.5=${formatRatio(repository.direct.f05)} tp=${repository.direct.tp} fp=${
        repository.direct.fp
      } fn=${repository.direct.fn} coverageLoss=${repository.direct.coverageLoss} unreviewed=${
        repository.direct.unreviewedFindings
      }\n`,
    );
    if (repository.direct.fnIds.length > 0) {
      process.stdout.write(`  direct fn: ${repository.direct.fnIds.join(", ")}\n`);
    }
    process.stdout.write(
      `  static: supportPrecision=${formatRatio(
        repository.staticHypotheses.supportPrecision,
      )} candidateRecall=${formatRatio(repository.staticHypotheses.candidateRecall)} candidateTp=${
        repository.staticHypotheses.candidateTp
      } candidateFn=${repository.staticHypotheses.candidateFn} falseSupport=${
        repository.staticHypotheses.falseSupport
      } falseContradiction=${repository.staticHypotheses.falseContradiction} unreviewedSupported=${
        repository.staticHypotheses.unreviewedSupported
      }\n`,
    );
    if (repository.staticHypotheses.candidateFnIds.length > 0) {
      process.stdout.write(
        `  static candidate fn: ${repository.staticHypotheses.candidateFnIds.join(", ")}\n`,
      );
    }
    for (const error of [
      ...repository.coverageErrors.map((error) => `coverage: ${error}`),
      ...repository.scoreabilityErrors,
    ]) {
      process.stdout.write(`  error: ${error}\n`);
    }
  }
  for (const aggregate of summary.aggregates) {
    process.stdout.write(
      `AGG ${aggregate.key} directPrecision=${formatRatio(
        aggregate.directPrecision,
      )} directRecall=${formatRatio(aggregate.directRecall)} directF0.5=${formatRatio(
        aggregate.directF05,
      )} staticSupportPrecision=${formatRatio(
        aggregate.staticSupportPrecision,
      )} staticCandidateRecall=${formatRatio(aggregate.staticCandidateRecall)}\n`,
    );
  }
  for (const missing of summary.missingRepositories) {
    process.stdout.write(`FAIL missing ${missing}\n`);
  }
  for (const error of summary.targetErrors) {
    process.stdout.write(`FAIL target ${error}\n`);
  }
}

function formatRatio(metric: RatioMetric): string {
  if (!metric.scoreable || metric.value === null) {
    return `n/a(${metric.numerator}/${metric.denominator})`;
  }
  return `${formatMetric(metric.value)}(${metric.numerator}/${metric.denominator})`;
}

function formatMetric(value: number): string {
  return value.toFixed(3);
}

function repositoryName(assessment: SecurityAssessment): string {
  return (
    assessment.repository.originUrl ??
    assessment.repository.localPath ??
    assessment.repository.name ??
    "repository"
  );
}

function normalizeSource(value: string): string {
  return value.replace(/\/$/, "").replace(/\.git$/, "");
}

function reasonSuffix(reason: string | undefined): string {
  return reason === undefined ? "" : `: ${reason}`;
}

function sum(values: ReadonlyArray<number>): number {
  return values.reduce((total, value) => total + value, 0);
}

function uniqueStrings(values: ReadonlyArray<string>): string[] {
  return [...new Set(values)];
}

function isScoreExpectationFile(value: unknown): value is DeepScoreExpectationFile {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as DeepScoreExpectationFile).version === 1 &&
    Array.isArray((value as DeepScoreExpectationFile).repositories)
  );
}
