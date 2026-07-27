#!/usr/bin/env tsx
import { pathToFileURL } from "node:url";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
import type { StaticHypothesis } from "../src/domain/static-hypothesis.js";
import { validateStaticHypotheses } from "../src/stages/static-hypothesis-validator.js";
import {
  type BuiltReportV1BenchmarkCase,
  buildReportV1BenchmarkCases,
  candidateRootCause,
  loadReportV1BenchmarkContract,
  type ReportV1BenchmarkContract,
  type ReportV1BenchmarkSplit,
} from "./report-v1-benchmark-fixtures.js";

export interface ReportV1Ratio {
  readonly numerator: number;
  readonly denominator: number;
  readonly value: number;
}

export interface ReportV1BenchmarkGate {
  readonly name: string;
  readonly passed: boolean;
  readonly actual: string;
  readonly target: string;
}

export interface ReportV1BenchmarkCaseResult {
  readonly id: string;
  readonly language: string;
  readonly variant: string;
  readonly candidateRootCauses: ReadonlyArray<string>;
  readonly hypotheses: ReadonlyArray<{
    readonly candidateId: string;
    readonly rootCause?: string;
    readonly status: StaticHypothesis["status"];
    readonly publishable: boolean;
    readonly reasons: StaticHypothesis["promotion"]["reasons"];
  }>;
  readonly ownerValidationRootCauses: ReadonlyArray<string>;
  readonly directFindingIds: ReadonlyArray<string>;
}

export interface ReportV1BenchmarkScore {
  readonly classification: "synthetic_contract_regression";
  readonly split: ReportV1BenchmarkSplit;
  readonly cases: ReadonlyArray<ReportV1BenchmarkCaseResult>;
  readonly metrics: {
    readonly publicationPrecisionOnConstructedCases: ReportV1Ratio;
    readonly publicationRecallOnConstructedCases: ReportV1Ratio;
    readonly publicationF05OnConstructedCases: number;
    readonly promotionPrecisionOnConstructedCases: ReportV1Ratio;
    readonly correlationRecallOnConstructedCases: ReportV1Ratio;
    readonly falseContradictions: number;
    readonly falseDeployBlockers: number;
    readonly deterministic: boolean;
  };
  readonly gates: ReadonlyArray<ReportV1BenchmarkGate>;
  readonly passed: boolean;
}

export async function scoreReportV1Benchmark(
  split: ReportV1BenchmarkSplit,
  providedContract?: ReportV1BenchmarkContract,
): Promise<ReportV1BenchmarkScore> {
  const contract = providedContract ?? (await loadReportV1BenchmarkContract());
  const benchmarkCases = await buildReportV1BenchmarkCases(contract, split);
  const first = benchmarkCases.map(runCase);
  const second = benchmarkCases.map(runCase);
  const deterministic = JSON.stringify(first) === JSON.stringify(second);
  let candidateTp = 0;
  let candidateFn = 0;
  let supportedTp = 0;
  let falseSupport = 0;
  let falseContradictions = 0;
  let falseDeployBlockers = 0;
  let ownerTp = 0;
  let ownerFp = 0;
  let ownerFn = 0;

  for (const [index, result] of first.entries()) {
    const benchmarkCase = requiredAt(benchmarkCases, index, "benchmark case");
    const expectedCandidates = new Set(benchmarkCase.record.truth.candidateRootCauses);
    const observedCandidates = new Set(result.candidateRootCauses);
    for (const expected of expectedCandidates) {
      if (observedCandidates.has(expected)) {
        candidateTp += 1;
      } else {
        candidateFn += 1;
      }
    }

    const expectedSupport = new Set(benchmarkCase.record.truth.supportedRootCauses);
    for (const hypothesis of result.hypotheses) {
      if (hypothesis.status === "statically_supported") {
        if (hypothesis.rootCause !== undefined && expectedSupport.has(hypothesis.rootCause)) {
          supportedTp += 1;
        } else {
          falseSupport += 1;
        }
      }
      if (
        hypothesis.status === "statically_contradicted" &&
        hypothesis.rootCause !== undefined &&
        expectedSupport.has(hypothesis.rootCause)
      ) {
        falseContradictions += 1;
      }
    }
    if (["clean", "guarded", "structural_only"].includes(result.variant)) {
      falseDeployBlockers += result.hypotheses.filter(
        (hypothesis) => hypothesis.publishable,
      ).length;
    }

    const expectedOwner = new Set(benchmarkCase.record.truth.ownerValidationRootCauses);
    const observedOwner = new Set(result.ownerValidationRootCauses);
    for (const observed of observedOwner) {
      if (expectedOwner.has(observed)) {
        ownerTp += 1;
      } else {
        ownerFp += 1;
      }
    }
    for (const expected of expectedOwner) {
      if (!observedOwner.has(expected)) {
        ownerFn += 1;
      }
    }
  }

  const publicationPrecision = ratio(ownerTp, ownerTp + ownerFp);
  const publicationRecall = ratio(ownerTp, ownerTp + ownerFn);
  const promotionPrecision = ratio(supportedTp, supportedTp + falseSupport);
  const correlationRecall = ratio(candidateTp, candidateTp + candidateFn);
  const targets = contract.targets;
  const gates = [
    gate(
      "synthetic publication precision",
      publicationPrecision.value >= targets.ownerGroupPrecision,
      publicationPrecision.value,
      `>= ${targets.ownerGroupPrecision}`,
    ),
    gate(
      "synthetic promotion precision",
      promotionPrecision.value >= targets.staticSupportPrecision,
      promotionPrecision.value,
      `>= ${targets.staticSupportPrecision}`,
    ),
    gate(
      "synthetic correlation recall",
      correlationRecall.value >= targets.candidateRecall,
      correlationRecall.value,
      `>= ${targets.candidateRecall}`,
    ),
    gate(
      "false deploy blockers",
      falseDeployBlockers <= targets.falseDeployBlockers,
      falseDeployBlockers,
      `<= ${targets.falseDeployBlockers}`,
    ),
    gate("deterministic repeat", deterministic, deterministic, "true"),
  ];
  return {
    classification: "synthetic_contract_regression",
    split,
    cases: first,
    metrics: {
      publicationPrecisionOnConstructedCases: publicationPrecision,
      publicationRecallOnConstructedCases: publicationRecall,
      publicationF05OnConstructedCases: f05(publicationPrecision.value, publicationRecall.value),
      promotionPrecisionOnConstructedCases: promotionPrecision,
      correlationRecallOnConstructedCases: correlationRecall,
      falseContradictions,
      falseDeployBlockers,
      deterministic,
    },
    gates,
    passed: gates.every((item) => item.passed),
  };
}

function runCase(benchmarkCase: BuiltReportV1BenchmarkCase): ReportV1BenchmarkCaseResult {
  const hypotheses = validateStaticHypotheses({
    graph: benchmarkCase.graph,
    candidates: benchmarkCase.candidates,
    evidence: benchmarkCase.evidence,
    manifestPaths: [benchmarkCase.record.fixturePath],
  });
  const candidatesById = new Map(
    benchmarkCase.candidates.map((candidate) => [candidate.id, candidate]),
  );
  const hypothesisResults = hypotheses.map((hypothesis) => {
    const candidate = requiredCandidate(candidatesById, hypothesis.candidateId);
    const rootCause = candidateRootCause(benchmarkCase, candidate);
    return {
      candidateId: hypothesis.candidateId,
      ...(rootCause === undefined ? {} : { rootCause }),
      status: hypothesis.status,
      publishable: hypothesis.promotion.publishable,
      reasons: hypothesis.promotion.reasons,
    };
  });
  const ownerValidationRootCauses = uniqueSorted(
    hypotheses.flatMap((hypothesis) => {
      if (!hypothesis.promotion.publishable) {
        return [];
      }
      const candidate = requiredCandidate(candidatesById, hypothesis.candidateId);
      if (candidate.findingIds.length > 0) {
        return [];
      }
      const rootCause = candidateRootCause(benchmarkCase, candidate);
      return rootCause === undefined ? [] : [rootCause];
    }),
  );
  return {
    id: benchmarkCase.record.id,
    language: benchmarkCase.record.language,
    variant: benchmarkCase.record.variant,
    candidateRootCauses: uniqueSorted(
      benchmarkCase.candidates.flatMap((candidate) => {
        const rootCause = candidateRootCause(benchmarkCase, candidate);
        return rootCause === undefined ? [] : [rootCause];
      }),
    ),
    hypotheses: hypothesisResults,
    ownerValidationRootCauses,
    directFindingIds: uniqueSorted(
      benchmarkCase.findingContexts.map((context) => context.findingId),
    ),
  };
}

function requiredCandidate(
  candidatesById: ReadonlyMap<string, HypothesisCandidate>,
  candidateId: string,
): HypothesisCandidate {
  const candidate = candidatesById.get(candidateId);
  if (candidate === undefined) {
    throw new Error(`missing candidate: ${candidateId}`);
  }
  return candidate;
}

function ratio(numerator: number, denominator: number): ReportV1Ratio {
  return {
    numerator,
    denominator,
    value: denominator === 0 ? 1 : round(numerator / denominator),
  };
}

function f05(precision: number, recall: number): number {
  const denominator = 0.25 * precision + recall;
  return denominator === 0 ? 0 : round((1.25 * precision * recall) / denominator);
}

function gate(
  name: string,
  passed: boolean,
  actual: unknown,
  target: string,
): ReportV1BenchmarkGate {
  return {
    name,
    passed,
    actual: typeof actual === "number" ? String(round(actual)) : String(actual),
    target,
  };
}

function round(value: number): number {
  return Number(value.toFixed(4));
}

function requiredAt<T>(values: ReadonlyArray<T>, index: number, label: string): T {
  const value = values[index];
  if (value === undefined) {
    throw new Error(`missing ${label} at index ${index}`);
  }
  return value;
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

async function main(): Promise<void> {
  const requestedSplit = option(process.argv.slice(2), "--split");
  if (
    requestedSplit !== undefined &&
    requestedSplit !== "all" &&
    requestedSplit !== "development" &&
    requestedSplit !== "synthetic-holdback"
  ) {
    throw new Error("--split must be one of: all, development, synthetic-holdback");
  }
  const splits: ReadonlyArray<ReportV1BenchmarkSplit> =
    requestedSplit === "development" || requestedSplit === "synthetic-holdback"
      ? [requestedSplit]
      : ["development", "synthetic-holdback"];
  const contract = await loadReportV1BenchmarkContract();
  const scores = await Promise.all(splits.map((split) => scoreReportV1Benchmark(split, contract)));
  process.stdout.write(
    `${JSON.stringify({ version: 1, classification: "synthetic_contract_regression", scores }, null, 2)}\n`,
  );
  if (scores.some((score) => !score.passed)) {
    process.exitCode = 1;
  }
}

function option(values: ReadonlyArray<string>, name: string): string | undefined {
  const index = values.indexOf(name);
  return index < 0 ? undefined : values[index + 1];
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
