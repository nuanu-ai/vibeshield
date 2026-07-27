import { describe, expect, it } from "vitest";
import { scoreReportV1Benchmark } from "../scripts/report-v1-benchmark.js";

describe("Report v1 benchmark gates", () => {
  it("passes development contract cases with strict promotion semantics", async () => {
    const score = await scoreReportV1Benchmark("development");

    expect(score.classification).toBe("synthetic_contract_regression");
    expect(score.passed).toBe(true);
    expect(score.gates.filter((gate) => !gate.passed)).toEqual([]);
    expect(score.metrics).toMatchObject({
      publicationPrecisionOnConstructedCases: { value: 1 },
      promotionPrecisionOnConstructedCases: { value: 1 },
      correlationRecallOnConstructedCases: { value: 1 },
      falseContradictions: 0,
      falseDeployBlockers: 0,
      deterministic: true,
    });
    expect(caseById(score, "ts-ssrf-guarded").hypotheses).toEqual([
      expect.objectContaining({ status: "statically_contradicted", publishable: false }),
    ]);
    expect(caseById(score, "ts-structural-only").hypotheses).toEqual([
      expect.objectContaining({ status: "inconclusive", publishable: false }),
    ]);
    expect(caseById(score, "java-stale-evidence").hypotheses).toEqual([
      expect.objectContaining({ status: "inconclusive", publishable: false }),
    ]);
    expect(caseById(score, "ts-irrelevant-guard").hypotheses).toEqual([
      expect.objectContaining({ status: "statically_supported", publishable: true }),
    ]);
    expect(caseById(score, "ts-duplicate-root").ownerValidationRootCauses).toEqual(["fetch-url"]);
    expect(caseById(score, "ts-direct-overlap").ownerValidationRootCauses).toEqual([]);
  });

  it("passes the synthetic holdback regression cases", async () => {
    const score = await scoreReportV1Benchmark("synthetic-holdback");

    expect(score.passed).toBe(true);
    expect(score.gates.filter((gate) => !gate.passed)).toEqual([]);
    expect(score.metrics.publicationF05OnConstructedCases).toBe(1);
    expect(caseById(score, "go-path-partial").hypotheses).toEqual([
      expect.objectContaining({ status: "inconclusive", publishable: false }),
    ]);
    expect(caseById(score, "python-command-vulnerable").ownerValidationRootCauses).toEqual([]);
  });
});

function caseById(score: Awaited<ReturnType<typeof scoreReportV1Benchmark>>, id: string) {
  const result = score.cases.find((record) => record.id === id);
  if (result === undefined) {
    throw new Error(`missing benchmark case: ${id}`);
  }
  return result;
}
