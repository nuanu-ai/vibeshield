import { describe, expect, it } from "vitest";
import {
  scoreBenchmarkReports,
  staticSupportReviewSummaries,
} from "../scripts/deep-benchmark-score.js";
import type { Finding } from "../src/domain/finding.js";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
import type { SecurityAssessment } from "../src/domain/security-assessment.js";
import type { StaticHypothesis } from "../src/domain/static-hypothesis.js";

describe("deep benchmark score", () => {
  it("scores direct precision/recall and static support/candidate metrics", () => {
    const summary = scoreBenchmarkReports(
      {
        version: 1,
        targets: {
          directPrecision: 0.5,
          directRecall: 1,
          staticSupportPrecision: 0.5,
          staticCandidateRecall: 1,
          maxTuningHeldOutGap: 1,
        },
        repositories: [
          {
            name: "Fixture app",
            language: "JS/TS",
            split: "tuning",
            match: { originUrl: "https://example.test/app.git" },
            expectedVerdict: "not-ready-to-deploy",
            directTruth: "complete",
            directFpReview: "complete",
            staticTruth: "complete",
            staticSupportReview: "complete",
            directFindings: [
              {
                id: "direct.secret",
                title: "Secret is found",
                coverageArea: "language_support",
                matcher: { ruleId: "generic-api-key", category: "secret" },
              },
            ],
            staticHypotheses: [
              {
                id: "static.sqli",
                title: "SQL injection path",
                coverageArea: "data_flow",
                candidateFamily: "external_input_to_dangerous_operation",
                matcher: {
                  titleIncludesAll: ["SQL", "injection"],
                  candidateReasonIncludesAll: ["/users", "query"],
                  statusIn: ["statically_supported"],
                },
              },
            ],
          },
        ],
      },
      [
        report({
          findings: [
            finding("finding.secret", {
              ruleId: "generic-api-key",
              category: "secret",
              filePath: "config.js",
            }),
            finding("finding.noise", {
              ruleId: "unused-secret",
              category: "secret",
              filePath: "fixtures/unused.js",
            }),
          ],
          candidates: [
            candidate("candidate.sqli", {
              family: "external_input_to_dangerous_operation",
              title: "SQL injection path",
              candidateReason: "SQL injection path: /users (src/server.ts:12) reaches query",
            }),
            candidate("candidate.noise", {
              family: "external_input_to_dangerous_operation",
              title: "Open redirect path",
            }),
          ],
          hypotheses: [
            hypothesis("hypothesis.sqli", "candidate.sqli", {
              status: "statically_supported",
              title: "SQL injection path",
            }),
            hypothesis("hypothesis.noise", "candidate.noise", {
              status: "statically_supported",
              title: "Open redirect path",
            }),
          ],
        }),
      ],
    );

    const repository = summary.repositories[0];
    expect(repository?.direct).toMatchObject({
      tp: 1,
      fp: 1,
      fn: 0,
      fnIds: [],
    });
    expect(repository?.direct.precision.value).toBe(0.5);
    expect(repository?.direct.recall.value).toBe(1);
    expect(repository?.staticHypotheses).toMatchObject({
      candidateTp: 1,
      candidateFn: 0,
      candidateFnIds: [],
      supportedTp: 1,
      falseSupport: 1,
    });
    expect(repository?.staticHypotheses.supportPrecision.value).toBe(0.5);
  });

  it("blocks target scoring when curated truth or FP review is incomplete", () => {
    const summary = scoreBenchmarkReports(
      {
        version: 1,
        repositories: [
          {
            name: "Incomplete fixture",
            language: "Python",
            split: "held-out",
            match: { originUrl: "https://example.test/incomplete" },
            directTruth: "incomplete",
            directFpReview: "incomplete",
            staticTruth: "incomplete",
            staticSupportReview: "incomplete",
            directFindings: [
              {
                id: "direct.secret",
                title: "Secret is found",
                coverageArea: "language_support",
                matcher: {
                  ruleId: "generic-api-key",
                  category: "secret",
                  filePathIncludes: "config.py",
                },
              },
            ],
            trueButUncuratedDirect: [
              {
                id: "extra.secret",
                reason: "Repeated config fixture secret is a true duplicate.",
                matcher: {
                  ruleId: "generic-api-key",
                  category: "secret",
                  filePathIncludes: "extra.py",
                },
              },
            ],
            staticHypotheses: [
              {
                id: "static.sqli",
                title: "SQL injection path",
                coverageArea: "data_flow",
                candidateFamily: "external_input_to_dangerous_operation",
                matcher: { titleIncludes: "SQL injection", statusIn: ["statically_supported"] },
              },
            ],
            trueButUncuratedStatic: [
              {
                id: "extra.xss",
                reason: "Repeated reflected response path is a true duplicate.",
                matcher: { titleIncludes: "Cross-site scripting" },
              },
            ],
          },
        ],
      },
      [
        report({
          originUrl: "https://example.test/incomplete",
          findings: [
            finding("finding.secret", {
              ruleId: "generic-api-key",
              category: "secret",
              filePath: "config.py",
            }),
            finding("finding.extra-secret", {
              ruleId: "generic-api-key",
              category: "secret",
              filePath: "extra.py",
            }),
            finding("finding.unreviewed", {
              ruleId: "unused-secret",
              category: "secret",
              filePath: "scratch.py",
            }),
          ],
          candidates: [
            candidate("candidate.sqli", {
              family: "external_input_to_dangerous_operation",
              title: "SQL injection path",
            }),
            candidate("candidate.xss", {
              family: "external_input_to_dangerous_operation",
              title: "Cross-site scripting path",
            }),
            candidate("candidate.open-redirect", {
              family: "external_input_to_dangerous_operation",
              title: "Open redirect path",
            }),
          ],
          hypotheses: [
            hypothesis("hypothesis.sqli", "candidate.sqli", {
              status: "statically_supported",
              title: "SQL injection path",
            }),
            hypothesis("hypothesis.xss", "candidate.xss", {
              status: "statically_supported",
              title: "Cross-site scripting path",
            }),
            hypothesis("hypothesis.unreviewed", "candidate.open-redirect", {
              status: "statically_supported",
              title: "Open redirect path",
            }),
          ],
        }),
      ],
    );

    expect(summary.repositories[0]?.direct).toMatchObject({
      tp: 1,
      trueButUncurated: 1,
      unreviewedFindings: 1,
      unreviewedFindingIds: ["finding.unreviewed"],
    });
    expect(summary.repositories[0]?.staticHypotheses).toMatchObject({
      supportedTp: 1,
      trueButUncuratedSupport: 1,
      unreviewedSupported: 1,
      unreviewedSupportedIds: ["hypothesis.unreviewed"],
    });
    expect(summary.repositories[0]?.scoreabilityErrors).toContain(
      "direct precision not scoreable: direct ground truth is incomplete",
    );
    expect(summary.repositories[0]?.scoreabilityErrors).toContain(
      "static support precision not scoreable: static ground truth is incomplete",
    );
    expect(summary.targetErrors.some((error) => error.includes("not scoreable"))).toBe(true);
  });

  it("summarizes static support review queues without changing scoreability", () => {
    const summaries = staticSupportReviewSummaries(
      {
        version: 1,
        repositories: [
          {
            name: "Review fixture",
            language: "JS/TS",
            split: "tuning",
            match: { originUrl: "https://example.test/review" },
            directTruth: "complete",
            directFpReview: "complete",
            staticTruth: "incomplete",
            staticSupportReview: "incomplete",
            staticHypotheses: [
              {
                id: "static.sql",
                title: "SQL injection path",
                coverageArea: "data_flow",
                candidateFamily: "external_input_to_dangerous_operation",
                matcher: { titleIncludes: "SQL injection", statusIn: ["statically_supported"] },
              },
            ],
            trueButUncuratedStatic: [
              {
                id: "extra.xss",
                reason: "Additional reflected response variants are true duplicates.",
                matcher: { titleIncludes: "Cross-site scripting" },
              },
            ],
          },
        ],
      },
      [
        report({
          originUrl: "https://example.test/review",
          candidates: [
            candidate("candidate.sql", {
              family: "external_input_to_dangerous_operation",
              title: "SQL injection path",
              candidateReason: "SQL injection path: /users reaches query",
            }),
            candidate("candidate.xss", {
              family: "external_input_to_dangerous_operation",
              title: "Cross-site scripting path",
              candidateReason: "Cross-site scripting path: /search reaches response",
            }),
            candidate("candidate.open-redirect", {
              family: "external_input_to_dangerous_operation",
              title: "Open redirect path",
              candidateReason: "Open redirect path: /go reaches redirect",
            }),
          ],
          hypotheses: [
            hypothesis("hypothesis.sql", "candidate.sql", {
              status: "statically_supported",
              title: "SQL injection path",
            }),
            hypothesis("hypothesis.xss", "candidate.xss", {
              status: "statically_supported",
              title: "Cross-site scripting path",
            }),
            hypothesis("hypothesis.open-redirect", "candidate.open-redirect", {
              status: "statically_supported",
              title: "Open redirect path",
            }),
          ],
        }),
      ],
    );

    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toMatchObject({
      supported: 3,
      expectedTruth: 1,
      trueButUncurated: 1,
      unreviewed: 1,
      unreviewedGroups: [
        {
          family: "external_input_to_dangerous_operation",
          title: "Open redirect path",
          count: 1,
          sampleHypothesisIds: ["hypothesis.open-redirect"],
          sampleCandidateReasons: ["Open redirect path: /go reaches redirect"],
        },
      ],
    });
  });

  it("does not fail per-language targets for complete empty denominators", () => {
    const summary = scoreBenchmarkReports(
      {
        version: 1,
        targets: { maxTuningHeldOutGap: 1 },
        repositories: [
          {
            name: "Scored fixture",
            language: "Go",
            split: "held-out",
            match: { originUrl: "https://example.test/scored" },
            directTruth: "complete",
            directFpReview: "complete",
            staticTruth: "complete",
            staticSupportReview: "complete",
            directFindings: [
              {
                id: "direct.secret",
                title: "Secret is found",
                coverageArea: "language_support",
                matcher: { ruleId: "generic-api-key", category: "secret" },
              },
            ],
            staticHypotheses: [
              {
                id: "static.sqli",
                title: "SQL injection path",
                coverageArea: "data_flow",
                candidateFamily: "external_input_to_dangerous_operation",
                matcher: { titleIncludes: "SQL injection", statusIn: ["statically_supported"] },
              },
            ],
          },
          {
            name: "Empty direct fixture",
            language: "Python",
            split: "held-out",
            match: { originUrl: "https://example.test/empty" },
            directTruth: "complete",
            directFpReview: "complete",
            staticTruth: "complete",
            staticSupportReview: "complete",
          },
        ],
      },
      [
        report({
          originUrl: "https://example.test/scored",
          findings: [
            finding("finding.secret", {
              ruleId: "generic-api-key",
              category: "secret",
              filePath: "config.go",
            }),
          ],
          candidates: [
            candidate("candidate.sqli", {
              family: "external_input_to_dangerous_operation",
              title: "SQL injection path",
            }),
          ],
          hypotheses: [
            hypothesis("hypothesis.sqli", "candidate.sqli", {
              status: "statically_supported",
              title: "SQL injection path",
            }),
          ],
        }),
        report({ originUrl: "https://example.test/empty" }),
      ],
    );

    const pythonAggregate = summary.aggregates.find((item) => item.key === "language:Python");
    expect(pythonAggregate?.directPrecision.blockedBy).toEqual(["metric denominator is zero"]);
    expect(summary.targetErrors.some((error) => error.includes("language:Python direct"))).toBe(
      false,
    );
    expect(summary.targetErrors.some((error) => error.includes("all direct precision"))).toBe(
      false,
    );
  });

  it("gates recall denominators on coverage loss instead of counting false misses", () => {
    const summary = scoreBenchmarkReports(
      {
        version: 1,
        targets: { maxTuningHeldOutGap: 1 },
        repositories: [
          {
            name: "Coverage fixture",
            language: "Go",
            split: "tuning",
            match: { originUrl: "https://example.test/coverage" },
            directTruth: "complete",
            directFpReview: "complete",
            staticTruth: "complete",
            staticSupportReview: "complete",
            directFindings: [
              {
                id: "direct.secret",
                title: "Secret is in failed coverage",
                coverageArea: "data_flow",
                matcher: { ruleId: "generic-api-key", category: "secret" },
              },
            ],
            staticHypotheses: [
              {
                id: "static.path",
                title: "Path is in partial graph coverage",
                coverageArea: "language_support",
                candidateFamily: "external_input_to_dangerous_operation",
                matcher: { titleIncludes: "Command injection" },
              },
            ],
            coverage: {
              data_flow: { stateIn: ["failed"] },
              language_support: { stateIn: ["partial"] },
            },
          },
        ],
      },
      [
        report({
          originUrl: "https://example.test/coverage",
          deepCoverage: [
            { area: "data_flow", state: "failed", reason: "backend failed" },
            { area: "language_support", state: "partial", reason: "unsupported php=1" },
          ],
        }),
      ],
    );

    expect(summary.repositories[0]?.direct.coverageLoss).toBe(1);
    expect(summary.repositories[0]?.direct.fn).toBe(0);
    expect(summary.repositories[0]?.staticHypotheses.coverageLoss).toBe(1);
    expect(summary.repositories[0]?.staticHypotheses.candidateFn).toBe(0);
  });
});

function report(input: {
  readonly originUrl?: string;
  readonly findings?: ReadonlyArray<Finding>;
  readonly candidates?: ReadonlyArray<HypothesisCandidate>;
  readonly hypotheses?: ReadonlyArray<StaticHypothesis>;
  readonly deepCoverage?: ReadonlyArray<{
    readonly area: string;
    readonly state: string;
    readonly reason?: string;
  }>;
}): { readonly runId: string; readonly assessment: SecurityAssessment } {
  const deepCoverage = (
    input.deepCoverage ?? [
      { area: "language_support", state: "checked" },
      { area: "data_flow", state: "checked" },
      { area: "dependency_usage", state: "checked" },
    ]
  ).map((entry) => ({
    area: entry.area,
    state: entry.state,
    ...(entry.reason === undefined ? {} : { reason: entry.reason }),
    producer: "fixture",
    producerVersion: "1",
  })) as NonNullable<SecurityAssessment["deepCoverage"]>;

  return {
    runId: "run-fixture",
    assessment: {
      repository: {
        name: "fixture",
        originUrl: input.originUrl ?? "https://example.test/app",
      },
      manifest: {
        fileCount: 1,
        totalBytes: 10,
        sourceHash: "sha256:fixture",
        commitSha: "abc123",
        exclusionCount: 0,
      },
      toolchain: { imageTag: "fixture", tools: [] },
      verdict: "not-ready-to-deploy",
      coverage: [],
      deepCoverage,
      findingSummary: { total: input.findings?.length ?? 0, bySeverity: {}, byCategory: {} },
      evidence: [],
      findings: input.findings ?? [],
      findingClusters: [],
      rankedActions: [],
      hypothesisCandidates: input.candidates ?? [],
      staticHypotheses: input.hypotheses ?? [],
      limitation: "fixture",
      generatedAt: "2026-06-26T00:00:00.000Z",
    },
  };
}

function finding(
  id: string,
  input: {
    readonly ruleId: string;
    readonly category: Finding["category"];
    readonly filePath: string;
  },
): Finding {
  return {
    id,
    sourceTool: "fixture",
    ruleId: input.ruleId,
    category: input.category,
    severity: "critical",
    confidence: "high",
    locations: [{ filePath: input.filePath, startLine: 1, endLine: 1 }],
    evidenceIds: [],
    fingerprint: `${input.ruleId}:${input.filePath}`,
  };
}

function candidate(
  id: string,
  input: {
    readonly family: string;
    readonly title: string;
    readonly candidateReason?: string;
  },
): HypothesisCandidate {
  return {
    id,
    ruleId: `fixture.${input.family}`,
    family: input.family,
    title: input.title,
    findingIds: [],
    supportingNodeIds: ["node.fixture"],
    supportingEdgeIds: [],
    contradictingNodeIds: [],
    contradictingEdgeIds: [],
    coverageRefs: ["data_flow:checked"],
    requiredValidation: ["runtime_validation"],
    candidateReason: input.candidateReason ?? input.title,
  };
}

function hypothesis(
  id: string,
  candidateId: string,
  input: {
    readonly status: StaticHypothesis["status"];
    readonly title: string;
  },
): StaticHypothesis {
  return {
    id,
    candidateId,
    status: input.status,
    staticConfidence: 0.9,
    title: input.title,
    pathSummary: input.title,
    supportingEvidenceIds: input.status === "statically_supported" ? ["evidence.fixture"] : [],
    contradictingEvidenceIds:
      input.status === "statically_contradicted" ? ["evidence.fixture"] : [],
    coverageState: "checked",
    runtimeValidationRequired: true,
  };
}
