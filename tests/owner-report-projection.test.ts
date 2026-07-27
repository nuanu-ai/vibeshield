import { describe, expect, it } from "vitest";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
import type { SecurityAssessment } from "../src/domain/security-assessment.js";
import type { StaticHypothesis, StaticHypothesisStatus } from "../src/domain/static-hypothesis.js";
import {
  renderDeepHtmlReport,
  renderDeepMarkdownReport,
  renderDeepReportJson,
} from "../src/reporting/deep-report.js";
import {
  buildOwnerReportProjection,
  MAX_FIX_NOW_GROUPS,
  MAX_VALIDATE_NEXT_GROUPS,
} from "../src/reporting/owner-report-projection.js";

describe("Report v1 owner projection", () => {
  it("caps expanded groups, keeps hidden blocking counts, and folds linked hypotheses into fixes", () => {
    const assessment = assessmentFixture({ actionCount: 7 });
    const linked = addHypothesis(assessment, {
      id: "linked",
      title: "Linked direct trace",
      family: "sast_reachable_path",
      findingIds: ["finding-0"],
    });
    let current = linked.assessment;
    for (const [index, family] of [
      "external_input_to_dangerous_operation",
      "dependency_usage_path",
      "ci_supply_chain_path",
      "content_resource_exposure_path",
      "smart_contract_risk_path",
    ].entries()) {
      current = addHypothesis(current, {
        id: `validation-${index}`,
        title: `Validation root cause ${index}`,
        family,
      }).assessment;
    }
    current = addHypothesis(current, {
      id: "candidate-only",
      title: "Candidate only",
      family: "external_input_to_dangerous_operation",
      status: "candidate",
    }).assessment;
    current = addHypothesis(current, {
      id: "inconclusive",
      title: "Inconclusive only",
      family: "external_input_to_dangerous_operation",
      status: "inconclusive",
    }).assessment;
    current = addHypothesis(current, {
      id: "contradicted",
      title: "Contradicted only",
      family: "external_input_to_dangerous_operation",
      status: "statically_contradicted",
    }).assessment;

    const projection = buildOwnerReportProjection(current);
    const markdown = renderDeepMarkdownReport("run-caps", current);

    expect(projection.fixGroups).toHaveLength(7);
    expect(projection.visibleFixGroups).toHaveLength(MAX_FIX_NOW_GROUPS);
    expect(projection.hiddenFixGroupCount).toBe(2);
    expect(
      projection.fixGroups[0]?.relatedStaticEvidence.map((trace) => trace.hypothesis.id),
    ).toEqual(["hypothesis-linked"]);
    expect(projection.validationGroups).toHaveLength(5);
    expect(projection.visibleValidationGroups).toHaveLength(MAX_VALIDATE_NEXT_GROUPS);
    expect(projection.hiddenValidationGroupCount).toBe(2);
    expect(projection.validationGroups.flatMap((group) => group.traces)).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          hypothesis: expect.objectContaining({ id: "hypothesis-linked" }),
        }),
      ]),
    );
    expect(markdown).toContain("Showing 5 of 7; 2 additional blocking groups are");
    expect(markdown).toContain("Showing 3 of 5; 2 additional groups are");
    expect(markdown).toContain("Candidate only");
    expect(markdown).toContain("Inconclusive only");
    expect(markdown).toContain("Contradicted only");
  });

  it("groups hundreds of same-root traces into capped validation cards", () => {
    let assessment = assessmentFixture({ verdict: "not-ready-to-deploy" });
    const titles = [
      "SQL injection path",
      "Path traversal path",
      "Access control path",
      "Open redirect path",
    ];
    for (let index = 0; index < 432; index += 1) {
      assessment = addHypothesis(assessment, {
        id: `juice-${index}`,
        title: titles[index % titles.length] ?? "Static path",
        family: "external_input_to_dangerous_operation",
        sourceLine: index + 1,
      }).assessment;
    }

    const projection = buildOwnerReportProjection(assessment);
    const html = renderDeepHtmlReport("run-juice", assessment);

    expect(projection.validationGroups).toHaveLength(4);
    expect(projection.visibleValidationGroups).toHaveLength(3);
    expect(projection.validationGroups.reduce((sum, group) => sum + group.traces.length, 0)).toBe(
      432,
    );
    expect(html.match(/<article class="action">/g)).toHaveLength(3);
    expect(html).toContain("Raw static traces (432)");
    expect(html).toContain("Additional Validate next groups (1)");
  });

  it("ranks validation groups by deterministic actionability rather than model copy", () => {
    let baseline = assessmentFixture({ verdict: "not-ready-to-deploy" });
    baseline = addHypothesis(baseline, {
      id: "content",
      title: "Content exposure",
      family: "content_resource_exposure_path",
      confidence: 0.99,
    }).assessment;
    baseline = addHypothesis(baseline, {
      id: "dangerous",
      title: "SQL injection path",
      family: "external_input_to_dangerous_operation",
      confidence: 0.7,
    }).assessment;
    const modelAuthored: SecurityAssessment = {
      ...baseline,
      hypothesisEnrichments: (baseline.staticHypotheses ?? []).map((hypothesis, index) => ({
        id: `enrichment-${index}`,
        hypothesisId: hypothesis.id,
        source: "model",
        attackDescription: `Model copy ${index}`,
        assumptions: ["Model assumption"],
        impact: `Model impact ${index}`,
        remediation: `Model remediation ${index}`,
        agentPrompt: `Fix immediately because model says ${index}`,
        acceptanceCriteria: ["Model acceptance"],
        validationRecipeText: "Model recipe",
      })),
    };

    const first = buildOwnerReportProjection(baseline);
    const second = buildOwnerReportProjection(modelAuthored);

    expect(first.validationGroups[0]?.title).toBe("SQL injection path");
    expect(first.validationGroups[0]?.actionabilityScore).toBeGreaterThan(
      first.validationGroups[1]?.actionabilityScore ?? 0,
    );
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(first.validationGroups[0]?.agentPrompt).toContain(
      "First confirm or disprove this static hypothesis",
    );
    expect(first.validationGroups[0]?.agentPrompt).not.toContain("Fix immediately because model");
  });

  it("uses validation-required verdict wording when only supported static groups block deploy", () => {
    const assessment = addHypothesis(assessmentFixture({ verdict: "not-ready-to-deploy" }), {
      id: "validation",
      title: "SQL injection path",
      family: "external_input_to_dangerous_operation",
    }).assessment;

    const projection = buildOwnerReportProjection(assessment);
    const markdown = renderDeepMarkdownReport("run-validation", assessment);

    expect(projection.banner.label).toBe("Validation required before deploy");
    expect(projection.banner.subline).toContain("Confirm or disprove");
    expect(markdown).toContain("**Verdict:** Validation required before deploy");
    expect(markdown).toContain("**Expected result:**");
  });

  it("keeps validation-required wording when direct fixes are also present", () => {
    const assessment = addHypothesis(
      assessmentFixture({ actionCount: 1, verdict: "not-ready-to-deploy" }),
      {
        id: "validation-with-fix",
        title: "SQL injection path",
        family: "external_input_to_dangerous_operation",
      },
    ).assessment;

    const projection = buildOwnerReportProjection(assessment);

    expect(projection.banner.label).toBe("Validation required before deploy");
    expect(projection.banner.subline).toContain("1 direct fix is also listed");
    expect(projection.banner.subline).toContain("SQL injection path");
  });

  it("does not tell an owner to fix missing cards and makes incomplete coverage explicit", () => {
    const assessment: SecurityAssessment = {
      ...assessmentFixture({ verdict: "looks-ok-for-now" }),
      deepCoverage: [
        {
          area: "language_support",
          state: "partial",
          reason: "One language was not analyzed.",
          producer: "joern",
          producerVersion: "test",
        },
      ],
    };

    const projection = buildOwnerReportProjection(assessment);
    const markdown = renderDeepMarkdownReport("run-partial", assessment);

    expect(projection.banner.label).toBe("Coverage limited");
    expect(projection.coverage.label).toBe("Partial");
    expect(markdown).not.toContain("Fix the issues below");
    expect(markdown).toContain("No direct scanner-backed fixes");
    expect(markdown).toContain("Coverage: Partial");
  });

  it("keeps complete findings, hypotheses, recipes, evidence, and coverage in report.json", () => {
    const assessment = addHypothesis(assessmentFixture(), {
      id: "complete",
      title: "Complete machine record",
      family: "external_input_to_dangerous_operation",
    }).assessment;

    const report = renderDeepReportJson("run-json", assessment);

    expect(report.assessment.findings).toBe(assessment.findings);
    expect(report.assessment.staticHypotheses).toBe(assessment.staticHypotheses);
    expect(report.assessment.validationRecipes).toBe(assessment.validationRecipes);
    expect(report.assessment.evidence).toBe(assessment.evidence);
    expect(report.assessment.coverage).toBe(assessment.coverage);
    expect(report.ownerReport.validationGroups).toHaveLength(1);
    expect(report.ownerReport.validationGroups[0]?.rootCauseKey).toBe(
      "root:complete machine record",
    );
  });
});

interface AssessmentFixtureOptions {
  readonly actionCount?: number;
  readonly verdict?: SecurityAssessment["verdict"];
}

function assessmentFixture(options: AssessmentFixtureOptions = {}): SecurityAssessment {
  const actionCount = options.actionCount ?? 0;
  const findings = Array.from({ length: actionCount }, (_, index) => ({
    id: `finding-${index}`,
    sourceTool: "semgrep",
    ruleId: `rule-${index}`,
    category: "code-pattern" as const,
    severity: "high" as const,
    confidence: "high" as const,
    locations: [{ filePath: `src/file-${index}.ts`, startLine: index + 1, endLine: index + 1 }],
    evidenceIds: [`direct-evidence-${index}`],
    fingerprint: `fingerprint-${index}`,
    remediationKey: `remediation-${index}`,
  }));
  const evidence = findings.map((finding, index) => ({
    id: `direct-evidence-${index}`,
    rawArtifactBlobSha256: `raw-${index}`,
    filePath: finding.locations[0]?.filePath ?? "src/file.ts",
    startLine: index + 1,
    endLine: index + 1,
    snippet: "redacted",
    snippetHash: `snippet-${index}`,
    tool: "semgrep",
  }));
  return {
    repository: { name: "fixture" },
    manifest: {
      fileCount: 10,
      totalBytes: 1000,
      sourceHash: "source",
      commitSha: null,
      exclusionCount: 0,
    },
    toolchain: { imageTag: "toolchain:test", tools: [] },
    verdict: options.verdict ?? (actionCount > 0 ? "critical-fix-needed" : "looks-ok-for-now"),
    coverage: [{ check: "scan.secrets.gitleaks", status: "checked" }],
    findingSummary: {
      total: findings.length,
      bySeverity: findings.length === 0 ? {} : { high: findings.length },
      byCategory: findings.length === 0 ? {} : { "code-pattern": findings.length },
    },
    evidence,
    findings,
    findingClusters: [],
    rankedActions: findings.map((finding, index) => ({
      candidate: {
        id: `action-${index}`,
        remediationKey: `remediation-${index}`,
        priorityScore: 100 - index,
        findingIds: [finding.id],
        evidenceIds: finding.evidenceIds,
        affectedFiles: [finding.locations[0]?.filePath ?? "src/file.ts"],
        verdictImpact: "blocks-deploy",
      },
      remediation: {
        candidateId: `action-${index}`,
        title: `Direct fix ${index}`,
        risk: "Direct scanner-backed risk.",
        whyFixNow: "The scanner directly observed it.",
        fixSteps: ["Apply the narrow fix."],
        operationalSteps: [],
        agentPrompt: `Fix direct issue ${index}.`,
        verifySteps: ["Re-run the scanner."],
        fromCatalog: true,
      },
    })),
    hypothesisCandidates: [],
    staticHypotheses: [],
    validationRecipes: [],
    hypothesisEnrichments: [],
    deepActionGroups: [],
    limitation: "This scan did not run the application.",
    generatedAt: "2026-07-17T10:00:00.000Z",
  };
}

interface AddHypothesisOptions {
  readonly id: string;
  readonly title: string;
  readonly family: string;
  readonly findingIds?: ReadonlyArray<string>;
  readonly status?: StaticHypothesisStatus;
  readonly confidence?: number;
  readonly sourceLine?: number;
}

function addHypothesis(
  assessment: SecurityAssessment,
  options: AddHypothesisOptions,
): { readonly assessment: SecurityAssessment; readonly hypothesis: StaticHypothesis } {
  const candidateId = `candidate-${options.id}`;
  const hypothesisId = `hypothesis-${options.id}`;
  const line = options.sourceLine ?? 10;
  const candidate: HypothesisCandidate = {
    id: candidateId,
    ruleId: `stage2.${options.family}`,
    family: options.family,
    title: options.title,
    findingIds: options.findingIds ?? [],
    supportingNodeIds: [`source-${options.id}`, `sink-${options.id}`],
    supportingEdgeIds: [`edge-${options.id}`],
    contradictingNodeIds:
      options.status === "statically_contradicted" ? [`guard-${options.id}`] : [],
    contradictingEdgeIds: [],
    coverageRefs: ["stage2:data_flow:checked"],
    requiredValidation: ["disposable_runtime_check"],
    candidateReason: `${options.title}: request (src/routes.ts:${line}) reaches sink (src/sink.ts:20) across 3 graph edges`,
  };
  const status = options.status ?? "statically_supported";
  const hypothesis: StaticHypothesis = {
    id: hypothesisId,
    candidateId,
    status,
    staticConfidence: options.confidence ?? 0.8,
    title: options.title,
    pathSummary: `${options.title} static path.`,
    supportingEvidenceIds:
      status === "statically_supported" ? [`static-evidence-${options.id}`] : [],
    contradictingEvidenceIds:
      status === "statically_contradicted" ? [`contradiction-${options.id}`] : [],
    coverageState: "checked",
    runtimeValidationRequired: status !== "statically_contradicted",
    promotion: {
      publishable: status === "statically_supported",
      source: "external_input",
      sink: "typed_security_sink",
      path: "connected_security_flow",
      control: status === "statically_contradicted" ? "effective" : "absent",
      evidence: "current_line_pinned",
      ...(status === "statically_supported"
        ? { rootCauseKey: `root:${normalizeRootTitle(options.title)}` }
        : {}),
      reasons: ["external_source_observed"],
    },
  };
  return {
    hypothesis,
    assessment: {
      ...assessment,
      hypothesisCandidates: [...(assessment.hypothesisCandidates ?? []), candidate],
      staticHypotheses: [...(assessment.staticHypotheses ?? []), hypothesis],
      validationRecipes: [
        ...(assessment.validationRecipes ?? []),
        {
          id: `recipe-${options.id}`,
          hypothesisId,
          requiredFixtures: ["disposable_fixture"],
          steps: ["Exercise the observed path with a harmless disposable fixture."],
          expectedResult: "The sink rejects the input or an effective guard blocks the path.",
          safetyNotes: ["Do not use production."],
          materializationHints: ["fixture:local"],
          knownGaps: [],
        },
      ],
    },
  };
}

function normalizeRootTitle(value: string): string {
  return value.replace(/\s+/g, " ").trim().toLowerCase();
}
