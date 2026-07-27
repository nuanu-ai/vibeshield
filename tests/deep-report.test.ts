import { describe, expect, it } from "vitest";
import type { SecurityAssessment } from "../src/domain/security-assessment.js";
import {
  renderDeepHtmlReport,
  renderDeepMarkdownReport,
  renderDeepReportJson,
} from "../src/reporting/deep-report.js";

describe("deep report renderers", () => {
  it("preserves deep machine-readable ids in JSON", () => {
    const assessment = deepAssessment();

    const json = renderDeepReportJson("run-1", assessment);

    expect(json.runId).toBe("run-1");
    expect(json.assessment.hypothesisCandidates?.[0]).toMatchObject({
      id: "candidate-1",
      family: "external_input_to_dangerous_operation",
      supportingEdgeIds: ["edge-1"],
    });
    expect(json.assessment.staticHypotheses?.[0]?.id).toBe("hypothesis-1");
    expect(json.assessment.validationRecipes?.[0]?.id).toBe("recipe-1");
    expect(json.assessment.deepActionGroups?.[0]?.id).toBe("group-1");
    expect(json.assessment.repositoryMapArtifactRef).toMatchObject({
      blobSha256: "repo-map-sha",
      role: "repository-map.json",
    });
  });

  it("renders owner-facing deep Markdown sections", () => {
    const markdown = renderDeepMarkdownReport("run-1", deepAssessment());

    expect(markdown).toContain("## Fix now");
    expect(markdown).toContain("Rotate leaked key");
    expect(markdown).toContain("Related static evidence (not a separate confirmed issue)");
    expect(markdown).toContain("## Validate next");
    expect(markdown).toContain("SQL injection path");
    expect(markdown).toContain("**Validation recipe**");
    expect(markdown).toContain("First confirm or disprove this static hypothesis");
    expect(markdown).not.toContain("Patch the SQL path before checking it.");
    expect(markdown).toContain("## Technical appendix");
    expect(markdown).toContain("| Call graph | Checked |");
    expect(markdown).toContain("`statically_supported`");
    expect(markdown).not.toContain("repo-map-sha");
  });

  it("deduplicates owner-facing attack paths without changing JSON", () => {
    const assessment = deepAssessment();
    const baseHypothesis = requiredById(
      assessment.staticHypotheses,
      "hypothesis-validation",
      "static hypothesis",
    );
    const baseCandidate = requiredById(
      assessment.hypothesisCandidates,
      "candidate-validation",
      "hypothesis candidate",
    );
    const baseRecipe = requiredByHypothesisId(
      assessment.validationRecipes,
      "hypothesis-validation",
      "validation recipe",
    );
    const baseEnrichment = requiredByHypothesisId(
      assessment.hypothesisEnrichments,
      "hypothesis-validation",
      "hypothesis enrichment",
    );
    const duplicateHypothesis: NonNullable<SecurityAssessment["staticHypotheses"]>[number] = {
      ...baseHypothesis,
      id: "hypothesis-duplicate",
      candidateId: "candidate-duplicate",
      staticConfidence: 0.78,
      pathSummary: "Alternate static path reaches the same fetch.",
    };
    const duplicateCandidate = {
      ...baseCandidate,
      id: "candidate-duplicate",
      candidateReason:
        "SQL injection path: request (src/other.ts:10) reaches query (src/db.ts:22) across 3 graph edges",
    };
    const duplicateRecipe: NonNullable<SecurityAssessment["validationRecipes"]>[number] = {
      ...baseRecipe,
      id: "recipe-duplicate",
      hypothesisId: "hypothesis-duplicate",
      steps: ["Replay the lower-confidence duplicate path."],
    };
    const duplicateEnrichment: NonNullable<SecurityAssessment["hypothesisEnrichments"]>[number] = {
      ...baseEnrichment,
      id: "enrichment-duplicate",
      hypothesisId: "hypothesis-duplicate",
    };
    const withDuplicate: SecurityAssessment = {
      ...assessment,
      hypothesisCandidates: [...(assessment.hypothesisCandidates ?? []), duplicateCandidate],
      staticHypotheses: [...(assessment.staticHypotheses ?? []), duplicateHypothesis],
      validationRecipes: [...(assessment.validationRecipes ?? []), duplicateRecipe],
      hypothesisEnrichments: [...(assessment.hypothesisEnrichments ?? []), duplicateEnrichment],
    };

    const json = renderDeepReportJson("run-1", withDuplicate);
    const markdown = renderDeepMarkdownReport("run-1", withDuplicate);
    const html = renderDeepHtmlReport("run-1", withDuplicate);

    expect(json.assessment.staticHypotheses?.map((hypothesis) => hypothesis.id)).toContain(
      "hypothesis-duplicate",
    );
    expect(markdown.match(/^### \d+\. SQL injection path.*Unconfirmed$/gm)).toHaveLength(1);
    expect(
      html.match(/<h3>SQL injection path: external input reaches SQL execution<\/h3>/g),
    ).toHaveLength(1);
    expect(markdown).not.toContain("Replay the lower-confidence duplicate path.");
    expect(html).toContain("src/other.ts:10");
  });

  it("groups same-root-cause paths while retaining multiple evidence locations", () => {
    const assessment = deepAssessment();
    const baseHypothesis = requiredById(
      assessment.staticHypotheses,
      "hypothesis-validation",
      "static hypothesis",
    );
    const baseCandidate = requiredById(
      assessment.hypothesisCandidates,
      "candidate-validation",
      "hypothesis candidate",
    );
    const baseRecipe = requiredByHypothesisId(
      assessment.validationRecipes,
      "hypothesis-validation",
      "validation recipe",
    );
    const baseEnrichment = requiredByHypothesisId(
      assessment.hypothesisEnrichments,
      "hypothesis-validation",
      "hypothesis enrichment",
    );
    const distinctHypothesis: NonNullable<SecurityAssessment["staticHypotheses"]>[number] = {
      ...baseHypothesis,
      id: "hypothesis-distinct",
      candidateId: "candidate-distinct",
      staticConfidence: 0.78,
      pathSummary: "External input from another handler reaches fetch.",
    };
    const distinctCandidate = {
      ...baseCandidate,
      id: "candidate-distinct",
      candidateReason:
        "SQL injection path: request (src/other-handler.ts:20) reaches query (src/db.ts:22) across 4 graph edges",
    };
    const distinctRecipe: NonNullable<SecurityAssessment["validationRecipes"]>[number] = {
      ...baseRecipe,
      id: "recipe-distinct",
      hypothesisId: "hypothesis-distinct",
    };
    const distinctEnrichment: NonNullable<SecurityAssessment["hypothesisEnrichments"]>[number] = {
      ...baseEnrichment,
      id: "enrichment-distinct",
      hypothesisId: "hypothesis-distinct",
      attackDescription: "External input reaches fetch through another handler.",
      agentPrompt: "Patch the other handler.",
    };
    const withDistinctPath: SecurityAssessment = {
      ...assessment,
      hypothesisCandidates: [...(assessment.hypothesisCandidates ?? []), distinctCandidate],
      staticHypotheses: [...(assessment.staticHypotheses ?? []), distinctHypothesis],
      validationRecipes: [...(assessment.validationRecipes ?? []), distinctRecipe],
      hypothesisEnrichments: [...(assessment.hypothesisEnrichments ?? []), distinctEnrichment],
    };

    const markdown = renderDeepMarkdownReport("run-1", withDistinctPath);

    expect(markdown.match(/^### \d+\. SQL injection path.*Unconfirmed$/gm)).toHaveLength(1);
    expect(markdown).toContain("src/routes.ts:12");
    expect(markdown).toContain("src/other-handler.ts:20");
  });

  it("renders equivalent escaped deep HTML sections", () => {
    const html = renderDeepHtmlReport("run-1", deepAssessment());

    expect(html).toContain("<h2>Fix now</h2>");
    expect(html).toContain("<h2>Validate next</h2>");
    expect(html).toContain('<h2 id="technical-appendix">Technical appendix</h2>');
    expect(html).toContain("External input reaches &lt;fetch&gt;");
    expect(html).not.toContain("<fetch>");
    expect(html).not.toContain("repo-map-sha");
    expect(html).toContain("statically_supported");
  });

  it("keeps Quick Scan assessments valid when deep fields are absent", () => {
    const assessment = quickAssessment();

    const markdown = renderDeepMarkdownReport("run-quick", assessment);
    const html = renderDeepHtmlReport("run-quick", assessment);

    expect(markdown).toContain("No unlinked, statically supported hypotheses");
    expect(markdown).toContain("## Technical appendix");
    expect(html).toContain("No unlinked, statically supported hypotheses");
  });
});

function deepAssessment(): SecurityAssessment {
  return {
    ...quickAssessment(),
    deepCoverage: [
      {
        area: "call_graph",
        state: "checked",
        producer: "joern",
        producerVersion: "joern@4.0.565",
      },
    ],
    findingContextAssessments: [
      {
        findingId: "finding-1",
        status: "linked_to_hypothesis",
        graphNodeIds: ["node-1"],
        graphEdgeIds: ["edge-1"],
        hypothesisIds: ["hypothesis-1"],
        reason: "Finding is on the analyzed static path.",
        coverageState: "checked",
      },
    ],
    hypothesisCandidates: [
      {
        id: "candidate-1",
        ruleId: "stage2.external-input-dangerous-operation",
        family: "external_input_to_dangerous_operation",
        title: "External input reaches <fetch>",
        findingIds: ["finding-1"],
        supportingNodeIds: ["node-1"],
        supportingEdgeIds: ["edge-1"],
        contradictingNodeIds: [],
        contradictingEdgeIds: [],
        coverageRefs: ["stage2:data_flow:checked"],
        requiredValidation: ["dangerous_operation_repro"],
        candidateReason: "External input reaches fetch across one graph edge.",
      },
      {
        id: "candidate-validation",
        ruleId: "stage2.external-input-dangerous-operation",
        family: "external_input_to_dangerous_operation",
        title: "SQL injection path: external input reaches SQL execution",
        findingIds: [],
        supportingNodeIds: ["node-source", "node-sink"],
        supportingEdgeIds: ["edge-sql"],
        contradictingNodeIds: [],
        contradictingEdgeIds: [],
        coverageRefs: ["stage2:data_flow:checked"],
        requiredValidation: ["dangerous_operation_repro"],
        candidateReason:
          "SQL injection path: request (src/routes.ts:12) reaches query (src/db.ts:22) across 3 graph edges",
      },
    ],
    staticHypotheses: [
      {
        id: "hypothesis-1",
        candidateId: "candidate-1",
        status: "statically_supported",
        staticConfidence: 0.83,
        title: "External input reaches <fetch>",
        pathSummary: "External input reaches fetch on an analyzed path.",
        supportingEvidenceIds: ["evidence-1"],
        contradictingEvidenceIds: [],
        coverageState: "checked",
        runtimeValidationRequired: true,
        promotion: supportedPromotion("root:direct-fetch"),
      },
      {
        id: "hypothesis-validation",
        candidateId: "candidate-validation",
        status: "statically_supported",
        staticConfidence: 0.88,
        title: "SQL injection path: external input reaches SQL execution",
        pathSummary: "Request input reaches a SQL query.",
        supportingEvidenceIds: ["evidence-1"],
        contradictingEvidenceIds: [],
        coverageState: "checked",
        runtimeValidationRequired: true,
        promotion: supportedPromotion("root:sql-query"),
      },
      {
        id: "hypothesis-contradicted",
        candidateId: "candidate-2",
        status: "statically_contradicted",
        staticConfidence: 0.1,
        title: "Contradicted path",
        pathSummary: "Control blocks this path.",
        supportingEvidenceIds: [],
        contradictingEvidenceIds: ["evidence-2"],
        coverageState: "checked",
        runtimeValidationRequired: false,
        promotion: {
          publishable: false,
          source: "external_input",
          sink: "typed_security_sink",
          path: "connected_security_flow",
          control: "effective",
          evidence: "current_line_pinned",
          reasons: ["effective_control_dominates_sink"],
        },
      },
    ],
    validationRecipes: [
      {
        id: "recipe-1",
        hypothesisId: "hypothesis-1",
        requiredFixtures: ["principal_a", "owned_resource"],
        steps: ["Prepare disposable tenants."],
        expectedResult: "Runtime validation should gather evidence later.",
        safetyNotes: ["Do not run against production."],
        materializationHints: ["factory:tenant"],
        knownGaps: [],
      },
      {
        id: "recipe-validation",
        hypothesisId: "hypothesis-validation",
        requiredFixtures: ["disposable_database"],
        steps: ["Send a harmless SQL metacharacter through the observed route."],
        expectedResult: "The query remains parameterized and no injected expression executes.",
        safetyNotes: ["Use a disposable local database."],
        materializationHints: ["fixture:local-database"],
        knownGaps: [],
      },
    ],
    hypothesisEnrichments: [
      {
        id: "enrichment-1",
        hypothesisId: "hypothesis-1",
        source: "catalog",
        attackDescription: "External input reaches fetch through the handler.",
        assumptions: ["Static graph evidence only."],
        impact: "Outbound request impact.",
        remediation: "Add a destination allowlist.",
        agentPrompt: "Patch the handler.",
        acceptanceCriteria: ["Path is blocked by a deterministic control."],
        validationRecipeText: "Use disposable fixtures later.",
      },
      {
        id: "enrichment-validation",
        hypothesisId: "hypothesis-validation",
        source: "model",
        attackDescription: "Model-authored attack description.",
        assumptions: ["Static graph evidence only."],
        impact: "Model-authored impact.",
        remediation: "Patch before validating.",
        agentPrompt: "Patch the SQL path before checking it.",
        acceptanceCriteria: ["Model-authored acceptance."],
        validationRecipeText: "Model-authored recipe.",
      },
    ],
    deepActionGroups: [
      {
        id: "group-1",
        leadKind: "direct_finding",
        remediationKey: "live-secret-in-source",
        priorityScore: 100,
        verdictImpact: "blocks-deploy",
        directActionIds: ["action-1"],
        findingIds: ["finding-1"],
        hypothesisIds: ["hypothesis-1"],
        evidenceIds: ["evidence-1"],
        affectedFiles: ["src/config.ts"],
        reason: "Direct action includes linked static hypothesis.",
      },
    ],
    repositoryMapArtifactRef: {
      blobSha256: "repo-map-sha",
      role: "repository-map.json",
      bytes: 123,
    },
    limitations: ["Python framework routes were partially analyzed."],
  };
}

function quickAssessment(): SecurityAssessment {
  return {
    repository: { name: "repo" },
    manifest: {
      fileCount: 3,
      totalBytes: 300,
      sourceHash: "source-sha",
      commitSha: null,
      exclusionCount: 0,
    },
    toolchain: { imageTag: "toolchain:test", tools: [] },
    verdict: "critical-fix-needed",
    coverage: [{ check: "scan.secrets.gitleaks", status: "checked" }],
    findingSummary: {
      total: 1,
      bySeverity: { critical: 1 },
      byCategory: { secret: 1 },
    },
    evidence: [
      {
        id: "evidence-1",
        rawArtifactBlobSha256: "raw-sha",
        filePath: "src/config.ts",
        startLine: 3,
        endLine: 3,
        snippet: "***REDACTED***",
        snippetHash: "snippet-sha",
        tool: "gitleaks",
      },
    ],
    findings: [
      {
        id: "finding-1",
        sourceTool: "gitleaks",
        ruleId: "api-key",
        category: "secret",
        severity: "critical",
        confidence: "high",
        locations: [{ filePath: "src/config.ts", startLine: 3, endLine: 3 }],
        evidenceIds: ["evidence-1"],
        fingerprint: "finding-fingerprint",
        remediationKey: "live-secret-in-source",
      },
    ],
    findingClusters: [],
    rankedActions: [
      {
        candidate: {
          id: "action-1",
          remediationKey: "live-secret-in-source",
          priorityScore: 100,
          findingIds: ["finding-1"],
          evidenceIds: ["evidence-1"],
          affectedFiles: ["src/config.ts"],
          verdictImpact: "blocks-deploy",
        },
        remediation: {
          candidateId: "action-1",
          title: "Rotate leaked key",
          risk: "A key is present in source.",
          whyFixNow: "Anyone with repository access can reuse it.",
          fixSteps: ["Remove the key."],
          operationalSteps: ["Rotate the key."],
          agentPrompt: "Patch src/config.ts.",
          verifySteps: ["Run scan again."],
          fromCatalog: true,
        },
      },
    ],
    limitation:
      "This scan did not run your app; authorization logic and runtime behavior were not checked.",
    generatedAt: "2026-06-24T10:00:00.000Z",
  };
}

function supportedPromotion(
  rootCauseKey: string,
): NonNullable<SecurityAssessment["staticHypotheses"]>[number]["promotion"] {
  return {
    publishable: true,
    source: "external_input",
    sink: "typed_security_sink",
    path: "connected_security_flow",
    control: "absent",
    evidence: "current_line_pinned",
    rootCauseKey,
    reasons: ["external_source_observed"],
  };
}

function requiredById<T extends { readonly id: string }>(
  values: ReadonlyArray<T> | undefined,
  id: string,
  label: string,
): T {
  const value = values?.find((record) => record.id === id);
  if (value === undefined) {
    throw new Error(`missing ${label}: ${id}`);
  }
  return value;
}

function requiredByHypothesisId<T extends { readonly hypothesisId: string }>(
  values: ReadonlyArray<T> | undefined,
  hypothesisId: string,
  label: string,
): T {
  const value = values?.find((record) => record.hypothesisId === hypothesisId);
  if (value === undefined) {
    throw new Error(`missing ${label}: ${hypothesisId}`);
  }
  return value;
}
