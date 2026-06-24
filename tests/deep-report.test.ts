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

    expect(markdown).toContain("## Fix these first");
    expect(markdown).toContain("Rotate leaked key");
    expect(markdown).toContain("## Likely attack paths");
    expect(markdown).toContain("External input reaches fetch");
    expect(markdown).toContain("High confidence");
    expect(markdown).toContain("## What was checked");
    expect(markdown).toContain("| Call graph | Checked |");
    expect(markdown).toContain("principal_a");
    expect(markdown).not.toContain("statically_supported");
    expect(markdown).not.toContain("hypothesis-1");
    expect(markdown).not.toContain("repo-map-sha");
  });

  it("renders equivalent escaped deep HTML sections", () => {
    const html = renderDeepHtmlReport("run-1", deepAssessment());

    expect(html).toContain("<h2>Fix these first</h2>");
    expect(html).toContain("<h2>Likely attack paths</h2>");
    expect(html).toContain("What was checked");
    expect(html).toContain("External input reaches &lt;fetch&gt;");
    expect(html).not.toContain("<fetch>");
    expect(html).not.toContain("repo-map-sha");
    expect(html).not.toContain("statically_supported");
  });

  it("keeps Quick Scan assessments valid when deep fields are absent", () => {
    const assessment = quickAssessment();

    const markdown = renderDeepMarkdownReport("run-quick", assessment);
    const html = renderDeepHtmlReport("run-quick", assessment);

    expect(markdown).toContain("The deep analysis didn't trace any likely attack paths.");
    expect(markdown).toContain("## What was checked");
    expect(html).toContain("The deep analysis didn't trace any likely attack paths.");
  });
});

function deepAssessment(): SecurityAssessment {
  return {
    ...quickAssessment(),
    deepCoverage: [
      {
        area: "call_graph",
        state: "checked",
        producer: "atom",
        producerVersion: "atom@2.5.6",
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
