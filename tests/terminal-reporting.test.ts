import { describe, expect, it } from "vitest";
import type { ScanOutcome } from "../src/application/scan-service.js";
import type { SecurityAssessment } from "../src/domain/security-assessment.js";
import { renderHelp, renderScanOutcome, TerminalEventSink } from "../src/reporting/terminal.js";

describe("terminal reporting", () => {
  it("renders a concise owner-facing receipt from the assessment contract", () => {
    const text = renderScanOutcome(sampleOutcome({ fromCatalog: false }));

    expect(text).toContain("VibeShield");
    expect(text).toContain("github.com/example/demo");
    expect(text).toContain("Critical fix needed");
    expect(text).toContain("1 fix to make before you ship");
    expect(text).toContain("Full report");
    expect(text).not.toContain("Fix these first");
    expect(text).not.toContain("src/config.ts:4");
    expect(text).not.toContain("Remove the committed Stripe secret");
    expect(text).toContain("/tmp/run/report.html");
    expect(text).not.toContain("\u001b[");
  });

  it("keeps internal pipeline jargon out of the receipt", () => {
    const text = renderScanOutcome(sampleOutcome({ fromCatalog: true }));

    expect(text).not.toContain("OpenRouter");
    expect(text).not.toContain("catalog");
    expect(text).not.toContain("deterministic");
    expect(text).not.toContain("Toolchain");
    expect(text).not.toContain("checked 1");
    expect(text).not.toContain("A live payment key is present in source code.");
    expect(text).toContain("Markdown and JSON are in the same folder.");
  });

  it("renders a richer Deep Static summary without dumping full fix details", () => {
    const base = sampleOutcome({ fromCatalog: false });
    const outcome: ScanOutcome = {
      ...base,
      assessment: {
        ...base.assessment,
        deepCoverage: [
          {
            area: "language_support",
            state: "checked",
            coveredCount: 12,
            totalCount: 12,
            producer: "joern",
            producerVersion: "4.0.565",
          },
          {
            area: "data_flow",
            state: "checked",
            coveredCount: 4,
            totalCount: 9,
            producer: "joern",
            producerVersion: "4.0.565",
          },
          {
            area: "dependency_usage",
            state: "checked",
            coveredCount: 2,
            totalCount: 2,
            producer: "joern",
            producerVersion: "4.0.565",
          },
        ],
        hypothesisCandidates: [
          {
            id: "candidate_input_sql",
            ruleId: "stage2.external-input-dangerous-operation",
            family: "external_input_to_dangerous_operation",
            title: "External input reaches a dangerous operation",
            findingIds: [],
            supportingNodeIds: ["node_1"],
            supportingEdgeIds: ["edge_1"],
            contradictingNodeIds: [],
            contradictingEdgeIds: [],
            coverageRefs: ["data_flow:checked"],
            requiredValidation: ["dangerous_operation_repro"],
            candidateReason: "/api/users reaches query across 3 graph edges",
          },
          {
            id: "candidate_dep",
            ruleId: "stage2.dependency-usage-path",
            family: "dependency_usage_path",
            title: "Vulnerable component is imported, used, or reachable in the dependency graph",
            findingIds: ["finding_1"],
            supportingNodeIds: ["node_2"],
            supportingEdgeIds: ["edge_2"],
            contradictingNodeIds: [],
            contradictingEdgeIds: [],
            coverageRefs: ["dependency_usage:checked"],
            requiredValidation: ["dependency_usage_review"],
            candidateReason: "src/server.ts reaches vulnerable package lodash",
          },
        ],
        staticHypotheses: [
          {
            id: "hypothesis_input_sql",
            candidateId: "candidate_input_sql",
            status: "statically_supported",
            staticConfidence: 0.84,
            title: "External input reaches a dangerous operation",
            pathSummary: "Static path reaches query.",
            supportingEvidenceIds: ["ev_1"],
            contradictingEvidenceIds: [],
            coverageState: "checked",
            runtimeValidationRequired: true,
          },
          {
            id: "hypothesis_dep",
            candidateId: "candidate_dep",
            status: "statically_supported",
            staticConfidence: 0.78,
            title: "Vulnerable component is imported, used, or reachable in the dependency graph",
            pathSummary: "Static path reaches vulnerable package.",
            supportingEvidenceIds: ["ev_1"],
            contradictingEvidenceIds: [],
            coverageState: "checked",
            runtimeValidationRequired: true,
          },
        ],
      },
    };

    const text = renderScanOutcome(outcome);

    expect(text).toContain("Deep Static");
    expect(text).toContain("2 likely attack paths traced");
    expect(text).toContain("2 with static support");
    expect(text).toContain("input-to-danger 1");
    expect(text).toContain("dependency usage 1");
    expect(text).toContain("/api/users reaches query");
    expect(text).toContain("src/server.ts reaches vulnerable package lodash");
    expect(text).toContain("Coverage: languages checked 12/12");
    expect(text).toContain("data flow checked 4/9");
    expect(text).not.toContain("stage2.external-input-dangerous-operation");
    expect(text).not.toContain("candidate_input_sql");
  });

  it("prints owner-facing progress events without requiring a live scan", () => {
    let output = "";
    const sink = new TerminalEventSink(
      {
        isTTY: false,
        write(chunk: string) {
          output += chunk;
          return true;
        },
      },
      { color: false },
    );

    sink.emit({
      type: "stage-started",
      stageId: "source.resolve",
      message: "source.resolve",
      timestamp: "2026-06-22T00:00:00.000Z",
    });
    sink.emit({
      type: "stage-started",
      stageId: "scan.secrets.gitleaks",
      message: "scan.secrets.gitleaks",
      timestamp: "2026-06-22T00:00:00.000Z",
    });
    sink.emit({
      type: "stage-started",
      stageId: "scan.code.opengrep",
      message: "scan.code.opengrep",
      timestamp: "2026-06-22T00:00:00.000Z",
    });
    sink.emit({
      type: "stage-started",
      stageId: "deep.static.compose",
      message: "deep.static.compose",
      timestamp: "2026-06-22T00:00:00.000Z",
    });
    sink.emit({
      type: "scan-progress",
      stageId: "deep.static.compose",
      message: "joern stderr: parsing internal slice",
      details: { publicLabel: "Tracing data flow" },
      timestamp: "2026-06-22T00:00:00.000Z",
    });
    sink.emit({
      type: "stage-started",
      stageId: "hypotheses.enrich",
      message: "hypotheses.enrich",
      timestamp: "2026-06-22T00:00:00.000Z",
    });
    sink.emit({
      type: "error",
      message: "sandbox unavailable",
      timestamp: "2026-06-22T00:00:00.000Z",
    });
    sink.emit({
      type: "run-finished",
      message: "sandbox unavailable",
      details: { status: "failed" },
      timestamp: "2026-06-22T00:00:00.000Z",
    });

    expect(output).toContain("Preparing the repository");
    expect(output).toContain("Running security checks");
    expect(output).toContain("Running Deep Static analysis");
    expect(output).toContain("Tracing data flow");
    expect(output).toContain("Explaining likely attack paths");
    expect(output).toContain("sandbox unavailable");
    expect(output).not.toContain("source.resolve");
    expect(output).not.toContain("scan.secrets.gitleaks");
    expect(output).not.toContain("scan.code.opengrep");
    expect(output).not.toContain("deep.static.compose");
    expect(output).not.toContain("hypotheses.enrich");
    expect(output).not.toContain("joern stderr");
    expect(output.match(/Running security checks/g)).toHaveLength(1);
    expect(output).not.toContain("Scan complete");
  });

  it("mentions the opt-in deep scan flag in help", () => {
    const text = renderHelp({ color: false });

    expect(text).toContain("[--deep]");
    expect(text).toContain("vibeshield scan ./my-app --deep");
  });
});

function sampleOutcome(opts: { readonly fromCatalog: boolean }): ScanOutcome {
  const assessment: SecurityAssessment = {
    repository: {
      name: "demo",
      originUrl: "https://github.com/example/demo.git",
      commitSha: "abcdef1234567890",
    },
    manifest: {
      fileCount: 4,
      totalBytes: 4096,
      sourceHash: "11112222333344445555",
      commitSha: "abcdef1234567890",
      exclusionCount: 2,
    },
    toolchain: {
      imageTag: "vibeshield-toolchain:test",
      tools: [{ tool: "gitleaks", version: "8.30.1" }],
    },
    verdict: "critical-fix-needed",
    coverage: [
      { check: "secrets.gitleaks", status: "checked" },
      { check: "dependencies.syft", status: "degraded", reason: "partial sbom" },
      { check: "dependencies.trivy", status: "failed", reason: "trivy db stale" },
      { check: "github-actions.actionlint", status: "skipped", reason: "no workflows" },
    ],
    findingSummary: {
      total: 1,
      bySeverity: { critical: 1 },
      byCategory: { secret: 1 },
    },
    evidence: [
      {
        id: "ev_1",
        rawArtifactBlobSha256: "raw",
        filePath: "src/config.ts",
        startLine: 4,
        endLine: 4,
        snippet: "STRIPE_SECRET_KEY=[REDACTED]",
        snippetHash: "snippet",
        tool: "gitleaks",
      },
    ],
    findings: [
      {
        id: "finding_1",
        sourceTool: "gitleaks",
        ruleId: "stripe-secret-key",
        category: "secret",
        severity: "critical",
        confidence: "high",
        locations: [{ filePath: "src/config.ts", startLine: 4, endLine: 4 }],
        evidenceIds: ["ev_1"],
        fingerprint: "fingerprint",
        remediationKey: "live-secret-in-source",
      },
    ],
    findingClusters: [
      {
        id: "cluster_1",
        category: "secret",
        findingIds: ["finding_1"],
        maxSeverity: "critical",
      },
    ],
    rankedActions: [
      {
        candidate: {
          id: "action_1",
          remediationKey: "live-secret-in-source",
          priorityScore: 100,
          findingIds: ["finding_1"],
          evidenceIds: ["ev_1"],
          affectedFiles: ["src/config.ts"],
          verdictImpact: "blocks-deploy",
        },
        remediation: {
          candidateId: "action_1",
          title: "Remove the committed Stripe secret",
          risk: "A live payment key is present in source code.",
          whyFixNow: "Anyone with repository access can use the key.",
          fixSteps: ["Remove the key from src/config.ts.", "Load it from environment instead."],
          operationalSteps: ["Rotate the leaked key in Stripe."],
          agentPrompt: "Remove the committed Stripe key and use process.env. Do not print secrets.",
          verifySteps: ["Run VibeShield again."],
          fromCatalog: opts.fromCatalog,
        },
      },
    ],
    limitation:
      "This scan did not run your app; authorization logic and runtime behavior were not checked.",
    generatedAt: "2026-06-22T00:00:00.000Z",
  };

  return {
    assessment,
    runId: "20260622000000-test",
    reportPaths: {
      json: "/tmp/run/report.json",
      markdown: "/tmp/run/report.md",
      html: "/tmp/run/report.html",
    },
  };
}
