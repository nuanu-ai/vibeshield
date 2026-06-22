import { describe, expect, it } from "vitest";
import type { ScanOutcome } from "../src/application/scan-service.js";
import type { SecurityAssessment } from "../src/domain/security-assessment.js";
import { renderScanOutcome, TerminalEventSink } from "../src/reporting/terminal.js";

describe("terminal reporting", () => {
  it("renders an owner-facing Fix Pack from the assessment contract", () => {
    const text = renderScanOutcome(sampleOutcome({ fromCatalog: false }));

    expect(text).toContain("VibeShield Quick Scan");
    expect(text).toContain("Verdict: Critical fix needed");
    expect(text).toContain(
      "Fix Pack: 1 action (OpenRouter enhanced; deterministic verdict/actions; 1 critical)",
    );
    expect(text).toContain("Checks: checked 1, degraded 1, failed 1, skipped 1");
    expect(text).toContain("Open the HTML report");
    expect(text).toContain("Human report: /tmp/run/report.html");
    expect(text).toContain("1. Remove the committed Stripe secret at src/config.ts:4");
    expect(text).toContain("JSON: /tmp/run/report.json");
    expect(text).not.toContain("Agent prompt:");
    expect(text).not.toContain("Remove the committed Stripe key and use process.env");
    expect(text).not.toContain("A live payment key is present in source code.");
    expect(text).not.toContain("\u001b[");
  });

  it("shows catalog fallback explicitly", () => {
    const text = renderScanOutcome(sampleOutcome({ fromCatalog: true }));

    expect(text).toContain(
      "Fix Pack: 1 action (catalog fallback; deterministic verdict/actions; 1 critical)",
    );
    expect(text).toContain(
      "Each fix has a clearly labeled prompt to paste into your coding agent.",
    );
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

    expect(output).toContain("[scan] Preparing the repository");
    expect(output).toContain("[scan] Running security checks");
    expect(output).toContain("[fail] sandbox unavailable");
    expect(output).not.toContain("source.resolve");
    expect(output).not.toContain("scan.secrets.gitleaks");
    expect(output).not.toContain("scan.code.opengrep");
    expect(output.match(/Running security checks/g)).toHaveLength(1);
    expect(output).not.toContain("[done] sandbox unavailable");
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
