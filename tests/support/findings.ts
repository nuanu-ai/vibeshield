import type { Finding, ReportInput, RulePolicy, ScanResult } from "../../src/scan/contracts.js";

const testPolicy: readonly RulePolicy[] = [
  {
    scanner: "gitleaks",
    ruleId: "generic-api-key",
    remediationKey: "secret-rotation",
    publishMedium: false,
    requireHighConfidence: true,
  },
  {
    scanner: "opengrep",
    ruleId: "command-injection",
    remediationKey: "command-input",
    publishMedium: false,
    requireHighConfidence: true,
  },
  {
    scanner: "osv",
    ruleId: "*",
    remediationKey: "dependency-upgrade",
    publishMedium: false,
    requireHighConfidence: false,
  },
];

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-secret-1",
    scanner: "gitleaks",
    ruleId: "generic-api-key",
    category: "secret",
    severity: "high",
    confidence: "high",
    title: "Exposed API credential",
    evidence: "Synthetic credential marker redacted before reporting.",
    locations: [{ path: "src/config.ts", line: 12 }],
    rootCause: "secret:src/config.ts",
    remediationKey: "secret-rotation",
    ...overrides,
  };
}

export function makeReportInput(results: ScanResult[]): ReportInput {
  return {
    repository: {
      url: "https://github.com/example/synthetic-web-app",
      commit: "0123456789abcdef",
      files: ["src/config.ts"],
      history: { commits: 12, truncated: false },
      languages: ["TypeScript"],
    },
    provenance: {
      image: "vibeshield-toolchain:test",
      tools: {
        gitleaks: "8.0.0-test",
        opengrep: "1.0.0-test",
        osv: "1.0.0-test",
        trivy: "1.0.0-test",
        zizmor: "1.0.0-test",
      },
      rulesRevision: "test-rules-1",
      advisoryData: [
        {
          source: "synthetic-advisory-db",
          retrievedAt: "2026-09-07T00:00:00.000Z",
          stale: false,
        },
      ],
    },
    generatedAt: "2026-09-07T00:00:00.000Z",
    results,
    policy: testPolicy,
  };
}
