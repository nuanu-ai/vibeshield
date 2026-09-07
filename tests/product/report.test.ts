import { describe, expect, it } from "vitest";

import type { Finding, RulePolicy } from "../../src/scan/contracts.js";
import { buildReport } from "../../src/scan/report.js";
import { makeFinding, makeReportInput } from "../support/findings.js";

describe("deterministic report publication", () => {
  it("keeps coverage loss visible beside a grouped important issue", () => {
    const finding = makeFinding();
    const report = buildReport(
      makeReportInput([
        {
          findings: [finding, { ...finding, id: "duplicate" }],
          coverage: [
            {
              scanner: "osv",
              area: "dependencies",
              status: "failed",
              reason: "Invalid JSON",
              applicable: true,
            },
          ],
        },
      ]),
    );
    expect(report.issues).toHaveLength(1);
    expect(report.issues[0]?.findingIds).toEqual([finding.id, "duplicate"]);
    expect(report.issues[0]?.verification.length).toBeGreaterThan(0);
    expect(report.incomplete).toBe(true);
  });

  it("keeps low-only results out of the issue list", () => {
    const report = buildReport(
      makeReportInput([{ findings: [makeFinding({ severity: "low" })], coverage: [] }]),
    );
    expect(report.issues).toEqual([]);
    expect(report.suppressedCount).toBe(1);
  });

  it("does not publish an unknown-severity advisory through the OSV wildcard", () => {
    const report = buildReport(
      makeReportInput([{ findings: [dependencyFinding({ severity: "unknown" })], coverage: [] }]),
    );
    expect(report.issues).toEqual([]);
  });

  it("publishes a medium finding only with explicit promotion", () => {
    const finding = makeFinding({ severity: "medium" });
    const base = makeReportInput([{ findings: [finding], coverage: [] }]);
    expect(buildReport(base).issues).toEqual([]);
    const policy: readonly RulePolicy[] = [
      {
        scanner: "gitleaks",
        ruleId: "generic-api-key",
        remediationKey: "secret-rotation",
        publishMedium: true,
        requireHighConfidence: true,
      },
    ];
    expect(buildReport({ ...base, policy }).issues).toHaveLength(1);
  });

  it("does not publish a code finding without required flow evidence", () => {
    const report = buildReport(
      makeReportInput([
        {
          findings: [
            makeFinding({
              scanner: "opengrep",
              ruleId: "command-injection",
              category: "code",
              remediationKey: "command-input",
              rootCause: "command:src/run.ts",
              evidence: "sink: exec",
            }),
          ],
          coverage: [],
        },
      ]),
    );
    expect(report.issues).toEqual([]);
  });

  it("keeps all seven important root causes accessible", () => {
    const findings = Array.from({ length: 7 }, (_, index) =>
      makeFinding({
        id: `finding-${index}`,
        rootCause: `secret:src/config-${index}.ts`,
        locations: [{ path: `src/config-${index}.ts`, line: index + 1 }],
      }),
    );
    const report = buildReport(makeReportInput([{ findings, coverage: [] }]));
    expect(report.issues).toHaveLength(7);
  });

  it("keeps a historical secret and prioritizes rotation", () => {
    const finding = makeFinding({
      locations: [{ path: "old/config.ts", line: 8, commit: "deadbeef" }],
    });
    const report = buildReport(makeReportInput([{ findings: [finding], coverage: [] }]));
    expect(report.issues[0]?.locations[0]).toEqual({
      path: "old/config.ts",
      line: 8,
      commit: "deadbeef",
    });
    expect(report.issues[0]?.remediation).toMatch(/rotat|revoke/i);
  });

  it("groups overlapping CVE and GHSA aliases without losing dependency evidence", () => {
    const first = dependencyFinding({ id: "cve" });
    const second = dependencyFinding({
      id: "ghsa",
      rootCause: "dependency:lodash:GHSA-test-1234",
      dependency: { ...requiredDependency(), advisoryIds: ["GHSA-test-1234", "CVE-2099-0001"] },
    });
    const report = buildReport(makeReportInput([{ findings: [first, second], coverage: [] }]));
    expect(report.issues).toHaveLength(1);
    expect(report.issues[0]?.findingIds).toEqual(["cve", "ghsa"]);
    expect(report.issues[0]?.evidence).toHaveLength(2);
  });

  it("does not merge dependency findings from different versions or manifests", () => {
    const first = dependencyFinding({ id: "v1" });
    const otherVersion = dependencyFinding({
      id: "v2",
      dependency: { ...requiredDependency(), version: "4.17.20" },
    });
    const otherManifest = dependencyFinding({
      id: "manifest",
      dependency: { ...requiredDependency(), manifest: "packages/app/package.json" },
    });
    const report = buildReport(
      makeReportInput([{ findings: [first, otherVersion, otherManifest], coverage: [] }]),
    );
    expect(report.issues).toHaveLength(3);
  });
});

function requiredDependency(): NonNullable<Finding["dependency"]> {
  return {
    ecosystem: "npm",
    name: "lodash",
    version: "4.17.19",
    manifest: "package-lock.json",
    scope: "runtime",
    advisoryIds: ["CVE-2099-0001"],
    fixedVersions: ["4.17.21"],
  };
}

function dependencyFinding(overrides: Partial<Finding> = {}): Finding {
  return makeFinding({
    id: "dependency-1",
    scanner: "osv",
    ruleId: "GHSA-test-1234",
    category: "dependency",
    title: "Vulnerable lodash version",
    evidence: "lodash 4.17.19 is present in package-lock.json",
    rootCause: "dependency:lodash:CVE-2099-0001",
    remediationKey: "dependency-upgrade",
    dependency: requiredDependency(),
    ...overrides,
  });
}
