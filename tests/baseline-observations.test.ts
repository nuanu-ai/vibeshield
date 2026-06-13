import { describe, expect, it } from "vitest";
import { normalizeBaselineObservations } from "../src/baseline/observations.js";

describe("deterministic baseline observation normalization", () => {
  it("turns Trivy vulnerabilities into dependency findings", () => {
    const observations = normalizeBaselineObservations({
      status: "completed",
      stdout: JSON.stringify({
        Results: [
          {
            Target: "pkg:npm/express@4.18.2",
            Vulnerabilities: [
              {
                FixedVersion: "4.18.3",
                InstalledVersion: "4.18.2",
                PkgName: "express",
                Severity: "HIGH",
                Title: "Fixture vulnerable dependency",
                VulnerabilityID: "CVE-2099-0001",
              },
            ],
          },
        ],
      }),
      tool: "trivy",
    });

    expect(observations).toEqual([
      {
        confidence: "high",
        evidence: ["pkg:npm/express@4.18.2"],
        kind: "dependency",
        message: "CVE-2099-0001 in express@4.18.2 fixed in 4.18.3: Fixture vulnerable dependency",
        severity: "high",
      },
    ]);
  });

  it("turns Checkov failed checks into IaC findings with file evidence", () => {
    const observations = normalizeBaselineObservations({
      status: "completed",
      stdout: JSON.stringify({
        results: {
          failed_checks: [
            {
              check_id: "CKV_DOCKER_3",
              check_name: "Ensure that a user for the container has been created",
              file_line_range: [1, 10],
              file_path: "/Dockerfile",
            },
          ],
        },
      }),
      tool: "checkov",
    });

    expect(observations).toEqual([
      {
        confidence: "high",
        evidence: ["Dockerfile:1-10"],
        kind: "iac",
        message: "CKV_DOCKER_3: Ensure that a user for the container has been created",
        severity: "unknown",
      },
    ]);
  });

  it("turns Gitleaks JSON reports into redacted secret findings", () => {
    const observations = normalizeBaselineObservations({
      status: "completed",
      stdout: JSON.stringify([
        {
          Description: "Generic API Key",
          EndLine: 12,
          File: "src/config.ts",
          RuleID: "generic-api-key",
          StartLine: 12,
        },
      ]),
      tool: "gitleaks",
    });

    expect(observations).toEqual([
      {
        confidence: "high",
        evidence: ["src/config.ts:12"],
        kind: "secret",
        message: "generic-api-key: Generic API Key",
        severity: "high",
      },
    ]);
  });

  it("turns Zizmor alerts into workflow findings with concrete evidence", () => {
    const observations = normalizeBaselineObservations({
      status: "completed",
      stdout: JSON.stringify([
        {
          desc: "template expansion in shell",
          determinations: {
            confidence: "High",
            severity: "High",
          },
          ident: "template-injection",
          locations: [
            {
              concrete: {
                location: {
                  end_point: { column: 20, row: 18 },
                  start_point: { column: 6, row: 16 },
                },
              },
              symbolic: {
                key: {
                  Local: {
                    given_path: "repo/.github/workflows/release.yml",
                    prefix: "repo/.github/workflows",
                  },
                },
              },
            },
          ],
        },
      ]),
      tool: "zizmor",
    });

    expect(observations).toEqual([
      {
        confidence: "high",
        evidence: [".github/workflows/release.yml:16-18"],
        kind: "workflow",
        message: "template-injection: template expansion in shell",
        severity: "high",
      },
    ]);
  });

  it("does not report findings for failed scanner execution", () => {
    const observations = normalizeBaselineObservations({
      status: "failed",
      stderr: "fatal: invalid sbom",
      stdout: "{}",
      tool: "trivy",
    });

    expect(observations).toEqual([]);
  });
});
