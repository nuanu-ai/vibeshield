import { describe, expect, it } from "vitest";
import type { Evidence } from "../src/domain/evidence.js";
import type { Finding, FindingCategory, FindingCluster } from "../src/domain/finding.js";
import type { Manifest } from "../src/domain/manifest.js";
import { composeQuickScanGraph } from "../src/stages/quick-scan-graph-import.js";

describe("composeQuickScanGraph finding import", () => {
  it("imports every finding with immutable ids and file location edges", () => {
    const graph = composeQuickScanGraph(input());
    const findingNodes = graph.nodes.filter(
      (node) => node.kind === "Finding" && node.properties.recordType === "finding",
    );
    const fileNodes = graph.nodes.filter(
      (node) => node.kind === "Resource" && node.properties.resourceType === "file",
    );

    expect(findingNodes.map((node) => node.properties.findingId).sort()).toEqual(
      findings()
        .map((finding) => finding.id)
        .sort(),
    );
    expect(findingNodes.every((node) => node.evidenceIds.length === 1)).toBe(true);
    expect(fileNodes.map((node) => node.repoPath).sort()).toEqual([
      ".github/workflows/ci.yml",
      "infra/main.tf",
      "package.json",
      "src/app.ts",
      "src/config.ts",
      "src/sbom.json",
    ]);
    expect(graph.edges.filter((edge) => edge.kind === "located_in")).toHaveLength(6);
  });
});

describe("composeQuickScanGraph category context", () => {
  it("maps Quick Scan categories to graph subject nodes and affects edges", () => {
    const graph = composeQuickScanGraph(input());

    expect(graph.nodes.map((node) => node.kind)).toEqual(
      expect.arrayContaining(["Secret", "Component", "BuildStep", "InfraResource", "CodeEntity"]),
    );
    expect(graph.nodes.filter((node) => node.kind === "Component")).toHaveLength(2);
    expect(graph.edges.filter((edge) => edge.kind === "affects")).toHaveLength(6);
  });
});

describe("composeQuickScanGraph clusters", () => {
  it("imports clusters without mutating member finding nodes", () => {
    const graph = composeQuickScanGraph(
      input({
        clusters: [
          {
            id: "cluster-secret",
            category: "secret",
            findingIds: ["finding-secret"],
            maxSeverity: "critical",
          },
        ],
      }),
    );

    expect(
      graph.nodes.find((node) => node.properties.recordType === "finding_cluster"),
    ).toMatchObject({
      kind: "Finding",
      properties: {
        clusterId: "cluster-secret",
        findingIds: ["finding-secret"],
      },
    });
    expect(graph.edges.find((edge) => edge.kind === "supported_by")).toMatchObject({
      properties: { clusterId: "cluster-secret", findingId: "finding-secret" },
    });
    expect(
      graph.nodes.find(
        (node) =>
          node.properties.recordType === "finding" &&
          node.properties.findingId === "finding-secret",
      ),
    ).toMatchObject({
      properties: { fingerprint: "fp-secret" },
    });
  });
});

describe("composeQuickScanGraph validation", () => {
  it("rejects missing evidence ids", () => {
    expect(() =>
      composeQuickScanGraph(
        input({
          findings: [{ ...firstFinding(), evidenceIds: ["missing-ev"] }],
        }),
      ),
    ).toThrow(/references missing evidence id: missing-ev/);
  });

  it("rejects outside-snapshot locations", () => {
    expect(() =>
      composeQuickScanGraph(
        input({
          findings: [
            {
              ...firstFinding(),
              locations: [{ filePath: "outside.ts", startLine: 1, endLine: 1 }],
            },
          ],
        }),
      ),
    ).toThrow(/points outside the snapshot: outside\.ts/);
  });

  it("rejects clusters that reference missing findings", () => {
    expect(() =>
      composeQuickScanGraph(
        input({
          clusters: [
            {
              id: "cluster-bad",
              category: "secret",
              findingIds: ["missing-finding"],
              maxSeverity: "critical",
            },
          ],
        }),
      ),
    ).toThrow(/finding cluster cluster-bad references missing finding: missing-finding/);
  });
});

describe("composeQuickScanGraph deterministic", () => {
  it("returns stable ids and ordering for repeated imports", () => {
    const first = composeQuickScanGraph(input());
    const second = composeQuickScanGraph(input());

    expect(first.id).toBe(second.id);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

function input(
  overrides: Partial<{
    readonly evidence: ReadonlyArray<Evidence>;
    readonly findings: ReadonlyArray<Finding>;
    readonly clusters: ReadonlyArray<FindingCluster>;
  }> = {},
) {
  return {
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: "1",
    manifest: manifest(),
    evidence: evidence(),
    findings: findings(),
    clusters: [],
    createdAt: "2026-06-24T10:00:00Z",
    ...overrides,
  };
}

function evidence(): Evidence[] {
  return [
    ev("ev-secret", "src/config.ts", "gitleaks"),
    ev("ev-dependency", "package.json", "trivy"),
    ev("ev-sbom", "src/sbom.json", "trivy"),
    ev("ev-action", ".github/workflows/ci.yml", "zizmor"),
    ev("ev-iac", "infra/main.tf", "trivy"),
    ev("ev-code", "src/app.ts", "semgrep"),
  ];
}

function ev(id: string, filePath: string, tool: string): Evidence {
  return {
    id,
    rawArtifactBlobSha256: `raw-${id}`,
    filePath,
    startLine: 1,
    endLine: 1,
    snippet: `${id} snippet`,
    snippetHash: `hash-${id}`,
    tool,
  };
}

function findings(): Finding[] {
  return [
    finding("finding-secret", "secret", "src/config.ts", "ev-secret", "critical"),
    finding("finding-dependency", "dependency", "package.json", "ev-dependency", "high"),
    finding("finding-sbom", "sbom", "src/sbom.json", "ev-sbom", "medium"),
    finding("finding-action", "github-action", ".github/workflows/ci.yml", "ev-action", "medium"),
    finding("finding-iac", "iac", "infra/main.tf", "ev-iac", "medium"),
    finding("finding-code", "code-pattern", "src/app.ts", "ev-code", "low"),
  ];
}

function firstFinding(): Finding {
  const finding = findings()[0];
  if (finding === undefined) {
    throw new Error("missing test finding");
  }
  return finding;
}

function finding(
  id: string,
  category: FindingCategory,
  filePath: string,
  evidenceId: string,
  severity: Finding["severity"],
): Finding {
  const ruleId = `${category}-rule`;
  return {
    id,
    sourceTool: category === "secret" ? "gitleaks" : "scanner",
    ruleId,
    category,
    severity,
    confidence: "high",
    locations: [{ filePath, startLine: 1, endLine: 1 }],
    evidenceIds: [evidenceId],
    fingerprint: `fp-${id.replace("finding-", "")}`,
    remediationKey: `${category}-remediation`,
  };
}

function manifest(): Manifest {
  return {
    origin: { kind: "local", path: "/repo" },
    commitSha: "abc123",
    sourceHash: "snapshot-1",
    files: [
      { path: "src/config.ts", size: 10, sha256: "config-sha" },
      { path: "package.json", size: 10, sha256: "package-sha" },
      { path: "src/sbom.json", size: 10, sha256: "sbom-sha" },
      { path: ".github/workflows/ci.yml", size: 10, sha256: "ci-sha" },
      { path: "infra/main.tf", size: 10, sha256: "iac-sha" },
      { path: "src/app.ts", size: 10, sha256: "app-sha" },
    ],
    exclusions: [],
    toolchain: { imageTag: "vibeshield-toolchain:test", tools: [] },
    createdAt: "2026-06-24T10:00:00Z",
  };
}
