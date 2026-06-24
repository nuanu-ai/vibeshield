import { describe, expect, it } from "vitest";
import type { Manifest } from "../src/domain/manifest.js";
import type { SecurityGraph, SecurityGraphNode } from "../src/domain/security-graph.js";
import { securityGraphId, securityGraphNodeId } from "../src/domain/security-graph.js";
import { composeCiIacContext } from "../src/stages/ci-iac-context.js";

describe("composeCiIacContext workflow projection", () => {
  it("projects workflow trigger step token and artifact context", () => {
    const graph = composeCiIacContext({
      graph: baseGraph(),
      manifest: manifest(),
      workflows: [workflow()],
    });

    expect(
      graph.nodes
        .filter((node) => node.kind === "BuildStep")
        .map((node) => node.properties.recordType),
    ).toEqual(expect.arrayContaining(["workflow", "workflow_trigger", "workflow_step"]));
    expect(
      graph.nodes.find((node) => node.properties.recordType === "workflow_step"),
    ).toMatchObject({
      properties: { uses: "actions/upload-artifact@v3", pinned: false },
    });
    expect(
      graph.nodes.find((node) => node.properties.resourceType === "token_permission"),
    ).toMatchObject({
      properties: { scope: "contents", access: "write" },
    });
    expect(graph.nodes.find((node) => node.properties.resourceType === "artifact")).toMatchObject({
      properties: { name: "dist" },
    });
    expect(graph.edges.map((edge) => edge.kind)).toEqual(
      expect.arrayContaining(["contains", "depends_on", "writes", "supported_by"]),
    );
  });

  it("forms a traversable workflow to token and artifact publication path", () => {
    const graph = composeCiIacContext({
      graph: baseGraph(),
      manifest: manifest(),
      workflows: [workflow()],
    });
    const step = graph.nodes.find((node) => node.properties.recordType === "workflow_step");
    const token = graph.nodes.find((node) => node.properties.resourceType === "token_permission");
    const artifact = graph.nodes.find((node) => node.properties.resourceType === "artifact");

    expect(graph.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "depends_on", fromNodeId: step?.id, toNodeId: token?.id }),
        expect.objectContaining({ kind: "writes", fromNodeId: step?.id, toNodeId: artifact?.id }),
      ]),
    );
  });
});

describe("composeCiIacContext IaC projection", () => {
  it("projects public resources and finding support", () => {
    const graph = composeCiIacContext({
      graph: baseGraph(),
      manifest: manifest(),
      iacResources: [
        {
          repoPath: "infra/main.tf",
          resourceType: "aws_security_group",
          name: "public_web",
          public: true,
          findingIds: ["finding-iac"],
          evidenceIds: ["ev-iac"],
          lineRange: { startLine: 3, endLine: 8 },
        },
      ],
    });

    expect(graph.nodes.find((node) => node.kind === "InfraResource")).toMatchObject({
      repoPath: "infra/main.tf",
      properties: { resourceType: "aws_security_group", public: true },
    });
    expect(graph.nodes.find((node) => node.kind === "ExternalService")).toMatchObject({
      label: "public internet",
    });
    expect(graph.edges.map((edge) => edge.kind)).toEqual(
      expect.arrayContaining(["exposes", "supported_by"]),
    );
  });
});

describe("composeCiIacContext validation", () => {
  it("rejects missing evidence and outside-snapshot paths", () => {
    expect(() =>
      composeCiIacContext({
        graph: baseGraph(),
        manifest: manifest(),
        workflows: [{ ...workflow(), evidenceIds: [] }],
      }),
    ).toThrow(/workflow \.github\/workflows\/ci.yml has no evidence/);

    expect(() =>
      composeCiIacContext({
        graph: baseGraph(),
        manifest: manifest(),
        iacResources: [
          {
            repoPath: "outside.tf",
            resourceType: "aws_s3_bucket",
            name: "public_bucket",
            public: true,
            evidenceIds: ["ev-iac"],
          },
        ],
      }),
    ).toThrow(/points outside the snapshot: outside\.tf/);
  });

  it("rejects support links to missing findings", () => {
    expect(() =>
      composeCiIacContext({
        graph: baseGraph(),
        manifest: manifest(),
        workflows: [{ ...workflow(), findingIds: ["missing-finding"] }],
      }),
    ).toThrow(/CI\/IaC context references missing finding: missing-finding/);
  });

  it("rejects token or artifact links to missing workflow steps", () => {
    expect(() =>
      composeCiIacContext({
        graph: baseGraph(),
        manifest: manifest(),
        workflows: [
          {
            ...workflow(),
            tokenPermissions: [
              { stepId: "missing", scope: "contents", access: "write", evidenceIds: ["ev-token"] },
            ],
          },
        ],
      }),
    ).toThrow(/workflow token contents references missing workflow step: missing/);

    expect(() =>
      composeCiIacContext({
        graph: baseGraph(),
        manifest: manifest(),
        workflows: [
          {
            ...workflow(),
            artifacts: [{ stepId: "missing", name: "dist", evidenceIds: ["ev-artifact"] }],
          },
        ],
      }),
    ).toThrow(/workflow artifact dist references missing workflow step: missing/);
  });

  it("is deterministic for repeated projection", () => {
    const first = composeCiIacContext({
      graph: baseGraph(),
      manifest: manifest(),
      workflows: [workflow()],
    });
    const second = composeCiIacContext({
      graph: baseGraph(),
      manifest: manifest(),
      workflows: [workflow()],
    });

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

function workflow() {
  return {
    workflowPath: ".github/workflows/ci.yml",
    name: "ci",
    evidenceIds: ["ev-workflow"],
    lineRange: { startLine: 1, endLine: 40 },
    findingIds: ["finding-action"],
    triggers: [{ event: "pull_request", evidenceIds: ["ev-trigger"] }],
    steps: [
      {
        id: "publish",
        name: "Upload artifact",
        uses: "actions/upload-artifact@v3",
        pinned: false,
        evidenceIds: ["ev-step"],
        findingIds: ["finding-action"],
      },
    ],
    tokenPermissions: [
      { stepId: "publish", scope: "contents", access: "write" as const, evidenceIds: ["ev-token"] },
    ],
    artifacts: [{ stepId: "publish", name: "dist", evidenceIds: ["ev-artifact"] }],
  };
}

function baseGraph(): SecurityGraph {
  return {
    id: securityGraphId("snapshot-1", "1"),
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: "1",
    nodes: [
      findingNode("finding-action", ".github/workflows/ci.yml", "ev-action"),
      findingNode("finding-iac", "infra/main.tf", "ev-iac"),
    ],
    edges: [],
    flows: [],
    coverage: [],
    createdAt: "2026-06-24T10:00:00Z",
  };
}

function findingNode(id: string, repoPath: string, evidenceId: string): SecurityGraphNode {
  const stableKey = `Finding:${id}`;
  return {
    id: securityGraphNodeId("1", stableKey),
    kind: "Finding",
    stableKey,
    label: id,
    repoPath,
    lineRange: { startLine: 1, endLine: 1 },
    symbol: id,
    properties: { recordType: "finding", findingId: id },
    evidenceIds: [evidenceId],
    producer: "test-fixture",
    producerVersion: "1",
    confidence: 1,
    coverageState: "checked",
  };
}

function manifest(): Manifest {
  return {
    origin: { kind: "local", path: "/repo" },
    commitSha: "abc123",
    sourceHash: "snapshot-1",
    files: [
      { path: ".github/workflows/ci.yml", size: 10, sha256: "ci-sha" },
      { path: "infra/main.tf", size: 10, sha256: "iac-sha" },
    ],
    exclusions: [],
    toolchain: { imageTag: "vibeshield-toolchain:test", tools: [] },
    createdAt: "2026-06-24T10:00:00Z",
  };
}
