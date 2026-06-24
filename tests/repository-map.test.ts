import { describe, expect, it } from "vitest";
import type { SecurityGraph, SecurityGraphEdge, SecurityGraphNode } from "../src/domain/index.js";
import { renderRepositoryMap } from "../src/stages/repository-map.js";

describe("renderRepositoryMap", () => {
  it("groups graph facts into a compact owner-facing map while preserving graph ids", () => {
    const map = renderRepositoryMap(graph());

    expect(map.graph).toMatchObject({
      id: "graph-1",
      runId: "run-1",
      snapshotId: "snapshot-1",
      graphVersion: "1",
    });
    expect(map.boundaries.map((node) => node.id)).toEqual(["node-boundary"]);
    expect(map.codeEntities.map((node) => node.id)).toEqual(["node-handler"]);
    expect(map.integrations.map((node) => node.id)).toEqual(["node-service", "node-component"]);
    expect(map.dataStores.map((node) => node.id)).toEqual(["node-db"]);
    expect(map.ciIacResources.map((node) => node.id)).toEqual(["node-infra", "node-build"]);
    expect(map.resources.map((node) => node.id)).toEqual(["node-resource"]);
    expect(map.securityFacts.map((node) => node.id)).toEqual(["node-sink", "node-source"]);
    expect(map.relationships).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "edge-call",
          kind: "calls",
          fromNodeId: "node-boundary",
          fromLabel: "POST /upload",
          toNodeId: "node-handler",
          toLabel: "uploadHandler",
        }),
      ]),
    );
    expect(map.flows).toEqual([
      expect.objectContaining({
        id: "flow-1",
        sourceNodeId: "node-boundary",
        sinkNodeId: "node-sink",
        pathEdgeIds: ["edge-call", "edge-flow"],
      }),
    ]);
  });

  it("returns deterministic JSON regardless of graph input order", () => {
    const ordered = renderRepositoryMap(graph());
    const shuffledGraph = graph({
      nodes: [...graph().nodes].reverse(),
      edges: [...graph().edges].reverse(),
      flows: [...graph().flows].reverse(),
      coverage: [...graph().coverage].reverse(),
    });

    expect(JSON.stringify(renderRepositoryMap(shuffledGraph))).toBe(JSON.stringify(ordered));
  });

  it("surfaces incomplete and missing coverage as fact gaps", () => {
    const map = renderRepositoryMap(graph());

    expect(map.coverage.map((entry) => [entry.area, entry.state])).toEqual([
      ["boundaries", "checked"],
      ["call_graph", "partial"],
      ["language_support", "skipped"],
    ]);
    expect(map.factGaps).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "coverage:call_graph:atom",
          source: "coverage",
          area: "call_graph",
          state: "partial",
          description: "One dynamic call target was not resolved.",
        }),
        expect.objectContaining({
          id: "coverage:data_flow:missing",
          source: "coverage",
          area: "data_flow",
          state: "skipped",
        }),
        expect.objectContaining({
          id: "node:node-source",
          source: "node",
          graphNodeId: "node-source",
          state: "partial",
        }),
        expect.objectContaining({
          id: "edge:edge-flow",
          source: "edge",
          graphEdgeId: "edge-flow",
          state: "degraded",
        }),
        expect.objectContaining({
          id: "flow:flow-1",
          source: "flow",
          graphFlowId: "flow-1",
          state: "partial",
        }),
      ]),
    );
    expect(map.factGaps.map((gap) => gap.id)).not.toContain("node:node-boundary");
  });

  it("normalizes properties with sorted JSON-safe keys", () => {
    const map = renderRepositoryMap(graph());

    expect(map.boundaries[0]?.properties).toEqual({
      boundaryType: "HTTP route",
      details: { a: true, z: "last" },
      method: "POST",
    });
  });
});

function graph(overrides: Partial<SecurityGraph> = {}): SecurityGraph {
  return {
    id: "graph-1",
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: "1",
    createdAt: "2026-06-24T10:00:00.000Z",
    nodes: [
      node("node-boundary", "Boundary", "POST /upload", {
        repoPath: "src/routes/upload.ts",
        symbol: "uploadRoute",
        properties: { method: "POST", boundaryType: "HTTP route", details: { z: "last", a: true } },
      }),
      node("node-handler", "CodeEntity", "uploadHandler", {
        repoPath: "src/routes/upload.ts",
        symbol: "uploadHandler",
      }),
      node("node-source", "Source", "req.query.url", {
        repoPath: "src/routes/upload.ts",
        coverageState: "partial",
      }),
      node("node-sink", "Sink", "fetch", { repoPath: "src/lib/fetch.ts" }),
      node("node-component", "Component", "undici", { properties: { packageName: "undici" } }),
      node("node-service", "ExternalService", "https://api.example.test"),
      node("node-db", "DataStore", "postgres://orders"),
      node("node-build", "BuildStep", "publish artifact"),
      node("node-infra", "InfraResource", "public bucket"),
      node("node-resource", "Resource", "uploaded file"),
    ],
    edges: [
      edge("edge-call", "calls", "node-boundary", "node-handler"),
      edge("edge-flow", "flows_to", "node-handler", "node-sink", { coverageState: "degraded" }),
      edge("edge-uses", "uses", "node-handler", "node-component"),
    ],
    flows: [
      {
        id: "flow-1",
        sourceNodeId: "node-boundary",
        sinkNodeId: "node-sink",
        pathEdgeIds: ["edge-call", "edge-flow"],
        controlNodeIds: [],
        coverageState: "partial",
        confidence: 0.74,
        evidenceIds: ["ev-route", "ev-sink"],
      },
    ],
    coverage: [
      {
        area: "boundaries",
        state: "checked",
        coveredCount: 1,
        totalCount: 1,
        producer: "atom",
        producerVersion: "1",
      },
      {
        area: "call_graph",
        state: "partial",
        coveredCount: 2,
        totalCount: 3,
        reason: "One dynamic call target was not resolved.",
        producer: "atom",
        producerVersion: "1",
      },
      {
        area: "language_support",
        state: "skipped",
        reason: "Ruby files are not supported by Deep Static v1.",
        producer: "vibeshield",
        producerVersion: "deep-static-v1",
      },
    ],
    ...overrides,
  };
}

function node(
  id: string,
  kind: SecurityGraphNode["kind"],
  label: string,
  overrides: Partial<SecurityGraphNode> = {},
): SecurityGraphNode {
  return {
    id,
    kind,
    stableKey: `stable:${id}`,
    label,
    lineRange: { startLine: 1, endLine: 1 },
    properties: {},
    evidenceIds: ["ev-route"],
    producer: "test",
    producerVersion: "1",
    confidence: 0.9,
    coverageState: "checked",
    ...overrides,
  };
}

function edge(
  id: string,
  kind: SecurityGraphEdge["kind"],
  fromNodeId: string,
  toNodeId: string,
  overrides: Partial<SecurityGraphEdge> = {},
): SecurityGraphEdge {
  return {
    id,
    kind,
    stableKey: `stable:${id}`,
    fromNodeId,
    toNodeId,
    properties: {},
    evidenceIds: ["ev-route"],
    producer: "test",
    producerVersion: "1",
    confidence: 0.9,
    coverageState: "checked",
    ...overrides,
  };
}
