import { describe, expect, it } from "vitest";
import {
  type GraphCoverageState,
  type SecurityGraph,
  securityFlowId,
  securityGraphEdgeId,
  securityGraphId,
  securityGraphNodeId,
  sortSecurityGraph,
  validateSecurityGraph,
} from "../src/domain/index.js";

describe("SecurityGraph", () => {
  it("accepts a minimal valid graph and sorts records deterministically", () => {
    const graph = makeGraph({
      nodes: [sinkNode(), boundaryNode()],
      edges: [callEdge()],
      flows: [flow()],
    });

    const validated = validateSecurityGraph(graph, validationContext());
    const expectedNodeIds = [boundaryNode().id, sinkNode().id].sort();

    expect(validated.nodes.map((node) => node.id)).toEqual(expectedNodeIds);
    expect(validated.edges.map((edge) => edge.id)).toEqual([callEdge().id]);
    expect(validated.flows.map((item) => item.id)).toEqual([flow().id]);
  });

  it("rejects a graph that references missing evidence", () => {
    const graph = makeGraph({
      nodes: [{ ...boundaryNode(), evidenceIds: ["ev-missing"] }],
    });

    expect(() => validateSecurityGraph(graph, validationContext())).toThrow(
      /missing evidence id: ev-missing/,
    );
  });

  it("rejects a graph path outside the snapshot", () => {
    const graph = makeGraph({
      nodes: [{ ...boundaryNode(), repoPath: "src/missing.ts" }],
    });

    expect(() => validateSecurityGraph(graph, validationContext())).toThrow(
      /outside the snapshot: src\/missing\.ts/,
    );
  });

  it("rejects duplicate stable node IDs", () => {
    const duplicate = {
      ...sinkNode(),
      id: securityGraphNodeId("1", "node:duplicate-id"),
      stableKey: boundaryNode().stableKey,
    };
    const graph = makeGraph({ nodes: [boundaryNode(), duplicate] });

    expect(() => validateSecurityGraph(graph, validationContext())).toThrow(
      /duplicate node stableKey/,
    );
  });

  it("rejects dangling edges", () => {
    const graph = makeGraph({
      edges: [{ ...callEdge(), fromNodeId: "node_missing" }],
      flows: [],
    });

    expect(() => validateSecurityGraph(graph, validationContext())).toThrow(
      /dangling fromNodeId: node_missing/,
    );
  });

  it("rejects invalid coverage states", () => {
    const graph = makeGraph({
      coverage: [
        {
          ...coverage(),
          state: "unknown" as GraphCoverageState,
        },
      ],
    });

    expect(() => validateSecurityGraph(graph, validationContext())).toThrow(
      /coverage boundaries state is invalid: unknown/,
    );
  });

  it("builds stable graph IDs and ordering for the same fixture", () => {
    const first = sortSecurityGraph(makeGraph());
    const second = sortSecurityGraph(makeGraph());

    expect(first.id).toBe(securityGraphId("snapshot-1", "1"));
    expect(first.nodes.map((node) => node.id)).toEqual(second.nodes.map((node) => node.id));
    expect(first.edges.map((edge) => edge.id)).toEqual(second.edges.map((edge) => edge.id));
    expect(first.flows.map((item) => item.id)).toEqual(second.flows.map((item) => item.id));
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

function validationContext() {
  return {
    manifestPaths: new Set(["src/routes/upload.ts", "src/lib/fetch.ts"]),
    evidenceIds: new Set(["ev-route", "ev-sink"]),
  };
}

function makeGraph(overrides: Partial<SecurityGraph> = {}): SecurityGraph {
  return {
    id: securityGraphId("snapshot-1", "1"),
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: "1",
    nodes: [boundaryNode(), sinkNode()],
    edges: [callEdge()],
    flows: [flow()],
    coverage: [coverage()],
    createdAt: "2026-06-24T09:00:00Z",
    ...overrides,
  };
}

function boundaryNode() {
  const stableKey = "Boundary:http:POST /upload:src/routes/upload.ts:10:uploadHandler";
  return {
    id: securityGraphNodeId("1", stableKey),
    kind: "Boundary" as const,
    stableKey,
    label: "POST /upload",
    repoPath: "src/routes/upload.ts",
    lineRange: { startLine: 10, endLine: 12 },
    symbol: "uploadHandler",
    properties: { boundaryType: "HTTP route", method: "POST" },
    evidenceIds: ["ev-route"],
    producer: "test-fixture",
    producerVersion: "1",
    confidence: 1,
    coverageState: "checked" as const,
  };
}

function sinkNode() {
  const stableKey = "Sink:http-client:src/lib/fetch.ts:4:fetchUrl";
  return {
    id: securityGraphNodeId("1", stableKey),
    kind: "Sink" as const,
    stableKey,
    label: "fetchUrl",
    repoPath: "src/lib/fetch.ts",
    lineRange: { startLine: 4, endLine: 4 },
    symbol: "fetchUrl",
    properties: { sinkType: "outbound_http" },
    evidenceIds: ["ev-sink"],
    producer: "test-fixture",
    producerVersion: "1",
    confidence: 0.95,
    coverageState: "checked" as const,
  };
}

function callEdge() {
  const stableKey = `calls:${boundaryNode().id}:${sinkNode().id}:src/routes/upload.ts:12`;
  return {
    id: securityGraphEdgeId("1", stableKey),
    kind: "calls" as const,
    stableKey,
    fromNodeId: boundaryNode().id,
    toNodeId: sinkNode().id,
    properties: { callsite: "src/routes/upload.ts:12" },
    evidenceIds: ["ev-route"],
    producer: "test-fixture",
    producerVersion: "1",
    confidence: 0.9,
    coverageState: "checked" as const,
  };
}

function flow() {
  const stableKey = `flow:${boundaryNode().id}:${sinkNode().id}:${callEdge().id}`;
  return {
    id: securityFlowId("1", stableKey),
    sourceNodeId: boundaryNode().id,
    sinkNodeId: sinkNode().id,
    pathEdgeIds: [callEdge().id],
    controlNodeIds: [],
    coverageState: "checked" as const,
    confidence: 0.9,
    evidenceIds: ["ev-route", "ev-sink"],
  };
}

function coverage() {
  return {
    area: "boundaries" as const,
    state: "checked" as const,
    coveredCount: 1,
    totalCount: 1,
    producer: "test-fixture",
    producerVersion: "1",
  };
}
