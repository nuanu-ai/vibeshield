import { describe, expect, it } from "vitest";
import type { FindingContextAssessment } from "../src/domain/finding-context-assessment.js";
import {
  type HypothesisCandidate,
  validateHypothesisCandidates,
} from "../src/domain/hypothesis-candidate.js";
import type {
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../src/domain/security-graph.js";
import {
  securityGraphEdgeId,
  securityGraphId,
  securityGraphNodeId,
} from "../src/domain/security-graph.js";
import {
  type CorrelationRuleDefinition,
  correlateGraphRules,
} from "../src/stages/correlation-rule-engine.js";

const GRAPH_VERSION = "1";

describe("correlateGraphRules candidates", () => {
  it("creates stable candidates from bounded graph paths and contextual findings", () => {
    const graph = graphFixture();
    const candidates = correlateGraphRules({
      graph,
      findingContexts: [
        findingContext("finding-code", {
          graphNodeIds: [nodeId("Sink:dangerous-operation")],
          graphEdgeIds: [edgeId("calls:handler:dangerous")],
        }),
      ],
      rules: [rule()],
    });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({
      ruleId: "external-input-dangerous-op",
      family: "external_input_to_dangerous_operation",
      title: "External input reaches dangerous operation",
      findingIds: ["finding-code"],
      supportingNodeIds: expect.arrayContaining([
        nodeId("Boundary:POST /submit"),
        nodeId("CodeEntity:handler"),
        nodeId("Sink:dangerous-operation"),
      ]),
      supportingEdgeIds: expect.arrayContaining([
        edgeId("receives:boundary:handler"),
        edgeId("calls:handler:dangerous"),
      ]),
      coverageRefs: ["call_graph:checked", "rule:external-input-dangerous-op"],
      requiredValidation: ["manual_repro"],
    });
    expect(candidates[0]?.id).toMatch(/^hypothesis_candidate_/);
    expect(candidates[0]?.candidateReason).toContain("External input reaches dangerous operation");
  });

  it("records controls and contradictions without suppressing candidate creation", () => {
    const graph = graphFixture({ controls: true });
    const candidates = correlateGraphRules({ graph, rules: [rule()] });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({
      contradictingNodeIds: expect.arrayContaining([
        nodeId("CodeEntity:handler"),
        nodeId("Sink:dangerous-operation"),
        nodeId("Control:auth-check"),
      ]),
      contradictingEdgeIds: expect.arrayContaining([
        edgeId("protected_by:handler:auth"),
        edgeId("contradicted_by:dangerous:auth"),
      ]),
    });
  });

  it("does not link standalone findings or category-only guesses", () => {
    const graph = graphFixture();
    const candidates = correlateGraphRules({
      graph,
      findingContexts: [
        {
          findingId: "finding-standalone",
          status: "standalone",
          graphNodeIds: [],
          graphEdgeIds: [],
          hypothesisIds: [],
          reason: "no graph context",
          coverageState: "checked",
        },
      ],
      rules: [rule()],
    });

    expect(candidates[0]?.findingIds).toEqual([]);
  });
});

describe("correlateGraphRules bounds and validation", () => {
  it("respects max path length and required edge kinds", () => {
    const graph = graphFixture();

    expect(
      correlateGraphRules({
        graph,
        rules: [{ ...rule(), path: { ...rule().path, maxPathLength: 1 } }],
      }),
    ).toHaveLength(0);

    expect(
      correlateGraphRules({
        graph,
        rules: [
          {
            ...rule(),
            path: {
              ...rule().path,
              allowedEdgeKinds: ["receives", "calls", "flows_to"],
              requiredEdgeKinds: ["flows_to"],
            },
          },
        ],
      }),
    ).toHaveLength(0);
  });

  it("rejects malformed rules and invalid candidate graph refs", () => {
    const graph = graphFixture();

    expect(() =>
      correlateGraphRules({
        graph,
        rules: [{ ...rule(), source: {} }],
      }),
    ).toThrow(/source selector must constrain at least one field/);

    expect(() =>
      correlateGraphRules({
        graph,
        rules: [{ ...rule(), source: { propertyEquals: {} } }],
      }),
    ).toThrow(/source propertyEquals must constrain at least one property/);

    expect(() =>
      correlateGraphRules({
        graph,
        rules: [{ ...rule(), path: { ...rule().path, allowedEdgeKinds: [] } }],
      }),
    ).toThrow(/allowedEdgeKinds are required/);

    expect(() =>
      correlateGraphRules({
        graph,
        rules: [
          {
            ...rule(),
            path: { ...rule().path, requiredEdgeKinds: ["flows_to"] },
          },
        ],
      }),
    ).toThrow(/required edge kind is not allowed: flows_to/);

    expect(() =>
      validateHypothesisCandidates([candidateWithMissingNode()], {
        graphNodeIds: graph.nodes.map((node) => node.id),
        graphEdgeIds: graph.edges.map((edge) => edge.id),
      }),
    ).toThrow(/references unknown graph node: missing-node/);

    expect(() =>
      correlateGraphRules({
        graph,
        findingContexts: [
          findingContext("finding-bad", {
            graphNodeIds: ["missing-node"],
            graphEdgeIds: [],
          }),
        ],
        rules: [rule()],
      }),
    ).toThrow(/findingContext finding-bad references unknown graph node: missing-node/);
  });

  it("is deterministic for repeated runs and shuffled graph input", () => {
    const graph = graphFixture({ branch: true });
    const shuffled: SecurityGraph = {
      ...graph,
      nodes: [...graph.nodes].reverse(),
      edges: [...graph.edges].reverse(),
    };

    const first = correlateGraphRules({ graph, rules: [rule()] });
    const second = correlateGraphRules({ graph: shuffled, rules: [rule()] });

    expect(first).toHaveLength(2);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(first.map((candidate) => candidate.id)).toEqual(
      [...first.map((candidate) => candidate.id)].sort(),
    );
  });
});

function graphFixture(
  opts: { readonly controls?: boolean; readonly branch?: boolean } = {},
): SecurityGraph {
  const boundary = node("Boundary", "Boundary:POST /submit", "POST /submit", {
    boundaryType: "http_route",
  });
  const handler = node("CodeEntity", "CodeEntity:handler", "submitHandler", {
    fullName: "submitHandler",
  });
  const dangerous = node("Sink", "Sink:dangerous-operation", "dangerousOperation", {
    sinkType: "command_exec",
  });
  const nodes = [boundary, handler, dangerous];
  const edges = [
    edge("receives", boundary, handler, "receives:boundary:handler"),
    edge("calls", handler, dangerous, "calls:handler:dangerous"),
  ];

  if (opts.controls === true) {
    const control = node("Control", "Control:auth-check", "auth check", {
      controlType: "authorization",
    });
    nodes.push(control);
    edges.push(
      edge("protected_by", handler, control, "protected_by:handler:auth"),
      edge("contradicted_by", dangerous, control, "contradicted_by:dangerous:auth"),
    );
  }

  if (opts.branch === true) {
    const alternate = node("CodeEntity", "CodeEntity:alternate-handler", "alternateHandler", {
      fullName: "alternateHandler",
    });
    nodes.push(alternate);
    edges.push(
      edge("receives", boundary, alternate, "receives:boundary:alternate"),
      edge("calls", alternate, dangerous, "calls:alternate:dangerous"),
    );
  }

  return {
    id: securityGraphId("snapshot-1", GRAPH_VERSION),
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: GRAPH_VERSION,
    nodes,
    edges,
    flows: [],
    coverage: [
      {
        area: "call_graph",
        state: "checked",
        producer: "test-fixture",
        producerVersion: GRAPH_VERSION,
      },
    ],
    createdAt: "2026-06-24T10:00:00Z",
  };
}

function rule(): CorrelationRuleDefinition {
  return {
    id: "external-input-dangerous-op",
    family: "external_input_to_dangerous_operation",
    title: "External input reaches dangerous operation",
    source: { kinds: ["Boundary"] },
    target: { kinds: ["Sink"], propertyEquals: { sinkType: "command_exec" } },
    path: {
      allowedEdgeKinds: ["receives", "calls"],
      requiredEdgeKinds: ["calls"],
      maxPathLength: 2,
    },
    coverageRefs: ["rule:external-input-dangerous-op"],
    requiredValidation: ["manual_repro"],
  };
}

function findingContext(
  findingId: string,
  context: {
    readonly graphNodeIds: ReadonlyArray<string>;
    readonly graphEdgeIds: ReadonlyArray<string>;
  },
): FindingContextAssessment {
  return {
    findingId,
    status: "corroborated",
    graphNodeIds: context.graphNodeIds,
    graphEdgeIds: context.graphEdgeIds,
    hypothesisIds: [],
    reason: "test context",
    coverageState: "checked",
  };
}

function candidateWithMissingNode(): HypothesisCandidate {
  return {
    id: "hypothesis_candidate_missing",
    ruleId: "rule",
    family: "family",
    title: "Candidate with missing node",
    findingIds: [],
    supportingNodeIds: ["missing-node"],
    supportingEdgeIds: [],
    contradictingNodeIds: [],
    contradictingEdgeIds: [],
    coverageRefs: ["call_graph:checked"],
    requiredValidation: ["manual_repro"],
    candidateReason: "test candidate",
  };
}

function node(
  kind: SecurityGraphNode["kind"],
  stableKey: string,
  label: string,
  properties: Readonly<Record<string, unknown>>,
): SecurityGraphNode {
  return {
    id: nodeId(stableKey),
    kind,
    stableKey,
    label,
    repoPath: "src/app.ts",
    lineRange: { startLine: 1, endLine: 1 },
    symbol: label,
    properties,
    evidenceIds: ["ev-graph"],
    producer: "test-fixture",
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState: "checked",
  };
}

function edge(
  kind: SecurityGraphEdge["kind"],
  from: SecurityGraphNode,
  to: SecurityGraphNode,
  stableKey: string,
): SecurityGraphEdge {
  return {
    id: edgeId(stableKey),
    kind,
    stableKey,
    fromNodeId: from.id,
    toNodeId: to.id,
    properties: {},
    evidenceIds: ["ev-graph"],
    producer: "test-fixture",
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState: "checked",
  };
}

function nodeId(stableKey: string): string {
  return securityGraphNodeId(GRAPH_VERSION, stableKey);
}

function edgeId(stableKey: string): string {
  return securityGraphEdgeId(GRAPH_VERSION, stableKey);
}
