import { describe, expect, it } from "vitest";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
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
import { validateStaticHypothesisRecords } from "../src/domain/static-hypothesis.js";
import { validateStaticHypotheses } from "../src/stages/static-hypothesis-validator.js";

const GRAPH_VERSION = "1";

describe("validateStaticHypotheses statuses", () => {
  it("supports checked candidates with path-edge evidence", () => {
    const fixture = graphFixture();
    const result = validateStaticHypotheses({
      graph: fixture.graph,
      candidates: [candidate(fixture)],
    });

    expect(result).toEqual([
      expect.objectContaining({
        candidateId: "candidate-1",
        status: "statically_supported",
        supportingEvidenceIds: ["ev-edge", "ev-sink", "ev-source"],
        contradictingEvidenceIds: [],
        coverageState: "checked",
        runtimeValidationRequired: true,
      }),
    ]);
    expect(result[0]?.staticConfidence).toBeGreaterThan(0.7);
  });

  it("lets contradictions win over support", () => {
    const fixture = graphFixture({ contradiction: true });
    const result = validateStaticHypotheses({
      graph: fixture.graph,
      candidates: [
        candidate(fixture, {
          contradictingNodeIds: [fixture.control?.id ?? ""],
          contradictingEdgeIds: [fixture.contradictionEdge?.id ?? ""],
        }),
      ],
    });

    expect(result[0]).toMatchObject({
      status: "statically_contradicted",
      contradictingEvidenceIds: ["ev-contradiction", "ev-control"],
      runtimeValidationRequired: false,
    });
    expect(result[0]?.staticConfidence).toBeLessThan(0.2);
  });

  it("marks incomplete coverage as inconclusive with conservative wording", () => {
    const fixture = graphFixture();
    const result = validateStaticHypotheses({
      graph: fixture.graph,
      candidates: [candidate(fixture, { coverageRefs: ["call_graph:partial"] })],
    });

    expect(result[0]).toMatchObject({
      status: "inconclusive",
      coverageState: "partial",
      runtimeValidationRequired: true,
    });
    expect(result[0]?.pathSummary).toContain("was not observed on the analyzed path");
    expect(result[0]?.pathSummary).not.toContain("has no allowlist");
  });

  it("keeps node-only evidence as a candidate", () => {
    const fixture = graphFixture();
    const result = validateStaticHypotheses({
      graph: fixture.graph,
      candidates: [candidate(fixture, { supportingEdgeIds: [] })],
    });

    expect(result[0]).toMatchObject({
      status: "candidate",
      coverageState: "checked",
      runtimeValidationRequired: true,
    });
    expect(result[0]?.staticConfidence).toBe(0.5);
  });
});

describe("validateStaticHypotheses validation", () => {
  it("rejects invalid graph references and invalid static records", () => {
    const fixture = graphFixture();

    expect(() =>
      validateStaticHypotheses({
        graph: fixture.graph,
        candidates: [candidate(fixture, { supportingNodeIds: ["missing-node"] })],
      }),
    ).toThrow(/references unknown graph node: missing-node/);

    expect(() =>
      validateStaticHypothesisRecords([
        {
          id: "static_bad",
          candidateId: "candidate-1",
          status: "statically_supported",
          staticConfidence: 1.5,
          title: "bad",
          pathSummary: "bad",
          supportingEvidenceIds: ["ev"],
          contradictingEvidenceIds: [],
          coverageState: "checked",
          runtimeValidationRequired: true,
        },
      ]),
    ).toThrow(/staticConfidence must be between 0 and 1/);
  });

  it("is deterministic for repeated validation", () => {
    const fixture = graphFixture();
    const first = validateStaticHypotheses({
      graph: fixture.graph,
      candidates: [
        candidate(fixture, { id: "candidate-b", title: "B" }),
        candidate(fixture, { id: "candidate-a", title: "A" }),
      ],
    });
    const second = validateStaticHypotheses({
      graph: fixture.graph,
      candidates: [
        candidate(fixture, { id: "candidate-b", title: "B" }),
        candidate(fixture, { id: "candidate-a", title: "A" }),
      ],
    });

    expect(first.map((record) => record.candidateId)).toEqual(["candidate-a", "candidate-b"]);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

interface GraphFixture {
  readonly graph: SecurityGraph;
  readonly source: SecurityGraphNode;
  readonly sink: SecurityGraphNode;
  readonly edge: SecurityGraphEdge;
  readonly control?: SecurityGraphNode;
  readonly contradictionEdge?: SecurityGraphEdge;
}

function graphFixture(opts: { readonly contradiction?: boolean } = {}): GraphFixture {
  const source = node("Boundary", "Boundary:POST /pay", "POST /pay", "ev-source");
  const sink = node("Sink", "Sink:charge", "chargeCard", "ev-sink");
  const edge = graphEdge("calls", source, sink, "calls:pay:charge", "ev-edge");
  const nodes = [source, sink];
  const edges = [edge];
  let control: SecurityGraphNode | undefined;
  let contradictionEdge: SecurityGraphEdge | undefined;

  if (opts.contradiction === true) {
    control = node("Control", "Control:allowlist", "destination allowlist", "ev-control");
    contradictionEdge = graphEdge(
      "contradicted_by",
      sink,
      control,
      "contradicted_by:charge:allowlist",
      "ev-contradiction",
    );
    nodes.push(control);
    edges.push(contradictionEdge);
  }

  return {
    graph: {
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
    },
    source,
    sink,
    edge,
    ...(control === undefined ? {} : { control }),
    ...(contradictionEdge === undefined ? {} : { contradictionEdge }),
  };
}

function candidate(
  fixture: GraphFixture,
  overrides: Partial<HypothesisCandidate> = {},
): HypothesisCandidate {
  return {
    id: "candidate-1",
    ruleId: "rule",
    family: "family",
    title: "External input reaches charge operation",
    findingIds: ["finding-1"],
    supportingNodeIds: [fixture.source.id, fixture.sink.id],
    supportingEdgeIds: [fixture.edge.id],
    contradictingNodeIds: [],
    contradictingEdgeIds: [],
    coverageRefs: ["call_graph:checked"],
    requiredValidation: ["manual_repro"],
    candidateReason: "test candidate",
    ...overrides,
  };
}

function node(
  kind: SecurityGraphNode["kind"],
  stableKey: string,
  label: string,
  evidenceId: string,
): SecurityGraphNode {
  return {
    id: securityGraphNodeId(GRAPH_VERSION, stableKey),
    kind,
    stableKey,
    label,
    repoPath: "src/app.ts",
    lineRange: { startLine: 1, endLine: 1 },
    symbol: label,
    properties: {},
    evidenceIds: [evidenceId],
    producer: "test-fixture",
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState: "checked",
  };
}

function graphEdge(
  kind: SecurityGraphEdge["kind"],
  from: SecurityGraphNode,
  to: SecurityGraphNode,
  stableKey: string,
  evidenceId: string,
): SecurityGraphEdge {
  return {
    id: securityGraphEdgeId(GRAPH_VERSION, stableKey),
    kind,
    stableKey,
    fromNodeId: from.id,
    toNodeId: to.id,
    properties: {},
    evidenceIds: [evidenceId],
    producer: "test-fixture",
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState: "checked",
  };
}
