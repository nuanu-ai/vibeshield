import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { Evidence } from "../src/domain/evidence.js";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
import type {
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../src/domain/security-graph.js";
import {
  securityFlowId,
  securityGraphEdgeId,
  securityGraphId,
  securityGraphNodeId,
} from "../src/domain/security-graph.js";
import { validateStaticHypothesisRecords } from "../src/domain/static-hypothesis.js";
import { validateStaticHypotheses } from "../src/stages/static-hypothesis-validator.js";

const GRAPH_VERSION = "1";
const REPO_PATH = "src/app.ts";

describe("validateStaticHypotheses promotion contract", () => {
  it("promotes only a typed external source-to-sink flow with current evidence", () => {
    const fixture = graphFixture();
    const result = validate(fixture);

    expect(result).toEqual([
      expect.objectContaining({
        candidateId: "candidate-1",
        status: "statically_supported",
        supportingEvidenceIds: ["ev-edge", "ev-sink", "ev-source"],
        contradictingEvidenceIds: [],
        coverageState: "checked",
        runtimeValidationRequired: true,
        promotion: expect.objectContaining({
          publishable: true,
          source: "external_input",
          sink: "typed_security_sink",
          path: "connected_security_flow",
          control: "absent",
          evidence: "current_line_pinned",
        }),
      }),
    ]);
    expect(result[0]?.promotion.rootCauseKey).toBeTruthy();
  });

  it("contradicts only when a current sink-matched control dominates the exact sink", () => {
    const fixture = graphFixture({ control: "effective" });
    const result = validate(fixture);

    expect(result[0]).toMatchObject({
      status: "statically_contradicted",
      contradictingEvidenceIds: ["ev-control", "ev-control-edge"],
      runtimeValidationRequired: false,
      promotion: { publishable: false, control: "effective" },
    });
  });

  it("ignores a typed control for a different sink class", () => {
    const fixture = graphFixture({ control: "irrelevant" });
    const result = validate(fixture);

    expect(result[0]).toMatchObject({
      status: "statically_supported",
      promotion: { publishable: true, control: "irrelevant" },
    });
  });

  it.each([
    ["structural reachability", { structuralOnly: true }, "structural_only"],
    ["stale endpoint evidence", { staleEvidence: true }, "connected_security_flow"],
    ["partial data-flow coverage", { partial: true }, "connected_security_flow"],
    ["missing control-flow coverage", { omitControlCoverage: true }, "connected_security_flow"],
  ] as const)("keeps %s as an inconclusive raw trace", (_label, options, expectedPath) => {
    const fixture = graphFixture(options);
    const result = validate(fixture);

    expect(result[0]).toMatchObject({
      status: "inconclusive",
      runtimeValidationRequired: true,
      promotion: { publishable: false, path: expectedPath },
    });
  });
});

describe("validateStaticHypotheses record validation", () => {
  it("rejects invalid graph references and inconsistent publication records", () => {
    const fixture = graphFixture();
    expect(() =>
      validateStaticHypotheses({
        ...inputFor(fixture),
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
          promotion: {
            publishable: true,
            source: "external_input",
            sink: "typed_security_sink",
            path: "connected_security_flow",
            control: "absent",
            evidence: "current_line_pinned",
            rootCauseKey: "root",
            reasons: ["external_source_observed"],
          },
        },
      ]),
    ).toThrow(/staticConfidence must be between 0 and 1/);
  });

  it("is byte-for-byte deterministic for repeated validation", () => {
    const fixture = graphFixture();
    const candidates = [
      candidate(fixture, { id: "candidate-b", title: "B" }),
      candidate(fixture, { id: "candidate-a", title: "A" }),
    ];
    const first = validateStaticHypotheses({ ...inputFor(fixture), candidates });
    const second = validateStaticHypotheses({ ...inputFor(fixture), candidates });

    expect(first.map((record) => record.candidateId)).toEqual(["candidate-a", "candidate-b"]);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

interface GraphFixture {
  readonly graph: SecurityGraph;
  readonly evidence: ReadonlyArray<Evidence>;
  readonly source: SecurityGraphNode;
  readonly sink: SecurityGraphNode;
  readonly edge: SecurityGraphEdge;
}

function graphFixture(
  options: {
    readonly control?: "effective" | "irrelevant";
    readonly omitControlCoverage?: boolean;
    readonly partial?: boolean;
    readonly staleEvidence?: boolean;
    readonly structuralOnly?: boolean;
  } = {},
): GraphFixture {
  const coverageState = options.partial === true ? "partial" : "checked";
  const source = node("Source", "Source:request", "request input", "ev-source", {
    sourceType: "external_input",
  });
  const sink = node("Sink", "Sink:exec", "exec", "ev-sink", {
    sinkType: "code_execution",
  });
  const edge = graphEdge(
    options.structuralOnly === true ? "calls" : "flows_to",
    source,
    sink,
    "path:request:exec",
    "ev-edge",
    {},
    coverageState,
  );
  const nodes: SecurityGraphNode[] = [source, sink];
  const edges: SecurityGraphEdge[] = [edge];
  let control: SecurityGraphNode | undefined;
  if (options.control !== undefined) {
    control = node("Control", "Control:allowlist", "allowlist", "ev-control", {
      controlEffect: "blocks_untrusted",
      protectsSinkType: options.control === "effective" ? "code_execution" : "server_side_request",
    });
    nodes.push(control);
    edges.push(
      graphEdge("protected_by", sink, control, "protected_by:exec:allowlist", "ev-control-edge", {
        relation: "dominates_sink",
      }),
    );
  }
  const graph: SecurityGraph = {
    id: securityGraphId("snapshot-1", GRAPH_VERSION),
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: GRAPH_VERSION,
    nodes,
    edges,
    flows:
      options.structuralOnly === true
        ? []
        : [
            {
              id: securityFlowId(GRAPH_VERSION, "request-to-exec"),
              sourceNodeId: source.id,
              sinkNodeId: sink.id,
              pathEdgeIds: [edge.id],
              controlNodeIds: control === undefined ? [] : [control.id],
              coverageState,
              confidence: 1,
              evidenceIds: ["ev-source", "ev-edge", "ev-sink"],
            },
          ],
    coverage: [
      {
        area: "data_flow",
        state: coverageState,
        producer: "test-fixture",
        producerVersion: GRAPH_VERSION,
      },
      ...(options.omitControlCoverage === true
        ? []
        : [
            {
              area: "control_flow" as const,
              state: "checked" as const,
              producer: "test-fixture",
              producerVersion: GRAPH_VERSION,
            },
          ]),
    ],
    createdAt: "2026-06-24T10:00:00Z",
  };
  const evidenceIds = uniqueSorted([
    ...nodes.flatMap((record) => record.evidenceIds),
    ...edges.flatMap((record) => record.evidenceIds),
  ]);
  const evidence = evidenceIds.map((id) =>
    evidenceRecord(id, options.staleEvidence === true && id === "ev-source" ? 2 : 1),
  );
  return { graph, evidence, source, sink, edge };
}

function validate(fixture: GraphFixture) {
  return validateStaticHypotheses({
    ...inputFor(fixture),
    candidates: [candidate(fixture)],
  });
}

function inputFor(fixture: GraphFixture) {
  return { graph: fixture.graph, evidence: fixture.evidence, manifestPaths: [REPO_PATH] };
}

function candidate(
  fixture: GraphFixture,
  overrides: Partial<HypothesisCandidate> = {},
): HypothesisCandidate {
  return {
    id: "candidate-1",
    ruleId: "rule",
    family: "external_input_to_dangerous_operation",
    title: "External input reaches exec",
    findingIds: [],
    supportingNodeIds: [fixture.source.id, fixture.sink.id],
    supportingEdgeIds: [fixture.edge.id],
    contradictingNodeIds: [],
    contradictingEdgeIds: [],
    coverageRefs: [
      `data_flow:${fixture.edge.coverageState}`,
      `language_support:${fixture.edge.coverageState}`,
    ],
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
  properties: Readonly<Record<string, unknown>>,
): SecurityGraphNode {
  return {
    id: securityGraphNodeId(GRAPH_VERSION, stableKey),
    kind,
    stableKey,
    label,
    repoPath: REPO_PATH,
    lineRange: { startLine: 1, endLine: 1 },
    symbol: label,
    properties,
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
  properties: Readonly<Record<string, unknown>> = {},
  coverageState: SecurityGraphEdge["coverageState"] = "checked",
): SecurityGraphEdge {
  return {
    id: securityGraphEdgeId(GRAPH_VERSION, stableKey),
    kind,
    stableKey,
    fromNodeId: from.id,
    toNodeId: to.id,
    properties,
    evidenceIds: [evidenceId],
    producer: "test-fixture",
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState,
  };
}

function evidenceRecord(id: string, line: number): Evidence {
  const snippet = `${id} evidence`;
  return {
    id,
    rawArtifactBlobSha256: sha256(`raw:${id}`),
    filePath: REPO_PATH,
    startLine: line,
    endLine: line,
    snippet,
    snippetHash: sha256(snippet),
    tool: "test-fixture",
  };
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}
