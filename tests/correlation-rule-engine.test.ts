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

  it("labels external-input hypotheses by sink taxonomy instead of one generic title", () => {
    const graph = graphFixture({ sinkType: "sql_execution" });
    const candidates = correlateGraphRules({
      graph,
      rules: [
        {
          ...rule(),
          target: { kinds: ["Sink"], propertyEquals: { sinkType: "sql_execution" } },
        },
      ],
    });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({
      title: "SQL injection path: external input reaches SQL execution",
      candidateReason:
        "SQL injection path: external input reaches SQL execution: POST /submit reaches dangerousOperation across 2 graph edges",
    });
  });

  it("labels access-control routes to SQL-backed data access without relabeling generic SQL", () => {
    const sqlRule = {
      ...rule(),
      target: { kinds: ["Sink"], propertyEquals: { sinkType: "sql_execution" } },
    } satisfies CorrelationRuleDefinition;

    expect(
      correlateGraphRules({
        graph: graphFixture({
          boundaryLabel: "access-control/users",
          sinkType: "sql_execution",
        }),
        rules: [sqlRule],
      })[0],
    ).toMatchObject({
      title:
        "Access control path: public route reaches SQL-backed data access without observed authorization",
      candidateReason:
        "Access control path: public route reaches SQL-backed data access without observed authorization: access-control/users reaches dangerousOperation across 2 graph edges",
    });

    expect(
      correlateGraphRules({
        graph: graphFixture({
          boundaryLabel: "GET /search",
          sinkType: "sql_execution",
        }),
        rules: [sqlRule],
      })[0],
    ).toMatchObject({
      title: "SQL injection path: external input reaches SQL execution",
    });

    expect(
      correlateGraphRules({
        graph: graphFixture({
          boundaryLabel: "access-control/users-admin-fix",
          sinkType: "sql_execution",
        }),
        rules: [sqlRule],
      })[0],
    ).toMatchObject({
      title: "SQL injection path: external input reaches SQL execution",
    });
  });

  it("labels server-side HTTP client paths as SSRF candidates", () => {
    const graph = graphFixture({ sinkType: "server_side_request" });
    const candidates = correlateGraphRules({
      graph,
      rules: [
        {
          ...rule(),
          target: { kinds: ["Sink"], propertyEquals: { sinkType: "server_side_request" } },
        },
      ],
    });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({
      title: "Server-side request forgery path: external input reaches a server-side HTTP client",
      candidateReason:
        "Server-side request forgery path: external input reaches a server-side HTTP client: POST /submit reaches dangerousOperation across 2 graph edges",
    });
  });

  it("labels external-input paths for NoSQL, upload validation, and SSTI taxonomy", () => {
    for (const { sinkType, title } of [
      {
        sinkType: "no_sql_execution",
        title: "NoSQL injection path: external input reaches NoSQL query execution",
      },
      {
        sinkType: "file_upload_validation",
        title: "File upload validation path: external input reaches upload validation logic",
      },
      {
        sinkType: "template_render",
        title: "Server-side template injection path: external input reaches template rendering",
      },
    ]) {
      const candidates = correlateGraphRules({
        graph: graphFixture({ sinkType }),
        rules: [
          {
            ...rule(),
            target: { kinds: ["Sink"], propertyEquals: { sinkType } },
          },
        ],
      });

      expect(candidates).toHaveLength(1);
      expect(candidates[0]?.title).toBe(title);
    }
  });

  it("labels HTML and script output paths as XSS candidates", () => {
    const graph = graphFixture({ sinkType: "cross_site_scripting" });
    const candidates = correlateGraphRules({
      graph,
      rules: [
        {
          ...rule(),
          target: { kinds: ["Sink"], propertyEquals: { sinkType: "cross_site_scripting" } },
        },
      ],
    });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({
      title: "Cross-site scripting path: external input reaches HTML or script output",
      candidateReason:
        "Cross-site scripting path: external input reaches HTML or script output: POST /submit reaches dangerousOperation across 2 graph edges",
    });
  });

  it("labels access-control and CSRF sink paths by security semantics", () => {
    const accessRule = {
      ...rule(),
      target: { kinds: ["Sink"], propertyEquals: { sinkType: "access_control" } },
    } satisfies CorrelationRuleDefinition;
    const csrfRule = {
      ...rule(),
      target: { kinds: ["Sink"], propertyEquals: { sinkType: "csrf_state_change" } },
    } satisfies CorrelationRuleDefinition;

    expect(
      correlateGraphRules({
        graph: graphFixture({ sinkType: "access_control", sinkLabel: "findOne" }),
        rules: [accessRule],
      })[0],
    ).toMatchObject({
      title: "Access control path: request-controlled resource id reaches owned data access",
    });
    expect(
      correlateGraphRules({
        graph: graphFixture({ sinkType: "access_control", sinkLabel: "IDOR object access" }),
        rules: [accessRule],
      })[0],
    ).toMatchObject({
      title: "IDOR path: request-controlled resource id reaches object access",
    });
    expect(
      correlateGraphRules({
        graph: graphFixture({ sinkType: "csrf_state_change", sinkLabel: "setValue" }),
        rules: [csrfRule],
      })[0],
    ).toMatchObject({
      title:
        "CSRF path: state-changing request reaches mutable server-side state without a strong CSRF control",
    });
  });

  it("uses source locations instead of verbose code labels in candidate reasons", () => {
    const graph = graphFixture({
      boundaryLabel: "function configureApp (app) {\n  app.use(compression())\n}",
    });
    const candidates = correlateGraphRules({ graph, rules: [rule()] });

    expect(candidates[0]?.candidateReason).toBe(
      "External input reaches dangerous operation: src/server.ts:10 reaches dangerousOperation across 2 graph edges",
    );
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

  it("does not cap candidates unless maxCandidatesPerRule is explicit", () => {
    const graph = graphFixture({ branches: 30 });

    expect(correlateGraphRules({ graph, rules: [rule()] })).toHaveLength(31);
    expect(correlateGraphRules({ graph, rules: [rule()], maxCandidatesPerRule: 5 })).toHaveLength(
      5,
    );
  });
});

function graphFixture(
  opts: {
    readonly controls?: boolean;
    readonly branch?: boolean;
    readonly branches?: number;
    readonly sinkType?: string;
    readonly sinkLabel?: string;
    readonly boundaryLabel?: string;
  } = {},
): SecurityGraph {
  const boundary = node(
    "Boundary",
    "Boundary:POST /submit",
    opts.boundaryLabel ?? "POST /submit",
    {
      boundaryType: "http_route",
    },
    { repoPath: "src/server.ts", lineRange: { startLine: 10, endLine: 10 } },
  );
  const handler = node("CodeEntity", "CodeEntity:handler", "submitHandler", {
    fullName: "submitHandler",
  });
  const dangerous = node(
    "Sink",
    "Sink:dangerous-operation",
    opts.sinkLabel ?? "dangerousOperation",
    {
      sinkType: opts.sinkType ?? "command_exec",
    },
  );
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

  for (let index = 0; index < (opts.branches ?? 0); index += 1) {
    const stableSuffix = String(index).padStart(2, "0");
    const branch = node(
      "CodeEntity",
      `CodeEntity:branch-${stableSuffix}`,
      `branch${stableSuffix}`,
      {
        fullName: `branch${stableSuffix}`,
      },
    );
    nodes.push(branch);
    edges.push(
      edge("receives", boundary, branch, `receives:boundary:branch-${stableSuffix}`),
      edge("calls", branch, dangerous, `calls:branch-${stableSuffix}:dangerous`),
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
  overrides: {
    readonly repoPath: string;
    readonly lineRange: NonNullable<SecurityGraphNode["lineRange"]>;
  } = {
    repoPath: "src/app.ts",
    lineRange: { startLine: 1, endLine: 1 },
  },
): SecurityGraphNode {
  return {
    id: nodeId(stableKey),
    kind,
    stableKey,
    label,
    repoPath: overrides.repoPath,
    lineRange: overrides.lineRange,
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
