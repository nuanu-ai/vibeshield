import { describe, expect, it } from "vitest";
import type { FindingContextAssessment } from "../src/domain/finding-context-assessment.js";
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
  correlateStage2Hypotheses,
  STAGE2_HYPOTHESIS_FAMILIES,
  type Stage2HypothesisFamily,
  stage2HypothesisRules,
} from "../src/stages/stage2-hypothesis-rules.js";

const GRAPH_VERSION = "1";

describe("stage2HypothesisRules", () => {
  it("defines exactly the planned families in stable order", () => {
    const rules = stage2HypothesisRules();

    expect(rules.map((rule) => rule.family)).toEqual([...STAGE2_HYPOTHESIS_FAMILIES]);
    expect(new Set(rules.map((rule) => rule.id)).size).toBe(STAGE2_HYPOTHESIS_FAMILIES.length);
    expect(rules.every((rule) => rule.requiredValidation.length > 0)).toBe(true);
    expect(rules.every((rule) => (rule.coverageRefs ?? []).length > 0)).toBe(true);
  });
});

describe("correlateStage2Hypotheses positive fixtures", () => {
  for (const fixture of positiveFixtures()) {
    it(`creates a ${fixture.family} candidate`, () => {
      const candidates = familyCandidates(fixture.family, fixture.graph, fixture.contexts);

      expect(candidates.length).toBeGreaterThan(0);
      expect(candidates[0]).toMatchObject({
        family: fixture.family,
        supportingNodeIds: expect.arrayContaining([...fixture.expectedNodeIds]),
        supportingEdgeIds: expect.arrayContaining([...fixture.expectedEdgeIds]),
      });
      expect(candidates[0]?.coverageRefs.length).toBeGreaterThan(0);
      expect(candidates[0]?.requiredValidation.length).toBeGreaterThan(0);
      if (fixture.expectedFindingId !== undefined) {
        expect(candidates[0]?.findingIds).toContain(fixture.expectedFindingId);
      }
    });
  }
});

describe("correlateStage2Hypotheses negative fixtures", () => {
  for (const fixture of positiveFixtures()) {
    it(`does not guess ${fixture.family} without required evidence`, () => {
      expect(
        familyCandidates(fixture.family, fixture.negativeGraph, fixture.negativeContexts),
      ).toEqual([]);

      if (fixture.contextRequired) {
        expect(familyCandidates(fixture.family, fixture.graph, [])).toEqual([]);
      }
    });
  }
});

describe("correlateStage2Hypotheses context and determinism", () => {
  it("links contextual findings only by graph-ref intersection", () => {
    const fixture = dependencyFixture();
    const candidates = familyCandidates(fixture.family, fixture.graph, [
      ...fixture.contexts,
      context("finding-unrelated", [nodeId("CodeEntity:unrelated")], []),
    ]);

    expect(candidates.length).toBeGreaterThan(0);
    expect(
      candidates.every((candidate) => candidate.findingIds.includes("finding-dependency")),
    ).toBe(true);
    expect(
      candidates.every((candidate) => !candidate.findingIds.includes("finding-unrelated")),
    ).toBe(true);
  });

  it("is deterministic for repeated and shuffled rule-pack evaluation", () => {
    const fixture = dependencyFixture({ alternatePath: true });
    const shuffled: SecurityGraph = {
      ...fixture.graph,
      nodes: [...fixture.graph.nodes].reverse(),
      edges: [...fixture.graph.edges].reverse(),
    };

    const first = familyCandidates(fixture.family, fixture.graph, fixture.contexts);
    const second = familyCandidates(fixture.family, shuffled, fixture.contexts);

    expect(first.length).toBeGreaterThan(1);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it("deduplicates semantically equivalent source-to-sink paths", () => {
    const request = node("Source", "Source:request", "r", {
      sourceType: "request",
    });
    const lambda = node("Source", "Source:lambda", "<lambda>1", {
      sourceType: "request",
    });
    const boundary = node("Boundary", "Boundary:lambda", "<lambda>1", {
      boundaryType: "framework-input",
    });
    const sink = node("Sink", "Sink:command", "CommandContext", {
      sinkType: "code_execution",
    });
    const firstPath = edge("flows_to", request, sink, "flows_to:request:command");
    const aliasPath = edge("flows_to", lambda, sink, "flows_to:lambda:command");
    const boundaryPath = edge("flows_to", boundary, sink, "flows_to:boundary:command");
    const sourceGraph = graph(
      [request, lambda, boundary, sink],
      [firstPath, aliasPath, boundaryPath],
    );

    const candidates = familyCandidates("external_input_to_dangerous_operation", sourceGraph, []);

    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.title).toBe(
      "Code execution path: external input reaches command or code execution",
    );
  });

  it("applies maxCandidatesPerRule after context-required filtering", () => {
    const fixture = dependencyFixture({ alternatePath: true });
    const candidates = correlateStage2Hypotheses({
      graph: fixture.graph,
      findingContexts: fixture.contexts,
      maxCandidatesPerRule: 1,
    }).filter((candidate) => candidate.family === fixture.family);

    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.findingIds).toContain("finding-dependency");
  });

  it("rejects invalid maxCandidatesPerRule values", () => {
    const fixture = dependencyFixture();

    expect(() =>
      correlateStage2Hypotheses({
        graph: fixture.graph,
        findingContexts: fixture.contexts,
        maxCandidatesPerRule: 0,
      }),
    ).toThrow(/maxCandidatesPerRule must be a positive integer/);
  });
});

interface FamilyFixture {
  readonly family: Stage2HypothesisFamily;
  readonly graph: SecurityGraph;
  readonly negativeGraph: SecurityGraph;
  readonly contexts: ReadonlyArray<FindingContextAssessment>;
  readonly negativeContexts: ReadonlyArray<FindingContextAssessment>;
  readonly expectedNodeIds: ReadonlyArray<string>;
  readonly expectedEdgeIds: ReadonlyArray<string>;
  readonly expectedFindingId?: string;
  readonly contextRequired: boolean;
}

function positiveFixtures(): FamilyFixture[] {
  return [
    externalInputFixture(),
    sastFixture(),
    dependencyFixture(),
    ciFixture(),
    secretFixture(),
    contentResourceFixture(),
    smartContractFixture(),
  ];
}

function externalInputFixture(): FamilyFixture {
  const boundary = node("Boundary", "Boundary:POST /pay", "POST /pay", {
    boundaryType: "http_route",
  });
  const handler = node("CodeEntity", "CodeEntity:pay-handler", "payHandler", {
    fullName: "payHandler",
  });
  const sink = node("Sink", "Sink:command-exec", "child_process.exec", {
    sinkType: "command_exec",
  });
  const receives = edge("receives", boundary, handler, "receives:pay:handler");
  const calls = edge("calls", handler, sink, "calls:handler:exec");

  return {
    family: "external_input_to_dangerous_operation",
    graph: graph([boundary, handler, sink], [receives, calls]),
    negativeGraph: graph([boundary, handler, sink], [receives]),
    contexts: [],
    negativeContexts: [],
    expectedNodeIds: [boundary.id, sink.id],
    expectedEdgeIds: [receives.id, calls.id],
    contextRequired: false,
  };
}

function sastFixture(): FamilyFixture {
  const boundary = node("Boundary", "Boundary:GET /item", "GET /item", {
    boundaryType: "http_route",
  });
  const vulnerable = node("CodeEntity", "CodeEntity:sast-target", "unsafeLookup", {
    fullName: "unsafeLookup",
  });
  const call = edge("calls", boundary, vulnerable, "calls:boundary:sast-target");

  return {
    family: "sast_reachable_path",
    graph: graph([boundary, vulnerable], [call]),
    negativeGraph: graph([boundary, vulnerable], []),
    contexts: [context("finding-sast", [vulnerable.id], [call.id])],
    negativeContexts: [context("finding-sast", [vulnerable.id], [])],
    expectedNodeIds: [boundary.id, vulnerable.id],
    expectedEdgeIds: [call.id],
    expectedFindingId: "finding-sast",
    contextRequired: true,
  };
}

function dependencyFixture(opts: { readonly alternatePath?: boolean } = {}): FamilyFixture {
  const boundary = node("Boundary", "Boundary:POST /search", "POST /search", {
    boundaryType: "http_route",
  });
  const handler = node("CodeEntity", "CodeEntity:search-handler", "searchHandler", {
    fullName: "searchHandler",
  });
  const component = node("Component", "Component:lodash", "lodash", {
    packageName: "lodash",
  });
  const unrelated = node("CodeEntity", "CodeEntity:unrelated", "unrelated", {
    fullName: "unrelated",
  });
  const receives = edge("receives", boundary, handler, "receives:search:handler");
  const uses = edge("uses", handler, component, "uses:handler:lodash");
  const nodes = [boundary, handler, component, unrelated];
  const edges = [receives, uses];

  if (opts.alternatePath === true) {
    const alternate = node("CodeEntity", "CodeEntity:alternate-search", "alternateSearch", {
      fullName: "alternateSearch",
    });
    nodes.push(alternate);
    edges.push(
      edge("receives", boundary, alternate, "receives:search:alternate"),
      edge("uses", alternate, component, "uses:alternate:lodash"),
    );
  }

  return {
    family: "dependency_usage_path",
    graph: graph(nodes, edges),
    negativeGraph: graph([boundary, handler, component, unrelated], [receives]),
    contexts: [context("finding-dependency", [component.id], [uses.id])],
    negativeContexts: [context("finding-dependency", [component.id], [])],
    expectedNodeIds: [boundary.id, component.id],
    expectedEdgeIds: [uses.id],
    expectedFindingId: "finding-dependency",
    contextRequired: true,
  };
}

function ciFixture(): FamilyFixture {
  const step = node("BuildStep", "BuildStep:publish", "publish", {
    recordType: "workflow_step",
  });
  const token = node("Resource", "Resource:contents-write-token", "contents:write", {
    resourceType: "token_permission",
    access: "write",
  });
  const depends = edge("depends_on", step, token, "depends_on:publish:contents-token");

  return {
    family: "ci_supply_chain_path",
    graph: graph([step, token], [depends]),
    negativeGraph: graph([step, token], []),
    contexts: [context("finding-ci", [step.id, token.id], [depends.id])],
    negativeContexts: [context("finding-ci", [step.id, token.id], [])],
    expectedNodeIds: [step.id, token.id],
    expectedEdgeIds: [depends.id],
    expectedFindingId: "finding-ci",
    contextRequired: true,
  };
}

function secretFixture(): FamilyFixture {
  const secret = node("Secret", "Secret:stripe-key", "stripe key", {
    ruleId: "stripe-access-token",
  });
  const service = node("ExternalService", "ExternalService:stripe", "Stripe API", {
    serviceType: "payment_provider",
  });
  const uses = edge("uses", secret, service, "uses:secret:stripe");

  return {
    family: "secret_impact_chain",
    graph: graph([secret, service], [uses]),
    negativeGraph: graph([secret, service], []),
    contexts: [context("finding-secret", [secret.id], [uses.id])],
    negativeContexts: [context("finding-secret", [secret.id], [])],
    expectedNodeIds: [secret.id, service.id],
    expectedEdgeIds: [uses.id],
    expectedFindingId: "finding-secret",
    contextRequired: true,
  };
}

function contentResourceFixture(): FamilyFixture {
  const resource = node("Resource", "ContentResource:obfuscated-route", "Obfuscated route", {
    resourceType: "content_resource",
    exposureType: "obfuscated_frontend_route",
  });
  const sink = node("Sink", "ContentSink:obfuscated-route", "Hidden content exposure", {
    sinkType: "hidden_content_exposure",
    exposureType: "obfuscated_frontend_route",
  });
  const exposes = edge("exposes", resource, sink, "exposes:content:sink");

  return {
    family: "content_resource_exposure_path",
    graph: graph([resource, sink], [exposes]),
    negativeGraph: graph([resource, sink], []),
    contexts: [],
    negativeContexts: [],
    expectedNodeIds: [resource.id, sink.id],
    expectedEdgeIds: [exposes.id],
    contextRequired: false,
  };
}

function smartContractFixture(): FamilyFixture {
  const contract = node("Resource", "SmartContract:Bank", "Bank", {
    resourceType: "smart_contract",
    contractName: "Bank",
  });
  const sink = node("Sink", "SmartContractRisk:Bank:withdraw", "Bank.withdraw reentrancy risk", {
    sinkType: "smart_contract_reentrancy",
    riskType: "reentrancy_value_transfer_before_state_update",
  });
  const flows = edge("flows_to", contract, sink, "flows_to:contract:risk");

  return {
    family: "smart_contract_risk_path",
    graph: graph([contract, sink], [flows]),
    negativeGraph: graph([contract, sink], []),
    contexts: [],
    negativeContexts: [],
    expectedNodeIds: [contract.id, sink.id],
    expectedEdgeIds: [flows.id],
    contextRequired: false,
  };
}

function familyCandidates(
  family: Stage2HypothesisFamily,
  sourceGraph: SecurityGraph,
  contexts: ReadonlyArray<FindingContextAssessment>,
) {
  return correlateStage2Hypotheses({ graph: sourceGraph, findingContexts: contexts }).filter(
    (candidate) => candidate.family === family,
  );
}

function graph(
  nodes: ReadonlyArray<SecurityGraphNode>,
  edges: ReadonlyArray<SecurityGraphEdge>,
): SecurityGraph {
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
      {
        area: "dependency_usage",
        state: "checked",
        producer: "test-fixture",
        producerVersion: GRAPH_VERSION,
      },
      {
        area: "ci_iac",
        state: "checked",
        producer: "test-fixture",
        producerVersion: GRAPH_VERSION,
      },
      {
        area: "content_assets",
        state: "checked",
        producer: "test-fixture",
        producerVersion: GRAPH_VERSION,
      },
      {
        area: "smart_contracts",
        state: "checked",
        producer: "test-fixture",
        producerVersion: GRAPH_VERSION,
      },
    ],
    createdAt: "2026-06-24T10:00:00Z",
  };
}

function context(
  findingId: string,
  graphNodeIds: ReadonlyArray<string>,
  graphEdgeIds: ReadonlyArray<string>,
): FindingContextAssessment {
  return {
    findingId,
    status: "corroborated",
    graphNodeIds,
    graphEdgeIds,
    hypothesisIds: [],
    reason: "test context",
    coverageState: "checked",
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
