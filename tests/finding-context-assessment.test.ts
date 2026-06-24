import { describe, expect, it } from "vitest";
import type { ComponentReachability } from "../src/domain/component-reachability.js";
import type { Finding, FindingCategory } from "../src/domain/finding.js";
import type {
  GraphCoverageState,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../src/domain/security-graph.js";
import {
  securityGraphEdgeId,
  securityGraphId,
  securityGraphNodeId,
} from "../src/domain/security-graph.js";
import { assessFindingContext } from "../src/stages/finding-context-assessment.js";

const GRAPH_VERSION = "1";

describe("assessFindingContext statuses", () => {
  it("returns standalone records without mutating findings", () => {
    const source = finding("finding-secret", "secret");
    const before = JSON.stringify(source);
    const graph = graphFor(source);

    expect(assessFindingContext({ findings: [source], graph })).toEqual([
      expect.objectContaining({
        findingId: "finding-secret",
        status: "standalone",
        graphNodeIds: [],
        graphEdgeIds: [],
        hypothesisIds: [],
      }),
    ]);
    expect(JSON.stringify(source)).toBe(before);
  });

  it("corroborates findings supported by explicit graph context", () => {
    const source = finding("finding-action", "github-action");
    const graph = graphFor(source, { supported: true });

    expect(assessFindingContext({ findings: [source], graph })).toEqual([
      expect.objectContaining({
        findingId: "finding-action",
        status: "corroborated",
        graphNodeIds: expect.arrayContaining([
          nodeId("QuickScanFinding:finding-action"),
          nodeId("BuildStep:publish"),
        ]),
        graphEdgeIds: [edgeId("supported_by:finding-action:publish")],
        hypothesisIds: [],
      }),
    ]);
  });

  it("maps component reachability into weakened and corroborated contexts", () => {
    const dep = finding("finding-dep", "dependency");
    const graph = graphFor(dep, { component: true, usage: true });
    const componentNodeId = nodeId("Component:lodash");
    const usageEdgeId = edgeId("uses:handler:lodash");

    const presentOnly = assessFindingContext({
      findings: [dep],
      graph,
      componentReachability: [
        componentReachability(dep.id, componentNodeId, "present", [], "checked"),
      ],
    });
    expect(presentOnly[0]).toMatchObject({
      status: "weakened",
      graphNodeIds: [componentNodeId],
      graphEdgeIds: [],
    });

    const reachable = assessFindingContext({
      findings: [dep],
      graph,
      componentReachability: [
        componentReachability(dep.id, componentNodeId, "reachable_from_boundary", [usageEdgeId]),
      ],
    });
    expect(reachable[0]).toMatchObject({
      status: "corroborated",
      graphNodeIds: [componentNodeId],
      graphEdgeIds: [usageEdgeId],
    });

    const unknown = assessFindingContext({
      findings: [dep],
      graph,
      componentReachability: [
        componentReachability(dep.id, componentNodeId, "unknown", [], "partial"),
      ],
    });
    expect(unknown[0]?.status).toBe("standalone");
  });

  it("marks findings as linked to explicit hypothesis context", () => {
    const source = finding("finding-code", "code-pattern");
    const graph = graphFor(source);

    expect(
      assessFindingContext({
        findings: [source],
        graph,
        hypothesisLinks: [{ findingId: source.id, hypothesisId: "hyp-bola" }],
      }),
    ).toEqual([
      expect.objectContaining({
        findingId: source.id,
        status: "linked_to_hypothesis",
        hypothesisIds: ["hyp-bola"],
      }),
    ]);
  });

  it("uses contradiction as the strongest status", () => {
    const source = finding("finding-iac", "iac");
    const graph = graphFor(source, { supported: true, contradicted: true });

    expect(
      assessFindingContext({
        findings: [source],
        graph,
        hypothesisLinks: [{ findingId: source.id, hypothesisId: "hyp-public-ingress" }],
      }),
    ).toEqual([
      expect.objectContaining({
        findingId: source.id,
        status: "contradicted",
        graphEdgeIds: [edgeId("contradicted_by:finding-iac:control")],
        hypothesisIds: [],
      }),
    ]);
  });
});

describe("assessFindingContext validation", () => {
  it("rejects missing graph finding nodes and unknown graph ids", () => {
    const source = finding("finding-code", "code-pattern");
    expect(() => assessFindingContext({ findings: [source], graph: emptyGraph() })).toThrow(
      /finding context missing graph finding node: finding-code/,
    );

    expect(() =>
      assessFindingContext({
        findings: [source],
        graph: graphFor(source),
        hypothesisLinks: [
          { findingId: source.id, hypothesisId: "hyp-code", graphNodeIds: ["missing-node"] },
        ],
      }),
    ).toThrow(/hypothesis link hyp-code references unknown graph node: missing-node/);
  });

  it("rejects contextual inputs that reference unknown findings", () => {
    const source = finding("finding-dep", "dependency");
    const graph = graphFor(source, { component: true });
    const componentNodeId = nodeId("Component:lodash");

    expect(() =>
      assessFindingContext({
        findings: [source],
        graph,
        hypothesisLinks: [{ findingId: "missing-finding", hypothesisId: "hyp-missing" }],
      }),
    ).toThrow(/hypothesis link references missing finding: missing-finding/);

    expect(() =>
      assessFindingContext({
        findings: [source],
        graph,
        componentReachability: [
          componentReachability("missing-finding", componentNodeId, "present", []),
        ],
      }),
    ).toThrow(/component reachability references missing finding: missing-finding/);
  });

  it("rejects invalid component reachability records before promotion", () => {
    const source = finding("finding-dep", "dependency");
    const graph = graphFor(source, { component: true });

    expect(() =>
      assessFindingContext({
        findings: [source],
        graph,
        componentReachability: [
          componentReachability(source.id, nodeId("Component:lodash"), "imported", []),
        ],
      }),
    ).toThrow(/componentReachability lodash pathEdgeIds are required/);
  });

  it("is deterministic for repeated assessment", () => {
    const a = finding("finding-z", "dependency");
    const b = finding("finding-a", "github-action");
    const graph = graphFor(a, { supported: true, component: true });
    const graphWithB = graphFor(b, { baseGraph: graph, supported: true });

    const first = assessFindingContext({ findings: [a, b], graph: graphWithB });
    const second = assessFindingContext({ findings: [a, b], graph: graphWithB });

    expect(first.map((record) => record.findingId)).toEqual(["finding-a", "finding-z"]);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

function graphFor(
  source: Finding,
  opts: {
    readonly baseGraph?: SecurityGraph;
    readonly component?: boolean;
    readonly usage?: boolean;
    readonly supported?: boolean;
    readonly contradicted?: boolean;
  } = {},
): SecurityGraph {
  const nodes = [...(opts.baseGraph?.nodes ?? [])];
  const edges = [...(opts.baseGraph?.edges ?? [])];
  const finding = findingNode(source);
  const subject = subjectNode(source);
  addNode(nodes, finding);
  addNode(nodes, subject);
  addEdge(edges, edge("affects", finding, subject, `affects:${source.id}`));

  if (opts.component === true) {
    addNode(nodes, componentNode());
  }
  if (opts.usage === true) {
    const handler = codeNode("CodeEntity:handler", "handler", "src/app.ts");
    addNode(nodes, handler);
    addEdge(edges, edge("uses", handler, componentNode(), "uses:handler:lodash"));
  }
  if (opts.supported === true) {
    const buildStep = buildStepNode();
    addNode(nodes, buildStep);
    addEdge(edges, edge("supported_by", finding, buildStep, `supported_by:${source.id}:publish`));
  }
  if (opts.contradicted === true) {
    const control = controlNode();
    addNode(nodes, control);
    addEdge(
      edges,
      edge("contradicted_by", subject, control, `contradicted_by:${source.id}:control`),
    );
  }

  return {
    id: opts.baseGraph?.id ?? securityGraphId("snapshot-1", GRAPH_VERSION),
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: GRAPH_VERSION,
    nodes,
    edges,
    flows: opts.baseGraph?.flows ?? [],
    coverage: opts.baseGraph?.coverage ?? [],
    createdAt: "2026-06-24T10:00:00Z",
  };
}

function emptyGraph(): SecurityGraph {
  return {
    id: securityGraphId("snapshot-1", GRAPH_VERSION),
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: GRAPH_VERSION,
    nodes: [],
    edges: [],
    flows: [],
    coverage: [],
    createdAt: "2026-06-24T10:00:00Z",
  };
}

function finding(id: string, category: FindingCategory): Finding {
  return {
    id,
    sourceTool: "scanner",
    ruleId: `${category}-rule`,
    category,
    severity: "high",
    confidence: "high",
    locations: [{ filePath: "src/app.ts", startLine: 1, endLine: 1 }],
    evidenceIds: [`ev-${id}`],
    fingerprint: `fp-${id}`,
    remediationKey: `${category}-remediation`,
  };
}

function findingNode(source: Finding): SecurityGraphNode {
  return node("Finding", `QuickScanFinding:${source.id}`, source.id, {
    recordType: "finding",
    findingId: source.id,
    category: source.category,
  });
}

function subjectNode(source: Finding): SecurityGraphNode {
  if (source.category === "dependency" || source.category === "sbom") {
    return componentNode();
  }
  return node("CodeEntity", `QuickScanSubject:${source.id}`, `${source.category}-subject`, {
    recordType: "subject",
    findingId: source.id,
  });
}

function componentNode(): SecurityGraphNode {
  return node("Component", "Component:lodash", "lodash", {
    recordType: "component",
    packageName: "lodash",
  });
}

function buildStepNode(): SecurityGraphNode {
  return node("BuildStep", "BuildStep:publish", "publish", {
    recordType: "workflow_step",
    stepId: "publish",
  });
}

function controlNode(): SecurityGraphNode {
  return node("Control", "Control:auth-check", "auth check", {
    recordType: "control",
  });
}

function codeNode(stableKey: string, label: string, repoPath: string): SecurityGraphNode {
  return node("CodeEntity", stableKey, label, { recordType: "code_entity" }, repoPath);
}

function node(
  kind: SecurityGraphNode["kind"],
  stableKey: string,
  label: string,
  properties: Readonly<Record<string, unknown>>,
  repoPath = "src/app.ts",
): SecurityGraphNode {
  return {
    id: nodeId(stableKey),
    kind,
    stableKey,
    label,
    repoPath,
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

function componentReachability(
  findingId: string,
  componentNodeId: string,
  level: ComponentReachability["level"],
  pathEdgeIds: ReadonlyArray<string>,
  coverageState: GraphCoverageState = "checked",
): ComponentReachability {
  return {
    componentNodeId,
    packageName: "lodash",
    findingIds: [findingId],
    level,
    pathEdgeIds,
    affectedSymbolReachability: "unknown",
    evidenceIds: ["ev-component"],
    coverageState,
  };
}

function addNode(nodes: SecurityGraphNode[], nodeToAdd: SecurityGraphNode): void {
  if (!nodes.some((current) => current.id === nodeToAdd.id)) {
    nodes.push(nodeToAdd);
  }
}

function addEdge(edges: SecurityGraphEdge[], edgeToAdd: SecurityGraphEdge): void {
  if (!edges.some((current) => current.id === edgeToAdd.id)) {
    edges.push(edgeToAdd);
  }
}

function nodeId(stableKey: string): string {
  return securityGraphNodeId(GRAPH_VERSION, stableKey);
}

function edgeId(stableKey: string): string {
  return securityGraphEdgeId(GRAPH_VERSION, stableKey);
}
