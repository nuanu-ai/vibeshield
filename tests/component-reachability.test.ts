import { describe, expect, it } from "vitest";
import type { Manifest } from "../src/domain/manifest.js";
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
  type ComponentDependencyObservation,
  type ComponentUsageObservation,
  composeComponentReachability,
} from "../src/stages/component-reachability.js";

describe("composeComponentReachability levels", () => {
  it("keeps a lockfile-only component at present without a boundary path", () => {
    const result = composeComponentReachability({ graph: baseGraph(), manifest: manifest() });

    expect(byPackage(result.reachability).get("lock-only")).toMatchObject({
      level: "present",
      pathEdgeIds: [],
      affectedSymbolReachability: "unknown",
    });
  });

  it("promotes a lockfile component when the package dependency graph reaches it", () => {
    const result = composeComponentReachability({
      graph: baseGraph(),
      manifest: manifest(),
      dependencyObservations: [
        dependency("fixture-app", "lock-only", "package.json", "ev-lock-only"),
      ],
    });
    const reachability = byPackage(result.reachability).get("lock-only");
    const dependencyEdge = result.graph.edges.find((edge) => edge.kind === "depends_on");

    expect(reachability).toMatchObject({
      level: "dependency_graph_reachable",
      pathEdgeIds: [dependencyEdge?.id],
      affectedSymbolReachability: "unknown",
    });
    expect(dependencyEdge).toMatchObject({
      kind: "depends_on",
      properties: {
        sourcePackageName: "fixture-app",
        packageName: "lock-only",
      },
    });
    expect(
      result.graph.nodes.find((node) => node.properties.recordType === "dependency_manifest"),
    ).toMatchObject({
      kind: "CodeEntity",
      repoPath: "package.json",
      properties: { sourcePackageName: "fixture-app", manifestPath: "package.json" },
    });
  });

  it("attaches dependency graph evidence to every component for the same package", () => {
    const graph = baseGraph();
    const duplicateComponent = node(
      "Component",
      "Component:lock-only:second-cve",
      "lock-only",
      ["ev-lock-only-2"],
      {
        symbol: "lock-only",
        properties: { packageName: "lock-only", version: "1.0.0" },
      },
    );
    const result = composeComponentReachability({
      graph: { ...graph, nodes: [...graph.nodes, duplicateComponent] },
      manifest: manifest(),
      dependencyObservations: [
        dependency("fixture-app", "lock-only", "package.json", "ev-lock-only"),
      ],
    });
    const lockOnlyReachability = result.reachability.filter(
      (record) => record.packageName === "lock-only",
    );

    expect(lockOnlyReachability).toHaveLength(2);
    expect(
      lockOnlyReachability.every((record) => record.level === "dependency_graph_reachable"),
    ).toBe(true);
    expect(
      result.graph.edges.filter(
        (edge) =>
          edge.kind === "depends_on" &&
          lockOnlyReachability.some((record) => record.componentNodeId === edge.toNodeId),
      ),
    ).toHaveLength(2);
  });

  it("creates imports and uses edges from explicit observations", () => {
    const result = composeComponentReachability({
      graph: baseGraph(),
      manifest: manifest(),
      observations: [
        usage("import-only", "src/internal.ts", "internal", "imported", "ev-import"),
        usage("used-internal", "src/internal.ts", "internal", "used", "ev-used"),
      ],
    });
    const reachability = byPackage(result.reachability);

    expect(reachability.get("import-only")).toMatchObject({ level: "imported" });
    expect(reachability.get("used-internal")).toMatchObject({ level: "used" });
    expect(result.graph.edges.filter((edge) => edge.kind === "imports")).toHaveLength(1);
    expect(result.graph.edges.filter((edge) => edge.kind === "uses")).toHaveLength(1);
    expect(result.graph.coverage).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          area: "dependency_usage",
          state: "checked",
          coveredCount: 2,
          totalCount: 6,
          producer: "component-reachability",
        }),
      ]),
    );
  });

  it("does not attach ownerless import observations to ambiguous multi-method files", () => {
    const result = composeComponentReachability({
      graph: {
        ...baseGraph(),
        nodes: [...baseGraph().nodes, codeNode("src/internal.ts", "secondInternal")],
      },
      manifest: manifest(),
      observations: [
        {
          packageName: "used-internal",
          repoPath: "src/internal.ts",
          usageKind: "imported",
          evidenceIds: ["ev-used"],
          lineRange: { startLine: 1, endLine: 1 },
        },
      ],
    });

    expect(result.graph.edges.filter((edge) => edge.kind === "imports")).toHaveLength(1);
    expect(
      result.graph.nodes.find((node) => node.properties.recordType === "component_usage"),
    ).toMatchObject({
      kind: "CodeEntity",
      repoPath: "src/internal.ts",
      properties: { packageName: "used-internal", usageKind: "imported" },
    });
    expect(byPackage(result.reachability).get("used-internal")).toMatchObject({
      level: "imported",
    });
  });

  it("promotes a component used by boundary-reachable code", () => {
    const result = composeComponentReachability({
      graph: baseGraph(),
      manifest: manifest(),
      observations: [usage("public-client", "src/public.ts", "publicHandler", "used", "ev-public")],
    });

    expect(byPackage(result.reachability).get("public-client")).toMatchObject({
      level: "reachable_from_boundary",
    });
    expect(byPackage(result.reachability).get("public-client")?.pathEdgeIds).toHaveLength(2);
  });

  it("matches Go module suffixes without broad fuzzy package matching", () => {
    const result = composeComponentReachability({
      graph: baseGraph(),
      manifest: manifest(),
      observations: [
        usage("github.com/dgrijalva/jwt-go", "src/public.ts", "publicHandler", "used", "ev-public"),
      ],
    });

    expect(byPackage(result.reachability).get("jwt-go")).toMatchObject({
      level: "reachable_from_boundary",
    });
  });

  it("promotes reachable affected-symbol evidence without treating missing data as no", () => {
    const result = composeComponentReachability({
      graph: baseGraph(),
      manifest: manifest(),
      observations: [
        {
          ...usage("affected-client", "src/public.ts", "publicHandler", "used", "ev-affected"),
          affectedSymbol: "affectedClient.request",
        },
        usage("used-internal", "src/internal.ts", "internal", "used", "ev-used"),
      ],
    });
    const reachability = byPackage(result.reachability);

    expect(reachability.get("affected-client")).toMatchObject({
      level: "affected_symbol_reachable",
      affectedSymbol: "affectedClient.request",
      affectedSymbolReachability: "reachable",
    });
    expect(reachability.get("used-internal")).toMatchObject({
      level: "used",
      affectedSymbolReachability: "unknown",
    });
  });
});

describe("composeComponentReachability validation", () => {
  it("ignores unmatched observations instead of fabricating graph nodes", () => {
    const result = composeComponentReachability({
      graph: baseGraph(),
      manifest: manifest(),
      observations: [
        usage("missing-package", "src/public.ts", "publicHandler", "used", "ev-missing"),
        usage("public-client", "src/missing.ts", "missing", "used", "ev-missing"),
      ],
    });

    expect(result.graph.edges.filter((edge) => edge.kind === "uses")).toHaveLength(0);
    expect(byPackage(result.reachability).get("public-client")).toMatchObject({
      level: "present",
    });
  });

  it("rejects matched observations without evidence", () => {
    expect(() =>
      composeComponentReachability({
        graph: baseGraph(),
        manifest: manifest(),
        observations: [
          {
            ...usage("public-client", "src/public.ts", "publicHandler", "used", "ev-public"),
            evidenceIds: [],
          },
        ],
      }),
    ).toThrow(/component usage observation for public-client has no evidence/);
  });

  it("is deterministic for repeated inputs", () => {
    const observations = [
      usage("public-client", "src/public.ts", "publicHandler", "used", "ev-public"),
    ];
    const first = composeComponentReachability({
      graph: baseGraph(),
      manifest: manifest(),
      observations,
    });
    const second = composeComponentReachability({
      graph: baseGraph(),
      manifest: manifest(),
      observations,
    });

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

function byPackage(records: ReturnType<typeof composeComponentReachability>["reachability"]) {
  return new Map(records.map((record) => [record.packageName, record]));
}

function usage(
  packageName: string,
  repoPath: string,
  symbol: string,
  usageKind: ComponentUsageObservation["usageKind"],
  evidenceId: string,
): ComponentUsageObservation {
  return {
    packageName,
    repoPath,
    symbol,
    usageKind,
    evidenceIds: [evidenceId],
    lineRange: { startLine: 1, endLine: 1 },
  };
}

function dependency(
  sourcePackageName: string,
  packageName: string,
  manifestPath: string,
  evidenceId: string,
): ComponentDependencyObservation {
  return {
    sourcePackageName,
    packageName,
    manifestPath,
    evidenceIds: [evidenceId],
    lineRange: { startLine: 1, endLine: 1 },
  };
}

function baseGraph(): SecurityGraph {
  const nodes = [
    boundaryNode(),
    codeNode("src/public.ts", "publicHandler"),
    codeNode("src/internal.ts", "internal"),
    ...components([
      "lock-only",
      "import-only",
      "used-internal",
      "public-client",
      "affected-client",
      "jwt-go",
    ]),
    ...componentFindings([
      "lock-only",
      "import-only",
      "used-internal",
      "public-client",
      "affected-client",
      "jwt-go",
    ]),
  ];
  return {
    id: securityGraphId("snapshot-1", "1"),
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: "1",
    nodes,
    edges: [
      edge("registers", boundaryNode().id, codeNode("src/public.ts", "publicHandler").id, [
        "ev-boundary",
      ]),
      ...affectsEdges([
        "lock-only",
        "import-only",
        "used-internal",
        "public-client",
        "affected-client",
      ]),
    ],
    flows: [],
    coverage: [],
    createdAt: "2026-06-24T10:00:00Z",
  };
}

function boundaryNode(): SecurityGraphNode {
  const stableKey = "Boundary:http:GET /public:src/public.ts:1";
  return node("Boundary", stableKey, "GET /public", ["ev-boundary"], {
    repoPath: "src/public.ts",
    lineRange: { startLine: 1, endLine: 1 },
    properties: { boundaryType: "HTTP route", routeOrName: "GET /public" },
  });
}

function codeNode(repoPath: string, symbol: string): SecurityGraphNode {
  const stableKey = `CodeEntity:${repoPath}:${symbol}`;
  return node("CodeEntity", stableKey, symbol, [`ev-${symbol}`], {
    repoPath,
    lineRange: { startLine: 1, endLine: 1 },
    symbol,
    properties: { fullName: symbol },
  });
}

function components(packageNames: ReadonlyArray<string>): SecurityGraphNode[] {
  return packageNames.map((packageName) =>
    node("Component", `Component:${packageName}`, packageName, [`ev-${packageName}`], {
      symbol: packageName,
      properties: { packageName, version: "1.0.0" },
    }),
  );
}

function componentFindings(packageNames: ReadonlyArray<string>): SecurityGraphNode[] {
  return packageNames.map((packageName) =>
    node("Finding", `Finding:${packageName}`, `${packageName} finding`, [`ev-${packageName}`], {
      symbol: `finding-${packageName}`,
      properties: { recordType: "finding", findingId: `finding-${packageName}` },
    }),
  );
}

function affectsEdges(packageNames: ReadonlyArray<string>): SecurityGraphEdge[] {
  return packageNames.map((packageName) =>
    edge(
      "affects",
      securityGraphNodeId("1", `Finding:${packageName}`),
      securityGraphNodeId("1", `Component:${packageName}`),
      [`ev-${packageName}`],
    ),
  );
}

function edge(
  kind: SecurityGraphEdge["kind"],
  fromNodeId: string,
  toNodeId: string,
  evidenceIds: ReadonlyArray<string>,
): SecurityGraphEdge {
  const stableKey = `${kind}:${fromNodeId}:${toNodeId}`;
  return {
    id: securityGraphEdgeId("1", stableKey),
    kind,
    stableKey,
    fromNodeId,
    toNodeId,
    properties: {},
    evidenceIds,
    producer: "test-fixture",
    producerVersion: "1",
    confidence: 1,
    coverageState: "checked",
  };
}

function node(
  kind: SecurityGraphNode["kind"],
  stableKey: string,
  label: string,
  evidenceIds: ReadonlyArray<string>,
  options: {
    readonly repoPath?: string;
    readonly lineRange?: SecurityGraphNode["lineRange"];
    readonly symbol?: string;
    readonly properties?: Readonly<Record<string, unknown>>;
  } = {},
): SecurityGraphNode {
  return {
    id: securityGraphNodeId("1", stableKey),
    kind,
    stableKey,
    label,
    ...(options.repoPath === undefined ? {} : { repoPath: options.repoPath }),
    ...(options.lineRange === undefined ? {} : { lineRange: options.lineRange }),
    ...(options.symbol === undefined ? {} : { symbol: options.symbol }),
    properties: options.properties ?? {},
    evidenceIds,
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
      { path: "src/public.ts", size: 10, sha256: "public-sha" },
      { path: "src/internal.ts", size: 10, sha256: "internal-sha" },
      { path: "package.json", size: 10, sha256: "package-sha" },
    ],
    exclusions: [],
    toolchain: { imageTag: "vibeshield-toolchain:test", tools: [] },
    createdAt: "2026-06-24T10:00:00Z",
  };
}
