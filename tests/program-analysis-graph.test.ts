import { describe, expect, it } from "vitest";
import type { Manifest } from "../src/domain/manifest.js";
import type { ArtifactRef } from "../src/domain/run.js";
import type {
  ProgramAnalysisExtractionArtifact,
  ProgramAnalysisExtractionKind,
} from "../src/ports/program-analysis-backend.js";
import { composeProgramAnalysisGraph } from "../src/stages/program-analysis-graph.js";

describe("composeProgramAnalysisGraph entities", () => {
  it("normalizes Atom objectSlices into deterministic CodeEntity nodes", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", positiveSlices())] }),
    );

    const codeEntities = graph.nodes.filter((node) => node.kind === "CodeEntity");
    expect(codeEntities.map((node) => node.symbol).sort()).toEqual([
      "src/lib/fetch.ts::program:fetchUrl",
      "src/routes/upload.ts::program:uploadHandler",
    ]);
    expect(codeEntities.map((node) => node.repoPath).sort()).toEqual([
      "src/lib/fetch.ts",
      "src/routes/upload.ts",
    ]);
  });
});

describe("composeProgramAnalysisGraph boundary", () => {
  it("creates Boundary and Source nodes from explicit boundary hints", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", positiveSlices())] }),
    );

    expect(graph.nodes.find((node) => node.kind === "Boundary")).toMatchObject({
      label: "POST /upload",
      properties: { boundaryType: "HTTP route", method: "POST" },
    });
    expect(graph.nodes.find((node) => node.kind === "Source")).toMatchObject({
      label: "req.query.url",
      properties: { sourceType: "external_input" },
    });
    expect(graph.edges.map((edge) => edge.kind)).toEqual(
      expect.arrayContaining(["receives", "registers"]),
    );
  });
});

describe("composeProgramAnalysisGraph path", () => {
  it("creates a cross-file handler-to-helper-to-sink call path", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", positiveSlices())] }),
    );
    const calls = graph.edges.filter((edge) => edge.kind === "calls");
    const labelsById = new Map(graph.nodes.map((node) => [node.id, node.label]));

    expect(
      calls.map((edge) => [labelsById.get(edge.fromNodeId), labelsById.get(edge.toNodeId)]),
    ).toEqual([
      ["uploadHandler", "fetchUrl"],
      ["fetchUrl", "fetch"],
    ]);
  });

  it("does not create a call edge for ambiguous bare target symbols", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", ambiguousSymbolSlices())] }),
    );

    expect(graph.edges.filter((edge) => edge.kind === "calls")).toHaveLength(0);
  });
});

describe("composeProgramAnalysisGraph flow", () => {
  it("creates SecurityFlow only when the boundary-to-sink path is connected", () => {
    const positive = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", positiveSlices())] }),
    );
    const negative = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", missingEdgeSlices())] }),
    );

    expect(positive.flows).toHaveLength(1);
    expect(positive.flows[0]?.pathEdgeIds).toHaveLength(4);
    expect(negative.flows).toHaveLength(0);
  });
});

describe("composeProgramAnalysisGraph coverage", () => {
  it("records boundary, call graph, and data-flow coverage from current artifacts", () => {
    const graph = composeProgramAnalysisGraph(
      input({
        artifacts: [
          artifact("entities", positiveSlices()),
          artifact("flows", { graph: { nodes: [], edges: [] }, paths: [[1, 2]] }),
        ],
      }),
    );

    expect(graph.coverage).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ area: "boundaries", state: "checked" }),
        expect.objectContaining({ area: "call_graph", state: "checked" }),
        expect.objectContaining({ area: "data_flow", state: "checked" }),
      ]),
    );
  });
});

describe("composeProgramAnalysisGraph snapshot", () => {
  it("skips unsafe or outside-snapshot backend paths before validation", () => {
    const graph = composeProgramAnalysisGraph(
      input({
        artifacts: [
          artifact("entities", {
            objectSlices: [
              {
                fullName: "../secret.ts::program:leak",
                fileName: "../secret.ts",
                lineNumber: 1,
                usages: [],
              },
            ],
          }),
        ],
      }),
    );

    expect(graph.nodes).toHaveLength(0);
    expect(graph.edges).toHaveLength(0);
    expect(graph.flows).toHaveLength(0);
  });
});

describe("composeProgramAnalysisGraph deterministic", () => {
  it("returns stable ids and ordering for repeated composition", () => {
    const first = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", positiveSlices())] }),
    );
    const second = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", positiveSlices())] }),
    );

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

function input(overrides: {
  readonly artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>;
}) {
  return {
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: "1",
    manifest: manifest(),
    createdAt: "2026-06-24T10:00:00.000Z",
    ...overrides,
  };
}

function positiveSlices() {
  return {
    objectSlices: [
      {
        fullName: "src/routes/upload.ts::program:uploadHandler",
        fileName: "src/routes/upload.ts",
        lineNumber: 10,
        boundary: {
          boundaryType: "HTTP route",
          routeOrName: "POST /upload",
          method: "POST",
          sourceName: "req.query.url",
        },
        usages: [
          {
            targetObj: {
              name: "fetchUrl",
              resolvedMethod: "src/lib/fetch.ts::program:fetchUrl",
              label: "CALL",
              lineNumber: 12,
            },
          },
        ],
      },
      {
        fullName: "src/lib/fetch.ts::program:fetchUrl",
        fileName: "src/lib/fetch.ts",
        lineNumber: 3,
        usages: [
          {
            targetObj: {
              name: "fetch",
              resolvedMethod: "fetch",
              isExternal: true,
              label: "CALL",
              lineNumber: 4,
            },
          },
        ],
      },
    ],
  };
}

function missingEdgeSlices() {
  const slices = positiveSlices();
  return {
    objectSlices: [{ ...slices.objectSlices[0], usages: [] }, slices.objectSlices[1]],
  };
}

function ambiguousSymbolSlices() {
  return {
    objectSlices: [
      {
        fullName: "src/routes/upload.ts::program:uploadHandler",
        fileName: "src/routes/upload.ts",
        lineNumber: 10,
        usages: [
          {
            targetObj: {
              name: "shared",
              label: "CALL",
              lineNumber: 12,
            },
          },
        ],
      },
      {
        fullName: "src/lib/one.ts::program:shared",
        fileName: "src/lib/one.ts",
        lineNumber: 3,
        usages: [],
      },
      {
        fullName: "src/lib/two.ts::program:shared",
        fileName: "src/lib/two.ts",
        lineNumber: 4,
        usages: [],
      },
    ],
  };
}

function artifact(
  kind: ProgramAnalysisExtractionKind,
  parsed: unknown,
): ProgramAnalysisExtractionArtifact {
  const sliceArtifact: ArtifactRef = {
    blobSha256: `slice-${kind}`,
    role: "program-analysis.slice",
    bytes: JSON.stringify(parsed).length,
  };
  return {
    backend: "atom",
    backendVersion: "atom@2.5.6",
    kind,
    language: "typescript",
    modelArtifact: { blobSha256: "model-sha", role: "program-analysis.raw", bytes: 10 },
    sliceArtifact,
    slicePath: `/work/vibeshield/atom-${kind}.json`,
    command: ["atom", kind],
    parsed,
  };
}

function manifest(): Manifest {
  return {
    origin: { kind: "local", path: "/repo" },
    commitSha: "abc123",
    sourceHash: "snapshot-1",
    files: [
      { path: "src/routes/upload.ts", size: 100, sha256: "route-sha" },
      { path: "src/lib/fetch.ts", size: 80, sha256: "fetch-sha" },
      { path: "src/lib/one.ts", size: 70, sha256: "one-sha" },
      { path: "src/lib/two.ts", size: 75, sha256: "two-sha" },
    ],
    exclusions: [],
    toolchain: {
      imageTag: "vibeshield-toolchain:test",
      tools: [],
    },
    createdAt: "2026-06-24T10:00:00.000Z",
  };
}
