import { describe, expect, it } from "vitest";
import type { Manifest } from "../src/domain/manifest.js";
import type { SecurityGraph } from "../src/domain/security-graph.js";
import { securityGraphId } from "../src/domain/security-graph.js";
import {
  composeContentResourceContext,
  contentResourceObservationsFromPath,
  contentResourceObservationsFromText,
} from "../src/stages/content-resource-context.js";

const GRAPH_VERSION = "1";

describe("content resource observations", () => {
  it("extracts hidden routes, obfuscated matchers, private assets, and content clues", () => {
    const observations = contentResourceObservationsFromText(
      "src/app.ts",
      [
        "app.get('/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg', serveEasterEgg())",
        "const routes = [{ matcher: tokenMatcher, component: TokenSaleComponent }]",
        "export function tokenMatcher (url) {",
        "  if (url[0].toString().match((token1(25, 184) + (36669).toString(36).toLowerCase()))) return ({ consumed: url })",
        "}",
        "res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'))",
        "void checkPatternInFeedbackAndComplaints(challenges.hiddenImageChallenge, { [Op.like]: '%pickle rick%' })",
      ].join("\n"),
    );

    expect(observations.map((item) => item.exposureType)).toEqual([
      "hidden_server_route",
      "obfuscated_frontend_route",
      "private_asset_reference",
      "steganography_content_clue",
    ]);
    expect(observations.map((item) => item.label).join("\n")).toContain("tokenMatcher");
    expect(observations.map((item) => item.label).join("\n")).toContain("thank-you.jpg");
    expect(observations.map((item) => item.label).join("\n")).toContain("pickle rick");
  });

  it("extracts suspicious uploaded image paths without reading binary content", () => {
    const observations = contentResourceObservationsFromPath({
      path: "frontend/src/assets/public/images/uploads/cat-#hidden-123.jpg",
      size: 10,
      sha256: "sha256-image",
    });

    expect(observations).toMatchObject([
      {
        repoPath: "frontend/src/assets/public/images/uploads/cat-#hidden-123.jpg",
        exposureType: "steganography_asset",
        assetPath: "frontend/src/assets/public/images/uploads/cat-#hidden-123.jpg",
      },
    ]);
  });
});

describe("composeContentResourceContext", () => {
  it("adds content resource exposure graph facts and coverage", () => {
    const observations = contentResourceObservationsFromText(
      "server.ts",
      "app.get('/this/page/is/hidden/behind/a/paywall/that/no-one/can/guess', servePremiumContent())",
    );
    const graph = composeContentResourceContext({
      graph: emptyGraph(),
      manifest: manifest(),
      observations,
      scannedFileCount: 1,
    });

    expect(graph.nodes.map((node) => node.kind)).toEqual(["Resource", "Sink"]);
    expect(graph.edges).toMatchObject([{ kind: "exposes" }]);
    expect(graph.coverage).toContainEqual(
      expect.objectContaining({
        area: "content_assets",
        state: "checked",
        coveredCount: 1,
        totalCount: 1,
        producer: "content-resource-context",
      }),
    );
  });
});

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
    createdAt: "2026-06-25T10:00:00Z",
  };
}

function manifest(): Manifest {
  return {
    origin: { kind: "github", url: "https://example.test/repo.git" },
    commitSha: "abc123",
    sourceHash: "snapshot-1",
    files: [
      {
        path: "server.ts",
        size: 100,
        sha256: "sha256-server",
      },
    ],
    exclusions: [],
    toolchain: { imageTag: "test", tools: [] },
    createdAt: "2026-06-25T10:00:00Z",
  };
}
