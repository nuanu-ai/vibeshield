import { describe, expect, it } from "vitest";
import type { Manifest } from "../src/domain/manifest.js";
import type { ArtifactRef } from "../src/domain/run.js";
import type {
  ProgramAnalysisExtractionArtifact,
  ProgramAnalysisExtractionKind,
} from "../src/ports/program-analysis-backend.js";
import { composeProgramAnalysisGraph } from "../src/stages/program-analysis-graph.js";

describe("composeProgramAnalysisGraph entities", () => {
  it("normalizes Joern objectSlices into deterministic CodeEntity nodes", () => {
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

  it("creates Boundary and Source nodes from Joern framework-input flows", () => {
    const graph = composeProgramAnalysisGraph(
      input({
        artifacts: [
          artifact("entities", realJoernUsageSlices()),
          artifact("call_edges", realJoernReachabilitySlices()),
        ],
      }),
    );

    expect(graph.nodes.find((node) => node.kind === "Boundary")).toMatchObject({
      label: "proxyHandler",
      repoPath: "src/routes/proxy.js",
      properties: { boundaryType: "framework-input", routeOrName: "proxyHandler" },
    });
    expect(graph.nodes.find((node) => node.kind === "Source")).toMatchObject({
      label: "req",
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
    ).toEqual(
      expect.arrayContaining([
        ["uploadHandler", "fetchUrl"],
        ["fetchUrl", "fetch"],
      ]),
    );
  });

  it("does not create a call edge for ambiguous bare target symbols", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", ambiguousSymbolSlices())] }),
    );

    expect(graph.edges.filter((edge) => edge.kind === "calls")).toHaveLength(0);
  });

  it("resolves Joern file-qualified call names through a unique target symbol", () => {
    const graph = composeProgramAnalysisGraph(
      input({
        artifacts: [
          artifact("entities", realJoernUsageSlices()),
          artifact("call_edges", realJoernReachabilitySlices()),
        ],
      }),
    );
    const calls = graph.edges.filter((edge) => edge.kind === "calls");
    const labelsById = new Map(graph.nodes.map((node) => [node.id, node.label]));

    expect(
      calls.map((edge) => [labelsById.get(edge.fromNodeId), labelsById.get(edge.toNodeId)]),
    ).toEqual(
      expect.arrayContaining([
        ["proxyHandler", "fetchUrl"],
        ["fetchUrl", "fetch"],
      ]),
    );
  });

  it("does not create a call edge for ambiguous file-qualified target symbols", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", ambiguousQualifiedSymbolSlices())] }),
    );

    expect(graph.edges.filter((edge) => edge.kind === "calls")).toHaveLength(0);
  });

  it("marks Java SQL calls as dangerous sinks on a boundary path", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", javaSqlSlices())] }),
    );
    const labelsById = new Map(graph.nodes.map((node) => [node.id, node.label]));
    const sink = graph.nodes.find((node) => node.kind === "Sink");
    const calls = graph.edges.filter((edge) => edge.kind === "calls");

    expect(sink).toMatchObject({
      label: "executeQuery",
      repoPath: "src/main/java/example/Lesson.java",
      properties: { sinkType: "sql_execution" },
    });
    expect(
      calls.map((edge) => [labelsById.get(edge.fromNodeId), labelsById.get(edge.toNodeId)]),
    ).toEqual(
      expect.arrayContaining([
        ["attack", "injectableQuery"],
        ["injectableQuery", "executeQuery"],
      ]),
    );
    expect(graph.flows).toHaveLength(1);
  });

  it("does not mark generic execute calls as sinks without a dangerous context", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", genericExecuteSlices())] }),
    );

    expect(graph.nodes.filter((node) => node.kind === "Sink")).toHaveLength(0);
    expect(graph.flows).toHaveLength(0);
  });

  it("marks Java crypto operations as cryptographic sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", genericUpdateSlices())] }),
    );

    expect(graph.nodes.find((node) => node.kind === "Sink")).toMatchObject({
      label: "cryptographic digest",
      properties: { sinkType: "crypto_weakness" },
    });
    expect(graph.flows).toHaveLength(1);
  });

  it("does not mark generic update calls as sinks without a dangerous context", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", nonDangerousUpdateSlices())] }),
    );

    expect(graph.nodes.filter((node) => node.kind === "Sink")).toHaveLength(0);
    expect(graph.flows).toHaveLength(0);
  });

  it("does not treat servlet request accessors as outbound HTTP sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", servletRequestAccessorSlices())] }),
    );

    expect(graph.nodes.filter((node) => node.kind === "Sink")).toHaveLength(0);
    expect(graph.flows).toHaveLength(0);
  });

  it("labels chained frontend HTTP calls by the HTTP operation", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", chainedHttpSlices())] }),
    );

    expect(graph.nodes.find((node) => node.kind === "Sink")).toMatchObject({
      label: "http.get",
      properties: { sinkType: "outbound_http" },
    });
  });

  it("marks server-side HTTP clients separately from frontend HTTP calls", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", serverSideFetchSlices())] }),
    );
    const frontendGraph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", monorepoWebFetchSlices())] }),
    );

    expect(graph.nodes.find((node) => node.kind === "Sink")).toMatchObject({
      label: "fetch",
      properties: { sinkType: "server_side_request" },
    });
    expect(frontendGraph.nodes.find((node) => node.kind === "Sink")).toMatchObject({
      label: "fetch",
      properties: { sinkType: "outbound_http" },
    });
    expect(graph.flows).toHaveLength(1);
  });

  it("does not mark browser window open calls as filesystem sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", browserWindowOpenSlices())] }),
    );

    expect(graph.nodes.filter((node) => node.kind === "Sink")).toHaveLength(0);
    expect(graph.flows).toHaveLength(0);
  });

  it("marks redirect helpers as redirect sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", redirectSlices())] }),
    );

    expect(graph.nodes.find((node) => node.kind === "Sink")).toMatchObject({
      label: "redirect",
      properties: { sinkType: "redirect" },
    });
    expect(graph.flows).toHaveLength(1);
  });

  it("marks JWT token operations and auth-bypass verification as semantic sinks", () => {
    const jwtGraph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", jwtTokenTrustSlices())] }),
    );
    const authGraph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", authBypassSlices())] }),
    );

    expect(jwtGraph.nodes.find((node) => node.kind === "Sink")).toMatchObject({
      label: "JWT signing",
      properties: { sinkType: "jwt_token_trust" },
    });
    expect(authGraph.nodes.find((node) => node.kind === "Sink")).toMatchObject({
      label: "account verification",
      properties: { sinkType: "authentication_bypass" },
    });
    expect(jwtGraph.flows).toHaveLength(1);
    expect(authGraph.flows).toHaveLength(1);
  });

  it("connects route handlers to sinks inside nested Joern lambda entities", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", nestedLambdaSqlSlices())] }),
    );
    const labelsById = new Map(graph.nodes.map((node) => [node.id, node.label]));
    const lexicalEdges = graph.edges.filter((edge) => edge.kind === "flows_to");

    expect(
      lexicalEdges.map((edge) => [labelsById.get(edge.fromNodeId), labelsById.get(edge.toNodeId)]),
    ).toEqual(expect.arrayContaining([["handler:<lambda>0", "handler:<lambda>0:<lambda>1"]]));
    expect(graph.nodes.find((node) => node.kind === "Sink")).toMatchObject({
      label: "query",
      properties: { sinkType: "sql_execution" },
    });
    expect(graph.flows).toHaveLength(1);
  });

  it("marks HTML output as XSS and server-side template compile as template rendering", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", crossSiteScriptingSlices())] }),
    );
    const sinkLabels = graph.nodes
      .filter((node) => node.kind === "Sink")
      .map((node) => [node.label, node.properties.sinkType])
      .sort();

    expect(sinkLabels).toEqual([
      ["append", "cross_site_scripting"],
      ["bypassSecurityTrustHtml", "cross_site_scripting"],
      ["compile", "template_render"],
      ["replace", "cross_site_scripting"],
    ]);
    expect(graph.flows).toHaveLength(4);
  });

  it("does not mark ordinary collection append or JSON response calls as XSS sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", nonHtmlOutputSlices())] }),
    );

    expect(graph.nodes.filter((node) => node.kind === "Sink")).toHaveLength(0);
    expect(graph.flows).toHaveLength(0);
  });

  it("marks request-controlled object identifiers as access-control sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", accessControlSlices())] }),
    );
    const sinks = graph.nodes
      .filter((node) => node.kind === "Sink")
      .filter((node) => node.properties.sinkType === "access_control")
      .map((node) => [node.label, node.properties.sinkType])
      .sort();

    expect(sinks).toEqual([
      ["IDOR object access", "access_control"],
      ["findOne", "access_control"],
    ]);
    expect(
      graph.nodes.some(
        (node) =>
          node.kind === "Sink" &&
          node.label === "build" &&
          node.properties.sinkType === "access_control",
      ),
    ).toBe(false);
  });

  it("marks state-changing handlers without strong CSRF controls as CSRF sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", csrfStateChangeSlices())] }),
    );

    expect(
      graph.nodes
        .filter((node) => node.kind === "Sink")
        .map((node) => [node.label, node.properties.sinkType]),
    ).toEqual([["setValue", "csrf_state_change"]]);
    expect(graph.flows).toHaveLength(1);
  });

  it("marks Python web handler calls to dangerous sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", pythonWebSinkSlices())] }),
    );
    const sinkTypes = graph.nodes
      .filter((node) => node.kind === "Sink")
      .map((node) => node.properties.sinkType)
      .sort();

    expect(sinkTypes).toEqual([
      "code_execution",
      "deserialization",
      "file_system",
      "sql_execution",
      "template_render",
    ]);
    expect(graph.flows).toHaveLength(5);
  });

  it("marks JavaScript web handler calls to NoSQL, XML, file, upload, and template sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", javascriptSpecialSinkSlices())] }),
    );
    const sinkTypes = graph.nodes
      .filter((node) => node.kind === "Sink")
      .map((node) => node.properties.sinkType)
      .sort();

    expect(sinkTypes).toEqual([
      "file_system",
      "file_upload_validation",
      "no_sql_execution",
      "template_render",
      "xml_processing",
    ]);
    expect(graph.flows).toHaveLength(5);
  });

  it("does not mark generic JavaScript array searches as NoSQL sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", genericArrayFindSlices())] }),
    );

    expect(graph.nodes.filter((node) => node.kind === "Sink")).toHaveLength(0);
    expect(graph.flows).toHaveLength(0);
  });

  it("connects Express route middleware registrations to imported handler functions", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", expressMiddlewareRegistrationSlices())] }),
    );
    const labelsById = new Map(graph.nodes.map((node) => [node.id, node.label]));
    const calls = graph.edges.filter((edge) => edge.kind === "calls");

    expect(
      calls.map((edge) => [labelsById.get(edge.fromNodeId), labelsById.get(edge.toNodeId)]),
    ).toEqual(
      expect.arrayContaining([
        ["configureApp", "handleXmlUpload"],
        ["handleXmlUpload", "parseXmlString"],
        ["parseXmlString", "fromString"],
      ]),
    );
    expect(graph.nodes.find((node) => node.kind === "Sink")).toMatchObject({
      label: "fromString",
      properties: { sinkType: "xml_processing" },
    });
    expect(graph.flows.length).toBeGreaterThan(0);
  });

  it("marks Go web handler calls to dangerous sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", goWebSinkSlices())] }),
    );
    const sinkTypes = graph.nodes
      .filter((node) => node.kind === "Sink")
      .map((node) => node.properties.sinkType)
      .sort();

    expect(sinkTypes).toEqual([
      "code_execution",
      "file_system",
      "server_side_request",
      "sql_execution",
    ]);
    expect(graph.flows).toHaveLength(4);
  });

  it("does not mark Go server request and response helpers as outbound HTTP sinks", () => {
    const graph = composeProgramAnalysisGraph(
      input({ artifacts: [artifact("entities", goServerHttpHelperSlices())] }),
    );

    expect(graph.nodes.filter((node) => node.kind === "Sink")).toHaveLength(0);
    expect(graph.flows).toHaveLength(0);
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

  it("creates SecurityFlow from Joern framework-input and unresolved cross-file call facts", () => {
    const graph = composeProgramAnalysisGraph(
      input({
        artifacts: [
          artifact("entities", realJoernUsageSlices()),
          artifact("call_edges", realJoernReachabilitySlices()),
        ],
      }),
    );

    expect(graph.flows).toHaveLength(1);
    expect(graph.flows[0]?.pathEdgeIds).toHaveLength(4);
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

function ambiguousQualifiedSymbolSlices() {
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
              resolvedMethod: "src/routes/upload.ts::program:shared",
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

function javaSqlSlices() {
  return {
    objectSlices: [
      {
        fullName: "example.Lesson.attack:<unresolvedSignature>(1)",
        fileName: "src/main/java/example/Lesson.java",
        lineNumber: 12,
        boundary: {
          boundaryType: "spring",
          routeOrName: "/attack",
          method: "POST",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "injectableQuery",
              resolvedMethod: "example.Lesson.injectableQuery:<unresolvedSignature>(1)",
              label: "CALL",
              lineNumber: 14,
            },
          },
        ],
      },
      {
        fullName: "example.Lesson.injectableQuery:<unresolvedSignature>(1)",
        fileName: "src/main/java/example/Lesson.java",
        lineNumber: 20,
        usages: [
          {
            targetObj: {
              name: "executeQuery",
              resolvedMethod:
                "java.sql.Statement.executeQuery:java.sql.ResultSet(java.lang.String)",
              code: "statement.executeQuery(query)",
              label: "CALL",
              lineNumber: 23,
            },
          },
        ],
      },
    ],
  };
}

function genericExecuteSlices() {
  return {
    objectSlices: [
      {
        fullName: "example.Job.run:<unresolvedSignature>(1)",
        fileName: "src/main/java/example/Job.java",
        lineNumber: 7,
        boundary: {
          boundaryType: "framework-input",
          routeOrName: "run",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "execute",
              resolvedMethod: "example.JobScheduler.execute:void(example.Job)",
              code: "scheduler.execute(job)",
              label: "CALL",
              lineNumber: 9,
            },
          },
        ],
      },
    ],
  };
}

function genericUpdateSlices() {
  return {
    objectSlices: [
      {
        fullName: "example.Crypto.hash:<unresolvedSignature>(1)",
        fileName: "src/main/java/example/Crypto.java",
        lineNumber: 7,
        boundary: {
          boundaryType: "framework-input",
          routeOrName: "hash",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "update",
              resolvedMethod: "java.security.MessageDigest.update:void(byte[])",
              code: "digest.update(bytes)",
              label: "CALL",
              lineNumber: 9,
            },
          },
        ],
      },
    ],
  };
}

function nonDangerousUpdateSlices() {
  return {
    objectSlices: [
      {
        fullName: "example.Profile.updateDisplayName:<unresolvedSignature>(1)",
        fileName: "src/main/java/example/Profile.java",
        lineNumber: 7,
        boundary: {
          boundaryType: "framework-input",
          routeOrName: "profile",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "update",
              resolvedMethod: "example.ProfileService.update:void(example.Profile)",
              code: "profileService.update(profile)",
              label: "CALL",
              lineNumber: 9,
            },
          },
        ],
      },
    ],
  };
}

function jwtTokenTrustSlices() {
  return {
    objectSlices: [
      {
        fullName: "example.jwt.JwtController.login:<unresolvedSignature>(1)",
        fileName: "src/main/java/example/jwt/JwtController.java",
        lineNumber: 7,
        boundary: {
          boundaryType: "spring",
          routeOrName: "/JWT/refresh/login",
          method: "POST",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "signWith",
              resolvedMethod:
                "io.jsonwebtoken.JwtBuilder.signWith:io.jsonwebtoken.JwtBuilder(io.jsonwebtoken.SignatureAlgorithm,java.lang.String)",
              code: "Jwts.builder().signWith(SignatureAlgorithm.HS512, JWT_PASSWORD)",
              label: "CALL",
              lineNumber: 12,
            },
          },
        ],
      },
    ],
  };
}

function authBypassSlices() {
  return {
    objectSlices: [
      {
        fullName: "example.auth.VerifyAccount.completed:<unresolvedSignature>(1)",
        fileName: "src/main/java/example/auth/VerifyAccount.java",
        lineNumber: 7,
        boundary: {
          boundaryType: "spring",
          routeOrName: "/auth-bypass/verify-account",
          method: "POST",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "verifyAccount",
              resolvedMethod:
                "example.auth.AccountVerificationHelper.verifyAccount:boolean(java.lang.Integer,java.util.HashMap)",
              code: "verificationHelper.verifyAccount(Integer.valueOf(userId), submittedAnswers)",
              label: "CALL",
              lineNumber: 14,
            },
          },
        ],
      },
    ],
  };
}

function servletRequestAccessorSlices() {
  return {
    objectSlices: [
      {
        fullName: "example.Controller.handle:<unresolvedSignature>(1)",
        fileName: "src/main/java/example/Controller.java",
        lineNumber: 11,
        boundary: {
          boundaryType: "spring",
          routeOrName: "/profile",
          method: "GET",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "getParameter",
              resolvedMethod:
                "jakarta.servlet.http.HttpServletRequest.getParameter:<unresolvedSignature>(1)",
              code: 'request.getParameter("id")',
              label: "CALL",
              lineNumber: 13,
            },
          },
        ],
      },
    ],
  };
}

function chainedHttpSlices() {
  return {
    objectSlices: [
      {
        fullName: "src/app/service.ts::program:load",
        fileName: "src/app/service.ts",
        lineNumber: 12,
        usages: [
          {
            targetObj: {
              name: "pipe",
              resolvedMethod: "<unknownFullName>",
              code: "this.http.get('/api/products').pipe(map((x) => x))",
              label: "CALL",
              lineNumber: 13,
            },
          },
        ],
      },
    ],
  };
}

function serverSideFetchSlices() {
  return {
    objectSlices: [
      {
        fullName: "routes/proxy.ts::program:proxy",
        fileName: "routes/proxy.ts",
        lineNumber: 9,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/proxy",
          method: "GET",
          sourceName: "req",
        },
        usages: [
          {
            targetObj: {
              name: "fetch",
              resolvedMethod: "fetch",
              code: "fetch(req.query.url)",
              label: "CALL",
              lineNumber: 11,
            },
          },
        ],
      },
    ],
  };
}

function monorepoWebFetchSlices() {
  return {
    objectSlices: [
      {
        fullName: "apps/web/src/lib/api-client.ts::program:load",
        fileName: "apps/web/src/lib/api-client.ts",
        lineNumber: 12,
        usages: [
          {
            targetObj: {
              name: "fetch",
              resolvedMethod: "fetch",
              code: "fetch('/api/profile')",
              label: "CALL",
              lineNumber: 13,
            },
          },
        ],
      },
    ],
  };
}

function browserWindowOpenSlices() {
  return {
    objectSlices: [
      {
        fullName: "apps/web/src/lib/external-links.ts::program:openExternal",
        fileName: "apps/web/src/lib/external-links.ts",
        lineNumber: 3,
        usages: [
          {
            targetObj: {
              name: "open",
              resolvedMethod: "<unknownFullName>",
              code: "window.open(url, '_blank')",
              label: "CALL",
              lineNumber: 4,
            },
          },
        ],
      },
    ],
  };
}

function redirectSlices() {
  return {
    objectSlices: [
      {
        fullName: "routes/redirect.ts::program:redirectHandler",
        fileName: "routes/redirect.ts",
        lineNumber: 6,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/redirect",
          method: "GET",
          sourceName: "req",
        },
        usages: [
          {
            targetObj: {
              name: "redirect",
              resolvedMethod: "express.Response.redirect",
              code: "res.redirect(req.query.to)",
              label: "CALL",
              lineNumber: 8,
            },
          },
        ],
      },
    ],
  };
}

function nestedLambdaSqlSlices() {
  return {
    objectSlices: [
      {
        fullName: "routes/search.ts::program:handler:<lambda>0",
        fileName: "routes/search.ts",
        lineNumber: 20,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/search",
          method: "GET",
          sourceName: "req",
        },
        usages: [],
      },
      {
        fullName: "routes/search.ts::program:handler:<lambda>0:<lambda>1",
        fileName: "routes/search.ts",
        lineNumber: 24,
        usages: [
          {
            targetObj: {
              name: "query",
              resolvedMethod: "sequelize.Sequelize.query",
              code: "sequelize.query('SELECT * FROM Products WHERE name LIKE ?')",
              label: "CALL",
              lineNumber: 25,
            },
          },
        ],
      },
    ],
  };
}

function crossSiteScriptingSlices() {
  return {
    objectSlices: [
      {
        fullName: "src/main/java/example/XssController.java:<global>.completed",
        fileName: "src/main/java/example/XssController.java",
        lineNumber: 42,
        boundary: {
          boundaryType: "spring",
          routeOrName: "/CrossSiteScripting/attack",
          method: "GET",
          sourceName: "request",
        },
        parameters: [
          { name: "field1", typeFullName: "java.lang.String", lineNumber: 48 },
          { name: "field2", typeFullName: "java.lang.String", lineNumber: 49 },
        ],
        usages: [
          {
            targetObj: {
              name: "append",
              resolvedMethod: "java.lang.StringBuilder.append",
              code: 'cart.append("<p>Card:" + field1 + "<br />")',
              label: "CALL",
              lineNumber: 55,
            },
          },
        ],
      },
      {
        fullName: "routes/profile.ts::program:handler",
        fileName: "routes/profile.ts",
        lineNumber: 20,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/profile",
          method: "GET",
          sourceName: "req",
        },
        usages: [
          {
            targetObj: {
              name: "compile",
              resolvedMethod: "pug.compile",
              code: "pug.compile(template)",
              label: "CALL",
              lineNumber: 31,
            },
          },
          {
            targetObj: {
              name: "replace",
              resolvedMethod: "String.prototype.replace",
              code: "compiledTemplate.replace('<script id=\"subtitle\"></script>', '<script>' + subs + '</script>')",
              label: "CALL",
              lineNumber: 33,
            },
          },
        ],
      },
      {
        fullName: "frontend/src/app/search.component.ts::program:SearchComponent.applyQuery",
        fileName: "frontend/src/app/search.component.ts",
        lineNumber: 17,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "SearchComponent.applyQuery",
          method: "CLIENT",
          sourceName: "routeParam",
        },
        usages: [
          {
            targetObj: {
              name: "bypassSecurityTrustHtml",
              resolvedMethod: "DomSanitizer.bypassSecurityTrustHtml",
              code: "this.sanitizer.bypassSecurityTrustHtml(queryParam)",
              label: "CALL",
              lineNumber: 21,
            },
          },
        ],
      },
    ],
  };
}

function nonHtmlOutputSlices() {
  return {
    objectSlices: [
      {
        fullName: "routes/api.ts::program:handler",
        fileName: "routes/api.ts",
        lineNumber: 8,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/api/items",
          method: "GET",
          sourceName: "req",
        },
        parameters: [{ name: "password", typeFullName: "java.lang.String", lineNumber: 8 }],
        usages: [
          {
            targetObj: {
              name: "append",
              resolvedMethod: "java.util.List.append",
              code: "items.append(value)",
              label: "CALL",
              lineNumber: 10,
            },
          },
          {
            targetObj: {
              name: "append",
              resolvedMethod: "java.lang.StringBuilder.append",
              code: 'output.append("<b>Length: </b>" + password.length() + "</br>")',
              label: "CALL",
              lineNumber: 11,
            },
          },
          {
            targetObj: {
              name: "json",
              resolvedMethod: "express.Response.json",
              code: "res.json(result)",
              label: "CALL",
              lineNumber: 12,
            },
          },
        ],
      },
    ],
  };
}

function accessControlSlices() {
  return {
    objectSlices: [
      {
        fullName: "routes/basket.ts::program:retrieveBasket",
        fileName: "routes/basket.ts",
        lineNumber: 14,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/rest/basket/:id",
          method: "GET",
          sourceName: "req",
        },
        usages: [
          {
            targetObj: {
              name: "<operator>.assignment",
              resolvedMethod: "<operator>.assignment",
              code: "const id = req.params.id",
              label: "CALL",
              lineNumber: 17,
            },
          },
          {
            targetObj: {
              name: "findOne",
              resolvedMethod: "sequelize.Model.findOne",
              code: "BasketModel.findOne({ where: { id }, include: [{ model: ProductModel }] })",
              label: "CALL",
              lineNumber: 19,
            },
          },
        ],
      },
      {
        fullName: "src/main/java/example/IDORViewOtherProfile.java:<global>.completed",
        fileName: "src/main/java/example/IDORViewOtherProfile.java",
        lineNumber: 38,
        boundary: {
          boundaryType: "spring",
          routeOrName: "/IDOR/profile/{userId}",
          method: "GET",
          sourceName: "request",
        },
        parameters: [{ name: "userId", typeFullName: "java.lang.String", lineNumber: 38 }],
        usages: [
          {
            targetObj: {
              name: "<operator>.new",
              resolvedMethod: "org.owasp.webgoat.lessons.idor.UserProfile.<init>",
              code: "new UserProfile(userId)",
              label: "CALL",
              lineNumber: 47,
            },
          },
        ],
      },
      {
        fullName: "routes/basketItems.ts::program:addBasketItem",
        fileName: "routes/basketItems.ts",
        lineNumber: 19,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/api/BasketItems",
          method: "POST",
          sourceName: "req",
        },
        usages: [
          {
            targetObj: {
              name: "build",
              resolvedMethod: "sequelize.Model.build",
              code: "if (user.bid !== req.body.BasketId) { res.status(401).send('Invalid BasketId') } BasketItemModel.build(req.body)",
              label: "CALL",
              lineNumber: 47,
            },
          },
        ],
      },
    ],
  };
}

function csrfStateChangeSlices() {
  return {
    objectSlices: [
      {
        fullName: "src/main/java/example/ForgedReviews.java:<global>.createNewReview",
        fileName: "src/main/java/example/ForgedReviews.java",
        lineNumber: 70,
        boundary: {
          boundaryType: "spring",
          routeOrName: "/csrf/review",
          method: "POST",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "setValue",
              resolvedMethod: "org.owasp.webgoat.container.session.LessonSession.setValue",
              code: 'userSessionData.setValue("csrf-feedback", flag)',
              label: "CALL",
              lineNumber: 88,
            },
          },
        ],
      },
      {
        fullName: "routes/profile.ts::program:updateProfile",
        fileName: "routes/profile.ts",
        lineNumber: 10,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/profile",
          method: "POST",
          sourceName: "req",
        },
        usages: [
          {
            targetObj: {
              name: "save",
              resolvedMethod: "profileStore.save",
              code: "if (req.body.csrfToken === req.session.csrfToken) { profileStore.save(req.body) }",
              label: "CALL",
              lineNumber: 18,
            },
          },
        ],
      },
    ],
  };
}

function pythonWebSinkSlices() {
  return {
    objectSlices: [
      {
        fullName: "app.py::program:profile",
        fileName: "app.py",
        lineNumber: 12,
        boundary: {
          boundaryType: "python-web",
          routeOrName: "/profile/<name>",
          method: "GET",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "execute",
              resolvedMethod: "sqlite3.Cursor.execute",
              code: "cur.execute(\"select * from users where name = '%s'\" % name)",
              label: "CALL",
              lineNumber: 14,
            },
          },
          {
            targetObj: {
              name: "check_output",
              resolvedMethod: "subprocess.check_output",
              code: "subprocess.check_output(command, shell=True)",
              label: "CALL",
              lineNumber: 15,
            },
          },
          {
            targetObj: {
              name: "open",
              resolvedMethod: "open",
              code: 'open(filename, "r")',
              label: "CALL",
              lineNumber: 16,
            },
          },
          {
            targetObj: {
              name: "loads",
              resolvedMethod: "pickle.loads",
              code: "pickle.loads(raw)",
              label: "CALL",
              lineNumber: 17,
            },
          },
          {
            targetObj: {
              name: "render_template_string",
              resolvedMethod: "flask.render_template_string",
              code: "render_template_string(template)",
              label: "CALL",
              lineNumber: 18,
            },
          },
        ],
      },
    ],
  };
}

function javascriptSpecialSinkSlices() {
  return {
    objectSlices: [
      {
        fullName: "src/routes/upload.ts::program:handleUpload",
        fileName: "src/routes/upload.ts",
        lineNumber: 10,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/upload",
          method: "POST",
          sourceName: "req",
        },
        usages: [
          {
            targetObj: {
              name: "find",
              resolvedMethod: "mongodb.Collection.find",
              code: "db.reviewsCollection.find({ $where: 'this.product == ' + req.params.id })",
              label: "CALL",
              lineNumber: 14,
            },
          },
          {
            targetObj: {
              name: "parseXmlString",
              resolvedMethod: "src/lib/xml.ts::program:parseXmlString",
              code: "parseXmlString(file.buffer.toString())",
              label: "CALL",
              lineNumber: 18,
            },
          },
          {
            targetObj: {
              name: "sendFile",
              resolvedMethod: "express.Response.sendFile",
              code: 'res.sendFile(path.resolve("ftp/", req.params.file))',
              label: "CALL",
              lineNumber: 22,
            },
          },
          {
            targetObj: {
              name: "endsWith",
              resolvedMethod: "String.prototype.endsWith",
              code: 'file.originalname.toLowerCase().endsWith(".pdf")',
              label: "CALL",
              lineNumber: 26,
            },
          },
          {
            targetObj: {
              name: "compile",
              resolvedMethod: "pug.compile",
              code: "pug.compile(req.body.template)",
              label: "CALL",
              lineNumber: 30,
            },
          },
        ],
      },
    ],
  };
}

function genericArrayFindSlices() {
  return {
    objectSlices: [
      {
        fullName: "src/routes/upload.ts::program:listVisible",
        fileName: "src/routes/upload.ts",
        lineNumber: 40,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/visible",
          method: "GET",
          sourceName: "req",
        },
        usages: [
          {
            targetObj: {
              name: "find",
              resolvedMethod: "Array.prototype.find",
              code: "items.find((item) => item.visible)",
              label: "CALL",
              lineNumber: 43,
            },
          },
        ],
      },
    ],
  };
}

function expressMiddlewareRegistrationSlices() {
  return {
    objectSlices: [
      {
        fullName: "server.ts::program:configureApp",
        fileName: "server.ts",
        lineNumber: 300,
        boundary: {
          boundaryType: "javascript-web",
          routeOrName: "/file-upload",
          method: "POST",
          sourceName: "req",
        },
        usages: [
          {
            targetObj: {
              name: "post",
              resolvedMethod: "express.Application.post",
              code: "app.post('/file-upload', upload.single('file'), ensureFileIsPassed, checkFileType, handleXmlUpload)",
              label: "CALL",
              lineNumber: 309,
            },
          },
        ],
      },
      {
        fullName: "routes/fileUpload.ts::program:ensureFileIsPassed",
        fileName: "routes/fileUpload.ts",
        lineNumber: 19,
        usages: [],
      },
      {
        fullName: "routes/fileUpload.ts::program:checkFileType",
        fileName: "routes/fileUpload.ts",
        lineNumber: 62,
        usages: [],
      },
      {
        fullName: "routes/fileUpload.ts::program:handleXmlUpload",
        fileName: "routes/fileUpload.ts",
        lineNumber: 70,
        usages: [
          {
            targetObj: {
              name: "parseXmlString",
              resolvedMethod: "lib/xml.ts::program:parseXmlString",
              code: "parseXmlString(data)",
              label: "CALL",
              lineNumber: 76,
            },
          },
        ],
      },
      {
        fullName: "lib/xml.ts::program:parseXmlString",
        fileName: "lib/xml.ts",
        lineNumber: 33,
        usages: [
          {
            targetObj: {
              name: "fromString",
              resolvedMethod: "libxml2.XmlDocument.fromString",
              code: "libxml2.XmlDocument.fromString(data, { option })",
              label: "CALL",
              lineNumber: 38,
            },
          },
        ],
      },
    ],
  };
}

function goWebSinkSlices() {
  return {
    objectSlices: [
      {
        fullName: "main.search",
        fileName: "main.go",
        lineNumber: 21,
        boundary: {
          boundaryType: "go-web",
          routeOrName: "/search",
          method: "GET",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "Query",
              resolvedMethod: "database/sql.(*DB).Query",
              code: 'db.Query("SELECT * FROM users WHERE name = ?", name)',
              label: "CALL",
              lineNumber: 24,
            },
          },
          {
            targetObj: {
              name: "Output",
              resolvedMethod: "os/exec.(*Cmd).Output",
              code: 'exec.Command("sh", "-c", command).Output()',
              label: "CALL",
              lineNumber: 25,
            },
          },
          {
            targetObj: {
              name: "Get",
              resolvedMethod: "net/http.Get",
              code: "http.Get(callbackUrl)",
              label: "CALL",
              lineNumber: 26,
            },
          },
          {
            targetObj: {
              name: "Open",
              resolvedMethod: "os.Open",
              code: "os.Open(filename)",
              label: "CALL",
              lineNumber: 27,
            },
          },
        ],
      },
    ],
  };
}

function goServerHttpHelperSlices() {
  return {
    objectSlices: [
      {
        fullName: "main.handle",
        fileName: "main.go",
        lineNumber: 21,
        boundary: {
          boundaryType: "go-web",
          routeOrName: "/health",
          method: "GET",
          sourceName: "request",
        },
        usages: [
          {
            targetObj: {
              name: "FormValue",
              resolvedMethod: "net/http.Request.FormValue",
              code: 'r.FormValue("extra")',
              label: "CALL",
              lineNumber: 22,
            },
          },
          {
            targetObj: {
              name: "Context",
              resolvedMethod: "net/http.Request.Context",
              code: "r.Context()",
              label: "CALL",
              lineNumber: 23,
            },
          },
          {
            targetObj: {
              name: "WriteHeader",
              resolvedMethod: "net/http.ResponseWriter.WriteHeader",
              code: "w.WriteHeader(http.StatusInternalServerError)",
              label: "CALL",
              lineNumber: 24,
            },
          },
          {
            targetObj: {
              name: "FileServer",
              resolvedMethod: "net/http.FileServer",
              code: "http.FileServer(http.Dir(templateDir))",
              label: "CALL",
              lineNumber: 25,
            },
          },
        ],
      },
    ],
  };
}

function realJoernUsageSlices() {
  return {
    objectSlices: [
      {
        fullName: "src/lib/fetcher.js::program",
        fileName: "src/lib/fetcher.js",
        lineNumber: 1,
        usages: [],
      },
      {
        fullName: "src/lib/fetcher.js::program:fetchUrl",
        fileName: "src/lib/fetcher.js",
        lineNumber: 1,
        usages: [
          {
            targetObj: {
              name: "url",
              typeFullName: "ANY",
              position: 1,
              lineNumber: 1,
              label: "PARAM",
            },
            invokedCalls: [
              {
                callName: "fetch",
                resolvedMethod: "fetch",
                isExternal: true,
                lineNumber: 2,
              },
            ],
          },
          {
            targetObj: {
              name: "fetch",
              resolvedMethod: "fetch",
              isExternal: true,
              lineNumber: 2,
              label: "CALL",
            },
          },
        ],
      },
      {
        fullName: "src/routes/proxy.js::program",
        fileName: "src/routes/proxy.js",
        lineNumber: 1,
        usages: [
          {
            targetObj: {
              name: "require",
              resolvedMethod: "src/routes/proxy.js::program:require",
              isExternal: true,
              lineNumber: 1,
              label: "CALL",
            },
          },
        ],
      },
      {
        fullName: "src/routes/proxy.js::program:proxyHandler",
        fileName: "src/routes/proxy.js",
        lineNumber: 3,
        usages: [
          {
            targetObj: {
              name: "fetchUrl",
              resolvedMethod: "src/routes/proxy.js::program:fetchUrl",
              isExternal: true,
              lineNumber: 4,
              label: "CALL",
            },
          },
        ],
      },
    ],
  };
}

function realJoernReachabilitySlices() {
  return [
    {
      flows: [
        {
          id: 41,
          label: "METHOD_PARAMETER_IN",
          name: "req",
          parentMethodName: "proxyHandler",
          parentFileName: "src/routes/proxy.js",
          parentClassName: "src/routes/proxy.js::program",
          lineNumber: 3,
          tags: "framework-input",
        },
      ],
      purls: [],
    },
  ];
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
    backend: "joern",
    backendVersion: "joern@4.0.565",
    kind,
    language: "typescript",
    modelArtifact: { blobSha256: "model-sha", role: "program-analysis.raw", bytes: 10 },
    sliceArtifact,
    slicePath: `/work/vibeshield/joern-${kind}.json`,
    command: ["vibeshield-joern-extract", "--kind", kind],
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
      { path: "src/routes/proxy.js", size: 120, sha256: "proxy-sha" },
      { path: "src/lib/fetcher.js", size: 90, sha256: "fetcher-sha" },
      { path: "server.ts", size: 160, sha256: "server-sha" },
      { path: "routes/fileUpload.ts", size: 140, sha256: "file-upload-sha" },
      { path: "lib/xml.ts", size: 80, sha256: "xml-sha" },
      { path: "src/lib/one.ts", size: 70, sha256: "one-sha" },
      { path: "src/lib/two.ts", size: 75, sha256: "two-sha" },
      { path: "src/main/java/example/Lesson.java", size: 140, sha256: "lesson-sha" },
      { path: "src/main/java/example/XssController.java", size: 140, sha256: "xss-sha" },
      {
        path: "src/main/java/example/IDORViewOtherProfile.java",
        size: 140,
        sha256: "idor-sha",
      },
      { path: "src/main/java/example/ForgedReviews.java", size: 140, sha256: "csrf-sha" },
      { path: "src/main/java/example/Job.java", size: 90, sha256: "job-sha" },
      { path: "src/main/java/example/Crypto.java", size: 90, sha256: "crypto-sha" },
      { path: "src/main/java/example/Profile.java", size: 90, sha256: "profile-java-sha" },
      {
        path: "src/main/java/example/jwt/JwtController.java",
        size: 90,
        sha256: "jwt-java-sha",
      },
      {
        path: "src/main/java/example/auth/VerifyAccount.java",
        size: 90,
        sha256: "auth-java-sha",
      },
      { path: "src/main/java/example/Controller.java", size: 100, sha256: "controller-sha" },
      { path: "src/app/service.ts", size: 100, sha256: "service-sha" },
      { path: "apps/web/src/lib/api-client.ts", size: 100, sha256: "web-client-sha" },
      { path: "apps/web/src/lib/external-links.ts", size: 100, sha256: "external-links-sha" },
      { path: "routes/proxy.ts", size: 100, sha256: "proxy-ts-sha" },
      { path: "routes/api.ts", size: 100, sha256: "api-sha" },
      { path: "routes/profile.ts", size: 100, sha256: "profile-sha" },
      { path: "routes/basket.ts", size: 100, sha256: "basket-sha" },
      { path: "routes/basketItems.ts", size: 100, sha256: "basket-items-sha" },
      { path: "routes/redirect.ts", size: 100, sha256: "redirect-sha" },
      { path: "routes/search.ts", size: 100, sha256: "search-sha" },
      { path: "frontend/src/app/search.component.ts", size: 100, sha256: "search-component-sha" },
      { path: "app.py", size: 100, sha256: "python-sha" },
      { path: "main.go", size: 100, sha256: "go-sha" },
    ],
    exclusions: [],
    toolchain: {
      imageTag: "vibeshield-toolchain:test",
      tools: [],
    },
    createdAt: "2026-06-24T10:00:00.000Z",
  };
}
