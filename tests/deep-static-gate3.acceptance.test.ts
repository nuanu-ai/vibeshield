import { describe, expect, it } from "vitest";
import type { Finding, FindingCategory, Severity } from "../src/domain/finding.js";
import type { Manifest } from "../src/domain/manifest.js";
import type {
  GraphCoverage,
  LineRange,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphEdgeKind,
  SecurityGraphNode,
} from "../src/domain/security-graph.js";
import {
  securityGraphEdgeId,
  securityGraphId,
  securityGraphNodeId,
} from "../src/domain/security-graph.js";
import { composeCiIacContext } from "../src/stages/ci-iac-context.js";
import { composeComponentReachability } from "../src/stages/component-reachability.js";
import { assessFindingContext } from "../src/stages/finding-context-assessment.js";
import {
  correlateStage2Hypotheses,
  STAGE2_HYPOTHESIS_FAMILIES,
  type Stage2HypothesisFamily,
} from "../src/stages/stage2-hypothesis-rules.js";
import { validateStaticHypotheses } from "../src/stages/static-hypothesis-validator.js";

const GRAPH_VERSION = "gate3-v1";
const RUN_ID = "run-gate3";
const SNAPSHOT_ID = "snapshot-gate3";
const CREATED_AT = "2026-06-24T10:00:00.000Z";

describe("Deep Static Gate 3 acceptance", () => {
  it("supports all planned families from deterministic graph evidence", () => {
    const first = gate3Result();
    const second = gate3Result();
    const candidatesById = new Map(first.candidates.map((candidate) => [candidate.id, candidate]));
    const supported = first.staticHypotheses.filter(
      (hypothesis) => hypothesis.status === "statically_supported",
    );
    const supportedFamilySet = new Set(
      supported.flatMap((hypothesis) => {
        const family = candidatesById.get(hypothesis.candidateId)?.family;
        return isStage2Family(family) ? [family] : [];
      }),
    );
    const supportedFamilies = STAGE2_HYPOTHESIS_FAMILIES.filter((family) =>
      supportedFamilySet.has(family),
    );

    expect(supportedFamilies).toEqual([...STAGE2_HYPOTHESIS_FAMILIES]);
    expect(JSON.stringify(first.staticHypotheses)).toBe(JSON.stringify(second.staticHypotheses));

    for (const family of STAGE2_HYPOTHESIS_FAMILIES) {
      const hypothesis = supported.find(
        (item) => candidatesById.get(item.candidateId)?.family === family,
      );
      const candidate =
        hypothesis === undefined ? undefined : candidatesById.get(hypothesis.candidateId);
      expect(candidate, `candidate for ${family}`).toBeDefined();
      expect(hypothesis, `hypothesis for ${family}`).toMatchObject({
        status: "statically_supported",
        runtimeValidationRequired: true,
      });
      expect(candidate?.supportingNodeIds.length).toBeGreaterThan(0);
      expect(candidate?.supportingEdgeIds.length).toBeGreaterThan(0);
      expect(candidate?.coverageRefs.length).toBeGreaterThan(0);
      expect(candidate?.requiredValidation.length).toBeGreaterThan(0);
      expect(hypothesis?.supportingEvidenceIds.length).toBeGreaterThan(0);
      if (
        family !== "external_input_to_dangerous_operation" &&
        family !== "content_resource_exposure_path" &&
        family !== "smart_contract_risk_path"
      ) {
        expect(candidate?.findingIds.length).toBeGreaterThan(0);
      }
    }

    expect(contextByFinding(first).get("finding-sast")).toMatchObject({
      status: "corroborated",
    });
    expect(contextByFinding(first).get("finding-dependency")).toMatchObject({
      status: "corroborated",
      reason: "component reachability corroborates the dependency finding",
    });
    expect(contextByFinding(first).get("finding-ci")).toMatchObject({
      status: "corroborated",
    });
    expect(contextByFinding(first).get("finding-secret")).toMatchObject({
      status: "corroborated",
    });
  });

  it("does not promote a dependency usage path without required graph evidence", () => {
    const result = gate3Result({ omitDependencyUsage: true });
    const candidatesById = new Map(result.candidates.map((candidate) => [candidate.id, candidate]));
    const dependencyHypotheses = result.staticHypotheses.filter(
      (hypothesis) =>
        candidatesById.get(hypothesis.candidateId)?.family === "dependency_usage_path",
    );

    expect(dependencyHypotheses).toEqual([]);
    expect(contextByFinding(result).get("finding-dependency")).toMatchObject({
      status: "weakened",
      reason: "component is present but no import, use, or boundary reachability was observed",
    });
  });

  it("marks contradicted graph evidence as statically contradicted", () => {
    const result = gate3Result({ addExternalContradiction: true });
    const candidatesById = new Map(result.candidates.map((candidate) => [candidate.id, candidate]));
    const externalHypotheses = result.staticHypotheses.filter(
      (hypothesis) =>
        candidatesById.get(hypothesis.candidateId)?.family ===
        "external_input_to_dangerous_operation",
    );

    expect(externalHypotheses.length).toBeGreaterThan(0);
    expect(
      externalHypotheses.every((hypothesis) => hypothesis.status === "statically_contradicted"),
    ).toBe(true);
    expect(
      externalHypotheses.every((hypothesis) => hypothesis.contradictingEvidenceIds.length > 0),
    ).toBe(true);
  });
});

interface Gate3Options {
  readonly omitDependencyUsage?: boolean;
  readonly addExternalContradiction?: boolean;
}

function gate3Result(options: Gate3Options = {}) {
  const manifest = gate3Manifest();
  const graphWithCi = composeCiIacContext({
    graph: baseGraph(options),
    manifest,
    workflows: [workflowObservation()],
  });
  const reachability = composeComponentReachability({ graph: graphWithCi, manifest });
  const findings = gate3Findings();
  const contexts = assessFindingContext({
    findings,
    graph: reachability.graph,
    componentReachability: reachability.reachability,
  });
  const candidates = correlateStage2Hypotheses({
    graph: reachability.graph,
    findingContexts: contexts,
    maxCandidatesPerRule: 5,
  });
  return {
    graph: reachability.graph,
    contexts,
    candidates,
    staticHypotheses: validateStaticHypotheses({ graph: reachability.graph, candidates }),
  };
}

function baseGraph(options: Gate3Options): SecurityGraph {
  const source = node("Source", "Source:request-url", "request.url", {
    repoPath: "src/app.ts",
    properties: { sourceType: "external_input" },
    evidenceIds: ["ev-boundary"],
  });
  const boundary = node("Boundary", "Boundary:GET /proxy", "GET /proxy", {
    repoPath: "src/app.ts",
    properties: { boundaryType: "HTTP route", routeOrName: "GET /proxy", method: "GET" },
    evidenceIds: ["ev-boundary"],
  });
  const handler = node("CodeEntity", "CodeEntity:proxyHandler", "proxyHandler", {
    repoPath: "src/app.ts",
    properties: { fullName: "proxyHandler" },
    evidenceIds: ["ev-handler"],
  });
  const sink = node("Sink", "Sink:fetch", "fetch", {
    repoPath: "src/app.ts",
    properties: { sinkType: "outbound_http", callName: "fetch" },
    evidenceIds: ["ev-sink"],
  });
  const sastTarget = node("CodeEntity", "CodeEntity:unsafeLookup", "unsafeLookup", {
    repoPath: "src/app.ts",
    properties: { fullName: "unsafeLookup" },
    evidenceIds: ["ev-sast-code"],
  });
  const component = node("Component", "Component:lodash", "lodash", {
    properties: { packageName: "lodash", version: "4.17.20" },
    evidenceIds: ["ev-dependency"],
  });
  const secret = node("Secret", "Secret:stripe-key", "stripe key", {
    repoPath: "src/config.ts",
    properties: { ruleId: "stripe-access-token" },
    evidenceIds: ["ev-secret"],
  });
  const service = node("ExternalService", "ExternalService:stripe", "Stripe API", {
    properties: { serviceType: "payment_provider" },
    evidenceIds: ["ev-secret-impact"],
  });
  const contentResource = node(
    "Resource",
    "ContentResource:obfuscated-token-route",
    "Obfuscated token sale route",
    {
      repoPath: "src/app.ts",
      properties: {
        resourceType: "content_resource",
        exposureType: "obfuscated_frontend_route",
      },
      evidenceIds: ["ev-content"],
    },
  );
  const contentSink = node(
    "Sink",
    "ContentSink:obfuscated-token-route",
    "Hidden content exposure",
    {
      repoPath: "src/app.ts",
      properties: {
        sinkType: "hidden_content_exposure",
        exposureType: "obfuscated_frontend_route",
      },
      evidenceIds: ["ev-content"],
    },
  );
  const smartContract = node("Resource", "SmartContract:Bank", "Bank", {
    repoPath: "contracts/Bank.sol",
    properties: {
      resourceType: "smart_contract",
      contractName: "Bank",
    },
    evidenceIds: ["ev-contract"],
  });
  const smartContractSink = node(
    "Sink",
    "SmartContractRisk:Bank:withdraw",
    "Bank.withdraw sends value before updating balances",
    {
      repoPath: "contracts/Bank.sol",
      properties: {
        sinkType: "smart_contract_reentrancy",
        riskType: "reentrancy_value_transfer_before_state_update",
      },
      evidenceIds: ["ev-contract"],
    },
  );
  const control =
    options.addExternalContradiction === true
      ? node("Control", "Control:destination-allowlist", "destination allowlist", {
          repoPath: "src/app.ts",
          properties: { controlType: "destination_allowlist" },
          evidenceIds: ["ev-control"],
        })
      : undefined;
  const findings = findingNodes();
  const edges = [
    edge("receives", source, boundary, "receives:request:proxy", ["ev-boundary"]),
    edge("registers", boundary, handler, "registers:proxy:handler", ["ev-boundary"]),
    edge("calls", handler, sink, "calls:handler:fetch", ["ev-sink"]),
    edge("calls", handler, sastTarget, "calls:handler:unsafeLookup", ["ev-sast-code"]),
    ...(options.omitDependencyUsage === true
      ? []
      : [edge("uses", handler, component, "uses:handler:lodash", ["ev-component-usage"])]),
    edge("affects", findings.sast, sastTarget, "affects:finding-sast:unsafeLookup", ["ev-sast"]),
    edge("supported_by", findings.sast, sastTarget, "supported_by:finding-sast:unsafeLookup", [
      "ev-sast",
    ]),
    edge("affects", findings.dependency, component, "affects:finding-dependency:lodash", [
      "ev-dependency",
    ]),
    edge("affects", findings.secret, secret, "affects:finding-secret:stripe-key", ["ev-secret"]),
    edge("uses", secret, service, "uses:secret:stripe", ["ev-secret-impact"]),
    edge("supported_by", findings.secret, service, "supported_by:finding-secret:stripe", [
      "ev-secret-impact",
    ]),
    edge("exposes", contentResource, contentSink, "exposes:content:hidden-route", ["ev-content"]),
    edge("flows_to", smartContract, smartContractSink, "flows_to:contract:risk", ["ev-contract"]),
    ...(control === undefined
      ? []
      : [edge("protected_by", handler, control, "protected_by:handler:allowlist", ["ev-control"])]),
  ];

  return {
    id: securityGraphId(SNAPSHOT_ID, GRAPH_VERSION),
    runId: RUN_ID,
    snapshotId: SNAPSHOT_ID,
    graphVersion: GRAPH_VERSION,
    nodes: [
      source,
      boundary,
      handler,
      sink,
      sastTarget,
      component,
      secret,
      service,
      contentResource,
      contentSink,
      smartContract,
      smartContractSink,
      ...(control === undefined ? [] : [control]),
      ...Object.values(findings),
    ],
    edges,
    flows: [],
    coverage: checkedCoverage(),
    createdAt: CREATED_AT,
  };
}

function findingNodes() {
  return {
    sast: findingNode("finding-sast", "src/app.ts", "ev-sast"),
    dependency: findingNode("finding-dependency", "package.json", "ev-dependency"),
    ci: findingNode("finding-ci", ".github/workflows/ci.yml", "ev-ci"),
    secret: findingNode("finding-secret", "src/config.ts", "ev-secret"),
  };
}

function workflowObservation() {
  return {
    workflowPath: ".github/workflows/ci.yml",
    name: "ci",
    evidenceIds: ["ev-workflow"],
    lineRange: { startLine: 1, endLine: 40 },
    findingIds: ["finding-ci"],
    triggers: [{ event: "pull_request", evidenceIds: ["ev-trigger"] }],
    steps: [
      {
        id: "publish",
        name: "Upload artifact",
        uses: "actions/upload-artifact@v3",
        pinned: false,
        evidenceIds: ["ev-step"],
        findingIds: ["finding-ci"],
      },
    ],
    tokenPermissions: [
      { stepId: "publish", scope: "contents", access: "write" as const, evidenceIds: ["ev-token"] },
    ],
    artifacts: [{ stepId: "publish", name: "dist", evidenceIds: ["ev-artifact"] }],
  };
}

function gate3Findings(): Finding[] {
  return [
    finding("finding-sast", "opengrep", "ssrf.fetch", "code-pattern", "high", "src/app.ts"),
    finding("finding-dependency", "trivy", "CVE-2024-1234", "dependency", "high", "package.json"),
    finding(
      "finding-ci",
      "zizmor",
      "unpinned-action",
      "github-action",
      "medium",
      ".github/workflows/ci.yml",
    ),
    finding(
      "finding-secret",
      "gitleaks",
      "stripe-access-token",
      "secret",
      "critical",
      "src/config.ts",
    ),
  ];
}

function finding(
  id: string,
  sourceTool: string,
  ruleId: string,
  category: FindingCategory,
  severity: Severity,
  filePath: string,
): Finding {
  return {
    id,
    sourceTool,
    ruleId,
    category,
    severity,
    confidence: "high",
    locations: [{ filePath, startLine: 1, endLine: 1 }],
    evidenceIds: [`ev-${id.replace(/^finding-/, "")}`],
    fingerprint: `${sourceTool}:${ruleId}:${filePath}:1`,
    remediationKey:
      category === "secret"
        ? "live-secret-in-source"
        : category === "dependency"
          ? "dependency-vulnerability"
          : category === "github-action"
            ? "github-actions-hardening"
            : "code-pattern-review",
  };
}

function findingNode(findingId: string, repoPath: string, evidenceId: string): SecurityGraphNode {
  return node("Finding", `Finding:${findingId}`, findingId, {
    repoPath,
    properties: { recordType: "finding", findingId },
    evidenceIds: [evidenceId],
  });
}

function node(
  kind: SecurityGraphNode["kind"],
  stableKey: string,
  label: string,
  options: {
    readonly repoPath?: string;
    readonly lineRange?: LineRange;
    readonly properties?: Readonly<Record<string, unknown>>;
    readonly evidenceIds?: ReadonlyArray<string>;
  } = {},
): SecurityGraphNode {
  return {
    id: securityGraphNodeId(GRAPH_VERSION, stableKey),
    kind,
    stableKey,
    label,
    ...(options.repoPath === undefined ? {} : { repoPath: options.repoPath }),
    lineRange: options.lineRange ?? { startLine: 1, endLine: 1 },
    symbol: label,
    properties: options.properties ?? {},
    evidenceIds: options.evidenceIds ?? [`ev-${stableKey}`],
    producer: "gate3-fixture",
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState: "checked",
  };
}

function edge(
  kind: SecurityGraphEdgeKind,
  from: SecurityGraphNode,
  to: SecurityGraphNode,
  stableKey: string,
  evidenceIds: ReadonlyArray<string>,
): SecurityGraphEdge {
  return {
    id: securityGraphEdgeId(GRAPH_VERSION, stableKey),
    kind,
    stableKey,
    fromNodeId: from.id,
    toNodeId: to.id,
    properties: {},
    evidenceIds,
    producer: "gate3-fixture",
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState: "checked",
  };
}

function checkedCoverage(): GraphCoverage[] {
  return [
    "boundaries",
    "call_graph",
    "data_flow",
    "dependency_usage",
    "ci_iac",
    "content_assets",
    "smart_contracts",
    "language_support",
  ].map((area) => ({
    area: area as GraphCoverage["area"],
    state: "checked",
    coveredCount: 1,
    totalCount: 1,
    producer: "gate3-fixture",
    producerVersion: GRAPH_VERSION,
  }));
}

function gate3Manifest(): Manifest {
  return {
    origin: { kind: "local", path: "/repo" },
    commitSha: "abc123",
    sourceHash: SNAPSHOT_ID,
    files: [
      { path: "src/app.ts", size: 120, sha256: "app-sha" },
      { path: "src/config.ts", size: 80, sha256: "config-sha" },
      { path: "package.json", size: 60, sha256: "package-sha" },
      { path: ".github/workflows/ci.yml", size: 120, sha256: "ci-sha" },
      { path: "contracts/Bank.sol", size: 120, sha256: "contract-sha" },
    ],
    exclusions: [],
    toolchain: { imageTag: "test-toolchain:latest", tools: [] },
    createdAt: CREATED_AT,
  };
}

function contextByFinding(result: ReturnType<typeof gate3Result>) {
  return new Map(result.contexts.map((context) => [context.findingId, context]));
}

function isStage2Family(value: unknown): value is Stage2HypothesisFamily {
  return (
    typeof value === "string" &&
    STAGE2_HYPOTHESIS_FAMILIES.includes(value as Stage2HypothesisFamily)
  );
}
