import { describe, expect, it } from "vitest";
import type { RemediationAction } from "../src/domain/action.js";
import type { Evidence } from "../src/domain/evidence.js";
import type { Finding } from "../src/domain/finding.js";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
import {
  hypothesisEnrichmentId,
  validateHypothesisEnrichments,
} from "../src/domain/hypothesis-enrichment.js";
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
import type { StaticHypothesis } from "../src/domain/static-hypothesis.js";
import { type ValidationRecipe, validationRecipeId } from "../src/domain/validation-recipe.js";
import type {
  ModelEnhanceBatchInput,
  ModelHypothesisEnrichBatchInput,
  ModelHypothesisEnrichment,
  ModelProvider,
} from "../src/ports/model-provider.js";
import { enrichStaticHypotheses } from "../src/stages/hypothesis-enrichment.js";

const GRAPH_VERSION = "1";

describe("enrichStaticHypotheses fallback", () => {
  it("returns deterministic catalog enrichment when the model is unavailable", async () => {
    const fixture = enrichmentFixture();
    const model = new FakeModel({ available: false });

    const first = await enrichStaticHypotheses({
      repositoryName: "repo",
      model,
      staticHypotheses: [fixture.hypothesis],
      candidates: [fixture.candidate],
      graph: fixture.graph,
      validationRecipes: [fixture.recipe],
      findings: [fixture.finding],
      evidence: [fixture.evidence],
    });
    const second = await enrichStaticHypotheses({
      repositoryName: "repo",
      model,
      staticHypotheses: [fixture.hypothesis],
      candidates: [fixture.candidate],
      graph: fixture.graph,
      validationRecipes: [fixture.recipe],
      findings: [fixture.finding],
      evidence: [fixture.evidence],
    });

    expect(model.hypothesisInputs).toEqual([]);
    expect(first).toEqual([
      expect.objectContaining({
        id: hypothesisEnrichmentId(fixture.hypothesis.id),
        hypothesisId: fixture.hypothesis.id,
        source: "catalog",
        validationRecipeText: expect.stringContaining("Required fixtures:"),
      }),
    ]);
    expect(first[0]?.attackDescription).toContain(
      "Untrusted input can reach a sensitive operation",
    );
    expect(first[0]?.attackDescription).not.toContain("graph edges");
    expect(first[0]?.agentPrompt).toContain("src/proxy.ts");
    expect(first[0]?.agentPrompt).not.toContain(fixture.hypothesis.id);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it("valid model output improves copy fields without changing deterministic facts", async () => {
    const fixture = enrichmentFixture();
    const model = new FakeModel({
      response: () => [
        {
          hypothesisId: fixture.hypothesis.id,
          attackDescription: "A clearer static attack description.",
          assumptions: ["Only supplied graph refs were used."],
          impact: "A clearer static impact statement.",
          remediation: "Add an allowlist before the outbound request.",
          agentPrompt: "Patch hypothesis hypothesis-1 using the supplied graph refs.",
          acceptanceCriteria: ["The path is blocked by a deterministic control."],
          validationRecipeText: "Use the supplied disposable fixtures later.",
        },
      ],
    });

    const result = await enrichStaticHypotheses({
      repositoryName: "repo",
      model,
      staticHypotheses: [fixture.hypothesis],
      candidates: [fixture.candidate],
      graph: fixture.graph,
      validationRecipes: [fixture.recipe],
      findings: [fixture.finding],
      evidence: [fixture.evidence],
    });

    expect(result).toEqual([
      {
        id: hypothesisEnrichmentId(fixture.hypothesis.id),
        hypothesisId: fixture.hypothesis.id,
        source: "model",
        attackDescription: "A clearer static attack description.",
        assumptions: ["Only supplied graph refs were used."],
        impact: "A clearer static impact statement.",
        remediation: "Add an allowlist before the outbound request.",
        agentPrompt: "Patch hypothesis hypothesis-1 using the supplied graph refs.",
        acceptanceCriteria: ["The path is blocked by a deterministic control."],
        validationRecipeText: "Use the supplied disposable fixtures later.",
      },
    ]);
    expect(model.hypothesisInputs[0]?.hypotheses[0]).toMatchObject({
      hypothesisId: fixture.hypothesis.id,
      candidateId: fixture.candidate.id,
      status: fixture.hypothesis.status,
      staticConfidence: fixture.hypothesis.staticConfidence,
      supportingEdgeIds: expect.arrayContaining([...fixture.candidate.supportingEdgeIds]),
      catalogEnrichment: expect.objectContaining({ hypothesisId: fixture.hypothesis.id }),
    });
  });

  it("falls back for missing, duplicate, unknown, prohibited, or unsafe model output", async () => {
    const fixture = enrichmentFixture();
    const fixture2 = enrichmentFixture({ suffix: "2", confidence: 0.7 });
    const inputs = {
      repositoryName: "repo",
      staticHypotheses: [fixture.hypothesis, fixture2.hypothesis],
      candidates: [fixture.candidate, fixture2.candidate],
      graph: mergeGraphs(fixture.graph, fixture2.graph),
      validationRecipes: [fixture.recipe, fixture2.recipe],
      findings: [fixture.finding, fixture2.finding],
      evidence: [fixture.evidence, fixture2.evidence],
    };
    for (const { response, sources } of [
      {
        response: [modelOutput("missing-hypothesis"), modelOutput(fixture2.hypothesis.id)],
        sources: ["catalog", "model"],
      },
      {
        response: [modelOutput(fixture.hypothesis.id), modelOutput(fixture.hypothesis.id)],
        sources: ["model", "catalog"],
      },
      {
        response: [
          {
            ...modelOutput(fixture.hypothesis.id),
            status: "confirmed",
          } as ModelHypothesisEnrichment,
          modelOutput(fixture2.hypothesis.id),
        ],
        sources: ["catalog", "model"],
      },
      {
        response: [
          {
            ...modelOutput(fixture.hypothesis.id),
            graphRefs: ["new-edge"],
          } as ModelHypothesisEnrichment,
          modelOutput(fixture2.hypothesis.id),
        ],
        sources: ["catalog", "model"],
      },
      {
        response: [
          {
            ...modelOutput(fixture.hypothesis.id),
            attackDescription: "Runtime confirmed exploit.",
          },
          modelOutput(fixture2.hypothesis.id),
        ],
        sources: ["catalog", "model"],
      },
    ] as const) {
      const result = await enrichStaticHypotheses({
        ...inputs,
        model: new FakeModel({ response: () => response }),
      });

      expect(result.map((record) => record.source)).toEqual(sources);
    }

    const allInvalid = await enrichStaticHypotheses({
      ...inputs,
      model: new FakeModel({ response: () => [modelOutput("missing-hypothesis")] }),
    });

    expect(allInvalid.map((record) => record.source)).toEqual(["catalog", "catalog"]);

    const partial = await enrichStaticHypotheses({
      ...inputs,
      model: new FakeModel({
        response: (input) =>
          input.hypotheses[0]?.hypothesisId === fixture.hypothesis.id
            ? [modelOutput(fixture.hypothesis.id)]
            : [modelOutput("missing-hypothesis")],
      }),
    });

    expect(partial.map((record) => record.source)).toEqual(["model", "catalog"]);
  });

  it("bounds, redacts, and truncates model input while preserving top hypothesis order", async () => {
    const lower = enrichmentFixture({ suffix: "lower", confidence: 0.6 });
    const higher = enrichmentFixture({
      suffix: "higher",
      confidence: 0.95,
      snippet: `api_key=${"x".repeat(32)} ${"a".repeat(700)}`,
    });
    const model = new FakeModel({
      response: (input) => input.hypotheses.map(modelOutputFromInput),
    });

    const result = await enrichStaticHypotheses({
      repositoryName: "repo",
      model,
      staticHypotheses: [lower.hypothesis, higher.hypothesis],
      candidates: [lower.candidate, higher.candidate],
      graph: mergeGraphs(lower.graph, higher.graph),
      validationRecipes: [lower.recipe, higher.recipe],
      findings: [lower.finding, higher.finding],
      evidence: [lower.evidence, higher.evidence],
      maxHypotheses: 1,
    });

    expect(result).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          hypothesisId: lower.hypothesis.id,
          source: "catalog",
        }),
        expect.objectContaining({
          hypothesisId: higher.hypothesis.id,
          source: "model",
          attackDescription: expect.stringContaining(higher.hypothesis.id),
        }),
      ]),
    );
    expect(result).toHaveLength(2);

    const modelHypotheses = model.hypothesisInputs[0]?.hypotheses ?? [];
    expect(modelHypotheses).toHaveLength(1);
    expect(modelHypotheses[0]?.hypothesisId).toBe(higher.hypothesis.id);
    expect(modelHypotheses[0]?.evidenceSnippets[0]?.snippet).toContain("***REDACTED***");
    expect(modelHypotheses[0]?.evidenceSnippets[0]?.snippet).toContain("[truncated]");
    expect(modelHypotheses[0]?.graphRefs.length).toBeGreaterThan(0);
    expect(modelHypotheses[0]?.validationRecipe?.requiredFixtures).toEqual([
      "boundary_input_fixture",
    ]);
  });

  it("reports bounded model enrichment progress per hypothesis batch", async () => {
    const first = enrichmentFixture({ suffix: "first", confidence: 0.9 });
    const second = enrichmentFixture({ suffix: "second", confidence: 0.8 });
    const progress: Array<{
      completed: number;
      total: number;
      completedBatches: number;
      totalBatches: number;
    }> = [];
    const model = new FakeModel({
      response: (input) => input.hypotheses.map(modelOutputFromInput),
    });

    const result = await enrichStaticHypotheses({
      repositoryName: "repo",
      model,
      staticHypotheses: [first.hypothesis, second.hypothesis],
      candidates: [first.candidate, second.candidate],
      graph: mergeGraphs(first.graph, second.graph),
      validationRecipes: [first.recipe, second.recipe],
      findings: [first.finding, second.finding],
      evidence: [first.evidence, second.evidence],
      onModelProgress: (event) => {
        progress.push(event);
      },
    });

    expect(result.map((record) => record.source)).toEqual(["model", "model"]);
    expect(model.hypothesisInputs).toHaveLength(1);
    expect(model.hypothesisInputs[0]?.hypotheses).toHaveLength(2);
    expect(progress[0]).toEqual({
      completed: 0,
      total: 2,
      completedBatches: 0,
      totalBatches: 1,
    });
    expect(progress.at(-1)).toEqual({
      completed: 2,
      total: 2,
      completedBatches: 1,
      totalBatches: 1,
    });
    expect(progress.map((event) => event.completed)).toEqual([0, 2]);
    expect(progress.map((event) => event.completedBatches)).toEqual([0, 1]);
  });

  it("splits an invalid model batch so one bad response does not drop the whole batch", async () => {
    const first = enrichmentFixture({ suffix: "first", confidence: 0.9 });
    const second = enrichmentFixture({ suffix: "second", confidence: 0.8 });
    const model = new FakeModel({
      response: (input) => {
        if (input.hypotheses.length > 1) {
          return null;
        }
        const hypothesisId = input.hypotheses[0]?.hypothesisId;
        return hypothesisId === first.hypothesis.id ? [modelOutput(hypothesisId)] : null;
      },
    });

    const result = await enrichStaticHypotheses({
      repositoryName: "repo",
      model,
      staticHypotheses: [first.hypothesis, second.hypothesis],
      candidates: [first.candidate, second.candidate],
      graph: mergeGraphs(first.graph, second.graph),
      validationRecipes: [first.recipe, second.recipe],
      findings: [first.finding, second.finding],
      evidence: [first.evidence, second.evidence],
    });

    expect(result.map((record) => record.source)).toEqual(["model", "catalog"]);
    expect(model.hypothesisInputs.map((input) => input.hypotheses.length)).toEqual([2, 1, 1]);
  });
});

describe("validateHypothesisEnrichments", () => {
  it("rejects unknown hypothesis ids", () => {
    expect(() =>
      validateHypothesisEnrichments([catalogRecord("hypothesis-1")], {
        hypothesisIds: ["other"],
      }),
    ).toThrow(/unknown hypothesis: hypothesis-1/);
  });
});

interface Fixture {
  readonly graph: SecurityGraph;
  readonly candidate: HypothesisCandidate;
  readonly hypothesis: StaticHypothesis;
  readonly recipe: ValidationRecipe;
  readonly finding: Finding;
  readonly evidence: Evidence;
}

function enrichmentFixture(
  opts: { readonly suffix?: string; readonly confidence?: number; readonly snippet?: string } = {},
): Fixture {
  const suffix = opts.suffix ?? "1";
  const boundary = node("Boundary", `Boundary:${suffix}:GET /proxy`, `GET /proxy ${suffix}`);
  const handler = node("CodeEntity", `CodeEntity:${suffix}:proxy`, `proxyHandler ${suffix}`);
  const sink = node("Sink", `Sink:${suffix}:fetch`, `fetch ${suffix}`);
  const receives = edge("receives", boundary, handler, `receives:${suffix}:proxy`);
  const calls = edge("calls", handler, sink, `calls:${suffix}:fetch`);
  const graph: SecurityGraph = {
    id: securityGraphId(`snapshot-${suffix}`, GRAPH_VERSION),
    runId: `run-${suffix}`,
    snapshotId: `snapshot-${suffix}`,
    graphVersion: GRAPH_VERSION,
    nodes: [boundary, handler, sink],
    edges: [receives, calls],
    flows: [],
    coverage: [],
    createdAt: "2026-06-24T10:00:00.000Z",
  };
  const evidence: Evidence = {
    id: `evidence-${suffix}`,
    rawArtifactBlobSha256: `blob-${suffix}`,
    filePath: "src/proxy.ts",
    startLine: 12,
    endLine: 16,
    snippet: opts.snippet ?? "fetch(req.query.url)",
    snippetHash: `snippet-${suffix}`,
    tool: "test-tool",
  };
  const finding: Finding = {
    id: `finding-${suffix}`,
    sourceTool: "semgrep",
    ruleId: "ssrf",
    category: "code-pattern",
    severity: "high",
    confidence: "medium",
    locations: [{ filePath: "src/proxy.ts", startLine: 12, endLine: 16 }],
    evidenceIds: [evidence.id],
    fingerprint: `finding-fingerprint-${suffix}`,
    remediationKey: "ssrf-review",
  };
  const candidate: HypothesisCandidate = {
    id: `candidate-${suffix}`,
    ruleId: "stage2.external-input-dangerous-operation",
    family: "external_input_to_dangerous_operation",
    title: `External input reaches outbound fetch ${suffix}`,
    findingIds: [finding.id],
    supportingNodeIds: [boundary.id, handler.id, sink.id],
    supportingEdgeIds: [receives.id, calls.id],
    contradictingNodeIds: [],
    contradictingEdgeIds: [],
    coverageRefs: ["stage2:call_graph:checked"],
    requiredValidation: ["boundary_input_fixture"],
    candidateReason: "Boundary input can reach outbound fetch.",
  };
  const hypothesis: StaticHypothesis = {
    id: `hypothesis-${suffix}`,
    candidateId: candidate.id,
    status: "statically_supported",
    staticConfidence: opts.confidence ?? 0.85,
    title: candidate.title,
    pathSummary: `Static graph supports outbound fetch path ${suffix}.`,
    supportingEvidenceIds: [evidence.id],
    contradictingEvidenceIds: [],
    coverageState: "checked",
    runtimeValidationRequired: true,
  };
  const recipe: ValidationRecipe = {
    id: validationRecipeId(hypothesis.id),
    hypothesisId: hypothesis.id,
    requiredFixtures: ["boundary_input_fixture"],
    steps: ["Prepare a disposable route input."],
    expectedResult: "Runtime validation should gather evidence later.",
    safetyNotes: ["Do not run against production."],
    materializationHints: ["factory:proxy-route"],
    knownGaps: [],
  };

  return { graph, candidate, hypothesis, recipe, finding, evidence };
}

function modelOutput(hypothesisId: string): ModelHypothesisEnrichment {
  return {
    hypothesisId,
    attackDescription: `Model attack description for ${hypothesisId}.`,
    assumptions: ["Assumption from supplied facts."],
    impact: "Model static impact.",
    remediation: "Model remediation.",
    agentPrompt: `Patch ${hypothesisId}.`,
    acceptanceCriteria: ["Model acceptance criterion."],
    validationRecipeText: "Model validation recipe text.",
  };
}

function modelOutputFromInput(input: ModelHypothesisEnrichBatchInput["hypotheses"][number]) {
  return modelOutput(input.hypothesisId);
}

function catalogRecord(hypothesisId: string) {
  return {
    id: hypothesisEnrichmentId(hypothesisId),
    hypothesisId,
    source: "catalog" as const,
    attackDescription: "attack",
    assumptions: ["assumption"],
    impact: "impact",
    remediation: "remediation",
    agentPrompt: "prompt",
    acceptanceCriteria: ["criterion"],
    validationRecipeText: "recipe",
  };
}

function mergeGraphs(first: SecurityGraph, second: SecurityGraph): SecurityGraph {
  return {
    ...first,
    nodes: [...first.nodes, ...second.nodes],
    edges: [...first.edges, ...second.edges],
  };
}

function node(
  kind: SecurityGraphNode["kind"],
  stableKey: string,
  label: string,
): SecurityGraphNode {
  return {
    id: securityGraphNodeId(GRAPH_VERSION, stableKey),
    kind,
    stableKey,
    label,
    repoPath: "src/proxy.ts",
    lineRange: { startLine: 1, endLine: 1 },
    symbol: label,
    properties: {},
    evidenceIds: [],
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
    id: securityGraphEdgeId(GRAPH_VERSION, stableKey),
    kind,
    stableKey,
    fromNodeId: from.id,
    toNodeId: to.id,
    properties: {},
    evidenceIds: [],
    producer: "test-fixture",
    producerVersion: GRAPH_VERSION,
    confidence: 1,
    coverageState: "checked",
  };
}

class FakeModel implements ModelProvider {
  readonly hypothesisInputs: ModelHypothesisEnrichBatchInput[] = [];

  constructor(
    private readonly opts: {
      readonly available?: boolean;
      readonly response?: (
        input: ModelHypothesisEnrichBatchInput,
      ) => ReadonlyArray<ModelHypothesisEnrichment> | null;
    } = {},
  ) {}

  async isAvailable(): Promise<boolean> {
    return this.opts.available ?? true;
  }

  async enhance(_input: ModelEnhanceBatchInput): Promise<ReadonlyArray<RemediationAction> | null> {
    return null;
  }

  async enrichHypotheses(
    input: ModelHypothesisEnrichBatchInput,
  ): Promise<ReadonlyArray<ModelHypothesisEnrichment> | null> {
    this.hypothesisInputs.push(input);
    return this.opts.response?.(input) ?? null;
  }
}
