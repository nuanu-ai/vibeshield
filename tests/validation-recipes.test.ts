import { describe, expect, it } from "vitest";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
import type { StaticHypothesis } from "../src/domain/static-hypothesis.js";
import {
  type ValidationRecipe,
  validateValidationRecipes,
  validationRecipeId,
} from "../src/domain/validation-recipe.js";
import { composeValidationRecipes } from "../src/stages/validation-recipes.js";

describe("composeValidationRecipes", () => {
  it("creates a conservative recipe for a supported runtime-required hypothesis", () => {
    const candidateRecord = candidate({
      id: "candidate-supported",
      requiredValidation: ["boundary_input_fixture", "dangerous_operation_repro"],
    });
    const hypothesis = staticHypothesis(candidateRecord, {
      id: "hypothesis-supported",
      status: "statically_supported",
      supportingEvidenceIds: ["ev-edge"],
    });

    const result = composeValidationRecipes({
      staticHypotheses: [hypothesis],
      candidates: [candidateRecord],
    });

    expect(result).toEqual([
      expect.objectContaining({
        id: validationRecipeId(hypothesis.id),
        hypothesisId: hypothesis.id,
        requiredFixtures: ["boundary_input_fixture", "dangerous_operation_repro"],
        materializationHints: [
          "candidate:candidate-supported",
          "family:external_input_to_dangerous_operation",
          "finding:finding-1",
          "rule:stage2.external-input-dangerous-operation",
        ],
        knownGaps: [],
      }),
    ]);
    expect(result[0]?.steps).toEqual([
      "Prepare isolated runtime fixtures: boundary_input_fixture, dangerous_operation_repro.",
      `Replay the static path described by hypothesis ${hypothesis.id} against a disposable environment.`,
      "Record whether the expected protection blocks the impact without changing production data.",
    ]);
    expect(result[0]?.safetyNotes).toEqual([
      "Run only in an isolated disposable environment, never against production systems or real customer data.",
      "Use least-privilege credentials and reversible fixture changes only.",
    ]);
    expect(result[0]?.expectedResult).toContain("does not claim runtime confirmation");
    expect(result[0]?.expectedResult).not.toMatch(/\bconfirmed\b/i);
  });

  it("carries BOLA principal and owned-resource fixture requirements without runtime proof", () => {
    const candidateRecord = candidate({
      id: "candidate-bola",
      family: "external_input_to_dangerous_operation",
      title: "Cross-tenant object access reaches update sink",
      requiredValidation: ["principal_a", "principal_b", "owned_resource"],
    });
    const hypothesis = staticHypothesis(candidateRecord, {
      id: "hypothesis-bola",
      status: "candidate",
    });

    const result = composeValidationRecipes({
      staticHypotheses: [hypothesis],
      candidates: [candidateRecord],
    });

    expect(result[0]?.requiredFixtures).toEqual(["owned_resource", "principal_a", "principal_b"]);
    expect(result[0]?.expectedResult).toContain("prove or disprove this candidate");
    expect(result[0]?.expectedResult).not.toMatch(/\bconfirmed\b/i);
  });

  it("adds known static gaps to inconclusive recipes", () => {
    const candidateRecord = candidate({
      id: "candidate-inconclusive",
      requiredValidation: ["allowlist_runtime_check"],
    });
    const hypothesis = staticHypothesis(candidateRecord, {
      id: "hypothesis-inconclusive",
      status: "inconclusive",
      coverageState: "partial",
      pathSummary:
        "Static support is inconclusive because destination allowlist was not observed on the analyzed path.",
    });

    const result = composeValidationRecipes({
      staticHypotheses: [hypothesis],
      candidates: [candidateRecord],
    });

    expect(result[0]?.knownGaps).toEqual([hypothesis.pathSummary]);
    expect(result[0]?.expectedResult).toContain("unobserved control");
  });

  it("does not create recipes for statically contradicted hypotheses", () => {
    const candidateRecord = candidate({ id: "candidate-contradicted" });
    const hypothesis = staticHypothesis(candidateRecord, {
      id: "hypothesis-contradicted",
      status: "statically_contradicted",
      runtimeValidationRequired: false,
      contradictingEvidenceIds: ["ev-control"],
    });

    expect(
      composeValidationRecipes({
        staticHypotheses: [hypothesis],
        candidates: [candidateRecord],
      }),
    ).toEqual([]);
  });

  it("merges explicit hints deterministically", () => {
    const candidateRecord = candidate({ id: "candidate-hinted" });
    const hypothesis = staticHypothesis(candidateRecord, {
      id: "hypothesis-hinted",
      status: "statically_supported",
      supportingEvidenceIds: ["ev-edge"],
    });

    const result = composeValidationRecipes({
      staticHypotheses: [hypothesis],
      candidates: [candidateRecord],
      hints: [
        {
          candidateId: candidateRecord.id,
          requiredFixtures: ["principal_a", "owned_resource"],
          steps: ["Create two isolated tenants before replaying the path."],
          safetyNotes: ["Use synthetic tenants and disposable auth tokens only."],
          materializationHints: ["factory:tenant_pair"],
          knownGaps: ["Framework-specific route factory has not been selected."],
        },
        {
          hypothesisId: hypothesis.id,
          requiredFixtures: ["principal_b", "principal_a"],
          steps: ["Attempt the owned-resource access as principal_b."],
        },
      ],
    });

    expect(result[0]).toMatchObject({
      requiredFixtures: [
        "boundary_input_fixture",
        "dangerous_operation_repro",
        "owned_resource",
        "principal_a",
        "principal_b",
      ],
      expectedResult:
        "Future runtime validation should gather controlled evidence for or against the statically supported path; this recipe does not claim runtime confirmation.",
      materializationHints: expect.arrayContaining(["factory:tenant_pair"]),
      knownGaps: ["Framework-specific route factory has not been selected."],
    });
    expect(result[0]?.steps).toContain("Create two isolated tenants before replaying the path.");
    expect(result[0]?.steps).toContain("Attempt the owned-resource access as principal_b.");
    expect(result[0]?.safetyNotes).toContain(
      "Use synthetic tenants and disposable auth tokens only.",
    );
  });

  it("rejects hints for unknown hypotheses or candidates", () => {
    const candidateRecord = candidate({ id: "candidate-known" });
    const hypothesis = staticHypothesis(candidateRecord, { id: "hypothesis-known" });

    expect(() =>
      composeValidationRecipes({
        staticHypotheses: [hypothesis],
        candidates: [candidateRecord],
        hints: [{ hypothesisId: "missing-hypothesis", requiredFixtures: ["fixture"] }],
      }),
    ).toThrow(/unknown hypothesisId: missing-hypothesis/);

    expect(() =>
      composeValidationRecipes({
        staticHypotheses: [hypothesis],
        candidates: [candidateRecord],
        hints: [{ candidateId: "missing-candidate", requiredFixtures: ["fixture"] }],
      }),
    ).toThrow(/unknown candidateId: missing-candidate/);
  });

  it("returns deterministic ids and ordering for repeated generation", () => {
    const candidateA = candidate({ id: "candidate-a", title: "A" });
    const candidateB = candidate({ id: "candidate-b", title: "B" });
    const hypothesisA = staticHypothesis(candidateA, { id: "hypothesis-a" });
    const hypothesisB = staticHypothesis(candidateB, { id: "hypothesis-b" });

    const first = composeValidationRecipes({
      staticHypotheses: [hypothesisB, hypothesisA],
      candidates: [candidateB, candidateA],
    });
    const second = composeValidationRecipes({
      staticHypotheses: [hypothesisB, hypothesisA],
      candidates: [candidateB, candidateA],
    });

    expect(first.map((recipe) => recipe.hypothesisId)).toEqual(["hypothesis-a", "hypothesis-b"]);
    expect(first.map((recipe) => recipe.id)).toEqual([
      validationRecipeId("hypothesis-a"),
      validationRecipeId("hypothesis-b"),
    ]);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

describe("validateValidationRecipes", () => {
  it("rejects records that reference unknown hypotheses", () => {
    const record: ValidationRecipe = {
      id: validationRecipeId("hypothesis-known"),
      hypothesisId: "hypothesis-known",
      requiredFixtures: ["fixture"],
      steps: ["step"],
      expectedResult: "expected",
      safetyNotes: ["safe"],
      materializationHints: ["hint"],
      knownGaps: [],
    };

    expect(() => validateValidationRecipes([record], { hypothesisIds: ["other"] })).toThrow(
      /unknown hypothesis: hypothesis-known/,
    );
  });
});

function candidate(overrides: Partial<HypothesisCandidate> = {}): HypothesisCandidate {
  return {
    id: "candidate-1",
    ruleId: "stage2.external-input-dangerous-operation",
    family: "external_input_to_dangerous_operation",
    title: "External input reaches a dangerous operation",
    findingIds: ["finding-1"],
    supportingNodeIds: ["node-source", "node-sink"],
    supportingEdgeIds: ["edge-path"],
    contradictingNodeIds: [],
    contradictingEdgeIds: [],
    coverageRefs: ["stage2:call_graph"],
    requiredValidation: ["boundary_input_fixture", "dangerous_operation_repro"],
    candidateReason: "Static path connects a boundary to a dangerous operation.",
    ...overrides,
  };
}

function staticHypothesis(
  candidateRecord: HypothesisCandidate,
  overrides: Partial<StaticHypothesis> = {},
): StaticHypothesis {
  const status = overrides.status ?? "statically_supported";
  return {
    id: "hypothesis-1",
    candidateId: candidateRecord.id,
    status,
    staticConfidence: 0.8,
    title: candidateRecord.title,
    pathSummary: `Path summary for ${candidateRecord.title}.`,
    supportingEvidenceIds: status === "statically_supported" ? ["ev-path"] : [],
    contradictingEvidenceIds: [],
    coverageState: "checked",
    runtimeValidationRequired: status !== "statically_contradicted",
    ...overrides,
  };
}
