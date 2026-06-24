import { describe, expect, it } from "vitest";
import type { ActionCandidate } from "../src/domain/action.js";
import {
  type DeepActionGroup,
  deepActionGroupId,
  validateDeepActionGroups,
} from "../src/domain/action-group.js";
import type { FindingContextAssessment } from "../src/domain/finding-context-assessment.js";
import type { HypothesisCandidate } from "../src/domain/hypothesis-candidate.js";
import type { StaticHypothesis } from "../src/domain/static-hypothesis.js";
import { groupDeepActions } from "../src/stages/deep-action-grouping.js";

describe("groupDeepActions direct grouping", () => {
  it("groups direct actions with hypotheses that share finding ids", () => {
    const action = directAction({
      id: "action-secret",
      remediationKey: "live-secret-in-source",
      priorityScore: 100,
      verdictImpact: "blocks-deploy",
      findingIds: ["finding-secret"],
    });
    const candidateRecord = candidate({
      id: "candidate-secret-impact",
      findingIds: ["finding-secret"],
      family: "secret_impact_chain",
    });
    const hypothesis = staticHypothesis(candidateRecord, { id: "hypothesis-secret-impact" });

    const result = groupDeepActions({
      directActions: [action],
      candidates: [candidateRecord],
      staticHypotheses: [hypothesis],
    });

    expect(result).toEqual([
      expect.objectContaining({
        leadKind: "direct_finding",
        remediationKey: "live-secret-in-source",
        priorityScore: 100,
        verdictImpact: "blocks-deploy",
        directActionIds: ["action-secret"],
        findingIds: ["finding-secret"],
        hypothesisIds: ["hypothesis-secret-impact"],
        evidenceIds: ["evidence-action"],
      }),
    ]);
    expect(result[0]?.reason).toContain("linked static hypotheses");
  });

  it("uses linked_to_hypothesis finding context even when the candidate has no finding ids", () => {
    const action = directAction({ id: "action-dependency", findingIds: ["finding-dependency"] });
    const candidateRecord = candidate({ id: "candidate-context-only", findingIds: [] });
    const hypothesis = staticHypothesis(candidateRecord, { id: "hypothesis-context-only" });
    const context = findingContext("finding-dependency", ["hypothesis-context-only"]);

    const result = groupDeepActions({
      directActions: [action],
      candidates: [candidateRecord],
      staticHypotheses: [hypothesis],
      findingContexts: [context],
    });

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      directActionIds: ["action-dependency"],
      hypothesisIds: ["hypothesis-context-only"],
    });
  });

  it("keeps a secret direct action direct-led with original priority and verdict", () => {
    const action = directAction({
      id: "action-secret",
      remediationKey: "live-secret-in-source",
      priorityScore: 120,
      verdictImpact: "blocks-deploy",
      findingIds: ["finding-secret"],
    });
    const candidateRecord = candidate({
      id: "candidate-secret",
      family: "secret_impact_chain",
      findingIds: ["finding-secret"],
    });
    const hypothesis = staticHypothesis(candidateRecord, {
      id: "hypothesis-secret",
      staticConfidence: 0.99,
    });

    const result = groupDeepActions({
      directActions: [action],
      candidates: [candidateRecord],
      staticHypotheses: [hypothesis],
    });

    expect(result[0]).toMatchObject({
      leadKind: "direct_finding",
      remediationKey: "live-secret-in-source",
      priorityScore: 120,
      verdictImpact: "blocks-deploy",
      hypothesisIds: ["hypothesis-secret"],
    });
  });
});

describe("groupDeepActions hypothesis-only groups", () => {
  it("creates hypothesis-led groups for non-contradicted hypotheses without direct actions", () => {
    const supportedCandidate = candidate({
      id: "candidate-supported",
      family: "external_input_to_dangerous_operation",
      findingIds: [],
    });
    const candidateOnly = candidate({
      id: "candidate-only",
      family: "dependency_usage_path",
      findingIds: [],
    });
    const supported = staticHypothesis(supportedCandidate, {
      id: "hypothesis-supported",
      status: "statically_supported",
      staticConfidence: 0.8,
    });
    const candidateHypothesis = staticHypothesis(candidateOnly, {
      id: "hypothesis-candidate",
      status: "candidate",
      staticConfidence: 0.5,
      supportingEvidenceIds: [],
    });

    const result = groupDeepActions({
      directActions: [],
      candidates: [supportedCandidate, candidateOnly],
      staticHypotheses: [supported, candidateHypothesis],
    });

    expect(result.map((group) => group.leadKind)).toEqual(["hypothesis", "hypothesis"]);
    expect(result.map((group) => group.hypothesisIds)).toEqual([
      ["hypothesis-supported"],
      ["hypothesis-candidate"],
    ]);
    expect(result[0]).toMatchObject({
      remediationKey: "hypothesis:external_input_to_dangerous_operation",
      verdictImpact: "degrades",
    });
    expect(result[1]).toMatchObject({
      remediationKey: "hypothesis:dependency_usage_path",
      verdictImpact: "informational",
    });
  });

  it("does not create hypothesis-only groups for contradicted hypotheses", () => {
    const candidateRecord = candidate({ id: "candidate-contradicted", findingIds: [] });
    const hypothesis = staticHypothesis(candidateRecord, {
      id: "hypothesis-contradicted",
      status: "statically_contradicted",
      supportingEvidenceIds: [],
      contradictingEvidenceIds: ["evidence-contradiction"],
    });

    expect(
      groupDeepActions({
        directActions: [],
        candidates: [candidateRecord],
        staticHypotheses: [hypothesis],
      }),
    ).toEqual([]);
  });
});

describe("groupDeepActions validation and determinism", () => {
  it("rejects invalid references", () => {
    const action = directAction({ findingIds: ["finding-known"] });
    const candidateRecord = candidate({ id: "candidate-known", findingIds: [] });
    const hypothesis = staticHypothesis(candidateRecord, { id: "hypothesis-known" });

    expect(() =>
      groupDeepActions({
        directActions: [action],
        candidates: [candidateRecord],
        staticHypotheses: [hypothesis],
        findingContexts: [findingContext("missing-finding", ["hypothesis-known"])],
      }),
    ).toThrow(/unknown finding: missing-finding/);

    expect(() =>
      validateDeepActionGroups([deepGroup("group-1", ["missing-hypothesis"])], {
        hypothesisIds: ["known-hypothesis"],
      }),
    ).toThrow(/unknown hypothesis: missing-hypothesis/);

    expect(() =>
      validateDeepActionGroups([
        deepGroup("duplicate", ["hypothesis-duplicate"]),
        deepGroup("duplicate", ["hypothesis-duplicate"]),
      ]),
    ).toThrow(/deepActionGroup id is duplicated: duplicate/);
  });

  it("produces deterministic group ids and ordering", () => {
    const action = directAction({ id: "action-a", findingIds: ["finding-a"] });
    const candidateRecord = candidate({ id: "candidate-a", findingIds: ["finding-a"] });
    const hypothesis = staticHypothesis(candidateRecord, { id: "hypothesis-a" });

    const first = groupDeepActions({
      directActions: [action],
      candidates: [candidateRecord],
      staticHypotheses: [hypothesis],
    });
    const second = groupDeepActions({
      directActions: [action],
      candidates: [candidateRecord],
      staticHypotheses: [hypothesis],
    });

    expect(first[0]?.id).toBe(deepActionGroupId(["direct", "action-a", "hypothesis-a"]));
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

function directAction(overrides: Partial<ActionCandidate> = {}): ActionCandidate {
  return {
    id: "action-1",
    remediationKey: "code-pattern-review",
    priorityScore: 80,
    findingIds: ["finding-1"],
    evidenceIds: ["evidence-action"],
    affectedFiles: ["src/app.ts"],
    verdictImpact: "degrades",
    ...overrides,
  };
}

function candidate(overrides: Partial<HypothesisCandidate> = {}): HypothesisCandidate {
  return {
    id: "candidate-1",
    ruleId: "stage2.external-input-dangerous-operation",
    family: "external_input_to_dangerous_operation",
    title: "External input reaches sink",
    findingIds: ["finding-1"],
    supportingNodeIds: ["node-source", "node-sink"],
    supportingEdgeIds: ["edge-path"],
    contradictingNodeIds: [],
    contradictingEdgeIds: [],
    coverageRefs: ["stage2:call_graph:checked"],
    requiredValidation: ["boundary_input_fixture"],
    candidateReason: "Static path exists.",
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
    pathSummary: "Static path summary.",
    supportingEvidenceIds: status === "statically_supported" ? ["evidence-hypothesis"] : [],
    contradictingEvidenceIds: [],
    coverageState: "checked",
    runtimeValidationRequired: status !== "statically_contradicted",
    ...overrides,
  };
}

function findingContext(
  findingId: string,
  hypothesisIds: ReadonlyArray<string>,
): FindingContextAssessment {
  return {
    findingId,
    status: "linked_to_hypothesis",
    graphNodeIds: [],
    graphEdgeIds: [],
    hypothesisIds,
    reason: "linked by context",
    coverageState: "checked",
  };
}

function deepGroup(id: string, hypothesisIds: ReadonlyArray<string>): DeepActionGroup {
  return {
    id,
    leadKind: "hypothesis",
    remediationKey: "hypothesis:test",
    priorityScore: 1,
    verdictImpact: "informational",
    directActionIds: [],
    findingIds: [],
    hypothesisIds,
    evidenceIds: [],
    affectedFiles: [],
    reason: "test",
  };
}
