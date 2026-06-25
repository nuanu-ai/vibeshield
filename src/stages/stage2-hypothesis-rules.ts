import type { FindingContextAssessment } from "../domain/finding-context-assessment.js";
import type { HypothesisCandidate } from "../domain/hypothesis-candidate.js";
import type { SecurityGraph } from "../domain/security-graph.js";
import { type CorrelationRuleDefinition, correlateGraphRules } from "./correlation-rule-engine.js";

export const STAGE2_HYPOTHESIS_FAMILIES = [
  "external_input_to_dangerous_operation",
  "sast_reachable_path",
  "dependency_usage_path",
  "ci_supply_chain_path",
  "secret_impact_chain",
  "content_resource_exposure_path",
] as const;

export type Stage2HypothesisFamily = (typeof STAGE2_HYPOTHESIS_FAMILIES)[number];

export interface Stage2HypothesisRuleOptions {
  readonly maxPathLength?: number;
}

export interface CorrelateStage2HypothesesInput extends Stage2HypothesisRuleOptions {
  readonly graph: SecurityGraph;
  readonly findingContexts?: ReadonlyArray<FindingContextAssessment>;
  readonly maxCandidatesPerRule?: number;
}

const DEFAULT_MAX_PATH_LENGTH = 6;
const CONTEXT_REQUIRED_FAMILIES = new Set<Stage2HypothesisFamily>([
  "sast_reachable_path",
  "dependency_usage_path",
  "ci_supply_chain_path",
  "secret_impact_chain",
]);

export function stage2HypothesisRules(
  options: Stage2HypothesisRuleOptions = {},
): CorrelationRuleDefinition[] {
  const maxPathLength = options.maxPathLength ?? DEFAULT_MAX_PATH_LENGTH;
  return [
    {
      id: "stage2.external-input-dangerous-operation",
      family: "external_input_to_dangerous_operation",
      title: "External input reaches a dangerous operation",
      source: { kinds: ["Boundary", "Source"] },
      target: { kinds: ["Sink"] },
      path: {
        allowedEdgeKinds: ["receives", "registers", "calls", "flows_to"],
        maxPathLength,
      },
      coverageRefs: ["stage2:boundaries", "stage2:call_graph", "stage2:data_flow"],
      requiredValidation: ["boundary_input_fixture", "dangerous_operation_repro"],
    },
    {
      id: "stage2.sast-reachable-path",
      family: "sast_reachable_path",
      title: "Quick SAST finding is reachable from an analyzed boundary",
      source: { kinds: ["Boundary", "Source"] },
      target: { kinds: ["CodeEntity"] },
      path: {
        allowedEdgeKinds: ["receives", "registers", "calls", "flows_to"],
        requiredEdgeKinds: ["calls"],
        maxPathLength,
      },
      coverageRefs: ["stage2:boundaries", "stage2:call_graph"],
      requiredValidation: ["sast_reachability_review"],
    },
    {
      id: "stage2.dependency-usage-path",
      family: "dependency_usage_path",
      title: "Vulnerable component is imported, used, or reachable in the dependency graph",
      source: { kinds: ["Boundary", "Source", "CodeEntity"] },
      target: { kinds: ["Component"] },
      path: {
        allowedEdgeKinds: ["receives", "registers", "calls", "imports", "uses", "depends_on"],
        maxPathLength,
      },
      coverageRefs: ["stage2:dependency_usage", "stage2:call_graph"],
      requiredValidation: ["dependency_usage_review"],
    },
    {
      id: "stage2.ci-supply-chain-path",
      family: "ci_supply_chain_path",
      title: "Build workflow can reach a mutable or privileged build resource",
      source: { kinds: ["BuildStep"] },
      target: { kinds: ["Resource"] },
      path: {
        allowedEdgeKinds: ["contains", "depends_on", "uses", "writes"],
        maxPathLength,
      },
      coverageRefs: ["stage2:ci_iac"],
      requiredValidation: ["ci_supply_chain_review"],
    },
    {
      id: "stage2.secret-impact-chain",
      family: "secret_impact_chain",
      title: "Secret context reaches a privileged integration or exposed resource",
      source: { kinds: ["Secret"] },
      target: { kinds: ["ExternalService", "InfraResource", "BuildStep"] },
      path: {
        allowedEdgeKinds: ["reads", "uses", "depends_on", "flows_to", "writes", "exposes"],
        maxPathLength,
      },
      coverageRefs: ["stage2:secret_impact", "stage2:ci_iac"],
      requiredValidation: ["secret_rotation_review", "integration_scope_review"],
    },
    {
      id: "stage2.content-resource-exposure-path",
      family: "content_resource_exposure_path",
      title:
        "Hidden content/resource exposure path: static content exposes hidden or private resources",
      source: { kinds: ["Resource"], propertyEquals: { resourceType: "content_resource" } },
      target: { kinds: ["Sink"], propertyEquals: { sinkType: "hidden_content_exposure" } },
      path: {
        allowedEdgeKinds: ["exposes"],
        maxPathLength: 1,
      },
      coverageRefs: ["stage2:content_assets"],
      requiredValidation: ["content_route_review", "asset_exposure_review"],
    },
  ];
}

export function correlateStage2Hypotheses(
  input: CorrelateStage2HypothesesInput,
): HypothesisCandidate[] {
  if (input.maxCandidatesPerRule !== undefined) {
    assertPositiveInteger(input.maxCandidatesPerRule, "maxCandidatesPerRule");
  }
  const engineInput = {
    graph: input.graph,
    findingContexts: input.findingContexts ?? [],
    rules: stage2HypothesisRules(
      input.maxPathLength === undefined ? {} : { maxPathLength: input.maxPathLength },
    ),
  };

  const filtered = correlateGraphRules(engineInput).filter((candidate) =>
    hasRequiredContext(candidate),
  );
  return input.maxCandidatesPerRule === undefined
    ? filtered
    : limitCandidatesPerRule(filtered, input.maxCandidatesPerRule);
}

function hasRequiredContext(candidate: HypothesisCandidate): boolean {
  return (
    !CONTEXT_REQUIRED_FAMILIES.has(candidate.family as Stage2HypothesisFamily) ||
    candidate.findingIds.length > 0
  );
}

function limitCandidatesPerRule(
  candidates: ReadonlyArray<HypothesisCandidate>,
  maxCandidatesPerRule: number,
): HypothesisCandidate[] {
  const counts = new Map<string, number>();
  const out: HypothesisCandidate[] = [];
  for (const candidate of candidates) {
    const count = counts.get(candidate.ruleId) ?? 0;
    if (count >= maxCandidatesPerRule) {
      continue;
    }
    counts.set(candidate.ruleId, count + 1);
    out.push(candidate);
  }
  return out;
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
}
