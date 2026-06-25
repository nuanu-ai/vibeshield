/**
 * ModelProvider port — optional copy enhancement calls.
 *
 * Turns deterministic actions and static hypotheses into plain-language
 * explanations + coding-agent prompts. Missing key or failed call degrades to
 * deterministic catalog text; the result is complete without any model.
 */

import type { RemediationAction, VerdictImpact } from "../domain/action.js";
import type { FindingCategory, Severity } from "../domain/finding.js";
import type { SecurityGraphEdgeKind, SecurityGraphNodeKind } from "../domain/security-graph.js";
import type {
  StaticHypothesisCoverageState,
  StaticHypothesisStatus,
} from "../domain/static-hypothesis.js";

export interface ModelEnhanceBatchInput {
  readonly repositoryName: string;
  readonly actions: ReadonlyArray<ModelEnhanceActionInput>;
}

export interface ModelEnhanceActionInput {
  readonly candidateId: string;
  readonly remediationKey: string;
  readonly priorityScore: number;
  readonly verdictImpact: VerdictImpact;
  readonly summary: ModelEnhanceActionSummary;
  readonly affectedFiles: ReadonlyArray<string>;
  readonly catalogRemediation: RemediationAction;
  readonly findings: ReadonlyArray<ModelEnhanceFindingInput>;
}

export interface ModelEnhanceActionSummary {
  readonly totalFindings: number;
  readonly includedFindings: number;
  readonly omittedFindings: number;
  readonly totalAffectedFiles: number;
  readonly includedAffectedFiles: number;
  readonly omittedAffectedFiles: number;
  readonly rules: ReadonlyArray<ModelEnhanceCount>;
  readonly tools: ReadonlyArray<ModelEnhanceCount>;
  readonly severities: ReadonlyArray<ModelEnhanceCount>;
}

export interface ModelEnhanceCount {
  readonly value: string;
  readonly count: number;
}

export interface ModelEnhanceFindingInput {
  readonly findingId: string;
  readonly sourceTool: string;
  readonly ruleId: string;
  readonly category: FindingCategory;
  readonly severity: Severity;
  readonly filePath: string;
  readonly startLine: number;
  readonly snippet: string;
}

export interface ModelHypothesisEnrichBatchInput {
  readonly repositoryName: string;
  readonly hypotheses: ReadonlyArray<ModelHypothesisEnrichInput>;
}

export interface ModelHypothesisEnrichInput {
  readonly hypothesisId: string;
  readonly candidateId: string;
  readonly family: string;
  readonly ruleId: string;
  readonly title: string;
  readonly status: StaticHypothesisStatus;
  readonly staticConfidence: number;
  readonly pathSummary: string;
  readonly runtimeValidationRequired: boolean;
  readonly candidateReason: string;
  readonly findingIds: ReadonlyArray<string>;
  readonly supportingNodeIds: ReadonlyArray<string>;
  readonly supportingEdgeIds: ReadonlyArray<string>;
  readonly contradictingNodeIds: ReadonlyArray<string>;
  readonly contradictingEdgeIds: ReadonlyArray<string>;
  readonly coverageState: StaticHypothesisCoverageState;
  readonly coverageRefs: ReadonlyArray<string>;
  readonly requiredValidation: ReadonlyArray<string>;
  readonly graphRefs: ReadonlyArray<ModelHypothesisGraphRefInput>;
  readonly observedControls: ReadonlyArray<ModelHypothesisGraphRefInput>;
  readonly coverageGaps: ReadonlyArray<string>;
  readonly evidenceSnippets: ReadonlyArray<ModelHypothesisEvidenceSnippetInput>;
  readonly validationRecipe: ModelHypothesisValidationRecipeInput | null;
  readonly catalogEnrichment: ModelHypothesisEnrichment;
}

export type ModelHypothesisGraphRefInput =
  | ModelHypothesisNodeRefInput
  | ModelHypothesisEdgeRefInput;

export interface ModelHypothesisNodeRefInput {
  readonly refType: "node";
  readonly id: string;
  readonly kind: SecurityGraphNodeKind;
  readonly label: string;
  readonly repoPath?: string;
  readonly lineRange?: ModelHypothesisLineRangeInput;
}

export interface ModelHypothesisEdgeRefInput {
  readonly refType: "edge";
  readonly id: string;
  readonly kind: SecurityGraphEdgeKind;
  readonly fromNodeId: string;
  readonly toNodeId: string;
}

export interface ModelHypothesisLineRangeInput {
  readonly startLine: number;
  readonly endLine: number;
}

export interface ModelHypothesisEvidenceSnippetInput {
  readonly evidenceId: string;
  readonly tool: string;
  readonly filePath: string;
  readonly startLine: number;
  readonly endLine: number;
  readonly snippet: string;
}

export interface ModelHypothesisValidationRecipeInput {
  readonly recipeId: string;
  readonly requiredFixtures: ReadonlyArray<string>;
  readonly steps: ReadonlyArray<string>;
  readonly expectedResult: string;
  readonly safetyNotes: ReadonlyArray<string>;
  readonly knownGaps: ReadonlyArray<string>;
}

export interface ModelHypothesisEnrichment {
  readonly hypothesisId: string;
  readonly attackDescription: string;
  readonly assumptions: ReadonlyArray<string>;
  readonly impact: string;
  readonly remediation: string;
  readonly agentPrompt: string;
  readonly acceptanceCriteria: ReadonlyArray<string>;
  readonly validationRecipeText: string;
}

export interface ModelProvider {
  /** True when a key/config is present and a call should be attempted. */
  isAvailable(): Promise<boolean>;
  /** Enhance a small Fix Pack batch. Returns null to fall back to the catalog. */
  enhance(input: ModelEnhanceBatchInput): Promise<ReadonlyArray<RemediationAction> | null>;
  /** Enrich a small static-hypothesis batch. Returns null for catalog fallback. */
  enrichHypotheses(
    input: ModelHypothesisEnrichBatchInput,
  ): Promise<ReadonlyArray<ModelHypothesisEnrichment> | null>;
}
