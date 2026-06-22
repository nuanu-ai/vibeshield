/**
 * ModelProvider port — the one optional enhancement call.
 *
 * Turns deterministic candidates into plain-language explanations + coding-agent
 * prompts. Missing key or failed call degrades to the catalog; the
 * deterministic result is complete without any model.
 */

import type { RemediationAction, VerdictImpact } from "../domain/action.js";
import type { FindingCategory, Severity } from "../domain/finding.js";

export interface ModelEnhanceBatchInput {
  readonly repositoryName: string;
  readonly actions: ReadonlyArray<ModelEnhanceActionInput>;
}

export interface ModelEnhanceActionInput {
  readonly candidateId: string;
  readonly remediationKey: string;
  readonly priorityScore: number;
  readonly verdictImpact: VerdictImpact;
  readonly affectedFiles: ReadonlyArray<string>;
  readonly catalogRemediation: RemediationAction;
  readonly findings: ReadonlyArray<ModelEnhanceFindingInput>;
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

export interface ModelProvider {
  /** True when a key/config is present and a call should be attempted. */
  isAvailable(): Promise<boolean>;
  /** Enhance a Fix Pack in one call. Returns null to fall back to the catalog. */
  enhance(input: ModelEnhanceBatchInput): Promise<ReadonlyArray<RemediationAction> | null>;
}
