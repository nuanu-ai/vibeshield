/**
 * ModelProvider port — the one optional enhancement call.
 *
 * Turns deterministic candidates into plain-language explanations + coding-agent
 * prompts. Missing key or failed call degrades to the catalog; the
 * deterministic result is complete without any model.
 */

import type { RemediationAction } from "../domain/action.js";

export interface ModelEnhanceInput {
  readonly candidateId: string;
  readonly remediationKey: string;
  readonly risk: string;
  readonly findings: ReadonlyArray<{
    readonly ruleId: string;
    readonly filePath: string;
    readonly snippet: string;
  }>;
}

export interface ModelProvider {
  /** True when a key/config is present and a call should be attempted. */
  isAvailable(): Promise<boolean>;
  /** Enhance one candidate. Returns null to fall back to the catalog. */
  enhance(input: ModelEnhanceInput): Promise<RemediationAction | null>;
}
