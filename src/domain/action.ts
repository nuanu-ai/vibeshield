/**
 * Action — the unit the owner acts on.
 *
 * An `ActionCandidate` is purely deterministic: priority and verdict impact are
 * rule-computed from findings, before any model call. A `RemediationAction`
 * fills in the plain-language explanation and the coding-agent prompt, either
 * from the one model call or the deterministic catalog fallback.
 */

import type { Severity } from "./finding.js";

export interface ActionCandidate {
  readonly id: string;
  /** Catalog/grouping key (e.g. "live-secret-in-source"). */
  readonly remediationKey: string;
  /** Higher is more urgent. Deterministic. */
  readonly priorityScore: number;
  readonly findingIds: ReadonlyArray<string>;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly affectedFiles: ReadonlyArray<string>;
  /** How this action moves the verdict if resolved. */
  readonly verdictImpact: VerdictImpact;
}

export type VerdictImpact = "blocks-deploy" | "degrades" | "informational";

/** Signals used by ranking — only what is available now, never guessed. */
export interface RankingSignals {
  readonly toolSeverity: Severity;
  readonly confidence: string;
  readonly secretType?: string;
  readonly toolsAgreeing: number;
  readonly dependencyRelation?: "direct" | "transitive";
  /** Speculative signals stay undefined, not fabricated. */
}

export interface RemediationAction {
  readonly candidateId: string;
  readonly title: string;
  /** Plain-language risk: what this is and why it matters. */
  readonly risk: string;
  /** Why fix now, in plain language. */
  readonly whyFixNow: string;
  readonly fixSteps: ReadonlyArray<string>;
  /** Operational steps kept separate from code changes. */
  readonly operationalSteps: ReadonlyArray<string>;
  /** Ready-to-paste prompt for the owner's coding agent. */
  readonly agentPrompt: string;
  readonly verifySteps: ReadonlyArray<string>;
  /** True when this came from the catalog rather than the model. */
  readonly fromCatalog: boolean;
}
