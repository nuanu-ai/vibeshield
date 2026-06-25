/**
 * SecurityAssessment — the one result object all reports render from.
 *
 * Composed after ranking and remediation. Renderers (terminal/json/md/html)
 * read from this object only; nothing reaches into domain internals.
 */

import type { ActionCandidate, RemediationAction } from "./action.js";
import type { DeepActionGroup } from "./action-group.js";
import type { Verdict } from "./assessment.js";
import type { CoverageEntry } from "./coverage-summary.js";
import { SCAN_LIMITATION } from "./coverage-summary.js";
import type { DeepCoverageEntry } from "./deep-coverage.js";
import type { Evidence } from "./evidence.js";
import type { Finding, FindingCluster } from "./finding.js";
import type { FindingContextAssessment } from "./finding-context-assessment.js";
import type { HypothesisCandidate } from "./hypothesis-candidate.js";
import type { HypothesisEnrichment } from "./hypothesis-enrichment.js";
import type { ManifestSummary, ToolchainSummary } from "./manifest-summary.js";
import type { ArtifactRef } from "./run.js";
import type { StaticHypothesis } from "./static-hypothesis.js";
import type { ValidationRecipe } from "./validation-recipe.js";

export interface SecurityAssessment {
  readonly repository: RepositorySummary;
  readonly manifest: ManifestSummary;
  readonly toolchain: ToolchainSummary;
  readonly verdict: Verdict;
  readonly coverage: ReadonlyArray<CoverageEntry>;
  readonly deepCoverage?: ReadonlyArray<DeepCoverageEntry>;
  readonly findingSummary: FindingSummary;
  readonly evidence: ReadonlyArray<Evidence>;
  readonly findings: ReadonlyArray<Finding>;
  readonly findingClusters: ReadonlyArray<FindingCluster>;
  readonly rankedActions: ReadonlyArray<RankedAction>;
  readonly findingContextAssessments?: ReadonlyArray<FindingContextAssessment>;
  readonly hypothesisCandidates?: ReadonlyArray<HypothesisCandidate>;
  readonly staticHypotheses?: ReadonlyArray<StaticHypothesis>;
  readonly validationRecipes?: ReadonlyArray<ValidationRecipe>;
  readonly hypothesisEnrichments?: ReadonlyArray<HypothesisEnrichment>;
  readonly deepActionGroups?: ReadonlyArray<DeepActionGroup>;
  readonly repositoryMapArtifactRef?: ArtifactRef;
  readonly limitations?: ReadonlyArray<string>;
  readonly limitation: string;
  readonly generatedAt: string;
}

export interface RankedAction {
  readonly candidate: ActionCandidate;
  readonly remediation: RemediationAction;
}

export interface RepositorySummary {
  readonly name: string;
  readonly originUrl?: string;
  readonly localPath?: string;
  readonly commitSha?: string;
}

export interface FindingSummary {
  readonly total: number;
  readonly bySeverity: Readonly<Record<string, number>>;
  readonly byCategory: Readonly<Record<string, number>>;
}

/** Convenience constructor so the limitation line never drifts. */
export function buildAssessment(input: Omit<SecurityAssessment, "limitation">): SecurityAssessment {
  return { ...input, limitation: SCAN_LIMITATION };
}

export type { Finding };
