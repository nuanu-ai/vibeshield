/**
 * SecurityAssessment — the one result object all reports render from.
 *
 * Composed after ranking and remediation. Renderers (terminal/json/md/html)
 * read from this object only; nothing reaches into domain internals.
 */

import type { ActionCandidate, RemediationAction } from "./action.js";
import type { Verdict } from "./assessment.js";
import type { CoverageEntry } from "./coverage-summary.js";
import { SCAN_LIMITATION } from "./coverage-summary.js";
import type { Evidence } from "./evidence.js";
import type { Finding } from "./finding.js";
import type { ManifestSummary, ToolchainSummary } from "./manifest-summary.js";

export interface SecurityAssessment {
  readonly repository: RepositorySummary;
  readonly manifest: ManifestSummary;
  readonly toolchain: ToolchainSummary;
  readonly verdict: Verdict;
  readonly coverage: ReadonlyArray<CoverageEntry>;
  readonly findingSummary: FindingSummary;
  readonly evidence: ReadonlyArray<Evidence>;
  readonly findings: ReadonlyArray<Finding>;
  readonly rankedActions: ReadonlyArray<RankedAction>;
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
