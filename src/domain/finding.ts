/**
 * Finding — one normalized security issue derived from raw evidence.
 *
 * A Finding never carries a secret value. Severity, confidence, and category
 * come straight from the tool; the fingerprint deduplicates findings across
 * reruns. The optional remediation key links a finding into the catalog.
 */

import type { Evidence } from "./evidence.js";

export type Severity = "critical" | "high" | "low" | "medium" | "unknown";
export type Confidence = "high" | "low" | "medium" | "unknown";
export type FindingCategory =
  | "secret"
  | "code-pattern"
  | "dependency"
  | "iac"
  | "github-action"
  | "sbom";

export interface FindingLocation {
  /** POSIX-relative path inside the repo, validated against the manifest. */
  readonly filePath: string;
  readonly startLine: number;
  readonly endLine: number;
}

export interface Finding {
  readonly id: string;
  readonly sourceTool: string;
  /** Tool-specific rule id (e.g. "stripe-access-token"). */
  readonly ruleId: string;
  readonly category: FindingCategory;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly locations: ReadonlyArray<FindingLocation>;
  readonly evidenceIds: ReadonlyArray<string>;
  /** Stable dedup key over tool + rule + location. */
  readonly fingerprint: string;
  /** Tool-specific normalized facts that are safe to expose and useful for graph joins. */
  readonly metadata?: Readonly<Record<string, string>>;
  /** Links into the remediation catalog; absent for uncatalogued findings. */
  readonly remediationKey?: string;
}

/** Same root cause across findings (current slice: identity grouping only). */
export interface FindingCluster {
  readonly id: string;
  readonly category: FindingCategory;
  readonly findingIds: ReadonlyArray<string>;
  readonly maxSeverity: Severity;
}

/** Collect the distinct evidence objects a finding references. */
export function evidenceFor(finding: Finding, byId: Map<string, Evidence>): Evidence[] {
  const out: Evidence[] = [];
  for (const id of finding.evidenceIds) {
    const ev = byId.get(id);
    if (ev !== undefined) {
      out.push(ev);
    }
  }
  return out;
}
