/**
 * Coverage — what was checked, skipped, failed, or degraded.
 *
 * Every applicable check is accounted for. A green verdict requires the
 * applicable required checks to have completed.
 */
export interface CoverageEntry {
  readonly check: string;
  readonly status: CoverageStatus;
  readonly reason?: string;
}

export type CoverageStatus = "checked" | "skipped" | "failed" | "degraded";

/**
 * Limitation line every report renders. Honest about what a static scan
 * cannot see.
 */
export const SCAN_LIMITATION =
  "This scan did not run your app; authorization logic and runtime behavior were not checked.";
