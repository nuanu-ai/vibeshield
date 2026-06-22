/**
 * Repository inventory — deterministic facts derived from the snapshot manifest.
 *
 * The inventory decides which scanner checks apply before any scanner output is
 * interpreted. It never reads source files directly.
 */

export interface RepositoryInventory {
  readonly languages: ReadonlyArray<string>;
  readonly packageManifests: ReadonlyArray<string>;
  readonly workflows: ReadonlyArray<string>;
  readonly iacFiles: ReadonlyArray<string>;
  readonly codeFileCount: number;
}

export interface ScanPlan {
  readonly checks: ReadonlyArray<PlannedCheck>;
}

export interface PlannedCheck {
  readonly check: string;
  readonly tool: string;
  readonly applicable: boolean;
  readonly required: boolean;
  /** True only when this codebase already has a stage that runs the tool. */
  readonly implemented: boolean;
  readonly reason?: string;
}
