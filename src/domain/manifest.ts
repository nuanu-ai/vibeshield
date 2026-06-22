/**
 * Snapshot manifest — the small, content-addressed description of what was
 * scanned. The source tree itself is never stored as an artifact; only this
 * manifest is. Same source bytes always produce the same source hash.
 */

export interface Manifest {
  readonly origin: ManifestOrigin;
  /** Commit SHA when available; null for sources without git history. */
  readonly commitSha: string | null;
  /** Hash over the canonical sorted file list (path + sha256), not the archive. */
  readonly sourceHash: string;
  readonly files: ReadonlyArray<ManifestFile>;
  readonly exclusions: ReadonlyArray<ManifestExclusion>;
  readonly toolchain: ToolchainRecord;
  readonly createdAt: string;
}

export interface ManifestFile {
  /** POSIX-relative path inside the repo root. No absolute paths or `..`. */
  readonly path: string;
  readonly size: number;
  readonly sha256: string;
}

export interface ManifestExclusion {
  readonly path: string;
  readonly reason: ExclusionReason;
}

export type ExclusionReason =
  | "git-ignored"
  | "builtin-ignore"
  | "too_large"
  | "truncated"
  | "symlink-escape"
  | "dot-env-exception";

export interface ToolchainRecord {
  /** Image tag booted for the scan, e.g. "vibeshield-toolchain:latest". */
  readonly imageTag: string;
  /** Per-tool version + database freshness, keyed by tool name. */
  readonly tools: ReadonlyArray<ToolVersion>;
}

export interface ToolVersion {
  readonly tool: string;
  readonly version: string;
  /** When the tool's vulnerability/rule database was last refreshed, ISO. */
  readonly dbDate?: string;
  /** True when a DB refresh failed and a stale cached DB was used. */
  readonly dbStale?: boolean;
}

export type ManifestOrigin =
  | { readonly kind: "github"; readonly url: string }
  | { readonly kind: "local"; readonly path: string };
