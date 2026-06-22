/**
 * Compact projections of the manifest used in reports. The full Manifest is
 * the source of truth; these carry only what a reader needs.
 */
import type { Manifest, ToolchainRecord } from "./manifest.js";

export interface ManifestSummary {
  readonly fileCount: number;
  readonly totalBytes: number;
  readonly sourceHash: string;
  readonly commitSha: string | null;
  readonly exclusionCount: number;
}

export function summarizeManifest(m: Manifest): ManifestSummary {
  let totalBytes = 0;
  for (const f of m.files) {
    totalBytes += f.size;
  }
  return {
    fileCount: m.files.length,
    totalBytes,
    sourceHash: m.sourceHash,
    commitSha: m.commitSha,
    exclusionCount: m.exclusions.length,
  };
}

export type { ToolchainRecord };
export interface ToolchainSummary {
  readonly imageTag: string;
  readonly tools: ReadonlyArray<{
    tool: string;
    version: string;
    dbDate?: string;
    dbStale?: boolean;
  }>;
}

export function summarizeToolchain(t: ToolchainRecord): ToolchainSummary {
  return { imageTag: t.imageTag, tools: t.tools };
}
