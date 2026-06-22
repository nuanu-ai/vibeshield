import { describe, expect, it } from "vitest";
import { VERDICT_ORDER, verdictLabel } from "../src/domain/assessment.js";
import { SCAN_LIMITATION } from "../src/domain/coverage-summary.js";
import type { Manifest, ToolchainRecord } from "../src/domain/manifest.js";
import { summarizeManifest, summarizeToolchain } from "../src/domain/manifest-summary.js";

describe("assessment domain", () => {
  it("maps every verdict to a non-empty human label", () => {
    for (const verdict of VERDICT_ORDER) {
      const label = verdictLabel(verdict);
      expect(label.length).toBeGreaterThan(0);
      expect(label).not.toEqual(verdict);
    }
  });

  it("never uses absolute safe wording for any verdict", () => {
    for (const verdict of VERDICT_ORDER) {
      const label = verdictLabel(verdict).toLowerCase();
      expect(label).not.toContain("safe");
      expect(label).not.toContain("secure");
    }
  });

  it("states the scan limitation line", () => {
    expect(SCAN_LIMITATION).toContain("did not run your app");
  });

  it("summarizes a manifest without losing file count or source hash", () => {
    const manifest: Manifest = {
      origin: { kind: "github", url: "https://github.com/o/r" },
      commitSha: "abc123",
      sourceHash: "deadbeef",
      files: [
        { path: "a.ts", size: 10, sha256: "h1" },
        { path: "b.ts", size: 20, sha256: "h2" },
      ],
      exclusions: [{ path: "node_modules", reason: "builtin-ignore" }],
      toolchain: {
        imageTag: "vibeshield-toolchain:latest",
        tools: [{ tool: "gitleaks", version: "8.30.1" }],
      },
      createdAt: "2026-01-01T00:00:00Z",
    };
    const summary = summarizeManifest(manifest);
    expect(summary.fileCount).toBe(2);
    expect(summary.totalBytes).toBe(30);
    expect(summary.sourceHash).toBe("deadbeef");
    expect(summary.exclusionCount).toBe(1);
  });

  it("summarizes the toolchain with image tag and tool versions", () => {
    const t: ToolchainRecord = {
      imageTag: "vibeshield-toolchain:latest",
      tools: [{ tool: "gitleaks", version: "8.30.1", dbDate: "2026-01-01" }],
    };
    const summary = summarizeToolchain(t);
    expect(summary.imageTag).toBe("vibeshield-toolchain:latest");
    expect(summary.tools).toHaveLength(1);
    expect(summary.tools[0]?.dbDate).toBe("2026-01-01");
  });
});
