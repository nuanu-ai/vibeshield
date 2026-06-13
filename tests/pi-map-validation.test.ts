import { describe, expect, it } from "vitest";
import type { StackBuildDepsArtifact } from "../src/artifacts/contracts.js";
import { validateStackBuildDepsArtifact } from "../src/pi/repository-map.js";

describe("repo-map validation", () => {
  it("accepts a valid stack/build/deps schema without evidence policing", () => {
    expect(() =>
      validateStackBuildDepsArtifact({
        artifact: {
          build: {
            commands: [],
            lockfiles: [],
            manifests: [{ evidence: ["requirements.txt:1"], path: "requirements.txt" }],
          },
          coverage: {
            not_covered: [
              {
                area: "dependency lockfile",
                reason: "no lockfile path was found in the inventory",
              },
            ],
            reviewed: [{ area: "dependency manifest", evidence: ["requirements.txt:1"] }],
          },
          dependencies: [],
          fact_gaps: [
            {
              area: "lockfile existence",
              evidence: [],
              missing_fact: "whether a lockfile exists outside the reviewed repository paths",
            },
          ],
          generated_at: "2026-06-13T00:00:00.000Z",
          generated_by: "pi",
          kind: "stack-build-deps",
          metadata: fakeMetadata("stack-build-deps"),
          repo: { commit_sha: "abc123", url: "https://github.com/example/repo" },
          stack: [
            {
              confidence: "high",
              evidence: ["requirements.txt:1"],
              id: "lang-python",
              kind: "language",
              name: "Python",
              role: "application language",
            },
          ],
        },
      }),
    ).not.toThrow();
  });
});

function fakeMetadata(step: string): StackBuildDepsArtifact["metadata"] {
  return {
    pi: {
      input_context_artifact: "outputs/pi-context-pack.json",
      invocation: { command: "pi" },
      model: "test",
      provider: "openrouter",
      step,
    },
  };
}
