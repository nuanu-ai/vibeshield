import { describe, expect, it } from "vitest";
import type {
  InventoryArtifact,
  PiContextPackArtifact,
  StackBuildDepsArtifact,
} from "../src/artifacts/contracts.js";
import { validateStackBuildDepsArtifact } from "../src/pi/repository-map.js";

describe("repo-map validation", () => {
  it("accepts fact gaps without invented evidence", () => {
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
        budget: fakeBudget(),
        inventory: fakeInventory(),
      }),
    ).not.toThrow();
  });
});

function fakeInventory(): InventoryArtifact {
  return {
    directories: [],
    files: [{ line_count: 1, path: "requirements.txt", size_bytes: 10, type: "file" }],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "vibeshield-inventory",
    kind: "inventory",
    sandbox: { id: "sandbox", inventory_location: "inside_sandbox" },
    source: {
      commit_sha: "abc123",
      owner: "example",
      repo: "repo",
      type: "github",
      url: "https://github.com/example/repo",
    },
    summary: {
      directory_count: 0,
      file_count: 1,
      manifest_files: ["requirements.txt"],
      total_file_bytes: 10,
    },
  };
}

function fakeBudget(): PiContextPackArtifact["budget"] {
  return {
    max_data_flows: 10,
    max_fact_gaps: 10,
    max_important_files: 10,
    max_stack_build_deps: 10,
  };
}

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
