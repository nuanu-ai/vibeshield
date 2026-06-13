import { describe, expect, it } from "vitest";
import type {
  DataFlowsArtifact,
  EntrypointsArtifact,
  InventoryArtifact,
  OperationSinksArtifact,
  PiContextPackArtifact,
} from "../src/artifacts/contracts.js";
import { validateDataFlowsArtifact } from "../src/pi/repository-map.js";

describe("repo-map data-flows validation", () => {
  it("canonicalizes location-specific not-traced statuses without losing the flow", () => {
    const artifact = fakeDataFlowsArtifact();
    const firstFlow = artifact.flows[0];
    if (firstFlow === undefined) {
      throw new Error("Expected fake data-flow fixture to contain at least one flow.");
    }
    artifact.flows[0] = {
      ...firstFlow,
      trace_status: "not traced beyond server.ts:480",
    } as unknown as DataFlowsArtifact["flows"][number];

    validateDataFlowsArtifact({
      artifact,
      budget: fakeBudget(),
      entrypoints: fakeEntrypointsArtifact(),
      inventory: fakeInventory(),
      operationSinks: fakeOperationSinksArtifact(),
    });

    expect(artifact.flows[0]?.trace_status).toBe("not traced beyond path:line");
  });
});

function fakeDataFlowsArtifact(): DataFlowsArtifact {
  return {
    coverage: { not_covered: [], reviewed: [{ area: "server route", evidence: ["server.ts:1"] }] },
    fact_gaps: [],
    flows: [
      {
        breakpoint: { evidence: ["server.ts:1"], reason: "framework-generated handler" },
        id: "flow-one",
        inference: true,
        intermediate_functions: [],
        operation_sink: "sink-one",
        operation_sink_evidence: ["server.ts:2"],
        source_entrypoint: "entry-one",
        source_evidence: ["server.ts:1"],
        trace_status: "not traced beyond path:line",
      },
    ],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    inputs: {
      entrypoints_artifact: "outputs/repo-map/entrypoints.json",
      operation_sinks_artifact: "outputs/repo-map/operation-sinks.json",
    },
    kind: "data-flows",
    metadata: fakeMetadata("data-flows"),
    repo: { commit_sha: "abc123", url: "https://github.com/example/repo" },
  };
}

function fakeEntrypointsArtifact(): EntrypointsArtifact {
  return {
    coverage: { not_covered: [], reviewed: [{ area: "server route", evidence: ["server.ts:1"] }] },
    entrypoints: [
      {
        confidence: "high",
        evidence: ["server.ts:1"],
        id: "entry-one",
        kind: "http_route",
        location: "server.ts",
        name: "GET /demo",
        route: "/demo",
      },
    ],
    fact_gaps: [],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "entrypoints",
    metadata: fakeMetadata("entrypoints"),
    repo: { commit_sha: "abc123", url: "https://github.com/example/repo" },
  };
}

function fakeOperationSinksArtifact(): OperationSinksArtifact {
  return {
    coverage: { not_covered: [], reviewed: [{ area: "sink", evidence: ["server.ts:2"] }] },
    fact_gaps: [],
    generated_at: "2026-06-13T00:00:00.000Z",
    generated_by: "pi",
    kind: "operation-sinks",
    metadata: fakeMetadata("operation-sinks"),
    operation_sinks: [
      {
        confidence: "high",
        evidence: ["server.ts:2"],
        id: "sink-one",
        kind: "sql_or_orm_query",
        location: "server.ts",
        operation: "db query",
      },
    ],
    repo: { commit_sha: "abc123", url: "https://github.com/example/repo" },
  };
}

function fakeInventory(): InventoryArtifact {
  return {
    directories: [],
    files: [{ line_count: 3, path: "server.ts", size_bytes: 80, type: "file" }],
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
      manifest_files: [],
      total_file_bytes: 80,
    },
  };
}

function fakeBudget(): PiContextPackArtifact["budget"] {
  return {
    max_data_flows: 10,
    max_entrypoints: 10,
    max_fact_gaps: 10,
    max_important_files: 10,
    max_operation_sinks: 10,
  };
}

function fakeMetadata(step: string) {
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
