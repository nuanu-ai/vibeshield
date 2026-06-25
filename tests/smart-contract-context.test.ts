import { describe, expect, it } from "vitest";
import type { Manifest } from "../src/domain/manifest.js";
import type { SecurityGraph } from "../src/domain/security-graph.js";
import { securityGraphId } from "../src/domain/security-graph.js";
import {
  composeSmartContractContext,
  smartContractRiskObservationsFromText,
} from "../src/stages/smart-contract-context.js";

const GRAPH_VERSION = "1";

describe("smart contract risk observations", () => {
  it("extracts value-transfer-before-state-update risks from Solidity withdraw functions", () => {
    const observations = smartContractRiskObservationsFromText(
      "contracts/Bank.sol",
      [
        "pragma solidity ^0.8.0;",
        "contract Bank {",
        "  mapping(address => uint) public balances;",
        "  function withdraw(uint amount) public {",
        "    require(balances[msg.sender] >= amount);",
        '    (bool ok, ) = msg.sender.call{ value: amount }("");',
        "    require(ok);",
        "    balances[msg.sender] -= amount;",
        "  }",
        "}",
      ].join("\n"),
    );

    expect(observations).toMatchObject([
      {
        repoPath: "contracts/Bank.sol",
        contractName: "Bank",
        functionName: "withdraw",
        riskType: "reentrancy_value_transfer_before_state_update",
        externalCallLine: 6,
        stateUpdateLine: 8,
      },
    ]);
  });

  it("does not flag checks-effects-interactions ordering", () => {
    const observations = smartContractRiskObservationsFromText(
      "contracts/Bank.sol",
      [
        "contract Bank {",
        "  mapping(address => uint) public balances;",
        "  function withdraw(uint amount) public {",
        "    balances[msg.sender] -= amount;",
        '    (bool ok, ) = msg.sender.call{ value: amount }("");',
        "    require(ok);",
        "  }",
        "}",
      ].join("\n"),
    );

    expect(observations).toEqual([]);
  });
});

describe("composeSmartContractContext", () => {
  it("adds smart contract risk graph facts and coverage", () => {
    const observations = smartContractRiskObservationsFromText(
      "contracts/Bank.sol",
      [
        "contract Bank {",
        "  mapping(address => uint) public balances;",
        "  function withdraw(uint amount) public {",
        '    (bool ok, ) = msg.sender.call{ value: amount }("");',
        "    balances[msg.sender] -= amount;",
        "  }",
        "}",
      ].join("\n"),
    );
    const graph = composeSmartContractContext({
      graph: emptyGraph(),
      manifest: manifest(),
      observations,
      scannedFileCount: 1,
    });

    expect(graph.nodes.map((node) => node.kind)).toEqual(["Resource", "Sink"]);
    expect(graph.edges).toMatchObject([{ kind: "flows_to" }]);
    expect(graph.coverage).toContainEqual(
      expect.objectContaining({
        area: "smart_contracts",
        state: "checked",
        coveredCount: 1,
        totalCount: 1,
        producer: "smart-contract-context",
      }),
    );
  });
});

function emptyGraph(): SecurityGraph {
  return {
    id: securityGraphId("snapshot-1", GRAPH_VERSION),
    runId: "run-1",
    snapshotId: "snapshot-1",
    graphVersion: GRAPH_VERSION,
    nodes: [],
    edges: [],
    flows: [],
    coverage: [],
    createdAt: "2026-06-25T10:00:00Z",
  };
}

function manifest(): Manifest {
  return {
    origin: { kind: "github", url: "https://example.test/repo.git" },
    commitSha: "abc123",
    sourceHash: "snapshot-1",
    files: [
      {
        path: "contracts/Bank.sol",
        size: 100,
        sha256: "sha256-contract",
      },
    ],
    exclusions: [],
    toolchain: { imageTag: "test", tools: [] },
    createdAt: "2026-06-25T10:00:00Z",
  };
}
