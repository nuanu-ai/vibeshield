import { createHash } from "node:crypto";
import path from "node:path";
import type { Manifest } from "../domain/manifest.js";
import type {
  LineRange,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../domain/security-graph.js";
import {
  securityGraphEdgeId,
  securityGraphNodeId,
  validateSecurityGraph,
} from "../domain/security-graph.js";

export interface SmartContractRiskObservation {
  readonly repoPath: string;
  readonly contractName: string;
  readonly functionName: string;
  readonly riskType: "reentrancy_value_transfer_before_state_update";
  readonly label: string;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly lineRange: LineRange;
  readonly externalCallLine: number;
  readonly stateUpdateLine: number;
}

export interface ComposeSmartContractContextInput {
  readonly graph: SecurityGraph;
  readonly manifest: Manifest;
  readonly observations?: ReadonlyArray<SmartContractRiskObservation>;
  readonly scannedFileCount: number;
}

interface GraphBuilder {
  readonly nodes: SecurityGraphNode[];
  readonly edges: SecurityGraphEdge[];
  readonly nodesByStableKey: Map<string, SecurityGraphNode>;
  readonly edgesByStableKey: Map<string, SecurityGraphEdge>;
}

interface SolidityFunctionBlock {
  readonly contractName: string;
  readonly functionName: string;
  readonly startLine: number;
  readonly endLine: number;
  readonly text: string;
}

const PRODUCER = "smart-contract-context";
const DEFAULT_CONFIDENCE = 0.82;

export function composeSmartContractContext(
  input: ComposeSmartContractContextInput,
): SecurityGraph {
  const builder = graphBuilder(input.graph);

  for (const observation of input.observations ?? []) {
    assertEvidence(observation.evidenceIds, `smart contract risk ${observation.label}`);
    addSmartContractRisk(builder, input.graph.graphVersion, observation);
  }

  const observations = input.observations ?? [];
  return validateSecurityGraph(
    {
      ...input.graph,
      nodes: builder.nodes,
      edges: builder.edges,
      coverage: withSmartContractCoverage(input.graph, input.scannedFileCount),
    },
    {
      manifestPaths: input.manifest.files.map((file) => file.path),
      evidenceIds: [
        ...collectGraphEvidenceIds(input.graph),
        ...observations.flatMap((observation) => observation.evidenceIds),
      ],
    },
  );
}

export function smartContractRiskObservationsFromText(
  repoPath: string,
  text: string,
): SmartContractRiskObservation[] {
  if (!isSolidityPath(repoPath) || isIgnoredSmartContractPath(repoPath)) {
    return [];
  }
  return solidityFunctionBlocks(text).flatMap((block) => {
    const externalCallLine = firstRelativeLine(block.text, /\bmsg\.sender\.call\s*\{\s*value\s*:/);
    if (externalCallLine === undefined) {
      return [];
    }
    const afterCall = block.text.split(/\r?\n/).slice(externalCallLine);
    const stateUpdateOffset = firstRelativeLine(
      afterCall.join("\n"),
      /\bbalances\s*\[[^\]]+\]\s*(?:-=|=)/,
    );
    if (stateUpdateOffset === undefined) {
      return [];
    }
    const absoluteExternalCallLine = block.startLine + externalCallLine;
    const absoluteStateUpdateLine = block.startLine + externalCallLine + stateUpdateOffset;
    const lineRange = {
      startLine: absoluteExternalCallLine,
      endLine: absoluteStateUpdateLine,
    };
    return [
      {
        repoPath,
        contractName: block.contractName,
        functionName: block.functionName,
        riskType: "reentrancy_value_transfer_before_state_update",
        label: `${block.contractName}.${block.functionName} sends value before updating balances`,
        evidenceIds: [
          smartContractEvidenceId(
            "reentrancy-value-transfer-before-state-update",
            repoPath,
            block.text,
          ),
        ],
        lineRange,
        externalCallLine: absoluteExternalCallLine,
        stateUpdateLine: absoluteStateUpdateLine,
      },
    ];
  });
}

export function isSolidityPath(repoPath: string): boolean {
  return /\.sol$/i.test(repoPath);
}

function graphBuilder(graph: SecurityGraph): GraphBuilder {
  return {
    nodes: [...graph.nodes],
    edges: [...graph.edges],
    nodesByStableKey: new Map(graph.nodes.map((node) => [node.stableKey, node])),
    edgesByStableKey: new Map(graph.edges.map((edge) => [edge.stableKey, edge])),
  };
}

function addSmartContractRisk(
  builder: GraphBuilder,
  graphVersion: string,
  observation: SmartContractRiskObservation,
): void {
  const contract = addNode(builder, graphVersion, {
    kind: "Resource",
    stableKey: `SmartContract:${observation.repoPath}:${observation.contractName}`,
    label: observation.contractName,
    repoPath: observation.repoPath,
    lineRange: observation.lineRange,
    symbol: observation.contractName,
    properties: {
      resourceType: "smart_contract",
      contractName: observation.contractName,
      language: "solidity",
    },
    evidenceIds: observation.evidenceIds,
  });
  const sink = addNode(builder, graphVersion, {
    kind: "Sink",
    stableKey: `SmartContractRisk:${observation.repoPath}:${observation.contractName}:${observation.functionName}:${observation.riskType}`,
    label: observation.label,
    repoPath: observation.repoPath,
    lineRange: observation.lineRange,
    symbol: observation.functionName,
    properties: {
      sinkType: "smart_contract_reentrancy",
      riskType: observation.riskType,
      contractName: observation.contractName,
      functionName: observation.functionName,
      externalCallLine: observation.externalCallLine,
      stateUpdateLine: observation.stateUpdateLine,
    },
    evidenceIds: observation.evidenceIds,
  });
  addEdge(
    builder,
    graphVersion,
    "flows_to",
    contract,
    sink,
    { riskType: observation.riskType },
    observation.evidenceIds,
  );
}

function solidityFunctionBlocks(text: string): SolidityFunctionBlock[] {
  const lines = text.split(/\r?\n/);
  const blocks: SolidityFunctionBlock[] = [];
  let contractName = "Contract";
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const contractMatch = line.match(/\bcontract\s+([A-Za-z_$][\w$]*)/);
    if (contractMatch?.[1] !== undefined) {
      contractName = contractMatch[1];
    }
    const functionMatch = line.match(/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/);
    if (functionMatch?.[1] === undefined) {
      continue;
    }
    const start = index;
    const end = findBlockEnd(lines, index);
    blocks.push({
      contractName,
      functionName: functionMatch[1],
      startLine: start + 1,
      endLine: end + 1,
      text: lines.slice(start, end + 1).join("\n"),
    });
    index = end;
  }
  return blocks;
}

function findBlockEnd(lines: ReadonlyArray<string>, start: number): number {
  let depth = 0;
  let opened = false;
  for (let index = start; index < lines.length; index += 1) {
    for (const char of lines[index] ?? "") {
      if (char === "{") {
        depth += 1;
        opened = true;
      }
      if (char === "}") {
        depth -= 1;
        if (opened && depth <= 0) {
          return index;
        }
      }
    }
  }
  return start;
}

function firstRelativeLine(text: string, pattern: RegExp): number | undefined {
  const lines = text.split(/\r?\n/);
  const index = lines.findIndex((line) => pattern.test(line));
  return index < 0 ? undefined : index;
}

function withSmartContractCoverage(
  graph: SecurityGraph,
  scannedFileCount: number,
): SecurityGraph["coverage"] {
  const coverage = {
    area: "smart_contracts" as const,
    state: "checked" as const,
    coveredCount: scannedFileCount,
    totalCount: scannedFileCount,
    producer: PRODUCER,
    producerVersion: graph.graphVersion,
  };
  return [
    ...graph.coverage.filter(
      (entry) => !(entry.area === coverage.area && entry.producer === coverage.producer),
    ),
    coverage,
  ];
}

function addNode(
  builder: GraphBuilder,
  graphVersion: string,
  input: {
    readonly kind: SecurityGraphNode["kind"];
    readonly stableKey: string;
    readonly label: string;
    readonly repoPath?: string;
    readonly lineRange?: LineRange;
    readonly symbol?: string;
    readonly properties: Readonly<Record<string, unknown>>;
    readonly evidenceIds: ReadonlyArray<string>;
  },
): SecurityGraphNode {
  const existing = builder.nodesByStableKey.get(input.stableKey);
  if (existing !== undefined) {
    return existing;
  }
  const node: SecurityGraphNode = {
    id: securityGraphNodeId(graphVersion, input.stableKey),
    kind: input.kind,
    stableKey: input.stableKey,
    label: input.label,
    properties: input.properties,
    evidenceIds: input.evidenceIds,
    producer: PRODUCER,
    producerVersion: graphVersion,
    confidence: DEFAULT_CONFIDENCE,
    coverageState: "checked",
    ...(input.repoPath === undefined ? {} : { repoPath: input.repoPath }),
    ...(input.lineRange === undefined ? {} : { lineRange: input.lineRange }),
    ...(input.symbol === undefined ? {} : { symbol: input.symbol }),
  };
  builder.nodes.push(node);
  builder.nodesByStableKey.set(node.stableKey, node);
  return node;
}

function addEdge(
  builder: GraphBuilder,
  graphVersion: string,
  kind: SecurityGraphEdge["kind"],
  from: SecurityGraphNode,
  to: SecurityGraphNode,
  properties: Readonly<Record<string, unknown>>,
  evidenceIds: ReadonlyArray<string>,
): SecurityGraphEdge {
  const stableKey = `${kind}:${from.id}:${to.id}`;
  const existing = builder.edgesByStableKey.get(stableKey);
  if (existing !== undefined) {
    return existing;
  }
  const edge: SecurityGraphEdge = {
    id: securityGraphEdgeId(graphVersion, stableKey),
    kind,
    stableKey,
    fromNodeId: from.id,
    toNodeId: to.id,
    properties,
    evidenceIds,
    producer: PRODUCER,
    producerVersion: graphVersion,
    confidence: DEFAULT_CONFIDENCE,
    coverageState: "checked",
  };
  builder.edges.push(edge);
  builder.edgesByStableKey.set(edge.stableKey, edge);
  return edge;
}

function smartContractEvidenceId(kind: string, repoPath: string, value: string): string {
  const hash = createHash("sha256")
    .update(`${kind}\0${repoPath}\0${value}`)
    .digest("hex")
    .slice(0, 16);
  return `smart-contract:${kind}:${hash}`;
}

function isIgnoredSmartContractPath(repoPath: string): boolean {
  return /(^|\/)(test|tests|__tests__|fixtures|docs)\//i.test(repoPath) ||
    /(^|\/)data\/static\/codefixes\//i.test(repoPath)
    ? true
    : path.posix.basename(repoPath).toLowerCase().includes("correct");
}

function collectGraphEvidenceIds(graph: SecurityGraph): string[] {
  return unique([
    ...graph.nodes.flatMap((node) => node.evidenceIds),
    ...graph.edges.flatMap((edge) => edge.evidenceIds),
    ...graph.flows.flatMap((flow) => flow.evidenceIds),
  ]);
}

function assertEvidence(evidenceIds: ReadonlyArray<string>, label: string): void {
  if (evidenceIds.length === 0) {
    throw new Error(`${label} has no evidence`);
  }
}

function unique(values: ReadonlyArray<string>): string[] {
  return [...new Set(values)];
}
