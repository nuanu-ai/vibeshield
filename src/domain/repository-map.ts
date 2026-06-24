import type {
  GraphCoverageArea,
  GraphCoverageState,
  LineRange,
  SecurityGraphEdgeKind,
  SecurityGraphNodeKind,
} from "./security-graph.js";

export interface RepositoryMap {
  readonly graph: RepositoryMapGraph;
  readonly boundaries: ReadonlyArray<RepositoryMapNode>;
  readonly codeEntities: ReadonlyArray<RepositoryMapNode>;
  readonly integrations: ReadonlyArray<RepositoryMapNode>;
  readonly dataStores: ReadonlyArray<RepositoryMapNode>;
  readonly ciIacResources: ReadonlyArray<RepositoryMapNode>;
  readonly resources: ReadonlyArray<RepositoryMapNode>;
  readonly securityFacts: ReadonlyArray<RepositoryMapNode>;
  readonly relationships: ReadonlyArray<RepositoryMapRelationship>;
  readonly flows: ReadonlyArray<RepositoryMapFlow>;
  readonly coverage: ReadonlyArray<RepositoryMapCoverage>;
  readonly factGaps: ReadonlyArray<RepositoryMapFactGap>;
}

export interface RepositoryMapGraph {
  readonly id: string;
  readonly runId: string;
  readonly snapshotId: string;
  readonly graphVersion: string;
  readonly createdAt: string;
}

export interface RepositoryMapNode {
  readonly id: string;
  readonly kind: SecurityGraphNodeKind;
  readonly label: string;
  readonly repoPath?: string;
  readonly lineRange?: LineRange;
  readonly symbol?: string;
  readonly properties: RepositoryMapProperties;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly producer: string;
  readonly producerVersion: string;
  readonly confidence: number;
  readonly coverageState: GraphCoverageState;
}

export interface RepositoryMapRelationship {
  readonly id: string;
  readonly kind: SecurityGraphEdgeKind;
  readonly fromNodeId: string;
  readonly fromLabel: string;
  readonly toNodeId: string;
  readonly toLabel: string;
  readonly properties: RepositoryMapProperties;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly producer: string;
  readonly producerVersion: string;
  readonly confidence: number;
  readonly coverageState: GraphCoverageState;
}

export interface RepositoryMapFlow {
  readonly id: string;
  readonly sourceNodeId: string;
  readonly sourceLabel: string;
  readonly sinkNodeId: string;
  readonly sinkLabel: string;
  readonly pathEdgeIds: ReadonlyArray<string>;
  readonly controlNodeIds: ReadonlyArray<string>;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly confidence: number;
  readonly coverageState: GraphCoverageState;
}

export interface RepositoryMapCoverage {
  readonly area: GraphCoverageArea;
  readonly state: GraphCoverageState;
  readonly coveredCount?: number;
  readonly totalCount?: number;
  readonly reason?: string;
  readonly producer: string;
  readonly producerVersion: string;
}

export interface RepositoryMapFactGap {
  readonly id: string;
  readonly source: "coverage" | "node" | "edge" | "flow";
  readonly state: GraphCoverageState;
  readonly label: string;
  readonly description: string;
  readonly area?: GraphCoverageArea;
  readonly producer?: string;
  readonly graphNodeId?: string;
  readonly graphEdgeId?: string;
  readonly graphFlowId?: string;
}

export type RepositoryMapProperties = Readonly<Record<string, RepositoryMapJsonValue>>;

export type RepositoryMapJsonValue =
  | string
  | number
  | boolean
  | null
  | ReadonlyArray<RepositoryMapJsonValue>
  | { readonly [key: string]: RepositoryMapJsonValue };
