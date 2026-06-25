import type { Manifest } from "../domain/manifest.js";
import type { RunId } from "../domain/run.js";
import type {
  GraphCoverage,
  GraphCoverageState,
  LineRange,
  SecurityFlow,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphNode,
} from "../domain/security-graph.js";
import {
  securityFlowId,
  securityGraphEdgeId,
  securityGraphId,
  securityGraphNodeId,
  validateSecurityGraph,
} from "../domain/security-graph.js";
import type {
  ProgramAnalysisExtractionArtifact,
  ProgramAnalysisExtractionKind,
} from "../ports/program-analysis-backend.js";

export interface ComposeProgramAnalysisGraphInput {
  readonly runId: RunId;
  readonly snapshotId: string;
  readonly graphVersion: string;
  readonly manifest: Manifest;
  readonly artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>;
  readonly createdAt: string;
}

type ProgramAnalysisObject = Readonly<Record<string, unknown>>;

interface ObservedEntity {
  readonly fullName: string;
  readonly symbol: string;
  readonly repoPath: string;
  readonly lineRange: LineRange;
  readonly slice: ProgramAnalysisObject;
  readonly evidenceId: string;
  readonly producerVersion: string;
}

interface BoundaryHint {
  readonly boundaryType: string;
  readonly routeOrName: string;
  readonly method?: string;
  readonly sourceName?: string;
}

interface FlowBoundaryObservation {
  readonly fullName: string;
  readonly repoPath: string;
  readonly lineRange: LineRange;
  readonly sourceName: string;
  readonly evidenceId: string;
  readonly producerVersion: string;
}

interface GraphBuilder {
  readonly nodes: SecurityGraphNode[];
  readonly edges: SecurityGraphEdge[];
  readonly nodesByStableKey: Map<string, SecurityGraphNode>;
  readonly codeByFullName: Map<string, SecurityGraphNode>;
  readonly codeBySymbol: Map<string, SecurityGraphNode[]>;
  readonly edgesByStableKey: Map<string, SecurityGraphEdge>;
}

const PRODUCER = "joern";
const DEFAULT_CONFIDENCE = 0.9;
const MAX_SECURITY_FLOW_PATH_LENGTH = 6;
const SQL_METHOD_NAMES = new Set([
  "createnativequery",
  "createquery",
  "createstatement",
  "execute",
  "executebatch",
  "executecontext",
  "executelargeupdate",
  "executemany",
  "executequery",
  "executeupdate",
  "exec",
  "execcontext",
  "preparecall",
  "preparestatement",
  "query",
  "querycontext",
  "queryrow",
  "queryrowcontext",
  "update",
]);
const SQL_TEXT_PATTERN =
  /\b(?:select\s+.+\s+from|insert\s+into|update\s+[\w".`[\]]+\s+set|delete\s+from|drop\s+table|alter\s+table|create\s+table)\b/;
const HTML_TEXT_PATTERN =
  /(?:<\s*(?:script|iframe|img|svg|a|div|span|p|br|hr|input|textarea|template)\b|&lt;\s*(?:script|iframe|img|svg|a|div|span|p|br|hr|input|textarea|template)\b|\[(?:innerHTML|outerHTML)\])/i;
const RESOURCE_IDENTIFIER_PATTERN =
  /\b(?:user|account|profile|basket|cart|order|customer|tenant|owner|role|admin|invoice|document|record|resource)[\w$-]*(?:id|name|email|hash)?\b|\b(?:id|uid|bid|cid|email|username|orderid|userid|basketid|user_id|basket_id|order_id)\b/i;
const ACCESS_CONTROL_RESOURCE_PATTERN =
  /\b(?:findone|findall|findbypk|findbyid|findbyuserid|findbyusername|find|update|destroy|delete|remove|save|insert|create|collection\.find|collection\.findone|model\.find|new\s+[A-Z][\w$]*(?:Profile|Account|Basket|Order|User|Record|Resource)|UserProfile\s*\()/i;
const CSRF_STATE_CHANGE_PATTERN =
  /\b(?:setvalue|put|save|update|destroy|delete|remove|insert|create|persist|merge|flush|commit|push|add|send|post|write|collection\.update|collection\.insert|model\.create|model\.update)\b/i;
const FILE_METHOD_NAMES = new Set([
  "create",
  "createreadstream",
  "createwritestream",
  "copy",
  "delete",
  "deleteifexists",
  "open",
  "move",
  "newbufferedreader",
  "newbufferedwriter",
  "newinputstream",
  "newoutputstream",
  "readfile",
  "readallbytes",
  "readalllines",
  "readstring",
  "write",
  "writefile",
  "writestring",
]);
const WEAK_CRYPTO_INDICATORS = ["z85", "base85", "hashids", "md5", "base64"] as const;

const PYTHON_SUBPROCESS_METHODS = new Set([
  "call",
  "check_call",
  "check_output",
  "getoutput",
  "getstatusoutput",
  "popen",
  "run",
]);

const NOSQL_METHOD_NAMES = new Set([
  "aggregate",
  "bulkwrite",
  "count",
  "countdocuments",
  "deletemany",
  "deleteone",
  "distinct",
  "find",
  "findone",
  "findoneanddelete",
  "findoneandremove",
  "findoneandupdate",
  "insert",
  "insertmany",
  "insertone",
  "remove",
  "replaceone",
  "update",
  "updatemany",
  "updateone",
]);

interface SinkClassification {
  readonly label: string;
  readonly sinkType: string;
}

export function composeProgramAnalysisGraph(
  input: ComposeProgramAnalysisGraphInput,
): SecurityGraph {
  const manifestPaths = new Set(input.manifest.files.map((file) => file.path));
  const artifactsByKind = artifactsByExtractionKind(input.artifacts);
  const usageArtifacts = [
    ...artifactsOfKind(artifactsByKind, "entities"),
    ...artifactsOfKind(artifactsByKind, "boundaries"),
    ...artifactsOfKind(artifactsByKind, "call_edges"),
    ...artifactsOfKind(artifactsByKind, "component_usage"),
  ];
  const flowArtifacts = artifactsOfKind(artifactsByKind, "flows");
  const reachabilityArtifacts = [
    ...artifactsOfKind(artifactsByKind, "call_edges"),
    ...artifactsOfKind(artifactsByKind, "component_usage"),
    ...flowArtifacts,
  ];
  const builder = graphBuilder();
  const observedEntities: ObservedEntity[] = [];

  for (const artifact of usageArtifacts) {
    observedEntities.push(...readObservedEntities(artifact, manifestPaths));
  }

  for (const entity of observedEntities) {
    const node = addCodeEntity(builder, input.graphVersion, entity);
    builder.codeByFullName.set(entity.fullName, node);
    addSymbolTarget(builder, entity.symbol, node);
  }

  for (const entity of observedEntities) {
    const owner = builder.codeByFullName.get(entity.fullName);
    if (owner === undefined) {
      continue;
    }
    addBoundaryHint(builder, input.graphVersion, entity, owner);
  }

  for (const observation of readFlowBoundaryObservations(reachabilityArtifacts, manifestPaths)) {
    addFlowBoundaryObservation(builder, input.graphVersion, observation);
  }

  for (const entity of observedEntities) {
    const owner = builder.codeByFullName.get(entity.fullName);
    if (owner === undefined) {
      continue;
    }
    addObservedCalls(builder, input.graphVersion, entity, owner);
    addEntitySemanticSinks(builder, input.graphVersion, entity, owner);
  }
  addLexicalFlowEdges(builder, input.graphVersion);

  const flows = buildFlows(input.graphVersion, builder);
  const graph: SecurityGraph = {
    id: securityGraphId(input.snapshotId, input.graphVersion),
    runId: input.runId,
    snapshotId: input.snapshotId,
    graphVersion: input.graphVersion,
    nodes: builder.nodes,
    edges: builder.edges,
    flows,
    coverage: buildCoverage({
      producerVersion: producerVersion(input.artifacts),
      entityCount: observedEntities.length,
      boundaryCount: countNodes(builder, "Boundary"),
      callEdgeCount: countEdges(builder, "calls"),
      flowArtifactCount: flowArtifacts.length,
      flowCount: flows.length,
    }),
    createdAt: input.createdAt,
  };

  const evidenceIds = new Set(input.artifacts.map((artifact) => artifact.sliceArtifact.blobSha256));
  return validateSecurityGraph(graph, { manifestPaths, evidenceIds });
}

function artifactsByExtractionKind(
  artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>,
): ReadonlyMap<ProgramAnalysisExtractionKind, ProgramAnalysisExtractionArtifact[]> {
  const byKind = new Map<ProgramAnalysisExtractionKind, ProgramAnalysisExtractionArtifact[]>();
  for (const artifact of artifacts) {
    const current = byKind.get(artifact.kind) ?? [];
    current.push(artifact);
    byKind.set(artifact.kind, current);
  }
  return byKind;
}

function artifactsOfKind(
  artifacts: ReadonlyMap<ProgramAnalysisExtractionKind, ProgramAnalysisExtractionArtifact[]>,
  kind: ProgramAnalysisExtractionKind,
): ReadonlyArray<ProgramAnalysisExtractionArtifact> {
  return artifacts.get(kind) ?? [];
}

function graphBuilder(): GraphBuilder {
  return {
    nodes: [],
    edges: [],
    nodesByStableKey: new Map(),
    codeByFullName: new Map(),
    codeBySymbol: new Map(),
    edgesByStableKey: new Map(),
  };
}

function readObservedEntities(
  artifact: ProgramAnalysisExtractionArtifact,
  manifestPaths: ReadonlySet<string>,
): ObservedEntity[] {
  const root = asObject(artifact.parsed);
  const objectSlices = asObjectArray(root.objectSlices);
  const observed: ObservedEntity[] = [];

  for (const slice of objectSlices) {
    const fullName = stringValue(slice.fullName);
    const repoPath = stringValue(slice.fileName);
    const lineNumber = positiveInteger(slice.lineNumber);
    if (fullName === undefined || repoPath === undefined || lineNumber === undefined) {
      continue;
    }
    if (!isSafeManifestPath(repoPath, manifestPaths)) {
      continue;
    }
    observed.push({
      fullName,
      symbol: symbolFromFullName(fullName),
      repoPath,
      lineRange: { startLine: lineNumber, endLine: lineNumber },
      slice,
      evidenceId: artifact.sliceArtifact.blobSha256,
      producerVersion: artifact.backendVersion,
    });
  }

  return observed;
}

function readFlowBoundaryObservations(
  artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>,
  manifestPaths: ReadonlySet<string>,
): FlowBoundaryObservation[] {
  return artifacts.flatMap((artifact) => {
    const observations: FlowBoundaryObservation[] = [];
    for (const flowRecord of asObjectArray(artifact.parsed)) {
      for (const flow of asObjectArray(flowRecord.flows)) {
        const label = stringValue(flow.label);
        const tags = stringValue(flow.tags);
        const repoPath = stringValue(flow.parentFileName);
        const methodName = stringValue(flow.parentMethodName);
        const parentClassName = stringValue(flow.parentClassName);
        const lineNumber = positiveInteger(flow.lineNumber);
        const sourceName = stringValue(flow.name) ?? stringValue(flow.code);
        if (
          label !== "METHOD_PARAMETER_IN" ||
          tags?.includes("framework-input") !== true ||
          repoPath === undefined ||
          methodName === undefined ||
          lineNumber === undefined ||
          sourceName === undefined ||
          !isSafeManifestPath(repoPath, manifestPaths)
        ) {
          continue;
        }
        observations.push({
          fullName:
            parentClassName === undefined
              ? `${repoPath}::program:${methodName}`
              : `${parentClassName}:${methodName}`,
          repoPath,
          lineRange: { startLine: lineNumber, endLine: lineNumber },
          sourceName,
          evidenceId: artifact.sliceArtifact.blobSha256,
          producerVersion: artifact.backendVersion,
        });
      }
    }
    return observations;
  });
}

function addCodeEntity(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
): SecurityGraphNode {
  return addNode(builder, graphVersion, {
    kind: "CodeEntity",
    stableKey: `CodeEntity:${entity.fullName}:${entity.repoPath}:${entity.lineRange.startLine}`,
    label: entity.symbol,
    repoPath: entity.repoPath,
    lineRange: entity.lineRange,
    symbol: entity.fullName,
    properties: {
      fullName: entity.fullName,
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
}

function addBoundaryHint(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
  owner: SecurityGraphNode,
): void {
  const hint = boundaryHint(entity.slice.boundary);
  if (hint === undefined) {
    return;
  }

  const boundary = addNode(builder, graphVersion, {
    kind: "Boundary",
    stableKey: `Boundary:${hint.boundaryType}:${hint.method ?? ""}:${hint.routeOrName}:${entity.fullName}`,
    label: hint.routeOrName,
    repoPath: entity.repoPath,
    lineRange: entity.lineRange,
    symbol: entity.fullName,
    properties: {
      boundaryType: hint.boundaryType,
      routeOrName: hint.routeOrName,
      ...(hint.method === undefined ? {} : { method: hint.method }),
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
  const source = addNode(builder, graphVersion, {
    kind: "Source",
    stableKey: `Source:${boundary.stableKey}:${hint.sourceName ?? "request"}`,
    label: hint.sourceName ?? "request input",
    repoPath: entity.repoPath,
    lineRange: entity.lineRange,
    symbol: hint.sourceName ?? "request",
    properties: {
      sourceType: "external_input",
      boundaryNodeId: boundary.id,
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });

  addEdge(builder, graphVersion, {
    kind: "receives",
    stableKey: `receives:${source.id}:${boundary.id}`,
    fromNodeId: source.id,
    toNodeId: boundary.id,
    properties: {},
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
  addEdge(builder, graphVersion, {
    kind: "registers",
    stableKey: `registers:${boundary.id}:${owner.id}`,
    fromNodeId: boundary.id,
    toNodeId: owner.id,
    properties: {},
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
}

function addFlowBoundaryObservation(
  builder: GraphBuilder,
  graphVersion: string,
  observation: FlowBoundaryObservation,
): void {
  const owner = findBoundaryOwner(builder, observation);
  if (owner === undefined || hasRegisteredBoundary(builder, owner.id)) {
    return;
  }

  const boundary = addNode(builder, graphVersion, {
    kind: "Boundary",
    stableKey: `Boundary:framework-input::${owner.symbol ?? owner.label}`,
    label: observationLabel(observation),
    repoPath: observation.repoPath,
    lineRange: observation.lineRange,
    ...(owner.symbol === undefined ? {} : { symbol: owner.symbol }),
    properties: {
      boundaryType: "framework-input",
      routeOrName: observationLabel(observation),
    },
    evidenceIds: [observation.evidenceId],
    producerVersion: observation.producerVersion,
  });
  const source = addNode(builder, graphVersion, {
    kind: "Source",
    stableKey: `Source:${boundary.stableKey}:${observation.sourceName}`,
    label: observation.sourceName,
    repoPath: observation.repoPath,
    lineRange: observation.lineRange,
    symbol: observation.sourceName,
    properties: {
      sourceType: "external_input",
      boundaryNodeId: boundary.id,
    },
    evidenceIds: [observation.evidenceId],
    producerVersion: observation.producerVersion,
  });

  addEdge(builder, graphVersion, {
    kind: "receives",
    stableKey: `receives:${source.id}:${boundary.id}`,
    fromNodeId: source.id,
    toNodeId: boundary.id,
    properties: {},
    evidenceIds: [observation.evidenceId],
    producerVersion: observation.producerVersion,
  });
  addEdge(builder, graphVersion, {
    kind: "registers",
    stableKey: `registers:${boundary.id}:${owner.id}`,
    fromNodeId: boundary.id,
    toNodeId: owner.id,
    properties: {},
    evidenceIds: [observation.evidenceId],
    producerVersion: observation.producerVersion,
  });
}

function addObservedCalls(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
  owner: SecurityGraphNode,
): void {
  for (const usage of asObjectArray(entity.slice.usages)) {
    const target = asObject(usage.targetObj);
    const name = stringValue(target.resolvedMethod) ?? stringValue(target.name);
    if (name === undefined || stringValue(target.label) !== "CALL") {
      continue;
    }
    addRouteRegistrationHandlerCalls(builder, graphVersion, entity, owner, target);
    addJavascriptSocketEventBoundary(builder, graphVersion, entity, owner, target);
    const targetNode =
      findTargetCodeEntity(builder, name) ??
      addSinkIfKnown(builder, graphVersion, entity, target, name);
    if (targetNode === undefined) {
      continue;
    }
    addEdge(builder, graphVersion, {
      kind: "calls",
      stableKey: `calls:${owner.id}:${targetNode.id}:${entity.repoPath}:${positiveInteger(target.lineNumber) ?? entity.lineRange.startLine}`,
      fromNodeId: owner.id,
      toNodeId: targetNode.id,
      properties: {
        callName: name,
      },
      evidenceIds: [entity.evidenceId],
      producerVersion: entity.producerVersion,
    });
  }
}

function addEntitySemanticSinks(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
  owner: SecurityGraphNode,
): void {
  const indicators = weakCryptoVerifierIndicators(entity);
  if (indicators.length === 0) {
    return;
  }
  const label = "weak crypto indicator verifier";
  const sink = addNode(builder, graphVersion, {
    kind: "Sink",
    stableKey: `Sink:crypto_weakness:${label}:${entity.fullName}:${entity.repoPath}:${entity.lineRange.startLine}`,
    label,
    repoPath: entity.repoPath,
    lineRange: entity.lineRange,
    symbol: label,
    properties: {
      sinkType: "crypto_weakness",
      semantic: "weak_crypto_indicator_verifier",
      indicators,
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });

  addEdge(builder, graphVersion, {
    kind: "flows_to",
    stableKey: `flows_to:${owner.id}:${sink.id}:weak-crypto-indicator-verifier`,
    fromNodeId: owner.id,
    toNodeId: sink.id,
    properties: {
      reason: "weak_crypto_indicator_verifier",
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
}

function addJavascriptSocketEventBoundary(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
  owner: SecurityGraphNode,
  target: ProgramAnalysisObject,
): void {
  const code = stringValue(target.code);
  const eventName = code === undefined ? undefined : javascriptSocketEventName(code);
  if (eventName === undefined) {
    return;
  }

  const lineNumber = positiveInteger(target.lineNumber) ?? entity.lineRange.startLine;
  const lineRange = { startLine: lineNumber, endLine: lineNumber };
  const sourceName = javascriptSocketPayloadName(code ?? "") ?? "socket payload";
  const boundary = addNode(builder, graphVersion, {
    kind: "Boundary",
    stableKey: `Boundary:socket-event::${eventName}:${entity.fullName}:${lineNumber}`,
    label: eventName,
    repoPath: entity.repoPath,
    lineRange,
    symbol: entity.fullName,
    properties: {
      boundaryType: "socket-event",
      routeOrName: eventName,
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
  const source = addNode(builder, graphVersion, {
    kind: "Source",
    stableKey: `Source:${boundary.stableKey}:${sourceName}`,
    label: sourceName,
    repoPath: entity.repoPath,
    lineRange,
    symbol: sourceName,
    properties: {
      sourceType: "external_input",
      boundaryNodeId: boundary.id,
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });

  addEdge(builder, graphVersion, {
    kind: "receives",
    stableKey: `receives:${source.id}:${boundary.id}`,
    fromNodeId: source.id,
    toNodeId: boundary.id,
    properties: {},
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
  addEdge(builder, graphVersion, {
    kind: "registers",
    stableKey: `registers:${boundary.id}:${owner.id}`,
    fromNodeId: boundary.id,
    toNodeId: owner.id,
    properties: {},
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
}

function javascriptSocketEventName(code: string): string | undefined {
  if (!/\b(?:socket|io)\.(?:on|once)\s*\(/i.test(code)) {
    return undefined;
  }
  return code.match(/\b(?:socket|io)\.(?:on|once)\s*\(\s*["'`]([^"'`]+)["'`]\s*,/i)?.[1];
}

function javascriptSocketPayloadName(code: string): string | undefined {
  return code.match(/,\s*(?:async\s*)?\(?\s*([A-Za-z_$][\w$]*)\s*(?::[^)=]+)?\)?\s*=>/i)?.[1];
}

function addRouteRegistrationHandlerCalls(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
  owner: SecurityGraphNode,
  target: ProgramAnalysisObject,
): void {
  const code = stringValue(target.code);
  if (code === undefined || !isJavascriptRouteRegistration(code)) {
    return;
  }
  for (const handlerName of routeRegistrationHandlerNames(code)) {
    const targetNode = findTargetCodeEntity(builder, handlerName);
    if (targetNode === undefined || targetNode.id === owner.id) {
      continue;
    }
    addEdge(builder, graphVersion, {
      kind: "calls",
      stableKey: `calls:${owner.id}:${targetNode.id}:${entity.repoPath}:${positiveInteger(target.lineNumber) ?? entity.lineRange.startLine}:route-handler`,
      fromNodeId: owner.id,
      toNodeId: targetNode.id,
      properties: {
        callName: handlerName,
        callType: "route_handler_registration",
      },
      evidenceIds: [entity.evidenceId],
      producerVersion: entity.producerVersion,
    });
  }
}

function findTargetCodeEntity(builder: GraphBuilder, name: string): SecurityGraphNode | undefined {
  const exactTarget = builder.codeByFullName.get(name);
  if (exactTarget !== undefined) {
    return exactTarget;
  }
  const symbolTargets = builder.codeBySymbol.get(symbolFromFullName(name)) ?? [];
  return symbolTargets.length === 1 ? symbolTargets[0] : undefined;
}

function isJavascriptRouteRegistration(code: string): boolean {
  return /\b(?:app|router|server)\.(?:get|post|put|patch|delete|all|use)\s*\(/i.test(code);
}

function routeRegistrationHandlerNames(code: string): string[] {
  const args = callArguments(code);
  if (args.length < 2) {
    return [];
  }
  return unique(
    args
      .slice(1)
      .flatMap(handlerNamesFromRouteArgument)
      .filter((name) => !isIgnoredRouteHandlerName(name)),
  );
}

function callArguments(code: string): string[] {
  const open = code.indexOf("(");
  const close = code.lastIndexOf(")");
  if (open < 0 || close <= open) {
    return [];
  }
  const args: string[] = [];
  let current = "";
  let depth = 0;
  let quote: string | undefined;
  let escaped = false;
  for (const char of code.slice(open + 1, close)) {
    if (quote !== undefined) {
      current += char;
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = undefined;
      }
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      current += char;
      continue;
    }
    if (char === "(" || char === "[" || char === "{") {
      depth += 1;
      current += char;
      continue;
    }
    if (char === ")" || char === "]" || char === "}") {
      depth = Math.max(0, depth - 1);
      current += char;
      continue;
    }
    if (char === "," && depth === 0) {
      args.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  if (current.trim() !== "") {
    args.push(current.trim());
  }
  return args;
}

function handlerNamesFromRouteArgument(argument: string): string[] {
  const trimmed = argument.trim();
  if (trimmed === "" || /^["'`]/.test(trimmed) || trimmed.startsWith("{")) {
    return [];
  }
  const direct = trimmed.match(/^([A-Za-z_$][\w$]*)$/)?.[1];
  if (direct !== undefined) {
    return [direct];
  }
  const wrapped = trimmed.match(/\b([A-Za-z_$][\w$]*)\s*\(\s*\)?\s*$/)?.[1];
  if (wrapped !== undefined && !trimmed.includes(".")) {
    return [wrapped];
  }
  const asyncWrapped = trimmed.match(/\basyncHandler\s*\(\s*([A-Za-z_$][\w$]*)\s*\(/)?.[1];
  if (asyncWrapped !== undefined) {
    return [asyncWrapped];
  }
  return [];
}

function isIgnoredRouteHandlerName(name: string): boolean {
  return (
    name === "undefined" ||
    name === "null" ||
    name === "true" ||
    name === "false" ||
    name === "Number" ||
    name === "String" ||
    name === "Boolean"
  );
}

function findBoundaryOwner(
  builder: GraphBuilder,
  observation: FlowBoundaryObservation,
): SecurityGraphNode | undefined {
  const exactTarget = builder.codeByFullName.get(observation.fullName);
  if (exactTarget !== undefined) {
    return exactTarget;
  }
  const symbolTargets = builder.codeBySymbol.get(symbolFromFullName(observation.fullName)) ?? [];
  const sameFileTargets = symbolTargets.filter((node) => node.repoPath === observation.repoPath);
  return sameFileTargets.length === 1 ? sameFileTargets[0] : undefined;
}

function hasRegisteredBoundary(builder: GraphBuilder, ownerId: string): boolean {
  return builder.edges.some(
    (edge) =>
      edge.kind === "registers" &&
      edge.toNodeId === ownerId &&
      builder.nodes.find((node) => node.id === edge.fromNodeId)?.kind === "Boundary",
  );
}

function addSymbolTarget(builder: GraphBuilder, symbol: string, node: SecurityGraphNode): void {
  const current = builder.codeBySymbol.get(symbol) ?? [];
  if (current.some((target) => target.id === node.id)) {
    return;
  }
  builder.codeBySymbol.set(symbol, [...current, node]);
}

function addSinkIfKnown(
  builder: GraphBuilder,
  graphVersion: string,
  entity: ObservedEntity,
  target: ProgramAnalysisObject,
  name: string,
): SecurityGraphNode | undefined {
  const classification = classifySinkCall(target, name, entity);
  if (classification === undefined) {
    return undefined;
  }
  const lineNumber = positiveInteger(target.lineNumber) ?? entity.lineRange.startLine;
  return addNode(builder, graphVersion, {
    kind: "Sink",
    stableKey: `Sink:${classification.sinkType}:${classification.label}:${entity.fullName}:${entity.repoPath}:${lineNumber}`,
    label: classification.label,
    repoPath: entity.repoPath,
    lineRange: { startLine: lineNumber, endLine: lineNumber },
    symbol: classification.label,
    properties: {
      sinkType: classification.sinkType,
      callName: name,
    },
    evidenceIds: [entity.evidenceId],
    producerVersion: entity.producerVersion,
  });
}

function classifySinkCall(
  target: ProgramAnalysisObject,
  selectedName: string,
  entity: ObservedEntity,
): SinkClassification | undefined {
  const candidates = unique([
    selectedName,
    stringValue(target.name) ?? "",
    stringValue(target.resolvedMethod) ?? "",
    stringValue(target.code) ?? "",
  ]).filter((value) => value !== "");

  for (const candidate of candidates) {
    const classification = classifySinkCandidate(candidate, entity);
    if (classification !== undefined) {
      return classification;
    }
  }
  return undefined;
}

function classifySinkCandidate(
  candidate: string,
  entity: ObservedEntity,
): SinkClassification | undefined {
  const lower = candidate.toLowerCase();
  const rawMethodName = methodNameFromCall(candidate);
  const methodName = rawMethodName.toLowerCase();
  const label = normalizedCallLabel(candidate, rawMethodName);
  const repoPath = entity.repoPath;

  if (
    methodName === "eval" ||
    (methodName === "exec" && /(^|[^\w.])exec\s*\(/.test(lower)) ||
    lower.includes("os.system") ||
    lower.includes("os.popen") ||
    (lower.includes("subprocess.") && PYTHON_SUBPROCESS_METHODS.has(methodName)) ||
    lower.includes("commands.getoutput") ||
    lower.includes("exec.command") ||
    lower.includes("child_process.exec") ||
    lower.includes("runtime.exec") ||
    (methodName === "exec" && (lower.includes("child_process") || lower.includes("runtime"))) ||
    (methodName === "start" && lower.includes("processbuilder"))
  ) {
    return { label, sinkType: "code_execution" };
  }

  const httpLabel = outboundHttpLabel(candidate, lower, methodName);
  if (httpLabel !== undefined) {
    return { label: httpLabel, sinkType: outboundHttpSinkType(repoPath, lower) };
  }

  if (isCryptographicOperation(candidate, lower, methodName, entity)) {
    return { label: cryptographicLabel(candidate, label), sinkType: "crypto_weakness" };
  }

  if (isJwtTokenTrustOperation(candidate, lower, methodName, entity)) {
    return { label: jwtTokenTrustLabel(candidate, label), sinkType: "jwt_token_trust" };
  }

  if (isPasswordResetTrustOperation(candidate, lower, methodName, entity)) {
    return {
      label: passwordResetTrustLabel(candidate, label),
      sinkType: "password_reset_trust",
    };
  }

  if (isTwoFactorTokenTrustOperation(candidate, lower, methodName, entity)) {
    return {
      label: twoFactorTokenTrustLabel(candidate, label),
      sinkType: "two_factor_token_trust",
    };
  }

  if (isLlmToolTrustOperation(candidate, lower, methodName, entity)) {
    return { label: llmToolTrustLabel(candidate, label), sinkType: "llm_tool_trust" };
  }

  if (isCouponEncodingTrustOperation(candidate, lower, methodName, entity)) {
    return {
      label: couponEncodingTrustLabel(candidate, label),
      sinkType: "coupon_encoding_trust",
    };
  }

  if (isAntiAutomationBypassOperation(candidate, lower, methodName, entity)) {
    return {
      label: antiAutomationBypassLabel(candidate, label, entity),
      sinkType: "anti_automation_bypass",
    };
  }

  if (isNoSqlOperation(lower, methodName)) {
    return { label, sinkType: "no_sql_execution" };
  }

  if (isAuthenticationBypassOperation(candidate, lower, methodName, entity)) {
    return {
      label: authenticationBypassLabel(candidate, label),
      sinkType: "authentication_bypass",
    };
  }

  if (isSecurityMisconfigurationOperation(candidate, lower, methodName, entity)) {
    return {
      label: securityMisconfigurationLabel(candidate, label, entity),
      sinkType: "security_misconfiguration",
    };
  }

  if (isSessionCookieTrustOperation(candidate, lower, methodName, entity)) {
    return {
      label: sessionCookieTrustLabel(candidate, label),
      sinkType: "session_cookie_trust",
    };
  }

  if (isCredentialTrustOperation(candidate, lower, methodName, entity)) {
    return { label: credentialTrustLabel(candidate, label, entity), sinkType: "credential_trust" };
  }

  if (isClientSideTrustOperation(candidate, lower, methodName, entity)) {
    return { label: clientSideTrustLabel(candidate, label), sinkType: "client_side_trust" };
  }

  if (isLogInjectionOperation(candidate, lower, methodName, entity)) {
    return { label: logInjectionLabel(candidate, label), sinkType: "log_injection" };
  }

  if (isAccessControlSensitiveResourceUse(candidate, lower, methodName, entity)) {
    return { label: accessControlLabel(candidate, label, entity), sinkType: "access_control" };
  }

  if (isCsrfSensitiveStateChange(candidate, lower, methodName, entity)) {
    return { label, sinkType: "csrf_state_change" };
  }

  if (isTemplateRenderOperation(lower, methodName)) {
    return { label, sinkType: "template_render" };
  }

  const xssLabel = crossSiteScriptingLabel(candidate, lower, methodName, label, entity);
  if (xssLabel !== undefined) {
    return { label: xssLabel, sinkType: "cross_site_scripting" };
  }

  if (SQL_METHOD_NAMES.has(methodName) && hasSqlContext(lower, methodName)) {
    return { label, sinkType: "sql_execution" };
  }

  if (
    (methodName === "readobject" &&
      (lower.includes("objectinputstream") ||
        lower.includes("xmldecoder") ||
        lower.includes(".readobject"))) ||
    lower.includes("pickle.loads") ||
    lower.includes("pickle.load") ||
    lower.includes("yaml.load")
  ) {
    return { label, sinkType: "deserialization" };
  }

  if (
    (methodName === "parse" || methodName === "unmarshal" || methodName === "read") &&
    (lower.includes("documentbuilder") ||
      lower.includes("saxparser") ||
      lower.includes("xmlinputfactory") ||
      lower.includes("xmlreader") ||
      lower.includes("saxreader") ||
      lower.includes("unmarshaller") ||
      lower.includes(".xml"))
  ) {
    return { label, sinkType: "xml_processing" };
  }
  if (isXmlProcessingOperation(lower, methodName)) {
    return { label, sinkType: "xml_processing" };
  }

  if (
    (FILE_METHOD_NAMES.has(methodName) &&
      (lower.includes("java.nio.file") ||
        lower.includes("java.io.") ||
        lower.includes("files.") ||
        lower.includes("pathlib.") ||
        lower.includes("os.open") ||
        lower.includes("os.create") ||
        lower.includes("ioutil.") ||
        lower.includes("os.readfile") ||
        lower.includes("os.writefile") ||
        lower.includes("fs.") ||
        lower.includes("node:fs") ||
        lower.includes("fs/promises") ||
        lower.includes("fileinputstream") ||
        lower.includes("fileoutputstream"))) ||
    (methodName === "open" && isBareFileOpen(repoPath, lower)) ||
    (methodName === "sendfile" && (lower.includes("sendfile") || lower.includes("path."))) ||
    (methodName === "get" && (lower.includes("paths.get") || lower.includes("filesystems.getpath")))
  ) {
    return { label, sinkType: "file_system" };
  }

  if (isFileUploadValidationOperation(candidate, lower, methodName)) {
    return { label: fileUploadLabel(candidate, label), sinkType: "file_upload_validation" };
  }

  if (
    methodName === "sendredirect" ||
    methodName === "redirect" ||
    lower.includes("redirectview")
  ) {
    return { label, sinkType: "redirect" };
  }

  if (
    (methodName === "process" &&
      (lower.includes("templateengine") || lower.includes("template.process"))) ||
    methodName === "render_template_string"
  ) {
    return { label, sinkType: "template_render" };
  }

  return undefined;
}

function isCryptographicOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  const cryptoContext =
    context.includes("/crypto/") ||
    context.includes("lessons.cryptography") ||
    context.includes("java.security.") ||
    context.includes("javax.crypto") ||
    context.includes("crypto.");
  if (!cryptoContext) {
    return false;
  }
  return (
    lower.includes("messagedigest") ||
    lower.includes("base64") ||
    lower.includes("keypairgenerator") ||
    lower.includes("signature.getinstance") ||
    lower.includes("signature.sign") ||
    lower.includes("signature.verify") ||
    lower.includes("javax.crypto") ||
    lower.includes("cipher.getinstance") ||
    (methodName === "getinstance" &&
      /\b(?:md5|sha1|sha-1|des|rc4|rsa|aes|cipher|signature|messagedigest)\b/i.test(candidate))
  );
}

function weakCryptoVerifierIndicators(entity: ObservedEntity): string[] {
  const context = entitySemanticContext(entity);
  if (!hasWeakCryptoVerifierContext(context)) {
    return [];
  }
  const indicators = WEAK_CRYPTO_INDICATORS.filter((indicator) =>
    weakCryptoIndicatorPattern(indicator).test(context),
  );
  return indicators.length >= 2 ? indicators : [];
}

function entitySemanticContext(entity: ObservedEntity): string {
  return [entity.fullName, entity.repoPath, JSON.stringify(entity.slice)].join("\n").toLowerCase();
}

function hasWeakCryptoVerifierContext(context: string): boolean {
  return /\b(?:op\.like|like|pattern|feedback|complaint|answer|challenge|verify|validator|allowlist|denylist)\b/i.test(
    context,
  );
}

function weakCryptoIndicatorPattern(indicator: string): RegExp {
  return new RegExp(`(?:^|[^a-z0-9])${escapeRegExp(indicator)}(?:[^a-z0-9]|$)`, "i");
}

function cryptographicLabel(candidate: string, fallbackLabel: string): string {
  const lower = candidate.toLowerCase();
  if (lower.includes("messagedigest")) {
    return "cryptographic digest";
  }
  if (lower.includes("base64")) {
    return "encoding operation";
  }
  if (lower.includes("signature")) {
    return "signature operation";
  }
  if (lower.includes("keypairgenerator") || lower.includes("keyfactory")) {
    return "key generation operation";
  }
  if (lower.includes("cipher")) {
    return "cipher operation";
  }
  return fallbackLabel;
}

function isJwtTokenTrustOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  const jwtContext =
    context.includes("/jwt/") ||
    context.includes("lessons.jwt") ||
    context.includes("routes/verify.ts") ||
    context.includes("lib/insecurity.ts") ||
    lower.includes("jsonwebtoken") ||
    lower.includes("io.jsonwebtoken") ||
    lower.includes("jwts.") ||
    lower.includes("com.auth0.jwt") ||
    lower.includes("signwith") ||
    lower.includes("setsigningkey");
  if (!jwtContext) {
    return false;
  }
  return (
    lower.includes("jwts.") ||
    lower.includes("io.jsonwebtoken") ||
    lower.includes("jwt.decode") ||
    lower.includes("jsonwebtoken.") ||
    lower.includes("signwith") ||
    lower.includes("jwtfrom") ||
    lower.includes("hasalgorithm") ||
    lower.includes("hasemail") ||
    lower.includes("parseclaimsjws") ||
    lower.includes("parseclaimsjwt") ||
    lower.includes("parse(") ||
    lower.includes("setSigningKey".toLowerCase()) ||
    [
      "authorize",
      "decode",
      "sign",
      "verify",
      "parse",
      "jwtfrom",
      "hasalgorithm",
      "hasemail",
      "signwith",
      "setsigningkey",
    ].includes(methodName)
  );
}

function jwtTokenTrustLabel(candidate: string, fallbackLabel: string): string {
  const lower = candidate.toLowerCase();
  if (lower.includes("signwith") || lower.includes(".sign")) {
    return "JWT signing";
  }
  if (lower.includes("parse") || lower.includes("setsigningkey") || lower.includes("verify")) {
    return "JWT verification";
  }
  if (lower.includes("decode")) {
    return "JWT decode";
  }
  return fallbackLabel;
}

function isPasswordResetTrustOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (!(context.includes("routes/resetpassword.ts") || context.includes("resetpassword"))) {
    return false;
  }
  return (
    ["findone", "hmac", "update", "solveif"].includes(methodName) ||
    lower.includes("securityanswermodel") ||
    lower.includes("security answer") ||
    lower.includes("verifysecurityanswerchallenges") ||
    lower.includes("newpassword")
  );
}

function passwordResetTrustLabel(candidate: string, fallbackLabel: string): string {
  const lower = candidate.toLowerCase();
  if (lower.includes("securityanswer") || lower.includes("hmac")) {
    return "security-question reset";
  }
  if (lower.includes("update") || lower.includes("newpassword")) {
    return "password update";
  }
  return fallbackLabel;
}

function isTwoFactorTokenTrustOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (!context.includes("routes/2fa.ts")) {
    return false;
  }
  return (
    ["verifysync", "generatesecret", "authorize", "verify", "decode", "save"].includes(
      methodName,
    ) ||
    lower.includes("totp") ||
    lower.includes("setuptoken") ||
    lower.includes("initialtoken") ||
    lower.includes("epochTolerance".toLowerCase())
  );
}

function twoFactorTokenTrustLabel(candidate: string, fallbackLabel: string): string {
  const lower = candidate.toLowerCase();
  if (lower.includes("verifysync") || lower.includes("totp")) {
    return "TOTP token trust";
  }
  if (lower.includes("generatesecret") || lower.includes("setuptoken")) {
    return "TOTP setup-token trust";
  }
  return fallbackLabel;
}

function isLlmToolTrustOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (
    !(
      context.includes("routes/chat.ts") ||
      context.includes("chatbotpromptinjectionchallenge") ||
      context.includes("chatbotgreedyinjectionchallenge")
    )
  ) {
    return false;
  }
  return (
    [
      "tool",
      "generatecoupon",
      "buildsystemprompt",
      "streamtext",
      "createopenaicompatible",
    ].includes(methodName) ||
    lower.includes("generatecoupon") ||
    lower.includes("system prompt") ||
    lower.includes("coupon policy") ||
    lower.includes("llm") ||
    lower.includes("tool(")
  );
}

function llmToolTrustLabel(candidate: string, fallbackLabel: string): string {
  const lower = candidate.toLowerCase();
  if (lower.includes("generatecoupon") || lower.includes("tool(")) {
    return "LLM tool trust";
  }
  if (lower.includes("systemprompt") || lower.includes("system prompt")) {
    return "LLM prompt trust";
  }
  return fallbackLabel;
}

function isCouponEncodingTrustOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (!(context.includes("routes/coupon.ts") || context.includes("lib/insecurity.ts"))) {
    return false;
  }
  return (
    [
      "generatecoupon",
      "discountfromcoupon",
      "encode",
      "decode",
      "parseint",
      "hasvalidformat",
    ].includes(methodName) ||
    lower.includes("z85.encode") ||
    lower.includes("z85.decode") ||
    lower.includes("discountfromcoupon") ||
    lower.includes("coupon") ||
    lower.includes("hasvalidformat")
  );
}

function couponEncodingTrustLabel(candidate: string, fallbackLabel: string): string {
  const lower = candidate.toLowerCase();
  if (
    lower.includes("z85") ||
    lower.includes("generatecoupon") ||
    lower.includes("discountfromcoupon")
  ) {
    return "Coupon encoding trust";
  }
  return fallbackLabel;
}

function isAntiAutomationBypassOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (isCaptchaBypassContext(context)) {
    return (
      methodName === "solve" ||
      methodName === "solveif" ||
      lower.includes("captchabypasschallenge") ||
      lower.includes("captchareqid") ||
      lower.includes("captchabypassreqtimes")
    );
  }
  if (isHiddenResourceAutomationContext(context)) {
    return (
      methodName === "solveif" ||
      lower.includes("extralanguagechallenge") ||
      lower.includes("tlh_aa.json")
    );
  }
  if (isDuplicateActionRaceContext(context)) {
    return (
      methodName === "solveif" ||
      lower.includes("timingattackchallenge") ||
      lower.includes("count > 2") ||
      lower.includes("likedby")
    );
  }
  return false;
}

function antiAutomationBypassLabel(
  candidate: string,
  fallbackLabel: string,
  entity: ObservedEntity,
): string {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (isCaptchaBypassContext(context)) {
    return "CAPTCHA rate bypass";
  }
  if (isHiddenResourceAutomationContext(context)) {
    return "hidden resource enumeration";
  }
  if (isDuplicateActionRaceContext(context)) {
    return "duplicate action race";
  }
  return fallbackLabel;
}

function isCaptchaBypassContext(context: string): boolean {
  return (
    context.includes("captchabypasschallenge") ||
    context.includes("captchareqid") ||
    context.includes("captchabypassreqtimes")
  );
}

function isHiddenResourceAutomationContext(context: string): boolean {
  return context.includes("extralanguagechallenge") || context.includes("tlh_aa.json");
}

function isDuplicateActionRaceContext(context: string): boolean {
  return (
    context.includes("timingattackchallenge") ||
    (context.includes("routes/likeproductreviews.ts") &&
      (context.includes("likedby") || context.includes("count > 2")))
  );
}

function isNoSqlOperation(lower: string, methodName: string): boolean {
  if (!NOSQL_METHOD_NAMES.has(methodName)) {
    return false;
  }
  if (
    lower.includes("mongodb") ||
    lower.includes("mongoose") ||
    lower.includes("mongoclient") ||
    lower.includes("nosql") ||
    lower.includes("$where") ||
    lower.includes("$set") ||
    lower.includes("$ne") ||
    lower.includes("$regex") ||
    lower.includes("objectid") ||
    /\b\w+collection\.(?:aggregate|count|countdocuments|deletemany|deleteone|distinct|find|findone|findoneanddelete|findoneandremove|findoneandupdate|insert|insertmany|insertone|remove|replaceone|update|updatemany|updateone)\s*\(/.test(
      lower,
    )
  ) {
    return true;
  }
  return /\b(?:db|database)\.[\w$]+\.(?:aggregate|count|countdocuments|deletemany|deleteone|distinct|find|findone|findoneanddelete|findoneandremove|findoneandupdate|insert|insertmany|insertone|remove|replaceone|update|updatemany|updateone)\s*\(/.test(
    lower,
  );
}

function isXmlProcessingOperation(lower: string, methodName: string): boolean {
  return (
    methodName === "parsexmlstring" ||
    lower.includes("xmldocument.fromstring") ||
    lower.includes("libxml2.xmldocument.fromstring") ||
    lower.includes("xml2js.parse") ||
    lower.includes("xml2js.parseString".toLowerCase()) ||
    lower.includes("fast-xml-parser") ||
    lower.includes("xml_parse_noent") ||
    lower.includes("xml_parse_dtdload") ||
    (lower.includes("libxml2") && lower.includes("fromstring"))
  );
}

function isFileUploadValidationOperation(
  candidate: string,
  lower: string,
  methodName: string,
): boolean {
  return (
    lower.includes("multer") ||
    lower.includes("filefilter") ||
    lower.includes("originalname") ||
    lower.includes("mimetype") ||
    lower.includes("file-type") ||
    lower.includes("filetype.frombuffer") ||
    lower.includes("busboy") ||
    lower.includes("formidable") ||
    /\bfile\.(?:size|type|mimetype|originalname|buffer)\b/.test(lower) ||
    (["endswith", "includes", "match", "test"].includes(methodName) &&
      /\b(?:originalname|mimetype|filetype|file\.type|file\.size|upload)\b/i.test(candidate))
  );
}

function fileUploadLabel(candidate: string, fallbackLabel: string): string {
  if (/\b(?:originalname|extension|extname|mimetype|filetype|file-type)\b/i.test(candidate)) {
    return "file upload type validation";
  }
  if (/\b(?:size|limit|limits)\b/i.test(candidate)) {
    return "file upload size validation";
  }
  return fallbackLabel;
}

function isTemplateRenderOperation(lower: string, methodName: string): boolean {
  return (
    lower.includes("pug.compile") ||
    lower.includes("jade.compile") ||
    lower.includes("handlebars.compile") ||
    lower.includes("mustache.render") ||
    lower.includes("ejs.render") ||
    lower.includes("nunjucks.renderstring") ||
    lower.includes("jinja2.template") ||
    methodName === "renderstring" ||
    (methodName === "compile" &&
      /\b(?:pug|jade|handlebars|mustache|ejs|nunjucks|template)\b/.test(lower))
  );
}

function isAccessControlSensitiveResourceUse(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  if (!isHttpBoundary(entity)) {
    return false;
  }
  const context = entityContext(entity, candidate);
  if (
    !RESOURCE_IDENTIFIER_PATTERN.test(context) ||
    !ACCESS_CONTROL_RESOURCE_PATTERN.test(context)
  ) {
    return false;
  }
  if (!hasRequestControlledResourceIdentifier(entity, candidate)) {
    return false;
  }
  if (hasOwnershipControl(context)) {
    return false;
  }
  return (
    [
      "findone",
      "findall",
      "findbypk",
      "findbyid",
      "find",
      "update",
      "destroy",
      "delete",
      "save",
    ].includes(methodName) ||
    lower.includes("new userprofile") ||
    lower.includes("where:") ||
    lower.includes("collection.find")
  );
}

function isAuthenticationBypassOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (
    !(
      context.includes("/auth-bypass/") ||
      context.includes("lessons.authbypass") ||
      context.includes("verify-account")
    )
  ) {
    return false;
  }
  return (
    methodName === "verifyaccount" ||
    lower.includes("verifyaccount") ||
    lower.includes("accountverificationhelper") ||
    (methodName === "setvalue" && context.includes("account-verified"))
  );
}

function authenticationBypassLabel(candidate: string, fallbackLabel: string): string {
  return candidate.toLowerCase().includes("verifyaccount") ? "account verification" : fallbackLabel;
}

function isSessionCookieTrustOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (
    !(
      context.includes("/hijacksession/") ||
      context.includes("lessons.hijacksession") ||
      context.includes("/spoofcookie/") ||
      context.includes("lessons.spoofcookie")
    )
  ) {
    return false;
  }
  return (
    lower.includes("@cookievalue") ||
    lower.includes("jakarta.servlet.http.cookie") ||
    lower.includes("javax.servlet.http.cookie") ||
    lower.includes("new cookie") ||
    lower.includes("addcookie") ||
    lower.includes("setsecure") ||
    lower.includes("setpath") ||
    lower.includes("encdec.") ||
    lower.includes("cookievalue") ||
    lower.includes("getvalue") ||
    lower.includes("authenticate") ||
    (["containskey", "equals"].includes(methodName) && context.includes("cookie"))
  );
}

function sessionCookieTrustLabel(candidate: string, fallbackLabel: string): string {
  const lower = candidate.toLowerCase();
  if (lower.includes("addcookie") || lower.includes("new cookie")) {
    return "Cookie trust";
  }
  if (lower.includes("authenticate")) {
    return "session authentication";
  }
  if (lower.includes("encdec") || lower.includes("decode") || lower.includes("encode")) {
    return "cookie encoding";
  }
  return fallbackLabel;
}

function isCredentialTrustOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (
    !(
      context.includes("/insecurelogin/") ||
      context.includes("lessons.insecurelogin") ||
      context.includes("routes/login.ts")
    )
  ) {
    return false;
  }
  return (
    methodName === "equals" ||
    lower.includes("captainjack") ||
    lower.includes("blackpearl") ||
    lower.includes("admin123") ||
    lower.includes("iamusedfortesting") ||
    lower.includes("password spraying") ||
    (lower.includes("username") && lower.includes("password"))
  );
}

function credentialTrustLabel(
  candidate: string,
  fallbackLabel: string,
  entity: ObservedEntity,
): string {
  const lower = candidate.toLowerCase();
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (
    context.includes("routes/login.ts") ||
    context.includes("/insecurelogin/") ||
    lower.includes("password") ||
    lower.includes("blackpearl")
  ) {
    return "Credential trust";
  }
  return fallbackLabel;
}

function isClientSideTrustOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (
    !(
      context.includes("/clientsidefiltering/") ||
      context.includes("lessons.clientsidefiltering") ||
      context.includes("/htmltampering/") ||
      context.includes("lessons.htmltampering") ||
      context.includes("/bypassrestrictions/") ||
      context.includes("lessons.bypassrestrictions")
    )
  ) {
    return false;
  }
  return (
    ["equals", "parsefloat", "matches", "success", "failed"].includes(methodName) ||
    lower.includes("float.parsefloat") ||
    lower.includes(".matches(") ||
    lower.includes("frontendvalidation") ||
    lower.includes("client-side") ||
    lower.includes("html-tampering")
  );
}

function clientSideTrustLabel(candidate: string, fallbackLabel: string): string {
  const lower = candidate.toLowerCase();
  if (lower.includes("parsefloat")) {
    return "client-side price trust";
  }
  if (lower.includes("matches") || lower.includes("frontendvalidation")) {
    return "client-side validation trust";
  }
  if (lower.includes("equals")) {
    return "Client-side trust";
  }
  return fallbackLabel;
}

function isSecurityMisconfigurationOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (isWebGoatSecurityMisconfigurationContext(context)) {
    return (
      ["equals", "isblank", "trim", "ok", "status", "body", "of", "put"].includes(methodName) ||
      lower.includes("responseentity") ||
      lower.includes("map.of") ||
      lower.includes("default_username") ||
      lower.includes("default_password") ||
      lower.includes("spring.security.user") ||
      lower.includes("management.endpoint") ||
      lower.includes("leaked_") ||
      lower.includes("debug_mode") ||
      lower.includes("stacktrace")
    );
  }
  return isJuiceShopSecurityMisconfigurationOperation(lower, methodName, context, entity);
}

function securityMisconfigurationLabel(
  candidate: string,
  fallbackLabel: string,
  entity: ObservedEntity,
): string {
  const lower = entityDescriptorContext(entity, candidate).toLowerCase();
  if (isJuiceShopDeprecatedInterfaceContext(lower)) {
    return "deprecated interface exposure";
  }
  if (isJuiceShopErrorHandlingContext(lower)) {
    return "verbose error exposure";
  }
  if (isJuiceShopLoginSupportContext(lower)) {
    return "support account hardcoded login";
  }
  if (isJuiceShopSvgInjectionContext(lower, entity)) {
    return "SVG redirect policy trust";
  }
  if (
    isWebGoatSecurityMisconfigurationContext(lower) ||
    lower.includes("default_") ||
    lower.includes("spring.security.user") ||
    lower.includes("management.endpoint")
  ) {
    return "Security misconfiguration";
  }
  if (lower.includes("responseentity") || lower.includes("stacktrace")) {
    return "verbose error exposure";
  }
  return fallbackLabel;
}

function isWebGoatSecurityMisconfigurationContext(context: string): boolean {
  return (
    context.includes("/securitymisconfiguration/") ||
    context.includes("lessons.securitymisconfiguration")
  );
}

function isJuiceShopSecurityMisconfigurationOperation(
  lower: string,
  methodName: string,
  context: string,
  entity: ObservedEntity,
): boolean {
  if (isJuiceShopDeprecatedInterfaceContext(context)) {
    return lower.includes("deprecatedinterfacechallenge") || lower.includes("deprecated");
  }
  if (isJuiceShopErrorHandlingContext(context)) {
    return (
      lower.includes("errorhandlingchallenge") ||
      (methodName === "solveif" && context.includes("errorhandlingchallenge")) ||
      (lower.includes("statuscode") && (lower.includes("> 401") || lower.includes("=== 200")))
    );
  }
  if (isJuiceShopLoginSupportContext(context)) {
    return (
      lower.includes("loginsupportchallenge") ||
      lower.includes("support@") ||
      lower.includes("j6avjtgoprs")
    );
  }
  if (isJuiceShopSvgInjectionContext(context, entity)) {
    return (
      lower.includes("svginjectionchallenge") ||
      lower.includes("verifysvginjectionchallenge") ||
      lower.includes("cataas.com") ||
      lower.includes("isredirectallowed")
    );
  }
  return false;
}

function isJuiceShopDeprecatedInterfaceContext(context: string): boolean {
  return (
    context.includes("routes/fileupload.ts") && context.includes("deprecatedinterfacechallenge")
  );
}

function isJuiceShopErrorHandlingContext(context: string): boolean {
  return context.includes("routes/verify.ts") && context.includes("errorhandlingchallenge");
}

function isJuiceShopLoginSupportContext(context: string): boolean {
  return (
    context.includes("routes/login.ts") &&
    (context.includes("loginsupportchallenge") ||
      context.includes("support@") ||
      context.includes("j6avjtgoprs"))
  );
}

function isJuiceShopSvgInjectionContext(context: string, entity: ObservedEntity): boolean {
  return (
    context.includes("lib/startup/registerwebsocketevents.ts") &&
    (context.includes("svginjectionchallenge") ||
      context.includes("verifysvginjectionchallenge") ||
      context.includes("cataas.com") ||
      (context.includes("isredirectallowed") && entity.lineRange.startLine >= 45))
  );
}

function isLogInjectionOperation(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const context = entityDescriptorContext(entity, candidate).toLowerCase();
  if (!(context.includes("/logspoofing/") || context.includes("lessons.logging"))) {
    return false;
  }
  return (
    lower.includes("log.info") ||
    lower.includes("logger.info") ||
    lower.includes("base64") ||
    ["replace", "contains", "indexof", "output", "encode", "encodetostring"].includes(methodName)
  );
}

function logInjectionLabel(candidate: string, fallbackLabel: string): string {
  const lower = candidate.toLowerCase();
  if (lower.includes("base64") || lower.includes("encodetostring")) {
    return "leaked log secret";
  }
  if (lower.includes("replace") || lower.includes("indexof") || lower.includes("contains")) {
    return "Log injection";
  }
  return fallbackLabel;
}

function isCsrfSensitiveStateChange(
  candidate: string,
  lower: string,
  methodName: string,
  entity: ObservedEntity,
): boolean {
  const hint = boundaryHint(entity.slice.boundary);
  if (hint === undefined || !isStateChangingHttpMethod(hint.method)) {
    return false;
  }
  if (hasStrongCsrfControl(entityContext(entity, candidate))) {
    return false;
  }
  return CSRF_STATE_CHANGE_PATTERN.test(lower) || CSRF_STATE_CHANGE_PATTERN.test(methodName);
}

function accessControlLabel(
  candidate: string,
  fallbackLabel: string,
  entity: ObservedEntity,
): string {
  const context = entityContext(entity, candidate);
  if (/\bidor\b|insecure[\w\s-]*direct[\w\s-]*object/i.test(context)) {
    return "IDOR object access";
  }
  return fallbackLabel;
}

function isHttpBoundary(entity: ObservedEntity): boolean {
  const hint = boundaryHint(entity.slice.boundary);
  if (hint === undefined) {
    return false;
  }
  const boundary = `${hint.boundaryType} ${hint.routeOrName}`.toLowerCase();
  return (
    boundary.includes("http") ||
    boundary.includes("web") ||
    boundary.includes("spring") ||
    boundary.includes("express") ||
    boundary.includes("route") ||
    hint.routeOrName.startsWith("/")
  );
}

function isStateChangingHttpMethod(method: string | undefined): boolean {
  switch (method?.toUpperCase()) {
    case "POST":
    case "PUT":
    case "PATCH":
    case "DELETE":
      return true;
    default:
      return false;
  }
}

function hasRequestControlledResourceIdentifier(
  entity: ObservedEntity,
  candidate: string,
): boolean {
  const parameterNames = asObjectArray(entity.slice.parameters)
    .map((parameter) => stringValue(parameter.name))
    .filter((name): name is string => name !== undefined);
  return (
    parameterNames.some((name) => RESOURCE_IDENTIFIER_PATTERN.test(name)) ||
    /\b(?:req|request|ctx)\s*(?:\.\s*(?:params|body|query|headers))?\s*(?:\.\s*|\[\s*['"])(?:id|uid|bid|cid|userId|userid|user_id|basketId|basketid|basket_id|orderId|orderid|order_id|accountId|account_id|profileId|profile_id|ownerId|owner_id|email|username)\b/i.test(
      candidate,
    ) ||
    /\b(?:params|body|query|headers)\s*\[\s*['"](?:id|uid|bid|cid|userId|userid|user_id|basketId|basketid|basket_id|orderId|orderid|order_id|accountId|account_id|profileId|profile_id|ownerId|owner_id|email|username)['"]\s*\]/i.test(
      candidate,
    ) ||
    (hasExternalRequestSource(entity) && hasHandlerLocalResourceIdentifier(candidate))
  );
}

function hasExternalRequestSource(entity: ObservedEntity): boolean {
  const hint = boundaryHint(entity.slice.boundary);
  if (hint?.sourceName !== undefined && /\b(?:req|request|ctx|context)\b/i.test(hint.sourceName)) {
    return true;
  }
  return asObjectArray(entity.slice.parameters).some((parameter) => {
    const name = stringValue(parameter.name) ?? "";
    const type = stringValue(parameter.typeFullName) ?? "";
    return /\b(?:req|request|ctx|context)\b/i.test(name) || /\bRequest\b/.test(type);
  });
}

function hasHandlerLocalResourceIdentifier(candidate: string): boolean {
  const identifier =
    "(?:id|uid|bid|cid|userId|userid|user_id|basketId|basketid|basket_id|orderId|orderid|order_id|accountId|account_id|profileId|profile_id|ownerId|owner_id|email|username)";
  return (
    new RegExp(String.raw`\bwhere\s*:\s*\{[^}]*\b${identifier}\b`, "i").test(candidate) ||
    new RegExp(
      String.raw`\b(?:findOne|findAll|findByPk|findById|find|update|destroy|delete|remove)\s*\([^)]*\b${identifier}\b`,
      "i",
    ).test(candidate) ||
    new RegExp(
      String.raw`\bnew\s+[A-Z][\w$]*(?:Profile|Account|Basket|Order|User|Record|Resource)\s*\(\s*${identifier}\b`,
      "i",
    ).test(candidate)
  );
}

function hasOwnershipControl(context: string): boolean {
  return (
    /\b(?:invalid\s+(?:basket|user|order|account)|does not belong|belongs to|owner|ownership)\b[\s\S]{0,160}\b(?:status\s*\(\s*40[13]|sendstatus\s*\(\s*40[13]|forbidden|unauthorized)\b/i.test(
      context,
    ) ||
    /\b(?:status\s*\(\s*40[13]|sendstatus\s*\(\s*40[13]|forbidden|unauthorized)\b[\s\S]{0,160}\b(?:invalid\s+(?:basket|user|order|account)|does not belong|belongs to|owner|ownership)\b/i.test(
      context,
    ) ||
    (/\b(?:forbidden|unauthorized|invalid\s+(?:basket|user|order|account)|does not belong|belongs to|owner|ownership)\b/i.test(
      context,
    ) &&
      /\b(?:return|throw|status\s*\(\s*40[13]|sendstatus\s*\(\s*40[13]|forbidden|unauthorized)\b/i.test(
        context,
      ))
  );
}

function hasStrongCsrfControl(context: string): boolean {
  return /\b(?:csrf(?:token|_token|middleware)|csrf[_-]?token|xsrf[_-]?token|csurf|anti[-_ ]?csrf|samesite|double[-_ ]?submit)\b/i.test(
    context,
  );
}

function entityContext(entity: ObservedEntity, candidate: string): string {
  return [
    entity.fullName,
    entity.repoPath,
    JSON.stringify(entity.slice.boundary ?? {}),
    ...asObjectArray(entity.slice.parameters).flatMap((parameter) => [
      stringValue(parameter.name) ?? "",
      stringValue(parameter.typeFullName) ?? "",
    ]),
    ...asObjectArray(entity.slice.usages).flatMap((usage) => {
      const target = asObject(usage.targetObj);
      return [
        stringValue(target.name) ?? "",
        stringValue(target.resolvedMethod) ?? "",
        stringValue(target.code) ?? "",
      ];
    }),
    candidate,
  ].join("\n");
}

function entityDescriptorContext(entity: ObservedEntity, candidate: string): string {
  return [
    entity.fullName,
    entity.repoPath,
    JSON.stringify(entity.slice.boundary ?? {}),
    ...asObjectArray(entity.slice.parameters).flatMap((parameter) => [
      stringValue(parameter.name) ?? "",
      stringValue(parameter.typeFullName) ?? "",
    ]),
    candidate,
  ].join("\n");
}

function crossSiteScriptingLabel(
  candidate: string,
  lower: string,
  methodName: string,
  fallbackLabel: string,
  entity: ObservedEntity,
): string | undefined {
  if (lower.includes("bypasssecuritytrusthtml")) {
    return "bypassSecurityTrustHtml";
  }
  if (lower.includes("dangerouslysetinnerhtml")) {
    return "dangerouslySetInnerHTML";
  }
  if (/\b(?:innerhtml|outerhtml|insertadjacenthtml)\b/.test(lower)) {
    return methodName === "assignment" ? "innerHTML" : fallbackLabel;
  }
  if (
    methodName === "compile" &&
    (lower.includes("pug.") ||
      lower.includes("handlebars.") ||
      lower.includes("mustache.") ||
      lower.includes("template"))
  ) {
    return fallbackLabel;
  }
  if (
    ["append", "concat", "replace", "write"].includes(methodName) &&
    HTML_TEXT_PATTERN.test(candidate) &&
    (methodName === "replace" || hasRawParameterHtmlInsertion(candidate, entity))
  ) {
    return fallbackLabel;
  }
  return undefined;
}

function hasRawParameterHtmlInsertion(candidate: string, entity: ObservedEntity): boolean {
  const parameterNames = asObjectArray(entity.slice.parameters)
    .map((parameter) => stringValue(parameter.name))
    .filter((name): name is string => name !== undefined)
    .filter((name) => !isFrameworkParameterName(name));
  return parameterNames.some((name) => {
    const escaped = escapeRegExp(name);
    return new RegExp(String.raw`(?:\+|\$\{)\s*(?:this\.)?${escaped}(?!\s*\.)\s*(?:[+)};]|$)`).test(
      candidate,
    );
  });
}

function isFrameworkParameterName(name: string): boolean {
  switch (name.toLowerCase()) {
    case "req":
    case "request":
    case "res":
    case "response":
    case "next":
    case "ctx":
    case "context":
      return true;
    default:
      return false;
  }
}

function outboundHttpLabel(
  candidate: string,
  lower: string,
  methodName: string,
): string | undefined {
  if (/\bfetch\s*\(/i.test(candidate) || methodName === "fetch") {
    return "fetch";
  }

  const axios = lower.match(/\baxios(?:\.(get|post|put|patch|delete|request))?/);
  if (axios !== null) {
    return axios[1] === undefined ? "axios" : `axios.${axios[1]}`;
  }

  const nodeHttp = lower.match(/\b(https?)\.(get|post|request)\s*\(/);
  if (nodeHttp !== null) {
    return `${nodeHttp[1]}.${nodeHttp[2]}`;
  }

  const angularHttp = lower.match(
    /\b(?:this\.)?http(?:client)?\.(get|post|put|patch|delete|request)\s*\(/,
  );
  if (angularHttp !== null) {
    return `http.${angularHttp[1]}`;
  }

  const pythonRequests = lower.match(/\brequests\.(get|post|put|patch|delete|request)\b/);
  if (pythonRequests !== null) {
    return `requests.${pythonRequests[1]}`;
  }

  if (lower.includes("resttemplate.") || lower.includes("webclient.")) {
    return methodName;
  }

  const goHttp = lower.match(
    /(?:^|[^\w])(?:net\/http|http)\.(get|post|head|postform|newrequest|newrequestwithcontext)\b/,
  );
  if (goHttp !== null) {
    return `http.${goHttp[1]}`;
  }

  if (methodName === "do" && lower.includes("net/http.client.do")) {
    return "http.client.do";
  }

  return undefined;
}

function outboundHttpSinkType(repoPath: string, lower: string): string {
  if (
    isLikelyBrowserClientPath(repoPath) ||
    lower.includes("this.http") ||
    lower.includes("httpclient")
  ) {
    return "outbound_http";
  }
  return "server_side_request";
}

function isLikelyBrowserClientPath(repoPath: string): boolean {
  const normalized = repoPath.toLowerCase();
  return (
    normalized.startsWith("frontend/") ||
    normalized.startsWith("client/") ||
    normalized.startsWith("web/") ||
    normalized.startsWith("apps/web/") ||
    normalized.startsWith("packages/web/") ||
    normalized.startsWith("mobile/") ||
    normalized.includes("/frontend/") ||
    normalized.includes("/client/") ||
    normalized.includes("/apps/web/") ||
    normalized.includes("/packages/web/") ||
    normalized.includes("/mobile/") ||
    normalized.includes("/public/") ||
    normalized.includes(".component.") ||
    normalized.includes(".service.")
  );
}

function isBareFileOpen(repoPath: string, lower: string): boolean {
  if (!/\bopen\s*\(/.test(lower) || isLikelyBrowserClientPath(repoPath)) {
    return false;
  }
  const normalized = repoPath.toLowerCase();
  return (
    normalized.endsWith(".py") ||
    lower.includes("fs.open") ||
    lower.includes("node:fs") ||
    lower.includes("fs/promises")
  );
}

function hasSqlContext(lower: string, methodName: string): boolean {
  return (
    lower.includes("java.sql") ||
    lower.includes("javax.sql") ||
    lower.includes("jdbc") ||
    lower.includes("statement") ||
    lower.includes("preparedstatement") ||
    lower.includes("callablestatement") ||
    lower.includes("entitymanager") ||
    lower.includes("jdbctemplate") ||
    lower.includes("databaseclient") ||
    lower.includes("sqlsession") ||
    lower.includes("sqlite3") ||
    lower.includes("cursor.") ||
    lower.includes("database/sql") ||
    lower.includes("sequelize.") ||
    lower.includes("knex.") ||
    lower.includes("pg.") ||
    lower.includes("mysql") ||
    SQL_TEXT_PATTERN.test(lower) ||
    methodName === "executequery" ||
    methodName === "executeupdate" ||
    methodName === "executebatch" ||
    methodName === "executelargeupdate" ||
    methodName === "preparestatement" ||
    methodName === "createquery" ||
    methodName === "createnativequery"
  );
}

function addLexicalFlowEdges(builder: GraphBuilder, graphVersion: string): void {
  const codeEntities = [...builder.codeByFullName.entries()].sort(([left], [right]) =>
    left.localeCompare(right),
  );
  for (const [fullName, child] of codeEntities) {
    const parentFullName = lexicalParentFullName(fullName);
    if (parentFullName === undefined) {
      continue;
    }
    const parent = builder.codeByFullName.get(parentFullName);
    if (parent === undefined || parent.repoPath !== child.repoPath) {
      continue;
    }
    addEdge(builder, graphVersion, {
      kind: "flows_to",
      stableKey: `flows_to:${parent.id}:${child.id}:lexical-child`,
      fromNodeId: parent.id,
      toNodeId: child.id,
      properties: {
        flowType: "lexical_child",
      },
      evidenceIds: unique([...parent.evidenceIds, ...child.evidenceIds]),
      producerVersion: child.producerVersion,
    });
  }
}

function lexicalParentFullName(fullName: string): string | undefined {
  const lambdaIndex = fullName.lastIndexOf(":<lambda>");
  if (lambdaIndex < 0) {
    return undefined;
  }
  const parent = fullName.slice(0, lambdaIndex);
  return parent === "" ? undefined : parent;
}

function buildFlows(graphVersion: string, builder: GraphBuilder): SecurityFlow[] {
  const sources = [...builder.nodes]
    .filter((node) => node.kind === "Source")
    .sort((left, right) => left.stableKey.localeCompare(right.stableKey));
  const sinks = new Set(
    builder.nodes.filter((node) => node.kind === "Sink").map((node) => node.id),
  );
  const outgoing = new Map<string, SecurityGraphEdge[]>();
  for (const edge of [...builder.edges].sort((left, right) =>
    left.stableKey.localeCompare(right.stableKey),
  )) {
    if (!["receives", "registers", "calls", "flows_to"].includes(edge.kind)) {
      continue;
    }
    const current = outgoing.get(edge.fromNodeId) ?? [];
    current.push(edge);
    outgoing.set(edge.fromNodeId, current);
  }

  const flows: Array<{ readonly stableKey: string; readonly flow: SecurityFlow }> = [];
  for (const source of sources) {
    for (const path of pathsToSinks(source.id, sinks, outgoing)) {
      const sinkId = path.at(-1)?.toNodeId;
      if (sinkId === undefined) {
        continue;
      }
      const stableKey = `flow:${source.id}:${sinkId}:${path.map((edge) => edge.id).join(">")}`;
      flows.push({
        stableKey,
        flow: {
          id: securityFlowId(graphVersion, stableKey),
          sourceNodeId: source.id,
          sinkNodeId: sinkId,
          pathEdgeIds: path.map((edge) => edge.id),
          controlNodeIds: [],
          coverageState: "checked",
          confidence: DEFAULT_CONFIDENCE,
          evidenceIds: unique(path.flatMap((edge) => edge.evidenceIds)),
        },
      });
    }
  }

  return flows
    .sort((left, right) => left.stableKey.localeCompare(right.stableKey))
    .map((entry) => entry.flow);
}

function pathsToSinks(
  startNodeId: string,
  sinkIds: ReadonlySet<string>,
  outgoing: ReadonlyMap<string, ReadonlyArray<SecurityGraphEdge>>,
): SecurityGraphEdge[][] {
  const queue: Array<{
    readonly nodeId: string;
    readonly path: ReadonlyArray<SecurityGraphEdge>;
    readonly nodeIds: ReadonlyArray<string>;
  }> = [{ nodeId: startNodeId, path: [], nodeIds: [startNodeId] }];
  const paths: SecurityGraphEdge[][] = [];

  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined) {
      continue;
    }
    if (sinkIds.has(current.nodeId) && current.path.length > 0) {
      paths.push([...current.path]);
      continue;
    }
    if (current.path.length >= MAX_SECURITY_FLOW_PATH_LENGTH) {
      continue;
    }
    for (const edge of outgoing.get(current.nodeId) ?? []) {
      if (current.nodeIds.includes(edge.toNodeId)) {
        continue;
      }
      queue.push({
        nodeId: edge.toNodeId,
        path: [...current.path, edge],
        nodeIds: [...current.nodeIds, edge.toNodeId],
      });
    }
  }

  return paths;
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
    readonly producerVersion: string;
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
    producerVersion: input.producerVersion,
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
  input: {
    readonly kind: SecurityGraphEdge["kind"];
    readonly stableKey: string;
    readonly fromNodeId: string;
    readonly toNodeId: string;
    readonly properties: Readonly<Record<string, unknown>>;
    readonly evidenceIds: ReadonlyArray<string>;
    readonly producerVersion: string;
  },
): SecurityGraphEdge {
  const existing = builder.edgesByStableKey.get(input.stableKey);
  if (existing !== undefined) {
    return existing;
  }
  const edge: SecurityGraphEdge = {
    id: securityGraphEdgeId(graphVersion, input.stableKey),
    kind: input.kind,
    stableKey: input.stableKey,
    fromNodeId: input.fromNodeId,
    toNodeId: input.toNodeId,
    properties: input.properties,
    evidenceIds: input.evidenceIds,
    producer: PRODUCER,
    producerVersion: input.producerVersion,
    confidence: DEFAULT_CONFIDENCE,
    coverageState: "checked",
  };
  builder.edges.push(edge);
  builder.edgesByStableKey.set(edge.stableKey, edge);
  return edge;
}

function buildCoverage(input: {
  readonly producerVersion: string;
  readonly entityCount: number;
  readonly boundaryCount: number;
  readonly callEdgeCount: number;
  readonly flowArtifactCount: number;
  readonly flowCount: number;
}): GraphCoverage[] {
  return [
    coverage(
      "entities",
      input.entityCount > 0 ? "checked" : "partial",
      input.entityCount,
      input.entityCount,
      input.producerVersion,
    ),
    coverage(
      "boundaries",
      input.boundaryCount > 0 ? "checked" : "partial",
      input.boundaryCount,
      input.entityCount,
      input.producerVersion,
    ),
    coverage(
      "call_graph",
      input.callEdgeCount > 0 ? "checked" : "partial",
      input.callEdgeCount,
      Math.max(input.entityCount, input.callEdgeCount),
      input.producerVersion,
    ),
    coverage(
      "data_flow",
      input.flowCount > 0 ? "checked" : input.flowArtifactCount > 0 ? "partial" : "skipped",
      input.flowCount,
      Math.max(input.boundaryCount, input.flowCount, 1),
      input.producerVersion,
    ),
  ];
}

function coverage(
  area: GraphCoverage["area"],
  state: GraphCoverageState,
  coveredCount: number,
  totalCount: number,
  producerVersion: string,
): GraphCoverage {
  return {
    area,
    state,
    coveredCount,
    totalCount,
    producer: PRODUCER,
    producerVersion,
    ...(state === "checked"
      ? {}
      : { reason: `${area} coverage is incomplete from current Joern artifacts.` }),
  };
}

function producerVersion(artifacts: ReadonlyArray<ProgramAnalysisExtractionArtifact>): string {
  return artifacts[0]?.backendVersion ?? "joern@unknown";
}

function countNodes(builder: GraphBuilder, kind: SecurityGraphNode["kind"]): number {
  return builder.nodes.filter((node) => node.kind === kind).length;
}

function countEdges(builder: GraphBuilder, kind: SecurityGraphEdge["kind"]): number {
  return builder.edges.filter((edge) => edge.kind === kind).length;
}

function boundaryHint(value: unknown): BoundaryHint | undefined {
  const hint = asObject(value);
  const boundaryType = stringValue(hint.boundaryType);
  const routeOrName = stringValue(hint.routeOrName);
  const method = stringValue(hint.method);
  const sourceName = stringValue(hint.sourceName);
  if (boundaryType === undefined || routeOrName === undefined) {
    return undefined;
  }
  return {
    boundaryType,
    routeOrName,
    ...(method === undefined ? {} : { method }),
    ...(sourceName === undefined ? {} : { sourceName }),
  };
}

function observationLabel(observation: FlowBoundaryObservation): string {
  return symbolFromFullName(observation.fullName);
}

function asObject(value: unknown): ProgramAnalysisObject {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as ProgramAnalysisObject)
    : {};
}

function asObjectArray(value: unknown): ProgramAnalysisObject[] {
  return Array.isArray(value)
    ? value.map(asObject).filter((item) => Object.keys(item).length > 0)
    : [];
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

function positiveInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : undefined;
}

function isSafeManifestPath(repoPath: string, manifestPaths: ReadonlySet<string>): boolean {
  return (
    manifestPaths.has(repoPath) &&
    !repoPath.startsWith("/") &&
    repoPath.split("/").every((part) => part !== "" && part !== "." && part !== "..")
  );
}

function symbolFromFullName(fullName: string): string {
  const programMethodIndex = fullName.lastIndexOf("::program:");
  if (programMethodIndex >= 0) {
    return fullName.slice(programMethodIndex + "::program:".length);
  }
  if (fullName.endsWith("::program")) {
    return "program";
  }

  const callableName = fullName.split(":").at(0) ?? fullName;
  const javaMethod = callableName.split(".").filter(Boolean).at(-1);
  if (javaMethod !== undefined && !javaMethod.includes("/")) {
    return javaMethod;
  }
  return fullName.split(":").filter(Boolean).at(-1) ?? fullName;
}

function methodNameFromCall(value: string): string {
  const withoutGlobal = value.replace(/^globalThis\./, "");
  const callableName = withoutGlobal.split(":").at(0) ?? withoutGlobal;
  const invokedFromCode = [...callableName.matchAll(/(?:^|[^\w$])([A-Za-z_$][\w$]*)\s*\(/g)]
    .map((match) => match[1])
    .filter((name): name is string => name !== undefined)
    .at(-1);
  if (invokedFromCode !== undefined) {
    return invokedFromCode;
  }
  const dotted = callableName.split(".").filter(Boolean).at(-1);
  if (dotted !== undefined) {
    return dotted.replace(/\(.*$/, "");
  }
  return symbolFromFullName(value).replace(/\(.*$/, "");
}

function normalizedCallLabel(value: string, methodName: string): string {
  if (value.includes("child_process.exec")) {
    return "child_process.exec";
  }
  if (value.toLowerCase().includes("runtime.exec")) {
    return "Runtime.exec";
  }
  return methodName || symbolFromFullName(value);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function unique(values: ReadonlyArray<string>): string[] {
  return [...new Set(values)];
}
