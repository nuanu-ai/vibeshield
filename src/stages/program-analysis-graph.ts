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

  if (isNoSqlOperation(lower, methodName)) {
    return { label, sinkType: "no_sql_execution" };
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
