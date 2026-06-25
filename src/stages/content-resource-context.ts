import { createHash } from "node:crypto";
import path from "node:path";
import type { Manifest, ManifestFile } from "../domain/manifest.js";
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

export type ContentResourceExposureType =
  | "hidden_server_route"
  | "obfuscated_frontend_route"
  | "sensitive_frontend_route"
  | "private_asset_reference"
  | "steganography_asset"
  | "steganography_content_clue";

export interface ContentResourceObservation {
  readonly repoPath: string;
  readonly exposureType: ContentResourceExposureType;
  readonly label: string;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly lineRange?: LineRange;
  readonly route?: string;
  readonly assetPath?: string;
  readonly matcher?: string;
  readonly clue?: string;
}

export interface ComposeContentResourceContextInput {
  readonly graph: SecurityGraph;
  readonly manifest: Manifest;
  readonly observations?: ReadonlyArray<ContentResourceObservation>;
  readonly scannedFileCount: number;
}

interface GraphBuilder {
  readonly nodes: SecurityGraphNode[];
  readonly edges: SecurityGraphEdge[];
  readonly nodesByStableKey: Map<string, SecurityGraphNode>;
  readonly edgesByStableKey: Map<string, SecurityGraphEdge>;
}

const PRODUCER = "content-resource-context";
const DEFAULT_CONFIDENCE = 0.86;

export function composeContentResourceContext(
  input: ComposeContentResourceContextInput,
): SecurityGraph {
  const builder = graphBuilder(input.graph);

  for (const observation of input.observations ?? []) {
    assertEvidence(observation.evidenceIds, `content resource ${observation.label}`);
    addContentResource(builder, input.graph.graphVersion, observation);
  }

  const observations = input.observations ?? [];
  return validateSecurityGraph(
    {
      ...input.graph,
      nodes: builder.nodes,
      edges: builder.edges,
      coverage: withContentCoverage(input.graph, input.scannedFileCount),
    },
    {
      manifestPaths: input.manifest.files.map((file) => file.path),
      evidenceIds: [
        ...collectGraphEvidenceIds(input.graph),
        ...collectObservationEvidenceIds(observations),
      ],
    },
  );
}

export function contentResourceObservationsFromText(
  repoPath: string,
  text: string,
): ContentResourceObservation[] {
  if (isIgnoredContentObservationPath(repoPath)) {
    return [];
  }
  return [
    ...hiddenServerRouteObservations(repoPath, text),
    ...obfuscatedFrontendRouteObservations(repoPath, text),
    ...sensitiveFrontendRouteObservations(repoPath, text),
    ...privateAssetReferenceObservations(repoPath, text),
    ...steganographyContentClueObservations(repoPath, text),
  ];
}

export function contentResourceObservationsFromPath(
  file: ManifestFile,
): ContentResourceObservation[] {
  if (
    isIgnoredContentObservationPath(file.path) ||
    !isImagePath(file.path) ||
    !looksLikeSteganographyAsset(file.path)
  ) {
    return [];
  }
  return [
    {
      repoPath: file.path,
      exposureType: "steganography_asset",
      label: `Steganography-looking asset ${path.posix.basename(file.path)}`,
      evidenceIds: [contentResourceEvidenceId("steganography-asset", file.path, file.sha256)],
      lineRange: { startLine: 1, endLine: 1 },
      assetPath: file.path,
    },
  ];
}

export function isContentResourceTextPath(repoPath: string): boolean {
  return /\.(?:[cm]?[jt]sx?|html?|svelte|vue|json|ya?ml|md|txt|scss|css|hbs)$/i.test(repoPath);
}

function graphBuilder(graph: SecurityGraph): GraphBuilder {
  return {
    nodes: [...graph.nodes],
    edges: [...graph.edges],
    nodesByStableKey: new Map(graph.nodes.map((node) => [node.stableKey, node])),
    edgesByStableKey: new Map(graph.edges.map((edge) => [edge.stableKey, edge])),
  };
}

function addContentResource(
  builder: GraphBuilder,
  graphVersion: string,
  observation: ContentResourceObservation,
): void {
  const symbol =
    observation.route ?? observation.assetPath ?? observation.matcher ?? observation.clue;
  const resource = addNode(builder, graphVersion, {
    kind: "Resource",
    stableKey: [
      "ContentResource",
      observation.exposureType,
      observation.repoPath,
      observation.lineRange?.startLine ?? 0,
      observation.route ??
        observation.assetPath ??
        observation.matcher ??
        observation.clue ??
        observation.label,
    ].join(":"),
    label: observation.label,
    repoPath: observation.repoPath,
    ...(observation.lineRange === undefined ? {} : { lineRange: observation.lineRange }),
    ...(symbol === undefined ? {} : { symbol }),
    properties: observationProperties(observation),
    evidenceIds: observation.evidenceIds,
  });
  const sink = addNode(builder, graphVersion, {
    kind: "Sink",
    stableKey: [
      "ContentSink",
      observation.exposureType,
      observation.repoPath,
      observation.lineRange?.startLine ?? 0,
      observation.route ??
        observation.assetPath ??
        observation.matcher ??
        observation.clue ??
        observation.label,
    ].join(":"),
    label: `Hidden content exposure: ${observation.label}`,
    repoPath: observation.repoPath,
    ...(observation.lineRange === undefined ? {} : { lineRange: observation.lineRange }),
    symbol: observation.exposureType,
    properties: {
      sinkType: "hidden_content_exposure",
      exposureType: observation.exposureType,
    },
    evidenceIds: observation.evidenceIds,
  });
  addEdge(
    builder,
    graphVersion,
    "exposes",
    resource,
    sink,
    { exposureType: observation.exposureType },
    observation.evidenceIds,
  );
}

function observationProperties(
  observation: ContentResourceObservation,
): Readonly<Record<string, unknown>> {
  return {
    resourceType: "content_resource",
    exposureType: observation.exposureType,
    ...(observation.route === undefined ? {} : { route: observation.route }),
    ...(observation.assetPath === undefined ? {} : { assetPath: observation.assetPath }),
    ...(observation.matcher === undefined ? {} : { matcher: observation.matcher }),
    ...(observation.clue === undefined ? {} : { clue: observation.clue }),
  };
}

function hiddenServerRouteObservations(
  repoPath: string,
  text: string,
): ContentResourceObservation[] {
  const lines = splitLines(text);
  return lines.flatMap((line, index) => {
    const match = line.match(/\bapp\.(get|post|put|patch|delete|use)\(\s*(['"`])([^'"`]+)\2/i);
    const method = match?.[1]?.toUpperCase();
    const route = match?.[3];
    if (method === undefined || route === undefined || !looksLikeHiddenRoute(route)) {
      return [];
    }
    const lineNumber = index + 1;
    return [
      {
        repoPath,
        exposureType: "hidden_server_route",
        label: `${method} ${route}`,
        route,
        evidenceIds: [contentResourceEvidenceId("hidden-server-route", repoPath, line)],
        lineRange: { startLine: lineNumber, endLine: lineNumber },
      },
    ];
  });
}

function obfuscatedFrontendRouteObservations(
  repoPath: string,
  text: string,
): ContentResourceObservation[] {
  if (!/\bmatcher\s*:/.test(text)) {
    return [];
  }
  const obfuscatedMatchers = obfuscatedMatcherNames(text);
  if (obfuscatedMatchers.size === 0) {
    return [];
  }
  return splitLines(text).flatMap((line, index) => {
    const matcher = line.match(/\bmatcher\s*:\s*([A-Za-z_$][\w$]*)/)?.[1];
    if (matcher === undefined || !obfuscatedMatchers.has(matcher)) {
      return [];
    }
    const lineNumber = index + 1;
    return [
      {
        repoPath,
        exposureType: "obfuscated_frontend_route",
        label: `Obfuscated frontend route matcher ${matcher}`,
        matcher,
        evidenceIds: [contentResourceEvidenceId("obfuscated-frontend-route", repoPath, line)],
        lineRange: { startLine: lineNumber, endLine: lineNumber },
      },
    ];
  });
}

function sensitiveFrontendRouteObservations(
  repoPath: string,
  text: string,
): ContentResourceObservation[] {
  if (!isRuntimeCodePath(repoPath) || !/\bpath\s*:/.test(text)) {
    return [];
  }
  const lines = splitLines(text);
  return lines.flatMap((line, index) => {
    const route = line.match(/\bpath\s*:\s*(['"`])([^'"`]+)\1/)?.[2];
    if (route === undefined || !looksLikeSensitiveFrontendRoute(route, routeBlock(lines, index))) {
      return [];
    }
    const lineNumber = index + 1;
    return [
      {
        repoPath,
        exposureType: "sensitive_frontend_route",
        label: `Sensitive frontend route ${route}`,
        route,
        evidenceIds: [contentResourceEvidenceId("sensitive-frontend-route", repoPath, line)],
        lineRange: { startLine: lineNumber, endLine: lineNumber },
      },
    ];
  });
}

function privateAssetReferenceObservations(
  repoPath: string,
  text: string,
): ContentResourceObservation[] {
  if (!isRuntimeCodePath(repoPath)) {
    return [];
  }
  return splitLines(text).flatMap((line, index) => {
    const assetPath = line.match(/(['"`])([^'"`]*assets\/private\/[^'"`\s)]+)\1/)?.[2];
    if (assetPath === undefined) {
      return [];
    }
    const lineNumber = index + 1;
    return [
      {
        repoPath,
        exposureType: "private_asset_reference",
        label: `Private asset reference ${assetPath}`,
        assetPath,
        evidenceIds: [contentResourceEvidenceId("private-asset-reference", repoPath, line)],
        lineRange: { startLine: lineNumber, endLine: lineNumber },
      },
    ];
  });
}

function steganographyContentClueObservations(
  repoPath: string,
  text: string,
): ContentResourceObservation[] {
  return splitLines(text).flatMap((line, index) => {
    if (!/steganograph|pickle\s+rick/i.test(line)) {
      return [];
    }
    const clue =
      line.match(/%\s*([^%]*pickle\s+rick[^%]*)\s*%/i)?.[1]?.trim() ?? "hidden image clue";
    const lineNumber = index + 1;
    return [
      {
        repoPath,
        exposureType: "steganography_content_clue",
        label: `Steganography content clue ${clue}`,
        clue,
        evidenceIds: [contentResourceEvidenceId("steganography-content-clue", repoPath, line)],
        lineRange: { startLine: lineNumber, endLine: lineNumber },
      },
    ];
  });
}

function obfuscatedMatcherNames(text: string): Set<string> {
  const names = new Set<string>();
  const matches = [...text.matchAll(/\b(?:export\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g)];
  for (let index = 0; index < matches.length; index += 1) {
    const match = matches[index];
    const name = match?.[1];
    const start = match?.index;
    if (name === undefined || start === undefined) {
      continue;
    }
    const end = matches[index + 1]?.index ?? text.length;
    const body = text.slice(start, end);
    if (looksObfuscated(body)) {
      names.add(name);
    }
  }
  return names;
}

function looksObfuscated(value: string): boolean {
  const normalized = value.toLowerCase();
  return (
    normalized.includes(".tostring(36)") ||
    normalized.includes("fromcharcode") ||
    normalized.includes(".reverse()") ||
    normalized.includes("charcodeat") ||
    normalized.includes("atob(") ||
    normalized.includes("decodeuricomponent(")
  );
}

function looksLikeHiddenRoute(route: string): boolean {
  const normalized = route.toLowerCase();
  if (
    /\/(?:hidden|private|secret|easter|paywall)\b/.test(normalized) ||
    normalized.includes("/the/devs/") ||
    normalized.includes("/we/may/also/") ||
    normalized.includes("/this/page/is/hidden")
  ) {
    return true;
  }
  const segmentCount = normalized.split("/").filter(Boolean).length;
  return segmentCount >= 8 && normalized.length >= 72;
}

function looksLikeSensitiveFrontendRoute(route: string, block: string): boolean {
  const normalizedRoute = route.toLowerCase();
  const normalizedBlock = block.toLowerCase();
  if (
    /\b(?:admin|administration|backoffice|debug|sandbox|devtools|internal|console|superuser)\b/.test(
      normalizedRoute,
    )
  ) {
    return true;
  }
  return (
    /\bcanactivate\s*:/.test(normalizedBlock) &&
    /\b(?:adminguard|roleguard|permissionguard|rbac|acl|authorization)\b/.test(normalizedBlock)
  );
}

function routeBlock(lines: ReadonlyArray<string>, routeLineIndex: number): string {
  const start = Math.max(0, routeLineIndex - 2);
  const end = Math.min(lines.length, routeLineIndex + 5);
  return lines.slice(start, end).join("\n");
}

function isImagePath(repoPath: string): boolean {
  return /\.(?:png|jpe?g|gif|webp|bmp|ico|svg)$/i.test(repoPath);
}

function looksLikeSteganographyAsset(repoPath: string): boolean {
  const base = path.posix.basename(repoPath).toLowerCase();
  return (
    /(?:steg|hidden|easter|secret)/i.test(repoPath) ||
    (repoPath.includes("/uploads/") && base.includes("#"))
  );
}

function isIgnoredContentObservationPath(repoPath: string): boolean {
  return (
    /(^|\/)(test|tests|__tests__|fixtures|docs)\//i.test(repoPath) ||
    /\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(repoPath) ||
    /(^|\/)data\/static\/(?:codefixes\/|challenges\.ya?ml$)/i.test(repoPath) ||
    /(^|\/)frontend\/src\/assets\/private\//i.test(repoPath)
  );
}

function isRuntimeCodePath(repoPath: string): boolean {
  return /\.(?:[cm]?[jt]sx?|go|java|py)$/i.test(repoPath);
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

function withContentCoverage(
  graph: SecurityGraph,
  scannedFileCount: number,
): SecurityGraph["coverage"] {
  const coverage = {
    area: "content_assets" as const,
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

function contentResourceEvidenceId(kind: string, repoPath: string, value: string): string {
  const hash = createHash("sha256")
    .update(`${kind}\0${repoPath}\0${value}`)
    .digest("hex")
    .slice(0, 16);
  return `content-resource:${kind}:${hash}`;
}

function collectObservationEvidenceIds(
  observations: ReadonlyArray<ContentResourceObservation>,
): string[] {
  return unique(observations.flatMap((observation) => observation.evidenceIds));
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

function splitLines(text: string): string[] {
  return text.split(/\r?\n/);
}

function unique(values: ReadonlyArray<string>): string[] {
  return [...new Set(values)];
}
