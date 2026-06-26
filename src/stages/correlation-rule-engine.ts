import {
  type FindingContextAssessment,
  validateFindingContextAssessments,
} from "../domain/finding-context-assessment.js";
import {
  type HypothesisCandidate,
  hypothesisCandidateId,
  validateHypothesisCandidates,
} from "../domain/hypothesis-candidate.js";
import type {
  GraphCoverageState,
  SecurityGraph,
  SecurityGraphEdge,
  SecurityGraphEdgeKind,
  SecurityGraphNode,
  SecurityGraphNodeKind,
} from "../domain/security-graph.js";

export interface CorrelationRuleDefinition {
  readonly id: string;
  readonly family: string;
  readonly title: string;
  readonly source: CorrelationNodeSelector;
  readonly target: CorrelationNodeSelector;
  readonly path: CorrelationPathDefinition;
  readonly requiredValidation: ReadonlyArray<string>;
  readonly coverageRefs?: ReadonlyArray<string>;
}

export interface CorrelationNodeSelector {
  readonly kinds?: ReadonlyArray<SecurityGraphNodeKind>;
  readonly stableKeys?: ReadonlyArray<string>;
  readonly coverageStates?: ReadonlyArray<GraphCoverageState>;
  readonly propertyEquals?: Readonly<Record<string, string | number | boolean>>;
}

export interface CorrelationPathDefinition {
  readonly allowedEdgeKinds: ReadonlyArray<SecurityGraphEdgeKind>;
  readonly requiredEdgeKinds?: ReadonlyArray<SecurityGraphEdgeKind>;
  readonly maxPathLength: number;
}

export interface CorrelateGraphRulesInput {
  readonly graph: SecurityGraph;
  readonly findingContexts?: ReadonlyArray<FindingContextAssessment>;
  readonly rules: ReadonlyArray<CorrelationRuleDefinition>;
  readonly maxCandidatesPerRule?: number;
  readonly deduplicateSemanticCandidates?: boolean;
}

interface SearchPath {
  readonly startNodeId: string;
  readonly endNodeId: string;
  readonly edgeIds: ReadonlyArray<string>;
  readonly nodeIds: ReadonlyArray<string>;
}

const CONTRADICTION_EDGE_KINDS = new Set<SecurityGraphEdgeKind>([
  "protected_by",
  "contradicted_by",
]);

export function correlateGraphRules(input: CorrelateGraphRulesInput): HypothesisCandidate[] {
  if (input.maxCandidatesPerRule !== undefined) {
    assertPositiveInteger(input.maxCandidatesPerRule, "maxCandidatesPerRule");
  }
  const rules = input.rules.map(validateRule);
  const graphNodeIds = new Set(input.graph.nodes.map((node) => node.id));
  const graphEdgeIds = new Set(input.graph.edges.map((edge) => edge.id));
  const findingContexts = validateFindingContextAssessments(input.findingContexts ?? [], {
    graphNodeIds,
    graphEdgeIds,
  });
  const findingIds = new Set(findingContexts.map((context) => context.findingId));
  const candidates: HypothesisCandidate[] = [];

  for (const rule of rules) {
    const ruleCandidates: HypothesisCandidate[] = [];
    const semanticCandidateIndexes =
      input.deduplicateSemanticCandidates === true ? new Map<string, number>() : undefined;
    for (const path of pathsForRule(input.graph, rule)) {
      const candidate = candidateForPath(input.graph, findingContexts, rule, path);
      if (semanticCandidateIndexes !== undefined) {
        const candidateKey = semanticCandidateKey(input.graph, candidate, path);
        const existingIndex = semanticCandidateIndexes.get(candidateKey);
        if (existingIndex !== undefined) {
          const existing = ruleCandidates[existingIndex];
          if (existing !== undefined) {
            ruleCandidates[existingIndex] = mergeSemanticCandidates(existing, candidate);
          }
          continue;
        }
        semanticCandidateIndexes.set(candidateKey, ruleCandidates.length);
      }
      ruleCandidates.push(candidate);
      if (
        input.maxCandidatesPerRule !== undefined &&
        ruleCandidates.length >= input.maxCandidatesPerRule
      ) {
        break;
      }
    }
    candidates.push(...ruleCandidates);
  }

  return validateHypothesisCandidates(candidates, { findingIds, graphNodeIds, graphEdgeIds });
}

function semanticCandidateKey(
  graph: SecurityGraph,
  candidate: HypothesisCandidate,
  path: SearchPath,
): string {
  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  return [
    candidate.ruleId,
    candidate.family,
    candidate.title,
    semanticNodeKey(nodesById.get(path.startNodeId)),
    semanticNodeKey(nodesById.get(path.endNodeId)),
  ].join("\0");
}

function mergeSemanticCandidates(
  current: HypothesisCandidate,
  duplicate: HypothesisCandidate,
): HypothesisCandidate {
  return {
    ...current,
    findingIds: uniqueSorted([...current.findingIds, ...duplicate.findingIds]),
    supportingNodeIds: uniqueSorted([...current.supportingNodeIds, ...duplicate.supportingNodeIds]),
    supportingEdgeIds: uniqueSorted([...current.supportingEdgeIds, ...duplicate.supportingEdgeIds]),
    contradictingNodeIds: uniqueSorted([
      ...current.contradictingNodeIds,
      ...duplicate.contradictingNodeIds,
    ]),
    contradictingEdgeIds: uniqueSorted([
      ...current.contradictingEdgeIds,
      ...duplicate.contradictingEdgeIds,
    ]),
    coverageRefs: uniqueSorted([...current.coverageRefs, ...duplicate.coverageRefs]),
    requiredValidation: uniqueSorted([
      ...current.requiredValidation,
      ...duplicate.requiredValidation,
    ]),
  };
}

function semanticNodeKey(node: SecurityGraphNode | undefined): string {
  if (node === undefined) {
    return "missing";
  }
  const location =
    node.repoPath === undefined || node.lineRange === undefined
      ? undefined
      : `${node.repoPath}:${node.lineRange.startLine}`;
  const semanticKind =
    location !== undefined && (node.kind === "Boundary" || node.kind === "Source")
      ? "Entry"
      : node.kind;
  const typedDescriptor =
    semanticKind === "Entry" ? undefined : semanticNodeDescriptor(node, location !== undefined);
  if (location !== undefined) {
    return [semanticKind, typedDescriptor ?? "", location].join(":");
  }
  return [semanticKind, typedDescriptor ?? node.stableKey].join(":");
}

function semanticNodeDescriptor(node: SecurityGraphNode, hasLocation: boolean): string | undefined {
  switch (node.kind) {
    case "Boundary":
      return stringProperty(node.properties.routeOrName);
    case "Sink":
      return stringProperty(node.properties.sinkType);
    case "Component":
      return stringProperty(node.properties.packageName);
    case "Resource":
      return stringProperty(node.properties.resourceType);
    case "ExternalService":
      return stringProperty(node.properties.serviceType);
    default:
      return hasLocation ? undefined : stringProperty(node.properties.fullName);
  }
}

function validateRule(rule: CorrelationRuleDefinition): CorrelationRuleDefinition {
  assertNonEmpty(rule.id, "correlation rule id");
  assertNonEmpty(rule.family, `correlation rule ${rule.id} family`);
  assertNonEmpty(rule.title, `correlation rule ${rule.id} title`);
  assertSelector(rule.source, `correlation rule ${rule.id} source`);
  assertSelector(rule.target, `correlation rule ${rule.id} target`);
  assertNonEmptyList(rule.path.allowedEdgeKinds, `correlation rule ${rule.id} allowedEdgeKinds`);
  assertPositiveInteger(rule.path.maxPathLength, `correlation rule ${rule.id} maxPathLength`);
  assertNonEmptyList(rule.requiredValidation, `correlation rule ${rule.id} requiredValidation`);

  const allowedEdgeKinds = new Set(rule.path.allowedEdgeKinds);
  for (const edgeKind of rule.path.requiredEdgeKinds ?? []) {
    if (!allowedEdgeKinds.has(edgeKind)) {
      throw new Error(`correlation rule ${rule.id} required edge kind is not allowed: ${edgeKind}`);
    }
  }
  return rule;
}

function pathsForRule(
  graph: SecurityGraph,
  rule: CorrelationRuleDefinition,
): ReadonlyArray<SearchPath> {
  const nodes = sortedNodes(graph.nodes);
  const starts = nodes.filter((node) => matchesSelector(node, rule.source));
  const targets = new Set(
    nodes.filter((node) => matchesSelector(node, rule.target)).map((node) => node.id),
  );
  const outgoing = outgoingEdges(graph.edges, new Set(rule.path.allowedEdgeKinds));
  const paths: SearchPath[] = [];

  for (const start of starts) {
    const queue: SearchPath[] = [
      { startNodeId: start.id, endNodeId: start.id, edgeIds: [], nodeIds: [start.id] },
    ];
    while (queue.length > 0) {
      const current = queue.shift();
      if (current === undefined) {
        continue;
      }
      if (
        current.edgeIds.length > 0 &&
        targets.has(current.endNodeId) &&
        hasRequiredEdgeKinds(current.edgeIds, graph.edges, rule.path.requiredEdgeKinds ?? [])
      ) {
        paths.push(current);
      }
      if (current.edgeIds.length >= rule.path.maxPathLength) {
        continue;
      }
      for (const edge of outgoing.get(current.endNodeId) ?? []) {
        if (current.nodeIds.includes(edge.toNodeId)) {
          continue;
        }
        queue.push({
          startNodeId: current.startNodeId,
          endNodeId: edge.toNodeId,
          edgeIds: [...current.edgeIds, edge.id],
          nodeIds: [...current.nodeIds, edge.toNodeId],
        });
      }
    }
  }

  return paths.sort(compareSearchPath);
}

function candidateForPath(
  graph: SecurityGraph,
  contexts: ReadonlyArray<FindingContextAssessment>,
  rule: CorrelationRuleDefinition,
  path: SearchPath,
): HypothesisCandidate {
  const edgesById = new Map(graph.edges.map((edge) => [edge.id, edge]));
  const supportEdges = path.edgeIds.flatMap((edgeId) => {
    const edge = edgesById.get(edgeId);
    return edge === undefined ? [] : [edge];
  });
  const supportingNodeIds = uniqueSorted([
    ...path.nodeIds,
    ...supportEdges.flatMap((edge) => [edge.fromNodeId, edge.toNodeId]),
  ]);
  const supportingEdgeIds = uniqueSorted(supportEdges.map((edge) => edge.id));
  const contradictionEdges = contradictionEdgesFor(graph.edges, supportingNodeIds);
  const contradictingNodeIds = endpointNodeIds(contradictionEdges);
  const contradictingEdgeIds = uniqueSorted(contradictionEdges.map((edge) => edge.id));
  const findingIds = linkedFindingIds(contexts, supportingNodeIds, supportingEdgeIds);
  const title = candidateTitle(graph.nodes, rule, path);

  return {
    id: hypothesisCandidateId(graph.graphVersion, rule.id, [
      path.startNodeId,
      path.endNodeId,
      ...supportingEdgeIds,
    ]),
    ruleId: rule.id,
    family: rule.family,
    title,
    findingIds,
    supportingNodeIds,
    supportingEdgeIds,
    contradictingNodeIds,
    contradictingEdgeIds,
    coverageRefs: coverageRefsFor(graph, rule),
    requiredValidation: uniqueSorted(rule.requiredValidation),
    candidateReason: candidateReason(graph.nodes, title, path, supportEdges.length),
  };
}

function candidateTitle(
  nodes: ReadonlyArray<SecurityGraphNode>,
  rule: CorrelationRuleDefinition,
  path: SearchPath,
): string {
  if (rule.family !== "external_input_to_dangerous_operation") {
    return rule.title;
  }
  const target = nodes.find((node) => node.id === path.endNodeId);
  if (target?.kind !== "Sink") {
    return rule.title;
  }
  const sinkType = stringProperty(target.properties.sinkType);
  if (sinkType === "security_misconfiguration") {
    return "Security misconfiguration path: request-controlled check reaches insecure configuration behavior";
  }
  const pathNodes = nodesForPath(nodes, path);
  const routeSemanticTitle = routeSemanticTitleForPath(pathNodes);
  if (routeSemanticTitle !== undefined) {
    return routeSemanticTitle;
  }
  if (sinkType === "sql_execution" && isAccessControlDataAccessPath(pathNodes)) {
    return "Access control path: public route reaches SQL-backed data access without observed authorization";
  }
  switch (sinkType) {
    case "sql_execution":
      return "SQL injection path: external input reaches SQL execution";
    case "no_sql_execution":
      return "NoSQL injection path: external input reaches NoSQL query execution";
    case "xml_processing":
      return "XXE path: external input reaches XML processing";
    case "deserialization":
      return "Insecure deserialization path: external input reaches deserialization";
    case "file_system":
      return "Path traversal or file access path: external input reaches filesystem access";
    case "log_disclosure":
      return "Log disclosure path: external input reaches exposed server log access";
    case "file_upload_validation":
      return "File upload validation path: external input reaches upload validation logic";
    case "redirect":
      return "Open redirect path: external input reaches a redirect";
    case "template_render":
      return "Server-side template injection path: external input reaches template rendering";
    case "code_execution":
      return "Code execution path: external input reaches command or code execution";
    case "hidden_content_exposure":
      return "Hidden content/resource exposure path: external input reaches hidden content";
    case "server_side_request":
      return "Server-side request forgery path: external input reaches a server-side HTTP client";
    case "outbound_http":
      return "Outbound request path: external input reaches an HTTP client";
    case "cross_site_scripting":
      return "Cross-site scripting path: external input reaches HTML or script output";
    case "crypto_weakness":
      return "Cryptographic weakness path: external input reaches cryptographic or encoding logic";
    case "jwt_token_trust":
      return "JWT token trust path: external input reaches JWT signing or parsing logic";
    case "password_reset_trust":
      return "Password reset path: request-controlled recovery data reaches password reset flow";
    case "authentication_bypass":
      return "Authentication bypass path: request-controlled verification data reaches account verification logic";
    case "two_factor_token_trust":
      return "Two-factor authentication path: request-controlled token data reaches TOTP or setup-token trust";
    case "llm_tool_trust":
      return "LLM prompt/tool trust path: request-controlled chat data reaches model tools or prompt policy";
    case "coupon_encoding_trust":
      return "Coupon encoding trust path: request-controlled coupon data reaches reversible discount logic";
    case "anti_automation_bypass":
      return "Anti-automation bypass path: request-controlled action reaches weak rate, replay, or duplicate-action control";
    case "session_cookie_trust":
      return "Cookie trust path: request-controlled cookie or session token reaches trusted session logic";
    case "credential_trust":
      return "Credential trust path: request-controlled login data reaches hardcoded or default credential logic";
    case "client_side_trust":
      return "Client-side trust path: request-controlled client-side value reaches server-side trust decision";
    case "security_misconfiguration":
      return "Security misconfiguration path: request-controlled check reaches insecure configuration behavior";
    case "log_injection":
      return "Log injection path: request-controlled value reaches logging or leaked log-secret flow";
    case "access_control":
      if (target.label.toLowerCase().includes("idor")) {
        return "IDOR path: request-controlled resource id reaches object access";
      }
      return "Access control path: request-controlled resource id reaches owned data access";
    case "csrf_state_change":
      return "CSRF path: state-changing request reaches mutable server-side state without a strong CSRF control";
    default:
      return rule.title;
  }
}

function nodesForPath(
  nodes: ReadonlyArray<SecurityGraphNode>,
  path: SearchPath,
): ReadonlyArray<SecurityGraphNode> {
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  return path.nodeIds.flatMap((nodeId) => {
    const node = nodesById.get(nodeId);
    return node === undefined ? [] : [node];
  });
}

function routeSemanticTitleForPath(
  pathNodes: ReadonlyArray<SecurityGraphNode>,
): string | undefined {
  const descriptors = entryNodeDescriptors(pathNodes).map(normalizeDescriptor);
  if (descriptors.some(hasJwtDescriptor)) {
    return "JWT token trust path: external input reaches JWT signing or parsing logic";
  }
  if (descriptors.some(hasPasswordResetDescriptor)) {
    return "Password reset path: request-controlled recovery data reaches password reset flow";
  }
  if (descriptors.some(hasAuthenticationBypassDescriptor)) {
    return "Authentication bypass path: request-controlled verification data reaches account verification logic";
  }
  if (descriptors.some(hasSecurityMisconfigurationDescriptor)) {
    return "Security misconfiguration path: request-controlled check reaches insecure configuration behavior";
  }
  if (descriptors.some(hasSessionCookieTrustDescriptor)) {
    return "Cookie trust path: request-controlled cookie or session token reaches trusted session logic";
  }
  if (descriptors.some(hasCredentialTrustDescriptor)) {
    return "Credential trust path: request-controlled login data reaches hardcoded or default credential logic";
  }
  if (descriptors.some(hasTwoFactorDescriptor)) {
    return "Two-factor authentication path: request-controlled token data reaches TOTP or setup-token trust";
  }
  if (descriptors.some(hasLlmToolDescriptor)) {
    return "LLM prompt/tool trust path: request-controlled chat data reaches model tools or prompt policy";
  }
  if (descriptors.some(hasCouponEncodingDescriptor)) {
    return "Coupon encoding trust path: request-controlled coupon data reaches reversible discount logic";
  }
  if (descriptors.some(hasAntiAutomationDescriptor)) {
    return "Anti-automation bypass path: request-controlled action reaches weak rate, replay, or duplicate-action control";
  }
  if (descriptors.some(hasClientSideTrustDescriptor)) {
    return "Client-side trust path: request-controlled client-side value reaches server-side trust decision";
  }
  if (descriptors.some(hasLogInjectionDescriptor)) {
    return "Log injection path: request-controlled value reaches logging or leaked log-secret flow";
  }
  if (descriptors.some(hasCryptographicDescriptor)) {
    return "Cryptographic weakness path: external input reaches cryptographic or encoding logic";
  }
  return undefined;
}

function isAccessControlDataAccessPath(pathNodes: ReadonlyArray<SecurityGraphNode>): boolean {
  const descriptors = entryNodeDescriptors(pathNodes).map(normalizeDescriptor);
  if (descriptors.some(isFixedOrSafeDescriptor)) {
    return false;
  }
  return descriptors.some(hasAccessControlDescriptor);
}

function entryNodeDescriptors(pathNodes: ReadonlyArray<SecurityGraphNode>): string[] {
  return pathNodes
    .filter((node) => node.kind === "Boundary" || node.kind === "Source")
    .flatMap(nodeDescriptors);
}

function nodeDescriptors(node: SecurityGraphNode): string[] {
  return [
    node.label,
    node.repoPath,
    node.symbol,
    stringProperty(node.properties.routeOrName),
    stringProperty(node.properties.fullName),
    stringProperty(node.properties.callName),
  ].flatMap((value) => (value === undefined ? [] : [value]));
}

function normalizeDescriptor(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function hasAccessControlDescriptor(value: string): boolean {
  return (
    value.includes("access-control") ||
    value.includes("missing-access-control") ||
    value.includes("missing-function-ac") ||
    value.includes("missingac")
  );
}

function hasJwtDescriptor(value: string): boolean {
  return value.includes("jwt") || value.includes("json-web-token");
}

function hasPasswordResetDescriptor(value: string): boolean {
  return value.includes("passwordreset") || value.includes("password-reset");
}

function hasAuthenticationBypassDescriptor(value: string): boolean {
  return value.includes("auth-bypass") || value.includes("authbypass");
}

function hasSessionCookieTrustDescriptor(value: string): boolean {
  return (
    value.includes("hijacksession") ||
    value.includes("hijack-session") ||
    value.includes("spoofcookie") ||
    value.includes("spoof-cookie")
  );
}

function hasCredentialTrustDescriptor(value: string): boolean {
  return (
    value.includes("insecurelogin") ||
    value.includes("insecure-login") ||
    value.includes("routes-login") ||
    value.includes("default-credential") ||
    value.includes("defaultcredentials")
  );
}

function hasTwoFactorDescriptor(value: string): boolean {
  return (
    value.includes("2fa") ||
    value.includes("two-factor") ||
    value.includes("totp") ||
    value.includes("twofactorauth")
  );
}

function hasLlmToolDescriptor(value: string): boolean {
  return (
    value.includes("routes-chat") ||
    value.includes("chatbot") ||
    value.includes("llm") ||
    value.includes("buildsystemprompt") ||
    value.includes("prompt-injection")
  );
}

function hasCouponEncodingDescriptor(value: string): boolean {
  return value.includes("coupon") || value.includes("discountfromcoupon");
}

function hasAntiAutomationDescriptor(value: string): boolean {
  return (
    value.includes("captchabypasschallenge") ||
    value.includes("captcha-bypass-challenge") ||
    value.includes("extralanguagechallenge") ||
    value.includes("extra-language-challenge") ||
    value.includes("timingattackchallenge") ||
    value.includes("timing-attack-challenge") ||
    value.includes("likeproductreviews") ||
    value.includes("like-product-reviews")
  );
}

function hasClientSideTrustDescriptor(value: string): boolean {
  return (
    value.includes("clientsidefiltering") ||
    value.includes("client-side-filtering") ||
    value.includes("htmltampering") ||
    value.includes("html-tampering") ||
    value.includes("bypassrestrictions") ||
    value.includes("bypass-restrictions")
  );
}

function hasSecurityMisconfigurationDescriptor(value: string): boolean {
  return (
    value.includes("securitymisconfiguration") ||
    value.includes("security-misconfiguration") ||
    value.includes("deprecatedinterfacechallenge") ||
    value.includes("deprecated-interface-challenge") ||
    value.includes("errorhandlingchallenge") ||
    value.includes("error-handling-challenge") ||
    value.includes("loginsupportchallenge") ||
    value.includes("login-support-challenge") ||
    value.includes("svginjectionchallenge") ||
    value.includes("svg-injection-challenge") ||
    value.includes("verifysvginjectionchallenge") ||
    value.includes("verify-svg-injection-challenge")
  );
}

function hasLogInjectionDescriptor(value: string): boolean {
  return (
    value.includes("logspoofing") ||
    value.includes("log-spoofing") ||
    value.includes("lessons-logging")
  );
}

function hasCryptographicDescriptor(value: string): boolean {
  return value.includes("crypto") || value.includes("cryptography");
}

function isFixedOrSafeDescriptor(value: string): boolean {
  return /(?:^|-)(?:fix|fixed|safe|secure)(?:$|-)/.test(value);
}

function linkedFindingIds(
  contexts: ReadonlyArray<FindingContextAssessment>,
  supportingNodeIds: ReadonlyArray<string>,
  supportingEdgeIds: ReadonlyArray<string>,
): string[] {
  const nodeIds = new Set(supportingNodeIds);
  const edgeIds = new Set(supportingEdgeIds);
  return uniqueSorted(
    contexts
      .filter((context) => context.status !== "standalone")
      .filter(
        (context) =>
          context.graphNodeIds.some((nodeId) => nodeIds.has(nodeId)) ||
          context.graphEdgeIds.some((edgeId) => edgeIds.has(edgeId)),
      )
      .map((context) => context.findingId),
  );
}

function contradictionEdgesFor(
  edges: ReadonlyArray<SecurityGraphEdge>,
  supportingNodeIds: ReadonlyArray<string>,
): SecurityGraphEdge[] {
  const nodeIds = new Set(supportingNodeIds);
  return sortedEdges(
    edges.filter(
      (edge) =>
        CONTRADICTION_EDGE_KINDS.has(edge.kind) &&
        (nodeIds.has(edge.fromNodeId) || nodeIds.has(edge.toNodeId)),
    ),
  );
}

function matchesSelector(node: SecurityGraphNode, selector: CorrelationNodeSelector): boolean {
  if (selector.kinds !== undefined && !selector.kinds.includes(node.kind)) {
    return false;
  }
  if (selector.stableKeys !== undefined && !selector.stableKeys.includes(node.stableKey)) {
    return false;
  }
  if (
    selector.coverageStates !== undefined &&
    !selector.coverageStates.includes(node.coverageState)
  ) {
    return false;
  }
  for (const [key, expected] of Object.entries(selector.propertyEquals ?? {})) {
    if (node.properties[key] !== expected) {
      return false;
    }
  }
  return true;
}

function outgoingEdges(
  edges: ReadonlyArray<SecurityGraphEdge>,
  allowedKinds: ReadonlySet<SecurityGraphEdgeKind>,
): ReadonlyMap<string, ReadonlyArray<SecurityGraphEdge>> {
  const out = new Map<string, SecurityGraphEdge[]>();
  for (const edge of sortedEdges(edges)) {
    if (!allowedKinds.has(edge.kind)) {
      continue;
    }
    const current = out.get(edge.fromNodeId) ?? [];
    current.push(edge);
    out.set(edge.fromNodeId, current);
  }
  return out;
}

function hasRequiredEdgeKinds(
  edgeIds: ReadonlyArray<string>,
  edges: ReadonlyArray<SecurityGraphEdge>,
  requiredKinds: ReadonlyArray<SecurityGraphEdgeKind>,
): boolean {
  if (requiredKinds.length === 0) {
    return true;
  }
  const edgesById = new Map(edges.map((edge) => [edge.id, edge]));
  const seenKinds = new Set(
    edgeIds.flatMap((edgeId) => {
      const edge = edgesById.get(edgeId);
      return edge === undefined ? [] : [edge.kind];
    }),
  );
  return requiredKinds.every((kind) => seenKinds.has(kind));
}

function coverageRefsFor(
  graph: SecurityGraph,
  rule: CorrelationRuleDefinition,
): ReadonlyArray<string> {
  return uniqueSorted([
    ...(rule.coverageRefs ?? []),
    ...graph.coverage.map((coverage) => `${coverage.area}:${coverage.state}`),
    ...(graph.coverage.length === 0 ? ["graph:coverage-unavailable"] : []),
  ]);
}

function candidateReason(
  nodes: ReadonlyArray<SecurityGraphNode>,
  title: string,
  path: SearchPath,
  edgeCount: number,
): string {
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  const start = reasonNodeLabel(nodesById.get(path.startNodeId)) ?? path.startNodeId;
  const end = reasonNodeLabel(nodesById.get(path.endNodeId)) ?? path.endNodeId;
  return `${title}: ${start} reaches ${end} across ${edgeCount} graph edges`;
}

function reasonNodeLabel(node: SecurityGraphNode | undefined): string | undefined {
  if (node === undefined) {
    return undefined;
  }
  const contentLabel = contentResourceReasonLabel(node);
  if (contentLabel !== undefined) {
    return contentLabel;
  }
  const location = nodeLocationLabel(node);
  if (!isVerboseCodeLabel(node.label)) {
    const label = trimWhitespace(node.label);
    if (location !== undefined && !label.includes(location)) {
      return `${label} (${location})`;
    }
    return label;
  }
  if (location !== undefined) {
    return location;
  }
  return trimWhitespace(node.label).slice(0, 80);
}

function contentResourceReasonLabel(node: SecurityGraphNode): string | undefined {
  if (node.properties.resourceType !== "content_resource") {
    return undefined;
  }
  const value =
    stringProperty(node.properties.route) ??
    stringProperty(node.properties.assetPath) ??
    stringProperty(node.properties.matcher) ??
    stringProperty(node.properties.clue) ??
    node.label;
  const label = trimWhitespace(value);
  const location = nodeLocationLabel(node);
  const compact = label.length > 120 ? `${label.slice(0, 117).trimEnd()}...` : label;
  return location === undefined ? compact : `${compact} (${location})`;
}

function nodeLocationLabel(node: SecurityGraphNode): string | undefined {
  if (node.repoPath === undefined || node.lineRange === undefined) {
    return undefined;
  }
  return `${node.repoPath}:${node.lineRange.startLine}`;
}

function isVerboseCodeLabel(label: string): boolean {
  const trimmed = trimWhitespace(label);
  return (
    label.includes("\n") ||
    trimmed.length > 80 ||
    trimmed.startsWith("function ") ||
    trimmed.startsWith("async function ") ||
    trimmed.startsWith("app.use(") ||
    trimmed.includes("=>")
  );
}

function trimWhitespace(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function stringProperty(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

function endpointNodeIds(edges: ReadonlyArray<SecurityGraphEdge>): string[] {
  return uniqueSorted(edges.flatMap((edge) => [edge.fromNodeId, edge.toNodeId]));
}

function compareSearchPath(a: SearchPath, b: SearchPath): number {
  return (
    a.startNodeId.localeCompare(b.startNodeId) ||
    a.endNodeId.localeCompare(b.endNodeId) ||
    a.edgeIds.join("\0").localeCompare(b.edgeIds.join("\0"))
  );
}

function sortedNodes(nodes: ReadonlyArray<SecurityGraphNode>): SecurityGraphNode[] {
  return [...nodes].sort(
    (a, b) => a.stableKey.localeCompare(b.stableKey) || a.id.localeCompare(b.id),
  );
}

function sortedEdges(edges: ReadonlyArray<SecurityGraphEdge>): SecurityGraphEdge[] {
  return [...edges].sort(
    (a, b) => a.stableKey.localeCompare(b.stableKey) || a.id.localeCompare(b.id),
  );
}

function assertSelector(selector: CorrelationNodeSelector, label: string): void {
  if (
    selector.kinds === undefined &&
    selector.stableKeys === undefined &&
    selector.coverageStates === undefined &&
    selector.propertyEquals === undefined
  ) {
    throw new Error(`${label} selector must constrain at least one field`);
  }
  if (selector.kinds !== undefined) {
    assertNonEmptyList(selector.kinds, `${label} kinds`);
  }
  if (selector.stableKeys !== undefined) {
    assertNonEmptyList(selector.stableKeys, `${label} stableKeys`);
  }
  if (selector.coverageStates !== undefined) {
    assertNonEmptyList(selector.coverageStates, `${label} coverageStates`);
  }
  const propertyKeys = Object.keys(selector.propertyEquals ?? {});
  if (selector.propertyEquals !== undefined && propertyKeys.length === 0) {
    throw new Error(`${label} propertyEquals must constrain at least one property`);
  }
  for (const key of propertyKeys) {
    assertNonEmpty(key, `${label} propertyEquals key`);
  }
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
}

function assertNonEmpty(value: string, label: string): void {
  if (value.trim() === "") {
    throw new Error(`${label} is required`);
  }
}

function assertNonEmptyList(values: ReadonlyArray<string>, label: string): void {
  if (values.length === 0) {
    throw new Error(`${label} are required`);
  }
  for (const value of values) {
    assertNonEmpty(value, label);
  }
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}
