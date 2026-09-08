import type { Finding, Issue, Report, ReportInput, RulePolicy, Severity } from "./contracts.js";
import type { RemediationKey } from "./remediation.js";
import { hasRemediationTemplate, remediationFor } from "./remediation.js";

export function buildReport(input: ReportInput): Report {
  const findings = input.results.flatMap((result) => result.findings);
  const published = findings.filter((finding) => shouldPublish(finding, input.policy));
  const coverage = input.results.flatMap((result) => result.coverage);

  return {
    repository: input.repository,
    provenance: input.provenance,
    generatedAt: input.generatedAt,
    issues: groupFindings(published).map(issueFor),
    coverage,
    incomplete: coverage.some(
      (entry) =>
        entry.applicable &&
        (entry.status === "failed" || entry.status === "degraded" || entry.status === "skipped"),
    ),
    suppressedCount: findings.length - published.length,
  };
}

function shouldPublish(finding: Finding, policy: readonly RulePolicy[]): boolean {
  if (finding.severity === "low" || finding.severity === "unknown") {
    return false;
  }
  if (!hasRemediationTemplate(finding.remediationKey) || !hasRequiredEvidence(finding)) {
    return false;
  }
  const matchingPolicy = policy.find((entry) => policyMatches(entry, finding));
  if (matchingPolicy === undefined || matchingPolicy.remediationKey !== finding.remediationKey) {
    return false;
  }
  if (matchingPolicy.requireHighConfidence && finding.confidence !== "high") {
    return false;
  }
  return finding.severity !== "medium" || matchingPolicy.publishMedium;
}

function policyMatches(policy: RulePolicy, finding: Finding): boolean {
  if (policy.scanner !== finding.scanner) {
    return false;
  }
  if (policy.ruleId === "*") {
    return finding.scanner === "osv" && isOsvAdvisoryFinding(finding);
  }
  return policy.ruleId === finding.ruleId;
}

function isOsvAdvisoryFinding(finding: Finding): boolean {
  const dependency = finding.dependency;
  return (
    finding.category === "dependency" &&
    dependency !== undefined &&
    hasText(dependency.ecosystem) &&
    hasText(dependency.name) &&
    hasText(dependency.version) &&
    hasText(dependency.manifest) &&
    dependency.advisoryIds.some(hasText)
  );
}

function hasText(value: string): boolean {
  return value.trim().length > 0;
}

function hasRequiredEvidence(finding: Finding): boolean {
  if (finding.evidence.trim().length === 0 || finding.locations.length === 0) {
    return false;
  }
  return finding.category !== "code" || /(?:^|\s)flow:/i.test(finding.evidence);
}

function groupFindings(findings: Finding[]): Finding[][] {
  const parent = findings.map((_, index) => index);
  const root = (index: number): number => {
    const ancestor = parent[index];
    if (ancestor === undefined || ancestor === index) {
      return index;
    }
    const resolved = root(ancestor);
    parent[index] = resolved;
    return resolved;
  };
  const join = (left: number, right: number): void => {
    const leftRoot = root(left);
    const rightRoot = root(right);
    if (leftRoot !== rightRoot) {
      parent[rightRoot] = leftRoot;
    }
  };

  for (let left = 0; left < findings.length; left += 1) {
    const leftFinding = findings[left];
    if (leftFinding === undefined) {
      continue;
    }
    for (let right = left + 1; right < findings.length; right += 1) {
      const rightFinding = findings[right];
      if (rightFinding !== undefined && sameRootCause(leftFinding, rightFinding)) {
        join(left, right);
      }
    }
  }

  const groups = new Map<number, Finding[]>();
  for (const [index, finding] of findings.entries()) {
    const component = root(index);
    const group = groups.get(component);
    if (group === undefined) {
      groups.set(component, [finding]);
    } else {
      group.push(finding);
    }
  }
  return [...groups.values()].sort(compareGroups);
}

function sameRootCause(left: Finding, right: Finding): boolean {
  if (left.category !== "dependency" || right.category !== "dependency") {
    return left.rootCause === right.rootCause;
  }
  if (!sameDependencyCoordinate(left, right)) {
    return false;
  }
  return left.rootCause === right.rootCause || sharesAdvisoryAlias(left, right);
}

function sameDependencyCoordinate(left: Finding, right: Finding): boolean {
  const leftDependency = left.dependency;
  const rightDependency = right.dependency;
  return (
    leftDependency !== undefined &&
    rightDependency !== undefined &&
    leftDependency.ecosystem === rightDependency.ecosystem &&
    leftDependency.name === rightDependency.name &&
    leftDependency.version === rightDependency.version &&
    leftDependency.manifest === rightDependency.manifest
  );
}

function sharesAdvisoryAlias(left: Finding, right: Finding): boolean {
  const rightAliases = new Set(right.dependency?.advisoryIds ?? []);
  return left.dependency?.advisoryIds.some((identifier) => rightAliases.has(identifier)) ?? false;
}

function issueFor(members: Finding[]): Issue {
  const sortedMembers = stableFindings(members);
  const representative = requiredFirst(sortedMembers, "issue group");
  const remediation = remediationFor(representative);
  const evidence = sortedMembers.map((finding) => finding.evidence);
  const locations = sortedMembers.flatMap((finding) => finding.locations).sort(compareLocations);
  const findingIds = sortedMembers.map((finding) => finding.id);
  return {
    id: `issue:${findingIds.join(",")}`,
    title: representative.title,
    remediationKey: representative.remediationKey as RemediationKey,
    severity: highestSeverity(members),
    why: `Observed by ${representative.scanner}; review the preserved evidence before deciding impact.`,
    locations,
    evidence,
    findingIds,
    remediation: remediation.remediation,
    verification: remediation.verification,
    prompt: deterministicPrompt(representative, locations, remediation),
  };
}

function compareLocations(
  left: Finding["locations"][number],
  right: Finding["locations"][number],
): number {
  return (
    left.path.localeCompare(right.path) ||
    left.line - right.line ||
    (left.commit ?? "").localeCompare(right.commit ?? "")
  );
}

function deterministicPrompt(
  finding: Finding,
  locations: Finding["locations"],
  remediation: { remediation: string; verification: string },
): string {
  const locationList = locations.map((location) => `${location.path}:${location.line}`).join(", ");
  return [
    `Observed finding: ${finding.title}.`,
    `Evidence locations: ${locationList}.`,
    `Apply this fix: ${remediation.remediation}`,
    `Verify it: ${remediation.verification}`,
    "Do not infer exploitability beyond the observed evidence.",
  ].join("\n");
}

function stableFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(compareFindings);
}

function compareFindings(left: Finding, right: Finding): number {
  return (
    severityRank(right.severity) - severityRank(left.severity) ||
    firstPath(left).localeCompare(firstPath(right)) ||
    left.ruleId.localeCompare(right.ruleId) ||
    left.id.localeCompare(right.id)
  );
}

function compareGroups(left: Finding[], right: Finding[]): number {
  return compareFindings(
    requiredFirst(stableFindings(left), "left issue group"),
    requiredFirst(stableFindings(right), "right issue group"),
  );
}

function highestSeverity(findings: Finding[]): Severity {
  return requiredFirst(stableFindings(findings), "issue group").severity;
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    case "unknown":
      return 0;
  }
}

function firstPath(finding: Finding): string {
  return finding.locations[0]?.path ?? "";
}

function requiredFirst<T>(values: readonly T[], label: string): T {
  const value = values[0];
  if (value === undefined) {
    throw new Error(`Expected ${label} to have at least one value`);
  }
  return value;
}
