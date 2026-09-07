export type ScannerId = "gitleaks" | "opengrep" | "osv" | "trivy" | "zizmor";
export type Severity = "critical" | "high" | "medium" | "low" | "unknown";
export type Category = "secret" | "code" | "dependency" | "config" | "workflow";

export interface Location {
  path: string;
  line: number;
  commit?: string;
}
export interface Dependency {
  ecosystem: string;
  name: string;
  version: string;
  manifest: string;
  scope: "runtime" | "development" | "unknown";
  advisoryIds: string[];
  fixedVersions: string[];
}
export interface Finding {
  id: string;
  scanner: ScannerId;
  ruleId: string;
  category: Category;
  severity: Severity;
  confidence: "high" | "medium" | "low" | "unknown";
  title: string;
  evidence: string;
  locations: Location[];
  rootCause: string;
  remediationKey: string;
  dependency?: Dependency;
}
export interface Coverage {
  scanner: ScannerId;
  area: string;
  status: "checked" | "skipped" | "failed" | "degraded";
  reason: string;
  applicable: boolean;
}
export interface ScanResult {
  findings: Finding[];
  coverage: Coverage[];
}
export interface Snapshot {
  url: string;
  commit: string;
  files: string[];
  history: { commits: number; truncated: boolean };
  languages: string[];
}
export interface Provenance {
  image: string;
  tools: Record<ScannerId, string>;
  rulesRevision: string;
  advisoryData: { source: string; retrievedAt: string; revision?: string; stale: boolean }[];
}
export interface Issue {
  id: string;
  title: string;
  severity: Severity;
  why: string;
  locations: Location[];
  evidence: string[];
  findingIds: string[];
  remediation: string;
  verification: string;
  prompt: string;
}
export interface Report {
  repository: Snapshot;
  provenance: Provenance;
  generatedAt: string;
  issues: Issue[];
  coverage: Coverage[];
  incomplete: boolean;
  suppressedCount: number;
}
export type Stage = "prepare" | "acquire" | ScannerId | "report" | "cleanup";
export interface Progress {
  stage: Stage;
  status: "waiting" | "running" | "completed" | "skipped" | "failed";
  message: string;
}
export interface RulePolicy {
  scanner: ScannerId;
  ruleId: string;
  remediationKey: string;
  publishMedium: boolean;
  requireHighConfidence: boolean;
}
export interface ReportInput {
  repository: Snapshot;
  provenance: Provenance;
  generatedAt: string;
  results: ScanResult[];
  policy: readonly RulePolicy[];
}
