import type { RulePolicy } from "./contracts.js";

export const defaultPolicy: readonly RulePolicy[] = [
  {
    scanner: "gitleaks",
    ruleId: "generic-api-key",
    remediationKey: "secret-rotation",
    publishMedium: false,
    requireHighConfidence: true,
  },
  {
    scanner: "opengrep",
    ruleId: "command-injection",
    remediationKey: "command-input",
    publishMedium: false,
    requireHighConfidence: true,
  },
  {
    scanner: "opengrep",
    ruleId: "sql-injection",
    remediationKey: "sql-input",
    publishMedium: false,
    requireHighConfidence: true,
  },
  {
    scanner: "opengrep",
    ruleId: "path-traversal",
    remediationKey: "path-url-validation",
    publishMedium: false,
    requireHighConfidence: true,
  },
  {
    scanner: "opengrep",
    ruleId: "ssrf",
    remediationKey: "path-url-validation",
    publishMedium: false,
    requireHighConfidence: true,
  },
  {
    scanner: "opengrep",
    ruleId: "unsafe-deserialization",
    remediationKey: "unsafe-deserialization",
    publishMedium: false,
    requireHighConfidence: true,
  },
  {
    scanner: "opengrep",
    ruleId: "jwt-validation",
    remediationKey: "jwt-validation",
    publishMedium: false,
    requireHighConfidence: true,
  },
  {
    scanner: "osv",
    ruleId: "*",
    remediationKey: "dependency-upgrade",
    publishMedium: false,
    requireHighConfidence: false,
  },
  {
    scanner: "trivy",
    ruleId: "privileged-container",
    remediationKey: "config-privilege",
    publishMedium: false,
    requireHighConfidence: true,
  },
  {
    scanner: "zizmor",
    ruleId: "dangerous-workflow-permissions",
    remediationKey: "workflow-privilege",
    publishMedium: false,
    requireHighConfidence: true,
  },
];
