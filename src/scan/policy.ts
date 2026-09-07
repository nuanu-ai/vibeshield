import type { RulePolicy } from "./contracts.js";

export const trivyPolicy = {
  version: "0.72.0",
  bundle: {
    digest: "sha256:1583562f8b90ed2a071b99f0e5ffff6b57e4ceb6ca3e4796577b4e6a339eb74c",
    revision: "d7c9302130a9b7e614a5c5d32854f6a08b4bc52e",
    version: "2.2.0",
    reviewedAt: "2026-09-07T00:00:00Z",
  },
  // Observed under this exact bundle on privileged/fixed Kubernetes pods.
  rules: [
    { id: "KSV-0017", namespace: "builtin.kubernetes.KSV017", remediationKey: "config-privilege" },
  ],
} as const;

// Only these explicit lockfile extractors are enabled; package.json resolution is disabled.
export const osvPolicy = {
  version: "2.3.8",
  lockfiles: ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"],
} as const;

export const opengrepRules = [
  {
    id: "rules_lgpl_javascript_exec_rule-shelljs-os-command-exec",
    source: "exec/rule-shelljs_os_command_exec",
    mode: "search",
    remediationKey: "command-input",
  },
  {
    id: "rules_lgpl_javascript_database_rule-node-sqli-injection",
    source: "database/rule-node_sqli_injection",
    mode: "search",
    remediationKey: "sql-input",
  },
  {
    id: "rules_lgpl_javascript_traversal_rule-express-lfr",
    source: "traversal/rule-express_lfr",
    mode: "taint",
    remediationKey: "path-url-validation",
  },
  {
    id: "rules_lgpl_javascript_ssrf_rule-node-ssrf",
    source: "ssrf/rule-node_ssrf",
    mode: "taint",
    remediationKey: "path-url-validation",
  },
  {
    id: "rules_lgpl_javascript_eval_rule-node-deserialize",
    source: "eval/rule-node_deserialize",
    mode: "search",
    remediationKey: "unsafe-deserialization",
  },
  {
    id: "rules_lgpl_javascript_jwt_rule-node-jwt-none-algorithm",
    source: "jwt/rule-node_jwt_none_algorithm",
    mode: "taint",
    remediationKey: "jwt-validation",
  },
] as const;

export const defaultPolicy: readonly RulePolicy[] = [
  {
    scanner: "gitleaks",
    ruleId: "generic-api-key",
    remediationKey: "secret-rotation",
    publishMedium: false,
    requireHighConfidence: true,
  },
  ...opengrepRules.map(
    (rule): RulePolicy => ({
      scanner: "opengrep",
      ruleId: rule.id,
      remediationKey: rule.remediationKey,
      publishMedium: false,
      requireHighConfidence: true,
    }),
  ),
  {
    scanner: "osv",
    ruleId: "*",
    remediationKey: "dependency-upgrade",
    publishMedium: false,
    requireHighConfidence: false,
  },
  ...trivyPolicy.rules.map(
    (rule): RulePolicy => ({
      scanner: "trivy",
      ruleId: rule.id,
      remediationKey: rule.remediationKey,
      publishMedium: false,
      requireHighConfidence: true,
    }),
  ),
  {
    scanner: "zizmor",
    ruleId: "dangerous-workflow-permissions",
    remediationKey: "workflow-privilege",
    publishMedium: false,
    requireHighConfidence: true,
  },
];
