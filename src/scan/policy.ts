import type { RulePolicy } from "./contracts.js";

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
