import type { Finding } from "./contracts.js";

const templates = {
  "secret-rotation": {
    remediation:
      "Revoke or rotate the exposed credential, replace it with a secret supplied outside the repository, and remove the committed value.",
    verification:
      "Confirm the old credential is rejected, then scan the current tree and the affected history again for the redacted marker.",
  },
  "dependency-upgrade": {
    remediation:
      "Upgrade the affected dependency to a fixed version and refresh the resolved lockfile without changing unrelated packages.",
    verification:
      "Install from the updated lockfile and rerun the dependency advisory scan to confirm the listed advisory is no longer reported.",
  },
  "command-input": {
    remediation:
      "Avoid shell construction from input; use a fixed executable with an argument array and validate each accepted value.",
    verification:
      "Add a test with an unexpected argument that proves it is rejected and rerun the selected code-security rule.",
  },
  "sql-input": {
    remediation:
      "Replace interpolated SQL with parameterized queries and validate values before they reach the query boundary.",
    verification:
      "Add a test using a quote-bearing input and verify it remains data rather than altering the query structure.",
  },
  "path-url-validation": {
    remediation:
      "Validate the requested path or URL against an allowlist before use, and reject traversal, private-address, or unsupported-scheme input as applicable.",
    verification:
      "Add tests for a disallowed path or URL and confirm the request is rejected before the filesystem or network operation.",
  },
  "unsafe-deserialization": {
    remediation:
      "Replace unsafe deserialization with a constrained data format and validate the decoded shape before it affects application behavior.",
    verification:
      "Add a malformed or unexpected payload test and confirm it is rejected without invoking application-controlled behavior.",
  },
  "jwt-validation": {
    remediation:
      "Verify the JWT signature and required claims with an explicit allowed algorithm and issuer/audience policy before authorizing a request.",
    verification:
      "Add tests for an invalid signature, unexpected algorithm, and invalid claims; each must be denied.",
  },
  "config-privilege": {
    remediation:
      "Remove the unnecessary privileged configuration and grant only the specific capability or access the workload requires.",
    verification:
      "Review the rendered configuration and run the configuration scan to confirm the privilege finding is gone.",
  },
  "workflow-input": {
    remediation:
      "Pass untrusted workflow input through an environment variable, then use safe quoting in shell commands. Do not interpolate the input directly into run or another executable script field.",
    verification:
      "Check a workflow fixture with a quote-bearing pull request title, confirm the title remains data, and rerun the workflow security scan.",
  },
  "workflow-privilege": {
    remediation:
      "Restrict workflow permissions and untrusted trigger access to the minimum needed for the job.",
    verification:
      "Run the workflow security check and inspect the effective permissions for the affected job.",
  },
} as const;

export type RemediationKey = keyof typeof templates;

export function hasRemediationTemplate(key: string): key is RemediationKey {
  return Object.hasOwn(templates, key);
}

export function remediationFor(finding: Finding): { remediation: string; verification: string } {
  if (!hasRemediationTemplate(finding.remediationKey)) {
    throw new Error(`No remediation template for ${finding.remediationKey}`);
  }
  return templates[finding.remediationKey];
}
