import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { Coverage, Finding, ScanResult, Severity } from "../contracts.js";
import { LIMITS } from "../limits.js";
import { isRecord, isSafeRepositoryPath } from "../manifest.js";
import { trivyPolicy } from "../policy.js";
import { readScannerJson, type ScannerContext } from "./shared.js";

const object = (value: unknown): Record<string, unknown> => (isRecord(value) ? value : {});
const text = (value: unknown): string => (typeof value === "string" ? value : "");
const candidate = (path: string): boolean =>
  /\.(?:ya?ml|json|tf|tfvars|hcl|bicep)$|(?:^|\/)(?:Dockerfile|Containerfile)(?:\.[^/]+)?$/i.test(
    path,
  );
// Package/scanner settings are not infrastructure candidates. Other YAML/JSON
// remains ambiguous until the engine recognizes it; omissions stay visible.
const configuration = (path: string): boolean =>
  /(?:^|\/)(?:package(?:-lock)?\.json|tsconfig[^/]*\.json|pnpm-(?:lock|workspace)\.yaml|trivy\.ya?ml|\.trivyignore(?:\.yaml)?)$/.test(
    path,
  );
function coverage(
  area: string,
  status: Coverage["status"],
  reason: string,
  applicable = true,
): Coverage {
  return { scanner: "trivy", area, status, reason, applicable };
}
function failed(): ScanResult {
  return {
    findings: [],
    coverage: [
      coverage(
        "kubernetes",
        "failed",
        "Configuration scan failed or its bounded export, engine version, or frozen checks bundle was invalid.",
      ),
    ],
  };
}
export async function scanTrivy({
  session,
  snapshot,
  signal,
}: ScannerContext): Promise<ScanResult> {
  try {
    signal.throwIfAborted();
    const candidates = snapshot.files.filter((path) => candidate(path) && !configuration(path));
    if (candidates.length === 0)
      return {
        findings: [],
        coverage: [
          coverage(
            "kubernetes",
            "skipped",
            "No infrastructure configuration candidate files are present.",
            false,
          ),
        ],
      };
    const status = await session.exec(["node", "/usr/local/bin/vibeshield-trivy"], {
      signal,
      timeoutMs: LIMITS.scannerMs,
    });
    if (status.exitCode !== 0) return failed();
    signal.throwIfAborted();
    const value = object(await readScannerJson(session, "/work/.vibeshield/exports/trivy.json"));
    const report = object(value.report);
    if (
      !isDeepStrictEqual(value.bundle, trivyPolicy.bundle) ||
      typeof value.warnings !== "boolean" ||
      report.SchemaVersion !== 2 ||
      object(report.Trivy).Version !== trivyPolicy.version ||
      report.ArtifactType !== "filesystem" ||
      !Array.isArray(report.Results)
    )
      return failed();
    const findings: Finding[] = [];
    const checked = new Set<string>();
    let degraded = value.warnings;
    for (const raw of report.Results) {
      const result = object(raw);
      const path = text(result.Target);
      if (!isSafeRepositoryPath(path) || !snapshot.files.includes(path)) return failed();
      if (
        result.Class !== "config" ||
        result.Type !== "kubernetes" ||
        !Array.isArray(result.Misconfigurations)
      ) {
        degraded = true;
        continue;
      }
      const observed = new Set<string>();
      for (const rawFinding of result.Misconfigurations) {
        const item = object(rawFinding);
        const rule = trivyPolicy.rules.find((rule) => rule.id === item.ID);
        if (!rule) continue;
        if (!["PASS", "FAIL"].includes(text(item.Status))) {
          degraded = true;
          continue;
        }
        observed.add(rule.id);
        if (item.Status === "PASS") continue;
        const cause = object(item.CauseMetadata);
        const line = cause.StartLine;
        const end = cause.EndLine;
        if (
          item.Namespace !== rule.namespace ||
          item.Query !== `data.${rule.namespace}.deny` ||
          typeof line !== "number" ||
          !Number.isSafeInteger(line) ||
          line < 1 ||
          typeof end !== "number" ||
          !Number.isSafeInteger(end) ||
          end < line ||
          !text(item.Title).trim() ||
          !text(item.Description).trim() ||
          !text(item.Resolution).trim() ||
          item.PrimaryURL !== `https://avd.aquasec.com/misconfig/${rule.id.toLowerCase()}` ||
          !Array.isArray(item.References) ||
          !item.References.every((ref) => typeof ref === "string" && /^https:\/\//.test(ref))
        ) {
          degraded = true;
          continue;
        }
        const severity = text(item.Severity).toLowerCase();
        const identity = createHash("sha256")
          .update(JSON.stringify([rule.id, path, line, end]))
          .digest("hex");
        findings.push({
          id: `trivy:${rule.id}:${identity}`,
          scanner: "trivy",
          ruleId: rule.id,
          category: "config",
          severity: ["critical", "high", "medium", "low"].includes(severity)
            ? (severity as Severity)
            : "unknown",
          confidence: "high",
          title: text(item.Title),
          evidence: `${rule.id} at ${path}:${line}-${end}. ${text(item.Description)} Recommended action: ${text(item.Resolution)} References: ${[...new Set([item.PrimaryURL, ...item.References])].join(" ")}`,
          locations: [{ path, line }],
          rootCause: `trivy:${rule.id}:${path}:${line}`,
          remediationKey: rule.remediationKey,
        });
      }
      if (trivyPolicy.rules.every((rule) => observed.has(rule.id))) checked.add(path);
      else degraded = true;
    }
    const omitted = candidates.filter((path) => !checked.has(path));
    const age = Date.now() - Date.parse(trivyPolicy.bundle.reviewedAt);
    const stale = age < 0 || age > 30 * 24 * 60 * 60 * 1000;
    return {
      findings,
      coverage: [
        coverage(
          "kubernetes",
          degraded || checked.size === 0 ? "degraded" : "checked",
          "Selected frozen check KSV-0017 evaluates recognized Kubernetes configurations. Other built-in findings are outside the reviewed publication policy; scanner warnings or missing selected results reduce coverage.",
        ),
        coverage(
          "check-bundle",
          stale ? "degraded" : "checked",
          `Frozen checks ${trivyPolicy.bundle.version} (${trivyPolicy.bundle.revision}); automatic downloads are disabled. Review date ${trivyPolicy.bundle.reviewedAt}; ${stale ? "review is older than 30 days or the clock is invalid" : "review is within 30 days"}. Upstream freshness was not checked during this scan.`,
        ),
        ...(omitted.length
          ? [
              coverage(
                "unrecognized-infrastructure",
                "degraded",
                `${omitted.length} configuration candidate file(s) lack selected Kubernetes check results. Other IaC formats and unrecognized YAML/JSON are not covered.`,
              ),
            ]
          : []),
      ],
    };
  } catch {
    signal.throwIfAborted();
    return failed();
  }
}
