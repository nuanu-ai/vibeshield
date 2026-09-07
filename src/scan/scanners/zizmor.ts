import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { Coverage, Finding, ScanResult } from "../contracts.js";
import { LIMITS } from "../limits.js";
import { isRecord, isSafeRepositoryPath } from "../manifest.js";
import { zizmorPolicy } from "../policy.js";
import { readScannerJson, type ScannerContext } from "./shared.js";

const object = (value: unknown): Record<string, unknown> => (isRecord(value) ? value : {});
const text = (value: unknown): string => (typeof value === "string" ? value : "");
const workflow = (path: string): boolean => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(path);
function coverage(
  area: string,
  status: Coverage["status"],
  reason: string,
  applicable = true,
): Coverage {
  return { scanner: "zizmor", area, status, reason, applicable };
}
function failed(): ScanResult {
  return {
    findings: [],
    coverage: [
      coverage(
        "workflows",
        "failed",
        "Workflow scan failed: invalid YAML, engine failure, or invalid bounded export or selected audit metadata.",
      ),
    ],
  };
}
export async function scanZizmor({
  session,
  snapshot,
  signal,
}: ScannerContext): Promise<ScanResult> {
  try {
    signal.throwIfAborted();
    const files = snapshot.files.filter(workflow).sort();
    if (files.length === 0)
      return {
        findings: [],
        coverage: [
          coverage("workflows", "skipped", "No GitHub Actions workflow files are present.", false),
        ],
      };
    const status = await session.exec(["node", "/usr/local/bin/vibeshield-zizmor"], {
      signal,
      timeoutMs: LIMITS.scannerMs,
    });
    signal.throwIfAborted();
    if (status.exitCode !== 0) return failed();
    const value = object(await readScannerJson(session, "/work/.vibeshield/exports/zizmor.json"));
    signal.throwIfAborted();
    if (
      value.version !== zizmorPolicy.version ||
      value.offline !== true ||
      typeof value.warnings !== "boolean" ||
      !isDeepStrictEqual(
        value.selectedAudits,
        zizmorPolicy.audits.map((a) => a.id),
      ) ||
      !Array.isArray(value.files) ||
      !isDeepStrictEqual([...value.files].sort(), files) ||
      !Array.isArray(value.findings)
    )
      return failed();
    const findings: Finding[] = [];
    for (const raw of value.findings) {
      const item = object(raw);
      const determinations = object(item.determinations);
      // Validate every emitted record before policy filtering. A malformed
      // unselected record cannot turn into successful empty workflow coverage.
      if (
        typeof item.ident !== "string" ||
        !/^[a-z][a-z0-9-]{0,127}$/.test(item.ident) ||
        !["Informational", "Low", "Medium", "High"].includes(text(determinations.severity)) ||
        !["Low", "Medium", "High"].includes(text(determinations.confidence)) ||
        !Array.isArray(item.locations) ||
        item.locations.length === 0 ||
        item.url !== `https://docs.zizmor.sh/audits/#${item.ident}`
      )
        return failed();
      const locations = [];
      for (const rawLocation of item.locations) {
        const loc = object(rawLocation);
        const absolute = text(loc.path);
        if (!absolute.startsWith("/work/snapshot/")) return failed();
        const path = absolute.slice("/work/snapshot/".length);
        const { row, endRow } = loc;
        if (
          !isSafeRepositoryPath(path) ||
          !files.includes(path) ||
          typeof row !== "number" ||
          !Number.isSafeInteger(row) ||
          row < 0 ||
          row >= Number.MAX_SAFE_INTEGER ||
          typeof endRow !== "number" ||
          !Number.isSafeInteger(endRow) ||
          endRow < row
        )
          return failed();
        locations.push({ path, line: row + 1 });
      }
      const rule = zizmorPolicy.audits.find((rule) => rule.id === item.ident);
      if (!rule) continue;
      const severity = text(determinations.severity).toLowerCase();
      const confidence = text(determinations.confidence).toLowerCase();
      const identity = createHash("sha256")
        .update(JSON.stringify([rule.id, locations]))
        .digest("hex");
      findings.push({
        id: `zizmor:${rule.id}:${identity}`,
        scanner: "zizmor",
        ruleId: rule.id,
        category: "workflow",
        severity:
          severity === "high" || severity === "medium" || severity === "low" ? severity : "unknown",
        confidence:
          confidence === "high" || confidence === "medium" || confidence === "low"
            ? confidence
            : "unknown",
        title: "Workflow input is expanded into executable code",
        evidence: `zizmor ${rule.id} identified template expansion into a code execution sink at ${locations.map((l) => `${l.path}:${l.line}`).join(", ")}. Reference: ${item.url}`,
        locations,
        rootCause: `zizmor:${rule.id}:${identity}`,
        remediationKey: rule.remediationKey,
      });
    }
    return {
      findings,
      coverage: [
        coverage(
          "workflows",
          value.warnings ? "degraded" : "checked",
          `Selected offline audits: ${zizmorPolicy.audits.map((a) => a.id).join(", ")}; ${files.length} workflow file(s) parsed successfully. Repository configuration and ignore annotations cannot suppress these checks. Engine warnings reduce coverage.`,
        ),
        coverage(
          "online-audits",
          "skipped",
          "Offline scan: impostor-commit, ref-confusion, stale-action-refs, ref-version-mismatch, and known-vulnerable-actions require network access and were not run.",
        ),
        coverage(
          "untrusted-checkout",
          "skipped",
          "The pinned dangerous-triggers audit establishes a trigger, not an untrusted checkout and execution with privileges. Those combinations are not covered; generic trigger, permission, and pinning advice is not published.",
        ),
      ],
    };
  } catch {
    signal.throwIfAborted();
    return failed();
  }
}
