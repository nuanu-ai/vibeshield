import { createHash } from "node:crypto";
import type { Coverage, Finding, Location, ScanResult, Severity, Snapshot } from "../contracts.js";
import { LIMITS } from "../limits.js";
import { isRecord, isSafeRepositoryPath } from "../manifest.js";
import { opengrepRules } from "../policy.js";
import { MAX_EXPORT_BYTES, readScannerJson, type ScannerContext } from "./shared.js";

function coverage(status: Coverage["status"]): Coverage {
  return {
    scanner: "opengrep",
    area: "javascript-typescript",
    status,
    applicable: status !== "skipped",
    reason:
      status === "checked"
        ? "Selected published JavaScript/TypeScript rules scanned the snapshot; tested source and sink shapes only, with no cross-file guarantee."
        : status === "degraded"
          ? "Selected code scan lost coverage: scanner warnings, unsupported results, or missing current locations/flow evidence."
          : status === "skipped"
            ? "No JavaScript/TypeScript source paths recognized by acquisition are present; selected code rules are not applicable."
            : "Code scan failed or its bounded SARIF export was invalid.",
  };
}
function applicable(snapshot: Snapshot): boolean {
  // Match the source extensions classified by acquisition, not a repository's
  // config or an aggregate language label without a corresponding source path.
  return snapshot.files.some((path) => /\.(?:js|jsx|mjs|ts|tsx)$/.test(path));
}
function skipped(): ScanResult {
  return { findings: [], coverage: [coverage("skipped")] };
}
function failed(): ScanResult {
  return { findings: [], coverage: [coverage("failed")] };
}
const record = (value: unknown): Record<string, unknown> => (isRecord(value) ? value : {});
const text = (value: unknown): string => (typeof value === "string" ? value : "");
function location(value: unknown, snapshot: Snapshot): Location | undefined {
  const physical = record(record(value).physicalLocation);
  const uri = text(record(physical.artifactLocation).uri);
  const path = uri.startsWith("/work/snapshot/") ? uri.slice("/work/snapshot/".length) : uri;
  const line = record(physical.region).startLine;
  if (
    !isSafeRepositoryPath(path) ||
    !snapshot.files.includes(path) ||
    typeof line !== "number" ||
    !Number.isSafeInteger(line) ||
    line < 1
  )
    return undefined;
  return { path, line };
}
function securitySeverity(value: unknown): Severity {
  const label = text(value).toLowerCase();
  if (["critical", "high", "medium", "low"].includes(label)) return label as Severity;
  if (!/^\d+(?:\.\d+)?$/.test(label)) return "unknown";
  const score = Number(label);
  if (score < 0 || score > 10) return "unknown";
  return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
}
export function parseOpengrepSarif(value: unknown, snapshot: Snapshot): ScanResult {
  if (!applicable(snapshot)) return skipped();
  try {
    const document = record(value);
    if (document.version !== "2.1.0" || !Array.isArray(document.runs) || document.runs.length !== 1)
      return failed();
    const run = record(document.runs[0]);
    const driver = record(record(run.tool).driver);
    if (
      driver.semanticVersion !== "1.25.0" ||
      !Array.isArray(driver.rules) ||
      !Array.isArray(run.results) ||
      !Array.isArray(run.invocations) ||
      run.invocations.length === 0
    )
      return failed();
    let degraded = false;
    for (const item of run.invocations) {
      const invocation = record(item);
      if (invocation.executionSuccessful !== true) return failed();
      for (const key of ["toolExecutionNotifications", "toolConfigurationNotifications"]) {
        if (invocation[key] === undefined) continue;
        if (!Array.isArray(invocation[key])) return failed();
        if (
          invocation[key].some(
            (item: unknown) => !["note", "none"].includes(text(record(item).level)),
          )
        )
          degraded = true;
      }
    }
    const definitions = new Map<string, Record<string, unknown>>();
    for (const item of driver.rules) {
      const rule = record(item);
      if (
        !opengrepRules.some((selected) => selected.id === rule.id) ||
        definitions.has(text(rule.id))
      )
        return failed();
      definitions.set(text(rule.id), rule);
    }
    if (definitions.size !== opengrepRules.length) return failed();
    const findings: Finding[] = [];
    for (const item of run.results) {
      const result = record(item);
      const selected = opengrepRules.find((rule) => rule.id === result.ruleId);
      const rule = definitions.get(text(result.ruleId));
      if (!selected || !rule) {
        degraded = true;
        continue;
      }
      const rawLocations = Array.isArray(result.locations) ? result.locations : [];
      const locations = rawLocations.map((item) => location(item, snapshot));
      if (locations.length === 0 || locations.some((item) => !item)) {
        degraded = true;
        continue;
      }
      const current = locations as Location[];
      const flows: Location[][] = [];
      if (selected.mode === "taint") {
        if (Array.isArray(result.codeFlows)) {
          for (const rawFlow of result.codeFlows) {
            const threads = record(rawFlow).threadFlows;
            if (!Array.isArray(threads)) {
              degraded = true;
              continue;
            }
            for (const thread of threads) {
              const steps = record(thread).locations;
              if (!Array.isArray(steps)) {
                degraded = true;
                continue;
              }
              const path = steps.map((step) => location(record(step).location, snapshot));
              const sink = path.at(-1);
              if (
                path.length < 2 ||
                path.some((item) => !item) ||
                !sink ||
                !current.some((item) => item.path === sink.path && item.line === sink.line)
              ) {
                degraded = true;
                continue;
              }
              flows.push(path as Location[]);
            }
          }
        }
        if (flows.length === 0) degraded = true;
      }
      const properties = record(rule.properties);
      const metadata = {
        name: text(rule.name) || selected.id,
        description: text(record(rule.fullDescription).text),
        help: text(record(rule.help).markdown) || text(record(rule.help).text),
        tags: Array.isArray(properties.tags)
          ? properties.tags.filter((tag): tag is string => typeof tag === "string")
          : [],
        precision: text(properties.precision),
        defaultLevel: text(record(rule.defaultConfiguration).level),
        securitySeverity: text(properties["security-severity"]),
      };
      const identity = createHash("sha256")
        .update(JSON.stringify([selected.id, current]))
        .digest("hex");
      findings.push({
        id: `opengrep:${selected.id}:${identity}`,
        scanner: "opengrep",
        ruleId: selected.id,
        category: "code",
        severity: securitySeverity(properties["security-severity"]),
        confidence: selected.mode === "search" ? "medium" : flows.length > 0 ? "high" : "unknown",
        title: text(record(rule.shortDescription).text) || selected.id,
        evidence:
          flows.length > 0
            ? flows
                .map(
                  (path) => `flow: ${path.map((item) => `${item.path}:${item.line}`).join(" -> ")}`,
                )
                .join("; ")
            : `${selected.mode === "search" ? "Contextual pattern" : "Taint result without a validated path"}: ${current.map((item) => `${item.path}:${item.line}`).join(", ")}.`,
        locations: current,
        rootCause: `opengrep:${selected.id}:${current[0]?.path}:${current[0]?.line}`,
        remediationKey: selected.remediationKey,
        code: { mode: selected.mode, flows, rule: metadata },
      });
    }
    return { findings, coverage: [coverage(degraded ? "degraded" : "checked")] };
  } catch {
    return failed();
  }
}
export async function scanOpengrep({
  session,
  snapshot,
  signal,
}: ScannerContext): Promise<ScanResult> {
  try {
    signal.throwIfAborted();
    if (!applicable(snapshot)) return skipped();
    const result = await session.exec(["node", "/usr/local/bin/vibeshield-opengrep"], {
      signal,
      timeoutMs: LIMITS.scannerMs,
      maxFileBytes: MAX_EXPORT_BYTES,
    });
    if (result.exitCode !== 0) return failed();
    signal.throwIfAborted();
    return parseOpengrepSarif(
      await readScannerJson(session, "/work/.vibeshield/exports/opengrep.json"),
      snapshot,
    );
  } catch {
    signal.throwIfAborted();
    return failed();
  }
}
