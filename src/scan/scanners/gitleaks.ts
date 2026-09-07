import { isDeepStrictEqual } from "node:util";
import type { Finding, Location, ScanResult } from "../contracts.js";
import { LIMITS } from "../limits.js";
import { isRecord, isSafeRepositoryPath, validateAcquisition } from "../manifest.js";
import { readScannerJson, type ScannerContext } from "./shared.js";

export async function scanGitleaks({
  session,
  snapshot,
  signal,
}: ScannerContext): Promise<ScanResult> {
  const result: ScanResult = { findings: [], coverage: [] };
  const findings = new Map<string, Finding>();
  for (const mode of ["current", "history"] as const) {
    try {
      signal.throwIfAborted();
      const metadata = validateAcquisition(
        await readScannerJson(session, "/work/.vibeshield/exports/snapshot.json"),
      );
      if (!isDeepStrictEqual(metadata.snapshot, snapshot)) throw new Error();
      const status = await session.exec(
        ["node", "/usr/local/bin/vibeshield-export-results", "gitleaks", mode],
        { signal, timeoutMs: LIMITS.scannerMs },
      );
      if (status.exitCode !== 0) throw new Error();
      signal.throwIfAborted();
      const records = await readScannerJson(
        session,
        `/work/.vibeshield/exports/gitleaks-${mode}.json`,
      );
      if (!Array.isArray(records)) throw new Error();
      const accepted: { id: string; ruleId: string; location: Location }[] = [];
      for (const record of records) {
        if (
          !isRecord(record) ||
          Object.keys(record).some(
            (key) => !["ruleId", "path", "line", "commit", "fingerprint"].includes(key),
          ) ||
          typeof record.ruleId !== "string" ||
          !/^[a-z0-9][a-z0-9-]{0,127}$/.test(record.ruleId) ||
          !isSafeRepositoryPath(record.path) ||
          typeof record.line !== "number" ||
          !Number.isSafeInteger(record.line) ||
          record.line < 1 ||
          typeof record.fingerprint !== "string" ||
          !/^[a-f0-9]{64}$/.test(record.fingerprint)
        )
          throw new Error();
        const location: Location = { path: record.path, line: record.line };
        if (mode === "current") {
          if (!snapshot.files.includes(record.path) || record.commit !== undefined)
            throw new Error();
        } else {
          if (typeof record.commit !== "string" || !metadata.fetchedCommits.includes(record.commit))
            throw new Error();
          location.commit = record.commit;
        }
        accepted.push({
          id: `${record.ruleId}:${record.fingerprint}`,
          ruleId: record.ruleId,
          location,
        });
      }
      for (const { id, ruleId, location } of accepted) {
        let finding = findings.get(id);
        if (!finding) {
          finding = {
            id: `gitleaks:${id}`,
            scanner: "gitleaks",
            ruleId,
            category: "secret",
            severity: "high",
            confidence: "high",
            title: "Exposed credential",
            evidence: "A credential pattern was detected; secret and matching text are redacted.",
            locations: [],
            rootCause: "credential-exposure",
            remediationKey: "secret-rotation",
          };
          findings.set(id, finding);
        }
        if (
          !finding.locations.some(
            (item) =>
              item.path === location.path &&
              item.line === location.line &&
              item.commit === location.commit,
          )
        )
          finding.locations.push(location);
      }
      const truncated = mode === "history" && snapshot.history.truncated;
      result.coverage.push({
        scanner: "gitleaks",
        area: mode,
        status: truncated ? "degraded" : "checked",
        applicable: true,
        reason:
          mode === "history"
            ? `Scanned ${snapshot.history.commits} fetched commits${truncated ? "; older history was not fetched" : ""}.`
            : "Scanned the regular files in the current snapshot.",
      });
    } catch {
      signal.throwIfAborted();
      result.coverage.push({
        scanner: "gitleaks",
        area: mode,
        status: "failed",
        applicable: true,
        reason: "Secret scan failed or its export was invalid.",
      });
    }
  }
  result.findings = [...findings.values()];
  return result;
}
