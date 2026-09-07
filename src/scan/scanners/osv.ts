import { createHash } from "node:crypto";
import { basename, dirname } from "node:path";
import type { SandboxSession } from "../../ports/sandbox-runtime.js";
import type {
  Coverage,
  Dependency,
  Finding,
  Provenance,
  ScanResult,
  Severity,
  Snapshot,
} from "../contracts.js";
import { LIMITS } from "../limits.js";
import { isRecord, isSafeRepositoryPath } from "../manifest.js";
import { osvPolicy } from "../policy.js";
import { readScannerJson, type ScannerContext } from "./shared.js";

const EXPORT = "/work/.vibeshield/exports/osv.json";
const record = (value: unknown): Record<string, unknown> => (isRecord(value) ? value : {});
const text = (value: unknown): string => (typeof value === "string" ? value : "");
const strings = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((x) => typeof x === "string" && x.length > 0);
// npm lockfile extractors emit resolved semver, never package.json constraints.
const installed = (value: unknown): value is string =>
  typeof value === "string" &&
  /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value);
function entry(
  area: string,
  status: Coverage["status"],
  reason: string,
  applicable = true,
): Coverage {
  return { scanner: "osv", area, status, reason, applicable };
}
function inventory(snapshot: Snapshot) {
  const supported = snapshot.files.filter((path) =>
    osvPolicy.lockfiles.some((name) => basename(path) === name),
  );
  const unsupported = snapshot.files
    .filter((path) => {
      if (supported.includes(path)) return false;
      if (basename(path) === "package.json")
        return !supported.some((lock) => dirname(lock) === dirname(path));
      return (
        /(?:\.lockb?|\.lock\.json|\.lock\.ya?ml|\.lockfile|\.locked)$/.test(path) ||
        [
          "requirements.txt",
          "npm-shrinkwrap.json",
          "pom.xml",
          "go.mod",
          "pyproject.toml",
          "packages.config",
          "cabal.project.freeze",
        ].includes(basename(path))
      );
    })
    .map((path) =>
      entry(
        path,
        "skipped",
        "Missing a supported installed-version lockfile, or this dependency format is outside the selected JavaScript lockfile policy.",
      ),
    );
  if (!supported.length && !unsupported.length)
    unsupported.push(
      entry(
        "dependencies",
        "skipped",
        "No supported dependency lockfile was found; dependencies could not be assessed.",
        snapshot.files.some((path) => /\.[cm]?[jt]sx?$/.test(path)),
      ),
    );
  return { supported, unsupported };
}
function severity(value: unknown): Severity {
  const label = text(value).toLowerCase();
  if (label === "moderate") return "medium";
  return ["critical", "high", "medium", "low"].includes(label) ? (label as Severity) : "unknown";
}
function parseEnvelope(value: unknown) {
  const data = record(value);
  if (
    data.scannerVersion !== osvPolicy.version ||
    !Number.isInteger(data.exitCode) ||
    typeof data.diagnostics !== "boolean"
  )
    throw new Error();
  return data;
}
function parseOutput(data: Record<string, unknown>, snapshot: Snapshot): ScanResult {
  const { supported, unsupported } = inventory(snapshot);
  const failure = (reason: string): ScanResult => ({
    findings: [],
    coverage: [...supported.map((path) => entry(path, "failed", reason)), ...unsupported],
  });
  if (![0, 1].includes(Number(data.exitCode))) {
    const reason =
      data.exitCode === 129
        ? "OSV advisory API failed; dependency vulnerabilities could not be checked."
        : data.exitCode === 124
          ? "OSV scan or advisory API timed out."
          : data.exitCode === 128
            ? "OSV found no package inventory in the selected lockfiles."
            : "OSV scanner failed; its output is not a completed dependency check.";
    return failure(reason);
  }
  const output = record(data.output);
  if (!Array.isArray(output.results)) return failure("OSV official JSON export is malformed.");
  const findings: Finding[] = [];
  const checked = new Map<string, boolean>();
  let unrecognized = false;
  for (const item of output.results) {
    const source = record(record(item).source);
    const rawPath = text(source.path);
    const manifest = rawPath.startsWith("/work/snapshot/")
      ? rawPath.slice("/work/snapshot/".length)
      : rawPath;
    const packages = record(item).packages;
    if (
      !isSafeRepositoryPath(manifest) ||
      !supported.includes(manifest) ||
      source.type !== "lockfile" ||
      !Array.isArray(packages) ||
      checked.has(manifest)
    ) {
      unrecognized = true;
      continue;
    }
    let degraded = data.diagnostics === true || packages.length === 0;
    for (const raw of packages) {
      const p = record(raw),
        pkg = record(p.package);
      if (
        pkg.ecosystem !== "npm" ||
        !/^(@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i.test(text(pkg.name)) ||
        !installed(pkg.version) ||
        (p.dependency_groups !== undefined && !strings(p.dependency_groups))
      ) {
        degraded = true;
        continue;
      }
      if (p.vulnerabilities === undefined) continue;
      if (!Array.isArray(p.vulnerabilities)) {
        degraded = true;
        continue;
      }
      for (const item of p.vulnerabilities) {
        const advisory = record(item);
        if (
          !/^[A-Za-z0-9][A-Za-z0-9._-]{1,199}$/.test(text(advisory.id)) ||
          (advisory.aliases !== undefined && !strings(advisory.aliases)) ||
          !Array.isArray(advisory.affected)
        ) {
          degraded = true;
          continue;
        }
        const affected = advisory.affected.filter((item) => {
          const target = record(record(item).package);
          return target.name === pkg.name && target.ecosystem === pkg.ecosystem;
        });
        if (!affected.length) {
          degraded = true;
          continue;
        }
        const fixedVersions: string[] = [];
        let malformed = false;
        for (const item of affected) {
          const ranges = record(item).ranges;
          if (ranges === undefined) continue;
          if (!Array.isArray(ranges)) {
            malformed = true;
            continue;
          }
          for (const range of ranges) {
            const events = record(range).events;
            if (!Array.isArray(events)) {
              malformed = true;
              continue;
            }
            for (const event of events) {
              const fixed = record(event).fixed;
              if (fixed === undefined) continue;
              if (!installed(fixed)) {
                malformed = true;
                continue;
              }
              fixedVersions.push(fixed);
            }
          }
        }
        if (malformed) {
          degraded = true;
          continue;
        }
        const rank = severity(record(advisory.database_specific).severity);
        if (rank === "unknown") degraded = true;
        const groups = p.dependency_groups as string[] | undefined;
        const scope: Dependency["scope"] = groups?.includes("dev")
          ? "development"
          : groups?.some((group) => ["prod", "runtime", "dependencies"].includes(group))
            ? "runtime"
            : "unknown";
        const groupAliases: string[] = [];
        if (p.groups !== undefined) {
          if (!Array.isArray(p.groups)) degraded = true;
          else
            for (const rawGroup of p.groups) {
              const group = record(rawGroup);
              if (!strings(group.ids) || (group.aliases !== undefined && !strings(group.aliases))) {
                degraded = true;
                continue;
              }
              if (group.ids.includes(text(advisory.id)))
                groupAliases.push(...group.ids, ...((group.aliases ?? []) as string[]));
            }
        }
        const dependency: Dependency = {
          name: text(pkg.name),
          ecosystem: "npm",
          version: pkg.version,
          manifest,
          scope,
          advisoryIds: [
            ...new Set([
              text(advisory.id),
              ...((advisory.aliases ?? []) as string[]),
              ...groupAliases,
            ]),
          ].sort(),
          fixedVersions: [...new Set(fixedVersions)].sort(),
        };
        const identity = createHash("sha256")
          .update(JSON.stringify([manifest, pkg.name, pkg.version, advisory.id]))
          .digest("hex");
        findings.push({
          id: `osv:${identity}`,
          scanner: "osv",
          ruleId: text(advisory.id),
          category: "dependency",
          severity: rank,
          confidence: "high",
          title: text(advisory.summary) || `Known vulnerability in ${pkg.name}`,
          evidence: `${pkg.name}@${pkg.version} is recorded in ${manifest} (${scope}); OSV advisory ${dependency.advisoryIds.join(", ")}. Runtime reachability was not assessed.`,
          locations: [{ path: manifest, line: 1 }],
          rootCause: `dependency:${manifest}:${pkg.name}:${pkg.version}`,
          remediationKey: "dependency-upgrade",
          dependency,
        });
      }
    }
    checked.set(manifest, degraded);
  }
  return {
    findings,
    coverage: [
      ...supported.map((path) => {
        const missing = !checked.has(path);
        const degraded =
          missing ||
          checked.get(path) ||
          unrecognized ||
          (data.exitCode === 1 && findings.length === 0);
        return entry(
          path,
          degraded ? "degraded" : "checked",
          missing
            ? "Enumerated supported lockfile was omitted from OSV package inventory; it may be empty, unsupported in this version, or unparsed."
            : degraded
              ? "OSV lockfile coverage is incomplete: diagnostics, unknown advisory severity, or invalid package/advisory evidence."
              : "OSV checked installed package versions from this lockfile; no target execution or reachability analysis.",
        );
      }),
      ...unsupported,
    ],
  };
}
/** Read after scanOsv for report provenance. No source revision is supplied by this API. */
export async function readOsvAdvisoryData(
  session: SandboxSession,
): Promise<Provenance["advisoryData"][number] | undefined> {
  try {
    const data = parseEnvelope(await readScannerJson(session, EXPORT));
    const advisory = record(data.advisoryData);
    if (
      ![0, 1].includes(Number(data.exitCode)) ||
      !Array.isArray(record(data.output).results) ||
      data.diagnostics ||
      advisory.source !== "OSV" ||
      advisory.stale !== false ||
      typeof advisory.retrievedAt !== "string" ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(advisory.retrievedAt) ||
      !Number.isFinite(Date.parse(advisory.retrievedAt))
    )
      return undefined;
    return { source: "OSV", retrievedAt: advisory.retrievedAt, stale: false };
  } catch {
    return undefined;
  }
}
export async function scanOsv({ session, snapshot, signal }: ScannerContext): Promise<ScanResult> {
  const { supported, unsupported } = inventory(snapshot);
  try {
    signal.throwIfAborted();
    if (!supported.length) return { findings: [], coverage: unsupported };
    const status = await session.exec(["node", "/usr/local/bin/vibeshield-osv"], {
      signal,
      timeoutMs: LIMITS.scannerMs,
    });
    if (status.exitCode !== 0) throw new Error();
    signal.throwIfAborted();
    return parseOutput(parseEnvelope(await readScannerJson(session, EXPORT)), snapshot);
  } catch {
    signal.throwIfAborted();
    return {
      findings: [],
      coverage: [
        ...supported.map((path) =>
          entry(path, "failed", "OSV scan timed out, failed, or its bounded export was invalid."),
        ),
        ...unsupported,
      ],
    };
  }
}
