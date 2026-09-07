#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { basename, dirname, matchesGlob } from "node:path";
import { fileURLToPath } from "node:url";
import {
  gitEnvironment,
  readBoundedJson,
  readBoundedText,
  SERVICE,
  safePath,
  writeExport,
} from "./export-results.mjs";

const RAW = `${SERVICE}/osv-raw.json`;
const object = (value) =>
  value && typeof value === "object" && !Array.isArray(value) ? value : {};
const list = (value, fn) => (Array.isArray(value) ? value.map(fn) : null);
// Conservative pnpm packages block-list subset. Ambiguous/unsupported YAML
// remains missing-lockfile coverage; no generic YAML execution or resolution.
function pnpmPatterns(value) {
  if (typeof value !== "string" || value.includes("\t")) return [];
  const lines = value.split(/\r?\n/);
  if (lines.filter((line) => /^packages\s*:/.test(line)).length !== 1) return [];
  const start = lines.findIndex((line) => /^packages:(?: +#.*| *)$/.test(line));
  if (start < 0) return [];
  // Only this standalone block is interpreted. Other YAML structure (including
  // quoted duplicate keys, anchors, and multiple documents) stays uncovered.
  if (lines.slice(0, start).some((line) => !/^\s*(?:#.*)?$/.test(line))) return [];
  const patterns = [];
  let indent;
  for (const line of lines.slice(start + 1)) {
    if (/^\s*(?:#.*)?$/.test(line)) continue;
    if (/^\S/.test(line)) return [];
    // Plain values are a narrow string-only subset, not YAML aliases, tags,
    // numbers or implicit booleans/null. A leading wildcard must be quoted.
    const match =
      /^( +)- +(?:'([^']*)'|"([^"\\]*)"|([A-Za-z_][A-Za-z0-9_./*-]*))(?: +#.*| *)$/.exec(line);
    if (!match || (indent !== undefined && match[1].length !== indent)) return [];
    indent = match[1].length;
    if (match[4] !== undefined && /^(?:null|true|false|yes|no|on|off|y|n)$/i.test(match[4]))
      return [];
    // Quoted whitespace is part of the value; never reinterpret another path.
    patterns.push(match[2] ?? match[3] ?? match[4]);
  }
  return patterns;
}
function validPattern(value) {
  if (typeof value !== "string" || value.length > 4096) return false;
  const pattern = value.startsWith("!") ? value.slice(1) : value;
  return (
    safePath(pattern) &&
    pattern
      .split("/")
      .every((part) => part === "*" || part === "**" || /^[A-Za-z0-9@_.-]+$/.test(part))
  );
}
export function workspaceMembers(files, configs) {
  if (!Array.isArray(files) || files.length > 50000 || !files.every(safePath)) throw new Error();
  const result = [];
  for (const lockfile of files.filter((path) =>
    ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"].includes(basename(path)),
  )) {
    const root = dirname(lockfile);
    const prefix = root === "." ? "" : `${root}/`;
    if (!files.includes(`${prefix}package.json`)) continue;
    const declaration = object(configs[`${prefix}package.json`]).workspaces;
    const patterns =
      basename(lockfile) === "pnpm-lock.yaml"
        ? files.includes(`${prefix}pnpm-workspace.yaml`)
          ? pnpmPatterns(configs[`${prefix}pnpm-workspace.yaml`])
          : []
        : Array.isArray(declaration)
          ? declaration
          : object(declaration).packages;
    if (
      !Array.isArray(patterns) ||
      !patterns.length ||
      patterns.length > 1000 ||
      !patterns.every(validPattern)
    )
      continue;
    for (const manifest of files) {
      if (basename(manifest) !== "package.json" || !manifest.startsWith(prefix)) continue;
      const relative = dirname(manifest.slice(prefix.length));
      if (relative === ".") continue;
      if (
        patterns.some((pattern) => !pattern.startsWith("!") && matchesGlob(relative, pattern)) &&
        !patterns.some(
          (pattern) => pattern.startsWith("!") && matchesGlob(relative, pattern.slice(1)),
        )
      )
        result.push({ manifest, lockfile });
    }
  }
  return result;
}
function snapshotWorkspaces() {
  const files = object(object(readBoundedJson(`${SERVICE}/exports/snapshot.json`)).snapshot).files;
  if (!Array.isArray(files) || files.length > 50000 || !files.every(safePath)) throw new Error();
  const configs = Object.create(null);
  const roots = new Set(
    files
      .filter((path) =>
        ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"].includes(basename(path)),
      )
      .map(dirname),
  );
  for (const path of files) {
    if (
      !roots.has(dirname(path)) ||
      !["package.json", "pnpm-workspace.yaml"].includes(basename(path))
    )
      continue;
    try {
      configs[path] =
        basename(path) === "package.json"
          ? readBoundedJson(`/work/snapshot/${path}`)
          : readBoundedText(`/work/snapshot/${path}`);
    } catch {
      /* Unreadable declarations cannot establish membership. */
    }
  }
  return workspaceMembers(files, configs);
}
// Official schema narrowed to package/advisory facts. Raw diagnostics and
// repository content never leave the guest.
export function sanitizeOsv(value) {
  return {
    results: list(object(value).results, (raw) => {
      const item = object(raw),
        source = object(item.source);
      return {
        source: { path: source.path, type: source.type },
        packages: list(item.packages, (raw) => {
          const item = object(raw),
            pkg = object(item.package);
          return {
            package: { name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem },
            ...(item.groups === undefined
              ? {}
              : {
                  groups: list(item.groups, (raw) => {
                    const group = object(raw);
                    return { ids: group.ids, aliases: group.aliases };
                  }),
                }),
            ...(item.dependency_groups === undefined
              ? {}
              : { dependency_groups: item.dependency_groups }),
            ...(item.vulnerabilities === undefined
              ? {}
              : {
                  vulnerabilities: list(item.vulnerabilities, (raw) => {
                    const advisory = object(raw);
                    return {
                      id: advisory.id,
                      aliases: advisory.aliases,
                      summary: advisory.summary,
                      database_specific: { severity: object(advisory.database_specific).severity },
                      affected: list(advisory.affected, (raw) => {
                        const affected = object(raw),
                          pkg = object(affected.package);
                        return {
                          package: { name: pkg.name, ecosystem: pkg.ecosystem },
                          ...(affected.ranges === undefined
                            ? {}
                            : {
                                ranges: list(affected.ranges, (raw) => {
                                  const range = object(raw);
                                  return {
                                    type: range.type,
                                    events: list(range.events, (raw) => ({
                                      fixed: object(raw).fixed,
                                    })),
                                  };
                                }),
                              }),
                        };
                      }),
                    };
                  }),
                }),
          };
        }),
      };
    }),
  };
}
export function osvCommand() {
  return [
    "scan",
    "source",
    "--recursive",
    "--no-ignore",
    "--config=/opt/vibeshield/osv.toml",
    "--no-call-analysis=all",
    "--no-resolve",
    "--experimental-no-default-plugins",
    "--experimental-plugins=javascript/packagelockjson,javascript/pnpmlock,javascript/yarnlock,javascript/bunlock",
    "--all-packages",
    "--all-vulns",
    "--verbosity=warn",
    "--format=json",
    `--output-file=${RAW}`,
    "/work/snapshot",
  ];
}
function main() {
  const version = spawnSync("/usr/local/bin/osv-scanner", ["--version"], {
    cwd: SERVICE,
    env: gitEnvironment(),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 10000,
    maxBuffer: 65536,
  });
  if (version.status !== 0 || version.stdout.split("\n")[0] !== "osv-scanner version: 2.3.8")
    throw new Error();
  const child = spawnSync("/usr/local/bin/osv-scanner", osvCommand(), {
    cwd: SERVICE,
    env: gitEnvironment(),
    stdio: ["ignore", "ignore", "pipe"],
    timeout: 110000,
    maxBuffer: 65536,
  });
  const exitCode =
    child.error?.code === "ETIMEDOUT" ? 124 : child.error || child.signal ? 127 : child.status;
  // Exit 1 takes precedence over logged parse errors in this pinned release.
  // Preserve diagnostic presence, never its bytes, including the findings branch.
  const diagnostics = Boolean(child.stderr?.length);
  const output = [0, 1].includes(exitCode) ? sanitizeOsv(readBoundedJson(RAW)) : null;
  writeExport(`${SERVICE}/exports/osv.json`, {
    scannerVersion: "2.3.8",
    exitCode,
    diagnostics,
    output,
    workspaceMembers: snapshotWorkspaces(),
    ...([0, 1].includes(exitCode) && !diagnostics
      ? { advisoryData: { source: "OSV", retrievedAt: new Date().toISOString(), stale: false } }
      : {}),
  });
}
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch {
    process.stderr.write("Dependency scan export failed\n");
    process.exitCode = 1;
  }
}
