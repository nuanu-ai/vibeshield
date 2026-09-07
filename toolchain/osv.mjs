#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gitEnvironment, readBoundedJson, SERVICE, writeExport } from "./export-results.mjs";

const RAW = `${SERVICE}/osv-raw.json`;
const object = (value) =>
  value && typeof value === "object" && !Array.isArray(value) ? value : {};
const list = (value, fn) => (Array.isArray(value) ? value.map(fn) : null);
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
