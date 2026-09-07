#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gitEnvironment, readBoundedJson, SERVICE, writeExport } from "./export-results.mjs";

const RULES = "/opt/vibeshield/rules";
const RAW = `${SERVICE}/opengrep-raw.json`;
const object = (value) =>
  value && typeof value === "object" && !Array.isArray(value) ? value : {};
const list = (value, fn) => (Array.isArray(value) ? value.map(fn) : null);
function cleanLocation(value) {
  const physical = object(object(value).physicalLocation);
  const artifact = object(physical.artifactLocation);
  const region = object(physical.region);
  return {
    physicalLocation: {
      artifactLocation: { uri: artifact.uri, uriBaseId: artifact.uriBaseId },
      region: { startLine: region.startLine },
    },
  };
}
// Keep static rule metadata, physical coordinates and warning levels. Target
// snippets, result messages, fingerprints and diagnostics never leave the guest.
export function sanitizeSarif(value) {
  return {
    version: object(value).version,
    runs: list(object(value).runs, (rawRun) => {
      const run = object(rawRun),
        driver = object(object(run.tool).driver);
      return {
        tool: {
          driver: {
            name: driver.name,
            semanticVersion: driver.semanticVersion,
            rules: list(driver.rules, (rawRule) => {
              const rule = object(rawRule),
                properties = object(rule.properties);
              return {
                id: rule.id,
                name: rule.name,
                shortDescription: rule.shortDescription,
                fullDescription: rule.fullDescription,
                help: rule.help,
                defaultConfiguration: rule.defaultConfiguration,
                properties: {
                  "security-severity": properties["security-severity"],
                  precision: properties.precision,
                  tags: properties.tags,
                },
              };
            }),
          },
        },
        invocations: list(run.invocations, (rawInvocation) => {
          const invocation = object(rawInvocation);
          const clean = { executionSuccessful: invocation.executionSuccessful };
          for (const field of ["toolExecutionNotifications", "toolConfigurationNotifications"]) {
            if (invocation[field] !== undefined)
              clean[field] = list(invocation[field], (item) => ({ level: object(item).level }));
          }
          return clean;
        }),
        results: list(run.results, (rawResult) => {
          const result = object(rawResult);
          return {
            ruleId: result.ruleId,
            locations: list(result.locations, cleanLocation),
            codeFlows: list(result.codeFlows, (flow) => ({
              threadFlows: list(object(flow).threadFlows, (thread) => ({
                locations: list(object(thread).locations, (step) => ({
                  location: cleanLocation(object(step).location),
                })),
              })),
            })),
          };
        }),
      };
    }),
  };
}
export function opengrepCommand() {
  return [
    "scan",
    "--disable-nosem",
    "--no-git-ignore",
    "--x-ignore-semgrepignore-files",
    "--no-rewrite-rule-ids",
    "--disable-version-check",
    "--dataflow-traces",
    "--max-target-bytes=5242880",
    "--config",
    `${RULES}/opengrep`,
    "--sarif",
    "--output",
    RAW,
    "/work/snapshot",
  ];
}
export function opengrepEnvironment() {
  return {
    ...gitEnvironment(),
    HOME: "/opt/vibeshield/opengrep-home",
    SEMGREP_SETTINGS_FILE: "/opt/vibeshield/opengrep-settings.yml",
    SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE: "/opt/vibeshield/opengrep.ignore",
  };
}
function verifyRules() {
  const manifest = JSON.parse(readFileSync(`${RULES}/manifest.json`, "utf8"));
  if (
    manifest.upstream !== "https://gitlab.com/gitlab-org/security-products/sast-rules" ||
    manifest.revision !== "7051ea7602a210dfb0793916afedc9a0555addb7" ||
    manifest.rules.length !== 6
  )
    throw new Error();
  const actual = readdirSync(`${RULES}/opengrep`, { recursive: true }).filter((path) =>
    /\.ya?ml$/.test(path),
  );
  if (actual.length !== manifest.rules.length) throw new Error();
  for (const rule of manifest.rules) {
    if (
      !/^opengrep\/[a-z]+\/rule-[a-z_]+\.yml$/.test(rule.path) ||
      !actual.includes(rule.path.slice("opengrep/".length))
    )
      throw new Error();
    const path = join(RULES, rule.path);
    if (
      !lstatSync(path).isFile() ||
      realpathSync(path) !== path ||
      createHash("sha256").update(readFileSync(path)).digest("hex") !== rule.sha256
    )
      throw new Error();
  }
}
function main() {
  verifyRules();
  const version = spawnSync("/usr/local/bin/opengrep", ["--version"], {
    cwd: SERVICE,
    env: opengrepEnvironment(),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 10_000,
  });
  if (version.status !== 0 || version.stdout.trim() !== "1.25.0") throw new Error();
  const child = spawnSync("/usr/local/bin/opengrep", opengrepCommand(), {
    cwd: SERVICE,
    env: opengrepEnvironment(),
    stdio: "ignore",
    timeout: 115_000,
  });
  if (child.error || child.signal || child.status !== 0) throw new Error();
  writeExport(`${SERVICE}/exports/opengrep.json`, sanitizeSarif(readBoundedJson(RAW)));
}
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch {
    process.stderr.write("Code scan export failed\n");
    process.exitCode = 1;
  }
}
