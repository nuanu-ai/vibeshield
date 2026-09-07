#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { closeSync, lstatSync, openSync, realpathSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import {
  gitEnvironment,
  readBoundedJson,
  readBoundedText,
  SERVICE,
  safePath,
  writeExport,
} from "./export-results.mjs";

// Exact v1.30.0 registry. An engine upgrade requires review of newly added audits.
const audits = [
  "artipacked",
  "unsound-contains",
  "unsound-ternary",
  "excessive-permissions",
  "dangerous-triggers",
  "impostor-commit",
  "ref-confusion",
  "use-trusted-publishing",
  "template-injection",
  "hardcoded-container-credentials",
  "self-hosted-runner",
  "known-vulnerable-actions",
  "unpinned-uses",
  "undocumented-permissions",
  "insecure-commands",
  "github-env",
  "cache-poisoning",
  "secrets-inherit",
  "bot-conditions",
  "overprovisioned-secrets",
  "unredacted-secrets",
  "forbidden-uses",
  "obfuscation",
  "stale-action-refs",
  "unpinned-images",
  "anonymous-definition",
  "unsound-condition",
  "ref-version-mismatch",
  "dependabot-execution",
  "dependabot-cooldown",
  "concurrency-limits",
  "archived-uses",
  "typosquat-uses",
  "misfeature",
  "secrets-outside-env",
  "superfluous-actions",
  "github-app",
  "unpinned-tools",
  "adhoc-packages",
  "insecure-url-scheme",
  "self-repository",
];
const selectedAudits = ["template-injection"];
const CONFIG = "/opt/vibeshield/zizmor.json";
const RAW = `${SERVICE}/zizmor-raw.json`;
const object = (value) =>
  value && typeof value === "object" && !Array.isArray(value) ? value : {};
export function zizmorConfig() {
  return {
    rules: Object.fromEntries(audits.map((id) => [id, { disable: !selectedAudits.includes(id) }])),
  };
}
export function sanitizeZizmor(value) {
  if (!Array.isArray(value)) throw new Error();
  return value.map((raw) => {
    const item = object(raw);
    if (!Array.isArray(item.locations)) throw new Error();
    return {
      ident: item.ident,
      url: item.url,
      determinations: {
        severity: object(item.determinations).severity,
        confidence: object(item.determinations).confidence,
      },
      locations: item.locations
        .filter((loc) => object(object(loc).symbolic).kind === "Primary")
        .map((raw) => {
          const loc = object(raw);
          const concrete = object(object(loc.concrete).location);
          return {
            path: object(object(object(loc.symbolic).key).Local).verbatim_path,
            row: object(concrete.start_point).row,
            endRow: object(concrete.end_point).row,
          };
        }),
    };
  });
}
export function zizmorCommand(files) {
  return [
    "--offline",
    "--format=json-v1",
    `--config=${CONFIG}`,
    "--no-ignores",
    "--strict-collection",
    "--no-exit-codes",
    "--no-progress",
    "--color=never",
    `--cache-dir=${SERVICE}/zizmor-cache`,
    "--",
    ...files.map((path) => `/work/snapshot/${path}`),
  ];
}
function main() {
  if (process.argv[2] === "install-config") {
    writeFileSync(CONFIG, JSON.stringify(zizmorConfig()), { flag: "wx", mode: 0o644 });
    return;
  }
  if (!isDeepStrictEqual(readBoundedJson(CONFIG), zizmorConfig())) throw new Error();
  const version = spawnSync("/usr/local/bin/zizmor", ["--version"], {
    cwd: SERVICE,
    env: gitEnvironment(),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 10_000,
    maxBuffer: 65536,
  });
  if (version.status !== 0 || version.stdout.trim() !== "zizmor 1.30.0") throw new Error();
  const snapshot = readBoundedJson(`${SERVICE}/exports/snapshot.json`).snapshot;
  if (!Array.isArray(snapshot?.files)) throw new Error();
  const files = snapshot.files
    .filter((path) => typeof path === "string" && /^\.github\/workflows\/[^/]+\.ya?ml$/.test(path))
    .sort();
  if (files.length === 0 || new Set(files).size !== files.length) throw new Error();
  for (const path of files) {
    const absolute = `/work/snapshot/${path}`;
    if (!safePath(path) || realpathSync(absolute) !== absolute || !lstatSync(absolute).isFile())
      throw new Error();
  }
  // zizmor has no output-file option: connect stdout directly to an owned file.
  // Neither process output nor source snippets are exported over the runtime API.
  const raw = openSync(RAW, "wx", 0o600);
  const logPath = `${SERVICE}/zizmor-log.txt`;
  let log;
  let child;
  try {
    log = openSync(logPath, "wx", 0o600);
    child = spawnSync("/usr/local/bin/zizmor", zizmorCommand(files), {
      cwd: SERVICE,
      env: gitEnvironment(),
      stdio: ["ignore", raw, log],
      timeout: 115_000,
    });
  } finally {
    closeSync(raw);
    if (log !== undefined) closeSync(log);
  }
  if (child.error || child.signal || child.status !== 0) throw new Error();
  const diagnostics = readBoundedText(logPath);
  writeExport(`${SERVICE}/exports/zizmor.json`, {
    version: "1.30.0",
    offline: true,
    selectedAudits,
    files,
    warnings: /\b(?:WARN|ERROR)\b/.test(diagnostics),
    findings: sanitizeZizmor(readBoundedJson(RAW)),
  });
}
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch {
    process.stderr.write("Workflow export failed\n");
    process.exitCode = 1;
  }
}
