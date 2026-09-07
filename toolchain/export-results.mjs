#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const MAX_EXPORT_BYTES = 8 * 1024 * 1024;
export const SERVICE = "/work/.vibeshield";
export const ignored = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  "out",
  "target",
  "vendor",
  ".venv",
  "venv",
  "__pycache__",
  ".cache",
  "coverage",
  "logs",
]);
export function safePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 4096 &&
    // biome-ignore lint/suspicious/noControlCharactersInRegex: Reject control bytes in untrusted paths.
    !/[\\:\x00-\x1f\x7f]/.test(value) &&
    value.split("/").every((part) => part && part !== "." && part !== ".." && !ignored.has(part))
  );
}
// Build from scratch: no proxy, credential, Git config, loader, or scanner overrides.
export function gitEnvironment() {
  const env = {
    PATH: "/usr/local/bin:/usr/bin:/bin",
    HOME: "/nonexistent",
    TMPDIR: `${SERVICE}/tmp`,
    LANG: "C.UTF-8",
    GIT_TERMINAL_PROMPT: "0",
    GIT_LFS_SKIP_SMUDGE: "1",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_ATTR_NOSYSTEM: "1",
  };
  const config = {
    "core.hooksPath": "/dev/null",
    "credential.helper": "",
    "protocol.allow": "never",
    "protocol.https.allow": "always",
    "http.followRedirects": "false",
    "core.attributesFile": "/dev/null",
    "core.pager": "cat",
    "core.fsmonitor": "false",
    "diff.external": "",
    "submodule.recurse": "false",
  };
  env.GIT_CONFIG_COUNT = String(Object.keys(config).length);
  Object.entries(config).forEach(([key, value], i) => {
    env[`GIT_CONFIG_KEY_${i}`] = key;
    env[`GIT_CONFIG_VALUE_${i}`] = value;
  });
  return env;
}
export function readBoundedJson(path) {
  let fd;
  try {
    if (resolve(path) !== path || realpathSync(dirname(path)) !== dirname(path)) throw new Error();
    const parent = lstatSync(dirname(path));
    if (!parent.isDirectory() || parent.uid !== process.getuid() || parent.mode & 0o022)
      throw new Error();
    const stat = lstatSync(path);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.uid !== process.getuid() ||
      stat.mode & 0o022 ||
      stat.size < 1 ||
      stat.size > MAX_EXPORT_BYTES
    )
      throw new Error();
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (
      !opened.isFile() ||
      opened.ino !== stat.ino ||
      opened.dev !== stat.dev ||
      opened.size > MAX_EXPORT_BYTES
    )
      throw new Error();
    const bytes = readFileSync(fd);
    if (bytes.length > MAX_EXPORT_BYTES) throw new Error();
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("Invalid scanner export");
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
export function writeExport(path, value) {
  const bytes = Buffer.from(JSON.stringify(value));
  if (bytes.length > MAX_EXPORT_BYTES) throw new Error("Invalid scanner export");
  writeFileSync(path, bytes, { mode: 0o600, flag: "wx" });
}
export function sanitizeGitleaks(value, metadata, mode) {
  if (!Array.isArray(value) || !["current", "history"].includes(mode))
    throw new Error("Invalid scanner export");
  const result = [];
  for (const item of value) {
    if (
      !item ||
      typeof item !== "object" ||
      typeof item.RuleID !== "string" ||
      !/^[a-z0-9][a-z0-9-]{0,127}$/.test(item.RuleID) ||
      !Number.isSafeInteger(item.StartLine) ||
      item.StartLine < 1 ||
      typeof item.File !== "string"
    )
      throw new Error("Invalid scanner export");
    const path =
      mode === "current" && item.File.startsWith("/work/snapshot/")
        ? item.File.slice("/work/snapshot/".length)
        : item.File;
    if (!safePath(path)) {
      // Generated files are excluded by service policy. Traversal is always failure.
      if (
        path.split("/").some((part) => ignored.has(part)) &&
        path.split("/").every((part) => part && part !== "." && part !== "..") &&
        // biome-ignore lint/suspicious/noControlCharactersInRegex: Reject control bytes in untrusted paths.
        !/[\\:\x00-\x1f\x7f]/.test(path)
      )
        continue;
      throw new Error("Invalid scanner export");
    }
    if (mode === "current" && !metadata.files.includes(path))
      throw new Error("Invalid scanner export");
    if (
      mode === "history" &&
      (typeof item.Commit !== "string" || !metadata.fetchedCommits.includes(item.Commit))
    )
      throw new Error("Invalid scanner export");
    // Scanner fingerprints can contain paths/commits and are never forwarded.
    // Group the same rule and source location across commits without secret bytes.
    const fingerprint = createHash("sha256")
      .update(JSON.stringify([item.RuleID, path, item.StartLine]))
      .digest("hex");
    result.push({
      ruleId: item.RuleID,
      path,
      line: item.StartLine,
      ...(mode === "history" ? { commit: item.Commit } : {}),
      fingerprint,
    });
  }
  return result;
}
function main() {
  const [command, argument] = process.argv.slice(2);
  if (command === "verify") {
    if (!/^\/work\/\.vibeshield\/exports\/[a-z][a-z0-9-]*\.json$/.test(argument)) throw new Error();
    readBoundedJson(argument);
    return;
  }
  if (command !== "gitleaks" || !["current", "history"].includes(argument)) throw new Error();
  const acquisition = readBoundedJson(`${SERVICE}/exports/snapshot.json`);
  const raw = `${SERVICE}/gitleaks-${argument}-raw.json`;
  const args = [
    argument === "current" ? "dir" : "git",
    argument === "current" ? "/work/snapshot" : "/work/repository",
    "--config=/opt/vibeshield/gitleaks.toml",
    "--gitleaks-ignore-path=/opt/vibeshield/gitleaks.ignore",
    "--ignore-gitleaks-allow",
    "--redact=100",
    "--exit-code=0",
    "--no-banner",
    "--report-format=json",
    `--report-path=${raw}`,
  ];
  if (argument === "history") args.push("--log-opts=--max-count=100 HEAD");
  // Neither raw output nor diagnostics leave the guest, including error branches.
  const child = spawnSync("gitleaks", args, {
    cwd: SERVICE,
    env: gitEnvironment(),
    stdio: "ignore",
    timeout: 115_000,
  });
  if (child.error || child.signal || child.status !== 0) throw new Error();
  const output = sanitizeGitleaks(
    readBoundedJson(raw),
    { files: acquisition.snapshot.files, fetchedCommits: acquisition.fetchedCommits },
    argument,
  );
  writeExport(`${SERVICE}/exports/gitleaks-${argument}.json`, output);
}
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch {
    process.stderr.write("Scanner export failed\n");
    process.exitCode = 1;
  }
}
