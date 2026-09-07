#!/usr/bin/env node
import { spawn } from "node:child_process";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

const TAIL_BYTES = 64 * 1024;
const FILE_BYTES = 64 * 1024 * 1024;

function ownedPath(path, directory = false) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path)
    throw new Error("Expected an absolute owned path");
  const stat = lstatSync(path);
  if (
    stat.isSymbolicLink() ||
    (directory && !stat.isDirectory()) ||
    stat.uid !== process.getuid() ||
    stat.mode & 0o022 ||
    realpathSync(path) !== path
  )
    throw new Error("Unsafe owned path");
  return stat;
}

function allocatedBytes(path) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) return 0;
  let size = stat.blocks * 512;
  if (stat.isDirectory())
    for (const name of readdirSync(path)) size += allocatedBytes(join(path, name));
  return size;
}

async function main() {
  const configPath = process.argv[2];
  ownedPath(dirname(configPath), true);
  const configStat = ownedPath(configPath);
  if (!configStat.isFile() || configStat.size > 65536) throw new Error("Invalid command config");
  const configFd = openSync(configPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let config;
  try {
    config = JSON.parse(readFileSync(configFd, "utf8"));
  } finally {
    closeSync(configFd);
  }
  const { argv, timeoutMs, workspace, maxWorkspaceBytes, stdoutPath } = config;
  ownedPath(workspace, true);
  if (
    !Array.isArray(argv) ||
    argv.length === 0 ||
    argv.some((arg) => typeof arg !== "string" || arg.includes("\0")) ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > 600000 ||
    !Number.isSafeInteger(maxWorkspaceBytes) ||
    maxWorkspaceBytes <= 0 ||
    maxWorkspaceBytes > 2 * 1024 ** 3
  )
    throw new Error("Invalid command limits");
  let outputFd;
  if (stdoutPath !== null && stdoutPath !== undefined) {
    if (
      typeof stdoutPath !== "string" ||
      !isAbsolute(stdoutPath) ||
      resolve(stdoutPath) !== stdoutPath ||
      relative(workspace, stdoutPath).startsWith("..") ||
      stdoutPath === workspace
    )
      throw new Error("Output must be inside the owned workspace");
    ownedPath(dirname(stdoutPath), true);
    outputFd = openSync(
      stdoutPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    if (!fstatSync(outputFd).isFile()) throw new Error("Output is not a regular file");
  }
  let stdout = Buffer.alloc(0),
    stderr = Buffer.alloc(0),
    outputBytes = 0;
  let forcedCode, killTimer, failure;
  // POSIX sh applies an inherited per-file rlimit before exec. 1024 is
  // conservative across shells using either 512-byte or 1024-byte units.
  const child = spawn(
    "/bin/sh",
    [
      "-c",
      'ulimit -f "$1" || exit 125; shift; exec "$@"',
      "run-check",
      String(Math.floor(Math.min(FILE_BYTES, maxWorkspaceBytes) / 1024)),
      ...argv,
    ],
    { cwd: workspace, detached: true, stdio: ["ignore", "pipe", "pipe"] },
  );
  function killGroup(signal) {
    if (!child.pid) return;
    try {
      process.kill(-child.pid, signal);
    } catch (error) {
      if (error.code !== "ESRCH") {
        failure = error;
        forcedCode = 125;
      }
    }
  }
  function terminate(code) {
    forcedCode ??= code;
    killGroup("SIGTERM");
    killTimer ??= setTimeout(() => killGroup("SIGKILL"), 100);
  }
  const term = () => terminate(143);
  process.on("SIGTERM", term);
  process.on("SIGINT", term);
  const timer = setTimeout(() => terminate(124), timeoutMs);
  const watchdog = setInterval(() => {
    try {
      if (allocatedBytes(workspace) > maxWorkspaceBytes) terminate(125);
    } catch (error) {
      failure = error;
      terminate(125);
    }
  }, 250);
  child.stdout.on("data", (data) => {
    stdout = Buffer.concat([stdout, data]).subarray(-TAIL_BYTES);
    if (outputFd !== undefined) {
      outputBytes += data.length;
      if (outputBytes > Math.min(FILE_BYTES, maxWorkspaceBytes)) return terminate(125);
      try {
        writeSync(outputFd, data);
      } catch (error) {
        failure = error;
        terminate(125);
      }
    }
  });
  child.stderr.on("data", (data) => {
    stderr = Buffer.concat([stderr, data]).subarray(-TAIL_BYTES);
  });
  child.on("error", (error) => {
    failure = error;
    forcedCode = 125;
  });
  // A parent can exit while descendants keep inherited pipes open. Terminate
  // that group on parent exit as well, before waiting for pipe closure.
  child.on("exit", () => {
    killGroup("SIGTERM");
    killTimer ??= setTimeout(() => killGroup("SIGKILL"), 100);
  });
  const code = await new Promise((resolveCode) =>
    child.on("close", (exitCode) => resolveCode(exitCode)),
  );
  clearTimeout(timer);
  clearInterval(watchdog);
  killGroup("SIGKILL");
  clearTimeout(killTimer);
  process.removeListener("SIGTERM", term);
  process.removeListener("SIGINT", term);
  if (outputFd !== undefined) closeSync(outputFd);
  process.stdout.write(stdout);
  process.stderr.write(stderr);
  if (failure)
    process.stderr.write(`\nCommand resource handling failed: ${failure.code ?? "error"}\n`);
  process.exitCode = forcedCode ?? code ?? 125;
}

main().catch((error) => {
  process.stderr.write(`Command rejected: ${error.message}\n`);
  process.exitCode = 125;
});
