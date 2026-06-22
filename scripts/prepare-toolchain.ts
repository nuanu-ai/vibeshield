#!/usr/bin/env tsx
import { execFile, spawn } from "node:child_process";
import { constants } from "node:fs";
import { access, mkdtemp, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileP = promisify(execFile);
const repoRoot = path.resolve(import.meta.dirname, "..");
const defaultTag = "vibeshield-toolchain:latest";

async function main(): Promise<void> {
  const tag = readTag();
  const imageBuilder = await firstAvailable(["docker", "podman"]);
  if (imageBuilder === null) {
    throw new Error("Docker or Podman is required to build the VibeShield toolchain image.");
  }
  const msb = await resolveMsb();
  const tmp = await mkdtemp(path.join(tmpdir(), "vibeshield-toolchain-"));
  const tarPath = path.join(tmp, "toolchain.tar");

  try {
    await run(imageBuilder, [
      "build",
      "-t",
      tag,
      "-f",
      path.join(repoRoot, "toolchain", "Dockerfile"),
      path.join(repoRoot, "toolchain"),
    ]);
    await run(imageBuilder, ["save", tag, "-o", tarPath]);
    await run(msb, ["load", "-t", tag, "-i", tarPath]);
    process.stdout.write(`VibeShield toolchain is ready: ${tag}\n`);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

function readTag(): string {
  const index = process.argv.indexOf("--tag");
  const value = index >= 0 ? process.argv[index + 1] : undefined;
  if (value !== undefined && value.length > 0) {
    return value;
  }
  return defaultTag;
}

async function resolveMsb(): Promise<string> {
  const fromPath = await firstAvailable(["msb"]);
  if (fromPath !== null) {
    return fromPath;
  }
  const bundled = path.join(homedir(), ".microsandbox", "bin", "msb");
  if (await executableExists(bundled)) {
    return bundled;
  }
  throw new Error("Microsandbox CLI is required. Install it so `msb` is on PATH.");
}

async function firstAvailable(commands: string[]): Promise<string | null> {
  for (const command of commands) {
    if (await executableExists(command)) {
      return command;
    }
  }
  return null;
}

async function executableExists(command: string): Promise<boolean> {
  try {
    if (command.includes("/")) {
      await access(command, constants.X_OK);
    } else {
      await execFileP("sh", ["-c", `command -v ${shellQuote(command)}`], {
        maxBuffer: 1024 * 1024,
      });
    }
    return true;
  } catch {
    return false;
  }
}

async function run(command: string, args: string[]): Promise<void> {
  process.stdout.write(`$ ${[command, ...args].join(" ")}\n`);
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, { cwd: repoRoot, stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} failed with ${signal ?? `exit code ${code ?? "unknown"}`}`));
    });
  });
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

await main();
