#!/usr/bin/env tsx
import { execFile, spawn } from "node:child_process";
import { constants } from "node:fs";
import { access, mkdtemp, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { Image } from "microsandbox";
import { toolchainImage } from "../src/adapters/toolchain.js";

const execFileP = promisify(execFile);
const repoRoot = path.resolve(import.meta.dirname, "..");

async function main(): Promise<void> {
  if (process.argv.length > 2)
    throw new Error("Toolchain tags are derived from content; no tag override is accepted.");
  const tag = toolchainImage();
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
    await run(imageBuilder, [
      "run",
      "--rm",
      tag,
      "node",
      "/opt/vibeshield/build-input/verify.mjs",
      tag,
    ]);
    if (toolchainImage() !== tag)
      throw new Error("Toolchain inputs changed during the build; prepare again.");
    await run(imageBuilder, ["save", tag, "-o", tarPath]);
    await run(msb, ["load", "-t", tag, "-i", tarPath]);
    process.stdout.write(`VibeShield toolchain is ready: ${tag}\n`);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
  await discardSuperseded(imageBuilder, tag);
}

/** Every toolchain build leaves a 4 GiB image behind in two places. Only our own
 * content-addressed tags are ever named, and cleanup never fails preparation. */
export function staleToolchainTags(references: readonly string[], keep: string): string[] {
  const ours = /^vibeshield-toolchain:sha256-[a-f0-9]{64}$/;
  return [...new Set(references)].filter((reference) => ours.test(reference) && reference !== keep);
}

async function discardSuperseded(imageBuilder: string, keep: string): Promise<void> {
  const built = await execFileP(imageBuilder, ["images", "--format", "{{.Repository}}:{{.Tag}}"])
    .then(({ stdout }) =>
      staleToolchainTags(
        stdout.split("\n").map((line) => line.trim()),
        keep,
      ),
    )
    .catch(() => []);
  for (const reference of built) {
    process.stdout.write(`Removing superseded image: ${reference}\n`);
    await execFileP(imageBuilder, ["rmi", reference]).catch(() => {});
  }
  const cached = await Image.list()
    .then((images) =>
      staleToolchainTags(
        images.map((image) => image.reference),
        keep,
      ),
    )
    .catch(() => []);
  for (const reference of cached) {
    process.stdout.write(`Removing superseded sandbox image: ${reference}\n`);
    await Image.remove(reference).catch(() => {});
  }
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
