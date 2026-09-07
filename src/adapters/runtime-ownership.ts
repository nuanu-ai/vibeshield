import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, realpath, unlink } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { Sandbox } from "microsandbox";
import type { MicrosandboxRuntime } from "./microsandbox/runtime.js";

export const OWNER_LABEL = "vibeshield.owner";
export interface RuntimeMarker {
  name: string;
  token: string;
}

async function privateDirectory(directory: string): Promise<void> {
  if (!isAbsolute(directory)) throw new Error("Runtime owner directory must be absolute");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await lstat(directory);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o077) !== 0 ||
    stat.uid !== process.getuid?.() ||
    (await realpath(directory)) !== resolve(directory)
  ) {
    throw new Error("Unsafe runtime owner directory");
  }
}

function markerPath(directory: string, name: string): string {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(name)) throw new Error("Invalid sandbox name");
  return join(directory, `${name}.json`);
}

export async function recordRuntimeOwnership(
  directory: string,
  name: string,
): Promise<RuntimeMarker> {
  await privateDirectory(directory);
  const marker = { name, token: randomUUID() };
  const file = await open(
    markerPath(directory, name),
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await file.writeFile(JSON.stringify(marker));
    await file.sync();
  } finally {
    await file.close();
  }
  return marker;
}

export async function readRuntimeOwnership(
  directory: string,
  name: string,
): Promise<RuntimeMarker | undefined> {
  await privateDirectory(directory);
  let file: Awaited<ReturnType<typeof open>>;
  try {
    file = await open(markerPath(directory, name), constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (["ENOENT", "ELOOP"].includes((error as NodeJS.ErrnoException).code ?? "")) return undefined;
    throw error;
  }
  try {
    const stat = await file.stat();
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.uid !== process.getuid?.() ||
      (stat.mode & 0o077) !== 0 ||
      stat.size > 1024
    )
      return undefined;
    const marker = JSON.parse(await file.readFile("utf8")) as RuntimeMarker;
    return marker.name === name &&
      typeof marker.token === "string" &&
      /^[0-9a-f-]{36}$/.test(marker.token)
      ? marker
      : undefined;
  } catch (error) {
    if (error instanceof SyntaxError) return undefined;
    throw error;
  } finally {
    await file.close();
  }
}

export async function clearRuntimeOwnership(directory: string, name: string): Promise<void> {
  if (await readRuntimeOwnership(directory, name)) await unlink(markerPath(directory, name));
}

export async function reconcileOwnedRuntime(
  runtime: MicrosandboxRuntime,
  ownerDir: string,
): Promise<void> {
  await privateDirectory(ownerDir);
  const resources = await Sandbox.list();
  for (const entry of await readdir(ownerDir, { withFileTypes: true })) {
    if (!entry.isFile() || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}\.json$/.test(entry.name)) continue;
    const name = entry.name.slice(0, -5);
    const marker = await readRuntimeOwnership(ownerDir, name);
    if (!marker) continue;
    const resource = resources.find((candidate) => candidate.name === name);
    if (resource) {
      const labels = resource.config().labels as Record<string, string> | undefined;
      if (labels?.[OWNER_LABEL] !== marker.token) continue;
      await runtime.destroy(name);
    }
    await clearRuntimeOwnership(ownerDir, name);
  }
}
