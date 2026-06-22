/**
 * MicrosandboxRuntime — production SandboxRuntime adapter.
 *
 * Boots one microsandbox per create(), reusing the locally-built toolchain
 * image (e.g. "vibeshield-toolchain:latest") that was loaded into
 * microsandbox's image cache. Network is on.
 *
 * The toolchain image is produced outside the runtime: `docker build` then
 * `msb load -t <tag>`. isAvailable() reports when both the runtime and the
 * toolchain image are present so the caller can fail clearly.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { isInstalled, Sandbox } from "microsandbox";
import type {
  SandboxAvailability,
  SandboxCreateOptions,
  SandboxRuntime,
} from "../../ports/sandbox-runtime.js";
import { MicrosandboxSession } from "./session.js";

const execFileP = promisify(execFile);

/** Resolve the msb binary path (installed under ~/.microsandbox/bin/msb). */
async function msbPath(): Promise<string | null> {
  try {
    const { stdout } = await execFileP("sh", ["-c", "echo $HOME"]);
    const home = stdout.trim();
    const path = `${home}/.microsandbox/bin/msb`;
    return path;
  } catch {
    return null;
  }
}

/** List cached image references via the msb CLI (avoids a broken SDK .d.ts). */
async function listCachedImages(): Promise<string[] | null> {
  const msb = await msbPath();
  if (msb === null) {
    return null;
  }
  try {
    const { stdout } = await execFileP(msb, ["image", "list", "--quiet"]);
    return stdout
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  } catch {
    return null;
  }
}

export interface MicrosandboxRuntimeOptions {
  /** Toolchain image tag; defaults to "vibeshield-toolchain:latest". */
  readonly imageTag?: string;
  /** vCPUs per sandbox; default 2. */
  readonly cpus?: number;
  /** Memory in MiB per sandbox; default 2048. */
  readonly memoryMib?: number;
}

export class MicrosandboxRuntime implements SandboxRuntime {
  private readonly imageTag: string;
  private readonly cpus: number;
  private readonly memoryMib: number;

  constructor(opts: MicrosandboxRuntimeOptions = {}) {
    this.imageTag = opts.imageTag ?? "vibeshield-toolchain:latest";
    this.cpus = opts.cpus ?? 2;
    this.memoryMib = opts.memoryMib ?? 2048;
  }

  async isAvailable(): Promise<SandboxAvailability> {
    if (!isInstalled()) {
      return {
        available: false,
        reason:
          "microsandbox runtime is not installed. Run the SDK's install step (see setup docs).",
      };
    }
    try {
      const images = await listCachedImages();
      if (images === null) {
        return {
          available: false,
          reason: "could not run the msb CLI to query the image cache.",
        };
      }
      const present = images.some((ref) => ref === this.imageTag);
      if (!present) {
        return {
          available: false,
          reason: `toolchain image "${this.imageTag}" is not loaded into the microsandbox cache. Build it and run: msb load -t ${this.imageTag} -i <image.tar>`,
        };
      }
    } catch {
      return {
        available: false,
        reason: `could not query the microsandbox image cache for "${this.imageTag}".`,
      };
    }
    return { available: true };
  }

  async create(options: SandboxCreateOptions): Promise<MicrosandboxSession> {
    const sb = await Sandbox.builder(options.name)
      .image(options.imageTag)
      .pullPolicy("never")
      .cpus(this.cpus)
      .memory(this.memoryMib)
      .replace()
      .create();
    return new MicrosandboxSession(sb, options.name);
  }

  async destroy(name: string): Promise<void> {
    const msb = await msbPath();
    if (msb !== null && (await removeWithCli(msb, name))) {
      return;
    }
    try {
      await Sandbox.remove(name);
    } catch {
      // destroy is best-effort; a missing or already-removed sandbox is fine.
    }
    if (msb !== null) {
      await removeWithCli(msb, name);
    }
  }
}

async function removeWithCli(msb: string, name: string): Promise<boolean> {
  for (let i = 0; i < 5; i += 1) {
    try {
      await execFileP(msb, ["remove", "--force", name]);
      return true;
    } catch {
      await sleep(200);
    }
  }
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
