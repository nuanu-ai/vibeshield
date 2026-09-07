/**
 * MicrosandboxRuntime — production SandboxRuntime adapter.
 *
 * Boots one microsandbox per create(), reusing the locally-built toolchain
 * content-derived toolchain image that was loaded into
 * microsandbox's image cache. Network is on.
 *
 * The toolchain image is produced outside the runtime: `docker build` then
 * `msb load -t <tag>`. isAvailable() reports when both the runtime and the
 * toolchain image are present so the caller can fail clearly.
 */

import { execFile } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { isInstalled, MiB, Sandbox } from "microsandbox";
import type {
  SandboxAvailability,
  SandboxCreateOptions,
  SandboxRuntime,
} from "../../ports/sandbox-runtime.js";
import {
  clearRuntimeOwnership,
  OWNER_LABEL,
  recordRuntimeOwnership,
} from "../runtime-ownership.js";
import { toolchainImage } from "../toolchain.js";
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
  readonly ownerDir?: string;
  /** Toolchain image tag; defaults to the current build-content identity. */
  readonly imageTag?: string;
  /** vCPUs per sandbox; default 2. */
  readonly cpus?: number;
  /** Memory in MiB per sandbox; default 4096. */
  readonly memoryMib?: number;
}

export class MicrosandboxRuntime implements SandboxRuntime {
  private readonly imageTag: string;
  private readonly cpus: number;
  private readonly memoryMib: number;
  private readonly ownerDir: string;
  private readonly live = new Map<string, Sandbox>();

  constructor(opts: MicrosandboxRuntimeOptions = {}) {
    this.imageTag = opts.imageTag ?? toolchainImage();
    this.cpus = opts.cpus ?? 2;
    this.memoryMib = opts.memoryMib ?? 4096;
    this.ownerDir =
      opts.ownerDir ?? join(homedir(), ".local", "state", "vibeshield", "runtime-ownership");
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
    options.signal?.throwIfAborted();
    if ((await Sandbox.list()).some((resource) => resource.name === options.name)) {
      throw new Error("Sandbox name is already in use");
    }
    const marker = await recordRuntimeOwnership(this.ownerDir, options.name);
    try {
      const sb = await Sandbox.builder(options.name)
        .image(options.imageTag)
        .pullPolicy("never")
        .cpus(this.cpus)
        .memory(this.memoryMib)
        .volume("/work", (mount) => mount.tmpfs().size(MiB(2048)).nosuid().nodev())
        .label(OWNER_LABEL, marker.token)
        .create();
      this.live.set(options.name, sb);
      if (options.signal?.aborted) {
        await this.destroy(options.name);
        options.signal.throwIfAborted();
      }
      return new MicrosandboxSession(sb, options.name, () => this.destroy(options.name));
    } catch (error) {
      try {
        if (!this.live.has(options.name)) {
          const resource = (await Sandbox.list()).find(
            (candidate) => candidate.name === options.name,
          );
          const labels = resource?.config().labels as Record<string, string> | undefined;
          if (resource && labels?.[OWNER_LABEL] !== marker.token) {
            throw new Error(
              "Sandbox cleanup refused: resource ownership differs from creation marker",
            );
          }
        }
        await this.destroy(options.name);
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          "Sandbox creation failed and cleanup failed",
        );
      }
      throw error;
    }
  }

  async destroy(name: string): Promise<void> {
    const msb = await msbPath();
    const errors: unknown[] = [];
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        const resource =
          this.live.get(name) ??
          (await Sandbox.list()).find((candidate) => candidate.name === name);
        if (resource) await resource.killWithTimeout(1_000);
      } catch (error) {
        errors.push(error);
      }
      try {
        if (msb === null) throw new Error("Microsandbox CLI unavailable");
        await execFileP(msb, ["remove", "--force", name], { timeout: 15_000, maxBuffer: 65536 });
      } catch (error) {
        errors.push(error);
        try {
          await Sandbox.remove(name);
        } catch (sdkError) {
          errors.push(sdkError);
        }
      }
      try {
        if (!(await Sandbox.list()).some((resource) => resource.name === name)) {
          this.live.delete(name);
          await clearRuntimeOwnership(this.ownerDir, name);
          return;
        }
      } catch (error) {
        errors.push(error);
      }
      if (attempt < 2) await sleep(100);
    }
    throw new AggregateError(
      errors,
      `Sandbox cleanup failed: absence of ${name} could not be established`,
    );
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
