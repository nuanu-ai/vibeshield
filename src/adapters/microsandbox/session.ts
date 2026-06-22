/**
 * MicrosandboxSession — a live SandboxRuntime session backed by a microsandbox
 * Sandbox handle. Translates the port's simple exec/upload/download/read API
 * onto the SDK's fluent calls.
 *
 * Network is on by default in microsandbox; we do not restrict egress here.
 */

import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import type { Sandbox } from "microsandbox";
import type { ExecResult, SandboxSession } from "../../ports/sandbox-runtime.js";

const execFileP = promisify(execFile);

export class MicrosandboxSession implements SandboxSession {
  constructor(
    private readonly sb: Sandbox,
    readonly id: string,
  ) {}

  async exec(command: string[]): Promise<ExecResult> {
    const joined = command.map(shellQuote).join(" ");
    const out = await withMicrosandboxContext(`running in Microsandbox: ${joined}`, () =>
      this.sb.shell(joined),
    );
    return { exitCode: out.code, stdout: out.stdout(), stderr: out.stderr() };
  }

  async upload(localPath: string, guestPath: string): Promise<void> {
    const data = await readFile(localPath);
    await withMicrosandboxContext(`uploading ${guestPath} to Microsandbox`, () =>
      this.sb.fs().write(guestPath, data),
    );
  }

  async uploadBytes(guestPath: string, data: Uint8Array): Promise<void> {
    await withMicrosandboxContext(`uploading ${guestPath} to Microsandbox`, () =>
      this.sb.fs().write(guestPath, Buffer.from(data)),
    );
  }

  async download(guestPath: string): Promise<Uint8Array> {
    const buf = await withMicrosandboxContext(`reading ${guestPath} from Microsandbox`, () =>
      this.sb.fs().read(guestPath),
    );
    return new Uint8Array(buf);
  }

  async read(guestPath: string): Promise<Uint8Array> {
    const buf = await withMicrosandboxContext(`reading ${guestPath} from Microsandbox`, () =>
      this.sb.fs().read(guestPath),
    );
    return new Uint8Array(buf);
  }

  async destroy(): Promise<void> {
    try {
      await this.sb.stop();
    } catch {
      // Best effort: the runtime-level destroy still tries to force-remove by name.
    }
    const msb = await msbPath();
    if (msb === null) {
      return;
    }
    for (let i = 0; i < 5; i += 1) {
      try {
        await execFileP(msb, ["remove", "--force", this.id]);
        return;
      } catch {
        await sleep(200);
      }
    }
  }
}

/**
 * Minimal POSIX-ish shell quoting. We always join argv into one shell command
 * because the SDK's `shell()` runs through `/bin/sh`. Single-quote wrap keeps
 * argument boundaries intact; embedded quotes are escaped.
 */
function shellQuote(arg: string): string {
  if (arg === "") {
    return "''";
  }
  if (/^[A-Za-z0-9@%_+=:,./-]+$/.test(arg)) {
    return arg;
  }
  return `'${arg.replace(/'/g, "'\\''")}'`;
}

async function withMicrosandboxContext<T>(operation: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    const message = errorMessage(error);
    if (message.includes("client closed")) {
      throw new Error(
        `Microsandbox session closed while ${operation}. This is a sandbox runtime interruption, not a scan finding. Re-run the scan; if it repeats, check \`msb list\` and reload the toolchain with \`pnpm toolchain:prepare\`. Original error: ${message}`,
      );
    }
    throw new Error(`Microsandbox failed while ${operation}: ${message}`);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function msbPath(): Promise<string | null> {
  try {
    const { stdout } = await execFileP("sh", ["-c", "echo $HOME"]);
    return `${stdout.trim()}/.microsandbox/bin/msb`;
  } catch {
    return null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
