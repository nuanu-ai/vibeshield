/**
 * MicrosandboxSession — a live SandboxRuntime session backed by a microsandbox
 * Sandbox handle. Translates the port's simple exec/upload/download/read API
 * onto the SDK's fluent calls.
 *
 * Network is on by default in microsandbox; we do not restrict egress here.
 */

import { readFile } from "node:fs/promises";
import type { Sandbox } from "microsandbox";
import type { ExecResult, SandboxSession } from "../../ports/sandbox-runtime.js";

export class MicrosandboxSession implements SandboxSession {
  constructor(
    private readonly sb: Sandbox,
    readonly id: string,
  ) {}

  async exec(command: string[]): Promise<ExecResult> {
    const joined = command.map(shellQuote).join(" ");
    const out = await this.sb.shell(joined);
    return { exitCode: out.code, stdout: out.stdout(), stderr: out.stderr() };
  }

  async upload(localPath: string, guestPath: string): Promise<void> {
    const data = await readFile(localPath);
    await this.sb.fs().write(guestPath, data);
  }

  async uploadBytes(guestPath: string, data: Uint8Array): Promise<void> {
    await this.sb.fs().write(guestPath, Buffer.from(data));
  }

  async download(guestPath: string): Promise<Uint8Array> {
    const buf = await this.sb.fs().read(guestPath);
    return new Uint8Array(buf);
  }

  async read(guestPath: string): Promise<Uint8Array> {
    const buf = await this.sb.fs().read(guestPath);
    return new Uint8Array(buf);
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
