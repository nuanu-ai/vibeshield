/**
 * MicrosandboxSession — a live SandboxRuntime session backed by a microsandbox
 * Sandbox handle. Translates the port's simple exec/upload/download/read API
 * onto the SDK's fluent calls.
 *
 * Network is on by default in microsandbox; we do not restrict egress here.
 */

import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { ExecEvent, ExecHandle, Sandbox } from "microsandbox";
import type {
  ExecResult,
  SandboxExecEvent,
  SandboxExecOptions,
  SandboxSession,
} from "../../ports/sandbox-runtime.js";

const decoder = new TextDecoder();
const TAIL_BYTES = 64 * 1024;

export class MicrosandboxSession implements SandboxSession {
  constructor(
    private readonly sb: Sandbox,
    readonly id: string,
    private readonly remove?: () => Promise<void>,
  ) {}

  async exec(command: string[], options: SandboxExecOptions = {}): Promise<ExecResult> {
    let cleanup: Promise<void> | undefined;
    let active: ExecHandle | undefined;
    let rejectAbort!: (error: unknown) => void;
    const aborted = new Promise<never>((_resolve, reject) => {
      rejectAbort = reject;
    });
    const abort = () => {
      cleanup ??= (async () => {
        let signalError: unknown;
        try {
          // A stuck signal acknowledgement must not prevent verified VM removal.
          void active?.signal(15).catch((error: unknown) => {
            signalError = error;
          });
        } catch (error) {
          signalError = error;
        }
        try {
          await this.destroy();
        } catch (error) {
          throw new AggregateError(
            [signalError, error].filter(Boolean),
            "Sandbox abort cleanup failed",
          );
        }
      })();
      void cleanup.then(
        () => rejectAbort(options.signal?.reason ?? new Error("Scan aborted")),
        rejectAbort,
      );
    };
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();
    try {
      return await Promise.race([
        withMicrosandboxContext(
          `running in Microsandbox: ${command.map(shellQuote).join(" ")}`,
          () =>
            this.run(command, options, (handle) => {
              active = handle;
            }),
        ),
        aborted,
      ]);
    } catch (error) {
      if (cleanup) {
        try {
          await cleanup;
        } catch (cleanupError) {
          throw new AggregateError([error, cleanupError], "Execution aborted and cleanup failed");
        }
      }
      throw error;
    } finally {
      options.signal?.removeEventListener("abort", abort);
    }
  }

  private async run(
    command: string[],
    options: SandboxExecOptions,
    setHandle: (handle: ExecHandle) => void,
  ): Promise<ExecResult> {
    options.signal?.throwIfAborted();
    const control = `/run/vibeshield-${randomUUID()}`;
    const configPath = `${control}.json`;
    await this.sb
      .fs()
      .write(
        `${control}-run-check.mjs`,
        await readFile(new URL("../../../toolchain/run-check.mjs", import.meta.url)),
      );
    options.signal?.throwIfAborted();
    await this.sb.fs().write(
      configPath,
      Buffer.from(
        JSON.stringify({
          argv: command,
          timeoutMs: options.timeoutMs ?? 600_000,
          workspace: "/work",
          maxWorkspaceBytes: 2 * 1024 ** 3,
          stdoutPath: options.stdoutPath ?? null,
        }),
      ),
    );
    options.signal?.throwIfAborted();
    const shellCommand = withEnvPrefix(
      `exec node ${shellQuote(`${control}-run-check.mjs`)} ${shellQuote(configPath)}`,
      options.env,
    );
    const onEvent = options.onEvent;
    return await withMicrosandboxContext(`streaming in Microsandbox: ${shellCommand}`, async () => {
      const handle = await this.sb.shellStream(shellCommand);
      setHandle(handle);
      let stdout = "";
      let stderr = "";
      let exitCode: number | undefined;

      for (;;) {
        const event = await handle.recv();
        if (event === null) {
          break;
        }
        const mapped = toSandboxExecEvent(event);
        if (mapped.type === "stdout") {
          stdout = tail(stdout + mapped.data);
        } else if (mapped.type === "stderr") {
          stderr = tail(stderr + mapped.data);
        } else if (mapped.type === "exited") {
          exitCode = mapped.exitCode;
        }
        onEvent?.(mapped);
      }

      if (exitCode === undefined) {
        exitCode = (await handle.wait()).code;
      }
      options.signal?.throwIfAborted();
      return { exitCode, stdout, stderr };
    });
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
    if (this.remove) return this.remove();
    const { MicrosandboxRuntime } = await import("./runtime.js");
    await new MicrosandboxRuntime().destroy(this.id);
  }
}

function withEnvPrefix(command: string, env: Readonly<Record<string, string>> | undefined): string {
  if (env === undefined || Object.keys(env).length === 0) {
    return command;
  }
  const prefix = Object.entries(env)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${shellEnvKey(key)}=${shellQuote(value)}`)
    .join(" ");
  return `${prefix} ${command}`;
}

function shellEnvKey(key: string): string {
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    return key;
  }
  throw new Error(`Invalid sandbox environment variable name: ${key}`);
}

function toSandboxExecEvent(event: ExecEvent): SandboxExecEvent {
  switch (event.kind) {
    case "started":
      return { type: "started", pid: event.pid };
    case "stdout":
      return { type: "stdout", data: decoder.decode(event.data) };
    case "stderr":
      return { type: "stderr", data: decoder.decode(event.data) };
    case "exited":
      return { type: "exited", exitCode: event.code };
  }
}

function tail(value: string): string {
  return Buffer.from(value).subarray(-TAIL_BYTES).toString("utf8");
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
        { cause: error },
      );
    }
    throw new Error(`Microsandbox failed while ${operation}: ${message}`, { cause: error });
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
