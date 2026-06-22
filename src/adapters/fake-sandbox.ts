/**
 * FakeSandboxRuntime — in-process SandboxRuntime double for tests.
 *
 * Tests of the deterministic pipeline (normalize, rank, report) need a sandbox
 * that records what the stages did without booting a VM. The exec handler is
 * pluggable: a test supplies the real gitleaks JSON a stage would parse, so the
 * test exercises normalization logic, never a fabricated scanner. A test that
 * needs to assert "the right gitleaks argv was run" inspects `invocations`.
 *
 * This is a test double only; it is never wired into the production scan path.
 */

import type {
  ExecResult,
  SandboxAvailability,
  SandboxCreateOptions,
  SandboxRuntime,
  SandboxSession,
} from "../ports/sandbox-runtime.js";

export type FakeExecHandler = (
  command: string[],
  session: FakeSandboxSession,
) => ExecResult | Promise<ExecResult>;

/** A captured exec invocation, for assertion in tests. */
export interface FakeInvocation {
  readonly name: string;
  readonly command: string[];
}

export class FakeSandboxSession implements SandboxSession {
  readonly files = new Map<string, Uint8Array>();
  readonly invocations: FakeInvocation[] = [];

  constructor(
    readonly id: string,
    private readonly execHandler: FakeExecHandler,
  ) {}

  async exec(command: string[]): Promise<ExecResult> {
    this.invocations.push({ name: this.id, command });
    return await this.execHandler(command, this);
  }

  async upload(localPath: string, guestPath: string): Promise<void> {
    const { readFile } = await import("node:fs/promises");
    this.files.set(guestPath, await readFile(localPath));
  }

  async uploadBytes(guestPath: string, data: Uint8Array): Promise<void> {
    this.files.set(guestPath, new Uint8Array(data));
  }

  async download(guestPath: string): Promise<Uint8Array> {
    return this.files.get(guestPath) ?? new Uint8Array();
  }

  async read(guestPath: string): Promise<Uint8Array> {
    return this.files.get(guestPath) ?? new Uint8Array();
  }

  async destroy(): Promise<void> {
    this.files.clear();
  }
}

export class FakeSandboxRuntime implements SandboxRuntime {
  /** All sessions created, keyed by name, for inspection in tests. */
  readonly sessions = new Map<string, FakeSandboxSession>();
  /** Every exec invocation across all sessions, in order. */
  readonly invocations: FakeInvocation[] = [];

  private readonly execHandler: FakeExecHandler;
  private available: SandboxAvailability;

  constructor(
    opts: {
      exec?: FakeExecHandler;
      available?: SandboxAvailability;
    } = {},
  ) {
    this.execHandler = opts.exec ?? (() => ({ exitCode: 0, stdout: "", stderr: "" }));
    this.available = opts.available ?? { available: true };
  }

  async isAvailable(): Promise<SandboxAvailability> {
    return this.available;
  }

  /** Tests can flip availability to exercise the "fail clearly" path. */
  setAvailability(a: SandboxAvailability): void {
    this.available = a;
  }

  async create(options: SandboxCreateOptions): Promise<FakeSandboxSession> {
    const session = new FakeSandboxSession(options.name, (cmd, currentSession) => {
      this.invocations.push({ name: options.name, command: cmd });
      return this.execHandler(cmd, currentSession);
    });
    this.sessions.set(options.name, session);
    return session;
  }

  async destroy(name: string): Promise<void> {
    this.sessions.delete(name);
  }
}
