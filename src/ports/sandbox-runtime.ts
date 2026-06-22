/**
 * SandboxRuntime port — isolate untrusted repos and run scanners inside.
 *
 * The only production adapter is MicrosandboxRuntime. A fake implementation
 * backs local tests. Domain code depends on this interface, never on an
 * adapter. One sandbox per run; network on.
 */

/** A running sandbox handle. Closed by `destroy()`. */
export interface SandboxSession {
  readonly id: string;
  /** Run a command, return exit code + stdout/stderr (UTF-8). */
  exec(command: string[]): Promise<ExecResult>;
  /** Upload a file from the host into the sandbox at `guestPath`. */
  upload(localPath: string, guestPath: string): Promise<void>;
  /** Upload bytes directly (no host file). */
  uploadBytes(guestPath: string, data: Uint8Array): Promise<void>;
  /** Download a file from the sandbox into `data` on the host. */
  download(guestPath: string): Promise<Uint8Array>;
  /** Read a file's bytes from the sandbox. */
  read(guestPath: string): Promise<Uint8Array>;
}

export interface ExecResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export interface SandboxCreateOptions {
  /** Run-local name; sandboxes for the same run share it. */
  readonly name: string;
  /** OCI image tag to boot (e.g. "vibeshield-toolchain:latest"). */
  readonly imageTag: string;
}

export interface SandboxRuntime {
  /** True when the runtime and toolchain image are usable on this host. */
  isAvailable(): Promise<SandboxAvailability>;
  /** Boot a new sandbox. Throws if the image is missing or boot fails. */
  create(options: SandboxCreateOptions): Promise<SandboxSession>;
  /** Remove a sandbox by name, best-effort. */
  destroy(name: string): Promise<void>;
}

export interface SandboxAvailability {
  readonly available: boolean;
  /** Missing runtime binary, missing image, unsupported host, etc. */
  readonly reason?: string;
}
