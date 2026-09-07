import type { SandboxSession } from "../../ports/sandbox-runtime.js";
import type { Snapshot } from "../contracts.js";
export interface ScannerContext {
  session: SandboxSession;
  snapshot: Snapshot;
  signal: AbortSignal;
}
export const MAX_EXPORT_BYTES = 8 * 1024 * 1024;
export async function readScannerJson(
  session: SandboxSession,
  guestPath: string,
): Promise<unknown> {
  if (!/^\/work\/\.vibeshield\/exports\/[a-z][a-z0-9-]*\.json$/.test(guestPath))
    throw new Error("Invalid scanner export path");
  try {
    // The guest checks type, no-follow ownership, JSON and size before the SDK read.
    const checked = await session.exec(
      ["node", "/usr/local/bin/vibeshield-export-results", "verify", guestPath],
      { timeoutMs: 10_000 },
    );
    if (checked.exitCode !== 0) throw new Error();
    const data = await session.read(guestPath);
    if (data.byteLength === 0 || data.byteLength > MAX_EXPORT_BYTES) throw new Error();
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data));
  } catch {
    throw new Error("Invalid scanner export");
  }
}
