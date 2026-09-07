import type { SandboxSession } from "../ports/sandbox-runtime.js";
import type { Snapshot } from "./contracts.js";
import { LIMITS } from "./limits.js";
import { validateAcquisition } from "./manifest.js";
import { readScannerJson } from "./scanners/shared.js";

export function parseRepositoryUrl(value: string): string {
  try {
    if (/[\\\s%]/.test(value)) throw new Error();
    const authority = /^https:\/\/([^/]+)\//.exec(value)?.[1];
    if (!authority || !/^github\.com$/i.test(authority)) throw new Error();
    const parsed = new URL(value);
    const rawPath = value.replace(/^https:\/\/[^/]+/, "");
    if (
      parsed.protocol !== "https:" ||
      parsed.hostname !== "github.com" ||
      parsed.port ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash ||
      !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/.test(rawPath) ||
      rawPath !== parsed.pathname
    )
      throw new Error();
    const [owner, name] = parsed.pathname.slice(1).replace(/\/$/, "").split("/");
    const repo = name?.replace(/\.git$/, "");
    if (!owner || !repo || [owner, repo].some((part) => part === "." || part === ".."))
      throw new Error();
    return `https://github.com/${owner}/${repo}`;
  } catch {
    throw new Error("Enter a public GitHub repository URL");
  }
}
export async function acquire(
  session: SandboxSession,
  url: string,
  signal: AbortSignal,
): Promise<Snapshot> {
  const canonical = parseRepositoryUrl(url);
  signal.throwIfAborted();
  const result = await session.exec(["node", "/usr/local/bin/vibeshield-acquire", canonical], {
    signal,
    timeoutMs: LIMITS.acquisitionMs,
  });
  if (result.exitCode !== 0) throw new Error("Repository acquisition failed");
  signal.throwIfAborted();
  const { snapshot } = validateAcquisition(
    await readScannerJson(session, "/work/.vibeshield/exports/snapshot.json"),
  );
  if (snapshot.url !== canonical) throw new Error("Invalid snapshot");
  return snapshot;
}
