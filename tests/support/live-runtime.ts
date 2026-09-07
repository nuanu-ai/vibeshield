import { randomUUID } from "node:crypto";
import { mkdir, readdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { Sandbox } from "microsandbox";
import { MicrosandboxRuntime } from "../../src/adapters/microsandbox/runtime.js";
import { toolchainImage, toolchainProvenance } from "../../src/adapters/toolchain.js";
import type { SandboxSession } from "../../src/ports/sandbox-runtime.js";
import type { Provenance } from "../../src/scan/contracts.js";

export const evidenceDirectory = resolve(
  process.env.VIBESHIELD_ACCEPTANCE_DIR ?? "artifacts/acceptance/manual",
);
export const ownerDirectory = resolve(evidenceDirectory, "owners");
export function liveSandboxName(purpose: string): string {
  return `vs-live-${purpose.slice(0, 12)}-${randomUUID()}`;
}
export function liveRuntime() {
  return new MicrosandboxRuntime({ imageTag: toolchainImage(), ownerDir: ownerDirectory });
}

export async function saveEvidence(name: string, value: unknown): Promise<void> {
  if (!/^[a-z][a-z0-9-]+$/.test(name)) throw new Error("Invalid evidence name");
  await mkdir(evidenceDirectory, { recursive: true, mode: 0o700 });
  await writeFile(
    resolve(evidenceDirectory, `${name}.json`),
    `${JSON.stringify(value, null, 2)}\n`,
    { mode: 0o600 },
  );
}

export async function withLiveSession<T>(
  purpose: string,
  operation: (session: SandboxSession) => Promise<T>,
): Promise<T> {
  const runtime = liveRuntime();
  const availability = await runtime.isAvailable();
  if (!availability.available)
    throw new Error(`Live runtime prerequisite unavailable: ${availability.reason}`);
  const name = liveSandboxName(purpose);
  const session = await runtime.create({ name, imageTag: toolchainImage() });
  try {
    return await operation(session);
  } finally {
    await runtime.destroy(name);
    await verifyRemoved(name);
  }
}

async function verifyRemoved(name: string): Promise<void> {
  if ((await Sandbox.list()).some((resource) => resource.name === name))
    throw new Error("Live acceptance left its sandbox behind");
}

export async function verifyLivePrerequisites(): Promise<Provenance> {
  const expected = toolchainProvenance();
  const actual = await withLiveSession("prerequisites", async (session) => {
    const output = await session.exec(
      ["node", "/opt/vibeshield/build-input/verify.mjs", expected.image],
      { timeoutMs: 120000 },
    );
    if (output.exitCode !== 0)
      throw new Error(
        "Live toolchain verification rejected installed versions, rules or image content",
      );
    const actual = JSON.parse(output.stdout) as Provenance;
    if (
      actual.image !== expected.image ||
      !isDeepStrictEqual(actual.tools, expected.tools) ||
      actual.rulesRevision !== expected.rulesRevision
    )
      throw new Error("Live toolchain provenance differs from its manifest");
    return actual;
  });
  await saveEvidence("prerequisites", actual);
  return actual;
}

export async function assertOwnedCleanup(): Promise<void> {
  let markers: string[] = [];
  try {
    markers = await readdir(ownerDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  if (markers.length) throw new Error("Live acceptance has unremoved ownership markers");
}
