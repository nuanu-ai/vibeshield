import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { FakeSandboxRuntime } from "../../src/adapters/fake-sandbox.js";
import { readScannerJson } from "../../src/scan/scanners/shared.js";

const guestPath = "../../toolchain/export-results.mjs";
const guest = await import(guestPath);
const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true });
});

// A lowered reader ceiling would discard valid output between 8 and 10 MiB;
// raising either boundary would admit an oversized scanner artifact.
it.each([
  10 * 1024 * 1024,
  10 * 1024 * 1024 + 1,
])("enforces the same inclusive 10 MiB export boundary in guest and host: %i bytes", async (bytes) => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "vs-export-limit-")));
  directories.push(directory);
  const file = join(directory, "scanner.json");
  const raw = `"${"x".repeat(bytes - 2)}"`;
  await writeFile(file, raw, { mode: 0o600 });
  const session = await new FakeSandboxRuntime().create({ name: "boundary", imageTag: "test" });
  await session.uploadBytes("/work/.vibeshield/exports/scanner.json", Buffer.from(raw));
  if (bytes === 10 * 1024 * 1024) {
    expect(guest.readBoundedJson(file).length).toBe(10 * 1024 * 1024 - 2);
    expect(
      (await readScannerJson(session, "/work/.vibeshield/exports/scanner.json")) as string,
    ).toHaveLength(10 * 1024 * 1024 - 2);
  } else {
    expect(() => guest.readBoundedJson(file)).toThrow("Invalid scanner export");
    await expect(
      readScannerJson(session, "/work/.vibeshield/exports/scanner.json"),
    ).rejects.toThrow("Invalid scanner export");
  }
});

// Removing the inherited limit lets a scanner write a 12 MiB raw JSON and
// report success even though its contract only permits 10 MiB.
it.each([
  "file",
  "stdout",
])("fails overflowing %s output without a truncated success", async (mode) => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "vs-output-limit-")));
  directories.push(directory);
  const workspace = join(directory, "work");
  await mkdir(workspace, { mode: 0o700 });
  const output = join(workspace, "scanner.json");
  const config = join(directory, "config.json");
  await writeFile(
    config,
    JSON.stringify({
      argv: [
        process.execPath,
        "-e",
        mode === "file"
          ? `require('fs').writeFileSync(${JSON.stringify(output)}, Buffer.alloc(12*1024*1024))`
          : "process.stdout.write(Buffer.alloc(12*1024*1024))",
      ],
      timeoutMs: 5000,
      workspace,
      maxWorkspaceBytes: 2 * 1024 ** 3,
      maxFileBytes: 10 * 1024 * 1024,
      stdoutPath: mode === "stdout" ? output : null,
    }),
    { mode: 0o600 },
  );
  const child = spawn(process.execPath, ["toolchain/run-check.mjs", config], { stdio: "ignore" });
  const [code] = await once(child, "close");
  expect(code).not.toBe(0);
  expect((await stat(output)).size).toBeLessThanOrEqual(10 * 1024 * 1024);
  expect((await readFile(output)).length).toBeLessThanOrEqual(10 * 1024 * 1024);
});
