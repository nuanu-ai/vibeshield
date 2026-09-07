import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { afterEach, expect, it } from "vitest";

const exec = promisify(execFile);
const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true });
});

// The real launcher must propagate the child result and cleanup failure into both
// its process status and evidence. Only external live prerequisites are replaced.
it.each([
  { childCode: 7, cleanupFails: false, want: 7 },
  { childCode: 0, cleanupFails: true, want: 1 },
])("keeps live-command exit/evidence truthful: $childCode, cleanup=$cleanupFails", async ({
  childCode,
  cleanupFails,
  want,
}) => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "vs-live-command-")));
  directories.push(directory);
  await mkdir(join(directory, "bin"));
  await writeFile(join(directory, "bin", "pnpm"), `#!/bin/sh\nexit ${childCode}\n`, {
    mode: 0o700,
  });
  const module = `export async function verifyLivePrerequisites() {} export async function assertOwnedCleanup() { ${cleanupFails ? 'throw new Error("Controlled cleanup failure")' : ""} }`;
  const moduleUrl = `data:text/javascript,${encodeURIComponent(module)}`;
  const hook = `import { registerHooks } from 'node:module'; registerHooks({resolve(specifier, context, next){return specifier.endsWith('tests/support/live-runtime.js') ? { url: ${JSON.stringify(moduleUrl)}, shortCircuit: true } : next(specifier, context);}});`;
  const result = await exec(
    process.execPath,
    [
      "--import",
      resolve("node_modules/tsx/dist/loader.mjs"),
      "--import",
      `data:text/javascript,${encodeURIComponent(hook)}`,
      resolve("scripts/live-acceptance.ts"),
    ],
    {
      cwd: directory,
      env: { ...process.env, PATH: `${join(directory, "bin")}:${process.env.PATH}` },
      timeout: 10000,
    },
  ).then(
    () => ({ code: 0 }),
    (error: { code: number }) => ({ code: error.code }),
  );
  expect(result.code).toBe(want);
  const evidence = join(directory, "artifacts", "acceptance");
  const runs = await readdir(evidence);
  expect(runs).toHaveLength(1);
  const outcome = JSON.parse(
    await readFile(join(evidence, runs[0] as string, "outcome.json"), "utf8"),
  );
  expect(outcome.exitCode).toBe(want);
});
