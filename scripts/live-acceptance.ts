import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export async function main(): Promise<number> {
  const directory = resolve("artifacts/acceptance", new Date().toISOString().replace(/[:.]/g, "-"));
  await mkdir(directory, { recursive: true, mode: 0o700 });
  process.env.VIBESHIELD_ACCEPTANCE_DIR = directory;
  const { assertOwnedCleanup, verifyLivePrerequisites } = await import(
    "../tests/support/live-runtime.js"
  );
  let code = 1;
  try {
    await verifyLivePrerequisites();
    code = await new Promise<number>((resolveCode, reject) => {
      const child = spawn("pnpm", ["exec", "vitest", "run", "--config", "vitest.live.config.ts"], {
        stdio: "inherit",
        env: process.env,
      });
      child.once("error", reject);
      child.once("exit", (exitCode) => resolveCode(exitCode ?? 1));
    });
    await assertOwnedCleanup();
    return code;
  } catch (error) {
    code = 1;
    await writeFile(
      resolve(directory, "failure.json"),
      JSON.stringify(
        {
          stage: "acceptance",
          error: error instanceof Error ? error.message : "Live acceptance failed",
        },
        null,
        2,
      ),
      { mode: 0o600 },
    );
    process.stderr.write("Mandatory live acceptance failed. Inspect the sanitized evidence.\n");
    return 1;
  } finally {
    await writeFile(
      resolve(directory, "outcome.json"),
      JSON.stringify(
        {
          exitCode: code,
          externalBrowserAcceptance:
            "Performed separately by the operator; no browser dependencies in the repository.",
        },
        null,
        2,
      ),
      { mode: 0o600 },
    );
    process.stdout.write(`Acceptance evidence: ${directory}\n`);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  process.exitCode = await main();
