#!/usr/bin/env tsx
/**
 * Generate a fixture git repo with a planted, gitleaks-proven fake credential.
 *
 * Run:
 *   pnpm exec tsx scripts/make-planted-secret-fixture.ts [dest-dir]
 *
 * Default destination is `tmp/planted-secret-repo` under the repo root. The
 * script is idempotent: an existing destination is removed first.
 *
 * Why a generator and not a committed repo: committing a nested git repo is
 * fragile (submodule confusion) and the repo needs a real `.git` with a commit
 * SHA so the source-acquisition stage can read it. Generating keeps the source
 * tree clean and reproduces the fixture deterministically on demand.
 *
 * The planted key value is chosen to satisfy gitleaks' `stripe-access-token`
 * rule (regex + entropy >= 2). It is NOT a real credential.
 */
import { execFile } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Planted fake Stripe key. Verified against real gitleaks v8.30.1:
// matches `stripe-access-token`, entropy ~4.88. Not a live credential.
const PLANTED_STRIPE_KEY = ["sk", "live", "26SGeL0ZOrD23wxj6X4Q5np2Ua0eJZ7m"].join("_");

async function git(cwd: string, args: string[]): Promise<void> {
  await execFileP("git", args, { cwd });
}

async function main(): Promise<void> {
  const dest = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.join(repoRoot, "tmp", "planted-secret-repo");

  await rm(dest, { recursive: true, force: true });
  await mkdir(dest, { recursive: true });

  await git(dest, ["init", "-q", "--initial-branch=main"]);
  await git(dest, ["config", "user.email", "fixture@vibeshield.test"]);
  await git(dest, ["config", "user.name", "VibeShield Fixture"]);

  await writeFile(
    path.join(dest, "README.md"),
    [
      "# Sample App",
      "",
      "A tiny fixture repo for VibeShield Quick Scan acceptance.",
      "It contains one file with a planted, well-known fake credential so a",
      "real gitleaks run produces a real finding.",
      "",
    ].join("\n"),
  );

  await mkdir(path.join(dest, "src"), { recursive: true });
  await writeFile(
    path.join(dest, "src", "config.ts"),
    [
      "export const config = {",
      "  // NOTE: this is a planted FAKE key for testing secret scanners.",
      "  // It matches gitleaks' stripe-access-token rule but is not a real credential.",
      `  stripeSecret: "${PLANTED_STRIPE_KEY}",`,
      "  port: 3000,",
      "};",
      "",
    ].join("\n"),
  );

  await git(dest, ["add", "-A"]);
  await git(dest, ["commit", "-q", "-m", "fixture: sample app with a planted fake stripe key"]);

  const { stdout: sha } = await execFileP("git", ["rev-parse", "HEAD"], { cwd: dest });
  process.stdout.write(`fixture generated at ${dest}\ncommit: ${sha.trim()}\n`);
}

await main();
