#!/usr/bin/env tsx
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const researchRoot = path.join(repoRoot, ".local/research/report-v1/phase1");

export async function freeze(out: string): Promise<Record<string, unknown>> {
  const codeql = path.join(researchRoot, "tools/codeql/codeql");
  const semgrep = await realpath(await commandOutput("which", ["semgrep"]));
  const semgrepRules = path.join(researchRoot, "corpora/semgrep-rules");
  const files = {
    runner: path.join(repoRoot, "scripts/phase1/run-tool.ts"),
    owaspScorer: path.join(repoRoot, "scripts/phase1/score-owasp.ts"),
    resultNormalizer: path.join(repoRoot, "scripts/phase1/normalize-results.ts"),
    joernQuery: path.join(repoRoot, "scripts/phase1/joern-cwe-flows.sc"),
    preregistration: path.join(repoRoot, "benchmarks/phase1/preregistration.json"),
  };
  const output = {
    schemaVersion: 1,
    state: "frozen_before_held_out_scans",
    frozenAt: new Date().toISOString(),
    scannerInputContract: "raw_clean_git_snapshot_only",
    snapshots: {
      tuning: await git(path.join(researchRoot, "corpora/BenchmarkJava"), ["rev-parse", "HEAD"]),
      heldOut: await git(path.join(researchRoot, "corpora/BenchmarkPython"), ["rev-parse", "HEAD"]),
      realPairRegistry: await git(path.join(researchRoot, "corpora/cwe-bench-java"), [
        "rev-parse",
        "HEAD",
      ]),
      javascriptBreadth: await git(path.join(researchRoot, "corpora/SecBench.js"), [
        "rev-parse",
        "HEAD",
      ]),
    },
    vibeshield: {
      repositoryHead: await git(repoRoot, ["rev-parse", "HEAD"]),
      scannerSourceSha256: await scannerSourceIdentity(repoRoot),
      toolchainImage: await commandOutput("docker", [
        "image",
        "ls",
        "--no-trunc",
        "--format={{.ID}}",
        "vibeshield-toolchain:latest",
      ]),
    },
    codeql: {
      version: JSON.parse(
        await commandOutput("arch", ["-x86_64", codeql, "version", "--format=json"]),
      ),
      executableSha256: await sha256File(codeql),
      suite: "security-extended",
    },
    semgrep: {
      version: await commandOutput(semgrep, ["--version"]),
      executable: semgrep,
      executableSha256: await sha256File(semgrep),
      rulesCommit: await git(semgrepRules, ["rev-parse", "HEAD"]),
    },
    joern: {
      version: "4.0.565",
      image: await commandOutput("docker", [
        "image",
        "ls",
        "--no-trunc",
        "--format={{.ID}}",
        "vibeshield-toolchain:latest",
      ]),
      querySha256: await sha256File(files.joernQuery),
    },
    researchCode: Object.fromEntries(
      await Promise.all(
        Object.entries(files).map(async ([name, file]) => [name, await sha256File(file)]),
      ),
    ),
    resourceContract: {
      commandTimeoutSeconds: 1800,
      codeqlRamMiB: 8192,
      directJoernRamMiB: 10240,
      directJoernCpus: 8,
      semgrepPerFileTimeoutSeconds: 30,
      semgrepMaxTargetBytes: 5_000_000,
      vibeshield: "production_microsandbox_4096MiB_2vCPU",
    },
  };
  await writeFile(path.resolve(out), `${JSON.stringify(output, null, 2)}\n`, { flag: "wx" });
  return output;
}

async function scannerSourceIdentity(root: string): Promise<string> {
  const scope = [
    "src",
    "toolchain",
    "package.json",
    "pnpm-lock.yaml",
    "tsconfig.json",
    "tsconfig.build.json",
  ];
  const files = (
    await commandOutput("git", [
      "-C",
      root,
      "ls-files",
      "--cached",
      "--others",
      "--exclude-standard",
      "--",
      ...scope,
    ])
  )
    .split("\n")
    .filter(Boolean)
    .sort();
  const hash = createHash("sha256");
  for (const relative of files) {
    hash.update(relative);
    hash.update(await readFile(path.join(root, relative)));
  }
  return hash.digest("hex");
}

async function sha256File(file: string): Promise<string> {
  return createHash("sha256")
    .update(await readFile(file))
    .digest("hex");
}

async function git(cwd: string, args: ReadonlyArray<string>): Promise<string> {
  return await commandOutput("git", ["-C", cwd, ...args]);
}

async function commandOutput(command: string, args: ReadonlyArray<string>): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const child = spawn(command, [...args], { stdio: ["ignore", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve(Buffer.concat(stdout).toString("utf8").trim());
      } else {
        reject(new Error(`${command} exited ${code}: ${Buffer.concat(stderr).toString("utf8")}`));
      }
    });
  });
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2).filter((arg) => arg !== "--");
  const index = args.indexOf("--out");
  const out = index === -1 ? undefined : args[index + 1];
  if (out === undefined) throw new Error("usage: --out <freeze-json>");
  const result = await freeze(out);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
