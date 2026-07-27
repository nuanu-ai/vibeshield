#!/usr/bin/env tsx
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { access, mkdir, readdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

type Tool = "codeql" | "joern" | "semgrep" | "vibeshield";
type Language = "go" | "java" | "javascript" | "python";

interface Options {
  readonly tool: Tool;
  readonly language: Language;
  readonly snapshot: string;
  readonly out: string;
}

interface CommandResult {
  readonly command: ReadonlyArray<string>;
  readonly exitCode: number;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly stdoutPath: string;
  readonly stderrPath: string;
  readonly timedOut: boolean;
}

const repoRoot = path.resolve(import.meta.dirname, "../..");
const researchRoot = path.join(repoRoot, ".local/research/report-v1/phase1");

export async function runPhase1Tool(options: Options): Promise<void> {
  rejectGroundTruthArguments(process.argv.slice(2));
  const snapshot = await realpath(options.snapshot);
  const out = path.resolve(options.out);
  await assertGitSnapshot(snapshot);
  await assertNewOutputDirectory(out);
  await mkdir(out, { recursive: true });

  const targetCommit = await git(snapshot, ["rev-parse", "HEAD"]);
  const targetRemote = await git(snapshot, ["remote", "get-url", "origin"]);
  const startedAt = new Date().toISOString();
  const commands: CommandResult[] = [];
  let state: "complete" | "failed" = "complete";
  let failure: string | undefined;

  try {
    switch (options.tool) {
      case "vibeshield":
        await runVibeShield(snapshot, out, commands);
        break;
      case "codeql":
        await runCodeQl(options.language, snapshot, out, commands);
        break;
      case "semgrep":
        await runSemgrep(options.language, snapshot, out, commands);
        break;
      case "joern":
        await runJoern(options.language, snapshot, out, commands);
        break;
    }
  } catch (error) {
    state = "failed";
    failure = error instanceof Error ? error.message : String(error);
  }

  const manifest = {
    schemaVersion: 1,
    isolation: "raw_git_snapshot_no_ground_truth_arguments",
    tool: options.tool,
    language: options.language,
    target: {
      remote: targetRemote,
      commit: targetCommit,
      snapshot,
      clean: true,
    },
    runner: {
      path: path.relative(repoRoot, import.meta.filename),
      sha256: await sha256File(import.meta.filename),
    },
    configuration: await configurationIdentity(options.tool),
    startedAt,
    finishedAt: new Date().toISOString(),
    state,
    ...(failure === undefined ? {} : { failure }),
    commands,
    artifacts: await artifactHashes(out),
  };
  await writeFile(path.join(out, "run-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  if (state === "failed") {
    throw new Error(failure);
  }
}

async function runVibeShield(
  snapshot: string,
  out: string,
  commands: CommandResult[],
): Promise<void> {
  const stateRoot = path.join(out, "state");
  await mkdir(stateRoot, { recursive: true });
  await executeLogged(
    commands,
    "pnpm",
    ["scan", snapshot, "--deep", "--no-model"],
    out,
    "vibeshield",
    repoRoot,
    {
      VIBESHIELD_STATE_ROOT: stateRoot,
      VIBESHIELD_NO_MODEL: "1",
      VIBESHIELD_TOOLCHAIN_TAG: "vibeshield-toolchain:latest",
    },
  );
}

async function runCodeQl(
  language: Language,
  snapshot: string,
  out: string,
  commands: CommandResult[],
): Promise<void> {
  const codeql = process.env.PHASE1_CODEQL ?? path.join(researchRoot, "tools/codeql/codeql");
  await access(codeql);
  const codeqlRoot = path.dirname(codeql);
  const javaHome = path.join(codeqlRoot, "tools/osx64/java");
  const codeqlEnv = {
    JAVA_HOME: javaHome,
    PATH: `${path.join(javaHome, "bin")}:${process.env.PATH ?? ""}`,
  };
  const database = path.join(out, "database");
  const sarif = path.join(out, "results.sarif");
  const codeqlLanguage = language === "javascript" ? "javascript-typescript" : language;
  const queryLanguage = language === "javascript" ? "javascript" : language;
  await executeLogged(
    commands,
    "arch",
    [
      "-x86_64",
      codeql,
      "database",
      "create",
      database,
      `--language=${codeqlLanguage}`,
      `--source-root=${snapshot}`,
      "--build-mode=none",
      "--threads=0",
    ],
    out,
    "codeql-create",
    snapshot,
    codeqlEnv,
  );
  const suite = `codeql/${queryLanguage}-queries:codeql-suites/${queryLanguage}-security-extended.qls`;
  await executeLogged(
    commands,
    "arch",
    [
      "-x86_64",
      codeql,
      "database",
      "analyze",
      database,
      suite,
      "--format=sarifv2.1.0",
      `--output=${sarif}`,
      "--threads=0",
      "--ram=8192",
    ],
    out,
    "codeql-analyze",
    snapshot,
    codeqlEnv,
  );
}

async function runSemgrep(
  language: Language,
  snapshot: string,
  out: string,
  commands: CommandResult[],
): Promise<void> {
  const rulesRoot =
    process.env.PHASE1_SEMGREP_RULES ?? path.join(researchRoot, "corpora/semgrep-rules");
  const configLanguage = language === "javascript" ? "javascript" : language;
  const config = path.join(rulesRoot, configLanguage);
  await access(config);
  await executeLogged(
    commands,
    process.env.PHASE1_SEMGREP ?? "semgrep",
    [
      "scan",
      "--config",
      config,
      "--json",
      "--output",
      path.join(out, "results.json"),
      "--metrics=off",
      "--disable-version-check",
      "--timeout=30",
      "--max-target-bytes=5000000",
      snapshot,
    ],
    out,
    "semgrep",
    snapshot,
  );
}

async function runJoern(
  language: Language,
  snapshot: string,
  out: string,
  commands: CommandResult[],
): Promise<void> {
  const image = process.env.PHASE1_JOERN_IMAGE ?? "vibeshield-toolchain:latest";
  const query = path.join(repoRoot, "scripts/phase1/joern-cwe-flows.sc");
  await access(query);
  const dockerLanguage =
    language === "java"
      ? "javasrc"
      : language === "javascript"
        ? "javascript"
        : language === "go"
          ? "golang"
          : "python";
  await executeLogged(
    commands,
    "docker",
    [
      "run",
      "--rm",
      "--memory=10g",
      "--cpus=8",
      "-v",
      `${snapshot}:/src:ro`,
      "-v",
      `${out}:/out`,
      image,
      "joern-parse",
      "--language",
      dockerLanguage,
      "/src",
      "-o",
      "/out/cpg.bin",
    ],
    out,
    "joern-parse",
    snapshot,
  );
  await executeLogged(
    commands,
    "docker",
    [
      "run",
      "--rm",
      "--memory=10g",
      "--cpus=8",
      "-v",
      `${out}:/out`,
      "-v",
      `${query}:/queries/joern-cwe-flows.sc:ro`,
      image,
      "joern",
      "--script",
      "/queries/joern-cwe-flows.sc",
      "--param",
      "cpgFile=/out/cpg.bin",
      "--param",
      "outFile=/out/results.tsv",
    ],
    out,
    "joern-query",
    snapshot,
  );
}

async function executeLogged(
  commands: CommandResult[],
  command: string,
  args: ReadonlyArray<string>,
  out: string,
  label: string,
  cwd: string,
  extraEnv: Readonly<Record<string, string>> = {},
): Promise<void> {
  const result = await runLogged(command, args, out, label, cwd, extraEnv);
  commands.push(result);
  if (result.exitCode !== 0) {
    const suffix = result.timedOut ? " after the Phase 1 runtime budget" : "";
    throw new Error(`${label} exited with code ${result.exitCode}${suffix}`);
  }
}

async function runLogged(
  command: string,
  args: ReadonlyArray<string>,
  out: string,
  label: string,
  cwd: string,
  extraEnv: Readonly<Record<string, string>> = {},
): Promise<CommandResult> {
  const startedAt = new Date().toISOString();
  const stdoutPath = path.join(out, `${label}.stdout.log`);
  const stderrPath = path.join(out, `${label}.stderr.log`);
  const stdout = createWriteStream(stdoutPath, { flags: "wx" });
  const stderr = createWriteStream(stderrPath, { flags: "wx" });
  process.stdout.write(`$ ${[command, ...args].join(" ")}\n`);
  let timedOut = false;
  const timeoutMs = toolTimeoutMs();
  const exitCode = await new Promise<number>((resolve, reject) => {
    const child = spawn(command, [...args], {
      cwd,
      env: { ...process.env, ...extraEnv },
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const timer = setTimeout(() => {
      timedOut = true;
      if (child.pid !== undefined) {
        terminateProcessGroup(child.pid);
      }
    }, timeoutMs);
    child.stdout.pipe(stdout);
    child.stderr.pipe(stderr);
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve(timedOut ? 124 : (code ?? 1));
    });
  });
  await Promise.all([streamClosed(stdout), streamClosed(stderr)]);
  const result = {
    command: [command, ...args],
    exitCode,
    startedAt,
    finishedAt: new Date().toISOString(),
    stdoutPath: path.basename(stdoutPath),
    stderrPath: path.basename(stderrPath),
    timedOut,
  };
  return result;
}

function toolTimeoutMs(): number {
  const configured = Number(process.env.PHASE1_TOOL_TIMEOUT_MS ?? 30 * 60 * 1000);
  if (!Number.isInteger(configured) || configured < 60_000) {
    throw new Error("PHASE1_TOOL_TIMEOUT_MS must be an integer of at least 60000");
  }
  return configured;
}

function terminateProcessGroup(pid: number): void {
  try {
    process.kill(-pid, "SIGTERM");
  } catch {
    return;
  }
  setTimeout(() => {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      // The process group already exited.
    }
  }, 5_000).unref();
}

async function streamClosed(stream: NodeJS.WritableStream): Promise<void> {
  if ((stream as { closed?: boolean }).closed === true) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    stream.once("close", resolve);
    stream.once("error", reject);
  });
}

async function configurationIdentity(tool: Tool): Promise<Record<string, unknown>> {
  switch (tool) {
    case "vibeshield":
      return {
        repositoryHead: await git(repoRoot, ["rev-parse", "HEAD"]),
        scannerSourceSha256: await scannerSourceIdentity(repoRoot),
        scannerSourceScope: [
          "src",
          "toolchain",
          "package.json",
          "pnpm-lock.yaml",
          "tsconfig.json",
          "tsconfig.build.json",
        ],
        toolchainImage: await commandOutput("docker", [
          "image",
          "ls",
          "--no-trunc",
          "--format={{.ID}}",
          "vibeshield-toolchain:latest",
        ]),
      };
    case "codeql": {
      const codeql = process.env.PHASE1_CODEQL ?? path.join(researchRoot, "tools/codeql/codeql");
      return {
        version: await commandOutput("arch", ["-x86_64", codeql, "version", "--format=json"]),
        executableSha256: await sha256File(codeql),
      };
    }
    case "semgrep": {
      const rules =
        process.env.PHASE1_SEMGREP_RULES ?? path.join(researchRoot, "corpora/semgrep-rules");
      return {
        version: await commandOutput(process.env.PHASE1_SEMGREP ?? "semgrep", ["--version"]),
        rulesCommit: await git(rules, ["rev-parse", "HEAD"]),
      };
    }
    case "joern": {
      const query = path.join(repoRoot, "scripts/phase1/joern-cwe-flows.sc");
      return {
        version: "4.0.565",
        image: await commandOutput("docker", [
          "image",
          "ls",
          "--no-trunc",
          "--format={{.ID}}",
          process.env.PHASE1_JOERN_IMAGE ?? "vibeshield-toolchain:latest",
        ]),
        querySha256: await sha256File(query),
      };
    }
  }
}

async function assertGitSnapshot(snapshot: string): Promise<void> {
  const root = await realpath(await git(snapshot, ["rev-parse", "--show-toplevel"]));
  if (root !== snapshot) {
    throw new Error(`snapshot must be the Git worktree root: ${snapshot}`);
  }
  const dirty = await git(snapshot, ["status", "--porcelain"]);
  if (dirty.length > 0) {
    throw new Error(`snapshot must be clean: ${snapshot}`);
  }
}

async function assertNewOutputDirectory(out: string): Promise<void> {
  const current = await stat(out).catch(() => undefined);
  if (current === undefined) {
    return;
  }
  if (!current.isDirectory() || (await readdir(out)).length > 0) {
    throw new Error(`output directory must not exist or must be empty: ${out}`);
  }
}

function rejectGroundTruthArguments(args: ReadonlyArray<string>): void {
  const forbidden = args.find((arg) =>
    /(?:expectedresults|ground[-_]?truth|\/truth\/)/iu.test(arg),
  );
  if (forbidden !== undefined) {
    throw new Error(`ground-truth argument is forbidden in scanner runner: ${forbidden}`);
  }
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
  const hash = createHash("sha256");
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
  for (const relative of files) {
    hash.update(relative);
    hash.update(await readFile(path.join(root, relative)));
  }
  return hash.digest("hex");
}

async function artifactHashes(out: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const name of await readdir(out)) {
    if (
      name === "database" ||
      name === "state" ||
      name === "cpg.bin" ||
      name === "run-manifest.json"
    ) {
      continue;
    }
    const file = path.join(out, name);
    if ((await stat(file)).isFile()) {
      result[name] = await sha256File(file);
    }
  }
  return result;
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
        reject(
          new Error(
            `${command} exited ${code ?? "unknown"}: ${Buffer.concat(stderr).toString("utf8").trim()}`,
          ),
        );
      }
    });
  });
}

function parseOptions(args: ReadonlyArray<string>): Options {
  const normalizedArgs = args[0] === "--" ? args.slice(1) : args;
  const values = new Map<string, string>();
  for (let index = 0; index < normalizedArgs.length; index += 2) {
    const name = normalizedArgs[index];
    const value = normalizedArgs[index + 1];
    if (name === undefined || value === undefined || !name.startsWith("--")) {
      throw new Error("usage: --tool <tool> --language <language> --snapshot <path> --out <path>");
    }
    values.set(name, value);
  }
  const tool = values.get("--tool");
  const language = values.get("--language");
  const snapshot = values.get("--snapshot");
  const out = values.get("--out");
  if (!isTool(tool) || !isLanguage(language) || snapshot === undefined || out === undefined) {
    throw new Error("usage: --tool <tool> --language <language> --snapshot <path> --out <path>");
  }
  return { tool, language, snapshot, out };
}

function isTool(value: string | undefined): value is Tool {
  return value === "codeql" || value === "joern" || value === "semgrep" || value === "vibeshield";
}

function isLanguage(value: string | undefined): value is Language {
  return value === "go" || value === "java" || value === "javascript" || value === "python";
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runPhase1Tool(parseOptions(process.argv.slice(2)));
}
