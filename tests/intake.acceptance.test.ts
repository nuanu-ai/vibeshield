import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli/run-cli.js";
import { runResume, runScan } from "../src/run/run-scan.js";
import { FakeDaytonaSandboxProvider } from "../src/sandbox/fake-daytona.js";

const execFileAsync = promisify(execFile);

const tempRoots: string[] = [];
const fixtureUrl = "https://github.com/vibeshield/intake-fixture";

async function createTempRoot(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempRoots.push(dir);
  return dir;
}

async function pathExists(filePath: string): Promise<boolean> {
  try {
    await stat(filePath);
    return true;
  } catch {
    return false;
  }
}

async function createFixtureGitRepo(): Promise<string> {
  const repoDir = await createTempRoot("vibeshield-fixture-");
  await writeFile(path.join(repoDir, "README.md"), "# Fixture project\n");
  await writeFile(
    path.join(repoDir, "package.json"),
    `${JSON.stringify(
      {
        name: "intake-fixture",
        scripts: {
          build: "node scripts/should-not-run.js",
          postinstall: "node scripts/should-not-run.js",
          test: "node scripts/should-not-run.js",
        },
      },
      null,
      2,
    )}\n`,
  );
  await writeFile(path.join(repoDir, "vibeshield-marker.txt"), "inventory marker\n");
  await execFileAsync("mkdir", ["-p", path.join(repoDir, "src"), path.join(repoDir, "scripts")]);
  await writeFile(path.join(repoDir, "src", "app.ts"), "export const marker = 'intake';\n");
  await writeFile(
    path.join(repoDir, "scripts", "should-not-run.js"),
    "throw new Error('repo-defined script was executed');\n",
  );

  await execFileAsync("git", ["init"], { cwd: repoDir });
  await execFileAsync("git", ["add", "."], { cwd: repoDir });
  await execFileAsync(
    "git",
    [
      "-c",
      "user.name=VibeShield Test",
      "-c",
      "user.email=vibeshield@example.test",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "-m",
      "fixture",
    ],
    {
      cwd: repoDir,
      env: {
        ...process.env,
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
      },
    },
  );
  return repoDir;
}

async function createLocalGitFilteredRepo(): Promise<string> {
  const repoDir = await createTempRoot("vibeshield-local-fixture-");
  await mkdir(path.join(repoDir, "src"), { recursive: true });
  await writeFile(
    path.join(repoDir, ".gitignore"),
    [".env", "ignored.txt", "node_modules/", "runs/", ""].join("\n"),
  );
  await writeFile(path.join(repoDir, "README.md"), "# Local fixture\n");
  await writeFile(path.join(repoDir, "src", "app.ts"), "export const marker = 'committed';\n");

  await execFileAsync("git", ["init"], { cwd: repoDir });
  await execFileAsync("git", ["add", "."], { cwd: repoDir });
  await execFileAsync(
    "git",
    [
      "-c",
      "user.name=VibeShield Test",
      "-c",
      "user.email=vibeshield@example.test",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "-m",
      "local fixture",
    ],
    {
      cwd: repoDir,
      env: {
        ...process.env,
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
      },
    },
  );

  await writeFile(path.join(repoDir, "src", "app.ts"), "export const marker = 'modified';\n");
  await writeFile(path.join(repoDir, "src", "untracked.ts"), "export const extra = true;\n");
  await mkdir(path.join(repoDir, "node_modules", "package"), { recursive: true });
  await mkdir(path.join(repoDir, "runs", "run-local"), { recursive: true });
  await writeFile(path.join(repoDir, ".env"), "SECRET=should-not-copy\n");
  await writeFile(path.join(repoDir, "ignored.txt"), "ignored\n");
  await writeFile(path.join(repoDir, "node_modules", "package", "index.js"), "ignored\n");
  await writeFile(path.join(repoDir, "runs", "run-local", "event.jsonl"), "{}\n");

  return repoDir;
}

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await readFile(filePath, "utf8")) as T;
}

async function createProvider(options?: { failAt?: "clone" | "inventory" }) {
  const fixtureRepo = await createFixtureGitRepo();
  const sandboxRoot = await createTempRoot("vibeshield-fake-daytona-");
  const providerOptions: ConstructorParameters<typeof FakeDaytonaSandboxProvider>[0] = {
    fixtureRepos: new Map([[fixtureUrl, fixtureRepo]]),
    sandboxRoot,
  };
  if (options?.failAt !== undefined) {
    providerOptions.failAt = options.failAt;
  }
  const provider = new FakeDaytonaSandboxProvider(providerOptions);
  return { fixtureRepo, provider, sandboxRoot };
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("GitHub intake and sandbox inventory acceptance", () => {
  it("prints CLI help with rerunnable resume steps", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];

    const exitCode = await runCli(["--", "--help"], {
      stderr: { write: (chunk: string) => stderr.push(chunk) },
      stdout: { write: (chunk: string) => stdout.push(chunk) },
    });

    expect(exitCode).toBe(0);
    expect(stderr.join("")).toBe("");
    expect(stdout.join("")).toContain("vibeshield resume /path/to/run-directory [--from <step>]");
    expect(stdout.join("")).toContain("vibeshield resume /path/to/run-directory --only <step>");
    expect(stdout.join("")).toContain("--only <step>");
    expect(stdout.join("")).not.toContain("--only-step");
    expect(stdout.join("")).toContain("attack-hypotheses");
    expect(stdout.join("")).toContain("final-report");
    expect(stdout.join("")).toContain("stack-build-deps");
  });

  it("rejects unknown resume --from steps before touching a run directory", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];

    const exitCode = await runCli(["resume", "/tmp/does-not-matter", "--from", "unknown-step"], {
      stderr: { write: (chunk: string) => stderr.push(chunk) },
      stdout: { write: (chunk: string) => stdout.push(chunk) },
    });

    expect(exitCode).toBe(1);
    expect(stdout.join("")).toBe("");
    expect(stderr.join("")).toContain("Unknown resume step: unknown-step");
    expect(stderr.join("")).toContain("attack-hypotheses");
  });

  it("rejects unknown resume --only steps before touching a run directory", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];

    const exitCode = await runCli(["resume", "/tmp/does-not-matter", "--only", "unknown-step"], {
      stderr: { write: (chunk: string) => stderr.push(chunk) },
      stdout: { write: (chunk: string) => stdout.push(chunk) },
    });

    expect(exitCode).toBe(1);
    expect(stdout.join("")).toBe("");
    expect(stderr.join("")).toContain("Unknown resume step: unknown-step");
    expect(stderr.join("")).toContain("attack-hypotheses");
  });

  it("rejects mixing resume --from and --only", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];

    const exitCode = await runCli(
      ["resume", "/tmp/does-not-matter", "--from", "entrypoints", "--only", "final-report"],
      {
        stderr: { write: (chunk: string) => stderr.push(chunk) },
        stdout: { write: (chunk: string) => stdout.push(chunk) },
      },
    );

    expect(exitCode).toBe(1);
    expect(stdout.join("")).toBe("");
    expect(stderr.join("")).toContain("--from and --only cannot be used together.");
  });

  it("does not accept --only-step as a resume alias", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];

    const exitCode = await runCli(["resume", "/tmp/does-not-matter", "--only-step", "context"], {
      stderr: { write: (chunk: string) => stderr.push(chunk) },
      stdout: { write: (chunk: string) => stdout.push(chunk) },
    });

    expect(exitCode).toBe(1);
    expect(stdout.join("")).toBe("");
    expect(stderr.join("")).toContain("Unknown argument: --only-step");
  });

  it("rejects unsupported URL and archive inputs before sandbox creation", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");
    const unsupportedInputs = [
      "repo.zip",
      "https://gitlab.com/owner/repo",
      "https://github.com/owner/repo/archive/refs/heads/main.zip",
    ];

    for (const input of unsupportedInputs) {
      const result = await runScan({
        sourceInput: input,
        runsRoot,
        sandboxProvider: provider,
      });

      if (result.exitCode !== 1) {
        throw new Error("Unsupported input unexpectedly succeeded.");
      }
      expect(result.runDir).toBeUndefined();
      expect(result.userMessage).toContain(
        "VibeShield accepts a GitHub repository URL or a local Git worktree root path",
      );
    }

    expect(provider.createdSandboxIds).toHaveLength(0);
  });

  it("rejects non-Git local paths before sandbox creation", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");
    const nonGitDir = await createTempRoot("vibeshield-non-git-");

    const result = await runScan({
      runsRoot,
      sandboxProvider: provider,
      sourceInput: nonGitDir,
    });

    if (result.exitCode !== 1) {
      throw new Error("Non-Git local path unexpectedly succeeded.");
    }
    expect(result.runDir).toBeUndefined();
    expect(result.userMessage).toContain("not inside a Git worktree");
    expect(provider.createdSandboxIds).toHaveLength(0);
  });

  it("returns a local run directory with inspectable intake artifacts", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");
    const stdout: string[] = [];
    const stderr: string[] = [];

    const exitCode = await runCli(
      ["scan", fixtureUrl],
      {
        stderr: { write: (chunk: string) => stderr.push(chunk) },
        stdout: { write: (chunk: string) => stdout.push(chunk) },
      },
      { runsRoot, sandboxProvider: provider },
    );

    expect(exitCode).toBe(0);
    expect(stderr.join("")).toBe("");

    const printedRunDir = stdout.join("").match(/Run directory: (?<runDir>.+)\n/)?.groups?.runDir;
    expect(printedRunDir).toBeDefined();
    const runDir = printedRunDir ?? "";

    expect(await pathExists(path.join(runDir, "run.json"))).toBe(true);
    expect(await pathExists(path.join(runDir, "events.jsonl"))).toBe(true);
    expect(await pathExists(path.join(runDir, "outputs"))).toBe(true);
    expect(await pathExists(path.join(runDir, "final-report.md"))).toBe(true);
    expect(await pathExists(path.join(runDir, "final-report.pdf"))).toBe(true);
    expect(await pathExists(path.join(runDir, "report.md"))).toBe(false);
    expect(stdout.join("")).toContain("Final report PDF:");
    expect(stdout.join("")).toContain("Final report MD:");

    const inventory = await readJson<{
      files: Array<{ path: string }>;
      summary: { file_count: number; manifest_files: string[] };
    }>(path.join(runDir, "outputs", "inventory.json"));
    const inventoryPaths = inventory.files.map((file) => file.path);

    expect(inventory.summary.file_count).toBeGreaterThan(0);
    expect(inventory.summary.manifest_files).toContain("package.json");
    expect(inventoryPaths).toEqual(
      expect.arrayContaining(["README.md", "package.json", "src/app.ts", "vibeshield-marker.txt"]),
    );

    const report = await readFile(path.join(runDir, "final-report.md"), "utf8");
    expect(report).toContain("# Security Report");
    expect(report).toContain("Repository: https://github.com/vibeshield/intake-fixture");
    expect(report).toContain("## Status:");
    expect(report).toContain("## Summary");
    expect(report).toContain("## Issues to fix");
    expect(report).toContain("## Leads to check");
    expect(report).not.toContain("syft");
    expect(report).not.toContain("trivy");
    expect(report).not.toContain("gitleaks");
    expect(report).not.toContain("## 0. Coverage");
    expect((await readFile(path.join(runDir, "final-report.pdf"))).subarray(0, 4).toString()).toBe(
      "%PDF",
    );
  });

  it("scans a local Git worktree with tracked and untracked non-ignored files only", async () => {
    const localRepo = await createLocalGitFilteredRepo();
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({
      runsRoot,
      sandboxProvider: provider,
      sourceInput: localRepo,
    });

    if (result.exitCode !== 0) {
      throw new Error(`Local scan unexpectedly failed: ${result.userMessage}`);
    }
    const runDir = result.runDir;
    const run = await readJson<{
      commit_sha?: string;
      source: {
        path: string;
        snapshot: { files: Array<{ path: string; sha256: string }> };
        type: string;
        url: string;
      };
    }>(path.join(runDir, "run.json"));
    const localRepoRealPath = await realpath(localRepo);
    expect(run.commit_sha).toBeUndefined();
    expect(run.source).toMatchObject({
      path: localRepoRealPath,
      type: "local",
      url: expect.stringContaining("file://"),
    });

    const snapshotPaths = run.source.snapshot.files.map((file) => file.path);
    expect(snapshotPaths).toEqual(
      expect.arrayContaining([".gitignore", "README.md", "src/app.ts", "src/untracked.ts"]),
    );
    expect(snapshotPaths).not.toEqual(
      expect.arrayContaining([
        ".env",
        "ignored.txt",
        "node_modules/package/index.js",
        "runs/run-local/event.jsonl",
      ]),
    );

    const inventory = await readJson<{
      files: Array<{ path: string; sha256?: string }>;
      source: { snapshot?: unknown; type: string; url: string };
      summary: { manifest_files: string[] };
    }>(path.join(runDir, "outputs", "inventory.json"));
    const inventoryPaths = inventory.files.map((file) => file.path);
    expect(inventory.source).toMatchObject({
      type: "local",
      url: run.source.url,
    });
    expect(inventory.source.snapshot).toBeUndefined();
    expect(inventoryPaths).toEqual(
      expect.arrayContaining([".gitignore", "README.md", "src/app.ts", "src/untracked.ts"]),
    );
    expect(inventoryPaths).not.toEqual(
      expect.arrayContaining([
        ".env",
        "ignored.txt",
        "node_modules/package/index.js",
        "runs/run-local/event.jsonl",
      ]),
    );

    const appFile = inventory.files.find((file) => file.path === "src/app.ts");
    expect(appFile?.sha256).toBe(
      "600705ad4c7b25cc0da4e57fd920d8269e1f2e51cd3afdea1bc12d92e557ecd3",
    );
  });

  it("refuses to resume a local run when the Git-filtered snapshot changed", async () => {
    const localRepo = await createLocalGitFilteredRepo();
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");
    const result = await runScan({
      runsRoot,
      sandboxProvider: provider,
      sourceInput: localRepo,
    });
    if (result.exitCode !== 0) {
      throw new Error(`Local scan unexpectedly failed: ${result.userMessage}`);
    }

    await writeFile(path.join(localRepo, "src", "untracked.ts"), "export const extra = false;\n");

    const resume = await runResume({
      runDir: result.runDir,
      sandboxProvider: provider,
    });

    if (resume.exitCode !== 1) {
      throw new Error("Local resume unexpectedly succeeded.");
    }
    expect(resume.userMessage).toContain("snapshot changed");
    expect(provider.createdSandboxIds).toHaveLength(1);
  });

  it("creates a fresh sandbox per run and keeps the checkout out of local artifacts", async () => {
    const { provider, sandboxRoot } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const first = await runScan({ sourceInput: fixtureUrl, runsRoot, sandboxProvider: provider });
    const second = await runScan({ sourceInput: fixtureUrl, runsRoot, sandboxProvider: provider });

    expect(first.exitCode).toBe(0);
    expect(second.exitCode).toBe(0);
    expect(provider.createdSandboxIds).toHaveLength(2);
    expect(provider.createdSandboxIds[0]).not.toBe(provider.createdSandboxIds[1]);
    expect(provider.liveSandboxIds).toHaveLength(0);

    for (const result of [first, second]) {
      expect(result.runDir).toBeDefined();
      const runDir = result.runDir ?? "";
      const run = await readJson<{
        sandbox: { id: string; cleanup: { deleted: boolean; success: boolean } };
      }>(path.join(runDir, "run.json"));

      expect(run.sandbox.cleanup).toMatchObject({ deleted: true, success: true });
      expect(await pathExists(path.join(runDir, "package.json"))).toBe(false);
      expect(await pathExists(path.join(runDir, "src", "app.ts"))).toBe(false);
      expect(await pathExists(path.join(runDir, ".git"))).toBe(false);

      const session = provider.sessions.find((candidate) => candidate.id === run.sandbox.id);
      expect(session).toBeDefined();
      expect(session?.repoPath.startsWith(sandboxRoot)).toBe(true);
      expect(session?.repoPath.startsWith(runDir)).toBe(false);
      expect(session?.commands.map((command) => command.stage)).toEqual(
        expect.arrayContaining(["clone", "commit", "inventory"]),
      );
      expect(session?.commands.every((command) => command.cwd.startsWith(sandboxRoot))).toBe(true);
    }
  });

  it("keeps the sandbox flow limited to controlled clone and read-only inventory", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ sourceInput: fixtureUrl, runsRoot, sandboxProvider: provider });

    expect(result.exitCode).toBe(0);
    const commands = provider.sessions.flatMap((session) => session.commands);
    expect(commands.length).toBeGreaterThan(0);
    expect(commands.every((command) => command.repoDefinedCommand === false)).toBe(true);
    expect(commands.map((command) => command.command).join("\n")).not.toMatch(
      /\b(npm|pnpm|yarn|bun|node scripts\/should-not-run|test|build|postinstall)\b/,
    );
  });

  it("leaves a failed run contract and deletes the sandbox after sandbox-created failure", async () => {
    const { provider } = await createProvider({ failAt: "inventory" });
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const result = await runScan({ sourceInput: fixtureUrl, runsRoot, sandboxProvider: provider });

    expect(result.exitCode).toBe(1);
    expect(result.runDir).toBeDefined();
    expect(provider.createdSandboxIds).toHaveLength(1);
    expect(provider.liveSandboxIds).toHaveLength(0);

    const runDir = result.runDir ?? "";
    const run = await readJson<{
      error: { stage: string; user_message: string };
      sandbox: { cleanup: { attempted: boolean; deleted: boolean; success: boolean } };
      status: string;
    }>(path.join(runDir, "run.json"));
    expect(run.status).toBe("failed");
    expect(run.error.stage).toBe("inventory");
    expect(run.error.user_message).toContain("inventory");
    expect(run.sandbox.cleanup).toMatchObject({
      attempted: true,
      deleted: true,
      success: true,
    });

    expect(await pathExists(path.join(runDir, "report.md"))).toBe(false);
    expect(await pathExists(path.join(runDir, "final-report.md"))).toBe(false);
    expect(await pathExists(path.join(runDir, "final-report.pdf"))).toBe(false);
  });
});
