import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli/run-cli.js";
import { runScan } from "../src/run/run-scan.js";
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
  it("rejects unsupported inputs before sandbox creation", async () => {
    const { provider } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");
    const unsupportedInputs = [
      "/tmp/local-repo",
      "../local-repo",
      "repo.zip",
      "not-a-url",
      "https://gitlab.com/owner/repo",
      "https://github.com/owner/repo/archive/refs/heads/main.zip",
    ];

    for (const input of unsupportedInputs) {
      const result = await runScan({
        repoUrlInput: input,
        runsRoot,
        sandboxProvider: provider,
      });

      if (result.exitCode !== 1) {
        throw new Error("Unsupported input unexpectedly succeeded.");
      }
      expect(result.runDir).toBeUndefined();
      expect(result.userMessage).toContain("VibeShield accepts only GitHub repository URLs");
    }

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
    expect(await pathExists(path.join(runDir, "report.md"))).toBe(true);

    const inventory = await readJson<{
      files: Array<{ path: string }>;
      summary: { file_count: number; manifest_files: string[] };
    }>(path.join(runDir, "outputs", "repo-inventory.json"));
    const inventoryPaths = inventory.files.map((file) => file.path);

    expect(inventory.summary.file_count).toBeGreaterThan(0);
    expect(inventory.summary.manifest_files).toContain("package.json");
    expect(inventoryPaths).toEqual(
      expect.arrayContaining(["README.md", "package.json", "src/app.ts", "vibeshield-marker.txt"]),
    );

    const report = await readFile(path.join(runDir, "report.md"), "utf8");
    expect(report).toContain("# VibeShield Repository Map");
    expect(report).toContain("## 0. Coverage");
    expect(report).not.toContain("not a security audit");
    expect(report).not.toContain("No security findings or verdict");
    expect(report).not.toContain("outputs/repo-inventory.json");
  });

  it("creates a fresh sandbox per run and keeps the checkout out of local artifacts", async () => {
    const { provider, sandboxRoot } = await createProvider();
    const runsRoot = await createTempRoot("vibeshield-runs-");

    const first = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });
    const second = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });

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

    const result = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });

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

    const result = await runScan({ repoUrlInput: fixtureUrl, runsRoot, sandboxProvider: provider });

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

    const report = await readFile(path.join(runDir, "report.md"), "utf8");
    expect(report).toContain("Scan did not complete");
    expect(report).toContain("Failed stage: inventory");
    expect(report).not.toContain("Status: success");
    expect(report).not.toContain("Security verdict");
  });
});
