import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  type DaytonaClientLike,
  type DaytonaExecuteResponse,
  type DaytonaSandboxLike,
  DaytonaSandboxProvider,
  missingDaytonaEnvVars,
  readDaytonaConfigFromEnv,
} from "../src/sandbox/daytona.js";
import { createDefaultSandboxProvider } from "../src/sandbox/default-provider.js";

const repo = {
  owner: "octocat",
  repo: "Hello-World",
  type: "github" as const,
  url: "https://github.com/octocat/Hello-World",
};

const tempFiles: string[] = [];

afterEach(async () => {
  await Promise.all(tempFiles.splice(0).map((file) => rm(file, { force: true })));
});

describe("Daytona production adapter boundary", () => {
  it("uses the real Daytona provider as the default sandbox provider", () => {
    expect(createDefaultSandboxProvider()).toBeInstanceOf(DaytonaSandboxProvider);
  });

  it("requires only DAYTONA_API_KEY and treats API URL and target as optional overrides", () => {
    const previousEnv = {
      DAYTONA_API_KEY: process.env.DAYTONA_API_KEY,
      DAYTONA_API_URL: process.env.DAYTONA_API_URL,
      DAYTONA_TARGET: process.env.DAYTONA_TARGET,
    };

    try {
      delete process.env.DAYTONA_API_KEY;
      delete process.env.DAYTONA_API_URL;
      delete process.env.DAYTONA_TARGET;
      expect(missingDaytonaEnvVars()).toEqual(["DAYTONA_API_KEY"]);

      process.env.DAYTONA_API_KEY = "test-api-key";
      process.env.DAYTONA_API_URL = "";
      process.env.DAYTONA_TARGET = "";

      expect(missingDaytonaEnvVars()).toEqual([]);
      expect(readDaytonaConfigFromEnv()).toEqual({ apiKey: "test-api-key" });

      process.env.DAYTONA_API_URL = "https://example.daytona.local";
      process.env.DAYTONA_TARGET = "eu";

      expect(readDaytonaConfigFromEnv()).toEqual({
        apiKey: "test-api-key",
        apiUrl: "https://example.daytona.local",
        target: "eu",
      });
    } finally {
      restoreEnv("DAYTONA_API_KEY", previousEnv.DAYTONA_API_KEY);
      restoreEnv("DAYTONA_API_URL", previousEnv.DAYTONA_API_URL);
      restoreEnv("DAYTONA_TARGET", previousEnv.DAYTONA_TARGET);
    }
  });

  it("drives create, clone, commit, inventory, pull, and delete through the SDK boundary", async () => {
    const sandbox = new MockDaytonaSandbox();
    const client = new MockDaytonaClient(sandbox);
    const provider = new DaytonaSandboxProvider({
      client,
      commandTimeoutSeconds: 7,
      createTimeoutSeconds: 11,
      deleteTimeoutSeconds: 13,
      downloadTimeoutSeconds: 17,
    });

    const session = await provider.createSandbox({ repo, runId: "run_test_123" });
    const cloneResult = await session.cloneRepository(repo);
    const inventory = await session.generateInventory({
      commitSha: cloneResult.commitSha,
      generatedAt: "2026-06-12T00:00:00.000Z",
      repo,
    });
    const localArtifactPath = path.join(tmpdir(), `vibeshield-daytona-${Date.now()}.json`);
    tempFiles.push(localArtifactPath);
    await session.pullFile(inventory.sandboxPath, localArtifactPath);
    await session.delete();

    expect(client.createCalls).toEqual([
      {
        options: { timeout: 11 },
        params: expect.objectContaining({
          ephemeral: true,
          labels: expect.objectContaining({
            app: "vibeshield",
            run_id: "run_test_123",
            source_owner: "octocat",
            source_repo: "Hello-World",
            workflow: "repository-map",
          }),
          language: "typescript",
          public: false,
        }),
      },
    ]);
    expect(sandbox.gitCloneCalls).toEqual([
      {
        path: "repo",
        url: repo.url,
      },
    ]);
    expect(sandbox.executeCommandCalls).toEqual([
      {
        command: "git rev-parse HEAD",
        cwd: "repo",
        env: {},
        timeout: 7,
      },
    ]);
    expect(cloneResult.commitSha).toBe("abc123");

    expect(sandbox.codeRunCalls).toHaveLength(1);
    expect(sandbox.codeRunCalls[0]?.timeout).toBe(7);
    expect(sandbox.codeRunCalls[0]?.code).toContain("lstat");
    expect(sandbox.codeRunCalls[0]?.code).toContain("repo-inventory.json");
    expect(sandbox.codeRunCalls[0]?.code).toContain("inventory_location");
    expect(sandbox.codeRunCalls[0]?.code).not.toMatch(
      /\b(npm install|pnpm install|yarn install|bun install|npm run|pnpm run|yarn run|postinstall)\b/,
    );

    expect(sandbox.downloadFileCalls).toEqual([
      {
        localPath: localArtifactPath,
        remotePath: "vibeshield/artifacts/repo-inventory.json",
        timeout: 17,
      },
    ]);
    expect(await readFile(localArtifactPath, "utf8")).toBe("{}\n");
    expect(sandbox.deleteCalls).toEqual([{ timeout: 13 }]);
  });

  it("attributes artifact pull failures to the caller stage and artifact context", async () => {
    const sandbox = new MockDaytonaSandbox();
    sandbox.downloadFailure = new Error("download unavailable");
    const provider = new DaytonaSandboxProvider({
      client: new MockDaytonaClient(sandbox),
      downloadTimeoutSeconds: 17,
    });
    const session = await provider.createSandbox({ repo, runId: "run_test_123" });
    const localArtifactPath = path.join(tmpdir(), `vibeshield-daytona-missing-${Date.now()}.json`);
    tempFiles.push(localArtifactPath);

    await expect(
      session.pullFile("vibeshield/artifacts/pi/metadata.json", localArtifactPath, {
        artifact: "pi/metadata.json",
        job: "pi-repository-map",
        stage: "pi",
      }),
    ).rejects.toMatchObject({
      stage: "pi",
      userMessage: expect.stringContaining("pi/metadata.json"),
    });

    expect(sandbox.downloadFileCalls).toEqual([
      {
        localPath: localArtifactPath,
        remotePath: "vibeshield/artifacts/pi/metadata.json",
        timeout: 17,
      },
    ]);
  });
});

class MockDaytonaClient implements DaytonaClientLike {
  readonly createCalls: Array<{ options?: { timeout?: number }; params?: unknown }> = [];

  constructor(private readonly sandbox: DaytonaSandboxLike) {}

  async create(params?: unknown, options?: { timeout?: number }): Promise<DaytonaSandboxLike> {
    const call: { options?: { timeout?: number }; params?: unknown } = {};
    if (options !== undefined) {
      call.options = options;
    }
    if (params !== undefined) {
      call.params = params;
    }
    this.createCalls.push(call);
    return this.sandbox;
  }
}

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}

class MockDaytonaSandbox implements DaytonaSandboxLike {
  readonly deleteCalls: Array<{ timeout?: number }> = [];
  readonly downloadFileCalls: Array<{ localPath: string; remotePath: string; timeout?: number }> =
    [];
  readonly executeCommandCalls: Array<{
    command: string;
    cwd?: string;
    env?: Record<string, string>;
    timeout?: number;
  }> = [];
  readonly gitCloneCalls: Array<{ path: string; url: string }> = [];
  readonly codeRunCalls: Array<{ code: string; timeout?: number }> = [];
  readonly id = "daytona-sandbox-123";
  downloadFailure?: Error;

  readonly fs = {
    downloadFile: async (remotePath: string, localPath: string, timeout?: number) => {
      const call: { localPath: string; remotePath: string; timeout?: number } = {
        localPath,
        remotePath,
      };
      if (timeout !== undefined) {
        call.timeout = timeout;
      }
      this.downloadFileCalls.push(call);
      if (this.downloadFailure !== undefined) {
        throw this.downloadFailure;
      }
      await import("node:fs/promises").then(({ writeFile }) =>
        writeFile(localPath, "{}\n", "utf8"),
      );
    },
  };

  readonly git = {
    clone: async (url: string, clonePath: string) => {
      this.gitCloneCalls.push({ path: clonePath, url });
    },
  };

  readonly process = {
    codeRun: async (code: string, _params?: unknown, timeout?: number) => {
      const call: { code: string; timeout?: number } = { code };
      if (timeout !== undefined) {
        call.timeout = timeout;
      }
      this.codeRunCalls.push(call);
      return { exitCode: 0, result: "" } satisfies DaytonaExecuteResponse;
    },
    executeCommand: async (
      command: string,
      cwd?: string,
      env?: Record<string, string>,
      timeout?: number,
    ) => {
      const call: {
        command: string;
        cwd?: string;
        env?: Record<string, string>;
        timeout?: number;
      } = { command };
      if (cwd !== undefined) {
        call.cwd = cwd;
      }
      if (env !== undefined) {
        call.env = env;
      }
      if (timeout !== undefined) {
        call.timeout = timeout;
      }
      this.executeCommandCalls.push(call);
      return { artifacts: { stdout: "abc123\n" }, exitCode: 0, result: "abc123\n" };
    },
  };

  async delete(timeout?: number): Promise<void> {
    const call: { timeout?: number } = {};
    if (timeout !== undefined) {
      call.timeout = timeout;
    }
    this.deleteCalls.push(call);
  }
}
