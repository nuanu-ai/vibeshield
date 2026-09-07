import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Sandbox } from "microsandbox";
import { describe, expect, it } from "vitest";
import { FakeSandboxRuntime } from "../src/adapters/fake-sandbox.js";
import { MicrosandboxSession } from "../src/adapters/microsandbox/session.js";

describe("MicrosandboxSession", () => {
  it("streams sandbox exec events and still returns collected output", async () => {
    const session = new MicrosandboxSession(streamingSandbox(), "streaming-client");
    const events: string[] = [];

    const out = await session.exec(["joern", "--version"], {
      onEvent(event) {
        if (event.type === "stdout" || event.type === "stderr") {
          events.push(`${event.type}:${event.data}`);
        } else if (event.type === "exited") {
          events.push(`exited:${event.exitCode}`);
        } else {
          events.push(event.type);
        }
      },
    });

    expect(out).toEqual({ exitCode: 0, stdout: "joern 4.0.565\n", stderr: "warming cache\n" });
    expect(events).toEqual([
      "started",
      "stdout:joern 4.0.565\n",
      "stderr:warming cache\n",
      "exited:0",
    ]);
  });

  it("wraps live sandbox commands with a wall-clock timeout when requested", async () => {
    const commands: string[] = [];
    const configurations: string[] = [];
    const sandbox = streamingSandbox(commands);
    sandbox.fs = () =>
      ({
        write: async (_path: string, bytes: Buffer) => {
          configurations.push(bytes.toString());
        },
      }) as ReturnType<Sandbox["fs"]>;
    const session = new MicrosandboxSession(sandbox, "timeout-client");

    await session.exec(
      ["vibeshield-joern-extract", "--kind", "flows", "--cpg", "/work/app.cpg.bin"],
      {
        timeoutMs: 61_000,
        onEvent() {},
      },
    );

    expect(configurations.some((value) => value.includes('"timeoutMs":61000'))).toBe(true);
    expect(commands.at(-1)).toMatch(/node .*run-check.mjs .*\.json/);
  });

  it("aborts a hanging command and its child before reporting cancellation", async () => {
    const child = spawn(
      process.execPath,
      [
        "-e",
        'require("node:child_process").spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"inherit"});process.stdout.write("ready");setInterval(()=>{},1000)',
      ],
      { detached: true, stdio: ["ignore", "pipe", "ignore"] },
    );
    await once(child, "spawn");
    if (!child.stdout) throw new Error("Missing test readiness pipe");
    await once(child.stdout, "data");
    const pid = child.pid;
    if (pid === undefined) throw new Error("Test command did not start");
    let terminated = false;
    const exited = once(child, "exit");
    const sandbox = streamingSandbox();
    let ready!: () => void;
    const running = new Promise<void>((resolve) => {
      ready = resolve;
    });
    sandbox.shellStream = async () => {
      ready();
      return {
        signal: async () => {},
        recv: async () => {
          await exited;
          return null;
        },
        wait: async () => ({ code: 143 }),
      } as unknown as Awaited<ReturnType<Sandbox["shellStream"]>>;
    };
    const session = new MicrosandboxSession(sandbox, "abort-client", async () => {
      process.kill(-pid, "SIGKILL");
      await exited;
      terminated = true;
    });
    const controller = new AbortController();
    const execution = session.exec(["hang"], { signal: controller.signal }).then(
      () => "resolved",
      () => "cancelled",
    );
    await running;
    controller.abort();
    const outcome = await Promise.race([
      execution,
      new Promise((resolve) => setTimeout(() => resolve("hanging"), 100)),
    ]);
    try {
      expect(outcome).toBe("cancelled");
      expect(terminated).toBe(true);
      expect(() => process.kill(-pid, 0)).toThrow();
    } finally {
      if (!terminated) {
        process.kill(-pid, "SIGKILL");
        await exited;
      }
    }
  });

  it("removes the VM despite a pending signal acknowledgement and waits for confirmed cleanup", async () => {
    const sandbox = streamingSandbox();
    let markRunning!: () => void;
    const running = new Promise<void>((resolve) => {
      markRunning = resolve;
    });
    sandbox.shellStream = async () =>
      ({
        signal: () => new Promise(() => {}),
        recv: () => {
          markRunning();
          return new Promise(() => {});
        },
      }) as unknown as Awaited<ReturnType<Sandbox["shellStream"]>>;
    let cleanupCalled = false;
    let confirmCleanup!: () => void;
    const confirmed = new Promise<void>((resolve) => {
      confirmCleanup = resolve;
    });
    const session = new MicrosandboxSession(sandbox, "pending-signal-client", async () => {
      cleanupCalled = true;
      await confirmed;
    });
    const controller = new AbortController();
    let outcome = "pending";
    const execution = session.exec(["hang"], { signal: controller.signal }).then(
      () => {
        outcome = "resolved";
      },
      () => {
        outcome = "cancelled";
      },
    );
    await running;
    controller.abort();
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(cleanupCalled).toBe(true);
    expect(outcome).toBe("pending");
    confirmCleanup();
    await Promise.race([execution, new Promise((resolve) => setTimeout(resolve, 100))]);
    expect(outcome).toBe("cancelled");
  });

  it("explains closed AgentClient errors with operation context", async () => {
    const session = new MicrosandboxSession(closedClientSandbox(), "closed-client");

    await expect(session.exec(["trivy", "image", "--download-db-only"])).rejects.toThrow(
      "Microsandbox session closed while running in Microsandbox: trivy image --download-db-only",
    );
    await expect(session.exec(["trivy", "image", "--download-db-only"])).rejects.toThrow(
      "not a scan finding",
    );
  });
});

describe("bounded guest wrapper", () => {
  it("cancels a pending fake command and removes its session", async () => {
    const runtime = new FakeSandboxRuntime({ exec: () => new Promise(() => {}) });
    const session = await runtime.create({ name: "fake-pending", imageTag: "fixture" });
    await session.uploadBytes("/work/data", new Uint8Array([1]));
    const controller = new AbortController();
    const execution = session.exec(["hang"], { signal: controller.signal }).then(
      () => "resolved",
      () => "cancelled",
    );
    controller.abort();
    const result = await Promise.race([
      execution,
      new Promise((resolve) => setTimeout(() => resolve("hanging"), 100)),
    ]);
    expect(result).toBe("cancelled");
    expect(session.files.size).toBe(0);
    expect(runtime.sessions.size).toBe(0);
  });
  it("honors already cancelled fake creation and execution", async () => {
    const runtime = new FakeSandboxRuntime();
    const signal = AbortSignal.abort();
    await expect(
      runtime.create({ name: "cancelled", imageTag: "fixture", signal }),
    ).rejects.toThrow();
    expect(runtime.sessions.size).toBe(0);
    const session = await runtime.create({ name: "active", imageTag: "fixture" });
    await expect(session.exec(["never-start"], { signal })).rejects.toThrow();
    expect(session.invocations).toHaveLength(0);
  });

  it("rejects output symlinks without changing the target", async () => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "vs-symlink-")));
    const workspace = join(directory, "work");
    await mkdir(workspace);
    const target = join(directory, "untouched");
    await writeFile(target, "untouched");
    const stdoutPath = join(workspace, "output");
    await symlink(target, stdoutPath);
    const config = join(directory, "config.json");
    await writeFile(
      config,
      JSON.stringify({
        argv: [process.execPath, "-e", 'process.stdout.write("overwrite")'],
        timeoutMs: 1000,
        workspace,
        maxWorkspaceBytes: 1024 * 1024,
        stdoutPath,
      }),
      { mode: 0o600 },
    );
    const wrapper = spawn(process.execPath, ["toolchain/run-check.mjs", config], {
      stdio: "ignore",
    });
    const [code] = await once(wrapper, "exit");
    try {
      expect(code).toBe(125);
      expect(await readFile(target, "utf8")).toBe("untouched");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("stops oversized scanner output at its file limit", async () => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "vs-bound-")));
    const workspace = join(directory, "work");
    await mkdir(workspace);
    const stdoutPath = join(workspace, "output");
    const config = join(directory, "config.json");
    await writeFile(
      config,
      JSON.stringify({
        argv: [
          process.execPath,
          "-e",
          'process.stdout.write("x".repeat(4*1024*1024));setInterval(()=>{},1000)',
        ],
        timeoutMs: 1000,
        workspace,
        maxWorkspaceBytes: 1024 * 1024,
        stdoutPath,
      }),
      { mode: 0o600 },
    );
    const wrapper = spawn(process.execPath, ["toolchain/run-check.mjs", config], {
      stdio: "ignore",
    });
    const [code] = await once(wrapper, "exit");
    try {
      expect(code).toBe(125);
      expect((await stat(stdoutPath)).size).toBeLessThanOrEqual(1024 * 1024);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
  it("times out and kills the command process group including its child", async () => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "vs-wrapper-")));
    const workspace = join(directory, "work");
    await mkdir(workspace);
    const pidPath = join(workspace, "pids");
    const config = join(directory, "config.json");
    const kernelRace = join(directory, "kernel-race.mjs");
    // XNU may return EPERM when a duplicate signal finds only exiting group members.
    // Deliver the first real signal; make that observed kernel race deterministic.
    await writeFile(
      kernelRace,
      `const kill = process.kill.bind(process); let termSent = false;
process.kill = (pid, signal) => {
  if (pid < 0 && signal === "SIGTERM") {
    if (termSent) throw Object.assign(new Error("Group already exiting"), { code: "EPERM" });
    termSent = true;
  }
  return kill(pid, signal);
};`,
      { mode: 0o600 },
    );
    await writeFile(
      config,
      JSON.stringify({
        argv: [
          process.execPath,
          "-e",
          `const c=require("node:child_process").spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"inherit"});require("node:fs").writeFileSync(${JSON.stringify(pidPath)},process.pid+" "+c.pid);setInterval(()=>{},1000)`,
        ],
        timeoutMs: 250,
        workspace,
        maxWorkspaceBytes: 1024 * 1024,
        stdoutPath: null,
      }),
      { mode: 0o600 },
    );
    const wrapper = spawn(
      process.execPath,
      ["--import", kernelRace, "toolchain/run-check.mjs", config],
      {
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const diagnostic: Buffer[] = [];
    wrapper.stderr.on("data", (data) => diagnostic.push(data));
    const code = await Promise.race([
      once(wrapper, "close").then(([value]) => value),
      new Promise((resolve) => setTimeout(() => resolve("hanging"), 1000)),
    ]);
    try {
      expect(code, Buffer.concat(diagnostic).toString("utf8")).toBe(124);
      const pids = (await readFile(pidPath, "utf8")).split(" ").map(Number);
      for (const pid of pids) expect(() => process.kill(pid, 0)).toThrow();
    } finally {
      for (const pid of (await readFile(pidPath, "utf8")).split(" ").map(Number)) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {}
      }
      wrapper.kill("SIGKILL");
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("keeps only a 64 KiB diagnostic tail and bounds scanner output", async () => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "vs-output-")));
    const workspace = join(directory, "work");
    await mkdir(workspace);
    const config = join(directory, "config.json");
    await writeFile(
      config,
      JSON.stringify({
        argv: [
          process.execPath,
          "-e",
          'process.stdout.write("x".repeat(100000));process.stderr.write("y".repeat(100000))',
        ],
        timeoutMs: 1000,
        workspace,
        maxWorkspaceBytes: 1024 * 1024,
        stdoutPath: join(workspace, "scanner.json"),
      }),
      { mode: 0o600 },
    );
    const wrapper = spawn(process.execPath, ["toolchain/run-check.mjs", config], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    wrapper.stdout.on("data", (data) => stdout.push(data));
    wrapper.stderr.on("data", (data) => stderr.push(data));
    const [code] = await once(wrapper, "close");
    try {
      expect(code).toBe(0);
      expect(Buffer.concat(stdout).length).toBe(65536);
      expect(Buffer.concat(stderr).length).toBe(65536);
      expect((await readFile(join(workspace, "scanner.json"))).length).toBe(100000);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

function streamingSandbox(commands?: string[]): Sandbox {
  const encoder = new TextEncoder();
  const events = [
    { kind: "started", pid: 42 },
    { kind: "stdout", data: encoder.encode("joern 4.0.565\n") },
    { kind: "stderr", data: encoder.encode("warming cache\n") },
    { kind: "exited", code: 0 },
  ];
  return {
    async shellStream(command: string) {
      commands?.push(command);
      let index = 0;
      return {
        async recv() {
          const event = events[index];
          index += 1;
          return event ?? null;
        },
        async wait() {
          return { code: 0, success: true };
        },
      };
    },
    fs() {
      return {
        async write() {},
        async read() {
          return new Uint8Array();
        },
      };
    },
    async stop() {},
  } as unknown as Sandbox;
}

function closedClientSandbox(): Sandbox {
  return {
    async shell() {
      throw new Error("[AgentClient] agent client error: client closed");
    },
    fs() {
      return {
        async write() {
          throw new Error("[AgentClient] agent client error: client closed");
        },
        async read() {
          throw new Error("[AgentClient] agent client error: client closed");
        },
      };
    },
    async stop() {},
  } as unknown as Sandbox;
}
