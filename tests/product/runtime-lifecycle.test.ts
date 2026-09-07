import { mkdtempSync, realpathSync } from "node:fs";
import { mkdtemp, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Sandbox } from "microsandbox";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MicrosandboxRuntime } from "../../src/adapters/microsandbox/runtime.js";
import {
  OWNER_LABEL,
  reconcileOwnedRuntime,
  recordRuntimeOwnership,
} from "../../src/adapters/runtime-ownership.js";

const state = vi.hoisted(() => ({
  running: false,
  removeFails: false,
  stillListed: false,
  names: new Set<string>(),
}));
vi.mock("node:child_process", async (original) => ({
  ...(await original<typeof import("node:child_process")>()),
  execFile: (
    file: string,
    args: string[],
    options: unknown,
    last?: (error: Error | null, output?: unknown) => void,
  ) => {
    const callback = (last ?? options) as (error: Error | null, output?: unknown) => void;
    if (file === "sh") return callback(null, { stdout: "/test-home\n", stderr: "" });
    if (args[0] === "remove") {
      if (state.running) return callback(new Error("sandbox still running"));
      if (state.removeFails) return callback(new Error("fixture removal refused"));
      if (!state.stillListed) state.names.delete(args.at(-1) ?? "");
    }
    callback(null, { stdout: [...state.names].join("\n"), stderr: "" });
  },
}));

const directories: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  state.names.clear();
  state.running = false;
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

function makeRemovalRuntime(options: { removeFails: boolean; stillListed: boolean }) {
  Object.assign(state, options);
  state.names.add("vibeshield-web-test");
  vi.spyOn(Sandbox, "remove").mockImplementation(async (name) => {
    if (state.running) throw new Error("sandbox still running");
    if (state.removeFails) throw new Error("fixture SDK removal refused");
    if (!state.stillListed) state.names.delete(name);
  });
  vi.spyOn(Sandbox, "list").mockImplementation(
    async () =>
      [...state.names].map((name) => ({
        name,
        killWithTimeout: async () => {
          state.running = false;
        },
      })) as unknown as Awaited<ReturnType<typeof Sandbox.list>>,
  );
  const ownerDir = realpathSync(mkdtempSync(join(tmpdir(), "vs-removal-test-")));
  directories.push(ownerDir);
  return new MicrosandboxRuntime({ ownerDir });
}

describe("runtime lifecycle", () => {
  it("does not delete another owner's sandbox when creation loses a name race", async () => {
    const runtime = makeRemovalRuntime({ removeFails: false, stillListed: false });
    state.names.clear();
    const builder = new Proxy(
      {},
      {
        get: (_target, key) =>
          key === "create"
            ? async () => {
                state.names.add("name-race");
                throw new Error("already exists");
              }
            : () => builder,
      },
    );
    vi.spyOn(Sandbox, "builder").mockReturnValue(builder as ReturnType<typeof Sandbox.builder>);
    vi.spyOn(Sandbox, "list").mockImplementation(
      async () =>
        [...state.names].map((name) => ({
          name,
          config: () => ({ labels: { [OWNER_LABEL]: "another-owner" } }),
          killWithTimeout: async () => {},
        })) as unknown as Awaited<ReturnType<typeof Sandbox.list>>,
    );
    await expect(runtime.create({ name: "name-race", imageTag: "fixture" })).rejects.toThrow();
    expect([...state.names]).toEqual(["name-race"]);
  });
  it("kills a running sandbox before attempting verified removal", async () => {
    const runtime = makeRemovalRuntime({ removeFails: false, stillListed: false });
    state.running = true;
    const result = await runtime.destroy("vibeshield-web-test").then(
      () => "removed",
      () => "failed",
    );
    expect(result).toBe("removed");
    expect(state.running).toBe(false);
    expect(state.names.size).toBe(0);
  });
  it("does not claim cleanup after a failed removal", async () => {
    const runtime = makeRemovalRuntime({ removeFails: true, stillListed: true });
    await expect(runtime.destroy("vibeshield-web-test")).rejects.toThrow(/cleanup/i);
  });

  it("does not trust a successful removal while the VM is still listed", async () => {
    const runtime = makeRemovalRuntime({ removeFails: false, stillListed: true });
    await expect(runtime.destroy("vibeshield-web-test")).rejects.toThrow(/cleanup/i);
  });

  it("removes a sandbox returned after pending creation was cancelled", async () => {
    const runtime = makeRemovalRuntime({ removeFails: false, stillListed: false });
    state.names.clear();
    let finish!: (sandbox: Sandbox) => void;
    const pending = new Promise<Sandbox>((resolve) => {
      finish = resolve;
    });
    const builder = new Proxy(
      {},
      { get: (_target, key) => (key === "create" ? () => pending : () => builder) },
    );
    vi.spyOn(Sandbox, "builder").mockReturnValue(builder as ReturnType<typeof Sandbox.builder>);
    const controller = new AbortController();
    const creation = runtime.create({
      name: "vibeshield-web-test",
      imageTag: "fixture",
      signal: controller.signal,
    });
    await new Promise((resolve) => setTimeout(resolve, 30));
    controller.abort();
    state.names.add("vibeshield-web-test");
    state.running = true;
    vi.spyOn(Sandbox, "list").mockImplementation(
      async () =>
        [...state.names].map((name) => ({
          name,
          killWithTimeout: async () => {
            throw new Error("External handle cannot close owning connection");
          },
        })) as unknown as Awaited<ReturnType<typeof Sandbox.list>>,
    );
    finish({
      killWithTimeout: async () => {
        state.running = false;
      },
    } as unknown as Sandbox);
    const outcome = await creation.then(
      () => "created",
      () => "cancelled",
    );
    expect(outcome).toBe("cancelled");
    expect(state.names.has("vibeshield-web-test")).toBe(false);
  });

  it("records ownership before pending creation", async () => {
    makeRemovalRuntime({ removeFails: false, stillListed: false });
    state.names.clear();
    const ownerDir = await realpath(await mkdtemp(join(tmpdir(), "vs-owner-test-")));
    directories.push(ownerDir);
    let finish!: (sandbox: Sandbox) => void;
    const pending = new Promise<Sandbox>((resolve) => {
      finish = resolve;
    });
    const builder = new Proxy(
      {},
      { get: (_target, key) => (key === "create" ? () => pending : () => builder) },
    );
    vi.spyOn(Sandbox, "builder").mockReturnValue(builder as ReturnType<typeof Sandbox.builder>);
    const runtime = new MicrosandboxRuntime({ ownerDir });
    const controller = new AbortController();
    const creation = runtime.create({
      name: "vibeshield-web-pending",
      imageTag: "fixture",
      signal: controller.signal,
    });
    await new Promise((resolve) => setTimeout(resolve, 30));
    const markers = await readdir(ownerDir);
    controller.abort();
    finish({ stop: async () => {}, kill: async () => {} } as unknown as Sandbox);
    await creation.catch(() => {});
    expect(markers).toHaveLength(1);
  });

  it("reconciles only matching ownership and ignores unrelated VMs and symlink markers", async () => {
    const runtime = makeRemovalRuntime({ removeFails: false, stillListed: false });
    state.names.clear();
    const ownerDir = await realpath(await mkdtemp(join(tmpdir(), "vs-owner-safe-")));
    directories.push(ownerDir);
    const owned = await recordRuntimeOwnership(ownerDir, "owned");
    const mismatch = await recordRuntimeOwnership(ownerDir, "unrelated");
    const target = join(ownerDir, "outside-marker");
    await writeFile(target, JSON.stringify({ name: "forged", token: owned.token }), {
      mode: 0o600,
    });
    await symlink(target, join(ownerDir, "forged.json"));
    for (const name of ["owned", "unrelated", "forged", "unmarked"]) state.names.add(name);
    vi.spyOn(Sandbox, "list").mockImplementation(
      async () =>
        [...state.names].map((name) => ({
          name,
          config: () => ({
            labels: { [OWNER_LABEL]: name === "unrelated" ? "different-owner" : owned.token },
          }),
        })) as unknown as Awaited<ReturnType<typeof Sandbox.list>>,
    );
    await reconcileOwnedRuntime(runtime, ownerDir);
    expect([...state.names].sort()).toEqual(["forged", "unmarked", "unrelated"]);
    expect(await readdir(ownerDir)).toContain(`${mismatch.name}.json`);
    expect(await readdir(ownerDir)).toContain("outside-marker");
    expect(await readdir(ownerDir)).not.toContain("owned.json");
  });
});
