import { describe, expect, it } from "vitest";
import { type FakeExecHandler, FakeSandboxRuntime } from "../src/adapters/fake-sandbox.js";

describe("FakeSandboxRuntime", () => {
  it("reports available by default and flips when set", async () => {
    const rt = new FakeSandboxRuntime();
    expect((await rt.isAvailable()).available).toBe(true);
    rt.setAvailability({ available: false, reason: "no image" });
    const a = await rt.isAvailable();
    expect(a.available).toBe(false);
    expect(a.reason).toBe("no image");
  });

  it("round-trips uploaded bytes through download and read", async () => {
    const rt = new FakeSandboxRuntime();
    const session = await rt.create({ name: "s1", imageTag: "img" });
    const payload = new Uint8Array([1, 2, 3, 4]);
    await session.uploadBytes("/work/file.txt", payload);
    expect(await session.read("/work/file.txt")).toEqual(payload);
    expect(await session.download("/work/file.txt")).toEqual(payload);
  });

  it("routes exec through the pluggable handler and records the invocation", async () => {
    const handler: FakeExecHandler = (cmd) => {
      if (cmd[0] === "gitleaks") {
        return { exitCode: 1, stdout: '[{"RuleID":"x"}]', stderr: "" };
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    };
    const rt = new FakeSandboxRuntime({ exec: handler });
    const session = await rt.create({ name: "scan", imageTag: "img" });
    const out = await session.exec(["gitleaks", "detect", "--source", "."]);
    expect(out.exitCode).toBe(1);
    expect(out.stdout).toContain("RuleID");
    expect(session.invocations).toHaveLength(1);
    expect(session.invocations[0]?.command).toEqual(["gitleaks", "detect", "--source", "."]);
    expect(rt.invocations).toHaveLength(1);
  });

  it("destroys sessions by name", async () => {
    const rt = new FakeSandboxRuntime();
    await rt.create({ name: "tmp", imageTag: "img" });
    expect(rt.sessions.has("tmp")).toBe(true);
    await rt.destroy("tmp");
    expect(rt.sessions.has("tmp")).toBe(false);
  });
});
