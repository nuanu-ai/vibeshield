import type { Sandbox } from "microsandbox";
import { describe, expect, it } from "vitest";
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
    const session = new MicrosandboxSession(streamingSandbox(commands), "timeout-client");

    await session.exec(
      ["vibeshield-joern-extract", "--kind", "flows", "--cpg", "/work/app.cpg.bin"],
      {
        timeoutMs: 61_000,
        onEvent() {},
      },
    );

    expect(commands).toEqual([
      "timeout --kill-after=5s 61s vibeshield-joern-extract --kind flows --cpg /work/app.cpg.bin",
    ]);
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
