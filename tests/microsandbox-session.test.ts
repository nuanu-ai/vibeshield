import type { Sandbox } from "microsandbox";
import { describe, expect, it } from "vitest";
import { MicrosandboxSession } from "../src/adapters/microsandbox/session.js";

describe("MicrosandboxSession", () => {
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
