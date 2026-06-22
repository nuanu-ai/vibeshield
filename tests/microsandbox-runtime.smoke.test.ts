/**
 * Live smoke test for the MicrosandboxRuntime adapter.
 *
 * Skipped by default — it boots a real microVM and needs the toolchain image
 * loaded. Run explicitly during acceptance:
 *   pnpm exec vitest run tests/microsandbox-runtime.smoke.test.ts
 *
 * It is intentionally not part of the default `pnpm test`: CI should not boot
 * VMs, and the deterministic product path never depends on this passing.
 */
import { describe, expect, it } from "vitest";
import { MicrosandboxRuntime } from "../src/adapters/microsandbox/runtime.js";

const TOOLCHAIN_TAG = process.env.VIBESHIELD_TOOLCHAIN_TAG ?? "vibeshield-toolchain:latest";

describe.skip("MicrosandboxRuntime (live)", () => {
  it("boots the toolchain image, writes a file, reads it back, destroys", async () => {
    const runtime = new MicrosandboxRuntime({ imageTag: TOOLCHAIN_TAG });
    const avail = await runtime.isAvailable();
    if (!avail.available) {
      console.warn("skipped:", avail.reason);
      return;
    }
    const session = await runtime.create({ name: "vs-smoke-test", imageTag: TOOLCHAIN_TAG });
    try {
      await session.uploadBytes("/tmp/vibe.txt", new TextEncoder().encode("hello-vibeshield"));
      const back = await session.read("/tmp/vibe.txt");
      expect(new TextDecoder().decode(back)).toBe("hello-vibeshield");
      // gitleaks is installed in the toolchain image
      const out = await session.exec(["gitleaks", "version"]);
      expect(out.exitCode).toBe(0);
    } finally {
      await runtime.destroy("vs-smoke-test");
    }
  }, 60_000);
});
