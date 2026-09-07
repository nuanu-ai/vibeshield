import { expect, it } from "vitest";
import { liveSandboxName } from "../support/live-runtime.js";

it("keeps disposable VM names inside the guest hostname limit with unique identities", () => {
  const first = liveSandboxName("prerequisites");
  expect(Buffer.byteLength(first)).toBeLessThanOrEqual(64);
  expect(first).toMatch(/^[a-z0-9-]+$/);
  expect(liveSandboxName("prerequisites")).not.toBe(first);
  expect(Buffer.byteLength(liveSandboxName("a".repeat(128)))).toBeLessThanOrEqual(64);
});
