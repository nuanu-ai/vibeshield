import { expect, it } from "vitest";
import { verifyLivePrerequisites } from "./support/live-runtime.js";

it("requires the real runtime and verified five-engine image; missing prerequisites fail", async () => {
  await expect(verifyLivePrerequisites()).resolves.toHaveProperty("tools.osv", "2.3.8");
}, 180000);
