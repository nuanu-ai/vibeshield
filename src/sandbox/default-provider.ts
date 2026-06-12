import { DaytonaSandboxProvider } from "./daytona.js";
import type { SandboxProvider } from "./types.js";

export function createDefaultSandboxProvider(): SandboxProvider {
  return new DaytonaSandboxProvider();
}
