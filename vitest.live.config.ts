import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    include: ["tests/live/**/*.test.ts", "tests/microsandbox-runtime.smoke.test.ts"],
    fileParallelism: false,
    maxWorkers: 1,
    testTimeout: 900000,
    hookTimeout: 180000,
  },
});
