import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    clearMocks: true,
    exclude: [
      ...configDefaults.exclude,
      "**/.local/**",
      "tests/live/**",
      "tests/microsandbox-runtime.smoke.test.ts",
    ],
    restoreMocks: true,
    testTimeout: 20_000,
  },
});
