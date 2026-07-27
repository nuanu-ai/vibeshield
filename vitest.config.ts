import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    clearMocks: true,
    exclude: [...configDefaults.exclude, "**/.local/**"],
    restoreMocks: true,
    testTimeout: 20_000,
  },
});
