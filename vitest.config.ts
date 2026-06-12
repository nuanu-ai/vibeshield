import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    clearMocks: true,
    restoreMocks: true,
    testTimeout: 20_000,
  },
});
