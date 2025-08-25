import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: ["node_modules/**", "dist/**", "tests/old_tests/**"],
    environment: "jsdom",
    globals: true,
    setupFiles: ["tests/setup/global-dompurify.ts"],
  },
});
