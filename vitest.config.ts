import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: ["node_modules/**", "dist/**"],
    environment: "jsdom",
    globals: true,
    setupFiles: ["tests/setup/global-dompurify.ts"],
    environmentOptions: {
      jsdom: {
        url: "http://localhost:3000",
      },
    },
    coverage: {
      provider: "v8" as const,
      reporter: ["text", "json", "html", "lcov"],
      exclude: [
        "node_modules/**",
        "dist/**",
        "tests/**",
        "**/*.d.ts",
        "**/*.config.*",
        "coverage/**",
        "demo/**",
        "scripts/**",
        "tools/**",
        "tmp-*/**",
        ".husky/**",
        ".vscode/**",
        ".github/**",
        ".sonarlint/**",
        ".mcp/**"
      ],
      include: ["src/**", "server/**", "tools/**", "scritps/**"],
      all: true,
      thresholds: {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80
        }
      }
    }
  },
  define: {
    __TEST__: false,
    "process.env.NODE_ENV": JSON.stringify("test"),
    "process.env.SECURITY_KIT_ALLOW_TEST_APIS": JSON.stringify("true"),
  },
});
