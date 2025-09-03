import { describe, it, expect, beforeEach, vi } from "vitest";

// Use per-test dynamic imports to avoid sharing module-initialization state
// across tests. This helps satisfy the QA constitution requirement for
// strict module isolation in stateful modules.

describe("reporting", () => {
  beforeEach(() => {
    // reset modules to ensure fresh module state when we import reporting
    vi.resetModules();
  });

  it("passes redacted context to production hook and does not throw", async () => {
    // Force production env
    const { environment } = await import("../../src/environment");
    const reporting = await import("../../src/reporting");

    environment.setExplicitEnv("production");

    // Install a hook that asserts it received a plain object without dangerous getters
    const hook = vi.fn((err: Error, context: Record<string, unknown>) => {
      expect(typeof context).toBe("object");
      expect(Object.keys(context)).not.toContain("password");
    });

    reporting.setProdErrorHook(hook);
    reporting.__test_setLastRefillForTesting(10000);

    reporting.reportProdError(new Error("boom"), {
      password: "s3cr3t",
      detail: "x",
    });

    expect(hook).toHaveBeenCalled();
  });
});
