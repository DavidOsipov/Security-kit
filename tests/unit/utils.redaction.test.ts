import { describe, it, expect, beforeEach, vi } from "vitest";

// Use per-test dynamic imports to avoid sharing logging/config state between
// test files. Callers should reset modules before importing stateful modules.

describe("utils._redact", () => {
  beforeEach(() => {
    // ensure development environment for tests
    vi.resetModules();
    return (async () => {
      const { environment } = await import("../../src/environment");
      const { setLoggingConfig } = await import("../../src/config");
      environment.setExplicitEnv("development");
      setLoggingConfig({
        allowUnsafeKeyNamesInDev: false,
        includeUnsafeKeyHashesInDev: false,
      });
    })();
  });

  it("omits unsafe keys and reports count", () => {
    return (async () => {
      const { _redact } = await import("../../src/utils");
      const obj = { good: "ok", "weird key!": "value", another: "x" } as any;
      const out = _redact(obj) as Record<string, unknown>;
      expect(out.__unsafe_key_count__).toBe(1);
      expect(out.good).toBe("ok");
      expect(out.another).toBe("x");
      expect(Object.keys(out)).not.toContain("weird key!");
    })();
  });

  it("includes hashes when enabled in dev", () => {
    return (async () => {
      const { setLoggingConfig } = await import("../../src/config");
      const { _redact } = await import("../../src/utils");
      setLoggingConfig({
        allowUnsafeKeyNamesInDev: true,
        includeUnsafeKeyHashesInDev: true,
        unsafeKeyHashSalt: "salt",
      });
      const obj = { secret$bad: "v" } as any;
      const out = _redact(obj) as Record<string, unknown>;
      expect(out.__unsafe_key_count__).toBe(1);
      expect(Array.isArray(out.__unsafe_key_hashes__)).toBe(true);
    })();
  });
});
