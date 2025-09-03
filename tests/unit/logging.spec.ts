import { describe, it, expect, vi, beforeEach } from "vitest";
import { _redact, secureDevLog } from "../../src/utils";
import { environment } from "../../src/environment";

describe("secureDevLog and _redact", () => {
  beforeEach(() => {
    // ensure development mode for tests
    environment.setExplicitEnv("development");
    environment.clearCache();
  });

  it("redacts sensitive keys and truncates long strings", () => {
    const obj = {
      api_key: "secret-123",
      regular: "ok",
      long: "a".repeat(9000),
      nested: { password: "hunter2" },
    } as unknown;

    const out = _redact(obj);
    // api keys and passwords should be redacted
    expect(JSON.stringify(out)).toContain("[REDACTED]");
    // long string should be truncated marker present
    expect(JSON.stringify(out)).toContain("[TRUNCATED");
  });

  it("does not throw when logging with secureDevLog in dev mode", () => {
    expect(() => secureDevLog("info", "test", "hello", { a: 1 })).not.toThrow();
  });
});
