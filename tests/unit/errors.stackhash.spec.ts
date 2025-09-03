import { describe, it, expect } from "vitest";
import { sanitizeErrorForLogs, getStackFingerprint } from "../../src/errors";
import {
  reportProdError,
  setProdErrorHook,
  __test_resetProdErrorReporter,
} from "../../src/reporting";
import { environment } from "../../src/environment";

describe("stack fingerprinting for errors", () => {
  it("generates stable stack fingerprint and includes in sanitized output", () => {
    const e = new Error("boom");
    // Create a fake stack to normalize
    e.stack = "Error: boom\n at foo (file.js:10:5)\n at bar (file.js:20:7)";
    const s = sanitizeErrorForLogs(e) as any;
    expect(s.stackHash).toBeDefined();
    const f = getStackFingerprint(e.stack);
    expect(s.stackHash).toBe(f);
  });

  it("reportProdError includes stackHash in redacted context", () => {
    __test_resetProdErrorReporter();
    environment.setExplicitEnv("production");
    const contexts: Array<any> = [];
    setProdErrorHook((_err, ctx) => contexts.push(ctx));
    const e = new Error("boom2");
    e.stack = "Error: boom2\n at x (file.js:1:1)";
    reportProdError(e, { some: "data" });
    expect(contexts.length).toBe(1);
    expect(contexts[0].stackHash).toBeDefined();
  });
});
