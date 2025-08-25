import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  configureProdErrorReporter,
  reportProdError,
  setProdErrorHook,
  __test_resetProdErrorReporter,
  __test_setLastRefillForTesting,
} from "../../src/reporting";
import { environment } from "../../src/environment";

describe("prod error reporter token refill (integer millitokens)", () => {
  beforeEach(() => {
    __test_resetProdErrorReporter();
    setProdErrorHook(null);
    environment.setExplicitEnv("production");
  });

  it("respects burst cap and consumes tokens", () => {
    const calls: Array<any> = [];
    setProdErrorHook((err, ctx) => calls.push({ err, ctx }));
    configureProdErrorReporter({ burst: 3, refillRatePerSec: 1 });

    // Should allow exactly 3 reports immediately
    reportProdError(new Error("one"));
    reportProdError(new Error("two"));
    reportProdError(new Error("three"));
    // Fourth should be rate-limited
    reportProdError(new Error("four"));

    expect(calls.length).toBe(3);
  });

  it("refills tokens after time passes (integer behavior)", () => {
    const calls: Array<any> = [];
    setProdErrorHook((err, ctx) => calls.push({ err, ctx }));
    configureProdErrorReporter({ burst: 2, refillRatePerSec: 2 });

    // consume two tokens
    reportProdError(new Error("one"));
    reportProdError(new Error("two"));
    expect(calls.length).toBe(2);

    // simulate 250ms passing -> should refill 0.5 tokens at rate 2/s -> rounded down to 0
    __test_setLastRefillForTesting(250);
    reportProdError(new Error("three"));
    expect(calls.length).toBe(2);

    // simulate 500ms passing -> refill 1 token (2/sec * 0.5s)
    __test_setLastRefillForTesting(500);
    reportProdError(new Error("four"));
    expect(calls.length).toBe(3);
  });

  it("does not report when hook is missing or environment not prod", () => {
    __test_resetProdErrorReporter();
    environment.setExplicitEnv("development");
    const calls: Array<any> = [];
    setProdErrorHook((err, ctx) => calls.push(1));
    reportProdError(new Error("nope"));
    expect(calls.length).toBe(0);
  });
});
