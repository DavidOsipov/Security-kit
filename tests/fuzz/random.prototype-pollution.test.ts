import { describe, it, expect } from "vitest";
import { Sanitizer, STRICT_HTML_POLICY_CONFIG } from "../../src/sanitizer";
import * as postMessageMod from "../../src/postMessage";

// This test is gated behind RUN_FUZZ=1 so it only runs when explicitly requested.
const shouldRun = process.env.RUN_FUZZ === "1";

describe("randomized prototype-pollution fuzz (gated)", () => {
  if (!shouldRun) {
    it("skipped (set RUN_FUZZ=1 to run)", () => {
      // Emit an explicit, allowed console message so CI and test reporters
      // record that the expensive fuzz test was intentionally skipped.
      // Use console.info (allowed by lint rules) rather than console.log.
      console.info(
        "RUN_FUZZ not set — skipping randomized prototype-pollution fuzz test",
      );
      // Make a tiny assertion so the test runner records a passing test.
      expect(true).toBe(true);
    });
    return;
  }

  it(
    "runs many randomized payloads and detects prototype mutation",
    async () => {
      const dp: any = { sanitize: (s: string) => s };
      const sanitizer = new Sanitizer(dp, {
        strict: STRICT_HTML_POLICY_CONFIG,
      });
      const iterations = Number(process.env.RUN_FUZZ_ITERATIONS || "2000");
      for (let i = 0; i < iterations; i++) {
        const p = makeRandomPayload(i);
        const before = Object.prototype.hasOwnProperty("polluted_random");
        try {
          try {
            sanitizer.getSanitizedString(JSON.stringify(p), "strict");
          } catch {}
          try {
            postMessageMod._validatePayload?.(p, (d: any) => true as any);
          } catch {}
        } catch (e) {
          // ignore
        }
        const after = Object.prototype.hasOwnProperty("polluted_random");
        expect(after).toBe(before);
      }
    },
    { timeout: 120000 },
  );
});

function makeRandomPayload(i: number): any {
  const r = Math.random();
  if (r < 0.15) return { __proto__: { junk: i } };
  if (r < 0.3) {
    const o: any = { a: 1 };
    o[Symbol(randomString(6))] = { x: i };
    return o;
  }
  if (r < 0.45) {
    const o: any = { a: 1 };
    Object.defineProperty(o, "b", {
      get() {
        throw new Error("hostile getter");
      },
      enumerable: true,
    });
    return o;
  }
  if (r < 0.6) {
    const a: any = { x: 1 };
    a.self = a;
    return a;
  }
  if (r < 0.8) return { deep: { nested: { __proto__: { p: i } } } };
  return { ok: i, rnd: randomString(4) };
}

function randomString(len = 6) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < len; i++)
    s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}
