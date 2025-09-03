import { describe, it, expect, beforeEach } from "vitest";
import DOMPurify from "dompurify";
import { Sanitizer, STRICT_HTML_POLICY_CONFIG } from "../../src/sanitizer";
import * as postMessageMod from "../../src/postMessage";

const payloads: any[] = [
  // direct __proto__ poisoning
  { __proto__: { polluted: true } },
  // nested poison
  { a: { b: { __proto__: { hacked: 1 } } } },
  // constructor prototype attack
  { constructor: { prototype: { evil: 1 } } },
  // array-with-proto
  [{ __proto__: { arrProto: 1 } }],
  // null-prototype object should be preserved
  Object.assign(Object.create(null), { safe: true }),
  // symbol-keyed property
  (() => {
    const s = Symbol("secret");
    const o: any = { a: 1 };
    o[s] = { hacked: true };
    return o;
  })(),
  // accessor property that throws when accessed
  (() => {
    const o: any = { a: 1 };
    Object.defineProperty(o, "b", {
      get() {
        throw new Error("hostile getter");
      },
      enumerable: true,
    });
    return o;
  })(),
];

describe("prototype-pollution fuzz tests", () => {
  beforeEach(() => {
    // noop for now; leave hooks available if tests need to reset module state
  });

  it("sanitizer does not mutate Object.prototype when sanitizing malicious inputs", () => {
    const before = Object.prototype.hasOwnProperty("polluted");
    // Instantiate a local DOMPurify-compatible object for the Sanitizer
    const dp: any = { sanitize: (s: string) => s || "" };
    const s = new Sanitizer(dp, { strict: STRICT_HTML_POLICY_CONFIG });
    for (const p of payloads) {
      try {
        // sanitizer API expects strings/html; stringify objects safely
        const html = JSON.stringify(p, (_k, v) => (v === undefined ? null : v));
        s.getSanitizedString(html, "strict");
      } catch {
        // ignore errors; main assertion is about prototype pollution
      }
    }
    const after = Object.prototype.hasOwnProperty("polluted");
    expect(after).toBe(before);
  });

  it("postMessage validator does not pollute prototypes when validating objects", () => {
    const before = Object.prototype.hasOwnProperty("evil");
    const validator = (obj: any) => {
      // simple validator that throws on unexpected keys but should not mutate prototypes
      if (typeof obj !== "object" || obj === null) return false;
      if (Object.hasOwn(obj, "unexpected")) throw new Error("unexpected");
      return true;
    };

    for (const p of payloads) {
      try {
        postMessageMod._validatePayload?.(p, validator as any);
      } catch {
        // ignore
      }
    }

    const after = Object.prototype.hasOwnProperty("evil");
    expect(after).toBe(before);
  });
});
