/* eslint-disable @typescript-eslint/no-explicit-any */
import { Sanitizer, STRICT_HTML_POLICY_CONFIG } from "../../src/sanitizer";
import * as postMessageMod from "../../src/postMessage";
import * as crypto from "crypto";

export function randomString(len = 6, rnd?: () => number) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  if (typeof rnd === "function") {
    for (let i = 0; i < len; i++) s += chars[Math.floor(rnd() * chars.length)];
    return s;
  }
  const buf = Buffer.alloc(len);
  crypto.randomFillSync(buf);
  for (let i = 0; i < len; i++) s += chars[(buf[i] as number) % chars.length];
  return s;
}

// Secure RNG returning a float in [0,1)
export function secureRandom(): number {
  const buf = Buffer.alloc(6);
  crypto.randomFillSync(buf);
  let v = 0;
  for (let i = 0; i < 6; i++) v = (v << 8) + buf.readUInt8(i);
  return v / 2 ** 48;
}

export function makeHostilePayload(
  i: number,
  rnd = secureRandom,
  randString = randomString,
  randInt?: (n: number) => number,
) {
  if (!randInt) randInt = (n: number) => Math.floor(rnd() * n);
  const r = rnd();
  if (r < 0.2) {
    return { __proto__: { hacked: i } } as any;
  }
  if (r < 0.4) {
    const o: any = { a: 1 };
    const s = Symbol(randString(6, rnd));
    o[s] = { evil: i };
    return o;
  }
  if (r < 0.6) {
    const o: any = { a: 1 };
    Object.defineProperty(o, "b", {
      get() {
        throw new Error("hostile getter");
      },
      enumerable: true,
    });
    return o;
  }
  if (r < 0.8) {
    const o: any = { nested: {} };
    o.nested.deep = { __proto__: { p: i } };
    return o;
  }

  // Extra vectors when rnd is present
  if (r < 0.9) {
    // toString/valueOf override or Symbol.toPrimitive
    const o: any = { v: 1 };
    if (randInt) {
      const choice = randInt(3);
      if (choice === 0) {
        o.toString = () => {
          throw new Error("poisoned toString");
        };
      } else if (choice === 1) {
        o.valueOf = () => {
          throw new Error("poisoned valueOf");
        };
      } else {
        o[Symbol.toPrimitive] = () => {
          throw new Error("poisoned toPrimitive");
        };
      }
    } else {
      o.toString = () => {
        throw new Error("poisoned toString");
      };
    }
    return o;
  }

  if (r < 0.95) {
    // setPrototypeOf attack on nested object keys
    const o: any = { a: { b: 1 } };
    try {
      Object.setPrototypeOf(o.a, { poisoned: true });
    } catch (err) {
      console.warn("setPrototypeOf failed during fuzz harness", (err as Error).message);
    }
    return o;
  }

  // long key names
  const key = new Array(512).fill(0).map(() => randomString(4, rnd)).join(":");
  const obj: any = {};
  obj[key] = { huge: i };
  return obj;
}

export async function runStandaloneFuzzHarness(iterations = 100) {
  const dp: any = { sanitize: (s: string) => s };
  const sanitizer = new Sanitizer(dp, { strict: STRICT_HTML_POLICY_CONFIG });

  for (let i = 0; i < iterations; i++) {
    const before = Object.prototype.hasOwnProperty("hacked");
    const p = makeHostilePayload(i);
    try {
      try {
        sanitizer.getSanitizedString(JSON.stringify(p), "strict");
      } catch (err) {
        console.warn("sanitizer error during fuzz iteration:", (err as Error).message);
      }
      try {
        postMessageMod._validatePayload?.(p, (_d: any) => true as any);
      } catch (err) {
        console.warn("postMessage validator error during fuzz iteration:", (err as Error).message);
      }
    } catch (e) {
      console.error("Unexpected crash", e);
      return 1;
    }
    const after = Object.prototype.hasOwnProperty("hacked");
    if (after !== before) {
      console.error("Prototype polluted! iteration", i, p, { before, after });
      return 2;
    }
  }
  console.info(`Fuzz finished: no prototype pollution detected in ${iterations} iterations`);
  return 0;
}
