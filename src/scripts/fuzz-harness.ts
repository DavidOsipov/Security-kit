import { Sanitizer, STRICT_HTML_POLICY_CONFIG } from "../sanitizer";
import * as postMessageModule from "../postMessage";
import * as crypto from "node:crypto";

function randomString(length = 6, rnd?: () => number) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  if (typeof rnd === "function") {
    return Array.from(
      { length },
      () => chars[Math.floor(rnd() * chars.length)],
    ).join("");
  }
  const buf = Buffer.alloc(length);
  crypto.randomFillSync(buf);
  return Array.from(buf)
    .map((b) => chars[(b as number) % chars.length])
    .join("");
}

// Secure RNG returning a float in [0,1)
function secureRandom(): number {
  const buf = Buffer.alloc(6);
  crypto.randomFillSync(buf);
  // Use a typed loop to compose a 48-bit integer from 6 random bytes
  // eslint-disable-next-line functional/no-let -- Local accumulator for random number generation; scoped to function
  let accumulator = 0;
  // eslint-disable-next-line functional/no-let -- Local loop index; scoped to function
  for (let index = 0; index < 6; index++) {
    accumulator = (accumulator << 8) + buf.readUInt8(index);
  }
  const v = accumulator;
  return v / 2 ** 48;
}

function makeHostilePayload(
  index: number,
  rnd = secureRandom,
  randString = randomString,
  randInt?: (n: number) => number,
): unknown {
  if (!randInt) randInt = (n: number) => Math.floor(rnd() * n);
  const r = rnd();
  if (r < 0.2) {
    // prototype pollution vector (intentional for fuzzing)

    return { __proto__: { hacked: index } };
  }
  if (r < 0.4) {
    const o: Record<PropertyKey, unknown> = { a: 1 };
    const s = Symbol(randString(6, rnd));
    // unsafe member access on purpose for fuzzing
    // Narrow, intentional mutation for the fuzz harness: we need to create a symbol-keyed
    // property to exercise sanitizer behavior across exotic keys. This is auditable and
    // intentionally unsafe in this test-only file.
    // eslint-disable-next-line functional/immutable-data -- intentional test harness behavior
    o[s] = { evil: index };

    return o;
  }
  if (r < 0.6) {
    // Use an object literal with an accessor to avoid mutating an existing object.
    const o: Record<PropertyKey, unknown> = {
      a: 1,
      get b() {
        throw new Error("hostile getter");
      },
    };

    return o;
  }
  if (r < 0.8) {
    const o: Record<PropertyKey, unknown> = { nested: {} };
    // deliberate nested mutation to exercise prototype setters in sanitizer
    // Cast to any for intentional test-only mutation
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (o as any).nested.deep = { __proto__: { p: index } };

    return o;
  }

  // Extra vectors when rnd is present
  if (r < 0.9) {
    // toString/valueOf override or Symbol.toPrimitive
    const o: Record<PropertyKey, unknown> = { v: 1 };
    if (randInt) {
      const choice = randInt(3);
      if (choice === 0) {
        // deliberate mutation to override toString for fuzzing
        // Narrow, intentional mutation: override built-in conversion helpers to assert
        // sanitizer and consumers handle poisoned primitives safely.
        // eslint-disable-next-line functional/immutable-data -- intentional fuzz harness mutation
        o.toString = () => {
          throw new Error("poisoned toString");
        };
      } else if (choice === 1) {
        // deliberate mutation to override valueOf for fuzzing
        // eslint-disable-next-line functional/immutable-data -- intentional fuzz harness mutation
        o.valueOf = () => {
          throw new Error("poisoned valueOf");
        };
      } else {
        // deliberate mutation to override Symbol.toPrimitive
        // eslint-disable-next-line functional/immutable-data -- intentional fuzz payload
        o[Symbol.toPrimitive] = () => {
          throw new Error("poisoned toPrimitive");
        };
      }
    } else {
      // Narrow intentional mutation for the fallback path when randInt is not provided.
      // eslint-disable-next-line functional/immutable-data -- intentional fuzz harness mutation
      o.toString = () => {
        throw new Error("poisoned toString");
      };
    }

    return o;
  }

  if (r < 0.95) {
    // setPrototypeOf attack on nested object keys
    const o: Record<PropertyKey, unknown> = { a: { b: 1 } };
    try {
      // intentionally mutate prototype to test sanitizer hardening
      // Cast to any for test-only mutation
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      Object.setPrototypeOf((o as any).a, { poisoned: true });
    } catch (error) {
      console.warn(
        "setPrototypeOf failed during fuzz harness",
        (error as Error).message,
      );
    }

    return o;
  }

  // long key names
  const key = Array.from({ length: 512 })
    .map(() => randomString(4, rnd))
    .join(":");
  const object: Record<string, unknown> = {};
  // deliberate long-key insertion for fuzzing
  // Narrow, intentional mutation to insert a very long property name to test
  // sanitizer/validator behavior on extreme keys.
  // eslint-disable-next-line functional/immutable-data -- intentional fuzz harness access
  object[key] = { huge: index };

  return object;
}

export async function runStandaloneFuzzHarness(iterations = 100) {
  const dp: { readonly sanitize: (s: string, cfg?: unknown) => string } = {
    sanitize: (s: string) => s,
  };
  const sanitizer = new Sanitizer(dp, { strict: STRICT_HTML_POLICY_CONFIG });
  for (const index of Array.from(
    { length: iterations },
    (_, index_) => index_,
  )) {
    const before = Object.prototype.hasOwnProperty("hacked");
    const p: unknown = makeHostilePayload(index);
    try {
      try {
        sanitizer.getSanitizedString(JSON.stringify(p), "strict");
      } catch (error) {
        console.warn(
          "sanitizer error during fuzz iteration:",
          (error as Error).message,
        );
      }
      try {
        postMessageModule._validatePayload?.(
          p,
          (_d: unknown) => true as unknown as boolean,
        );
      } catch (error) {
        console.warn(
          "postMessage validator error during fuzz iteration:",
          (error as Error).message,
        );
      }
    } catch (caught) {
      // give a more descriptive name to caught exception
      console.error("Unexpected crash", caught);
      return 1;
    }
    const after = Object.prototype.hasOwnProperty("hacked");
    if (after !== before) {
      console.error("Prototype polluted! iteration", index, p, {
        before,
        after,
      });
      return 2;
    }
  }
  console.info(
    `Fuzz finished: no prototype pollution detected in ${iterations} iterations`,
  );
  return 0;
}
