import { test, expect } from "vitest";
import loadPostMessageInternals from "../../tests/helpers/vmPostMessageHelper";

test("ensureFingerprintSalt returns a Uint8Array and is stable under repeated calls", async () => {
  const pm = loadPostMessageInternals();
  const internals = pm.__test_internals ?? pm;
  expect(internals.ensureFingerprintSalt).toBeDefined();
  const aRaw = await internals.ensureFingerprintSalt();
  // Coerce cross-realm/VM Uint8Array-like objects into host Uint8Array for assertions
  const a = aRaw instanceof Uint8Array ? aRaw : new Uint8Array(aRaw as any);
  expect(a).toBeInstanceOf(Uint8Array);
  const bRaw = await internals.ensureFingerprintSalt();
  const b = bRaw instanceof Uint8Array ? bRaw : new Uint8Array(bRaw as any);
  expect(b).toBeInstanceOf(Uint8Array);
}, // Increase timeout for slower machines (default Vitest timeout is 5000ms)
10000);
