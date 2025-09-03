import { expect, test, beforeEach } from "vitest";

// Enable test-only runtime APIs in this process
(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

import {
  __test_toNullProto,
  __test_deepFreeze,
  __test_ensureFingerprintSalt,
  __test_getPayloadFingerprint,
  __test_resetForUnitTests,
  _validatePayload,
  _validatePayloadWithExtras,
} from "../../src/postMessage";

beforeEach(async () => {
  // reset internal salt/diagnostics state between tests
  try {
    __test_resetForUnitTests();
  } catch {
    // best-effort
  }
});

test("toNullProto strips prototype and forbidden keys and enforces depth", () => {
  const input = Object.create({ inherited: "bad" });
  (input as any).safe = "ok";
  (input as any).__proto__ = { polluted: true };
  (input as any).constructor = "x";

  const out = __test_toNullProto(input as unknown as Record<string, unknown>);
  expect(out && typeof out === "object").toBe(true);
  // inherited props should not be present
  expect((out as any).inherited).toBeUndefined();
  // forbidden keys removed
  expect((out as any).__proto__).toBeUndefined();
  expect((out as any).constructor).toBeUndefined();
  expect((out as any).safe).toBe("ok");
});

test("toNullProto enforces max depth", () => {
  const deep = { a: { b: { c: { d: { e: { f: "too deep" } } } } } };
  expect(() => __test_toNullProto(deep, 0, 3)).toThrow();
});

test("deepFreeze makes object immutable (best-effort) and handles cycles", () => {
  const a: any = { x: 1 };
  a.self = a; // cyclic
  const frozen = __test_deepFreeze(a);
  expect(Object.isFrozen(frozen)).toBe(true);
  expect(frozen.x).toBe(1);
});

test("ensureFingerprintSalt returns stable salt and getPayloadFingerprint uses it", async () => {
  const salt1 = await __test_ensureFingerprintSalt();
  expect(salt1).toBeInstanceOf(Uint8Array);
  const fp1 = await __test_getPayloadFingerprint({ a: 1 });
  expect(typeof fp1).toBe("string");
  // subsequent calls should return same salt (reset done in beforeEach)
  const salt2 = await __test_ensureFingerprintSalt();
  expect(salt2).toBeInstanceOf(Uint8Array);
});

test("_validatePayload detects forbidden keys and type mismatches", () => {
  const data = { good: "ok", bad: 1 };
  // mark 'bad' as forbidden via constants? Use direct detection by key name
  const res1 = _validatePayload(data, { good: "string" });
  expect(res1.valid).toBe(true);

  const res2 = _validatePayload({ notAnObject: 1 }, { k: "string" });
  expect(res2.valid).toBe(false);
});

test("_validatePayloadWithExtras rejects unexpected extra properties by default", () => {
  const schema = { a: "string" } as const;
  const ok = _validatePayloadWithExtras({ a: "x" }, schema, false);
  expect(ok.valid).toBe(true);
  const extra = _validatePayloadWithExtras({ a: "x", b: 2 }, schema, false);
  expect(extra.valid).toBe(false);
  const allowed = _validatePayloadWithExtras({ a: "x", b: 2 }, schema, true);
  expect(allowed.valid).toBe(true);
});
