import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as SK from "../../src";
import {
  makeDeterministicStub,
  makeAll255Stub,
} from "./_test-helpers/crypto-stubs";

const {
  generateSecureId,
  generateSecureIdSync,
  generateSecureUUID,
  generateSecureStringAsync,
  getSecureRandomInt,
  getSecureRandomBytesSync,
  setCrypto,
} = SK as any;

describe("crypto primitives (unit)", () => {
  beforeEach(() => {
    // Default: use real global crypto if present; tests will inject stubs as needed
  });
  afterEach(() => {
    try {
      setCrypto(null);
    } catch {}
  });

  it("generateSecureId produces correct length and hex output", async () => {
    const id = await generateSecureId();
    expect(typeof id).toBe("string");
    expect(id).toMatch(/^[0-9a-f]{64}$/);
  });

  it("generateSecureIdSync works for boundaries", () => {
    const id = generateSecureIdSync(16);
    expect(typeof id).toBe("string");
    expect(id.length).toBe(16);
  });

  it("generateSecureUUID uses crypto.randomUUID when available", async () => {
    const uuid = await generateSecureUUID();
    expect(typeof uuid).toBe("string");
    expect(uuid.length).toBeGreaterThan(0);
  });

  it("generateSecureStringAsync produces correct length and respects alphabet", async () => {
    const alphabet = "abc";
    const out = await generateSecureStringAsync(alphabet, 32);
    expect(out.length).toBe(32);
    expect(out.split("").every((c) => alphabet.includes(c))).toBe(true);
  });

  it("getSecureRandomInt returns integer in range and handles deterministic stub", async () => {
    const stub = makeDeterministicStub([10]);
    setCrypto(stub);
    const val = await getSecureRandomInt(0, 20);
    expect(Number.isInteger(val)).toBe(true);
    expect(val).toBeGreaterThanOrEqual(0);
    expect(val).toBeLessThanOrEqual(20);
  });

  it("getSecureRandomBytesSync returns non-zero bytes and enforces bounds", () => {
    const out = getSecureRandomBytesSync(16);
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBe(16);
    expect(out.every((b: number) => b === 0)).toBe(false);
    expect(() => getSecureRandomBytesSync(0)).toThrow();
  });

  it("handles pathological all-255 stub for random int", async () => {
    const stub = makeAll255Stub();
    setCrypto(stub);
    const v = await getSecureRandomInt(0, 1);
    expect(Number.isInteger(v)).toBe(true);
    expect(v).toBeGreaterThanOrEqual(0);
    expect(v).toBeLessThanOrEqual(1);
  });
});
