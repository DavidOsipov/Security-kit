import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

describe("_validatePayload (schema)", () => {
  beforeEach(async () => {
    // Reset module cache before each test to ensure clean state
    vi.resetModules();
    // Allow test APIs in runtime by setting global flag
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  });
  afterEach(async () => {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    vi.restoreAllMocks();
  });

  it("validates simple schema and rejects forbidden keys", async () => {
    const postMessage = await import("../../src/postMessage");
    const schema = { id: "string" as const, n: "number" as const };
    expect(postMessage._validatePayload({ id: "x", n: 1 }, schema).valid).toBe(true);
    expect(postMessage._validatePayload({ id: "x" }, schema).valid).toBe(false);
    expect(postMessage._validatePayload({ id: "x", n: "no" }, schema).valid).toBe(false);
    // forbidden key test
    expect(postMessage._validatePayload({ __proto__: {} }, schema).valid).toBe(false);
  });

  it("allows function validators and surfaces thrown errors", async () => {
    const postMessage = await import("../../src/postMessage");
    const fn = (d: unknown) => {
      if (typeof d !== "object" || d == null) throw new Error("bad");
      return true;
    };
    const res = postMessage._validatePayload({ a: 1 }, fn as any);
    expect(res.valid).toBe(true);
    const res2 = postMessage._validatePayload("no", fn as any);
    expect(res2.valid).toBe(false);
  });
});

describe("_validatePayloadWithExtras", () => {
  beforeEach(async () => {
    // Reset module cache before each test to ensure clean state
    vi.resetModules();
    // Allow test APIs in runtime by setting global flag
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  });
  afterEach(async () => {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    vi.restoreAllMocks();
  });

  it("rejects unexpected extra props when not allowed", async () => {
    const postMessage = await import("../../src/postMessage");
    const schema = { a: "number" as const };
    expect(postMessage._validatePayloadWithExtras({ a: 1, b: 2 }, schema, false).valid).toBe(false);
    expect(postMessage._validatePayloadWithExtras({ a: 1, b: 2 }, schema, true).valid).toBe(true);
  });
});
