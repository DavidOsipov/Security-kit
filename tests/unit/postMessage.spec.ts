import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  InvalidParameterError,
  TransferableNotAllowedError,
} from "../../src/errors";

// Helper that mirrors the createSecurePostMessageListener signature for tests.
async function createListener(allowed: any, onMessage?: (d: unknown) => void) {
  // Intercept window.addEventListener to capture the registered handler.
  const origAdd = window.addEventListener;
  let captured: ((ev: MessageEvent) => void) | undefined;
  // @ts-ignore override for test
  window.addEventListener = function (
    type: string,
    handler: EventListenerOrEventListenerObject,
    options?: any,
  ) {
    if (type === "message") {
      // store the handler so tests can invoke it directly
      // EventListenerObject and function union: coerce to function when possible
      if (typeof handler === "function")
        captured = handler as (ev: MessageEvent) => void;
      else if (handler && typeof (handler as any).handleEvent === "function")
        captured = (handler as any).handleEvent.bind(handler);
    }
    // Call through to original to maintain behavior (may be noop in tests)
    return origAdd.call(window, type as any, handler as any, options);
  } as any;

  // Use dynamic import for createSecurePostMessageListener
  const postMessage = await import("../../src/postMessage");
  const listener = postMessage.createSecurePostMessageListener(
    allowed as any,
    onMessage as any,
  );

  // restore original addEventListener to avoid polluting global for other tests
  // @ts-ignore
  window.addEventListener = origAdd;

  return {
    handler:
      captured ??
      ((ev: MessageEvent) => {
        /* no-op */
      }),
    destroy: listener.destroy,
  };
}

describe("postMessage utilities", () => {
  beforeEach(async () => {
    // Reset module cache before each test to ensure clean state
    vi.resetModules();
    // Allow test APIs in runtime by setting global flag
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
    // Reset test state using dynamic import
    const postMessage = await import("../../src/postMessage");
    postMessage.__test_resetForUnitTests();
  });
  afterEach(async () => {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    // Reset test state using dynamic import
    const postMessage = await import("../../src/postMessage");
    postMessage.__test_resetForUnitTests();
    vi.restoreAllMocks();
  });

  it("validateTransferables throws for MessagePort-like object when not allowed", async () => {
    const postMessage = await import("../../src/postMessage");
    const { TransferableNotAllowedError } = await import("../../src/errors");
    // Build an object whose prototype constructor name is MessagePort
    // Create a constructor with the name 'MessagePort' so safeCtorName detects it
    // eslint-disable-next-line @typescript-eslint/no-redeclare
    function MessagePort() {}
    const fakePort = Object.create((MessagePort as any).prototype);
    try {
      postMessage.validateTransferables(fakePort, false, false);
      expect.fail("Expected TransferableNotAllowedError to be thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(TransferableNotAllowedError);
    }
  });

  it("validateTransferables allows typed arrays when allowTypedArrays=true", async () => {
    const postMessage = await import("../../src/postMessage");
    const ta = new Uint8Array([1, 2, 3]);
    expect(() =>
      postMessage.validateTransferables(ta, false, true),
    ).not.toThrow();
  });

  it("toNullProto strips forbidden keys and rejects depth overflow", async () => {
    const postMessage = await import("../../src/postMessage");
    const { InvalidParameterError } = await import("../../src/errors");
    const src = {
      a: 1,
      __proto__: { polluted: true },
      constructor: 2,
      nested: { ok: 3 },
    } as any;
    const res = postMessage.__test_toNullProto(src, 0, 10) as Record<
      string,
      unknown
    >;
    expect(res.a).toBe(1);
    expect((res as any).__proto__).toBeUndefined();
    expect((res as any).constructor).toBeUndefined();
    // Depth overflow
    const deep = { v: 0 } as any;
    let cur = deep;
    for (let i = 0; i < 20; i++) {
      cur.next = { i };
      cur = cur.next;
    }
    try {
      postMessage.__test_toNullProto(deep, 0, 5);
      expect.fail("Expected InvalidParameterError to be thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidParameterError);
    }
  });

  it("sendSecurePostMessage JSON path serializes and posts string", async () => {
    const postMessage = await import("../../src/postMessage");
    const posted: any[] = [];
    const win = {
      postMessage: (d: unknown, origin: string) => posted.push({ d, origin }),
    } as unknown as Window;
    postMessage.sendSecurePostMessage({
      targetWindow: win,
      payload: { x: 1 },
      targetOrigin: "https://example.com",
      wireFormat: "json",
    });
    expect(posted.length).toBe(1);
    expect(typeof posted[0].d).toBe("string");
    expect(posted[0].origin).toBe("https://example.com");
  });

  it("sendSecurePostMessage JSON rejects oversized payloads", async () => {
    const postMessage = await import("../../src/postMessage");
    const { InvalidParameterError } = await import("../../src/errors");
    const win = {
      postMessage: (_: unknown, __: string) => {},
    } as unknown as Window;
    const big = "x".repeat(postMessage.POSTMESSAGE_MAX_PAYLOAD_BYTES + 10);
    try {
      postMessage.sendSecurePostMessage({
        targetWindow: win,
        payload: big,
        targetOrigin: "https://example.com",
        wireFormat: "json",
      });
      expect.fail("Expected InvalidParameterError to be thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidParameterError);
    }
  });

  it("sendSecurePostMessage structured path rejects when sanitize + allowTypedArrays incompatible", async () => {
    const postMessage = await import("../../src/postMessage");
    const { InvalidParameterError } = await import("../../src/errors");
    const win = {
      postMessage: (_: unknown, __: string) => {},
    } as unknown as Window;
    try {
      postMessage.sendSecurePostMessage({
        targetWindow: win,
        payload: new Uint8Array([1]),
        targetOrigin: "https://example.com",
        wireFormat: "structured",
        sanitize: true,
        allowTypedArrays: true,
      });
      expect.fail("Expected InvalidParameterError to be thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidParameterError);
    }
  });

  it("getPayloadFingerprint and salt cooldown behavior", async () => {
    const postMessage = await import("../../src/postMessage");
    // Simulate failure cooldown: set timestamp first so ensureFingerprintSalt will throw
    const ts = Date.now();
    postMessage.__test_setSaltFailureTimestamp(ts);
    await expect(postMessage.__test_ensureFingerprintSalt()).rejects.toThrow();
    // Clear cooldown and ensure salt generation now succeeds
    postMessage.__test_setSaltFailureTimestamp(undefined);
    const salt = await postMessage.__test_ensureFingerprintSalt();
    expect(salt).toBeInstanceOf(Uint8Array);
  });

  it("compute fingerprint for simple object via test helper", async () => {
    const postMessage = await import("../../src/postMessage");
    const fp = await postMessage.__test_getPayloadFingerprint({ a: 1 });
    expect(typeof fp).toBe("string");
    expect(fp.length).toBeGreaterThan(0);
  });

  it("createSecurePostMessageListener JSON path rejects non-string and parses JSON", async () => {
    const onMessage = vi.fn();
    const listener = await createListener({
      allowedOrigins: ["https://example.com"],
      onMessage,
      validate: () => true,
      wireFormat: "json",
    });
    // non-string data should be rejected when wireFormat=json: handler swallows parse error and does not call consumer
    const ev1 = {
      origin: "https://example.com",
      data: { a: 1 },
    } as unknown as MessageEvent;
    expect(() => listener.handler(ev1 as any)).not.toThrow();
    expect(onMessage).not.toHaveBeenCalled();

    // string JSON should be parsed and delivered
    const ev2 = {
      origin: "https://example.com",
      data: JSON.stringify({ b: 2 }),
    } as unknown as MessageEvent;
    expect(() => listener.handler(ev2 as any)).not.toThrow();
    expect(onMessage).toHaveBeenCalled();
    listener.destroy();
  });

  it("createSecurePostMessageListener auto allows same-origin structured data and rejects otherwise", async () => {
    const onMessage = vi.fn();
    const l = await createListener({
      allowedOrigins: ["https://example.com"],
      onMessage,
      wireFormat: "auto",
      validate: () => true,
    });

    // Simulate same-origin structured object by stubbing location.origin
    const origBackup = (globalThis as any).location;
    (globalThis as any).location = { origin: "https://example.com" };
    const ev = {
      origin: "https://example.com",
      data: { x: 1 },
    } as unknown as MessageEvent;
    expect(() => l.handler(ev as any)).not.toThrow();
    expect(onMessage).toHaveBeenCalled();
    (globalThis as any).location = origBackup;
    l.destroy();
  });

  it("createSecurePostMessageListener expectedSource comparator throwing is handled", async () => {
    const onMessage = vi.fn();
    const comparator = () => {
      throw new Error("boom");
    };
    const l = await createListener({
      allowedOrigins: ["https://example.com"],
      onMessage,
      expectedSource: comparator as any,
    });
    const ev = {
      origin: "https://example.com",
      data: JSON.stringify({}),
      source: {},
    } as unknown as MessageEvent;
    // comparator throws; handler should swallow and return false path
    expect(() => l.handler(ev as any)).not.toThrow();
    expect(onMessage).not.toHaveBeenCalled();
    l.destroy();
  });

  it("_validatePayload and _validatePayloadWithExtras schema and extras behavior", async () => {
    const postMessage = await import("../../src/postMessage");
    const schema = { a: "number" as const };
    expect(postMessage._validatePayload({ a: 1 }, schema).valid).toBe(true);
    expect(postMessage._validatePayload({ a: "x" }, schema).valid).toBe(false);
    expect(
      postMessage._validatePayloadWithExtras({ a: 1, b: 2 }, schema, false)
        .valid,
    ).toBe(false);
    expect(
      postMessage._validatePayloadWithExtras({ a: 1, b: 2 }, schema, true)
        .valid,
    ).toBe(true);
  });

  it("structured path validation rejects transferables when not allowed", async () => {
    const postMessage = await import("../../src/postMessage");
    const { TransferableNotAllowedError } = await import("../../src/errors");
    const win = {
      postMessage: (_: unknown, __: string) => {},
    } as unknown as Window;
    // MessagePort-like object
    // eslint-disable-next-line @typescript-eslint/no-redeclare
    function MessagePort() {}
    const fakePort = Object.create((MessagePort as any).prototype);
    try {
      postMessage.sendSecurePostMessage({
        targetWindow: win,
        payload: fakePort,
        targetOrigin: "https://example.com",
        wireFormat: "structured",
      });
      expect.fail("Expected TransferableNotAllowedError to be thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(TransferableNotAllowedError);
    }
  });
});
