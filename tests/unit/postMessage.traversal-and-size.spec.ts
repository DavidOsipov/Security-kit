import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  sendSecurePostMessage,
  // Access test-only helpers via guarded API if needed in future
} from "../../src/postMessage";
import {
  setPostMessageConfig,
  getPostMessageConfig,
} from "../../src/config";
import {
  InvalidParameterError,
  TransferableNotAllowedError,
} from "../../src/errors";

describe("postMessage traversal/size hardening", () => {
  const original = getPostMessageConfig();

  beforeEach(() => {
    vi.restoreAllMocks();
    // Keep defaults conservative; individual tests will override temporarily
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  });

  afterEach(() => {
    // Restore config to defaults to avoid cross-test coupling
    setPostMessageConfig(original as any);
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  });

  it("rejects sanitize=false + allowTypedArrays=true payloads that exceed maxPayloadBytes by byteLength", () => {
    // Tighten the payload limit for a quick test
    setPostMessageConfig({ maxPayloadBytes: 64 });
    const target = { postMessage: (_: unknown, __: string) => {} } as unknown as Window;

    // 80 bytes should exceed the 64-byte cap
    const arr = new Uint8Array(80);
    for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff;

    expect(() =>
      sendSecurePostMessage({
        targetWindow: target,
        payload: arr,
        targetOrigin: "https://example.com",
        wireFormat: "structured",
        sanitize: false,
        allowTypedArrays: true,
      }),
    ).toThrow(InvalidParameterError);
  });

  it("accepts sanitize=false + allowTypedArrays=true when byteLength within cap", () => {
    setPostMessageConfig({ maxPayloadBytes: 128 });
    const targetOrigin = "https://example.com";
    const posted: Array<{ data: unknown; origin: string }> = [];
    const target = {
      postMessage(data: unknown, origin: string) {
        posted.push({ data, origin });
      },
    } as unknown as Window;

    const arr = new Uint8Array(64);
    for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff;

    expect(() =>
      sendSecurePostMessage({
        targetWindow: target,
        payload: arr,
        targetOrigin,
        wireFormat: "structured",
        sanitize: false,
        allowTypedArrays: true,
      }),
    ).not.toThrow();
    expect(posted.length).toBe(1);
    expect(posted[0]?.data).toBe(arr);
    expect(posted[0]?.origin).toBe(targetOrigin);
  });

  it("enforces maxArrayItems breadth cap during sanitize", () => {
    setPostMessageConfig({ maxArrayItems: 2 });
    const target = { postMessage: (_: unknown, __: string) => {} } as unknown as Window;
    const payload = [1, 2, 3];

    expect(() =>
      sendSecurePostMessage({
        targetWindow: target,
        payload,
        targetOrigin: "https://example.com",
        wireFormat: "structured",
        sanitize: true,
      }),
    ).toThrow(InvalidParameterError);
  });

  it("drops or rejects symbol-keyed properties by default in sanitize path", () => {
    // Default config drops symbol keys (includeSymbolKeysInSanitizer=false)
    const s = Symbol("hidden");
    const obj: any = { a: 1 };
    obj[s] = 42;

    const captured: Array<unknown> = [];
    const target = {
      postMessage(data: unknown) {
        captured.push(data);
      },
    } as unknown as Window;

    expect(() =>
      sendSecurePostMessage({
        targetWindow: target,
        payload: obj,
        targetOrigin: "https://example.com",
        wireFormat: "structured",
        sanitize: true,
      }),
    ).not.toThrow();

    expect(captured.length).toBe(1);
    const sent = captured[0] as Record<string, unknown>;
    // Symbol keys are not enumerable on plain JSON stringify; our sanitizer drops them entirely
    expect(Object.getOwnPropertySymbols(sent as object).length).toBe(0);
    expect((sent as any).a).toBe(1);
  });

  it("enforces maxTransferables cap when transferables are allowed", () => {
    setPostMessageConfig({ maxTransferables: 1 });
    const target = { postMessage: (_: unknown, __: string) => {} } as unknown as Window;
    const payload = { a: new ArrayBuffer(8), b: new ArrayBuffer(8) };

    expect(() =>
      sendSecurePostMessage({
        targetWindow: target,
        payload,
        targetOrigin: "https://example.com",
        wireFormat: "structured",
        sanitize: false,
        allowTransferables: true,
        allowTypedArrays: true,
      }),
    ).toThrow(TransferableNotAllowedError);
  });
});
