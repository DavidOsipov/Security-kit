// tests/security/prototype-pollution.test.ts
// RULE-ID: adversarial-prototype-pollution

import { test, expect, vi, beforeEach, afterEach } from "vitest";

let capturedMessageListener: ((event: MessageEvent) => void) | undefined;
const mockPostMessage = vi.fn();

function setupMocks() {
  vi.resetModules();
  vi.clearAllMocks();
  capturedMessageListener = undefined;

  vi.stubGlobal("self", {
    postMessage: mockPostMessage,
    close: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  });
  vi.stubGlobal("postMessage", mockPostMessage as any);
  vi.stubGlobal("location", { origin: "https://example.com" });

  const mockSign = vi.fn();
  const mockImportKey = vi.fn();
  vi.stubGlobal("crypto", {
    ...global.crypto,
    subtle: { sign: mockSign, importKey: mockImportKey },
    getRandomValues: vi.fn(),
  } as any);

  vi.mock("../../src/postMessage", async (importOriginal) => {
    const actual = await importOriginal<typeof import("../../src/postMessage")>();
    return {
      ...actual,
      createSecurePostMessageListener: vi.fn((opts) => {
        const l = async (event: MessageEvent) => {
          await opts.onMessage(event.data, {
            origin: event.origin,
            ports: event.ports,
            event,
          });
        };
        capturedMessageListener = l;
        try {
          globalThis.addEventListener("message", l);
        } catch {}
        try {
          if ((globalThis as any).window)
            (globalThis as any).window.addEventListener("message", l);
        } catch {}
        return { destroy: vi.fn() };
      }),
      computeInitialAllowedOrigin: vi.fn(() => "https://example.com"),
      isEventAllowedWithLock: vi.fn(() => true),
    } as any;
  });

  globalThis.addEventListener = vi.fn((type: string, listener: any) => {
    if (type === "message") capturedMessageListener = listener;
    return undefined;
  }) as any;
}

beforeEach(() => {
  setupMocks();
});
afterEach(() => {
  vi.restoreAllMocks();
});

// Try to pollute Object.prototype via a message payload
test("worker resists prototype pollution attempts", async () => {
  setupMocks();
  const workerModule = await import("../../src/worker/signing-worker");
  for (let i = 0; i < 10; i++) {
    if (capturedMessageListener) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  if (!capturedMessageListener) throw new Error("listener not captured");

  // Create a malicious message trying to pollute prototypes
  const payload: any = { type: "sign", requestId: 1, canonical: "good" };
  payload.__proto__ = { polluted: true };

  await capturedMessageListener(
    new MessageEvent("message", { data: payload } as any),
  );

  // Ensure the global Object prototype hasn't been polluted
  expect((Object.prototype as any).polluted).not.toBe(true);
});

// Advanced prototype pollution payloads
test("resists advanced prototype pollution with nested constructor", async () => {
  setupMocks();
  const workerModule = await import("../../src/worker/signing-worker");
  for (let i = 0; i < 10; i++) {
    if (capturedMessageListener) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  if (!capturedMessageListener) throw new Error("listener not captured");

  const payload: any = { type: "sign", requestId: 1, canonical: "good" };
  payload.constructor = { prototype: { polluted: true } };

  await capturedMessageListener(
    new MessageEvent("message", { data: payload } as any),
  );

  expect((Object.prototype as any).polluted).toBeUndefined();
});

test("resists prototype pollution via __proto__ chain", async () => {
  setupMocks();
  const workerModule = await import("../../src/worker/signing-worker");
  for (let i = 0; i < 10; i++) {
    if (capturedMessageListener) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  if (!capturedMessageListener) throw new Error("listener not captured");

  const payload: any = { type: "sign", requestId: 1, canonical: "good" };
  payload.__proto__ = { __proto__: { polluted: true } };

  await capturedMessageListener(
    new MessageEvent("message", { data: payload } as any),
  );

  expect((Object.prototype as any).polluted).toBeUndefined();
});

test("resists prototype pollution via Object.defineProperty", async () => {
  setupMocks();
  const workerModule = await import("../../src/worker/signing-worker");
  for (let i = 0; i < 10; i++) {
    if (capturedMessageListener) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  if (!capturedMessageListener) throw new Error("listener not captured");

  const payload: any = { type: "sign", requestId: 1, canonical: "good" };
  Object.defineProperty(payload, "__proto__", {
    value: { polluted: true },
    enumerable: true,
  });

  await capturedMessageListener(
    new MessageEvent("message", { data: payload } as any),
  );

  expect((Object.prototype as any).polluted).toBeUndefined();
});

// Test with toNullProto and toCanonicalValue from the old plan
test("toNullProto prevents prototype pollution", async () => {
  const mod = await import("../../src/postMessage");
  const toNullProto = (mod as any).__test_toNullProto as (
    o: unknown,
  ) => unknown;

  const payloads = [
    JSON.parse('{"__proto__": {"isPolluted": true}}'),
    JSON.parse('{"constructor": {"prototype": {"isPolluted": true}}}'),
  ];

  payloads.forEach((payload) => {
    const sanitized = toNullProto(payload);
    expect((Object.prototype as any).isPolluted).toBeUndefined();
    expect((sanitized as any).isPolluted).toBeUndefined();
  });
});

test("toCanonicalValue prevents prototype pollution", async () => {
  const mod = await import("../../src/canonical");
  const toCanonicalValue = (mod as any).toCanonicalValue as (
    o: unknown,
  ) => unknown;

  const payloads = [
    JSON.parse('{"__proto__": {"isPolluted": true}}'),
    JSON.parse('{"constructor": {"prototype": {"isPolluted": true}}}'),
  ];

  payloads.forEach((payload) => {
    const canonical = toCanonicalValue(payload);
    expect((Object.prototype as any).isPolluted).toBeUndefined();
    expect((canonical as any).isPolluted).toBeUndefined();
  });
});
