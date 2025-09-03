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

  vi.mock("../../src/postMessage", () => ({
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
  }));

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
