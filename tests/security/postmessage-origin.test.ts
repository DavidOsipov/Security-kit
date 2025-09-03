// tests/security/postmessage-origin.test.ts
// RULE-ID: postmessage-origin

import { test, expect, vi, beforeEach, afterEach } from "vitest";

// This test ensures the worker enforces a strict allowed origin and rejects others.

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
  vi.stubGlobal("location", { origin: "https://allowed.example" });

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
    computeInitialAllowedOrigin: vi.fn(() => "https://allowed.example"),
    isEventAllowedWithLock: vi.fn((event, lock) => {
      return event.origin === lock;
    }),
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

test("worker rejects messages from wrong origin", async () => {
  const mocks = setupMocks();
  const workerModule = await import("../../src/worker/signing-worker");
  // Wait for listener
  for (let i = 0; i < 10; i++) {
    if (capturedMessageListener) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  if (!capturedMessageListener) throw new Error("listener not captured");

  // Initialize from allowed origin
  const initEvent = new MessageEvent("message", {
    data: { type: "init", secretBuffer: new ArrayBuffer(32) },
    origin: "https://allowed.example",
  } as any);
  await capturedMessageListener(initEvent);
  mockPostMessage.mockClear();

  // Send sign from disallowed origin
  const badEvent = new MessageEvent("message", {
    data: { type: "sign", requestId: 1, canonical: "x" },
    origin: "https://evil.example",
  } as any);
  await capturedMessageListener(badEvent);

  // No response expected (silently ignored) or safe error — ensure not signed
  const calls = mockPostMessage.mock.calls || [];
  for (const c of calls) {
    const msg = c[0];
    expect(msg.type).not.toBe("signed");
  }
});
