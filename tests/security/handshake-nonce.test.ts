// tests/security/handshake-nonce.test.ts
// RULE-ID: handshake-nonce-validation

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

test("worker validates handshake nonce formats and length", async () => {
  setupMocks();
  const workerModule = await import("../../src/worker/signing-worker");
  for (let i = 0; i < 10; i++) {
    if (capturedMessageListener) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  if (!capturedMessageListener) throw new Error("listener not captured");

  // Initialize worker
  const initEvent = new MessageEvent("message", {
    data: {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {
        allowedNonceFormats: ["base64"],
        handshakeMaxNonceLength: 16,
      },
    },
    origin: "https://example.com",
  } as any);
  await capturedMessageListener(initEvent);

  // Create a reply port
  const mockPort = { postMessage: vi.fn() } as any;

  // Valid nonce (base64-like)
  const good = new MessageEvent("message", {
    data: { type: "handshake", nonce: "YWJj" },
    ports: [mockPort],
  } as any);
  await capturedMessageListener(good);
  expect(mockPort.postMessage).toHaveBeenCalled();

  // Invalid format
  const badFormat = new MessageEvent("message", {
    data: { type: "handshake", nonce: "not-base64!" },
    ports: [mockPort],
  } as any);
  mockPort.postMessage.mockClear();
  await capturedMessageListener(badFormat);
  expect(mockPort.postMessage).toHaveBeenCalledWith({
    type: "error",
    reason: "nonce-format-invalid",
  });

  // Too long
  const tooLong = new MessageEvent("message", {
    data: { type: "handshake", nonce: "Y".repeat(100) },
    ports: [mockPort],
  } as any);
  mockPort.postMessage.mockClear();
  await capturedMessageListener(tooLong);
  expect(mockPort.postMessage).toHaveBeenCalledWith({
    type: "error",
    reason: "nonce-too-large",
  });
});
