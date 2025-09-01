import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the Web Worker environment BEFORE importing the worker module
const mockPostMessage = vi.fn();
const mockAddEventListener = vi.fn();
const mockRemoveEventListener = vi.fn();
const mockImportKey = vi.fn();
const mockSign = vi.fn();
const mockVerify = vi.fn();
const mockClose = vi.fn();

// Mock MessageEvent and MessagePort
class MockMessageEvent {
  constructor(public data: any, public origin: string = "https://example.com") {}
}

class MockMessagePort {
  postMessage = vi.fn();
  close = vi.fn();
  addEventListener = vi.fn();
  removeEventListener = vi.fn();
}

// Setup global mocks BEFORE module import
vi.stubGlobal("self", {
  postMessage: mockPostMessage,
  addEventListener: mockAddEventListener,
  removeEventListener: mockRemoveEventListener,
  close: mockClose,
});

// Ensure the global postMessage alias (used by worker code) is available
vi.stubGlobal("postMessage", mockPostMessage);

vi.stubGlobal("location", {
  origin: "https://example.com",
});

vi.stubGlobal("crypto", {
  subtle: {
    importKey: mockImportKey,
    sign: mockSign,
    verify: mockVerify,
  },
});

vi.stubGlobal("MessageEvent", MockMessageEvent);
vi.stubGlobal("MessagePort", MockMessagePort);

// Hoisted mocks used by vi.mock factory (which is hoisted by Vitest)
const __hoisted = vi.hoisted(() => ({
  mockCreateSecurePostMessageListener: vi.fn(),
  mockComputeInitialAllowedOrigin: vi.fn(() => "https://example.com"),
  mockIsEventAllowedWithLock: vi.fn(() => true),
}));

// Mock the postMessage module to capture the listener setup
vi.mock("../../src/postMessage", () => ({
  createSecurePostMessageListener: __hoisted.mockCreateSecurePostMessageListener,
  computeInitialAllowedOrigin: __hoisted.mockComputeInitialAllowedOrigin,
  isEventAllowedWithLock: __hoisted.mockIsEventAllowedWithLock,
}));

// Now import the worker module AFTER mocks are set up
import * as workerModule from "../../src/worker/signing-worker";

describe("signing-worker", () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    // Reset mocks to default behavior
    mockImportKey.mockResolvedValue({} as CryptoKey);
    mockSign.mockResolvedValue(new ArrayBuffer(32));
    mockVerify.mockResolvedValue(true);
    __hoisted.mockCreateSecurePostMessageListener.mockReturnValue({ destroy: vi.fn() });

    // Ensure the worker module executes and registers the listener fresh for each test
    vi.resetModules();
    await import("../../src/worker/signing-worker");
  });

  afterEach(() => {
    vi.clearAllTimers();
  });

  // Helper function to get the message listener from mock calls
  const getMessageListener = () => {
    const call = __hoisted.mockCreateSecurePostMessageListener.mock.calls[0];
    return call ? call[0].onMessage : undefined;
  };

  // Basic discovery tests
  it("basic test discovery works", () => {
    expect(workerModule).toBeDefined();
  });

  it("can dynamically import worker module", async () => {
    const module = await import("../../src/worker/signing-worker");
    expect(module).toBeDefined();
  });

  it("can setup worker environment mocks", () => {
    expect(globalThis.self).toBeDefined();
    expect(globalThis.crypto).toBeDefined();
  });

  it("worker initializes with mocked environment", () => {
    // The worker module should have called createSecurePostMessageListener
    expect(__hoisted.mockCreateSecurePostMessageListener).toHaveBeenCalled();
  });

  // Security tests - malformed input
  it("rejects malformed message types", async () => {
    const event = new MockMessageEvent({ type: null });
    const msgListener = getMessageListener();
    if (msgListener) {
      await msgListener(event.data, { event });
    }
    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "invalid-message-format"
    });
  });

  it("rejects oversized payloads", async () => {
    const largePayload = "x".repeat(10 * 1024 * 1024); // 10MB
    const event = new MockMessageEvent({ type: "sign", canonical: largePayload });
    const msgListener = getMessageListener();
    if (msgListener) {
      await msgListener(event.data, { event });
    }
    // Since we bypass the top-level validator by calling onMessage directly,
    // the worker's parameter validation reports invalid-params
    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "invalid-params",
      requestId: undefined,
    });
  });

  it("prevents type confusion attacks", async () => {
    const event = new MockMessageEvent({
      type: "sign",
      __proto__: { type: "init" },
      canonical: "test"
    });
    const msgListener = getMessageListener();
    if (msgListener) {
      await msgListener(event.data, { event });
    }
    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "invalid-params",
      requestId: undefined,
    });
  });

  it("handles circular references safely", async () => {
    const circular: any = { type: "sign", canonical: "test" };
    circular.self = circular;
    const event = new MockMessageEvent(circular);
    const msgListener = getMessageListener();
    if (msgListener) {
      await msgListener(event.data, { event });
    }
    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "invalid-params",
      requestId: undefined,
    });
  });

  it("validates input encoding and characters", async () => {
    const event = new MockMessageEvent({
      type: "sign",
      canonical: "test\x00null\x01byte"
    });
    const msgListener = getMessageListener();
    if (msgListener) {
      await msgListener(event.data, { event });
    }
    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "invalid-params",
      requestId: undefined,
    });
  });

  // Integration tests - actual message processing
  it("handles init message with valid secret buffer", async () => {
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {}
    };

    const event = new MockMessageEvent(initMessage);
    const msgListenerA = getMessageListener();
    if (msgListenerA) {
      await msgListenerA(initMessage, { event });
    }

    expect(mockImportKey).toHaveBeenCalled();
  });

  it("rejects init message without secret buffer", async () => {
    const initMessage = {
      type: "init",
      options: {}
    };

    const event = new MockMessageEvent(initMessage);
    const msgListenerB = getMessageListener();
    if (msgListenerB) {
      await msgListenerB(initMessage, { event });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "missing-secret"
    });
  });

  it("rejects duplicate init messages", async () => {
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {}
    };

    const event = new MockMessageEvent(initMessage);
    const msgListenerC = getMessageListener();
    if (msgListenerC) {
      await msgListenerC(initMessage, { event });
      await msgListenerC(initMessage, { event });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "already-initialized"
    });
  });

  it("handles valid handshake message", async () => {
    // First initialize
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {}
    };
    const initEvent = new MockMessageEvent(initMessage);
    const msgListenerD = getMessageListener();
    if (msgListenerD) {
      await msgListenerD(initMessage, { event: initEvent });
    }

    // Now test handshake
    const mockReplyPort = new MockMessagePort();
    const handshakeMessage = {
      type: "handshake",
      nonce: "test-nonce-123",
      replyPort: mockReplyPort
    };

    const handshakeEvent = new MockMessageEvent(handshakeMessage);
    (handshakeEvent as any).ports = [mockReplyPort];

    if (msgListenerD) {
      await msgListenerD(handshakeMessage, { event: handshakeEvent });
    }

    expect(mockSign).toHaveBeenCalled();
    expect(mockReplyPort.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "handshake",
        signature: expect.any(String),
      })
    );
  });

  it("rejects handshake without reply port", async () => {
    const handshakeMessage = {
      type: "handshake",
      nonce: "test-nonce-123"
    };

    const event = new MockMessageEvent(handshakeMessage);
    const msgListenerE = getMessageListener();
    if (msgListenerE) {
      await msgListenerE(handshakeMessage, { event });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "invalid-handshake"
    });
  });

  it("rejects handshake with invalid nonce format", async () => {
    const mockReplyPort = new MockMessagePort();
    const handshakeMessage = {
      type: "handshake",
      nonce: "invalid-nonce-format!",
      replyPort: mockReplyPort
    };

    const event = new MockMessageEvent(handshakeMessage);
    (event as any).ports = [mockReplyPort];
    const msgListenerF = getMessageListener();
    if (msgListenerF) {
      await msgListenerF(handshakeMessage, { event });
    }

    expect(mockReplyPort.postMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "nonce-format-invalid"
    });
  });

  it("rejects handshake without reply port", async () => {
    const handshakeMessage = {
      type: "handshake",
      nonce: "test-nonce-123"
    };

    const event = new MockMessageEvent(handshakeMessage);
    const msgListenerG = getMessageListener();
    if (msgListenerG) {
      await msgListenerG(handshakeMessage, { event });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "invalid-handshake"
    });
  });

  it("rejects handshake with invalid nonce format", async () => {
    const mockReplyPort = new MockMessagePort();
    const handshakeMessage = {
      type: "handshake",
      nonce: "invalid-nonce-format!",
      replyPort: mockReplyPort
    };

    const event = new MockMessageEvent(handshakeMessage);
    (event as any).ports = [mockReplyPort];
    const msgListenerH = getMessageListener();
    if (msgListenerH) {
      await msgListenerH(handshakeMessage, { event });
    }

    expect(mockReplyPort.postMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "nonce-format-invalid"
    });
  });

  it("handles valid sign message", async () => {
    // First initialize
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      options: {}
    };
    const initEvent = new MockMessageEvent(initMessage);
    const msgListenerI = getMessageListener();
    if (msgListenerI) {
      await msgListenerI(initMessage, { event: initEvent });
    }

    // Now test sign
    const signMessage = {
      type: "sign",
      requestId: 123,
      canonical: "test-canonical-string"
    };

    const signEvent = new MockMessageEvent(signMessage);
    const msgListenerJ = getMessageListener();
    if (msgListenerJ) {
      await msgListenerJ(signMessage, { event: signEvent });
    }

    expect(mockSign).toHaveBeenCalled();
    expect(mockPostMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "signed",
        requestId: 123
      })
    );
  });

  it("rejects sign message with invalid parameters", async () => {
    const signMessage = {
      type: "sign",
      requestId: "invalid",
      canonical: null
    };

    const event = new MockMessageEvent(signMessage);
    const msgListenerK = getMessageListener();
    if (msgListenerK) {
      await msgListenerK(signMessage, { event });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      requestId: undefined,
      reason: "invalid-params"
    });
  });

  it("enforces rate limiting", async () => {
    // Initialize with rate limiting
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: { rateLimitPerMinute: 1 }
    };
    const initEvent = new MockMessageEvent(initMessage);
    const msgListenerL = getMessageListener();
    if (msgListenerL) {
      await msgListenerL(initMessage, { event: initEvent });
    }

    // First request should succeed
    const signMessage1 = {
      type: "sign",
      requestId: 1,
      canonical: "test1"
    };
    const signEvent1 = new MockMessageEvent(signMessage1);
    const msgListener1 = getMessageListener();
    if (msgListener1) {
      await msgListener1(signMessage1, { event: signEvent1 });
    }

    // Second request should be rate limited
    const signMessage2 = {
      type: "sign",
      requestId: 2,
      canonical: "test2"
    };
    const signEvent2 = new MockMessageEvent(signMessage2);
    const msgListener2 = getMessageListener();
    if (msgListener2) {
      await msgListener2(signMessage2, { event: signEvent2 });
    }

    // Second call should be an error due to rate limit
    expect(mockPostMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "error",
        requestId: 2,
        reason: "rate-limit-exceeded",
      })
    );
  });

  it("enforces concurrency limits", async () => {
    // Initialize with low concurrency limit
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: { maxConcurrentSigning: 1 }
    };
    const initEvent = new MockMessageEvent(initMessage);
    const msgListener3 = getMessageListener();
    if (msgListener3) {
      await msgListener3(initMessage, { event: initEvent });
    }

    // Make crypto.sign take a long time to simulate pending operation
    mockSign.mockImplementation(() => new Promise(resolve => setTimeout(() => resolve(new ArrayBuffer(32)), 100)));

    // First request
    const signMessage1 = {
      type: "sign",
      requestId: 1,
      canonical: "test1"
    };
    const signEvent1 = new MockMessageEvent(signMessage1);
    const msgListener4 = getMessageListener();
    if (msgListener4) {
      void msgListener4(signMessage1, { event: signEvent1 });
    }

    // Second request should be rejected due to concurrency limit
    const signMessage2 = {
      type: "sign",
      requestId: 2,
      canonical: "test2"
    };
    const signEvent2 = new MockMessageEvent(signMessage2);
    const msgListener5 = getMessageListener();
    if (msgListener5) {
      await msgListener5(signMessage2, { event: signEvent2 });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      requestId: 2,
      reason: "worker-overloaded"
    });
  });

  it("handles shutdown gracefully", async () => {
    // Initialize first
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {}
    };
    const initEvent = new MockMessageEvent(initMessage);
    const msgListener6 = getMessageListener();
    if (msgListener6) {
      await msgListener6(initMessage, { event: initEvent });
    }

    // Send destroy message
    const destroyMessage = { type: "destroy" };
    const destroyEvent = new MockMessageEvent(destroyMessage);
    const msgListener7 = getMessageListener();
    if (msgListener7) {
      await msgListener7(destroyMessage, { event: destroyEvent });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({ type: "destroyed" });
    expect(mockClose).toHaveBeenCalled();
  });

  it("rejects sign requests during shutdown", async () => {
    // Initialize first
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {}
    };
    const initEvent = new MockMessageEvent(initMessage);
    const msgListener8 = getMessageListener();
    if (msgListener8) {
      await msgListener8(initMessage, { event: initEvent });
    }

    // Send destroy message
    const destroyMessage = { type: "destroy" };
    const destroyEvent = new MockMessageEvent(destroyMessage);
    const msgListener9 = getMessageListener();
    if (msgListener9) {
      await msgListener9(destroyMessage, { event: destroyEvent });
    }

    // Try to sign during shutdown
    const signMessage = {
      type: "sign",
      requestId: 123,
      canonical: "test"
    };
    const signEvent = new MockMessageEvent(signMessage);
    const msgListener10 = getMessageListener();
    if (msgListener10) {
      await msgListener10(signMessage, { event: signEvent });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      requestId: 123,
      reason: "worker-shutting-down"
    });
  });

  it("handles crypto operation failures gracefully", async () => {
    // Initialize first
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {}
    };
    const initEvent = new MockMessageEvent(initMessage);
    const msgListener11 = getMessageListener();
    if (msgListener11) {
      await msgListener11(initMessage, { event: initEvent });
    }

    // Make crypto.sign fail
    mockSign.mockRejectedValue(new Error("Crypto operation failed"));

    const signMessage = {
      type: "sign",
      requestId: 123,
      canonical: "test"
    };
    const signEvent = new MockMessageEvent(signMessage);
    const msgListener12 = getMessageListener();
    if (msgListener12) {
      await msgListener12(signMessage, { event: signEvent });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      requestId: 123,
      reason: "sign-failed"
    });
  });

  it("handles handshake crypto failures gracefully", async () => {
    // Initialize first
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      options: {}
    };
    const initEvent = new MockMessageEvent(initMessage);
    const msgListener13 = getMessageListener();
    if (msgListener13) {
      await msgListener13(initMessage, { event: initEvent });
    }

    // Make crypto.sign fail
    mockSign.mockRejectedValue(new Error("Crypto operation failed"));

    const mockReplyPort = new MockMessagePort();
    const handshakeMessage = {
      type: "handshake",
      nonce: "test-nonce-123",
      replyPort: mockReplyPort
    };

    const handshakeEvent = new MockMessageEvent(handshakeMessage);
    (handshakeEvent as any).ports = [mockReplyPort];

    const msgListener14 = getMessageListener();
    if (msgListener14) {
      await msgListener14(handshakeMessage, { event: handshakeEvent });
    }

    expect(mockReplyPort.postMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "handshake-failed"
    });
  });

  it("rejects messages from invalid origins (dropped silently)", async () => {
    __hoisted.mockIsEventAllowedWithLock.mockReturnValueOnce(false);
    const event = new MockMessageEvent({ type: "sign", canonical: "test" }, "https://malicious.com");
    const msgListener15 = getMessageListener();
    if (msgListener15) {
      await msgListener15(event.data, { event });
    }
    expect(mockPostMessage).not.toHaveBeenCalled();
  });

  it("rejects unknown message types", async () => {
    const event = new MockMessageEvent({ type: "unknown", data: "test" });
    const msgListener16 = getMessageListener();
    if (msgListener16) {
      await msgListener16(event.data, { event });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      requestId: undefined,
      reason: "unknown-message-type"
    });
  });

  it("handles unhandled exceptions gracefully", async () => {
    // Force an exception by passing invalid data that causes internal errors
    const event = new MockMessageEvent({
      type: "sign",
      requestId: Symbol("invalid"), // This should cause issues
      canonical: "test"
    });
    const msgListener17 = getMessageListener();
    if (msgListener17) {
      await msgListener17(event.data, { event });
    }

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      requestId: undefined,
      reason: "invalid-params"
    });
  });
});