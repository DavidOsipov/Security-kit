import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock MessageEvent and MessagePort
class MockMessagePort {
  postMessage = vi.fn();
  close = vi.fn();
  addEventListener = vi.fn();
  removeEventListener = vi.fn();
  start = vi.fn();
  dispatchEvent = vi.fn();
}

// Mock the Web Worker environment BEFORE importing the worker module
const mockPostMessage = vi.fn();
const mockAddEventListener = vi.fn();
const mockRemoveEventListener = vi.fn();
const mockImportKey = vi.fn();
const mockSign = vi.fn();
const mockVerify = vi.fn();
const mockClose = vi.fn();

// Setup global mocks BEFORE module import
vi.stubGlobal("self", {
  postMessage: mockPostMessage,
  addEventListener: mockAddEventListener,
  removeEventListener: mockRemoveEventListener,
  close: mockClose,
});

vi.stubGlobal("location", {
  origin: "https://example.com",
});

// Make mockAddEventListener available to the environment
(globalThis as any).mockAddEventListener = mockAddEventListener;

vi.stubGlobal("crypto", {
  subtle: {
    importKey: mockImportKey,
    sign: mockSign,
    verify: mockVerify,
  },
});

// Mock the global postMessage function (available in Web Workers)
vi.stubGlobal("postMessage", mockPostMessage);

// Hoisted mocks used by vi.mock factory
const __hoisted = vi.hoisted(() => ({
  mockCreateSecurePostMessageListener: vi.fn(),
  registeredListener: undefined as undefined | ((e: MessageEvent) => unknown),
}));

// Mock the postMessage module using vi.mock (with hoisting)
vi.mock("../../src/postMessage", () => ({
  createSecurePostMessageListener: __hoisted.mockCreateSecurePostMessageListener.mockImplementation(
    (options: any) => {
      // Simulate the actual behavior: set up a message event listener
      const listener = async (event: MessageEvent) => {
        await options.onMessage(event.data, {
          origin: (event as any).origin,
          source: (event as any).source,
          ports: (event as any).ports,
          event,
        });
      };
      __hoisted.registeredListener = listener;
      return { destroy: vi.fn() };
    }
  ),
  computeInitialAllowedOrigin: vi.fn(() => "https://example.com"),
  isEventAllowedWithLock: vi.fn(() => true),
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
    // Re-import worker each test to ensure fresh listener registration
    vi.resetModules();
    await import("../../src/worker/signing-worker");
  });

  afterEach(() => {
    vi.clearAllTimers();
  });

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
    // The worker should have registered a listener via our mock
    expect(__hoisted.mockCreateSecurePostMessageListener).toHaveBeenCalled();
    expect(__hoisted.registeredListener).toBeTypeOf("function");
  });

  // Test that the worker module can be imported without errors
  it("worker module imports successfully", () => {
    expect(() => {
      // The worker module should have been imported at the top
      expect(workerModule).toBeDefined();
    }).not.toThrow();
  });

  // Test basic mock setup
  it("mocks are properly configured", () => {
    expect(mockPostMessage).toBeDefined();
    expect(mockAddEventListener).toBeDefined();
  });

  // Test that crypto operations are mocked
  it("crypto operations are mocked", async () => {
    const result = await mockImportKey();
    expect(result).toBeDefined();

    const signResult = await mockSign();
    expect(signResult).toBeInstanceOf(ArrayBuffer);
  });

  // Test that actually exercises worker functionality
  it("handles init message through postMessage", async () => {
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {}
    };

    // Create a proper MessageEvent and trigger the listener
    const mockEvent = new MessageEvent("message", {
      data: initMessage,
      origin: "https://example.com",
    });
    const listener = __hoisted.registeredListener!;
    await listener(mockEvent as any);

    // Verify the message was processed
    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "initialized"
    });
  });

  it("handles sign message through postMessage", async () => {
    // First initialize
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {}
    };
    const initEvent = new MessageEvent("message", {
      data: initMessage,
      origin: "https://example.com",
    });
  const listener = __hoisted.registeredListener!;
  await listener(initEvent as any);

    // Clear previous calls
    mockPostMessage.mockClear();

    // Now send sign message
    const signMessage = {
      type: "sign",
      requestId: 123,
      canonical: "test-canonical-string"
    };
    const signEvent = new MessageEvent("message", {
      data: signMessage,
      origin: "https://example.com",
    });
  await listener(signEvent as any);

    // Verify the sign operation was processed
    expect(mockPostMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "signed",
        requestId: 123
      })
    );
  });

  it("handles handshake message through postMessage", async () => {
    // First initialize
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {}
    };
    const initEvent = new MessageEvent("message", {
      data: initMessage,
      origin: "https://example.com",
    });
  const listener = __hoisted.registeredListener!;
  await listener(initEvent as any);

    // Clear previous calls
    mockPostMessage.mockClear();

    // Send handshake message
    const mockReplyPort = new MockMessagePort();
    const handshakeMessage = {
      type: "handshake",
      nonce: "test-nonce-123",
      replyPort: mockReplyPort
    };
    const handshakeEvent = new MessageEvent("message", {
      data: handshakeMessage,
      origin: "https://example.com",
      ports: [mockReplyPort as any],
    });
  await listener(handshakeEvent as any);

    // Verify handshake was processed
    expect(mockReplyPort.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "handshake",
        signature: expect.any(String),
      })
    );
  });

  it("handles destroy message through postMessage", async () => {
    // First initialize
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      workerOptions: {}
    };
    const initEvent = new MessageEvent("message", {
      data: initMessage,
      origin: "https://example.com",
    });
  const listener = __hoisted.registeredListener!;
  await listener(initEvent as any);

    // Clear previous calls
    mockPostMessage.mockClear();

    // Send destroy message
    const destroyMessage = { type: "destroy" };
    const destroyEvent = new MessageEvent("message", {
      data: destroyMessage,
      origin: "https://example.com",
    });
  await listener(destroyEvent as any);

    // Verify destroy was processed
    expect(mockPostMessage).toHaveBeenCalledWith({ type: "destroyed" });
    expect(mockClose).toHaveBeenCalled();
  });

  it("rejects invalid message types", async () => {
    const invalidMessage = { type: "invalid-type" };
    const event = new MessageEvent("message", {
      data: invalidMessage,
      origin: "https://example.com",
    });
  const listener = __hoisted.registeredListener!;
  await listener(event as any);

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      requestId: undefined,
      reason: "unknown-message-type",
    });
  });

  it("handles malformed messages gracefully", async () => {
    const malformedMessage = null;
    const event = new MessageEvent("message", {
      data: malformedMessage,
      origin: "https://example.com",
    });
  const listener = __hoisted.registeredListener!;
  await listener(event as any);

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "invalid-message-format"
    });
  });
});