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

vi.stubGlobal("crypto", {
  subtle: {
    importKey: mockImportKey,
    sign: mockSign,
    verify: mockVerify,
  },
});

// Mock the global postMessage function (available in Web Workers)
vi.stubGlobal("postMessage", mockPostMessage);

// Mock the postMessage module BEFORE importing the worker
let capturedOnMessage: any;
vi.mock("../../src/postMessage", () => ({
  createSecurePostMessageListener: vi.fn((options) => {
    // Capture the onMessage callback
    capturedOnMessage = options.onMessage;
    return { destroy: vi.fn() };
  }),
  computeInitialAllowedOrigin: vi.fn(() => "https://example.com"),
  isEventAllowedWithLock: vi.fn(() => true),
}));

describe("signing-worker", () => {
  let workerModule: any;

  beforeEach(async () => {
    vi.clearAllMocks();

    // Reset mocks to default behavior
    mockImportKey.mockResolvedValue({} as CryptoKey);
    mockSign.mockResolvedValue(new ArrayBuffer(32));
    mockVerify.mockResolvedValue(true);

    // Import the worker module dynamically after mocks are set up
    workerModule = await import("../../src/worker/signing-worker");
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
    // Since we're using vi.doMock, we can't directly check the mock
    // But we can verify the worker module was imported successfully
    expect(workerModule).toBeDefined();
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
      options: {}
    };

    // Create a proper MessageEvent and trigger the listener
    const mockEvent = new MessageEvent("message", {
      data: initMessage,
      origin: "https://example.com",
    });

    // Wait for the worker to initialize and capture the listener
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(capturedOnMessage).toBeDefined();

    // Call the listener with the event
    await capturedOnMessage(initMessage, {
      origin: "https://example.com",
      source: null,
      ports: [],
      event: mockEvent,
    });

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
      options: {}
    };
    const initEvent = new MessageEvent("message", {
      data: initMessage,
      origin: "https://example.com",
    });

    await capturedOnMessage(initMessage, {
      origin: "https://example.com",
      source: null,
      ports: [],
      event: initEvent,
    });

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
    await capturedOnMessage(signMessage, {
      origin: "https://example.com",
      source: null,
      ports: [],
      event: signEvent,
    });

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
      options: {}
    };
    const initEvent = new MessageEvent("message", {
      data: initMessage,
      origin: "https://example.com",
    });

    // Initialize first
    await capturedOnMessage(initMessage, {
      origin: "https://example.com",
      source: null,
      ports: [],
      event: initEvent,
    });

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
    await capturedOnMessage(handshakeMessage, {
      origin: "https://example.com",
      source: null,
      ports: [mockReplyPort as any],
      event: handshakeEvent,
    });

    // Verify handshake was processed
    expect(mockReplyPort.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "handshake",
        signature: expect.any(String)
      })
    );
  });

  it("handles destroy message through postMessage", async () => {
    // First initialize
    const initMessage = {
      type: "init",
      secretBuffer: new ArrayBuffer(32),
      options: {}
    };
    const initEvent = new MessageEvent("message", {
      data: initMessage,
      origin: "https://example.com",
    });

    // Initialize first
    await capturedOnMessage(initMessage, {
      origin: "https://example.com",
      source: null,
      ports: [],
      event: initEvent,
    });

    // Clear previous calls
    mockPostMessage.mockClear();

    // Send destroy message
    const destroyMessage = { type: "destroy" };
    const destroyEvent = new MessageEvent("message", {
      data: destroyMessage,
      origin: "https://example.com",
    });
    await capturedOnMessage(destroyMessage, {
      origin: "https://example.com",
      source: null,
      ports: [],
      event: destroyEvent,
    });

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

    await capturedOnMessage(invalidMessage, {
      origin: "https://example.com",
      source: null,
      ports: [],
      event: event,
    });

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

    await capturedOnMessage(malformedMessage, {
      origin: "https://example.com",
      source: null,
      ports: [],
      event: event,
    });

    expect(mockPostMessage).toHaveBeenCalledWith({
      type: "error",
      reason: "invalid-message-format"
    });
  });
});