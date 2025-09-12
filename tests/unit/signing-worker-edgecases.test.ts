import { describe, it, expect, vi, beforeEach } from "vitest";

// Enable test APIs
process.env.SECURITY_KIT_ALLOW_TEST_APIS = "true";

// Hoisted mock holder so the mock implementation can expose the registered listener
const __hoisted = vi.hoisted(() => ({
  mockCreateSecurePostMessageListener: vi.fn(),
  registeredListener: undefined as undefined | ((e: MessageEvent) => unknown),
  isEventAllowedWithLock: vi.fn(() => true),
}));

// Mock postMessage module so we capture the registered listener and control origin checks
vi.mock("../../src/postMessage", () => ({
  createSecurePostMessageListener:
    __hoisted.mockCreateSecurePostMessageListener.mockImplementation(
      (options: any) => {
        const listener = async (event: MessageEvent) => {
          await options.onMessage(event.data, {
            event,
            origin: (event as any).origin,
            source: (event as any).source,
            ports: (event as any).ports,
          });
        };
        __hoisted.registeredListener = listener;
        return { destroy: vi.fn() };
      },
    ),
  computeInitialAllowedOrigin: vi.fn(() => "https://example.com"),
  isEventAllowedWithLock: (...args: unknown[]) => __hoisted.isEventAllowedWithLock(...(args as [])),
}));

// Mock config to control nonce policies
vi.mock("../../src/config", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/config")>();
  return {
    ...actual,
    getHandshakeConfig: vi.fn(() => ({
      allowedNonceFormats: ["base64", "base64url", "hex"],
      handshakeMaxNonceLength: 64,
    })),
    setHandshakeConfig: vi.fn(),
  };
});

// Mock encoding-utils for format checks
vi.mock("../../src/encoding-utils", () => ({
  isLikelyBase64: vi.fn((s: string) => /^[A-Za-z0-9+/=]+$/.test(s)),
  isLikelyBase64Url: vi.fn((s: string) => /^[A-Za-z0-9_-]+$/.test(s)),
}));

// Provide minimal global worker environment mocks before importing worker module
const mockPostMessage = vi.fn();
vi.stubGlobal("postMessage", mockPostMessage);
vi.stubGlobal("location", { origin: "https://example.com" });

// Minimal crypto mocks needed for init path
const mockImportKey = vi.fn();
const mockSign = vi.fn();
vi.stubGlobal("crypto", {
  subtle: {
    importKey: mockImportKey,
    sign: mockSign,
  },
});

// Import the worker module (module registers the listener)
import * as workerModule from "../../src/worker/signing-worker";

describe("signing-worker edge cases", () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    mockImportKey.mockResolvedValue({} as CryptoKey);
    mockSign.mockResolvedValue(new ArrayBuffer(32));
    // Re-import to ensure fresh registration of mocked listener
    vi.resetModules();
    // Re-require postMessage mock so hoisted state remains
    await import("../../src/worker/signing-worker");
  });

  it("should reply with nonce-format-invalid when handshake nonce format is invalid", async () => {
    // Initialize the worker first so it accepts handshake and has hmacKey
    const initMessage = { type: "init", secretBuffer: new ArrayBuffer(32), workerOptions: {} };
    const initEvent = new MessageEvent("message", { data: initMessage, origin: "https://example.com" });
    const listener = __hoisted.registeredListener!;
    await listener(initEvent as any);

    // Prepare a reply port mock
    const mockReplyPort = { postMessage: vi.fn() } as unknown as MessagePort;

    // Send handshake with invalid nonce format
    const handshakeMessage = { type: "handshake", nonce: "!invalid+nonce@" };
    const handshakeEvent = new MessageEvent("message", { data: handshakeMessage, origin: "https://example.com", ports: [mockReplyPort as any] });
    await listener(handshakeEvent as any);

    expect(mockReplyPort.postMessage).toHaveBeenCalledWith(expect.objectContaining({ type: "error", reason: "nonce-format-invalid" }));
  });

  it("should post invalid-handshake when reply port is missing", async () => {
    // Initialize first
    const initMessage = { type: "init", secretBuffer: new ArrayBuffer(32), workerOptions: {} };
    const initEvent = new MessageEvent("message", { data: initMessage, origin: "https://example.com" });
    const listener = __hoisted.registeredListener!;
    await listener(initEvent as any);

    // Send handshake without ports
    const handshakeMessage = { type: "handshake", nonce: "SGVsbG8=" };
    const handshakeEvent = new MessageEvent("message", { data: handshakeMessage, origin: "https://example.com" });
    await listener(handshakeEvent as any);

    expect(mockPostMessage).toHaveBeenCalledWith({ type: "error", reason: "invalid-handshake" });
  });

  it("should silently drop messages when origin is rejected by lock", async () => {
    // Configure the imported isEventAllowedWithLock to return false to simulate origin mismatch
    __hoisted.isEventAllowedWithLock.mockReturnValue(false);

    const listener = __hoisted.registeredListener!;

    const signMessage = { type: "sign", requestId: 1, canonical: "x" };
    const signEvent = new MessageEvent("message", { data: signMessage, origin: "https://attacker.example" });

    await listener(signEvent as any);

    // Should not post any errors (message is dropped)
    expect(mockPostMessage).not.toHaveBeenCalled();
  });
});
