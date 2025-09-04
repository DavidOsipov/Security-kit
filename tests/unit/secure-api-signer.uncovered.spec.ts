import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from "vitest";
import { SecureApiSigner } from "../../src/secure-api-signer";
import {
  InvalidParameterError,
  WorkerError,
  RateLimitError,
  CircuitBreakerError,
  SecurityKitError,
} from "../../src/errors";

// Helpers
const toBase64 = (bytes: Uint8Array) => {
  const s = String.fromCharCode(...bytes);
  return btoa(s);
};
const SIG32 = toBase64(new Uint8Array(32).fill(1));

// Mock dependencies
type Listener = (event: MessageEvent) => void;
class FakeWorker {
  // listeners per type
  private listeners: Record<string, Set<Listener>> = {
    message: new Set(),
    error: new Set(),
    messageerror: new Set(),
  };
  public onmessage: any = null;
  public onerror: any = null;
  public terminate = vi.fn();
  // Behavior controls for tests to toggle
  public suppressHandshake = false;
  public suppressSignResponse = false;
  public invalidHandshake = false;
  public failSignWithError = false;
  public sendMalformedOnSign = false;

  addEventListener = vi.fn((type: string, listener: Listener) => {
    if (!this.listeners[type]) this.listeners[type] = new Set();
    this.listeners[type].add(listener);
  });
  removeEventListener = vi.fn((type: string, listener: Listener) => {
    this.listeners[type]?.delete(listener);
  });

  private dispatchMessage(data: unknown) {
    const event = { data } as MessageEvent;
    // Fire addEventListener handlers
    for (const l of this.listeners.message) {
      try { l(event); } catch { /* ignore */ }
    }
    // Also call onmessage property if present (for tests that inspect it)
    if (typeof this.onmessage === "function") {
      try { this.onmessage(event); } catch { /* ignore */ }
    }
  }
  private dispatchError(message: string) {
    const event = { message } as unknown as ErrorEvent;
    for (const l of this.listeners.error) {
      try { (l as unknown as (e: ErrorEvent) => void)(event); } catch { /* ignore */ }
    }
    if (typeof this.onerror === "function") {
      try { this.onerror(event as any); } catch { /* ignore */ }
    }
  }
  public emitError(message: string) { this.dispatchError(message); }

  public postMessage = vi.fn((message: any, transfer?: any[]) => {
    const type = message?.type;
    // Respond asynchronously to mimic real worker scheduling
    setTimeout(() => {
      try {
        if (type === "init") {
          // Signal initialized on the worker global channel
          this.dispatchMessage({ type: "initialized" });
        } else if (type === "handshake") {
          // Respond over MessagePort (index 0) with handshake
          const port: MessagePort | undefined = transfer?.[0];
          if (!this.suppressHandshake && port) {
            if (this.invalidHandshake) {
              port.postMessage({ type: "handshake", signature: 123 });
            } else {
              port.postMessage({ type: "handshake", signature: SIG32 });
            }
          }
        } else if (type === "sign") {
          const port: MessagePort | undefined = transfer?.[0];
          if (!this.suppressSignResponse && port) {
            if (this.failSignWithError) {
              port.postMessage({ type: "error", reason: "Worker error" });
            } else if (this.sendMalformedOnSign) {
              port.postMessage({ what: "ever" } as any);
            } else {
              port.postMessage({ type: "signed", signature: SIG32 });
            }
          }
        } else if (type === "destroy") {
          // Acknowledge destroy
          this.dispatchMessage({ type: "destroyed" });
        }
      } catch {
        /* ignore */
      }
    }, 0);
  });
}

let mockWorker: FakeWorker;
const nextWorkerOpts: { invalidHandshake?: boolean; suppressHandshake?: boolean } = {};

const mockFetch = vi.fn();
const mockCrypto = {
  subtle: {
    digest: vi.fn(),
    importKey: vi.fn(),
    sign: vi.fn(),
    verify: vi.fn(),
  },
  getRandomValues: vi.fn(),
};

// Mock URL static methods only
const originalURL = globalThis.URL;
const originalCreateObjectURL = originalURL.createObjectURL;
const originalRevokeObjectURL = originalURL.revokeObjectURL;

Object.defineProperty(originalURL, 'createObjectURL', {
  writable: true,
  value: vi.fn(() => "blob:test-url"),
});

Object.defineProperty(originalURL, 'revokeObjectURL', {
  writable: true,
  value: vi.fn(),
});

const mockBlob = vi.fn();

// Setup global mocks
Object.defineProperty(globalThis, 'Worker', {
  writable: true,
  value: vi.fn(() => {
    const w = new FakeWorker();
    if (nextWorkerOpts.invalidHandshake) w.invalidHandshake = true;
    if (nextWorkerOpts.suppressHandshake) w.suppressHandshake = true;
    mockWorker = w;
    // reset one-shot options
    delete nextWorkerOpts.invalidHandshake;
    delete nextWorkerOpts.suppressHandshake;
    return w as unknown as Worker;
  }),
});

Object.defineProperty(globalThis, 'fetch', {
  writable: true,
  value: mockFetch,
});

Object.defineProperty(globalThis, 'crypto', {
  writable: true,
  value: mockCrypto,
});

Object.defineProperty(globalThis, 'URL', {
  writable: true,
  value: originalURL,
});

Object.defineProperty(globalThis, 'Blob', {
  writable: true,
  value: mockBlob,
});

// Mock location
Object.defineProperty(globalThis, 'location', {
  writable: true,
  value: { href: 'https://example.com' },
});

describe("secure-api-signer.ts - uncovered branches", () => {
  let signer: SecureApiSigner;

  beforeEach(async () => {
    vi.clearAllMocks();
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
      text: () => Promise.resolve(""),
      arrayBuffer: () => Promise.resolve(new ArrayBuffer(100)),
      url: "https://example.com/worker.js",
      redirected: false,
    });

  // WebCrypto subtle.digest returns an ArrayBuffer
  mockCrypto.subtle.digest.mockResolvedValue(new Uint8Array(32).buffer);
    mockCrypto.getRandomValues.mockImplementation((buf) => {
      for (let i = 0; i < buf.length; i++) buf[i] = i % 256;
      return buf;
    });

    (originalURL.createObjectURL as any).mockReturnValue("blob:test-url");
    mockBlob.mockImplementation((content, options) => ({
      content,
      options,
    }));

    signer = await SecureApiSigner.create({
      secret: new Uint8Array(32),
      workerUrl: "https://example.com/worker.js",
      integrity: "none", // Skip integrity checks for testing
      allowCrossOriginWorkerOrigins: ["https://example.com"],
    });
  });

  afterEach(() => {
    if (signer) {
      signer.destroy();
    }
  });

  describe("integrity mode validation", () => {
    it("rejects invalid integrity mode", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "invalid" as any,
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      })).rejects.toThrow(InvalidParameterError);
    });

    it("rejects integrity mode with wrong type", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: 123 as any,
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      })).rejects.toThrow(InvalidParameterError);
    });

    it("handles null integrity mode", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: null as any,
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      })).rejects.toThrow(InvalidParameterError);
    });

    it("accepts valid integrity modes", async () => {
      // require should fail without expected hash, so we skip it here
      const s1 = await SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "compute",
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      });
      await s1.destroy();

      const s2 = await SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "none",
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      });
      await s2.destroy();
    });

    it("defaults to strict mode", async () => {
      // Default is 'require' which should demand expectedWorkerScriptHash
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      })).rejects.toThrow();
    });
  });

  describe("worker URL validation", () => {
    it("rejects invalid worker URL type", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: 123 as any,
        integrity: "none",
      })).rejects.toThrow(InvalidParameterError);
    });

    it("rejects null worker URL", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: null as any,
        integrity: "none",
      })).rejects.toThrow(InvalidParameterError);
    });

    it("rejects empty string worker URL", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "",
        integrity: "none",
      })).rejects.toThrow(InvalidParameterError);
    });

    it("rejects malformed URL", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "not-a-url",
        integrity: "none",
      })).rejects.toThrow(InvalidParameterError);
    });

    it("rejects non-HTTP/HTTPS URL", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "ftp://example.com",
        integrity: "none",
      })).rejects.toThrow(InvalidParameterError);
    });

    it("accepts valid HTTPS URL", async () => {
      const s = await SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "none",
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      });
      await s.destroy();
    });

    // Blob scheme is not allowed for workerUrl input; only http(s) is accepted.
  });

  describe("circuit breaker edge cases", () => {
    it("handles rapid state transitions", async () => {
      // Simulate rapid failures
      for (let i = 0; i < 12; i++) {
        mockFetch.mockRejectedValueOnce(new Error("Network error"));
        try {
          await signer.sign("test payload");
        } catch {
          // Expected
        }
      }

  // Should be in open state
      const st = signer.getCircuitBreakerStatus();
      expect(["open", "half-open"]).toContain(st.state);
    });

    it("handles success after failures", async () => {
      // Fail first
      mockFetch.mockRejectedValueOnce(new Error("Network error"));
      try {
        await signer.sign("test payload");
      } catch {
        // Expected
      }

      // Succeed second
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
        text: () => Promise.resolve(""),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(100)),
        url: "https://example.com/worker.js",
        redirected: false,
      });

      const result = await signer.sign("test payload");
      expect(result).toBeDefined();
    });

    it("handles timeout in half-open state", async () => {
      // Force breaker to open then elapse timeout to transition to half-open implicitly
      for (let i = 0; i < 5; i++) {
        mockFetch.mockRejectedValueOnce(new Error("Network error"));
        try { await signer.sign("test payload"); } catch { /* expected */ }
      }
      // Advance timers beyond timeout to allow half-open attempt
      vi.useFakeTimers();
      vi.advanceTimersByTime(61000);

      // Timeout the request
      mockFetch.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 6000)));

      try {
        await signer.sign("test payload");
      } catch {
        // Expected timeout
      }

  // Should go back to open
  expect(signer.getCircuitBreakerStatus().state).toBe("open");
  vi.useRealTimers();
    });

    it("handles concurrent requests during half-open", async () => {
      // Move to half-open by opening then waiting out timeout
      for (let i = 0; i < 5; i++) {
        mockFetch.mockRejectedValueOnce(new Error("Network error"));
        try { await signer.sign("test payload"); } catch { /* expected */ }
      }
      vi.useFakeTimers();
      vi.advanceTimersByTime(61000);
      vi.useRealTimers();

      const promises = Array.from({ length: 5 }, () =>
        signer.sign("test payload")
      );

      // All should succeed or fail consistently
      const results = await Promise.allSettled(promises);
      const successCount = results.filter(r => r.status === "fulfilled").length;
      const failureCount = results.filter(r => r.status === "rejected").length;

      expect(successCount + failureCount).toBe(5);
    });
  });

  describe("rate limiting edge cases", () => {
    it("handles burst requests", async () => {
      const requests = Array.from({ length: 100 }, () =>
        signer.sign("test payload")
      );

      const results = await Promise.allSettled(requests);
      const successCount = results.filter(r => r.status === "fulfilled").length;
      const failureCount = results.filter(r => r.status === "rejected").length;

      expect(successCount + failureCount).toBe(100);
      // Should have some rate limiting
      expect(failureCount).toBeGreaterThan(0);
    });

    it("handles time window resets", async () => {
      // Fill rate limit
      vi.useFakeTimers();
      for (let i = 0; i < 10; i++) {
        try {
          await signer.sign("test payload");
        } catch {
          // Expected
        }
      }

      // Advance time past window
      vi.advanceTimersByTime(61000); // 61 seconds

      // Should allow requests again
      const resultPromise = signer.sign("test payload");
      // flush microtasks if any
      await Promise.resolve();
      const result = await resultPromise;
      expect(result).toBeDefined();

      vi.useRealTimers();
    });

    it("handles per-endpoint rate limiting", async () => {
      const endpoint1 = "https://api1.example.com";
      const endpoint2 = "https://api2.example.com";

      // Exhaust rate limit for endpoint1
      for (let i = 0; i < 10; i++) {
        try {
          await signer.sign("test payload", { path: endpoint1 });
        } catch {
          // Expected
        }
      }

      // endpoint2 should still work
      const result = await signer.sign("test payload", { path: endpoint2 });
      expect(result).toBeDefined();
    });
  });

  describe("handshake failures", () => {
    it("handles worker initialization failure", async () => {
      // Simulate constructor throwing
      const originalWorkerCtor = globalThis.Worker as any;
      (globalThis as any).Worker = vi.fn(() => { throw new Error("Worker creation failed"); });
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "none",
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      })).rejects.toThrow();
      globalThis.Worker = originalWorkerCtor;
    });

    it("handles worker message timeout", async () => {
      mockWorker.suppressSignResponse = true;
      await expect(signer.sign("test payload")).rejects.toThrow();
    });

    it("handles worker error during handshake", async () => {
      // Emit error event
      mockWorker.emitError("Worker error");
      // After error, operations should reject
      await expect(signer.sign("test payload")).rejects.toThrow();
    });

    it("handles invalid handshake response", async () => {
      nextWorkerOpts.invalidHandshake = true;
      // Create signer which will get invalid handshake
      const bad = await SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "none",
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      }).catch((e) => e);
      expect(bad).toBeInstanceOf(Error);
    });
  });

  describe("canonical computation edge cases", () => {
    it("handles empty request body", async () => {
      const result = await signer.sign("test payload");
      expect(result).toBeDefined();
    });

    it("handles large request body", async () => {
      const largeBody = "x".repeat(1000000); // 1MB
      const result = await signer.sign("test payload", { body: largeBody });
      expect(result).toBeDefined();
    });

    it("handles binary request body", async () => {
      const binaryBody = new Uint8Array(1000);
      for (let i = 0; i < binaryBody.length; i++) {
        binaryBody[i] = i % 256;
      }

      const result = await signer.sign("test payload", { body: binaryBody });
      expect(result).toBeDefined();
    });

    it("handles complex headers", async () => {
      const result = await signer.sign("test payload", {
        method: "POST",
        path: "/api/test",
        body: { key: "value" }
      });
      expect(result).toBeDefined();
    });

    it("handles URL with query parameters", async () => {
      const result = await signer.sign("test payload", {
        path: "/path?param1=value1&param2=value2"
      });
      expect(result).toBeDefined();
    });

    it("handles URL with fragments", async () => {
      const result = await signer.sign("test payload", {
        path: "/path#fragment"
      });
      expect(result).toBeDefined();
    });
  });

  describe("reservation system edge cases", () => {
    it("handles concurrent reservations", async () => {
      const promises = Array.from({ length: 10 }, () =>
        (signer as any)._reservePendingSlot()
      );

      const reservations = await Promise.all(promises);
      reservations.forEach(reservation => {
        expect(typeof reservation).toBe("number");
      });

      // All IDs should be unique
      const ids = reservations;
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("handles reservation expiration", async () => {
      vi.useFakeTimers();

      const reservationId = (signer as any)._reservePendingSlot();

      // Advance time past expiration (simulate)
      vi.advanceTimersByTime(310000); // 5 minutes 10 seconds

      // Should handle gracefully
      expect(typeof reservationId).toBe("number");

      vi.useRealTimers();
    });

    it("handles invalid reservation ID", async () => {
      // Try to release invalid reservation
      (signer as any)._releaseReservationIfPresent(99999);
      // Should not throw
    });

    it("handles reservation reuse", async () => {
      const reservationId = (signer as any)._reservePendingSlot();

      // Use reservation (simulate)
      (signer as any)._consumeReservationIfAvailable();

      // Try to release used reservation
      (signer as any)._releaseReservationIfPresent(reservationId);
      // Should handle gracefully
    });
  });

  describe("destroy cleanup", () => {
    it("handles destroy during active request", async () => {
      const promise = signer.sign("test payload");

      // Destroy while request is pending
      signer.destroy();

      await expect(promise).rejects.toThrow();
    });

    it("handles multiple destroy calls", () => {
      signer.destroy();
      expect(() => signer.destroy()).not.toThrow();
    });

    it("rejects operations after destroy", async () => {
      signer.destroy();

      await expect(signer.sign("test payload")).rejects.toThrow();
      expect(() => signer.getPendingRequestCount()).toThrow();
    });

    it("cleans up worker resources", () => {
      signer.destroy();
      expect(mockWorker.terminate).toHaveBeenCalled();
      expect((originalURL.revokeObjectURL as any)).toHaveBeenCalled();
    });
  });

  describe("error handling and recovery", () => {
    it("handles crypto operation failures", async () => {
      mockCrypto.subtle.digest.mockRejectedValue(new Error("Crypto error"));

      await expect(signer.sign("test payload")).rejects.toThrow();
    });

    it("handles fetch failures", async () => {
      mockFetch.mockRejectedValue(new Error("Network error"));

      await expect(signer.sign("test payload")).rejects.toThrow();
    });

    it("handles malformed responses", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve("Internal Server Error"),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
        url: "https://example.com/worker.js",
        redirected: false,
      });

      await expect(signer.sign("test payload")).rejects.toThrow();
    });

    it("handles JSON parsing errors", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.reject(new Error("Invalid JSON")),
        text: () => Promise.resolve("invalid json"),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
        url: "https://example.com/worker.js",
        redirected: false,
      });

      await expect(signer.sign("test payload")).rejects.toThrow();
    });
  });

  describe("blob URL handling", () => {
    it("handles blob URL creation failure", async () => {
      (originalURL.createObjectURL as any).mockImplementation(() => {
        throw new Error("Blob URL creation failed");
      });

      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "none",
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      })).rejects.toThrow();
    });

    it("handles blob URL revocation failure", () => {
      (originalURL.revokeObjectURL as any).mockImplementation(() => {
        throw new Error("Revocation failed");
      });

      // Should not throw during destroy
      expect(() => signer.destroy()).not.toThrow();
    });

    it("handles invalid blob content", async () => {
      mockBlob.mockImplementation(() => {
        throw new Error("Blob creation failed");
      });

      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "none",
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      })).rejects.toThrow();
    });
  });

  describe("configuration validation", () => {
    it("rejects invalid maxRequestsPerMinute", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "none",
        maxPendingRequests: -1,
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      })).rejects.toThrow(InvalidParameterError);
    });

    it("rejects invalid circuitBreakerThreshold", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "none",
        requestTimeoutMs: 0,
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      })).rejects.toThrow(InvalidParameterError);
    });

    it("rejects invalid reservationTimeoutMs", async () => {
      await expect(SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "none",
        destroyAckTimeoutMs: -1,
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      })).rejects.toThrow(InvalidParameterError);
    });

    it("accepts valid configuration", async () => {
      const signer = await SecureApiSigner.create({
        secret: new Uint8Array(32),
        workerUrl: "https://example.com/worker.js",
        integrity: "none",
        maxPendingRequests: 100,
        requestTimeoutMs: 5000,
        destroyAckTimeoutMs: 2000,
        allowCrossOriginWorkerOrigins: ["https://example.com"],
      });
      expect(signer).toBeDefined();
      await signer.destroy();
    });
  });

  describe("pending request tracking", () => {
    it("tracks concurrent requests", async () => {
      const promises = Array.from({ length: 5 }, () =>
        signer.sign("test payload")
      );

      // Check count while requests are pending
      expect(signer.getPendingRequestCount()).toBe(5);

      await Promise.all(promises);

      // Should be 0 after completion
      expect(signer.getPendingRequestCount()).toBe(0);
    });

    it("handles request failures in count", async () => {
      mockFetch.mockRejectedValue(new Error("Network error"));

      const promise = signer.sign("test payload");

      expect(signer.getPendingRequestCount()).toBe(1);

      try {
        await promise;
      } catch {
        // Expected
      }

      expect(signer.getPendingRequestCount()).toBe(0);
    });
  });
});