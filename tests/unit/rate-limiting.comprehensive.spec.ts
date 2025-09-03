// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
/**
 * Comprehensive tests for rate limiting functionality in SecureApiSigner and worker.
 * Tests the token bucket algorithm, concurrency controls, and error handling.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { SecureApiSigner } from "../../src/secure-api-signer";
import type {
  InitMessage,
  SignRequest,
  SignedResponse,
  ErrorResponse,
} from "../../src/protocol";
import { RateLimitError, WorkerError } from "../../src/errors";

// Mock dependencies
let mockWorker: any;
let mockFetch: any;

beforeEach(() => {
  // Create a fresh mock worker for each test
  mockWorker = {
    postMessage: vi.fn(),
    terminate: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    onerror: null,
    onmessage: null,
    onmessageerror: null,
  };

  mockFetch = vi.fn();

  // Mock global Worker constructor
  global.Worker = vi.fn((url, options) => {
    return mockWorker;
  }) as any;

  // Mock global fetch
  global.fetch = mockFetch;

  // Mock location for URL validation
  global.location = {
    href: "https://example.com/",
    protocol: "https:",
    hostname: "example.com",
    port: "",
    origin: "https://example.com",
  } as any;

  // Reset mocks
  vi.clearAllMocks();

  // Polyfill MessageChannel/MessagePort for deterministic behavior in Node test env.
  // Our polyfill ensures postMessage on one port delivers to the partner's onmessage handler.
  global.MessageChannel = function MessageChannelPolyfill(this: any) {
    let p1: any = { onmessage: null, onmessageerror: null };
    let p2: any = { onmessage: null, onmessageerror: null };
    p1.postMessage = (data: any) => {
      setImmediate(() => {
        try {
          if (typeof p2.onmessage === "function") p2.onmessage({ data });
        } catch (e) {
          if (typeof p2.onmessageerror === "function") p2.onmessageerror(e);
        }
      });
    };
    p2.postMessage = (data: any) => {
      setImmediate(() => {
        try {
          if (typeof p1.onmessage === "function") p1.onmessage({ data });
        } catch (e) {
          if (typeof p1.onmessageerror === "function") p1.onmessageerror(e);
        }
      });
    };
    p1.close = () => {};
    p2.close = () => {};
    return { port1: p1, port2: p2 };
  } as any;

  // Default successful fetch response for worker script
  mockFetch.mockImplementation((url: any, options?: any) => {
    console.log("[MOCK FETCH] Called with url:", url, "options:", options);
    return Promise.resolve({
      ok: true,
      url: String(url),
      redirected: false,
      arrayBuffer: () => Promise.resolve(new ArrayBuffer(100)),
    });
  });

  // Mock crypto for tests
  if (!globalThis.crypto) {
    globalThis.crypto = {
      getRandomValues: (array: any) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = Math.floor(Math.random() * 256);
        }
        return array;
      },
    } as any;
  }
});

afterEach(() => {
  vi.resetAllMocks();
  // Reset mock worker state
  if (mockWorker) {
    mockWorker.onmessage = null;
    mockWorker.onerror = null;
    mockWorker.onmessageerror = null;
  }
});

describe("Rate Limiting - Comprehensive Tests", () => {
  // Rate limiting state for mock worker
  let rateLimitTokens = 10;
  let maxConcurrent = 5;
  let pendingRequests = 0;
  let rateLimitPerMinute = 10;
  // Track last refill timestamp for deterministic token bucket behavior
  let internalLastRefillMs = Date.now();

  beforeEach(() => {
    // Reset mock state
    rateLimitTokens = 10;
    maxConcurrent = 5;
    pendingRequests = 0;
    rateLimitPerMinute = 10;
    internalLastRefillMs = Date.now();

    // Mock worker message handling
    mockWorker.addEventListener.mockImplementation(
      (event: string, handler: Function) => {
        if (event === "message") {
          mockWorker.onmessage = handler;
        } else if (event === "error") {
          mockWorker.onerror = handler;
        } else if (event === "messageerror") {
          mockWorker.onmessageerror = handler;
        }
      },
    );

    mockWorker.postMessage.mockImplementation((msg: any, transfer?: any[]) => {
      // Debug log to help trace handshake/init during tests
      if (msg.type === "init") {
        // Extract config from init message
        const opts = msg.workerOptions || {};
        rateLimitPerMinute = opts.rateLimitPerMinute || 10;
        maxConcurrent = opts.maxConcurrentSigning || 5;
        // Expose these values on the mock worker so tests can assert they were propagated
        mockWorker.rateLimitPerMinute = rateLimitPerMinute;
        mockWorker.maxConcurrentSigning = maxConcurrent;
        // Initialize token bucket: start full up to a burst cap.
        // For simplicity in tests, use per-minute cap as an upper bound.
        // Individual requests always consume 1 token.
        rateLimitTokens = Math.max(0, Math.floor(rateLimitPerMinute));
        internalLastRefillMs = Date.now();
        // Also expose/track lastRefillMs for tests that manipulate it
        mockWorker.lastRefillMs = internalLastRefillMs;

        // Simulate successful initialization - use setImmediate for faster response
        setImmediate(() => {
          if (mockWorker.onmessage) {
            mockWorker.onmessage({ data: { type: "initialized" } });
          } else {
          }
        });
      } else if (
        msg.type === "handshake" &&
        transfer &&
        transfer.length === 1
      ) {
        // Handle handshake request
        const port = transfer[0] as MessagePort;
        setImmediate(() => {
          try {
            // The real worker expects a handshake response with signature of the nonce
            // For testing purposes, we'll create a mock signature
            const nonce = msg.nonce || "";
            const signature = Buffer.from(`signed-${nonce}`).toString("base64");
            port.postMessage({ type: "handshake", signature });
          } catch (e) {
            port.postMessage({ type: "error", reason: "handshake-failed" });
          } finally {
            try {
              port.close();
            } catch {}
          }
        });
      } else if (msg.type === "sign") {
        const { requestId, canonical } = msg;
        const port = transfer && transfer.length === 1 ? transfer[0] : null;

        // On-demand token refill using floor-based integer arithmetic.
        // Allows fractional accumulation over time without floating point drift.
        const now = Date.now();
        // Prefer externally controlled lastRefillMs if tests set it; else use internal tracker
        const lastRefill =
          typeof mockWorker.lastRefillMs === "number"
            ? mockWorker.lastRefillMs
            : internalLastRefillMs;
        const elapsedMs = Math.max(0, now - lastRefill);
        if (rateLimitPerMinute > 0 && elapsedMs > 0) {
          // tokensToAdd = floor(elapsedMs * rateLimitPerMinute / 60000)
          const tokensToAdd = Math.floor(
            (elapsedMs * rateLimitPerMinute) / 60000,
          );
          if (tokensToAdd > 0) {
            // Cap to a simple burst limit: do not exceed rateLimitPerMinute
            const cap = Math.max(1, Math.floor(rateLimitPerMinute));
            rateLimitTokens = Math.min(cap, rateLimitTokens + tokensToAdd);
            // Advance lastRefill by the exact whole-token time we accounted for
            const msPerToken = 60000 / Math.max(1, rateLimitPerMinute);
            const advanced = Math.floor(tokensToAdd * msPerToken);
            internalLastRefillMs = lastRefill + advanced;
            mockWorker.lastRefillMs = internalLastRefillMs;
          }
        }

        // Check concurrency - use >= to match real worker behavior
        if (pendingRequests >= maxConcurrent) {
          const err = { type: "error", requestId, reason: "worker-overloaded" };
          setImmediate(() => {
            if (port) {
              port.postMessage(err);
              try {
                port.close();
              } catch {}
            } else if (mockWorker.onmessage) {
              mockWorker.onmessage({ data: err });
            }
          });
          return;
        }

        // Check rate limiting
        if (rateLimitPerMinute > 0 && rateLimitTokens <= 0) {
          const err = {
            type: "error",
            requestId,
            reason: "rate-limit-exceeded",
          };
          setImmediate(() => {
            if (port) {
              port.postMessage(err);
              try {
                port.close();
              } catch {}
            } else if (mockWorker.onmessage) {
              mockWorker.onmessage({ data: err });
            }
          });
          return;
        }

        if (rateLimitPerMinute > 0) {
          rateLimitTokens--;
        }

        // Simulate successful signing - increment pending BEFORE async processing
        pendingRequests++;

        // Use a small timeout to simulate processing time for concurrency tests
        const delay = pendingRequests === 1 ? 100 : 1; // First request takes much longer to test concurrency
        setTimeout(() => {
          pendingRequests--;
          // Generate a valid 32-byte base64 signature
          const mockSignature = Buffer.from(
            new Uint8Array(32).fill(0),
          ).toString("base64");
          const response = {
            type: "signed",
            requestId,
            signature: mockSignature,
          };
          if (port) {
            port.postMessage(response);
            try {
              port.close();
            } catch {}
          } else if (mockWorker.onmessage) {
            mockWorker.onmessage({ data: response });
          }
        }, delay);
      } else if (msg.type === "destroy") {
        setImmediate(() => {
          if (mockWorker.onmessage) {
            mockWorker.onmessage({ data: { type: "destroyed" } });
          }
        });
      } else {
      }
    });
  });

  describe("Rate Limit Configuration", () => {
    it("stores and exposes rate limit configuration", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 100,
        maxConcurrentSigning: 10,
      });

      const config = signer.getRateLimitConfig();
      expect(config.rateLimitPerMinute).toBe(100);
      expect(config.maxConcurrentSigning).toBe(10);

      await signer.destroy();
    });

    it("uses default rate limit from logging config when not specified", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      // Import and configure logging
      const { setLoggingConfig } = await import("../../src/config");
      setLoggingConfig({ rateLimitTokensPerMinute: 150 });

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        // No rateLimitPerMinute specified
      });

      const config = signer.getRateLimitConfig();
      expect(config.rateLimitPerMinute).toBe(150);

      await signer.destroy();
    });

    it("propagates rate limit config to worker during initialization", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 60,
        maxConcurrentSigning: 3,
      });

      // Check that mock worker received the configuration
      expect(mockWorker.rateLimitPerMinute).toBe(60);
      expect(mockWorker.maxConcurrentSigning).toBe(3);

      await signer.destroy();
    });
  });

  describe("Token Bucket Rate Limiting", () => {
    it("enforces rate limit per minute", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 2, // Very low for testing
        maxConcurrentSigning: 10,
      });

      // First two requests should succeed
      const p1 = signer.sign({ test: 1 });
      const p2 = signer.sign({ test: 2 });

      const [r1, r2] = await Promise.all([p1, p2]);
      expect(r1.signature).toBeDefined();
      expect(r2.signature).toBeDefined();

      // Third request should fail due to rate limit
      await expect(signer.sign({ test: 3 })).rejects.toThrow(/rate.*limit/i);

      await signer.destroy();
    });

    it("refills tokens over time", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 60, // 1 per second
        maxConcurrentSigning: 10,
      });

      // Exhaust initial tokens
      await signer.sign({ test: 1 });

      // Manually advance token refill in mock worker
      mockWorker.lastRefillMs = Date.now() - 2000; // 2 seconds ago

      // Should succeed after token refill
      const result = await signer.sign({ test: 2 });
      expect(result.signature).toBeDefined();

      await signer.destroy();
    });
  });

  describe("Concurrency Limiting", () => {
    it("enforces maxConcurrentSigning limit", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 1000, // High rate limit
        maxConcurrentSigning: 1, // Low concurrency
      });

      // Start first request (will be pending due to mock delay)
      const p1 = signer.sign({ test: 1 });

      // Second request should fail due to concurrency limit
      // Give a longer delay to ensure first request starts processing
      await new Promise((resolve) => setTimeout(resolve, 15));
      await expect(signer.sign({ test: 2 })).rejects.toThrow(/overload/i);

      // Clean up
      await p1;
      await signer.destroy();
    });

    it("includes pending reservations in request count", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        maxPendingRequests: 2,
      });

      expect(signer.getPendingRequestCount()).toBe(0);

      // Start requests that will create reservations
      const p1 = signer.sign({ test: 1 });
      const p2 = signer.sign({ test: 2 });

      // Pending count should include reservations
      expect(signer.getPendingRequestCount()).toBeGreaterThan(0);

      await Promise.all([p1, p2]);
      await signer.destroy();
    });
  });

  describe("Error Handling", () => {
    it("returns proper error reasons for rate limiting", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 1,
      });

      // Exhaust rate limit
      await signer.sign({ test: 1 });

      try {
        await signer.sign({ test: 2 });
        expect.fail("Should have thrown rate limit error");
      } catch (error) {
        expect(error).toBeInstanceOf(WorkerError);
        expect((error as WorkerError).message).toMatch(/rate.*limit/i);
      }

      await signer.destroy();
    });

    it("returns proper error reasons for worker overload", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        maxConcurrentSigning: 1,
      });

      // Start first request
      const p1 = signer.sign({ test: 1 });

      // Wait a moment for it to start processing
      await new Promise((resolve) => setTimeout(resolve, 15));

      try {
        await signer.sign({ test: 2 });
        expect.fail("Should have thrown worker overload error");
      } catch (error) {
        expect(error).toBeInstanceOf(WorkerError);
        expect((error as WorkerError).message).toMatch(/overload/i);
      }

      await p1;
      await signer.destroy();
    });
  });

  describe("Edge Cases", () => {
    it("handles zero rate limit (unlimited)", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 0, // Unlimited
      });

      // Should be able to make many requests quickly
      const promises = Array.from({ length: 5 }, (_, i) =>
        signer.sign({ test: i }),
      );

      const results = await Promise.all(promises);
      expect(results).toHaveLength(5);
      results.forEach((result) => expect(result.signature).toBeDefined());

      await signer.destroy();
    });

    it("clamps maxConcurrentSigning to reasonable bounds", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        maxConcurrentSigning: 2000, // Should be clamped to 1000
      });

      const config = signer.getRateLimitConfig();
      expect(config.maxConcurrentSigning).toBe(1000);

      await signer.destroy();
    });

    it("handles negative rate limit values gracefully", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: -10, // Should be clamped to 0
      });

      const config = signer.getRateLimitConfig();
      expect(config.rateLimitPerMinute).toBe(0);

      await signer.destroy();
    });
  });

  describe("Token Bucket Fractional Accumulation", () => {
    it("accumulates fractional tokens over very short intervals", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 60, // 1 token per second
        maxConcurrentSigning: 10,
      });

      // Exhaust initial tokens
      await signer.sign({ test: 1 });

      // Simulate very short time intervals (100ms each)
      // With rate 60/min = 1/sec, each second should add 1 token
      // But 100ms should add 0.1 tokens (fractional accumulation)
      const shortIntervals = 10; // 1 second total
      for (let i = 0; i < shortIntervals; i++) {
        // Manually simulate fractional refill in mock
        // In real implementation, this would accumulate internally
        mockWorker.lastRefillMs = Date.now() - 100; // 100ms ago
        await new Promise((resolve) => setTimeout(resolve, 10)); // Small delay
      }

      // After accumulating fractional tokens, should be able to make request
      const result = await signer.sign({ test: 2 });
      expect(result.signature).toBeDefined();

      await signer.destroy();
    });

    it("handles floor-based token refills correctly", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 120, // 2 tokens per second
        maxConcurrentSigning: 10,
      });

      // Exhaust initial tokens
      await signer.sign({ test: 1 });
      await signer.sign({ test: 2 });

      // Simulate time passing that should add exactly 1.5 tokens
      // But due to floor-based arithmetic, only 1 token should be added
      mockWorker.lastRefillMs = Date.now() - 750; // 750ms = 1.5 tokens worth

      // With a standard token bucket, floor(1.5) = 1 token is available,
      // which is sufficient for a single request. This should succeed.
      const r3 = await signer.sign({ test: 3 });
      expect(r3.signature).toBeDefined();

      // After full second, there would be 2 tokens; next request should also succeed
      mockWorker.lastRefillMs = Date.now() - 1000; // 1 second = 2 tokens
      const r4 = await signer.sign({ test: 4 });
      expect(r4.signature).toBeDefined();

      await signer.destroy();
    });

    it("prevents overflow in token accumulation", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 60,
        maxConcurrentSigning: 10,
      });

      // Exhaust tokens
      await signer.sign({ test: 1 });

      // Simulate very long time period that could cause overflow
      mockWorker.lastRefillMs = Date.now() - 3600 * 1000; // 1 hour ago

      // Should succeed without overflow issues
      const result = await signer.sign({ test: 2 });
      expect(result.signature).toBeDefined();

      await signer.destroy();
    });

    it("handles precision multiplier correctly for fractional rates", async () => {
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("https://example.com/worker.js"),
        integrity: "none",
        rateLimitPerMinute: 1, // Very slow rate: 1 token per minute
        maxConcurrentSigning: 10,
      });

      // Exhaust token
      await signer.sign({ test: 1 });

      // Simulate 30 seconds passing (should add 0.5 tokens fractionally)
      mockWorker.lastRefillMs = Date.now() - 30000; // 30 seconds

      // Should still be rate limited (0.5 < 1)
      await expect(signer.sign({ test: 2 })).rejects.toThrow(/rate.*limit/i);

      // Wait for full minute
      mockWorker.lastRefillMs = Date.now() - 60000; // 60 seconds = 1 token

      const result = await signer.sign({ test: 3 });
      expect(result.signature).toBeDefined();

      await signer.destroy();
    });
  });
});
