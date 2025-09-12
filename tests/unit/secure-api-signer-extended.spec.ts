// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
/**
 * Comprehensive tests for SecureApiSigner with extended canonical format
 * and Security Constitution compliance features.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { withAdvancedDateNow } from "../../tests/helpers/advanceDateNow";
import { SecureApiSigner } from "../../src/secure-api-signer";
import {
  verifyApiRequestSignature,
  InMemoryNonceStore,
  type INonceStore,
  type VerifyExtendedInput,
} from "../../server/verify-api-request-signature";
import {
  CircuitBreakerError,
  RateLimitError,
  WorkerError,
  TimestampError,
  ReplayAttackError,
  SignatureVerificationError,
} from "../../src/errors";
import { safeStableStringify } from "../../src/canonical";
import { createHmac, createHash } from "crypto";
import { getSecureRandomBytesSync } from "../../src/crypto";

// Enhanced MockWorker that supports the new extended canonical format
class ExtendedMockWorker {
  listeners: Record<string, Function[]> = {};
  keyBytes: Buffer | null = null;
  opts: any;
  destroyed = false;

  constructor(url: string, opts?: any) {
    this.opts = opts || {};
  }

  addEventListener(name: string, fn: Function) {
    (this.listeners[name] = this.listeners[name] || []).push(fn);
  }

  removeEventListener(name: string, fn: Function) {
    this.listeners[name] = (this.listeners[name] || []).filter((f) => f !== fn);
  }

  postMessage(msg: any, transfer?: any[]) {
    if (this.destroyed) return;

    if (msg.type === "init") {
      this.keyBytes = Buffer.from(
        msg.secretBuffer instanceof ArrayBuffer
          ? new Uint8Array(msg.secretBuffer)
          : msg.secretBuffer,
      );
      Promise.resolve().then(() =>
        this.emit("message", { data: { type: "initialized" } }),
      );
      return;
    }

    // Handle handshake message transferred with a MessagePort
    if (msg.type === "handshake" && transfer && transfer.length === 1) {
      const port = transfer[0] as MessagePort;
      Promise.resolve().then(() => {
        try {
          const nonce = msg.nonce as string;
          const signature = this.keyBytes
            ? createHmac("sha256", this.keyBytes).update(nonce).digest("base64")
            : "";
          try {
            port.postMessage({ type: "handshake", signature });
          } catch (e) {}
        } catch (e) {
          try {
            port.postMessage({ type: "error", reason: "handshake-failed" });
          } catch (e) {}
        } finally {
          try {
            port.close();
          } catch {}
        }
      });
      return;
    }

    if (msg.type === "sign") {
      const { requestId, canonical } = msg;
      // record canonical for diagnostics
      try {
        (globalThis as any).__LAST_CANONICAL = canonical;
      } catch {
        /* ignore */
      }
      const delay =
        typeof this.opts.delayMs === "number" ? this.opts.delayMs : 5;
      const port =
        transfer && transfer.length === 1 ? (transfer[0] as MessagePort) : null;

      // Helper to deliver a message either via microtask (fast) or setTimeout (delayed).
      // Tests rely on microtask-scheduled quick responses for deterministic behavior
      // (Promise.resolve().then(...)). Using vitest fake timers interferes with
      // microtask scheduling and can cause flaky timeouts; therefore tests that
      // rely on microtask responses should avoid fake timers or use the
      // `withAdvancedDateNow` helper to control Date.now without mocking timers.
      const schedule = (fn: () => void) => {
        if (delay <= 1) Promise.resolve().then(fn);
        else setTimeout(fn, delay);
      };

      // Support transient failures: fail first `failCount` requests then succeed
      if (typeof this.opts.failCount === "number" && this.opts.failCount > 0) {
        this.opts.failCount -= 1;
        schedule(() => {
          const err = { type: "error", requestId, reason: "transient-failure" };
          if (port) {
            try {
              port.postMessage(err);
            } catch {}
            try {
              port.close();
            } catch {}
          } else {
            this.emit("message", { data: err });
          }
        });
        return;
      }

      if (this.opts.shouldError) {
        schedule(() => {
          const err = { type: "error", requestId, reason: "mock-error" };
          if (port) {
            try {
              port.postMessage(err);
            } catch {}
            try {
              port.close();
            } catch {}
          } else {
            this.emit("message", { data: err });
          }
        });
        return;
      }

      schedule(() => {
        if (!this.keyBytes) {
          const err = { type: "error", requestId, reason: "not-initialized" };
          if (port) {
            try {
              port.postMessage(err);
            } catch {}
            try {
              port.close();
            } catch {}
          } else {
            this.emit("message", { data: err });
          }
          return;
        }
        // Sign the canonical string directly (new format)
        // Diagnostic: expose the canonical in test logs to help debug mismatches
        try {
          console.debug("[TEST-DIAG] canonical:", canonical);
        } catch {}
        const sig = createHmac("sha256", this.keyBytes)
          .update(canonical)
          .digest("base64");
        const resp = { type: "signed", requestId, signature: sig };
        if (port) {
          try {
            port.postMessage(resp);
          } catch {}
          try {
            port.close();
          } catch {}
        } else {
          this.emit("message", { data: resp });
        }
      });
      return;
    }

    if (msg.type === "destroy") {
      this.destroyed = true;
      Promise.resolve().then(() =>
        this.emit("message", { data: { type: "destroyed" } }),
      );
      return;
    }
  }

  terminate() {
    this.destroyed = true;
  }

  emit(name: string, ev: any) {
    if (this.destroyed) return;
    (this.listeners[name] || []).forEach((fn) => {
      try {
        fn(ev);
      } catch (e) {
        /* swallow */
      }
    });
  }
}

describe("SecureApiSigner - Extended Canonical Format & Security Features", () => {
  let origWorker: any;
  let mockWorker: ExtendedMockWorker;

  beforeEach(() => {
    origWorker = (globalThis as any).Worker;
    (globalThis as any).Worker = function (url: string, opts?: any) {
      mockWorker = new ExtendedMockWorker(url, opts);
      return mockWorker;
    } as any;
  });

  afterEach(() => {
    (globalThis as any).Worker = origWorker;
    // Ensure fake timers are not leaking between tests
    try {
      vi.useRealTimers();
    } catch {}
    try {
      vi.restoreAllMocks();
    } catch {}
  });

  describe("Extended Canonical Format", () => {
  it("creates signatures compatible with server verification", async () => {
      // Allow more time for this test in resource-constrained environments
      try {
        // Use the proper vitest API to increase timeout for this slow test.
        // Some environments expose `vi` as global; call both to be defensive.
        try { vi.setTimeout(45000); } catch {}
        try { (global as any).vi?.setTimeout?.(45000); } catch {}
      } catch {
        /* ignore if vi global not available */
      }
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);
      const kid = "0123456789abcdef0123456789abcdef";

      const signer = await SecureApiSigner.create({
        secret,
        kid,
        workerUrl: new URL("./mock-worker.js", import.meta.url),
        integrity: "none",
        wipeProvidedSecret: false,
      });

      const payload = { userId: 123, action: "update" };
      const context = {
        method: "POST",
        path: "/api/users/123",
        body: { name: "John Doe" },
      };

      const signed = await signer.sign(payload, context);

      // Verify signature on server side
      const nonceStore = new InMemoryNonceStore();
      const bodyHash = createHash("sha256")
        .update(safeStableStringify(context.body))
        .digest("base64");
      const verifyInput: VerifyExtendedInput = {
        secret,
        payload,
        nonce: signed.nonce,
        timestamp: signed.timestamp,
        signatureBase64: signed.signature,
        kid: signed.kid,
        method: context.method,
        path: context.path,
        bodyHash,
      };

      const isValid = await verifyApiRequestSignature(verifyInput, nonceStore);
      expect(isValid).toBe(true);

      await signer.destroy();
  }, 45000);

    it("includes all canonical parts in correct order", async () => {
      const secret = Buffer.from(
        "test-secret-canonical-check-32bytes-owasp-compliant-strength",
      );
      const kid = "canonical-test";

      const signer = await SecureApiSigner.create({
        secret,
        kid,
        workerUrl: new URL("./mock-worker.js", import.meta.url),
        integrity: "none",
        wipeProvidedSecret: false,
      });

      const payload = "test-payload";
      const context = {
        method: "PUT",
        path: "/test/path",
        body: "test-body",
      };

      const signed = await signer.sign(payload, context);

      // Manually compute expected canonical string and signature
      const bodyHash = createHash("sha256")
        .update(safeStableStringify(context.body))
        .digest("base64");
      const canonicalParts = [
        String(signed.timestamp),
        signed.nonce,
        "PUT",
        "/test/path",
        bodyHash,
        safeStableStringify(payload),
        kid,
      ];
      const expectedCanonical = canonicalParts.join(".");
      const expectedSig = createHmac("sha256", secret)
        .update(expectedCanonical)
        .digest("base64");

      expect(signed.signature).toBe(expectedSig);

      await signer.destroy();
    });

    it("handles empty/missing context fields correctly", async () => {
      const secret = Buffer.from(
        "test-secret-empty-context-32bytes-owasp-compliant-key",
      );

      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("./mock-worker.js", import.meta.url),
        integrity: "none",
        wipeProvidedSecret: false,
      });

      const signed = await signer.sign("payload-only");

      // Should work with server verification when no context provided
      const nonceStore = new InMemoryNonceStore();
      const verifyInput: VerifyExtendedInput = {
        secret,
        payload: "payload-only",
        nonce: signed.nonce,
        timestamp: signed.timestamp,
        signatureBase64: signed.signature,
      };

      const isValid = await verifyApiRequestSignature(verifyInput, nonceStore);
      expect(isValid).toBe(true);

      await signer.destroy();
    });
  });

  describe("Circuit Breaker Functionality", () => {
    it("opens circuit after excessive failures", async () => {
      // Configure worker to always error
      (globalThis as any).Worker = function (url: string, opts?: any) {
        return new ExtendedMockWorker(url, { shouldError: true, delayMs: 1 });
      } as any;

      const secret = new Uint8Array(32);
      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("./mock-worker.js", import.meta.url),
        integrity: "none",
        wipeProvidedSecret: false,
      });

      // Trigger failures to open circuit breaker
      const failures = [];
      for (let i = 0; i < 12; i++) {
        // Exceed CIRCUIT_BREAKER_FAILURE_THRESHOLD (10)
        try {
          await signer.sign("test");
        } catch (error) {
          failures.push(error);
        }
      }

      expect(failures.length).toBeGreaterThanOrEqual(10);

      // Next request should fail with circuit breaker error
      await expect(signer.sign("test")).rejects.toThrow(CircuitBreakerError);

      await signer.destroy();
    });

    it("allows requests in half-open state after timeout", async () => {
      // Use real timers for this test to avoid fake-timer interactions with
      // microtask-scheduled mock worker responses. We'll only enable fake timers
      // briefly to set system time for the circuit-breaker window.
      try {
        const secret = new Uint8Array(32);
        console.debug("[TEST] creating signer");
        const signer = await SecureApiSigner.create({
          secret,
          workerUrl: new URL("./mock-worker.js", import.meta.url),
          integrity: "none",
          wipeProvidedSecret: false,
        });
        console.debug("[TEST] signer created");

        // Configure the created mockWorker to fail first N requests
        if (mockWorker && mockWorker.opts) {
          mockWorker.opts.failCount = 10;
          mockWorker.opts.delayMs = 1;
        }

        console.debug("[TEST] starting failure loop");
        // Force circuit breaker open by triggering the transient failures
        for (let i = 0; i < 10; i++) {
          try {
            const p = signer.sign("test");
            // attach immediate handler so rejections are not reported as unhandled
            p.catch(() => {});
            // Await the promise so mock microtask responses settle
            await p;
          } catch {}
        }
        console.debug("[TEST] failure loop complete");

        // Should be blocked by circuit breaker now
        console.debug("[TEST] asserting circuit is open");
        const blocked = signer.sign("test");
        // attach a noop catch so any internal rejection is observed and not treated as unhandled
        blocked.catch(() => {});
        // Allow one macrotask tick (setTimeout 0) so any microtask-scheduled responses
        // and next-turn timers settle under real timers.
        await new Promise((r) => setTimeout(r, 0));
        await Promise.resolve();
        await expect(blocked).rejects.toThrow(CircuitBreakerError);
        console.debug("[TEST] circuit open assertion passed");

        // Advance system time past circuit breaker timeout (60 seconds)
        console.debug("[TEST] advancing system time past timeout");
        // Advance relative to the signer's last failure time to ensure we surpass
        // the internal circuit-breaker lastFailureTime deterministically.
        const lastFailure =
          signer.getCircuitBreakerStatus().lastFailureTime || Date.now();
        // Run the recovery attempt with Date.now patched to an advanced time while
        // leaving timers and microtasks intact (use helper to centralize behavior).
        await withAdvancedDateNow(lastFailure + 61000, async () => {
          // Ensure the worker will respond successfully for the half-open recovery attempt
          if (mockWorker && mockWorker.opts) {
            mockWorker.opts.failCount = 0;
          }

          // Attempt recovery request; advance timers so worker can respond
          console.debug("[TEST] attempting recovery request");
          const recovery = signer.sign("recovery-test");
          recovery.catch(() => {});
          // Allow one macrotask tick so worker's microtask-scheduled response can run
          await new Promise((r) => setTimeout(r, 0));
          await Promise.resolve();
          const result = await recovery;
          console.debug("[TEST] recovery result received");
          expect(result.signature).toBeTruthy();

          await signer.destroy();
          await signer.destroy();
        });
      } finally {
        vi.useRealTimers();
      }
    }, 30000);
  });

  describe("Rate Limiting", () => {
    it("enforces maxPendingRequests limit", async () => {
      const secret = new Uint8Array(32);
      const signer = await SecureApiSigner.create({
        secret,
        maxPendingRequests: 2,
        workerUrl: new URL("./mock-worker.js", import.meta.url),
        integrity: "none",
      });

      // Start multiple concurrent requests
      const p1 = signer.sign("request-1");
      const p2 = signer.sign("request-2");

      // Third should be rejected due to rate limit
      await expect(signer.sign("request-3")).rejects.toThrow(RateLimitError);

      // Clean up
      await Promise.allSettled([p1, p2]);
      await signer.destroy();
    });
  });

  describe("Error Handling", () => {
    it("throws WorkerError on timeout", async () => {
      // Configure slow worker before creation
      (globalThis as any).Worker = function (url: string, opts?: any) {
        return new ExtendedMockWorker(url, { delayMs: 50 });
      } as any;
      const secret = new Uint8Array(32);
      const signer = await SecureApiSigner.create({
        secret,
        requestTimeoutMs: 10, // Very short timeout
        workerUrl: new URL("./mock-worker.js", import.meta.url),
        integrity: "none",
        wipeProvidedSecret: false,
      });

      await expect(signer.sign("slow-test")).rejects.toThrow(WorkerError);

      await signer.destroy();
    });

    it("throws WorkerError on worker message failure", async () => {
      // Configure worker error before creation
      (globalThis as any).Worker = function (url: string, opts?: any) {
        return new ExtendedMockWorker(url, { shouldError: true });
      } as any;
      const secret = new Uint8Array(32);
      const signer = await SecureApiSigner.create({
        secret,
        workerUrl: new URL("./mock-worker.js", import.meta.url),
        integrity: "none",
        wipeProvidedSecret: false,
      });

      await expect(signer.sign("error-test")).rejects.toThrow(WorkerError);

      await signer.destroy();
    });
  });
});

describe("Server-side verification - Security Constitution Compliance", () => {
  let nonceStore: INonceStore;

  beforeEach(() => {
    nonceStore = new InMemoryNonceStore();
  });

  describe("Input Validation (Positive Validation)", () => {
    const validInput: VerifyExtendedInput = {
      secret: Buffer.from(
        "test-secret-validation-32bytes-owasp-compliant-strength",
      ),
      payload: "test-payload",
      nonce: Buffer.from(getSecureRandomBytesSync(16)).toString("base64"),
      timestamp: Date.now(),
      signatureBase64: "dGVzdC1zaWduYXR1cmU=", // "test-signature" base64
      kid: "0123456789abcdef0123456789abcdef",
      method: "POST",
      path: "/api/test",
    };

    it("validates nonce format", async () => {
      const invalidInput = { ...validInput, nonce: "invalid-nonce!" };
      await expect(
        verifyApiRequestSignature(invalidInput, nonceStore),
      ).rejects.toThrow("[security-kit] nonce is not in an allowed format");
    });

    it("validates signature format", async () => {
      const invalidInput = {
        ...validInput,
        signatureBase64: "invalid-signature!",
      };
      await expect(
        verifyApiRequestSignature(invalidInput, nonceStore),
      ).rejects.toThrow(
        "[security-kit] signatureBase64 must be base64 or base64url",
      );
    });

    it("validates HTTP method", async () => {
      const invalidInput = { ...validInput, method: "INVALID_METHOD_NAME" };
      // Implementation throws a generic InvalidParameterError with message 'Invalid method'
      await expect(
        verifyApiRequestSignature(invalidInput, nonceStore),
      ).rejects.toThrow("[security-kit] method must be a valid HTTP method");
    });

    it("validates path format", async () => {
      const invalidInput = { ...validInput, path: "not-a-path" };
      await expect(
        verifyApiRequestSignature(invalidInput, nonceStore),
      ).rejects.toThrow("[security-kit] path must start with '/'");
    });

    it("validates kid format", async () => {
      const invalidInput = { ...validInput, kid: "invalid@kid!" };
      await expect(
        verifyApiRequestSignature(invalidInput, nonceStore),
      ).rejects.toThrow("kid contains invalid characters");
    });

    it("validates timestamp range", async () => {
      const invalidInput = { ...validInput, timestamp: -1 };
      await expect(
        verifyApiRequestSignature(invalidInput, nonceStore),
      ).rejects.toThrow("timestamp out of reasonable range");
    });

    it("enforces payload size limits", async () => {
      const largePayload = "x".repeat(11 * 1024 * 1024); // 11MB > limit
      const invalidInput = { ...validInput, payload: largePayload };
      await expect(
        verifyApiRequestSignature(invalidInput, nonceStore),
      ).rejects.toThrow("payload too large");
    });
  });

  describe("Timestamp Validation", () => {
    it("rejects timestamps outside acceptable window", async () => {
      const secret = Buffer.from(
        "test-secret-timestamp-32bytes-owasp-compliant-key",
      );
      const oldTimestamp = Date.now() - 5 * 60 * 1000 - 1000; // 5 minutes + 1s ago (exceeds skew)

      const input: VerifyExtendedInput = {
        secret,
        payload: "test",
        nonce: Buffer.from(getSecureRandomBytesSync(16)).toString("base64"),
        timestamp: oldTimestamp,
        signatureBase64: "dGVzdA==",
        kid: "test",
      };

      await expect(
        verifyApiRequestSignature(input, nonceStore),
      ).rejects.toThrow(TimestampError);
    });

    it("accepts timestamps within acceptable window", async () => {
      const secret = Buffer.from(
        "test-secret-timestamp-32bytes-owasp-compliant-key",
      );
      const timestamp = Date.now() - 30 * 1000; // 30 seconds ago
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString(
        "base64",
      );
      const kid = "test";

      // Compute valid signature using shared canonicalization
      const payloadString = safeStableStringify("test");
      const canonicalParts = [
        String(timestamp),
        nonce,
        "",
        "",
        "",
        payloadString,
        kid,
      ];
      const canonical = canonicalParts.join(".");
      const signature = createHmac("sha256", secret)
        .update(canonical)
        .digest("base64");

      const input: VerifyExtendedInput = {
        secret,
        payload: "test",
        nonce,
        timestamp,
        signatureBase64: signature,
        kid,
      };

      const result = await verifyApiRequestSignature(input, nonceStore);
      expect(result).toBe(true);
    });
  });

  describe("Replay Attack Protection", () => {
    it("rejects reused nonces", async () => {
      const secret = Buffer.from(
        "test-secret-replay-protection-32bytes-owasp-compliant",
      );
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString(
        "base64",
      );
      const kid = "test";

      // Compute valid signature using shared canonicalization
      const payloadString = safeStableStringify("test");
      const canonicalParts = [
        String(timestamp),
        nonce,
        "",
        "",
        "",
        payloadString,
        kid,
      ];
      const canonical = canonicalParts.join(".");
      const signature = createHmac("sha256", secret)
        .update(canonical)
        .digest("base64");

      const input: VerifyExtendedInput = {
        secret,
        payload: "test",
        nonce,
        timestamp,
        signatureBase64: signature,
        kid,
      };

      // First verification should succeed
      const result1 = await verifyApiRequestSignature(input, nonceStore);
      expect(result1).toBe(true);

      // Second verification with same nonce should fail
      await expect(
        verifyApiRequestSignature(input, nonceStore),
      ).rejects.toThrow(ReplayAttackError);
    });
  });

  describe("Signature Verification", () => {
    it("rejects invalid signatures", async () => {
      const secret = Buffer.from(
        "test-secret-signature-32bytes-owasp-compliant-key",
      );
      const timestamp = Date.now();
      const nonce = Buffer.from(getSecureRandomBytesSync(16)).toString(
        "base64",
      );
      const kid = "test";

      const input: VerifyExtendedInput = {
        secret,
        payload: "test",
        nonce,
        timestamp,
        signatureBase64: "aW52YWxpZC1zaWduYXR1cmU=", // "invalid-signature" base64
        kid,
      };

      await expect(
        verifyApiRequestSignature(input, nonceStore),
      ).rejects.toThrow(SignatureVerificationError);
    });
  });

  describe("Nonce Store Interface Compliance", () => {
    it("requires nonce store implementation", async () => {
      const input: VerifyExtendedInput = {
        secret: Buffer.from(
          "test-secret-nonce-store-32bytes-owasp-compliant-key",
        ),
        payload: "test",
        nonce: Buffer.from(getSecureRandomBytesSync(16)).toString("base64"),
        timestamp: Date.now(),
        signatureBase64: "dGVzdA==",
        kid: "test",
      };

      // Should reject missing nonce store
      await expect(
        verifyApiRequestSignature(input, undefined as any),
      ).rejects.toThrow("nonceStore is required");
    });

    it("validates nonce store parameters", async () => {
      const store = new InMemoryNonceStore();

      await expect(store.has("", "nonce")).rejects.toThrow(
        "kid must be a non-empty string",
      );
      await expect(store.has("kid", "")).rejects.toThrow(
        "nonce must be a non-empty string",
      );
      await expect(store.store("kid", "nonce", -1)).rejects.toThrow(
        "ttlMs must be between 1 and 86400000",
      );
    });
  });
});
