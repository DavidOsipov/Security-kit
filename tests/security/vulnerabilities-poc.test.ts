// vulnerabilities-poc.test.ts

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fc from "fast-check";
import { createHmac } from "node:crypto";
import { safeStableStringify } from "../../src/canonical";
import { fileURLToPath } from "node:url";

// --- Mocks and Imports for Vulnerability 1 ---
import {
  verifyApiRequestSignature,
  type INonceStore,
} from "../../server/verify-api-request-signature";
import {
  SignatureVerificationError,
  ReplayAttackError,
} from "../../src/errors";

// --- Mocks and Imports for Vulnerability 2 & 4 ---
// Note: Directly testing the worker is complex. We will test the SecureApiSigner class
// which orchestrates the worker. For the test-only API, we will import it directly.
import { SecureApiSigner } from "../../src/secure-api-signer";
import { __test_validateHandshakeNonce } from "../../src/worker/signing-worker";

// --- Mocks and Imports for Vulnerability 3 ---
import { SecureLRUCache } from "../../src/secure-cache";

// --- Mocks and Imports for Vulnerability 5 ---
// We will define the proposed type guard and test it directly.
import type { SignRequest } from "../../src/protocol";

// Helper to surface clearer, security-focused failure messages
const TEST_FILE = fileURLToPath(import.meta.url);
async function warnIfFails(title: string, fn: () => void | Promise<void>) {
  try {
    await fn();
  } catch (err) {
    const cause = err instanceof Error ? err.message : String(err);
    throw new Error(
      `WARNING: ${title} detected in ${TEST_FILE}\nCause: ${cause}`,
    );
  }
}

// Note: PoC tests are expressed as standard Vitest tests.
// IMPORTANT: If a vulnerability is present and exploitable, these tests will FAIL loudly.

// Shared test data used by multiple PoCs (moved to top-level so all describes can access it)
const testData = {
  secret: "a-very-strong-and-long-secret-key-for-hmac-sha256",
  payload: { data: "some content" },
  timestamp: Date.now(),
  // A valid signature for nonce 'nonce-1' (placeholder)
  validSignature:
    "3322a321a718386116f1981e47f5a95ce24a8f3a12b7e5f3f653b8274a44101e",
  // This signature is intentionally incorrect
  invalidSignature: "invalid-signature-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

// ================================================================================
// PoC for Vulnerability 1: Nonce-Store Denial of Service (DoS)
// ================================================================================

describe("Vulnerability 1: Nonce-Store DoS via Premature Reservation", () => {
  // A mock nonce store to track interactions
  class MockNonceStore implements INonceStore {
    // backing map for simple in-memory behavior
    private map = new Map<string, number>();

    public reserve = vi.fn(
      async (kid: string, nonce: string, ttl: number): Promise<boolean> => {
        const key = `${kid}:${nonce}`;
        if (this.map.has(key)) return false;
        this.map.set(key, Date.now() + ttl);
        return true;
      },
    );

    public storeIfNotExists = vi.fn(
      async (kid: string, nonce: string, ttl: number): Promise<boolean> => {
        const key = `${kid}:${nonce}`;
        if (this.map.has(key)) return false;
        this.map.set(key, Date.now() + ttl);
        return true;
      },
    );

    public has = vi.fn(async (kid: string, nonce: string): Promise<boolean> => {
      return this.map.has(`${kid}:${nonce}`);
    });

    public store = vi.fn(
      async (kid: string, nonce: string, ttlMs: number): Promise<void> => {
        const key = `${kid}:${nonce}`;
        this.map.set(key, Date.now() + ttlMs);
      },
    );

    public finalize = vi.fn(
      async (kid: string, nonce: string, ttlMs: number): Promise<void> => {
        const key = `${kid}:${nonce}`;
        this.map.set(key, Date.now() + ttlMs);
      },
    );

    public delete = vi.fn(async (kid: string, nonce: string): Promise<void> => {
      const key = `${kid}:${nonce}`;
      this.map.delete(key);
    });
  }

  let mockNonceStore: MockNonceStore;

  // NOTE: shared `testData` is declared at file top-level for reuse by RedTeam tests.

  beforeEach(() => {
    mockNonceStore = new MockNonceStore();
  });

  // SECURITY: Invalid signatures must not interact with nonce store (fail-closed).
  // If the implementation reserves before verifying, this test WILL FAIL (as intended).
  it("[SECURITY] Invalid signature must not touch nonce store", async () => {
    await warnIfFails(
      "Vulnerability 1: Nonce store touched before verification",
      async () => {
        const attackPayload = {
          ...testData,
          nonce: "bm9uY2UtZm9yLWludmFsaWQtc2ln", // base64 for 'nonce-for-invalid-sig'
          signatureBase64: Buffer.from(testData.invalidSignature).toString(
            "base64",
          ),
        };

        await expect(
          verifyApiRequestSignature(attackPayload, mockNonceStore),
        ).rejects.toThrow(SignatureVerificationError);

        // Assert no nonce-store interaction for invalid signature
        expect(mockNonceStore.reserve).not.toHaveBeenCalled();
        expect(mockNonceStore.storeIfNotExists).not.toHaveBeenCalled();
        expect(mockNonceStore.store).not.toHaveBeenCalled();
        expect(mockNonceStore.finalize).not.toHaveBeenCalled();
      },
    );
  });

  // This test verifies the fix. It should PASS after the fix.
  // Duplicate of the above but kept to emphasize contract; could be merged.
  it("[SECURITY] Signature is checked before nonce-store access", async () => {
    await warnIfFails(
      "Vulnerability 1: Verification order allows nonce reservation",
      async () => {
        const attackPayload = {
          ...testData,
          nonce: "bm9uY2UtZm9yLWludmFsaWQtc2ln",
          signatureBase64: Buffer.from(testData.invalidSignature).toString(
            "base64",
          ),
        };
        await expect(
          verifyApiRequestSignature(attackPayload, mockNonceStore),
        ).rejects.toThrow(SignatureVerificationError);
        expect(mockNonceStore.reserve).toHaveBeenCalledTimes(0);
        expect(mockNonceStore.storeIfNotExists).toHaveBeenCalledTimes(0);
      },
    );
  });

  it("[SECURITY] Nonce is stored only after successful verification", async () => {
    await warnIfFails(
      "Vulnerability 1: Nonce stored/reserved before verification completes",
      async () => {
        // Dynamically generate a valid signature for deterministic success
        const nonce = "bm9uY2UtMQ=="; // base64 for 'nonce-1'
        const payloadString = safeStableStringify(testData.payload);
        const canonical = [
          String(testData.timestamp),
          nonce,
          "",
          "",
          "",
          payloadString,
          "",
        ].join(".");
        const secretBytes = new TextEncoder().encode(testData.secret);
        const h = createHmac("sha256", Buffer.from(secretBytes));
        h.update(canonical);
        const validSignatureBase64 = h.digest("base64");

        const validPayload = {
          ...testData,
          secret: secretBytes,
          nonce,
          signatureBase64: validSignatureBase64,
        } as any;
        const result = await verifyApiRequestSignature(
          validPayload,
          mockNonceStore,
        );
        expect(result).toBe(true);

        // Exactly one atomic store call, reserve not used
        expect(mockNonceStore.storeIfNotExists).toHaveBeenCalledTimes(1);
        expect(mockNonceStore.reserve).not.toHaveBeenCalled();
      },
    );
  });

  // Aggressive: flood with many unique invalid nonces MUST NOT touch the nonce store
  it("[SECURITY][Aggressive] Flood of invalid signatures must not touch nonce store", async () => {
    await warnIfFails(
      "Vulnerability 1: Flood of invalid signatures consumes nonce store",
      async () => {
        const concurrency = 100;
        const tasks: Promise<unknown>[] = [];
        for (let i = 0; i < concurrency; i++) {
          const nonceRaw = `attack-${i}-${Date.now()}`;
          const payload = {
            ...testData,
            nonce: Buffer.from(nonceRaw).toString("base64"),
            signatureBase64: Buffer.from(testData.invalidSignature).toString(
              "base64",
            ),
          };
          tasks.push(
            verifyApiRequestSignature(payload, mockNonceStore).catch(() => {}),
          );
        }
        await Promise.all(tasks);
        expect(mockNonceStore.reserve).toHaveBeenCalledTimes(0);
        expect(mockNonceStore.storeIfNotExists).toHaveBeenCalledTimes(0);
        expect(mockNonceStore.store).toHaveBeenCalledTimes(0);
      },
    );
  });

  // Aggressive: repeated same-nonce invalid attempts must not create entries (atomic behavior)
  it("[SECURITY][Aggressive] Repeated invalid attempts must not create entries", async () => {
    await warnIfFails(
      "Vulnerability 1: Repeated invalid attempts create nonce-store entries",
      async () => {
        const attempts = 100;
        const nonce = Buffer.from("same-nonce-agg").toString("base64");
        const tasks: Promise<unknown>[] = [];
        for (let i = 0; i < attempts; i++) {
          const payload = {
            ...testData,
            nonce,
            signatureBase64: Buffer.from(testData.invalidSignature).toString(
              "base64",
            ),
          };
          tasks.push(
            verifyApiRequestSignature(payload, mockNonceStore).catch(() => {}),
          );
        }
        await Promise.all(tasks);
        expect(mockNonceStore.reserve).toHaveBeenCalledTimes(0);
        expect(mockNonceStore.storeIfNotExists).toHaveBeenCalledTimes(0);
        expect(mockNonceStore.store).toHaveBeenCalledTimes(0);
      },
    );
  });

  // Property-based: For random invalid signatures and allowed nonces/kids, no store interaction
  it("[SECURITY][Fuzz][fast-check] Invalid signatures never touch nonce store", async () => {
    const allowedChars =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";
    const kidArb = fc
      .string({ minLength: 1, maxLength: 32 })
      .filter((s) => [...s].every((ch) => allowedChars.includes(ch)));
    const nonceBytesArb = fc.uint8Array({ minLength: 8, maxLength: 32 });
    const sigBytesArb = fc.uint8Array({ minLength: 16, maxLength: 64 });

    await warnIfFails(
      "Vulnerability 1: Invalid signatures cause nonce-store interactions (fuzz)",
      async () => {
        await fc.assert(
          fc.asyncProperty(
            kidArb,
            nonceBytesArb,
            sigBytesArb,
            async (kid, nonceBytes, sigBytes) => {
              const store = new MockNonceStore();
              const nonce = Buffer.from(nonceBytes).toString("base64");
              const signatureBase64 = Buffer.from(sigBytes).toString("base64");
              const payload = {
                ...testData,
                kid: kid as string,
                nonce,
                signatureBase64,
                timestamp: Date.now(),
              } as any;

              await expect(
                verifyApiRequestSignature(payload, store),
              ).rejects.toBeInstanceOf(Error);
              expect(store.reserve).toHaveBeenCalledTimes(0);
              expect(store.storeIfNotExists).toHaveBeenCalledTimes(0);
              expect(store.store).toHaveBeenCalledTimes(0);
            },
          ),
          { numRuns: 50 },
        );
      },
    );
  });
});

// ================================================================================
// PoC for Vulnerability 2: "Push Bombing" Enablement
// ================================================================================

describe('Vulnerability 2: "Push Bombing" Enablement via Global Rate Limiting', () => {
  // This PoC demonstrates that the library itself does not prevent numerous
  // requests for the same user, as its rate limiting is global. The fix is
  // documentation advising consumers to implement per-user rate limiting.

  it("[Info] Allows many requests for same user up to global limit (documented)", async () => {
    // This test simulates an attacker trying to "push bomb" user 'victim-user-123'.
    // NOTE: The signer will fetch the worker script. Mock fetch to avoid network access in tests.
    const originalFetch = (globalThis as any).fetch;
    const originalWorker = (globalThis as any).Worker;
    // Simple mock Worker implementation for Node test environment. It accepts postMessage calls
    // and will reply to init/handshake/sign messages. Restored after the test.
    class MockWorker {
      private listeners: Record<string, ((e: any) => void)[]> = {
        message: [],
        error: [],
      };
      constructor(_url: string, _opts?: any) {}
      addEventListener(name: string, fn: (e: any) => void) {
        (this.listeners[name] ||= []).push(fn);
      }
      removeEventListener(name: string, fn: (e: any) => void) {
        this.listeners[name] = (this.listeners[name] || []).filter(
          (f) => f !== fn,
        );
      }
      postMessage(msg: any, transfers?: any[]) {
        try {
          if (msg && msg.type === "init") {
            // simulate async init response
            setTimeout(() => {
              for (const h of this.listeners.message)
                h({ data: { type: "initialized" } });
            }, 0);
          } else if (
            msg &&
            msg.type === "handshake" &&
            Array.isArray(transfers) &&
            transfers[0]
          ) {
            // post handshake response on the provided port
            try {
              transfers[0].postMessage({
                type: "handshake",
                signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              });
            } catch {}
          } else if (
            msg &&
            msg.type === "sign" &&
            Array.isArray(transfers) &&
            transfers[0]
          ) {
            try {
              transfers[0].postMessage({
                type: "signed",
                signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              });
            } catch {}
          }
        } catch {}
      }
      terminate() {}
    }
    (globalThis as any).Worker = MockWorker;
    const workerScript = `self.onmessage = function(e){
      try {
        const d = e.data;
        if (d && d.type === 'init') {
          // respond initialized
          self.postMessage({ type: 'initialized' });
        } else if (d && d.type === 'handshake') {
          // reply handshake on MessagePort usage is complex; noop for tests
          // rely on SecureApiSigner.create to handle handshake via postMessage
        } else if (d && d.type === 'sign') {
          // return a fixed signature (base64 32 bytes)
          self.postMessage({ type: 'signed', signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' });
        }
      } catch (err) { /* ignore */ }
    };`;
    (globalThis as any).fetch = vi.fn(async (url: string) => {
      return {
        ok: true,
        redirected: false,
        url: String(url),
        status: 200,
        statusText: "OK",
        arrayBuffer: async () => new TextEncoder().encode(workerScript).buffer,
      } as unknown as Response;
    });
    // The signer is configured with a generous global limit.
    const signer = await SecureApiSigner.create({
      secret: new TextEncoder().encode("super-secret-key-for-mfa"),
      workerUrl: new URL("./signing-worker.ts", import.meta.url).href, // Assuming worker is accessible
      integrity: "compute",
      allowComputeIntegrityInProduction: true,
      maxConcurrentSigning: 20,
      rateLimitPerMinute: 100,
    });

    const victimUserId = "victim-user-123";
    const numberOfAttackRequests = 15;
    const promises: Promise<any>[] = [];

    console.log(
      `Simulating ${numberOfAttackRequests} rapid MFA sign requests for user: ${victimUserId}...`,
    );

    for (let i = 0; i < numberOfAttackRequests; i++) {
      // Each request has a slightly different payload to be unique,
      // but targets the same user.
      const promise = signer.sign({
        userId: victimUserId,
        action: "approve-login",
        attempt: i + 1,
        timestamp: Date.now(),
      });
      promises.push(promise);
    }

    const results = await Promise.allSettled(promises);

    const successfulSigns = results.filter((r) => r.status === "fulfilled");

    // THE VULNERABILITY DEMONSTRATED:
    // All 15 requests succeeded because they did not breach the *global* rate limit.
    // In a real MFA system, this would have sent 15 push notifications to the user,
    // demonstrating the "push bomb" attack. The library's behavior enables this.
    expect(successfulSigns.length).toBe(numberOfAttackRequests);

    console.log(
      `SUCCESS: All ${numberOfAttackRequests} signing requests were fulfilled. This demonstrates that application-level, per-user rate limiting is required to prevent "push bombing".`,
    );

    await signer.destroy();
    // restore fetch and worker
    (globalThis as any).fetch = originalFetch;
    (globalThis as any).Worker = originalWorker;
  }, 20000); // Increase timeout for this test
});

// ================================================================================
// RedTeam: Advanced aggressive PoCs (fuzzing, randomized races, distributed-store sim)
// ================================================================================
describe("RedTeam Aggressive PoCs", () => {
  // Mock distributed nonce store that simulates small race windows and latency.
  class MockDistributedNonceStore implements INonceStore {
    private map = new Map<string, number>();
    private latencyMs: number;
    constructor(latencyMs = 5) {
      this.latencyMs = latencyMs;
    }
    private key(kid: string, nonce: string) {
      return `${kid}:${nonce}`;
    }
    async has(kid: string, nonce: string): Promise<boolean> {
      await new Promise((r) => setTimeout(r, this.latencyMs));
      const key = this.key(kid, nonce);
      const exp = this.map.get(key) ?? 0;
      if (exp <= Date.now()) this.map.delete(key);
      return this.map.has(key);
    }
    // Non-atomic store implementation (vulnerable)
    async store(kid: string, nonce: string, ttlMs: number): Promise<void> {
      await new Promise((r) => setTimeout(r, this.latencyMs));
      this.map.set(this.key(kid, nonce), Date.now() + ttlMs);
    }
    // Non-atomic storeIfNotExists simulated with race window depending on latency
    async storeIfNotExists(
      kid: string,
      nonce: string,
      ttlMs: number,
    ): Promise<boolean> {
      // Intentionally allow races by checking then setting with the latency window
      const exists = await this.has(kid, nonce);
      if (exists) return false;
      // small yield to simulate race window
      await new Promise((r) =>
        setTimeout(r, Math.floor(Math.random() * this.latencyMs)),
      );
      this.map.set(this.key(kid, nonce), Date.now() + ttlMs);
      return true;
    }
    async reserve(
      kid: string,
      nonce: string,
      reserveTtlMs: number,
    ): Promise<boolean> {
      return this.storeIfNotExists(kid, nonce, reserveTtlMs);
    }
    async delete(kid: string, nonce: string): Promise<void> {
      this.map.delete(this.key(kid, nonce));
    }
  }

  it("[SECURITY][RedTeam] Payload fuzzing should not touch nonce store", async () => {
    await warnIfFails(
      "Vulnerability 1: Payload fuzzing triggers nonce-store entries",
      async () => {
        const store = new MockDistributedNonceStore(3);
        const kids = ["default", "alt-kid", "k".repeat(64), "", "NULL"];

        const cases: Array<Record<string, any>> = [];
        // add sizes
        cases.push({ body: "a".repeat(10) });
        cases.push({ body: "a".repeat(1000) });
        cases.push({ body: "a".repeat(10000) });
        // malformed base64
        cases.push({ signatureBase64: "!!not-base64!!" });
        cases.push({ signatureBase64: "aGVsbG8" }); // invalid padding
        // weird kids
        for (const k of kids) cases.push({ kid: k });

        const results = [] as string[];
        for (const c of cases) {
          const payload: any = {
            ...testData,
            nonce: `rt-${Math.random().toString(36).slice(2)}`,
            signatureBase64:
              c["signatureBase64"] ??
              Buffer.from(testData.invalidSignature).toString("base64"),
            body: c["body"],
            kid: c["kid"],
          };
          try {
            await verifyApiRequestSignature(payload as any, store as any);
            results.push("ok");
          } catch (err) {
            results.push(String(err));
          }
        }
        // Ensure we exercised cases and didn't crash
        expect(results.length).toBe(cases.length);
        // Nonce store must not be touched for invalid signatures
        expect((store as any).map.size).toBe(0);
      },
    );
  });

  it("[SECURITY][RedTeam] Randomized timing: invalid signatures do not create entries", async () => {
    await warnIfFails(
      "Vulnerability 1: Races create nonce-store entries",
      async () => {
        const distStore = new MockDistributedNonceStore(8);
        const tasks: Promise<void>[] = [];
        for (let t = 0; t < 80; t++) {
          tasks.push(
            (async () => {
              const nonce = `race-${Math.floor(Math.random() * 10)}`; // limited nonce set
              // random delay before call
              await new Promise((r) =>
                setTimeout(r, Math.floor(Math.random() * 20)),
              );
              try {
                await verifyApiRequestSignature(
                  {
                    ...testData,
                    nonce,
                    signatureBase64: Buffer.from(
                      testData.invalidSignature,
                    ).toString("base64"),
                  },
                  distStore as any,
                );
              } catch {
                // ignore
              }
            })(),
          );
        }
        await Promise.all(tasks);
        // No entries should be created by invalid signatures
        const mapSize = (distStore as any).map.size;
        expect(mapSize).toBe(0);
      },
    );
  });
});

// ================================================================================
// PoC for Vulnerability 3: Information Leakage in SecureLRUCache
// ================================================================================

describe("Vulnerability 3: Information Leakage in SecureLRUCache onEvict", () => {
  // This test demonstrates the vulnerability. It should FAIL after the fix.
  it("[SECURITY] onEvict should not expose raw URL by default", () => {
    return warnIfFails(
      "Vulnerability 3: SecureLRUCache leaks raw URL on eviction",
      async () => {
        const onEvictCallback = vi.fn();
        const sensitiveUrl = "https://internal.corp/api/v1/user/secret-data";

        // Instantiate the cache with default options, which are insecure.
        const cache = new SecureLRUCache<string, Uint8Array>({
          maxEntries: 1,
          onEvict: onEvictCallback,
        });

        cache.set(sensitiveUrl, new Uint8Array([1]));
        // This second `set` will evict the first entry.
        cache.set("https://another.url/data", new Uint8Array([2]));
        // onEvict dispatches asynchronously by default; allow microtask to flush
        await Promise.resolve();
        // Default behavior should redact
        expect(onEvictCallback).toHaveBeenCalledTimes(1);
        expect(onEvictCallback).toHaveBeenCalledWith({
          url: "[redacted]",
          bytesLength: 1,
          reason: "capacity",
        });
      },
    );
  });

  // This test verifies the fix. It should PASS after the fix.
  it("[SECURITY] Explicit redaction remains in place", () => {
    return warnIfFails(
      "Vulnerability 3: Redaction not applied in onEvict",
      async () => {
        const onEvictCallback = vi.fn();
        const sensitiveUrl = "https://internal.corp/api/v1/user/secret-data";

        // Instantiate the cache with default options. After the fix, this will be secure.
        const cache = new SecureLRUCache<string, Uint8Array>({
          maxEntries: 1,
          onEvict: onEvictCallback,
        });

        cache.set(sensitiveUrl, new Uint8Array([1]));
        cache.set("https://another.url/data", new Uint8Array([2]));
        // onEvict dispatches asynchronously by default; allow microtask to flush
        await Promise.resolve();
        // The callback was invoked with a redacted URL.
        expect(onEvictCallback).toHaveBeenCalledTimes(1);
        expect(onEvictCallback).toHaveBeenCalledWith({
          url: "[redacted]", // Or whatever the redacted value is
          bytesLength: 1,
          reason: "capacity",
        });
      },
    );
  });
});

// ================================================================================
// PoC for Vulnerability 4: Insufficient Hardening of Test-Only APIs
// ================================================================================

describe("Vulnerability 4: Insufficient Hardening of Test-Only APIs", () => {
  let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    // Spy on console.warn to check if our security warning is logged.
    consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    // Clean up spies and global state
    consoleWarnSpy.mockRestore();
    // @ts-ignore
    delete globalThis.__SECURITY_KIT_ALLOW_TEST_APIS;
  });

  // This test verifies the fix. It should PASS after the fix.
  it("[SECURITY] Emits a warning when test-only API used in non-test environment", () => {
    return warnIfFails(
      "Vulnerability 4: Test-only API used without warning in non-test env",
      async () => {
        // Simulate an attacker enabling the test API in a "production" context
        // @ts-ignore
        globalThis.__SECURITY_KIT_ALLOW_TEST_APIS = true;
        const originalNodeEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = "production";

        // The test function should still be available due to the global flag
        expect(__test_validateHandshakeNonce).toBeDefined();

        // Call the function
        __test_validateHandshakeNonce?.("some-nonce");

        // A loud security warning should be logged to the console.
        expect(consoleWarnSpy).toHaveBeenCalled();
        expect(consoleWarnSpy).toHaveBeenCalledWith(
          expect.stringContaining(
            "SECURITY WARNING: A test-only API (__test_validateHandshakeNonce) was called in a non-test environment.",
          ),
        );

        // Restore original env
        process.env.NODE_ENV = originalNodeEnv;
      },
    );
  });
});

// ================================================================================
// PoC for Improvement 5: Enhancing Type Safety with Type Guards
// ================================================================================

describe("Improvement 5: Enhancing Type Safety with Type Guards", () => {
  // This PoC tests the proposed type guard function directly.
  // Its existence and correctness prove the improvement.

  // Proposed type guard function
  function isMessageWithType(data: unknown): data is { readonly type: string } {
    return (
      typeof data === "object" &&
      data !== null &&
      "type" in data &&
      typeof (data as { readonly type: unknown }).type === "string"
    );
  }

  function isSignRequest(data: unknown): data is SignRequest {
    if (!isMessageWithType(data) || data.type !== "sign") return false;
    const d = data as Record<string, unknown>;
    return typeof d.requestId === "number" && typeof d.canonical === "string";
  }

  it("[PoC] isSignRequest type guard should correctly validate message shapes", () => {
    // 1. Valid case
    const validRequest: SignRequest = {
      type: "sign",
      requestId: 123,
      canonical: "GET./api/data.1678886400000",
    };
    expect(isSignRequest(validRequest)).toBe(true);

    // 2. Invalid cases
    const wrongType = { type: "init", secretBuffer: new ArrayBuffer(0) };
    const missingRequestId = { type: "sign", canonical: "..." };
    const wrongRequestIdType = {
      type: "sign",
      requestId: "123",
      canonical: "...",
    };
    const missingCanonical = { type: "sign", requestId: 123 };
    const wrongCanonicalType = { type: "sign", requestId: 123, canonical: 456 };
    const notAnObject = "just a string";
    const nullValue = null;

    expect(isSignRequest(wrongType)).toBe(false);
    expect(isSignRequest(missingRequestId)).toBe(false);
    expect(isSignRequest(wrongRequestIdType)).toBe(false);
    expect(isSignRequest(missingCanonical)).toBe(false);
    expect(isSignRequest(wrongCanonicalType)).toBe(false);
    expect(isSignRequest(notAnObject)).toBe(false);
    expect(isSignRequest(nullValue)).toBe(false);

    console.log(
      "SUCCESS: The isSignRequest type guard correctly distinguishes valid from invalid message shapes, proving its robustness.",
    );
  });
});
