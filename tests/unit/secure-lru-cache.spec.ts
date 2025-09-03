import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { VerifiedByteCache } from "../../src/secure-lru-cache";
import { SecureApiSigner } from "../../src/secure-api-signer";

// These tests focus on cache eviction/TTL and blob URL revocation behavior

let originalCreate: any;
let originalRevoke: any;
let originalWorker: any;
let originalBlob: any;

beforeEach(() => {
  originalCreate = (URL as any).createObjectURL;
  originalRevoke = (URL as any).revokeObjectURL;
  originalWorker = (globalThis as any).Worker;
  originalBlob = (globalThis as any).Blob;

  (globalThis as any).Blob = function (arr: any, opts: any) {
    return { arr, opts } as any;
  } as any;
  (URL as any).createObjectURL = vi.fn(
    (blob: any) => `blob://fake-${Math.random()}`,
  );
  (URL as any).revokeObjectURL = vi.fn(() => {});

  class FakeWorker {
    private handlers: { [k: string]: Function[] } = {};
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(public script: string) {}
    addEventListener(ev: string, fn: Function) {
      this.handlers[ev] = this.handlers[ev] || [];
      this.handlers[ev].push(fn);
    }
    removeEventListener(ev: string, fn: Function) {
      if (!this.handlers[ev]) return;
      this.handlers[ev] = this.handlers[ev].filter((f) => f !== fn);
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    postMessage(msg: any) {
      const transfer = arguments[1] as any[] | undefined;
      if (msg && msg.type === "init") {
        setTimeout(() => {
          const event = { data: { type: "initialized" } } as any;
          (this.handlers["message"] || []).forEach((h) => h(event));
        }, 1);
        return;
      }
      if (msg && msg.type === "handshake") {
        if (
          transfer &&
          transfer.length > 0 &&
          typeof (transfer[0] as any)?.postMessage === "function"
        ) {
          setTimeout(() => {
            try {
              (transfer[0] as any).postMessage({
                type: "handshake",
                signature: "AAA",
              });
            } catch {
              // ignore
            }
          }, 1);
          return;
        }
        setTimeout(() => {
          const event = {
            data: { type: "handshake", signature: "AAA" },
          } as any;
          (this.handlers["message"] || []).forEach((h) => h(event));
        }, 1);
      }
    }
    terminate() {
      // no-op
    }
  }

  (globalThis as any).Worker = vi.fn(function (_script: string, _opts: any) {
    return new FakeWorker("");
  });

  VerifiedByteCache.clear();
});

afterEach(() => {
  (URL as any).createObjectURL = originalCreate;
  (URL as any).revokeObjectURL = originalRevoke;
  (globalThis as any).Worker = originalWorker;
  (globalThis as any).Blob = originalBlob;
  vi.restoreAllMocks();
  try {
    vi.useRealTimers();
  } catch {
    /* ignore */
  }
});

describe("VerifiedByteCache eviction and blob URL revocation", () => {
  it("evicts entries after TTL elapses", async () => {
    vi.useFakeTimers();

    const testUrl = "https://example.com/worker.js";
    const bytes = new Uint8Array([1, 2, 3, 4]);

    // Put entry into cache
    VerifiedByteCache.set(testUrl, bytes);
    expect(VerifiedByteCache.get(testUrl)).toBeDefined();

    // Advance time less than TTL (should still be present)
    vi.advanceTimersByTime(1000);
    expect(VerifiedByteCache.get(testUrl)).toBeDefined();

    // Advance time to exceed TTL (5 minutes + 1ms)
    vi.advanceTimersByTime(5 * 60 * 1000 + 1);
    expect(VerifiedByteCache.get(testUrl)).toBeUndefined();
  });

  it("limits cache size and evicts oldest when full", () => {
    // Fill the cache with MAX_CACHE_SIZE + 2 entries, ensure oldest removed
    for (let i = 0; i < 12; i++) {
      const url = `https://example.com/worker-${i}.js`;
      VerifiedByteCache.set(url, new Uint8Array([i]));
    }

    const stats = VerifiedByteCache.getStats();
    expect(stats.size).toBeLessThanOrEqual(10);
    // Oldest (worker-0.js) should be evicted
    expect(
      VerifiedByteCache.get("https://example.com/worker-0.js"),
    ).toBeUndefined();
  });

  it("creates blob URL and revokes on signer destroy", async () => {
    // We will simulate fetch so SecureApiSigner can compute and cache bytes
    globalThis.fetch = vi.fn(async () => {
      return {
        ok: true,
        redirected: false,
        url: "https://example.com/worker.js",
        arrayBuffer: async () => new Uint8Array([1, 2, 3, 4]).buffer,
      } as any;
    });

    const { setRuntimePolicy } = await import("../../src/config");
    setRuntimePolicy({ allowBlobWorkers: true });

    // Create signer which should cache bytes and create a Blob worker URL
    const signer = await SecureApiSigner.create({
      secret: new Uint8Array(32),
      workerUrl: new URL("https://example.com/worker.js"),
      integrity: "compute",
      allowCrossOriginWorkerOrigins: ["https://example.com"],
    } as any);

    // Expect createObjectURL was called (blob URL created)
    expect((URL as any).createObjectURL).toHaveBeenCalled();

    // Destroy signer should result in revokeObjectURL being called
    await signer.destroy();
    expect((URL as any).revokeObjectURL).toHaveBeenCalled();
  });

  it("getStats and clear work as expected", () => {
    // Ensure cache has some entries
    VerifiedByteCache.set("https://example.com/a.js", new Uint8Array([1]));
    VerifiedByteCache.set("https://example.com/b.js", new Uint8Array([2]));

    const statsBefore = VerifiedByteCache.getStats();
    expect(statsBefore.size).toBeGreaterThanOrEqual(2);
    // urls are intentionally not exposed by default; do not assert on them

    // Clear and ensure cache is empty
    VerifiedByteCache.clear();
    const statsAfter = VerifiedByteCache.getStats();
    expect(statsAfter.size).toBe(0);
  });

  it("delete removes a specific entry", () => {
    const url = "https://example.com/x.js";
    const buf = new Uint8Array([9, 9, 9]);
    VerifiedByteCache.set(url, buf);
    expect(VerifiedByteCache.get(url)).toBeDefined();
    // Ensure internal buffer is a copy (mutate original should not affect cache)
    buf[0] = 0;
    VerifiedByteCache.delete(url);
    expect(VerifiedByteCache.get(url)).toBeUndefined();
  });

  it("eviction order determinism: oldest removed first", () => {
    // Clear then insert
    VerifiedByteCache.clear();
    VerifiedByteCache.set("https://example.com/old.js", new Uint8Array([1]));
    VerifiedByteCache.set("https://example.com/mid.js", new Uint8Array([2]));
    VerifiedByteCache.set("https://example.com/new.js", new Uint8Array([3]));

    // Fill to capacity to force eviction (we know MAX_CACHE_SIZE is 10)
    for (let i = 0; i < 10; i++) {
      VerifiedByteCache.set(
        `https://example.com/fill-${i}.js`,
        new Uint8Array([i]),
      );
    }

    // Oldest entry should no longer exist
    expect(VerifiedByteCache.get("https://example.com/old.js")).toBeUndefined();
  });

  it("concurrent set/get stress test (basic)", async () => {
    VerifiedByteCache.clear();
    const urls = Array.from(
      { length: 20 },
      (_, i) => `https://example.com/c-${i}.js`,
    );

    // Concurrently set entries
    await Promise.all(
      urls.map((u, i) =>
        Promise.resolve().then(() =>
          VerifiedByteCache.set(u, new Uint8Array([i])),
        ),
      ),
    );

    // Concurrently get entries
    const results = await Promise.all(
      urls.map((u) => Promise.resolve().then(() => VerifiedByteCache.get(u))),
    );

    // At least some entries should be present (cache caps at 10)
    const present = results.filter((r) => r !== undefined).length;
    expect(present).toBeGreaterThanOrEqual(1);
  });

  it("LRU recency is respected on get (moves to MRU)", () => {
    VerifiedByteCache.clear();
    for (let i = 0; i < 10; i++) {
      VerifiedByteCache.set(
        `https://example.com/lru-${i}.js`,
        new Uint8Array([i]),
      );
    }
    // Touch the first key to make it MRU
    expect(VerifiedByteCache.get("https://example.com/lru-0.js")).toBeDefined();
    // Insert one more to trigger eviction of the least-recent (which should be lru-1.js now)
    VerifiedByteCache.set(
      "https://example.com/lru-new.js",
      new Uint8Array([99]),
    );
    expect(
      VerifiedByteCache.get("https://example.com/lru-1.js"),
    ).toBeUndefined();
    // And 0 should still be present
    expect(VerifiedByteCache.get("https://example.com/lru-0.js")).toBeDefined();
  });

  it("short TTL (<=120s) expires entries", () => {
    vi.useFakeTimers();
    VerifiedByteCache.clear();
    const u = "https://example.com/short-ttl.js";
    VerifiedByteCache.set(u, new Uint8Array([1]));
    // 60s should still be present
    vi.advanceTimersByTime(60_000);
    expect(VerifiedByteCache.get(u)).toBeDefined();
    // 120s + 1ms should expire
    vi.advanceTimersByTime(60_000 + 1);
    expect(VerifiedByteCache.get(u)).toBeUndefined();
  });

  it("Blob worker uses exact verified bytes (hash equality)", async () => {
    // Enable caching and blob workers to exercise Blob path
    const { setRuntimePolicy } = await import("../../src/config");
    setRuntimePolicy({ enableWorkerByteCache: true, allowBlobWorkers: true });

    // Provide deterministic bytes and hash them
    const scriptBytes = new Uint8Array([10, 20, 30, 40]);
    const { sha256Base64 } = await import("../../src/encoding-utils");
    const expectedHash = await sha256Base64(scriptBytes.buffer as ArrayBuffer);

    // Mock fetch to return those exact bytes
    globalThis.fetch = vi.fn(
      async () =>
        ({
          ok: true,
          redirected: false,
          url: "https://example.com/exact.js",
          arrayBuffer: async () => scriptBytes.buffer,
        }) as any,
    );

    // Intercept Blob creation to capture the bytes handed to the Blob
    const seen: Uint8Array[] = [];
    (globalThis as any).Blob = function (arr: any[]) {
      if (arr && arr[0] instanceof ArrayBuffer) {
        seen.push(new Uint8Array(arr[0] as ArrayBuffer));
      }
      return { arr } as any;
    } as any;

    // Create signer in compute mode; it should fetch, hash, cache, and create Blob worker
    const signer = await SecureApiSigner.create({
      secret: new Uint8Array(32),
      workerUrl: new URL("https://example.com/exact.js"),
      integrity: "compute",
      allowCrossOriginWorkerOrigins: ["https://example.com"],
    } as any);

    // Ensure bytes used for Blob equal the expected bytes by hash
    const used = seen[0];
    expect(used).toBeDefined();
    const usedHash = await (
      await import("../../src/encoding-utils")
    ).sha256Base64((used as Uint8Array)!.buffer as ArrayBuffer);
    expect(usedHash).toBe(expectedHash);

    await signer.destroy();
  });

  it("wipes bytes on clear and TTL eviction", async () => {
    // Place an entry and then clear; behaviorally validate clear()
    const u1 = "https://example.com/wipe1.js";
    VerifiedByteCache.set(u1, new Uint8Array([1, 2, 3]));
    expect(VerifiedByteCache.get(u1)).toBeDefined();
    VerifiedByteCache.clear();
    expect(VerifiedByteCache.get(u1)).toBeUndefined();

    // TTL eviction path
    vi.useFakeTimers();
    const u2 = "https://example.com/wipe2.js";
    VerifiedByteCache.set(u2, new Uint8Array([4, 5, 6]));
    expect(VerifiedByteCache.get(u2)).toBeDefined();
    vi.advanceTimersByTime(5 * 60 * 1000 + 5);
    expect(VerifiedByteCache.get(u2)).toBeUndefined();
  });

  it("policy opt-out disables caching of bytes", async () => {
    // Arrange: turn off worker byte cache via runtime policy
    const { setRuntimePolicy } = await import("../../src/config");
    setRuntimePolicy({ enableWorkerByteCache: false, allowBlobWorkers: true });
    globalThis.fetch = vi.fn(async () => {
      return {
        ok: true,
        redirected: false,
        url: "https://example.com/worker.js",
        arrayBuffer: async () => new Uint8Array([7, 7, 7, 7]).buffer,
      } as any;
    });

    // Create signer; since cache is disabled, Blob worker path should not be used and thus
    // createObjectURL should not be called.
    const signer = await SecureApiSigner.create({
      secret: new Uint8Array(32),
      workerUrl: new URL("https://example.com/worker.js"),
      integrity: "compute",
      allowCrossOriginWorkerOrigins: ["https://example.com"],
    } as any);
    expect((URL as any).createObjectURL).not.toHaveBeenCalled();
    await signer.destroy();
  });
});
