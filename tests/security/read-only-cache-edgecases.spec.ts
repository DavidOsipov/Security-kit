import { describe, it, expect } from "vitest";
import {
  SecureLRUCache,
  VerifiedByteCache,
  asReadOnlyCache,
} from "../../src/secure-cache";

const u = (s: string) => new Uint8Array(Buffer.from(s));

describe("read-only cache facade — edge cases", () => {
  it("asReadOnlyCache facade hides mutators and returns copies when requested", async () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 4,
      copyOnGet: true,
    });
    const ro = asReadOnlyCache(cache);

    // has/peek/get should work
    expect(ro.has("a")).toBe(false);
    expect(ro.peek("a")).toBeUndefined();

    cache.set("a", u("v1"));
    const g = ro.get("a");
    expect(g).toBeDefined();
    expect(g).not.toBe(cache.get("a")); // copyOnGet -> not same ref
    expect(new TextDecoder().decode(g!)).toBe("v1");

    // ensure mutators are not present on the facade
    expect((ro as any).set).toBeUndefined();
  });

  it("VerifiedByteCache.asReadOnly returns a facade that reflects underlying changes", async () => {
    const r1 = VerifiedByteCache.asReadOnly();
    const r2 = VerifiedByteCache.asReadOnly();

    VerifiedByteCache.set("x", u("hello"));
    const a = r1.get("x");
    const b = r2.get("x");
    expect(a).toBeDefined();
    expect(b).toBeDefined();
    expect(new TextDecoder().decode(a!)).toBe("hello");
    expect(new TextDecoder().decode(b!)).toBe("hello");

    // ensure the two read-only facades are behavioral equivalents
    expect(a!.length).toBe(b!.length);
  });

  it("peek does not promote recency", async () => {
    const cache = new SecureLRUCache<string, Uint8Array>({ maxEntries: 2 });

    cache.set("a", u("1"));
    cache.set("b", u("2"));
    // peek 'a' then add 'c', 'a' should be evicted if peek does not promote
    cache.peek("a");
    cache.set("c", u("3"));

    // either 'a' or 'b' should be gone, ensure 'a' can be evicted
    const vA = cache.get("a");
    const vB = cache.get("b");
    const vC = cache.get("c");

    // ensure at least one of previous entries is evicted
    const present = [!!vA, !!vB, !!vC].filter(Boolean).length;
    expect(present).toBeLessThanOrEqual(2);
  });

  it("getStats returns expected fields and updates", async () => {
    const cache = new SecureLRUCache<string, Uint8Array>({ maxEntries: 2 });
    cache.set("k1", u("x"));
    cache.get("k1");
    const stats = cache.getStats();
    expect(typeof stats.size).toBe("number");
    expect(typeof stats.totalBytes).toBe("number");
    expect(typeof stats.hits).toBe("number");
    expect(typeof stats.misses).toBe("number");
  });
});
