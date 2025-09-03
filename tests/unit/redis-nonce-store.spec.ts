import { describe, it, expect, vi } from "vitest";
import { RedisNonceStore } from "../../server/redis-nonce-store";

describe("RedisNonceStore", () => {
  it("store, storeIfNotExists, reserve, finalize and delete behave correctly", async () => {
    const seen = new Set<string>();
    const redis = {
      set: vi.fn(async (key: string, value: string, opts: any) => {
        // Simulate NX behavior: only succeed if key not seen
        if (opts && opts.NX) {
          if (seen.has(key)) return null;
          seen.add(key);
          return "OK";
        }
        seen.add(key);
        return "OK";
      }),
      pExpire: vi.fn(async (_key: string, _ttl: number) => 1),
      del: vi.fn(async (_key: string) => 1),
    } as any;

    const store = new RedisNonceStore(redis, "pref");

    // store should succeed
    await store.store("kid", "AA==", 1000);
    expect(redis.set).toHaveBeenCalled();

    // storeIfNotExists should return true when key not present and false when present
    const first = await store.storeIfNotExists("kid", "BB==", 1000);
    expect(first).toBe(true);
    const second = await store.storeIfNotExists("kid", "BB==", 1000);
    expect(second).toBe(false);

    // reserve should behave like storeIfNotExists
    const r1 = await store.reserve("kid", "CC==", 1000);
    expect(r1).toBe(true);
    const r2 = await store.reserve("kid", "CC==", 1000);
    expect(r2).toBe(false);

    // finalize should call pExpire and succeed normally
    await store.finalize("kid", "CC==", 2000);
    expect(redis.pExpire).toHaveBeenCalled();

    // delete should call del
    await store.delete("kid", "CC==");
    expect(redis.del).toHaveBeenCalled();
  });

  it("finalize throws when pExpire reports missing key", async () => {
    const redis = {
      set: vi.fn(async () => "OK"),
      pExpire: vi.fn(async () => 0),
      del: vi.fn(async () => 1),
    } as any;
    const store = new RedisNonceStore(redis, "x");
    await expect(store.finalize("k", "n", 1000)).rejects.toThrow(
      /RedisNonceStore.finalize: key missing during finalize/,
    );
  });
});
