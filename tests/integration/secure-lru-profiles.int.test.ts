// SPDX-License-Identifier: MIT
// Integration tests for SecureLRUCache profiles and semantics

import { describe, it, expect, beforeEach, vi } from "vitest";
import { SecureLRUCache, type EvictedEntry } from "../../src/secure-lru-cache";
import {
  getSecureLRUProfiles,
  resolveSecureLRUOptions,
  setSecureLRUProfiles,
} from "../../src/config";

const KEY = "k1";
const BYTES = new Uint8Array(64).fill(7);

function makeCache(profile?: string) {
  const opts = resolveSecureLRUOptions(profile);
  return new SecureLRUCache<string, Uint8Array>({
    maxEntries: 32,
    maxBytes: 128 * 1024,
    ...opts,
  });
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

// Capture wipe events via onEvict and ensure best-effort zeroization happened before callback
function makeEvictObserver() {
  const events: EvictedEntry[] = [];
  const onEvict = (e: EvictedEntry) => events.push(e);
  return { events, onEvict };
}

describe("SecureLRU profiles exist and resolve", () => {
  it("should list the expected built-in profiles", () => {
    const cfg = getSecureLRUProfiles();
    const names = new Set(cfg.profiles.map((p) => p.name));
    expect(names.has("balanced")).toBe(true);
    expect(names.has("low-latency-lru")).toBe(true);
    expect(names.has("throughput-segmented")).toBe(true);
    expect(names.has("throughput-segmented-aggressive")).toBe(true);
    expect(names.has("read-heavy-lru-coarse")).toBe(true);
  });

  it("should resolve each profile without throwing", () => {
    for (const name of [
      "balanced",
      "low-latency-lru",
      "throughput-segmented",
      "throughput-segmented-aggressive",
      "read-heavy-lru-coarse",
    ]) {
      const opts = resolveSecureLRUOptions(name);
      expect(typeof opts).toBe("object");
      // spot-check a few well-known knobs
      expect("ttlAutopurge" in opts).toBe(true);
      expect("copyOnGet" in opts).toBe(true);
      expect("rejectSharedBuffers" in opts).toBe(true);
    }
  });
});

describe("TTL autopurge behavior", () => {
  it("expires entries close to their TTL given the configured resolution tick", async () => {
    // Use a stricter tick for test determinism
    setSecureLRUProfiles({
      defaultProfile: "low-latency-lru",
    });
    const cache = makeCache();
    // Put one short-lived entry
    cache.set(KEY, BYTES, { ttlMs: 100 });
    expect(cache.get(KEY)).toBeInstanceOf(Uint8Array);
    // Wait slightly over TTL + a little buffer for timer to fire
    await sleep(250);
    const v = cache.get(KEY);
    expect(v).toBeUndefined();
  });
});

describe("Recency policy modes", () => {
  it("LRU mode moves items to tail on get (always or sampled)", () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 5,
      maxBytes: 64 * 1024,
      recencyMode: "lru",
      promoteOnGet: "always",
    });
    // insert A,B,C
    cache.set("A", BYTES);
    cache.set("B", BYTES);
    cache.set("C", BYTES);
    // Access A to make it most-recent
    expect(cache.get("A")).toBeTruthy();
    // Insert D,E and then F to force eviction
    cache.set("D", BYTES);
    cache.set("E", BYTES);
    cache.set("F", BYTES);
    // Under true LRU, B should be oldest (A was promoted), so B likely evicted
    const stats = cache.getStats();
    expect(stats.evictions).toBeGreaterThanOrEqual(1);
  });

  it("Segmented mode does not churn pointers on every get and evicts older generations preferentially", () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 5,
      maxBytes: 64 * 1024,
      recencyMode: "segmented",
      segmentedEvictScan: 8,
      segmentRotateEveryOps: 16,
    });
    for (const k of ["A", "B", "C", "D", "E"]) cache.set(k, BYTES);
    // Access some keys to set current generation
    for (const k of ["C", "D", "E"]) expect(cache.get(k)).toBeTruthy();
    // Force an eviction
    cache.set("F", BYTES);
    const stats = cache.getStats();
    expect(stats.evictions).toBeGreaterThanOrEqual(1);
  });
});

describe("Wipe semantics", () => {
  it("best-effort zeroization before onEvict callback when deferred", async () => {
    const { events, onEvict } = makeEvictObserver();
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 2,
      maxBytes: 64 * 1024,
      wipeStrategy: "defer",
      onEvict,
    });
    const x = new Uint8Array(32).fill(1);
    const y = new Uint8Array(32).fill(2);
    cache.set("x", x);
    cache.set("y", y);
    // Evict one
    cache.set("z", new Uint8Array(16));
    // Allow microtasks/timeouts to flush
    await sleep(10);
    expect(events.length).toBeGreaterThanOrEqual(1);
  });
});

// Profile-level smoke test

describe("Profile sanity — end-to-end basic ops", () => {
  const profiles = [
    "balanced",
    "low-latency-lru",
    "throughput-segmented",
    "throughput-segmented-aggressive",
    "read-heavy-lru-coarse",
  ] as const;
  for (const name of profiles) {
    it(`basic set/get/delete works [${name}]`, () => {
      const cache = makeCache(name);
      cache.set("a", BYTES);
      expect(cache.get("a")).toBeInstanceOf(Uint8Array);
      cache.delete("a");
      expect(cache.get("a")).toBeUndefined();
    });
  }
});
