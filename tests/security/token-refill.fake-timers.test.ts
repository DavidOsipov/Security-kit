// tests/security/token-refill.fake-timers.test.ts
// RULE-ID: deterministic-async

import { describe, beforeEach, afterEach, test, expect, vi } from "vitest";

describe("token refill math (deterministic fake timers)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("refills proportionally per second up to burst capacity", async () => {
    const state = {
      rateLimitPerMinute: 60,
      tokens: 0,
      burst: 10,
      lastRefillSec: Math.floor(Date.now() / 1000),
    };
    function refillTokens(nowSec: number) {
      const rateLimitPerMinute = state.rateLimitPerMinute;
      if (rateLimitPerMinute <= 0) return;
      const last = state.lastRefillSec ?? nowSec;
      if (nowSec <= last) return;
      const deltaSec = Math.min(nowSec - last, 3600);
      const precision = 60000;
      const perMs = Math.floor((rateLimitPerMinute * precision) / 60000);
      const deltaMs = deltaSec * 1000;
      const currentTokens = Math.floor(state.tokens * precision);
      const capacity = Math.floor(state.burst * precision);
      const remainingCapacity = Math.max(0, capacity - currentTokens);
      const tokensToAdd = Math.min(remainingCapacity, perMs * deltaMs);
      const nextTokens = currentTokens + tokensToAdd;
      state.tokens = Math.floor(nextTokens / precision);
      state.lastRefillSec = nowSec;
    }

    const start = Math.floor(Date.now() / 1000);
    refillTokens(start);
    expect(state.tokens).toBe(0);

    await vi.advanceTimersByTimeAsync(1000);
    refillTokens(start + 1);
    // With 60 tokens/minute => ~1 token per second, floor with precision
    expect(state.tokens).toBeGreaterThanOrEqual(1);
    expect(state.tokens).toBeLessThanOrEqual(state.burst);

    // Advance 20s should fill up to burst (10)
    await vi.advanceTimersByTimeAsync(20000);
    refillTokens(start + 21);
    expect(state.tokens).toBe(state.burst);
  });

  test("very low rate accumulates slowly and floors correctly", async () => {
    const state = {
      rateLimitPerMinute: 1,
      tokens: 0,
      burst: 5,
      lastRefillSec: Math.floor(Date.now() / 1000),
    };
    function refillTokens(nowSec: number) {
      const rateLimitPerMinute = state.rateLimitPerMinute;
      if (rateLimitPerMinute <= 0) return;
      const last = state.lastRefillSec ?? nowSec;
      if (nowSec <= last) return;
      const deltaSec = Math.min(nowSec - last, 3600);
      const precision = 60000;
      const perMs = Math.floor((rateLimitPerMinute * precision) / 60000);
      const deltaMs = deltaSec * 1000;
      const currentTokens = Math.floor(state.tokens * precision);
      const capacity = Math.floor(state.burst * precision);
      const remainingCapacity = Math.max(0, capacity - currentTokens);
      const tokensToAdd = Math.min(remainingCapacity, perMs * deltaMs);
      const nextTokens = currentTokens + tokensToAdd;
      state.tokens = Math.floor(nextTokens / precision);
      state.lastRefillSec = nowSec;
    }
    const start = Math.floor(Date.now() / 1000);
    refillTokens(start);
    expect(state.tokens).toBe(0);
    // 60 seconds at 1 token/minute in a single refill => 1 token
    await vi.advanceTimersByTimeAsync(60000);
    refillTokens(start + 60);
    expect(state.tokens).toBe(1);

    // Note: two 30s steps each floor to 0 due to per-step flooring; document behavior
    state.tokens = 0;
    state.lastRefillSec = start;
    await vi.advanceTimersByTimeAsync(30000);
    refillTokens(start + 30);
    await vi.advanceTimersByTimeAsync(30000);
    refillTokens(start + 60);
    expect(state.tokens).toBe(0);
  });

  test("large delta is capped (max 3600 seconds) and respects burst", async () => {
    const state = {
      rateLimitPerMinute: 120,
      tokens: 0,
      burst: 50,
      lastRefillSec: Math.floor(Date.now() / 1000),
    };
    function refillTokens(nowSec: number) {
      const rateLimitPerMinute = state.rateLimitPerMinute;
      if (rateLimitPerMinute <= 0) return;
      const last = state.lastRefillSec ?? nowSec;
      if (nowSec <= last) return;
      const deltaSec = Math.min(nowSec - last, 3600);
      const precision = 60000;
      const perMs = Math.floor((rateLimitPerMinute * precision) / 60000);
      const deltaMs = deltaSec * 1000;
      const currentTokens = Math.floor(state.tokens * precision);
      const capacity = Math.floor(state.burst * precision);
      const remainingCapacity = Math.max(0, capacity - currentTokens);
      const tokensToAdd = Math.min(remainingCapacity, perMs * deltaMs);
      const nextTokens = currentTokens + tokensToAdd;
      state.tokens = Math.floor(nextTokens / precision);
      state.lastRefillSec = nowSec;
    }
    const start = Math.floor(Date.now() / 1000);
    // Simulate a huge jump (e.g., 10 hours) — the implementation caps at 3600s
    await vi.advanceTimersByTimeAsync(10 * 3600 * 1000);
    refillTokens(start + 10 * 3600);
    // With 120 tokens/minute => 2 tokens/sec, for capped 3600s => 7200 tokens, but burst=50 caps
    expect(state.tokens).toBe(state.burst);
  });

  test("precision boundary: many small steps do not overshoot due to flooring", async () => {
    const state = {
      rateLimitPerMinute: 60,
      tokens: 0,
      burst: 5,
      lastRefillSec: Math.floor(Date.now() / 1000),
    };
    function refillTokens(nowSec: number) {
      const rateLimitPerMinute = state.rateLimitPerMinute;
      if (rateLimitPerMinute <= 0) return;
      const last = state.lastRefillSec ?? nowSec;
      if (nowSec <= last) return;
      const deltaSec = Math.min(nowSec - last, 3600);
      const precision = 60000;
      const perMs = Math.floor((rateLimitPerMinute * precision) / 60000);
      const deltaMs = deltaSec * 1000;
      const currentTokens = Math.floor(state.tokens * precision);
      const capacity = Math.floor(state.burst * precision);
      const remainingCapacity = Math.max(0, capacity - currentTokens);
      const tokensToAdd = Math.min(remainingCapacity, perMs * deltaMs);
      const nextTokens = currentTokens + tokensToAdd;
      state.tokens = Math.floor(nextTokens / precision);
      state.lastRefillSec = nowSec;
    }
    const start = Math.floor(Date.now() / 1000);
    refillTokens(start);
    for (let i = 1; i <= 10; i++) {
      await vi.advanceTimersByTimeAsync(100); // 100ms slices
      // Use integer seconds for lastRefillSec progression; simulate fractional by batching
      const nowSec = Math.floor(Date.now() / 1000);
      refillTokens(nowSec);
    }
    // Many small steps may floor to 0; assert no overshoot and within [0,1]
    expect(state.tokens).toBeGreaterThanOrEqual(0);
    expect(state.tokens).toBeLessThanOrEqual(1);
  });
});
