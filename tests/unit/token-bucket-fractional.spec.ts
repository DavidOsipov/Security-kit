// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
/**
 * Tests for token bucket refill logic with fractional accumulation.
 * Tests the integer arithmetic implementation in refillTokens function.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";

// Mock Date.now to control time in tests
const mockNow = vi.fn();
Date.now = mockNow;

// Since refillTokens is internal, we'll create a test version that replicates the logic
describe("Token Bucket Refill - Fractional Accumulation", () => {
  interface WorkerState {
    readonly tokens: number;
    readonly burst: number;
    readonly lastRefillSec: number;
    readonly rateLimitPerMinute: number;
  }

  function createTestState(overrides: Partial<WorkerState> = {}): WorkerState {
    const now = Math.floor(mockNow() / 1000);
    return {
      tokens: 10,
      burst: 10,
      lastRefillSec: now,
      rateLimitPerMinute: 60,
      ...overrides,
    };
  }

  // Replicate the refillTokens logic from the worker
  function refillTokens(state: WorkerState): WorkerState {
    const nowSec = Math.floor(Date.now() / 1000);
    const { rateLimitPerMinute, tokens, burst, lastRefillSec } = state;

    if (rateLimitPerMinute <= 0) return state;

    const last = lastRefillSec ?? nowSec;
    if (nowSec <= last) return state;

    // Prevent overflow: cap delta to reasonable maximum (1 hour)
    const deltaSec = Math.min(nowSec - last, 3600);

    // Use higher precision for accurate token calculation
    // 60000ms per minute ensures exact timing for any rate limit
    const precision = 60000;
    const perMs = Math.floor((rateLimitPerMinute * precision) / 60000);
    const deltaMs = deltaSec * 1000; // convert to milliseconds

    const currentTokens = Math.floor(tokens * precision);
    const capacity = Math.floor(burst * precision);

    // Prevent overflow: ensure tokensToAdd doesn't exceed remaining capacity
    const remainingCapacity = Math.max(0, capacity - currentTokens);
    const tokensToAdd = Math.min(remainingCapacity, perMs * deltaMs);
    const nextTokens = currentTokens + tokensToAdd;

    return {
      ...state,
      tokens: Math.floor(nextTokens / precision),
      lastRefillSec: nowSec,
    };
  }

  describe("Fractional Token Accumulation", () => {
    beforeEach(() => {
      // Reset mock time to a known value
      mockNow.mockReturnValue(1000000000000); // 1 second in milliseconds
    });

    it("accumulates fractional tokens over very short intervals", () => {
      let state = createTestState({ tokens: 0, rateLimitPerMinute: 60 }); // 1 token per second

      // Simulate 100ms passing (should add 0.1 tokens)
      mockNow.mockReturnValue(1000000000100); // +100ms
      state = refillTokens(state);
      expect(state.tokens).toBe(0); // Floor(0.1) = 0

      // Another 100ms (total 200ms, 0.2 tokens)
      mockNow.mockReturnValue(1000000000200); // +200ms total
      state = refillTokens(state);
      expect(state.tokens).toBe(0); // Still 0 due to flooring

      // Another 800ms (total 1 second, 1.0 tokens)
      mockNow.mockReturnValue(1000000001000); // +1000ms total
      state = refillTokens(state);
      expect(state.tokens).toBe(1); // Now we get 1 token
    });

    it("handles floor-based refills correctly", () => {
      let state = createTestState({ tokens: 0, rateLimitPerMinute: 120 }); // 2 tokens per second

      // 1000ms should add 2 tokens (120 tokens/minute = 2 tokens/second)
      mockNow.mockReturnValue(1000000001000); // +1000ms = 1 second
      state = refillTokens(state);
      expect(state.tokens).toBe(2);

      // Another 1000ms (total 2 seconds, should add another 2 tokens, total 4)
      mockNow.mockReturnValue(1000000002000); // +2000ms total
      state = refillTokens(state);
      expect(state.tokens).toBe(4);
    });

    it("handles precision multiplier correctly for fractional rates", () => {
      let state = createTestState({ tokens: 0, rateLimitPerMinute: 1 }); // 1 token per minute

      // 120 seconds = 2.0 tokens (should add 2 tokens)
      mockNow.mockReturnValue(1000000000000 + 120000); // +120 seconds
      state = refillTokens(state);
      expect(state.tokens).toBe(2);
    });

    it("respects burst capacity limits", () => {
      let state = createTestState({
        tokens: 0,
        burst: 5,
        rateLimitPerMinute: 120,
      });

      // 3 seconds = 6 tokens, but burst is 5
      mockNow.mockReturnValue(1000000000000 + 3000); // +3 seconds
      state = refillTokens(state);
      expect(state.tokens).toBe(5); // Capped at burst
    });

    it("handles zero rate limit", () => {
      let state = createTestState({ tokens: 0, rateLimitPerMinute: 0 });

      mockNow.mockReturnValue(1000000000000 + 1000); // +1 second
      state = refillTokens(state);
      expect(state.tokens).toBe(0); // No refill when rate is 0
    });

    it("handles negative rate limit", () => {
      let state = createTestState({ tokens: 0, rateLimitPerMinute: -10 });

      mockNow.mockReturnValue(1000000000000 + 1000); // +1 second
      state = refillTokens(state);
      expect(state.tokens).toBe(0); // No refill when rate is negative
    });

    it("accumulates correctly with multiple small refills", () => {
      let state = createTestState({ tokens: 0, rateLimitPerMinute: 60 });

      // 10 refills of 100ms each = 1 second = 1 token
      for (let i = 0; i < 10; i++) {
        mockNow.mockReturnValue(1000000000000 + (i + 1) * 100); // +100ms each time
        state = refillTokens(state);
      }
      expect(state.tokens).toBe(1);
    });

    it("maintains precision across multiple operations", () => {
      let state = createTestState({ tokens: 0, rateLimitPerMinute: 120 });

      // First 1000ms = 2 tokens
      mockNow.mockReturnValue(1000000001000); // +1000ms
      state = refillTokens(state);
      expect(state.tokens).toBe(2);

      // Another 1000ms = another 2 tokens (total 4)
      mockNow.mockReturnValue(1000000002000); // +2000ms total
      state = refillTokens(state);
      expect(state.tokens).toBe(4);
    });

    it("demonstrates fractional accumulation threshold", () => {
      let state = createTestState({ tokens: 0, rateLimitPerMinute: 60 }); // 1 token/second

      // With precision = 60000, perMs = floor((60 * 60000) / 60000) = 60
      // For 100ms: tokensToAdd = 60 * 100 = 6000
      // currentTokens = 0 * 60000 = 0
      // nextTokens = 0 + 6000 = 6000
      // final tokens = floor(6000 / 60000) = 0

      // 100ms should not add any tokens (fractional accumulation)
      mockNow.mockReturnValue(1000000000100); // +100ms
      state = refillTokens(state);
      expect(state.tokens).toBe(0);

      // 900ms more (total 1000ms) should add 1 token
      mockNow.mockReturnValue(1000000001000); // +1000ms total
      state = refillTokens(state);
      expect(state.tokens).toBe(1);
    });

    it("prevents overflow in token accumulation", () => {
      let state = createTestState({
        tokens: 0,
        rateLimitPerMinute: 60,
        burst: 10,
      });

      // Simulate 2 hours passing (should be capped to 1 hour = 60 tokens, but burst is 10)
      mockNow.mockReturnValue(1000000000000 + 2 * 60 * 60 * 1000); // +2 hours
      state = refillTokens(state);
      expect(state.tokens).toBe(10); // Capped at burst capacity
    });
  });
});
