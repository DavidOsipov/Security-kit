// Test migration utilities for Deno
// Provides compatibility layer between Vitest and Deno.test

export function describe(name: string, fn: () => void | Promise<void>) {
  return Deno.test({
    name: `${name} (suite)`,
    fn: async (t) => {
      // Setup describe context
      await fn();
    }
  });
}

export function it(name: string, fn: () => void | Promise<void>) {
  return Deno.test({
    name,
    fn: async () => {
      await fn();
    }
  });
}

// Vitest assertion compatibility
export { assertEquals as expect } from "https://deno.land/std@0.210.0/assert/mod.ts";

// Export Deno test utilities
export { 
  assertEquals,
  assertThrows,
  assert,
  assertExists 
} from "https://deno.land/std@0.210.0/assert/mod.ts";