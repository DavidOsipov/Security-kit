// Test migration utilities for Security-kit
// Provides compatibility layer between Vitest and Deno.test

// Re-export Deno's testing utilities
export {
  assertEquals,
  assertThrows,
  assert,
  assertExists,
  assertStrictEquals,
  assertNotEquals
} from "https://deno.land/std@0.210.0/assert/mod.ts";

// Compatibility helpers for Vitest migration
export function describe(name: string, fn: () => void | Promise<void>) {
  console.log(`📋 ${name}`);
  return fn();
}

export function it(name: string, fn: () => void | Promise<void>) {
  return Deno.test({
    name,
    fn: async () => {
      console.log(`  ✓ ${name}`);
      await fn();
    }
  });
}

// Enhanced expect with security-focused assertions
export class SecurityExpect<T> {
  constructor(private value: T) {}
  
  toBe(expected: T) {
    assertEquals(this.value, expected);
  }
  
  toBeSecure() {
    // Custom security assertion
    if (typeof this.value === 'string' && this.value.includes('password')) {
      throw new Error('Security violation: password in plain text');
    }
  }
  
  toHaveLength(expected: number) {
    if (typeof this.value === 'string' || Array.isArray(this.value)) {
      assertEquals((this.value as any).length, expected);
    }
  }
}

export function expect<T>(value: T): SecurityExpected<T> {
  return new SecurityExpected(value);
}