# Test Migration Guide: Vitest → Deno.test

## 🎯 Migration Strategy

### Before (Vitest):
```typescript
import { describe, it, expect, vi } from 'vitest';
import { generateSecureIdSync } from '../src/crypto.ts';

describe('crypto tests', () => {
  it('should generate secure IDs', () => {
    const id = generateSecureIdSync({ length: 32 });
    expect(id).toHaveLength(32);
  });
});
```

### After (Deno.test):
```typescript
import { assertEquals } from "https://deno.land/std@0.210.0/assert/mod.ts";
import { generateSecureIdSync } from "../src/crypto.ts";

Deno.test("crypto: should generate secure IDs", () => {
  const id = generateSecureIdSync({ length: 32 });
  assertEquals(id.length, 32);
});
```

## 🔄 Migration Patterns

### 1. Simple Assertions
- `expect(a).toBe(b)` → `assertEquals(a, b)`
- `expect(a).toHaveLength(n)` → `assertEquals(a.length, n)`
- `expect(fn).toThrow()` → `assertThrows(fn)`

### 2. Test Structure
- `describe('name', () => { ... })` → Group related tests with naming
- `it('should...', () => { ... })` → `Deno.test('should...', () => { ... })`

### 3. Mocking (Advanced)
Vitest `vi.mock` needs careful consideration:
- Simple mocks: Use dependency injection
- Complex mocks: Consider test-specific implementations

## 🛡️ Security-Enhanced Testing

### Timing Attack Testing:
```typescript
Deno.test("security: constant-time comparison", async () => {
  const start = performance.now();
  await secureCompareAsync("secret1", "secret2");
  const time1 = performance.now() - start;
  
  const start2 = performance.now();
  await secureCompareAsync("secret1", "different");
  const time2 = performance.now() - start2;
  
  // Timing should be similar (within reasonable variance)
  const variance = Math.abs(time1 - time2);
  assertEquals(variance < 1, true); // 1ms variance threshold
});
```

### Memory Safety Testing:
```typescript
Deno.test("security: memory wiping", () => {
  const sensitiveData = new Uint8Array([1, 2, 3, 4]);
  secureWipe(sensitiveData);
  
  // Verify all bytes are zeroed
  for (const byte of sensitiveData) {
    assertEquals(byte, 0);
  }
});
```

## ⚡ Performance Testing with Deno.bench

```typescript
import { generateSecureIdSync } from "../src/crypto.ts";

Deno.bench("generateSecureIdSync", () => {
  generateSecureIdSync({ length: 32 });
});

Deno.bench("crypto.getRandomValues", () => {
  crypto.getRandomValues(new Uint8Array(32));
});
```
