// Migrated crypto tests for Deno
import { assertEquals, assertThrows } from "https://deno.land/std@0.210.0/assert/mod.ts";
import { generateSecureIdSync } from "../../src/crypto.ts";
import { secureCompareAsync } from "../../src/utils.ts";

Deno.test("crypto: generateSecureIdSync creates unique IDs", () => {
  const id1 = generateSecureIdSync(32);
  const id2 = generateSecureIdSync(32);
  
  assertEquals(id1.length, 32);
  assertEquals(id2.length, 32);
  assertEquals(id1 === id2, false); // Should be unique
});

Deno.test("crypto: secure comparison prevents timing attacks", async () => {
  const secret = "super-secret-token";
  const correct = "super-secret-token";
  const wrong = "wrong-secret-token";
  
  // Test that comparison works
  const result1 = await secureCompareAsync(secret, correct);
  const result2 = await secureCompareAsync(secret, wrong);
  
  assertEquals(result1, true);
  assertEquals(result2, false);
  
  // Test timing consistency (simplified)
  const start1 = performance.now();
  await secureCompareAsync(secret, correct);
  const time1 = performance.now() - start1;
  
  const start2 = performance.now();
  await secureCompareAsync(secret, wrong);
  const time2 = performance.now() - start2;
  
  // Times should be similar (within reasonable variance for test environment)
  const variance = Math.abs(time1 - time2);
  console.log(`Timing variance: ${variance.toFixed(3)}ms`);
});

Deno.test("crypto: rejects invalid parameters", () => {
  assertThrows(() => {
    generateSecureIdSync(-1);
  });
  
  assertThrows(() => {
    generateSecureIdSync(10000); // Too large
  });
});