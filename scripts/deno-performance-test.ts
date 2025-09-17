#!/usr/bin/env -S deno run --allow-read --allow-env
import { generateSecureIdSync, getSecureRandomBytesSync } from '../src/crypto.ts';
import { secureCompareAsync } from '../src/utils.ts';

console.log('🚀 Deno Performance Validation for Security-kit');
console.log('='.repeat(50));

// Test 1: Secure ID Generation
console.log('\n📊 Testing secure ID generation...');
const start1 = performance.now();
for (let i = 0; i < 1000; i++) {
  generateSecureIdSync(32);
}
const end1 = performance.now();
const rate1 = Math.round(1000 / (end1 - start1) * 1000);
console.log(`✅ 1000x ID generation: ${Math.round(end1 - start1)}ms`);
console.log(`⚡ Rate: ${rate1} IDs/sec`);

// Test 2: Random Bytes Generation  
console.log('\n🔐 Testing random bytes generation...');
const start2 = performance.now();
for (let i = 0; i < 1000; i++) {
  getSecureRandomBytesSync(256);
}
const end2 = performance.now();
const rate2 = Math.round(1000 / (end2 - start2) * 1000);
console.log(`✅ 1000x 256-byte generation: ${Math.round(end2 - start2)}ms`);
console.log(`⚡ Rate: ${rate2} operations/sec`);

// Test 3: Secure Comparison
console.log('\n🛡️ Testing secure comparison...');
const testStr1 = generateSecureIdSync(64);
const testStr2 = generateSecureIdSync(64);
const start3 = performance.now();
for (let i = 0; i < 1000; i++) {
  await secureCompareAsync(testStr1, testStr2);
}
const end3 = performance.now();
const rate3 = Math.round(1000 / (end3 - start3) * 1000);
console.log(`✅ 1000x secure comparisons: ${Math.round(end3 - start3)}ms`);
console.log(`⚡ Rate: ${rate3} comparisons/sec`);

console.log('\n🎉 Deno Performance Summary:');
console.log(`   🚀 ID Generation: ${rate1} ops/sec`);
console.log(`   🔐 Random Bytes: ${rate2} ops/sec`); 
console.log(`   🛡️ Secure Compare: ${rate3} ops/sec`);
console.log('\n✨ All operations using native Web Crypto API!');