// Quick validation test for the security fixes
import { sendSecurePostMessage } from './src/postMessage.js';
import { InvalidParameterError } from './src/errors.js';

// Mock target window
const mockWindow = {
  postMessage: (data, origin) => {
    console.log('✅ Message sent successfully:', data instanceof Uint8Array ? `Uint8Array(${data.length})` : data);
  }
};

console.log('=== Testing Security Fixes ===\n');

// Test 1: Verify the sanitize + allowTypedArrays conflict is now caught
console.log('Test 1: sanitize=true + allowTypedArrays=true should fail fast');
try {
  sendSecurePostMessage({
    targetWindow: mockWindow,
    payload: new Uint8Array([1, 2, 3, 4]),
    targetOrigin: 'https://example.com',
    wireFormat: 'structured',
    sanitize: true, // default
    allowTypedArrays: true,
  });
  console.log('❌ FAILED: Should have thrown an error');
} catch (error) {
  if (error instanceof InvalidParameterError && error.message.includes('Incompatible options')) {
    console.log('✅ PASSED: Correctly caught incompatible options');
  } else {
    console.log('❌ FAILED: Wrong error type:', error.message);
  }
}

// Test 2: Verify sanitize=false + allowTypedArrays=true works
console.log('\nTest 2: sanitize=false + allowTypedArrays=true should work');
try {
  sendSecurePostMessage({
    targetWindow: mockWindow,
    payload: new Uint8Array([1, 2, 3, 4]),
    targetOrigin: 'https://example.com',
    wireFormat: 'structured',
    sanitize: false,
    allowTypedArrays: true,
  });
  console.log('✅ PASSED: Successfully sent typed array with sanitize=false');
} catch (error) {
  console.log('❌ FAILED: Should not have thrown:', error.message);
}

// Test 3: Verify sanitize=true with plain objects still works
console.log('\nTest 3: sanitize=true with plain objects should work');
try {
  sendSecurePostMessage({
    targetWindow: mockWindow,
    payload: { message: 'test', data: [1, 2, 3] },
    targetOrigin: 'https://example.com',
    wireFormat: 'structured',
    sanitize: true,
  });
  console.log('✅ PASSED: Successfully sent plain object with sanitize=true');
} catch (error) {
  console.log('❌ FAILED: Should not have thrown:', error.message);
}

console.log('\n=== All tests completed ===');