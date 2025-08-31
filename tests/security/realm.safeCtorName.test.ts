import { test, expect } from 'vitest';

// RULE-ID: controlled-realm-testing
// This test uses the project's VM helper pattern. If no helper exists,
// exercise a small vm instance to run code and return JSON-serializable output.

import vm from 'node:vm';

function runInVmJson(code: string) {
  const script = new vm.Script(`(function(){ ${code} })()`);
  const context = vm.createContext({});
  const result = script.runInContext(context);
  return result;
}

test('safeCtorName-like behavior inside VM: create typed array and return shape', () => {
  // Create a Uint8Array in the VM and return its byteLength and ctor name
  const result = runInVmJson(`
    const arr = new Uint8Array([1,2,3]);
    return JSON.stringify({ ctor: arr.constructor.name, len: arr.length });
  `);

  const parsed = JSON.parse(result);
  expect(parsed.ctor).toBe('Uint8Array');
  expect(parsed.len).toBe(3);
});