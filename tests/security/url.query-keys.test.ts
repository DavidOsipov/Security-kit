// SPDX-License-Identifier: LGPL-3.0-or-later
// Tests for query parameter key filtration & hardening in createSecureURL / updateURLParams.

import { describe, it, expect } from 'vitest';
import { createSecureURL } from '../../src/url.ts';
import { InvalidParameterError } from '../../src/errors.ts';

// Helper to invoke createSecureURL with minimal base
function build(params: Record<string, unknown>, opts: Parameters<typeof createSecureURL>[4] = {}) {
  return createSecureURL('https://example.com', [], params, undefined, opts);
}

describe('query parameter key filtration - throw mode (explicit)', () => {
  it('throws on forbidden prototype pollution keys when onUnsafeKey=throw', () => {
    // Computed property ensures own data property named __proto__ instead of altering prototype
    const obj: Record<string, unknown> = { ['__proto__']: 'x' };
    expect(() => build(obj, { onUnsafeKey: 'throw' })).toThrow(InvalidParameterError);
    expect(() => build({ constructor: 'x' }, { onUnsafeKey: 'throw' })).toThrow(InvalidParameterError);
    expect(() => build({ prototype: 'x' }, { onUnsafeKey: 'throw' })).toThrow(InvalidParameterError);
    // Map variant
    const m = new Map<string, unknown>([["__proto__", "v"]]);
    expect(() => createSecureURL('https://example.com', [], m, undefined, { onUnsafeKey: 'throw' })).toThrow(InvalidParameterError);
  });

  it('throws on unsafe characters in key when onUnsafeKey=throw', () => {
    expect(() => build({ ' space': 'x' }, { onUnsafeKey: 'throw' })).toThrow(InvalidParameterError);
    expect(() => build({ 'semi;colon': 'x' }, { onUnsafeKey: 'throw' })).toThrow(InvalidParameterError);
  });

  it('throws when key exceeds configured maximum length', () => {
    const longKey = 'a'.repeat(129);
    expect(() => build({ [longKey]: 'v' }, { onUnsafeKey: 'throw' })).toThrow(InvalidParameterError);
  });

  it('throws when value exceeds maximum length (default 2048)', () => {
    const longVal = 'v'.repeat(2049);
    expect(() => build({ ok: longVal }, { onUnsafeKey: 'throw' })).toThrow(InvalidParameterError);
  });

  it('rejects control characters in value', () => {
    expect(() => build({ ok: 'abc\u0001def' }, { onUnsafeKey: 'throw' })).toThrow(InvalidParameterError);
  });

  it('rejects malformed percent-encoding in value', () => {
    expect(() => build({ ok: 'bad%GZ' }, { onUnsafeKey: 'throw' })).toThrow(InvalidParameterError);
  });
});

describe('query parameter key filtration - skip / warn modes', () => {
  it('skips unsafe keys when onUnsafeKey=skip', () => {
    const url = build({ safe: '1', __proto__: 'x', prototype: 'y' }, { onUnsafeKey: 'skip' });
    expect(url).toBe('https://example.com/?safe=1');
  });

  it('skip mode preserves ordering of accepted keys', () => {
    const url = build({ b: '2', __proto__: 'x', a: '1' }, { onUnsafeKey: 'skip' });
    // Order: entries enumeration order of object: insertion order
    expect(url).toBe('https://example.com/?b=2&a=1');
  });
});

describe('query parameter safe key acceptance', () => {
  it('accepts a range of safe keys', () => {
    const url = build({ A: '1', a: '2', 'a_b-C.d': '3', Z9: '4' });
    // Encoding rules produce predictable order
    expect(url).toBe('https://example.com/?A=1&a=2&a_b-C.d=3&Z9=4');
  });
});
