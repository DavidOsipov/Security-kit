import { describe, it, expect } from 'vitest';
import { hasCircularSentinel } from '../../src/canonical';

describe('hasCircularSentinel helper', () => {
  it('detects direct __circular property on object', () => {
    const o: any = { __circular: true };
    expect(hasCircularSentinel(o)).toBe(true);
  });

  it('detects nested __circular in arrays', () => {
    const a: any = [1, { __circular: true }, 3];
    expect(hasCircularSentinel(a)).toBe(true);
  });

  it('returns false for non-circular shapes', () => {
    const o = { a: 1, b: [2, 3] };
    expect(hasCircularSentinel(o)).toBe(false);
  });

  it('handles exotic objects without throwing', () => {
    const o: any = Object.create(null);
    Object.defineProperty(o, 'x', { get() { throw new Error('nope'); } });
    // Should not throw even when property accessors are hostile
    expect(hasCircularSentinel(o)).toBe(false);
  });
});
