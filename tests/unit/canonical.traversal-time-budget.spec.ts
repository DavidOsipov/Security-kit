import { describe, it, expect } from 'vitest';
import { toCanonicalValue, setCanonicalConfig } from '../../src/canonical';
import { CanonicalizationTraversalError } from '../../src/errors';

describe('canonicalization traversal time budget', () => {
  it('throws when traversal exceeds small time budget', () => {
    // Set extremely small traversal budget to force timeout
    setCanonicalConfig({ traversalTimeBudgetMs: 1, circularPolicy: 'fail' });

    // Create a proxy that performs busy-wait to consume time per property access
    const target: Record<string, unknown> = {};
    for (let i = 0; i < 50; i++) target['k' + i] = i;

    const proxy = new Proxy(target, {
      get(obj, prop, receiver) {
        const start = Date.now();
        while (Date.now() - start < 2) { /* busy wait ~2ms */ }
        return Reflect.get(obj, prop, receiver);
      },
      getOwnPropertyDescriptor(obj, prop) {
        const start = Date.now();
        while (Date.now() - start < 2) { /* busy wait */ }
        return Object.getOwnPropertyDescriptor(obj, prop);
      }
    });

    expect(() => toCanonicalValue(proxy)).toThrow(CanonicalizationTraversalError);
  });
});
