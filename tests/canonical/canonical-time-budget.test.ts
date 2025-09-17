// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { setCanonicalConfig, toCanonicalValue } from '../../src/index.ts';

// We simulate traversal budget exhaustion by setting an extremely low time budget and
// constructing a large nested structure; we also monkey patch Date.now temporarily.

describe('canonicalization traversal time budget', () => {
  it('throws CanonicalizationTraversalError when time budget exceeded', () => {
    setCanonicalConfig({ traversalTimeBudgetMs: 1, circularPolicy: 'fail' });
    const originalNow = Date.now;
    try {
      let calls = 0;
      // Advance virtual time aggressively after a few calls to force deadline exceed.
      const start = originalNow();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (Date as any).now = () => { calls++; return start + (calls > 50 ? 10_000 : 0); };
      // Deep-ish nested object to trigger iterative traversal.
      const root: Record<string, unknown> = {};
      let cursor = root;
      for (let i = 0; i < 300; i++) {
        const child: Record<string, unknown> = {};
        cursor['k' + i] = child; // eslint-disable-line security/detect-object-injection -- controlled test generation
        cursor = child;
      }
      expect(() => toCanonicalValue(root)).toThrowError(/time budget exceeded|Traversal/);
    } finally {
      // restore
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (Date as any).now = originalNow;
    }
  });
});
