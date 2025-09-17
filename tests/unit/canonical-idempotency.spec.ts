// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { normalizeInputString } from '../../src/canonical.ts';
import { InvalidParameterError } from '../../src/errors.ts';

/**
 * Idempotency anomaly test:
 * We monkey-patch String.prototype.normalize temporarily so that a second call
 * to .normalize('NFKC') returns a different string, simulating a hostile
 * environment or polyfill inconsistency. The library should detect this and throw.
 */

describe('canonical: normalization idempotency verification', () => {
  it('throws when second normalization pass changes output', () => {
    const original = String.prototype.normalize;
    try {
      // First call behaves normally; second call mutates result by appending a marker
  let callCount = 0;
      // eslint-disable-next-line no-extend-native -- intentional test patching
      String.prototype.normalize = function patched(this: string, form?: string): string {
        const base = original.call(this, form as string | undefined);
        callCount += 1;
        // Return unchanged on first call, modified on second call only.
        return callCount === 1 ? base + '\\u200C' : base;
      } as unknown as typeof String.prototype.normalize;

  expect(() => normalizeInputString('SimpleValue', 'idempotency-test')).toThrow(InvalidParameterError);
    } finally {
      // Restore original implementation
      String.prototype.normalize = original;
    }
  });
});
