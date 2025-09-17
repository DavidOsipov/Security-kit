// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect, beforeEach } from 'vitest';
import { normalizeInputString } from '../../src/canonical.ts';
import { registerTelemetry, _resetTelemetryForTests } from '../../src/utils.ts';

/**
 * Deterministic structural introduction test:
 * Uses FULLWIDTH FULL STOP (U+FF0E) which NFKC normalizes to '.'
 * and FULLWIDTH COLON (U+FF1A) which normalizes to ':' to ensure
 * structural delimiter introduction is detected and metric emitted.
 */

describe('canonical: structural introduction detection', () => {
  const emitted: Array<{ name: string; value?: number; tags?: Record<string, string> }> = [];

  beforeEach(() => {
    _resetTelemetryForTests();
    emitted.length = 0;
    registerTelemetry((name, value, tags) => {
      emitted.push({ name, value, tags });
    });
  });

  it('throws and emits unicode.structural.introduced for fullwidth delimiters', async () => {
    const raw = 'segment\uFF0Einner\uFF1Atrail'; // contains no ASCII '.' or ':' literally
    let threw = false;
    try {
      normalizeInputString(raw, 'struct-intro');
    } catch (e) {
      threw = true;
      expect(String(e)).toMatch(/introduced structural characters/);
    }
    expect(threw).toBe(true);
    // Flush microtask queue for telemetry emission
    await Promise.resolve();
    await Promise.resolve();
    const metric = emitted.find(e => e.name === 'unicode.structural.introduced');
    expect(metric).toBeDefined();
    expect(metric?.value).toBeGreaterThanOrEqual(1);
    expect(metric?.tags?.context).toBe('struct-intro');
    expect(metric?.tags?.chars).toMatch(/[.:]/);
  });
});
