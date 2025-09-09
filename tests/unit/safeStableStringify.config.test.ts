import { describe, it, expect, beforeEach } from 'vitest';
import { _resetCanonicalConfigForTests, setCanonicalConfig } from '../../src/config';
import { safeStableStringify } from '../../src/canonical';

describe('safeStableStringify with config', () => {
  beforeEach(() => {
    _resetCanonicalConfigForTests();
  });

  it('rejects strings larger than configured maxStringLengthBytes', () => {
    setCanonicalConfig({ maxStringLengthBytes: 8 });
    const big = 'a'.repeat(9);
    expect(() => safeStableStringify(big)).toThrow();
  });

  it('allows strings within configured limit', () => {
    setCanonicalConfig({ maxStringLengthBytes: 8 });
    const ok = 'a'.repeat(8);
    expect(() => safeStableStringify(ok)).not.toThrow();
  });
});
