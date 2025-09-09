import { describe, it, expect, beforeEach } from 'vitest';
import { getCanonicalConfig, setCanonicalConfig, _resetCanonicalConfigForTests } from '../../src/config';

describe('Canonical config', () => {
  beforeEach(() => {
    _resetCanonicalConfigForTests();
  });

  it('returns defaults initially', () => {
    const cfg = getCanonicalConfig();
    expect(cfg.maxStringLengthBytes).toBeGreaterThan(0);
    expect(cfg.maxTopLevelArrayLength).toBeGreaterThan(0);
  });

  it('accepts valid settings and applies them', () => {
    setCanonicalConfig({ maxStringLengthBytes: 1024, maxTopLevelArrayLength: 10 });
    const cfg = getCanonicalConfig();
    expect(cfg.maxStringLengthBytes).toBe(1024);
    expect(cfg.maxTopLevelArrayLength).toBe(10);
  });

  it('rejects invalid settings', () => {
    expect(() => setCanonicalConfig({ maxStringLengthBytes: -1 as any })).toThrow();
    expect(() => setCanonicalConfig({ maxTopLevelArrayLength: 0 as any })).toThrow();
  });
});
