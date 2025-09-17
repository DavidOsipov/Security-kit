import { describe, it, expect } from 'vitest';
import { toCanonicalValue, setCanonicalConfig } from '../../src/canonical';
import { CanonicalizationTraversalError } from '../../src/errors';

describe('circularPolicy behavior', () => {
  it('fails fast on circular reference with default policy (fail)', () => {
    setCanonicalConfig({ circularPolicy: 'fail' });
    const a: any = {};
    a.self = a;
    expect(() => toCanonicalValue(a)).toThrow(CanonicalizationTraversalError);
  });

  it('annotates circular reference when policy=annotate', () => {
    setCanonicalConfig({ circularPolicy: 'annotate' });
    const a: any = {};
    a.self = a;
    const canon = toCanonicalValue(a) as any;
    // Top-level may get non-enumerable marker only if nested; we assert nested marker
    expect(canon.self.__circular).toBe(true);
  });
});
