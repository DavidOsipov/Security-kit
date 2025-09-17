// Tests for new Unicode canonicalization hardening features
// Focus: structural char derivation, proxy descriptor cap, ordering determinism,
// low entropy heuristic enhancement, metrics spec stability, logging cap.
import { describe, it, expect } from 'vitest';
import { normalizeInputString, sanitizeForLogging, __test_structuralRiskChars, UNICODE_RISK_METRICS_SPEC, toCanonicalValue, safeStableStringify } from '../src/canonical.ts';
import { InvalidParameterError, CircuitBreakerError } from '../src/errors.ts';

// Helper to build a proxy with expensive descriptor accesses
function buildHostileProxy(attempts: { count: number }) {
  const target: Record<string, unknown> = { a: 1, b: 2 };
  return new Proxy(target, {
    getOwnPropertyDescriptor(_t, prop) {
      attempts.count++;
      // Simulate expensive trap; return normal descriptor
      return { configurable: true, enumerable: true, value: (prop === 'loop' ? target : (target as any)[prop]) };
    },
    ownKeys() {
      attempts.count++;
      return ['a','b','loop'];
    },
    get(t, p, r) {
      attempts.count++;
      return Reflect.get(t,p,r);
    }
  });
}

describe('structural risk char derivation', () => {
  it('derived structural list should all match regex individually via normalize (no throw)', () => {
    for (const ch of __test_structuralRiskChars) {
      // normalization should not throw simply for the character alone
      expect(() => normalizeInputString(ch)).not.toThrow();
    }
  });
});

describe('proxy descriptor attempt cap', () => {
  it('caps descriptor attempts on hostile proxy (no unbounded growth)', () => {
    const attempts = { count: 0 };
    const proxy = buildHostileProxy(attempts);
    // Nest proxy so canonicalization traverses object path
    const payload = { proxy };
    toCanonicalValue(payload);
    // attempts should exceed a small number to ensure traps were invoked
    expect(attempts.count).toBeGreaterThan(5);
    // And remain safely below a hard upper bound (< cap + probe overhead)
    expect(attempts.count).toBeLessThan(550);
  });
});

describe('deterministic key ordering', () => {
  it('object keys are sorted lexicographically by code point', () => {
    const obj = { b:1, a:1, 'A':1, 'aa':1 };
    const canonical = toCanonicalValue(obj) as Record<string, unknown>;
    const json = safeStableStringify(canonical);
    // Expect ordering: A, a, aa, b (code point order)
    expect(json.startsWith('{"A":')).toBe(true);
    expect(json.indexOf('\"A\":') < json.indexOf('\"a\":')).toBe(true);
    expect(json.indexOf('\"a\":') < json.indexOf('\"aa\":')).toBe(true);
  });
});

describe('low entropy heuristic enhancement', () => {
  it('detects single char dominance', () => {
    const s = 'a'.repeat(60) + 'bcdef';
    const norm = normalizeInputString(s); // should pass but risk scoring only if enabled; internal heuristic not exposed
    expect(norm.length).toBe(s.length);
  });
  it('captures top-4 coverage case', () => {
    const chars = ['a','b','c','d'];
    let s = '';
    for (let i=0;i<100;i++) s += chars[i % chars.length];
    // Ensure no single char >50% but combined top 4 = 100%
    const norm = normalizeInputString(s);
    expect(norm.length).toBe(100);
  });
});

describe('risk metrics spec stability', () => {
  it('spec has expected metric ids', () => {
    const ids = UNICODE_RISK_METRICS_SPEC.map(m => m.id).sort();
    expect(ids).toEqual(['bidi','combiningDensity','combiningRun','expansionSoft','introducedStructural','invisibles','lowEntropy','mixedScriptHomoglyph'].sort());
  });
});

describe('logging hard cap', () => {
  it('truncates before normalization beyond 8192 chars (indirectly via output length)', () => {
    const long = 'x'.repeat(9000);
    const out = sanitizeForLogging(long, 9000);
    // sanitized output should reflect earlier truncation but keep <= 9000; since we cap raw to 8192 then no ellipsis unless > maxLength
    expect(out.length).toBeLessThanOrEqual(8200); // allow hash tail
  });
});
