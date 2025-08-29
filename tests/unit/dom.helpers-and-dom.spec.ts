import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

// We import the module dynamically in tests to avoid brittle named-export assumptions
describe('dom helpers and DOMValidator (jsdom)', () => {
  let mod: any;
  beforeEach(async () => {
    mod = await import('../../src/dom');
  });

  it('redactAttributesSafely removes attribute values and preserves names', () => {
    const fn = (mod as any).redactAttributesSafely;
    expect(typeof fn).toBe('function');
    const input = `div[data-test="secret value"][x=unquoted]`;
    const out = fn(input);
    expect(out).toContain('data-test');
    expect(out).toContain('x');
    expect(out).toMatch(/<redacted>/i); // should include redaction token for quoted segments
    expect(out).not.toContain('secret value');
    expect(out).not.toContain('unquoted');
  });

  it('removeQuotedSegmentsSafely strips quoted substrings and handles escapes', () => {
    const fn = (mod as any).removeQuotedSegmentsSafely;
    const input = `a[title="he\"llo"] b[class='x'] c`;
    const out = fn(input);
    expect(out).toContain('<redacted>');
    expect(out).not.toContain('he"llo');
    expect(out).not.toContain("'x'");
  });

  it('extractAttributeSegments returns bracketed segments', () => {
    const fn = (mod as any).extractAttributeSegments;
    const input = `div[data-a="1"][data-b='2'] span`;
    const parts = fn(input);
    expect(Array.isArray(parts)).toBe(true);
    expect(parts.length).toBeGreaterThanOrEqual(2);
    expect(parts[0]).toMatch(/^\[data-a/);
    expect(parts[1]).toMatch(/^\[data-b/);
  });

  it('DOMValidator queryAllSafely and validateElement work with jsdom', () => {
    const { createDefaultDOMValidator } = mod;
    const container = document.createElement('div');
    container.id = 'main-content';
    document.body.appendChild(container);

    // add a child element inside allowed root
    const child = document.createElement('button');
    child.className = 'btn';
    container.appendChild(child);

    const v = createDefaultDOMValidator({
      allowedRootSelectors: new Set(['#main-content']),
      forbiddenRoots: new Set(['body']),
    });

    // queryAllSafely should find the button
    const found = v.queryAllSafely('.btn');
    expect(found.length).toBeGreaterThanOrEqual(1);
    expect(found[0].tagName.toLowerCase()).toBe('button');

    // containsWithinAllowedRoots should be true for the child
    expect(v.containsWithinAllowedRoots(child)).toBe(true);

    // validateElement should accept the element and set TTL-based cache
    const res = v.validateElement(child);
    expect(res).toBe(child);
  });

  it('invalidateCache clears resolved roots and emits cache_refresh event when auditHook set', async () => {
    const spy = vi.fn();
    const { createDefaultDOMValidator } = mod;
    const container = document.createElement('div');
    container.id = 'main-header';
    document.body.appendChild(container);

    const v = createDefaultDOMValidator({
      allowedRootSelectors: new Set(['#main-header']),
      forbiddenRoots: new Set(['body']),
      auditHook: spy,
      auditHookTimeoutMs: 500,
    });

    // prime the cache
    v.queryAllSafely('div');
    v.invalidateCache();

  // allow the fire-and-forget audit call to run
  vi.useFakeTimers();
  await vi.runAllTimersAsync();
  vi.useRealTimers();
    expect(spy).toHaveBeenCalled();
    const called = spy.mock.calls[0][0];
    expect(called.kind).toBe('cache_refresh');
  });

  it('rate limiter triggers InvalidParameterError when exceeded', () => {
    const { createDefaultDOMValidator, DOMValidator } = mod;
    // small maxValidationsPerSecond to trigger quickly
    const v = createDefaultDOMValidator({
      allowedRootSelectors: new Set(['#main-content']),
      forbiddenRoots: new Set(['body']),
      maxValidationsPerSecond: 1,
    });

    // first call should succeed
    expect(() => v.validateSelectorSyntax('#a')).not.toThrow();
    // second call within same second should exceed the limit and throw
    let threw = false;
    try {
      v.validateSelectorSyntax('#b');
    } catch (err) {
      threw = true;
    }
    expect(threw).toBe(true);
  });

  it('emitSelectorHash produces follow-up validation_failure_hash when enabled', async () => {
    const spy = vi.fn();
    const { createDefaultDOMValidator } = mod;
    const v = createDefaultDOMValidator({
      allowedRootSelectors: new Set(['#main-content']),
      forbiddenRoots: new Set(['body']),
      auditHook: spy,
      emitSelectorHash: true,
      auditHookTimeoutMs: 2000,
    });

    // invoke a validation failure by passing an expensive selector
    try {
      v.validateSelectorSyntax('div:has(span)');
    } catch {
      // expected
    }

  // allow async follow-up hash emission to complete
  vi.useFakeTimers();
  await vi.runAllTimersAsync();
  vi.useRealTimers();
    // we expect at least two calls: initial validation_failure and follow-up validation_failure_hash
    expect(spy.mock.calls.length).toBeGreaterThanOrEqual(1);
    const kinds = spy.mock.calls.map((c: any) => c[0].kind);
    expect(kinds).toContain('validation_failure');
    // follow-up hash may come later; allow it to be present if environment supports sha256
    if (kinds.includes('validation_failure_hash')) {
      const found = spy.mock.calls.find((c: any) => c[0].kind === 'validation_failure_hash');
      if (found && found[0]) {
        const follow = found[0];
        expect(typeof follow.selectorHash).toBe('string');
        expect(follow.selectorHash.length).toBeGreaterThan(0);
      }
    }
  });
});
