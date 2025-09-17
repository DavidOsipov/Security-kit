import { describe, it, expect } from 'vitest';
import { normalizeInputString } from '../src/canonical.ts';
import { resolveSecurityProfile } from '../src/config.ts';

describe('Context-aware security profiles', () => {
  it('should allow Hello World! in natural language context', () => {
    expect(() => normalizeInputString('Hello World!', 'natural-language')).not.toThrow();
    const result = normalizeInputString('Hello World!', 'natural-language');
    expect(result).toBe('Hello World!');
  });

  it('should block Hello World! in shell input context', () => {
    expect(() => normalizeInputString('Hello World!', 'shell-input')).toThrow();
  });

  it('should allow Hello World! in display text context', () => {
    expect(() => normalizeInputString('Hello World!', 'display-text')).not.toThrow();
    const result = normalizeInputString('Hello World!', 'display-text');
    expect(result).toBe('Hello World!');
  });

  it('should allow URLs in scheme-authority context', () => {
    expect(() => normalizeInputString('https://example.com', 'scheme-authority')).not.toThrow();
    const result = normalizeInputString('https://example.com', 'scheme-authority');
    expect(result).toBe('https://example.com');
  });

  it('should have appropriate security profiles', () => {
    const naturalLanguage = resolveSecurityProfile('natural-language');
    const shellInput = resolveSecurityProfile('shell-input');
    const schemeAuthority = resolveSecurityProfile('scheme-authority');

    expect(naturalLanguage.threshold).toBeGreaterThan(90);
    expect(naturalLanguage.allowLegitimateUse).toBe(true);
    
    expect(shellInput.threshold).toBeLessThan(25);
    expect(shellInput.allowLegitimateUse).toBe(false);
    
    expect(schemeAuthority.threshold).toBeGreaterThan(120);
    expect(schemeAuthority.allowLegitimateUse).toBe(true);
  });
});