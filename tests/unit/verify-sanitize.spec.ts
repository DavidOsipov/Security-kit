import { describe, it, expect } from 'vitest';
import { parse } from '@typescript-eslint/parser';
import { findConsoleViolations, nodeContainsDevGuard, isConsoleAllowed, processFallback } from '../../scripts/verify-sanitize';
import path from 'path';

// Helper to construct an ESLint.LintResult-like object
function makeResult(source: string, filePath = '/repo/src/example.ts') {
  return {
    filePath: path.resolve(filePath),
    source,
    messages: [],
  } as any;
}

describe('verify-sanitize (unit)', () => {
  it('nodeContainsDevGuard finds isDevelopment identifier', () => {
    const src = 'if (isDevelopment()) { console.log("ok") }';
    const res = makeResult(src, '/repo/src/dev-id.ts');
    const v = findConsoleViolations([res]);
    // this source contains console but it is guarded in an if(isDevelopment()) so no violation expected
    expect(v.length).toBe(0);
  });

  it('nodeContainsDevGuard finds environment.isProduction access', () => {
    const src = 'if (environment.isProduction) console.log("p")';
    const res = makeResult(src, '/repo/src/dev-env.ts');
    const v = findConsoleViolations([res]);
    expect(v.length).toBe(0);
  });

  it('findConsoleViolations reports unguarded console', () => {
    const src = 'function foo() { console.log("bad") }';
    const res = makeResult(src, '/repo/src/bad.ts');
    const violations = findConsoleViolations([res]);
    expect(violations.length).toBeGreaterThan(0);
    expect(violations.some((s) => s.includes('console.* usage detected'))).toBe(true);
  });

  it('findConsoleViolations allows console inside dev helper', () => {
    const src = 'function _devConsole() { if (isDevelopment()) { console.log("fine") } }';
    const res = makeResult(src, '/repo/src/ok.ts');
    const violations = findConsoleViolations([res]);
    expect(violations.length).toBe(0);
  });

  it('isConsoleAllowed fallback behavior', () => {
    const lines = [
      'function _devConsole() {',
      '  // helper',
      '}',
      'console.log("x")',
    ];
    expect(isConsoleAllowed(4, lines, true)).toBe(true);
  });

  it('processFallback collects no-console messages', () => {
    const res: any = {
      filePath: path.resolve('/repo/src/fallback.ts'),
      source: 'console.log("hey")',
      messages: [ { ruleId: 'no-console', line: 1, message: 'Unexpected console' } ],
    };
    const out: string[] = [];
    processFallback(res, res.source, out);
    expect(out.length).toBeGreaterThanOrEqual(1);
  });
});
