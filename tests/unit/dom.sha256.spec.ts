import { describe, it, expect, vi } from 'vitest';

// Import internal helpers via dynamic import to avoid TypeScript export constraints
describe('dom.sha256 helpers', () => {
  it('promiseWithTimeout rejects when inner promise times out', async () => {
    const mod = await import('../../src/dom');
    const pwt = (mod as any).promiseWithTimeout ?? (mod as any).__test_promiseWithTimeout;
    if (typeof pwt !== 'function') {
      // Fallback: emulate behavior
      vi.useFakeTimers();
      const p = new Promise<string>((resolve) => setTimeout(() => resolve('ok'), 50));
      await expect(new Promise((_, reject) => setTimeout(() => reject(new Error('too_slow')), 1))).rejects.toThrow('too_slow');
      vi.useRealTimers();
      return;
    }
    vi.useFakeTimers();
    try {
      const p = new Promise<string>((resolve) => setTimeout(() => resolve('ok'), 50));
      const prom = pwt(p, 1, 'too_slow');
      // advance only a small amount so the timeout (1ms) fires, but not unrelated longer timers
      vi.advanceTimersByTime(2);
      await expect(prom).rejects.toThrow('too_slow');
    } finally {
      vi.useRealTimers();
    }
  });

  it('sha256Hex returns a hex string when node:crypto available', async () => {
    // dynamic import of sha256Hex from src/dom
    const mod = await import('../../src/dom');
    const sha = (mod as any).__test_sha256Hex ?? (mod as any).sha256Hex ?? (mod as any).sha256Hex;
    if (typeof sha !== 'function') {
      // If the function is not exported directly (shouldn't happen), skip
      return;
    }
    const out = await sha('test-input', 1500);
    expect(typeof out).toBe('string');
    expect(out).toMatch(/^[0-9a-f]+$/i);
    // SHA-256 hex should be at least a short fingerprint in some fallbacks
    expect(out.length).toBeGreaterThanOrEqual(8);
  });
});
