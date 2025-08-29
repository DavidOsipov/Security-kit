import { it, describe, expect } from 'vitest';
import { withAdvancedDateNow } from './advanceDateNow';

describe('withAdvancedDateNow helper', () => {
  it('patches Date.now during execution and restores afterwards', async () => {
    const before = Date.now();
    const advanced = before + 60_000;

    const result = await withAdvancedDateNow(advanced, async () => {
      // inside callback, Date.now should return the advanced value
      expect(Date.now()).toBe(advanced);
      return 'ok';
    });

    expect(result).toBe('ok');
    // after completion, Date.now should be back to near original (allow small drift)
    const after = Date.now();
    expect(after).toBeGreaterThanOrEqual(before);
    expect(after).toBeLessThan(advanced);
  });

  it('restores Date.now even if callback throws', async () => {
    const before = Date.now();
    const advanced = before + 10_000;

    await expect(
      withAdvancedDateNow(advanced, async () => {
        expect(Date.now()).toBe(advanced);
        throw new Error('test-ex');
      }),
    ).rejects.toThrow('test-ex');

    const after = Date.now();
    expect(after).toBeGreaterThanOrEqual(before);
    expect(after).toBeLessThan(advanced);
  });
});
