import { describe, beforeEach, afterEach, test, expect, vi } from 'vitest';

// RULE-ID: deterministic-async

describe('Scheduler deterministic timers', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test('setTimeout scheduled task runs after advancing timers', async () => {
    const cb = vi.fn();
    setTimeout(cb, 100);

    expect(cb).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(100);

    expect(cb).toHaveBeenCalledTimes(1);
  });
});