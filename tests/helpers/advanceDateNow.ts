// Test helper: run a function with Date.now temporarily overridden to return a fixed timestamp.
// Use this in tests that need deterministic Date.now behavior while allowing real timers
// and microtasks to run normally (avoids vitest fake-timer interaction with Promise microtasks).

export async function withAdvancedDateNow<T>(
  timeMs: number,
  fn: () => Promise<T> | T,
): Promise<T> {
  const origDateNow = Date.now;
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test-only shim
    (Date as any).now = () => timeMs;
    const res = await fn();
    return res as T;
  } finally {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- restore
    (Date as any).now = origDateNow;
  }
}
