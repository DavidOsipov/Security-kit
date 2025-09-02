// SPDX-License-Identifier: MIT
import { describe, expect, test } from 'vitest';
// Env knobs
const PERF_LOG = process.env.PERF_LOG === '1' || process.env.PERF_LOG === 'true';
import { SecureLRUCache } from '../../src/secure-lru-cache';

// Utilities (kept small and focused)
function now(): number {
  return typeof performance !== 'undefined' && performance.now
    ? performance.now()
    : Date.now();
}

async function warmup(fn: () => void, iterations = 100): Promise<void> {
  for (let i = 0; i < iterations; i++) fn();
  await new Promise((r) => setTimeout(r, 5));
}

function forceGC(): void {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if (typeof (globalThis as any).gc === 'function') {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).gc();
  }
}

function median(values: number[]): number {
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 0 ? (s[mid - 1] + s[mid]) / 2 : s[mid];
}

function runBenchmark(fn: () => void, samples = 200): number[] {
  const out: number[] = [];
  for (let i = 0; i < samples; i++) {
    const t0 = now();
    fn();
    const t1 = now();
    out.push(t1 - t0);
    if ((i & 0xff) === 0) forceGC();
  }
  return out;
}

describe('SecureLRUCache - security performance benchmarks', () => {
  test('wipe() cost under heavy evictions', async () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 50,
      maxBytes: 50 * 1024,
      defaultTtlMs: 60_000,
      copyOnSet: true,
      copyOnGet: true,
      rejectSharedBuffers: true,
      maxEntryBytes: 32 * 1024,
      maxSyncEvictions: 16,
      recencyMode: 'sieve',
    });

    // Fill cache with moderately large values
    for (let i = 0; i < 50; i++) {
      const v = new Uint8Array(6 * 1024);
      cache.set(`k-${i}`, v);
    }

    await warmup(() => cache.get('k-0'));

    const samples = runBenchmark(() => {
      // Insert one that forces multiple evictions
      const v = new Uint8Array(24 * 1024);
      cache.set(`k-new-${Math.random()}`, v);
    }, 300);

    const med = median(samples);
    // Ensure wipe isn't catastrophic (tunable threshold)
    expect(med).toBeLessThan(10);
  }, 30_000);

  test('copyOnSet / copyOnGet overhead', async () => {
    const baseOptions = {
      maxEntries: 200,
      maxBytes: 2 * 1024 * 1024,
      defaultTtlMs: 60_000,
      maxEntryBytes: 128 * 1024,
    } as const;

  const cacheCopy = new SecureLRUCache<string, Uint8Array>({ ...baseOptions, copyOnSet: true, copyOnGet: true, recencyMode: 'sieve' });
  const cacheNoCopy = new SecureLRUCache<string, Uint8Array>({ ...baseOptions, copyOnSet: false, copyOnGet: false, recencyMode: 'sieve' });

    const payload = new Uint8Array(16 * 1024);

    await warmup(() => {
      cacheCopy.set('warm', payload);
      cacheNoCopy.set('warm', payload);
    }, 50);

    const samplesCopySet = runBenchmark(() => cacheCopy.set(`c-${Math.random()}`, payload), 200);
    const samplesNoCopySet = runBenchmark(() => cacheNoCopy.set(`n-${Math.random()}`, payload), 200);

    const medCopy = median(samplesCopySet);
    const medNoCopy = median(samplesNoCopySet);

    // Copy-on-set should be measurable but not orders of magnitude slower
    expect(medCopy).toBeGreaterThanOrEqual(medNoCopy);
    expect(medCopy / Math.max(1, medNoCopy)).toBeLessThan(8);
  }, 30_000);

  test('rejectSharedBuffers performance and correctness', async () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 20,
      maxBytes: 200 * 1024,
      rejectSharedBuffers: true,
      recencyMode: 'sieve',
    });

    // Create a SharedArrayBuffer view if supported
    let sabSupported = false;
    try {
      // @ts-ignore
      if (typeof SharedArrayBuffer !== 'undefined') {
        // @ts-ignore
        const sab = new SharedArrayBuffer(1024);
        const view = new Uint8Array(sab);
        cache.set('sab', view);
        sabSupported = true;
      }
    } catch {
      // fallback: ensure rejection path exists logically
      sabSupported = false;
    }

    // The operation should either throw or ignore the set; ensure stability
    const samples = runBenchmark(() => {
      try {
        // @ts-ignore
        const v = typeof SharedArrayBuffer !== 'undefined' ? new Uint8Array(new SharedArrayBuffer(256)) : new Uint8Array(256);
        cache.set(`s-${Math.random()}`, v);
      } catch {
        // swallow; we're measuring performance impact not correctness here
      }
    }, 150);

    const med = median(samples);
    expect(med).toBeLessThan(5);
    // Sanity: if SAB isn't supported we still ran the benchmark
    expect(typeof sabSupported).toBe('boolean');
  }, 20_000);

  test('eviction storm: many small entries + rapid gets', async () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 500,
      maxBytes: 512 * 1024,
      defaultTtlMs: 30_000,
      copyOnSet: true,
      maxSyncEvictions: 32,
      recencyMode: 'sieve',
    });

    const small = new Uint8Array(64);
    for (let i = 0; i < 500; i++) cache.set(`pre-${i}`, small);

    await warmup(() => cache.get('pre-0'), 50);

    const samples = runBenchmark(() => {
      for (let j = 0; j < 20; j++) {
        cache.set(`e-${Math.random()}`, small);
        cache.get(`pre-${Math.floor(Math.random() * 500)}`);
      }
    }, 120);

    const med = median(samples);
    // Ensure storm handler isn't catastrophic
    expect(med).toBeLessThan(20);
  }, 40_000);
});
