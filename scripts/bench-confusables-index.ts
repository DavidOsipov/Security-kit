// SPDX-License-Identifier: LGPL-3.0-or-later
/**
 * Simple micro benchmark comparing confusables lookup with and without the index.
 * Not a rigorous statistical benchmark; intended as a quick verification tool.
 */
import { performance } from 'node:perf_hooks';
import { setUnicodeSecurityConfig } from '../src/config.ts';
import { getConfusableTargets } from '../src/canonical.ts';

function run(label: string, iterations: number, char: string): number {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    getConfusableTargets(char);
  }
  return performance.now() - start;
}

async function main(): Promise<void> {
  const iterations = Number(process.env.CI ? 2_000 : 10_000);
  const char = 'a';
  setUnicodeSecurityConfig({ dataProfile: 'standard', enableConfusableIndex: false });
  // Warm
  getConfusableTargets(char);
  const linearMs = run('linear', iterations, char);

  setUnicodeSecurityConfig({ dataProfile: 'standard', enableConfusableIndex: true });
  // Warm index
  getConfusableTargets(char);
  const indexedMs = run('indexed', iterations, char);

  const speedup = linearMs / indexedMs;
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({ iterations, linearMs, indexedMs, speedup }, null, 2));
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error('[bench-confusables-index] Failed:', e);
  process.exit(1);
});
