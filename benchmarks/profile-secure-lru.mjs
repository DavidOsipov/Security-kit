/* eslint-env node, es2022 */
import { setTimeout as sleep } from 'timers/promises';

function now() { return (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now(); }

async function tryImport(spec) {
  try { return await import(spec); } catch { return null; }
}

async function loadSecureLRU() {
  const dist = await tryImport('../dist/index.mjs');
  if (dist && dist.SecureLRUCache) return dist.SecureLRUCache;
  // Fallback to TS source via tsx if available
  const src = await tryImport('../dist/src/secure-lru-cache.mjs');
  if (src && src.SecureLRUCache) return src.SecureLRUCache;
  throw new Error('SecureLRUCache not found. Build the project to generate dist/index.mjs');
}

function makeTunedOptions() {
  return {
    maxEntries: 1000,
    maxBytes: 1024 * 1024,
    maxEntryBytes: 32 * 1024,
    ttlAutopurge: true,
    ttlResolutionMs: 500,
    maxDeferredWipesPerFlush: 256,
    deferredWipeScheduler: 'auto',
    deferredWipeTimeoutMs: 1,
    deferredWipeAutoThreshold: 256,
    deferredWipeAutoBytesThreshold: 1024 * 1024,
  };
}

function makeDefaultOptions() {
  return {
    maxEntries: 1000,
    maxBytes: 1024 * 1024,
    maxEntryBytes: 32 * 1024,
  };
}

function randomKey(i) { return `k${i}`; }

function prepareValue(size = 1024) {
  const v = new Uint8Array(size);
  for (let i = 0; i < size; i++) v[i] = i & 0xff;
  return v;
}

async function runSetLoop(CacheClass, opts, iterations, keySpace = 1000) {
  const cache = new CacheClass(opts);
  const value = prepareValue(1024);
  const start = now();
  for (let i = 0; i < iterations; i++) {
    const k = randomKey(i % keySpace);
    cache.set(k, value);
  }
  return now() - start;
}

async function runGetLoop(CacheClass, opts, iterations, keySpace = 1000) {
  const cache = new CacheClass(opts);
  const value = prepareValue(1024);
  // Warm-up populate
  for (let i = 0; i < keySpace; i++) cache.set(randomKey(i), value);
  const start = now();
  for (let i = 0; i < iterations; i++) {
    const k = randomKey(i % keySpace);
    cache.get(k);
  }
  return now() - start;
}

async function runUpdateLoop(CacheClass, opts, iterations, keySpace = 1000) {
  const cache = new CacheClass(opts);
  const value = prepareValue(1024);
  // Warm-up populate
  for (let i = 0; i < keySpace; i++) cache.set(randomKey(i), value);
  const start = now();
  for (let i = 0; i < iterations; i++) {
    const k = randomKey(i % keySpace);
    cache.set(k, value);
  }
  return now() - start;
}

async function main() {
  const SecureLRU = await loadSecureLRU();
  const op = process.env.OP || (process.argv[2] || 'SET'); // SET|GET|UPDATE
  const mode = process.env.MODE || (process.argv[3] || 'default'); // default|tuned
  const iterations = Number(process.env.ITERS || process.argv[4] || 200000);
  const keySpace = Number(process.env.KEYS || process.argv[5] || 1000);

  const opts = mode === 'tuned' ? makeTunedOptions() : makeDefaultOptions();

  console.log(`Profiling SecureLRU — op=${op} mode=${mode} iterations=${iterations} keySpace=${keySpace}`);
  // Small delay so CPU profiler can attach before the heavy loop starts
  await sleep(50);

  let ms = 0;
  if (op === 'SET') ms = await runSetLoop(SecureLRU, opts, iterations, keySpace);
  else if (op === 'GET') ms = await runGetLoop(SecureLRU, opts, iterations, keySpace);
  else if (op === 'UPDATE') ms = await runUpdateLoop(SecureLRU, opts, iterations, keySpace);
  else throw new Error(`Unknown OP: ${op}`);

  const opsPerSec = Math.round((iterations / ms) * 1000);
  console.log(JSON.stringify({ op, mode, iterations, keySpace, ms, opsPerSec }, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
